/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 * Adapted for KernelHook by bmax121, 2026 (parts ported from KernelPatch
 * kernel/patch/module/{insn,relo,module}.c — see kh_loader_*.c headers).
 *
 * KernelHook in-kernel loader: minimal AArch64 ELF relocation primitives
 * shared between the freestanding khimg blob and the fat.ko kmod path.
 *
 * Status: SUBSET PORT (insn + relo only). The full "load this raw .ko
 * buffer" function (kh_load_module) is NOT implemented here — see
 * loader/BLOCKER.md for the reasoning. The two callers (khimg/kh_load.c
 * and kmod/src/ksu_load.c) currently invoke init_module / load_module
 * via kallsyms and are not changed by this port. This header reserves
 * the public surface so a future end-to-end loader has a well-defined
 * insertion point without churning callers again.
 *
 * What IS shipped here:
 *   - kh_aarch64_insn_encode_immediate()        (insn.c subset)
 *   - kh_apply_relocate_add()                   (relo.c, full)
 *
 * Both are pure functions of their inputs — no kallsyms, no allocator,
 * no PTE hooks. They compile in two environments via the KH_LOADER_*
 * macros below; the freestanding khimg path uses baselib for memcpy/
 * memset, the fat.ko path uses the kernel-shim string.h.
 */

#ifndef KMOD_LOADER_KH_LOADER_H
#define KMOD_LOADER_KH_LOADER_H

#include <stdint.h>
#include <stddef.h>

/* ----------------------------------------------------------------------
 * Build-environment selector
 *
 * Exactly one of these must be #defined by the caller's build system:
 *
 *   KH_LOADER_FREESTANDING  — khimg blob, no kernel headers, baselib only
 *   KH_LOADER_HOST          — kmod fat.ko, freestanding shim with
 *                              <linux/string.h> + ksyms_lookup() etc.
 *   KH_LOADER_UNITTEST      — host-side ctest, libc available
 *
 * The .c files include this header and dispatch via these macros.
 * -------------------------------------------------------------------- */
#if !defined(KH_LOADER_FREESTANDING) && \
    !defined(KH_LOADER_HOST) && \
    !defined(KH_LOADER_UNITTEST)
#  error "kh_loader.h: caller must define KH_LOADER_FREESTANDING, KH_LOADER_HOST, or KH_LOADER_UNITTEST"
#endif

/* ----------------------------------------------------------------------
 * AArch64 immediate-field encoder.
 *
 * The relocation engine needs to splice various immediate sub-fields
 * (12-bit, 16-bit, 19-bit, 21-bit ADR, 26-bit branch, 6-bit shift, etc.)
 * into existing instructions. This is mechanical bit manipulation with
 * no environment dependency.
 *
 * Returns the modified 32-bit instruction word, or 0 on bad type.
 * -------------------------------------------------------------------- */
enum kh_aarch64_insn_imm_type {
    KH_AARCH64_INSN_IMM_ADR,
    KH_AARCH64_INSN_IMM_26,
    KH_AARCH64_INSN_IMM_19,
    KH_AARCH64_INSN_IMM_16,
    KH_AARCH64_INSN_IMM_14,
    KH_AARCH64_INSN_IMM_12,
    KH_AARCH64_INSN_IMM_9,
    KH_AARCH64_INSN_IMM_7,
    KH_AARCH64_INSN_IMM_6,
    KH_AARCH64_INSN_IMM_S,
    KH_AARCH64_INSN_IMM_R,
    KH_AARCH64_INSN_IMM_MAX
};

uint32_t kh_aarch64_insn_encode_immediate(enum kh_aarch64_insn_imm_type type,
                                          uint32_t insn, uint64_t imm);

/* ----------------------------------------------------------------------
 * AArch64 RELA relocation.
 *
 * Walk a pre-laid-out section table (caller has already moved each
 * SHF_ALLOC section into its final runtime address and stamped that
 * address into sechdrs[i].sh_addr) and apply every R_AARCH64_* RELA
 * entry in `relsec`.
 *
 * Symbols whose st_shndx == SHN_UNDEF must be pre-resolved by the
 * caller — i.e. the caller has overwritten sym->st_value with the
 * runtime kernel address of the named symbol via kallsyms_lookup_name
 * (or equivalent) before calling this function. This is exactly KP's
 * simplify_symbols() responsibility, which we leave to the caller.
 *
 * Returns 0 on success, negative on relocation overflow / unsupported
 * RELA type. The caller is expected to log the failure with the
 * project's pr_err / printk equivalent.
 *
 * sechdrs / strtab MUST point to ELF64 (Elf64_Shdr) headers regardless
 * of build environment — we deliberately use raw uint64_t / uint32_t
 * field types to avoid pulling in a full <linux/elf.h>.
 * -------------------------------------------------------------------- */

/* Minimal subset of <linux/elf.h> Elf64 types used by the relocator.
 * Layouts match the SysV ELF64 spec exactly so we can cast a real
 * <linux/elf.h> Elf64_Shdr* to (struct kh_elf64_shdr*). */
struct kh_elf64_shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct kh_elf64_sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct kh_elf64_rela {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};

/* Apply every RELA entry in sechdrs[relsec] using sechdrs[symindex] as
 * the symbol table. Caller has already resolved SHN_UNDEF symbols.
 *
 * Returns:
 *    0           — success
 *   -8           — overflow / out-of-range relocation (KP returns -ENOEXEC,
 *                  we use a stable numeric value to avoid pulling errno.h)
 *   -22          — unsupported RELA type
 */
int kh_apply_relocate_add(struct kh_elf64_shdr *sechdrs,
                          const char *strtab,
                          unsigned int symindex,
                          unsigned int relsec);

/* SHT_REL is unused on AArch64 (which is RELA-only) but the loader API
 * keeps the same shape KP did, so callers can switch on shdr->sh_type
 * without a special-case. Always returns 0 — the function exists so a
 * future port that runs on relocation-rich architectures can plug a
 * real implementation in. */
int kh_apply_relocate(struct kh_elf64_shdr *sechdrs,
                      const char *strtab,
                      unsigned int symindex,
                      unsigned int relsec);

/* ----------------------------------------------------------------------
 * NOT IMPLEMENTED — see loader/BLOCKER.md
 *
 * The original task asked for a single end-to-end "kh_load_module(buf,
 * len, args, ops)" that both khimg and fat.ko would call instead of
 * init_module/load_module. We did not implement that function; the
 * minimum viable port (KP's KPM-only loader) does not handle real LKMs
 * (no vermagic, no __ksymtab linking, no kCFI, no PLT, no struct
 * module setup). The KernelHook project has already solved real-LKM
 * loading via the tools/kmod_loader strategy system + graft path; the
 * correct evolution is to extend that, not to retrofit KP's KPM
 * loader. This is documented in detail in loader/BLOCKER.md.
 *
 * The forward-declaration below stays in the header so that if/when a
 * real loader is added, callers do not need to refactor: they include
 * this header and call the function. For now the symbol resolves to
 * weak undefined and any caller would link-fail at build time, which
 * is the desired tripwire — we do not want a silent stub.
 * -------------------------------------------------------------------- */

/* ops are caller-supplied: alloc_exec must return RWX (or RW + flush)
 * memory of `len` bytes; lookup is the kallsyms equivalent; pr is
 * printk-compatible; flush_icache_range is invoked after the relocator
 * writes to the new image. */
struct kh_loader_ops {
    void          *(*alloc_exec)(unsigned long len);
    void           (*free_exec)(void *ptr);
    unsigned long  (*lookup)(const char *name);
    int            (*pr)(const char *fmt, ...);
    void           (*flush_icache_range)(unsigned long start, unsigned long end);
};

/* DEFERRED — see BLOCKER.md. Declared but intentionally not defined in
 * this port. Linker error on first use is intentional. */
int kh_load_module(const void *kbuf, unsigned long len, const char *uargs,
                   const struct kh_loader_ops *ops);

#endif /* KMOD_LOADER_KH_LOADER_H */
