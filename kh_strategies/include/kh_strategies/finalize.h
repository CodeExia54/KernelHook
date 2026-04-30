/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KH_STRATEGIES_FINALIZE_H
#define KH_STRATEGIES_FINALIZE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Patch primitives for kernel module finalization.
 *
 * These functions rewrite .ko ELF sections (kCFI hashes, __versions CRCs,
 * vermagic, .gnu.linkonce.this_module reloc offsets, __ex_table format,
 * and printk symbol name) to match the running kernel before insmod.
 *
 * Callers must include <elf.h> before this header to get Elf64_Ehdr.
 * All finalize_*.c implementation files and kmod_loader.c are built with
 * <elf.h> available (Linux / Android NDK targets only).
 *
 * On macOS hosts the CMake target excludes finalize_*.c (CheckIncludeFile
 * gate in kh_strategies/CMakeLists.txt); the Makefile path always builds
 * them since it targets the NDK cross-compiler.
 */

/* ---------------------------------------------------------------------------
 * Caller-supplied callbacks — the lib does no I/O on its own beyond the
 * ELF byte manipulation.  kmod_loader supplies implementations backed by
 * crc_fallback_chain / get_vermagic; khtools (Task 2.2) will supply its
 * own boot.img-driven implementations.
 * --------------------------------------------------------------------------- */
struct kh_finalize_callbacks {
    /*
     * crc_lookup: resolve the CRC for a kernel symbol.
     * Returns 0 on success (sets *out_crc), -1 on miss.
     */
    int (*crc_lookup)(const char *sym, uint32_t *out_crc, void *userdata);

    /*
     * vermagic_get: copy the target kernel's vermagic string into out[0..cap-1].
     * Returns 0 on success, -1 if unavailable.
     */
    int (*vermagic_get)(char *out, size_t cap, void *userdata);

    /*
     * module_layout_preset: fill init_off, exit_off, mod_size for the running
     * kernel's struct module layout.  Any field left as 0 means unknown.
     * Returns 0 on success, -1 if unavailable.
     */
    int (*module_layout_preset)(uint32_t *init_off, uint32_t *exit_off,
                                uint32_t *mod_size, void *userdata);

    void *userdata;
};

/* ---------------------------------------------------------------------------
 * Pure helpers — no callbacks, just ELF byte rewrites.
 * All signatures use Elf64_Ehdr directly; callers need <elf.h>.
 * --------------------------------------------------------------------------- */

/*
 * kh_patch_elf_symbol: write a 64-bit value to the section backing a named
 * symbol in .symtab.  Returns 0 on success, -1 if sym not found or out of
 * bounds.
 */
int kh_patch_elf_symbol(uint8_t *mod, size_t mod_alloc_size,
                        const Elf64_Ehdr *eh, const char *sym_name,
                        uint64_t value);

/*
 * kh_patch_extable_format: if the running kernel uses 8-byte __ex_table
 * entries (pre-5.15), compress the module's 12-byte entries in-place and
 * rewire .rela__ex_table offsets.  target_entry_size must be 8; passing 12
 * is a no-op.  Returns number of entries compressed, 0 if nothing to do,
 * -1 on error.
 */
int kh_patch_extable_format(uint8_t *mod, const Elf64_Ehdr *eh,
                            int target_entry_size);

/* ---------------------------------------------------------------------------
 * Callback-driven helpers.
 * --------------------------------------------------------------------------- */

/*
 * kh_patch_kcfi_hashes: scan vendor .ko files in /vendor/lib/modules and
 * /vendor_dlkm/lib/modules, extract kCFI hashes for init_module /
 * cleanup_module, and patch them into mod.  Returns number of hashes
 * patched (0 if nothing needed or no vendor .ko found).
 *
 * Note: this function does its own filesystem I/O to locate a vendor .ko
 * reference; the cb parameter is reserved for future use and may be NULL.
 */
int kh_patch_kcfi_hashes(uint8_t *mod, size_t mod_size, const Elf64_Ehdr *eh,
                          const struct kh_finalize_callbacks *cb);

/*
 * kh_patch_crcs: update all CRC entries in __versions using cb->crc_lookup.
 * Returns number of entries where a CRC was found (not necessarily changed).
 */
int kh_patch_crcs(uint8_t *mod, const Elf64_Ehdr *eh,
                  const struct kh_finalize_callbacks *cb);

/*
 * kh_patch_vermagic: patch the vermagic= string in .modinfo using
 * cb->vermagic_get.  No return value (best-effort; logs to stderr on
 * length mismatch).
 */
void kh_patch_vermagic(uint8_t *mod, const Elf64_Ehdr *eh,
                       const struct kh_finalize_callbacks *cb);

/*
 * kh_patch_module_layout: patch .rela.gnu.linkonce.this_module reloc offsets
 * for init_module / cleanup_module to match the running kernel's struct module
 * layout, and optionally shrink sh_size via cb->module_layout_preset.
 * Returns 0 on success, -1 if .gnu.linkonce.this_module section not found.
 */
int kh_patch_module_layout(uint8_t *mod, size_t mod_size, const Elf64_Ehdr *eh,
                           const struct kh_finalize_callbacks *cb);

/*
 * kh_patch_printk_symbol: if the running kernel exports "printk" (not
 * "_printk"), rename the symbol in __versions and the UND entry in .symtab.
 * No return value (best-effort).
 */
void kh_patch_printk_symbol(uint8_t *mod, const Elf64_Ehdr *eh,
                             const struct kh_finalize_callbacks *cb);

#endif /* KH_STRATEGIES_FINALIZE_H */
