/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * In-kernel ELF finalize for incoming .ko buffers.
 *
 * Userspace tools/kmod_loader does the full finalize pipeline (CRCs,
 * vermagic, struct module layout, kCFI, printk symbol rename, extable
 * format) before insmod. When fat.ko ingests a third-party LKM at
 * runtime — e.g. KernelSU's kernelsu.ko delivered via the path-1
 * `ksu_path=` finit_module arg — that pipeline is no longer in the
 * critical path: we have to finalize in-kernel.
 *
 * This file implements the most common slice: __versions CRC patch
 * driven by the running kernel's `__crc_<sym>` kallsyms entries.
 * That fixes the "disagrees about version of symbol X" load failure
 * that hits every cross-kernel-subversion module load.
 *
 * Deferred sub-pieces (TODO):
 *   - vermagic patch — needs init_uts_ns->name.release offset table
 *     across struct uts_namespace layout drift
 *   - struct module layout (init_off / exit_off / sh_size shrink) —
 *     needs per-version preset table, kallsyms can't tell us
 *     sizeof(struct module) directly
 *   - kCFI hash patch — needs vendor .ko reference; on AVD targets
 *     the kernel-side scan path doesn't exist
 *
 * For LKMs whose vermagic / layout already match the running kernel
 * (AVD case: KSU GKI-tagged .ko on matching AVD image), CRC-only
 * finalize is sufficient. For mismatches, the syscall body will still
 * reject — but with a clear error in dmesg pointing at the next
 * sub-piece to land.
 */
#include <linux/printk.h>
#include <linux/string.h>
#include <symbol.h>
#include <kh_hook.h>
#include "kernelhook/kh_finalize_kernel.h"

/* Minimal Elf64 layout — matches SysV ELF64 spec exactly so we don't
 * need <elf.h>. Same struct kh_elf64_shdr the loader port uses;
 * duplicated here to keep this file self-contained. */
struct kh_fk_ehdr {
	uint8_t  e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct kh_fk_shdr {
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

/* __versions entry layout. Stable since 2.6.x. Each entry is exactly
 * 64 bytes: 8-byte CRC + 56-char NUL-padded name. */
struct kh_fk_modver {
	uint64_t crc;
	char     name[56];
};

#define ELFMAG0 0x7f
#define ELF_MAGIC_BYTES { 0x7f, 'E', 'L', 'F' }
#define EM_AARCH64 183

static int kh_fk_validate_ehdr(const struct kh_fk_ehdr *eh, unsigned long len)
{
	if (len < sizeof(*eh)) return -1;
	if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' ||
	    eh->e_ident[2] != 'L'  || eh->e_ident[3] != 'F') return -1;
	if (eh->e_ident[4] != 2)  return -1; /* ELFCLASS64 */
	if (eh->e_ident[5] != 1)  return -1; /* ELFDATA2LSB */
	if (eh->e_machine != EM_AARCH64) return -1;
	if (eh->e_shoff == 0 || eh->e_shnum == 0) return -1;
	if (eh->e_shstrndx >= eh->e_shnum) return -1;
	return 0;
}

/* Find a section by name. Returns the shdr pointer, or NULL. */
static struct kh_fk_shdr *kh_fk_find_section(uint8_t *mod, unsigned long mod_size,
                                             const struct kh_fk_ehdr *eh,
                                             const char *name)
{
	struct kh_fk_shdr *shdrs;
	const char        *strtab;
	unsigned int       i;

	if (eh->e_shoff + (uint64_t)eh->e_shnum * eh->e_shentsize > mod_size)
		return NULL;
	shdrs = (struct kh_fk_shdr *)(mod + eh->e_shoff);
	if (shdrs[eh->e_shstrndx].sh_offset >= mod_size) return NULL;
	strtab = (const char *)(mod + shdrs[eh->e_shstrndx].sh_offset);

	for (i = 0; i < eh->e_shnum; i++) {
		const char *sn;
		if (shdrs[i].sh_name >= shdrs[eh->e_shstrndx].sh_size) continue;
		sn = strtab + shdrs[i].sh_name;
		if (strcmp(sn, name) == 0)
			return &shdrs[i];
	}
	return NULL;
}

/* Look up `__crc_<sym>` in running kernel's kallsyms. Returns 0 on
 * success and stores the CRC value in *out. Returns -1 if not found.
 *
 * The kallsyms entry for `__crc_<sym>` is the address of the CRC
 * value, not the value itself — this is how MODVERSIONS represents
 * CRCs. Same convention modules' __versions section uses, but the
 * kernel side stores them as 4-byte unsigned in `__kcrctab`. We deref
 * that 4-byte value and zero-extend to 64-bit so it lines up with
 * the .ko's kh_fk_modver.crc field width. */
KCFI_EXEMPT
static int kh_fk_lookup_crc(const char *sym, uint64_t *out)
{
	char     name[80];
	unsigned long addr;
	size_t   nlen, slen;

	/* Build "__crc_<sym>" without depending on strcpy/memcpy/strlen
	 * resolution order (the shim's libc layer is fine but using
	 * inline byte ops here keeps this TU self-contained). */
	{
		const char *p = sym;
		char *q = name;
		const char  prefix[] = "__crc_";
		size_t k;
		for (k = 0; k < sizeof(prefix) - 1; k++) *q++ = prefix[k];
		nlen = sizeof(prefix) - 1;
		slen = 0;
		while (*p && nlen + slen + 1 < sizeof(name)) {
			*q++ = *p++;
			slen++;
		}
		*q = '\0';
		if (slen == 0) return -1;
	}

	addr = ksyms_lookup(name);
	if (!addr) return -1;

	/* The CRC is 4 bytes at *addr. Read it directly. */
	*out = (uint64_t)(*(volatile uint32_t *)(uintptr_t)addr);
	return 0;
}

int kh_finalize_versions_in_place(uint8_t *mod, unsigned long mod_size)
{
	struct kh_fk_ehdr  *eh;
	struct kh_fk_shdr  *vsec;
	struct kh_fk_modver *mvers;
	unsigned long       n_entries;
	unsigned long       i;
	int                 patched = 0, missing = 0;

	if (!mod || mod_size < sizeof(struct kh_fk_ehdr)) return -1;
	eh = (struct kh_fk_ehdr *)mod;
	if (kh_fk_validate_ehdr(eh, mod_size) != 0) {
		pr_err("kh: finalize: ELF header validation failed\n");
		return -1;
	}

	vsec = kh_fk_find_section(mod, mod_size, eh, "__versions");
	if (!vsec) {
		/* Not all .ko have __versions; built without MODVERSIONS
		 * is fine, just skip silently. */
		return 0;
	}
	if (vsec->sh_offset + vsec->sh_size > mod_size ||
	    vsec->sh_size % sizeof(struct kh_fk_modver) != 0) {
		pr_err("kh: finalize: __versions section bounds invalid\n");
		return -1;
	}

	mvers = (struct kh_fk_modver *)(mod + vsec->sh_offset);
	n_entries = vsec->sh_size / sizeof(struct kh_fk_modver);

	for (i = 0; i < n_entries; i++) {
		uint64_t kernel_crc;
		/* Defensive: ensure name is NUL-terminated within the slot. */
		mvers[i].name[sizeof(mvers[i].name) - 1] = '\0';
		if (kh_fk_lookup_crc(mvers[i].name, &kernel_crc) != 0) {
			missing++;
			continue;
		}
		if (mvers[i].crc != kernel_crc) {
			mvers[i].crc = kernel_crc;
			patched++;
		}
	}

	pr_info("kh: finalize: __versions: %lu entries, %d patched, %d missing\n",
	        n_entries, patched, missing);
	return 0;
}
