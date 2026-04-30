/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * finalize_misc.c — pure ELF patch helpers: kh_patch_elf_symbol and
 * kh_patch_extable_format.  No I/O; no callbacks needed.
 */

#include <elf.h>
#include "elf_helpers.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "kh_strategies/finalize.h"

int kh_patch_elf_symbol(uint8_t *mod, size_t mod_alloc_size,
                        const Ehdr *eh, const char *sym_name, uint64_t value)
{
    /* Find .symtab and .strtab */
    Shdr *symtab_sh = NULL, *strtab_sh = NULL;
    for (int i = 0; i < eh->e_shnum; i++) {
        Shdr *sh = (Shdr *)(mod + eh->e_shoff + i * eh->e_shentsize);
        if (sh->sh_type == SHT_SYMTAB && sh->sh_link < (unsigned)eh->e_shnum) {
            symtab_sh = sh;
            strtab_sh = (Shdr *)(mod + eh->e_shoff +
                                 sh->sh_link * eh->e_shentsize);
            break;
        }
    }
    if (!symtab_sh || !strtab_sh) return -1;

    int num_syms = (int)(symtab_sh->sh_size / symtab_sh->sh_entsize);
    Elf64_Sym *syms = (Elf64_Sym *)(mod + symtab_sh->sh_offset);
    const char *strs = (const char *)(mod + strtab_sh->sh_offset);

    for (int i = 0; i < num_syms; i++) {
        if (strcmp(strs + syms[i].st_name, sym_name) != 0) continue;
        if (syms[i].st_shndx == SHN_UNDEF ||
            syms[i].st_shndx >= (unsigned)eh->e_shnum)
            continue;

        Shdr *sec = (Shdr *)(mod + eh->e_shoff +
                             syms[i].st_shndx * eh->e_shentsize);
        uint64_t offset = sec->sh_offset + syms[i].st_value;
        if (offset + sizeof(value) > mod_alloc_size) continue;
        memcpy(mod + offset, &value, sizeof(value));
        return 0;
    }
    return -1;
}

int kh_patch_extable_format(uint8_t *mod, const Ehdr *eh, int target_entry_size)
{
    if (target_entry_size != 8 && target_entry_size != 12) return 0;
    if (target_entry_size == 12) return 0;  /* already native format */

    Shdr *ex = kh_elf_find_section(mod, eh, "__ex_table");
    if (!ex || ex->sh_size == 0) return 0;
    if (ex->sh_size % 12 != 0) {
        fprintf(stderr,
                "kh_strategies: __ex_table size %lu not multiple of 12 — leaving untouched\n",
                (unsigned long)ex->sh_size);
        return 0;
    }
    int num_entries = (int)(ex->sh_size / 12);

    Shdr *rela = kh_elf_find_section(mod, eh, ".rela__ex_table");
    if (!rela || rela->sh_entsize != sizeof(Rela)) {
        fprintf(stderr,
                "kh_strategies: no .rela__ex_table — assuming pre-resolved values (unusual)\n");
        return 0;
    }

    size_t num_relas = rela->sh_size / sizeof(Rela);
    Rela *relas = (Rela *)(mod + rela->sh_offset);
    int rewired = 0;
    for (size_t i = 0; i < num_relas; i++) {
        uint64_t old_off = relas[i].r_offset;
        uint64_t entry_idx = old_off / 12;
        uint64_t field_off = old_off % 12;
        if (field_off != 0 && field_off != 4) {
            fprintf(stderr,
                    "kh_strategies: unexpected __ex_table reloc field_off=%lu — abort\n",
                    (unsigned long)field_off);
            return -1;
        }
        if ((int)entry_idx >= num_entries) continue;
        relas[i].r_offset = entry_idx * 8 + field_off;
        rewired++;
    }

    ex->sh_size = (uint32_t)(num_entries * 8);
    fprintf(stderr,
            "kh_strategies: __ex_table: %d entries compressed 12B->8B "
            "(legacy format, %d relocs rewired)\n",
            num_entries, rewired);
    return num_entries;
}
