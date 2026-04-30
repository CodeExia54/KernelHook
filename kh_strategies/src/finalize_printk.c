/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * finalize_printk.c — printk symbol rename patch.
 *
 * Pre-6.1 kernels export "printk"; 6.1+ exports "_printk".  Our module
 * references "_printk" by default.  If the running kernel only has "printk",
 * rename the symbol in __versions and in the .symtab UND entry.
 *
 * Symbol availability is probed via /proc/kallsyms.
 */

#include <elf.h>
#include "elf_helpers.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "kh_strategies/finalize.h"

/* Minimal /proc/kallsyms address lookup — returns 0 if not found. */
static uint64_t kallsyms_addr(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) return 0;
    char line[256];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), f)) {
        char sname[128];
        uint64_t saddr;
        char stype;
        if (sscanf(line, "%llx %c %127s",
                   (unsigned long long *)&saddr, &stype, sname) == 3) {
            if (strcmp(sname, name) == 0) {
                addr = saddr;
                break;
            }
        }
    }
    fclose(f);
    return addr;
}

void kh_patch_printk_symbol(uint8_t *mod, const Ehdr *eh,
                             const struct kh_finalize_callbacks *cb)
{
    (void)cb;  /* reserved for future use */

    uint64_t addr_printk  = kallsyms_addr("printk");
    uint64_t addr_uprintk = kallsyms_addr("_printk");

    if (addr_uprintk) return;  /* _printk exists — no rename needed */
    if (!addr_printk) return;  /* neither present */

    fprintf(stderr,
            "kh_strategies: kernel uses 'printk' instead of '_printk'\n");

    /* Patch __versions entry. */
    Shdr *ver = kh_elf_find_section(mod, eh, "__versions");
    if (ver) {
        int n = (int)(ver->sh_size / 64);
        for (int i = 0; i < n; i++) {
            char *sym = (char *)(mod + ver->sh_offset + i * 64 + 8);
            if (strcmp(sym, "_printk") == 0) {
                memmove(sym, sym + 1, strlen(sym));
                fprintf(stderr,
                        "kh_strategies: __versions _printk -> printk\n");
            }
        }
    }

    /* Patch UND _printk in .symtab strtab — shift name bytes left by 1. */
    Shdr *symtab_sh = NULL, *linked_strtab = NULL;
    for (int i = 0; i < eh->e_shnum; i++) {
        Shdr *sh = (Shdr *)(mod + eh->e_shoff + i * eh->e_shentsize);
        if (sh->sh_type == SHT_SYMTAB &&
            sh->sh_link < (unsigned)eh->e_shnum) {
            symtab_sh = sh;
            linked_strtab = (Shdr *)(mod + eh->e_shoff +
                                     sh->sh_link * eh->e_shentsize);
            break;
        }
    }
    if (symtab_sh && linked_strtab) {
        int num_syms = (int)(symtab_sh->sh_size / symtab_sh->sh_entsize);
        Elf64_Sym *syms = (Elf64_Sym *)(mod + symtab_sh->sh_offset);
        char *strs = (char *)(mod + linked_strtab->sh_offset);
        int patched = 0;
        for (int i = 0; i < num_syms; i++) {
            if (syms[i].st_shndx != SHN_UNDEF) continue;
            char *name = strs + syms[i].st_name;
            if (strcmp(name, "_printk") == 0) {
                memmove(name, name + 1, strlen(name));
                patched++;
            }
        }
        if (patched) {
            fprintf(stderr,
                    "kh_strategies: strtab UND _printk -> printk (%d)\n",
                    patched);
        }
    }
}
