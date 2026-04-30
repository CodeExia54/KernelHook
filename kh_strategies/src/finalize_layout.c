/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * finalize_layout.c — struct module layout patching.
 *
 * Patches .rela.gnu.linkonce.this_module reloc offsets so the init_module
 * and cleanup_module function pointers land at the correct offsets for the
 * running kernel's struct module.  Also shrinks sh_size if the preset
 * provides a mod_size (required by Android 15 GKI 6.6+).
 *
 * The init_off / exit_off / mod_size values are obtained via
 * cb->module_layout_preset, keeping this file free of resolver.h and
 * patch_this_module.h dependencies.
 */

#include <elf.h>
#include "elf_helpers.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "kh_strategies/finalize.h"

int kh_patch_module_layout(uint8_t *mod, size_t mod_size, const Ehdr *eh,
                           const struct kh_finalize_callbacks *cb)
{
    (void)mod_size;

    Shdr *this_mod = kh_elf_find_section(mod, eh, ".gnu.linkonce.this_module");
    Shdr *rela     = kh_elf_find_section(mod, eh, ".rela.gnu.linkonce.this_module");

    if (!this_mod) {
        fprintf(stderr,
                "kh_strategies: .gnu.linkonce.this_module not found\n");
        return -1;
    }

    /* Resolve preset values from callback. */
    uint32_t preset_init_off = 0, preset_exit_off = 0, preset_mod_size = 0;
    if (cb && cb->module_layout_preset)
        cb->module_layout_preset(&preset_init_off, &preset_exit_off,
                                 &preset_mod_size, cb->userdata);

    /* Patch relocation offsets for init/exit functions. */
    if (rela && rela->sh_size >= 2 * sizeof(Rela) &&
        (preset_init_off != 0 || preset_exit_off != 0)) {
        Rela *entries = (Rela *)(mod + rela->sh_offset);
        int num_rela = (int)(rela->sh_size / sizeof(Rela));

        /* Locate init_module and cleanup_module symbol indices in .symtab. */
        Shdr *symtab_sh = NULL;
        for (int i = 0; i < eh->e_shnum; i++) {
            Shdr *sh = (Shdr *)(mod + eh->e_shoff + i * eh->e_shentsize);
            if (sh->sh_type == SHT_SYMTAB) { symtab_sh = sh; break; }
        }
        uint32_t init_sym_idx = 0, exit_sym_idx = 0;
        if (symtab_sh && symtab_sh->sh_link < (unsigned)eh->e_shnum) {
            Shdr *str = (Shdr *)(mod + eh->e_shoff +
                                 symtab_sh->sh_link * eh->e_shentsize);
            int ns = (int)(symtab_sh->sh_size / symtab_sh->sh_entsize);
            Elf64_Sym *sy = (Elf64_Sym *)(mod + symtab_sh->sh_offset);
            const char *st = (const char *)(mod + str->sh_offset);
            for (int i = 0; i < ns; i++) {
                const char *n = st + sy[i].st_name;
                if (strcmp(n, "init_module") == 0) init_sym_idx = (uint32_t)i;
                else if (strcmp(n, "cleanup_module") == 0) exit_sym_idx = (uint32_t)i;
            }
        }

        for (int i = 0; i < num_rela; i++) {
            uint32_t sym_idx = (uint32_t)(entries[i].r_info >> 32);
            uint64_t old_off = entries[i].r_offset;

            if (sym_idx == init_sym_idx && init_sym_idx != 0 &&
                preset_init_off != 0) {
                if (old_off != preset_init_off) {
                    fprintf(stderr,
                            "kh_strategies: init offset 0x%llx -> 0x%x\n",
                            (unsigned long long)old_off, preset_init_off);
                    entries[i].r_offset = preset_init_off;
                }
            } else if (sym_idx == exit_sym_idx && exit_sym_idx != 0 &&
                       preset_exit_off != 0) {
                if (old_off != preset_exit_off) {
                    fprintf(stderr,
                            "kh_strategies: exit offset 0x%llx -> 0x%x\n",
                            (unsigned long long)old_off, preset_exit_off);
                    entries[i].r_offset = preset_exit_off;
                }
            }
            /* Other relocations (cfi_check, etc.) are left unchanged. */
        }
    }

    /* Shrink sh_size to match running kernel's sizeof(struct module).
     * Required by Android 15 GKI 6.6+; a no-op on older kernels. */
    if (preset_mod_size != 0 &&
        this_mod->sh_size > (Elf64_Xword)preset_mod_size) {
        /* Defensive: refuse if a reloc target would be cut off. */
        uint32_t rela_max = preset_init_off;
        if (preset_exit_off > rela_max) rela_max = preset_exit_off;
        if (rela_max != 0 &&
            (unsigned long long)rela_max + 8ULL > preset_mod_size) {
            fprintf(stderr,
                    "kh_strategies: sh_size shrink refused: reloc target 0x%x "
                    "would exceed 0x%x (current 0x%llx)\n",
                    rela_max, preset_mod_size,
                    (unsigned long long)this_mod->sh_size);
        } else {
            fprintf(stderr,
                    "kh_strategies: shrink this_module sh_size 0x%llx -> 0x%x\n",
                    (unsigned long long)this_mod->sh_size, preset_mod_size);
            this_mod->sh_size = preset_mod_size;
        }
    }

    return 0;
}
