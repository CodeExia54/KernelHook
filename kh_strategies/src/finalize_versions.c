/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * finalize_versions.c — __versions CRC patching via callback.
 *
 * kh_patch_crcs iterates every entry in __versions and calls
 * cb->crc_lookup for each symbol name.  The caller (kmod_loader)
 * wires this to crc_fallback_chain; khtools (Task 2.2) will wire it
 * to its own boot.img-driven resolver.
 */

#include <elf.h>
#include "elf_helpers.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "kh_strategies/finalize.h"

int kh_patch_crcs(uint8_t *mod, const Ehdr *eh,
                  const struct kh_finalize_callbacks *cb)
{
    Shdr *ver = kh_elf_find_section(mod, eh, "__versions");
    if (!ver || ver->sh_size == 0) return 0;

    int patched = 0;
    int num_entries = (int)(ver->sh_size / 64);
    for (int i = 0; i < num_entries; i++) {
        uint8_t *ent = mod + ver->sh_offset + i * 64;
        const char *sym = (const char *)(ent + 8);
        uint32_t new_crc;

        if (cb && cb->crc_lookup &&
            cb->crc_lookup(sym, &new_crc, cb->userdata) == 0) {
            uint32_t old_crc;
            memcpy(&old_crc, ent, 4);
            if (old_crc != new_crc) {
                memcpy(ent, &new_crc, 4);
                fprintf(stderr, "kh_strategies: CRC %s: 0x%08x -> 0x%08x\n",
                        sym, old_crc, new_crc);
            }
            patched++;
        } else {
            fprintf(stderr,
                    "kh_strategies: CRC %s: not found (keeping 0x%08x)\n",
                    sym, *(uint32_t *)ent);
        }
    }
    return patched;
}
