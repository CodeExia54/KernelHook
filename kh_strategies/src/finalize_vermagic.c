/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * finalize_vermagic.c — .modinfo vermagic string patching.
 *
 * kh_patch_vermagic calls cb->vermagic_get to obtain the target string and
 * rewrites the vermagic= entry in .modinfo in-place.  If the new string is
 * longer than the available slot, logs to stderr and skips.
 */

#include <elf.h>
#include "elf_helpers.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "kh_strategies/finalize.h"

#define KH_VERMAGIC_BUF 256

void kh_patch_vermagic(uint8_t *mod, const Ehdr *eh,
                       const struct kh_finalize_callbacks *cb)
{
    Shdr *mi = kh_elf_find_section(mod, eh, ".modinfo");
    if (!mi) return;

    if (!cb || !cb->vermagic_get) return;

    char new_vm[KH_VERMAGIC_BUF];
    if (cb->vermagic_get(new_vm, sizeof(new_vm), cb->userdata) != 0) return;
    if (!new_vm[0]) return;

    uint8_t *base = mod + mi->sh_offset;
    uint8_t *end  = base + mi->sh_size;

    for (uint8_t *p = base; p < end; ) {
        if (strncmp((char *)p, "vermagic=", 9) == 0) {
            char *old_vm = (char *)p + 9;
            /* Scan to find total slot length including any null padding. */
            size_t str_len = strlen(old_vm);
            char *slot_end = old_vm + str_len + 1;
            while (slot_end < (char *)end && *slot_end == '\0')
                slot_end++;
            size_t avail = (size_t)(slot_end - old_vm - 1);
            size_t new_len = strlen(new_vm);
            if (new_len <= avail) {
                memcpy(old_vm, new_vm, new_len);
                memset(old_vm + new_len, 0, avail - new_len + 1);
                fprintf(stderr, "kh_strategies: vermagic patched (avail=%zu)\n",
                        avail);
            } else {
                fprintf(stderr,
                        "kh_strategies: new vermagic too long (%zu > %zu)\n",
                        new_len, avail);
            }
            return;
        }
        p += strlen((char *)p) + 1;
    }
}
