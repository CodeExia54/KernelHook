/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include "probe_image.h"
#include "kallsym.h"
#include <string.h>
#include <stdio.h>

int kh_probe_image(const uint8_t *image_data, size_t image_len,
                   struct kh_probe_report *r) {
    memset(r, 0, sizeof(*r));

    kallsym_t info = {0};
    if (analyze_kallsym_info(&info, (char *)image_data, (int32_t)image_len, ARM64, 1) != 0) {
        fprintf(stderr, "kh: probe: kallsyms parse failed\n");
        return 2;
    }
    r->kallsyms_count = (uint64_t)info.kallsyms_num_syms;

    /* ksymtab variant — placeholder until Task 2.1 carves out the real detector */
    struct kh_probe_image strat_img = {
        .data = image_data, .len = image_len,
    };
    r->ksymtab_variant = kh_probe_image_ksymtab(&strat_img);

    /* kCFI initcall typeid presence + first 4 bytes of the symbol's content. */
    int off = get_symbol_offset(&info, (char *)image_data, "__kcfi_typeid_init_module");
    r->kcfi_initcall_typeid = (off > 0) ? 1 : 0;
    if (r->kcfi_initcall_typeid && (size_t)off + 4 <= image_len) {
        memcpy(r->init_module_kcfi_hash, image_data + off, 4);
    }

    /* linux_banner — extract first line. */
    int banner_off = get_symbol_offset(&info, (char *)image_data, "linux_banner");
    if (banner_off > 0 && (size_t)banner_off < image_len) {
        size_t max = image_len - (size_t)banner_off;
        if (max > sizeof(r->banner) - 1) max = sizeof(r->banner) - 1;
        memcpy(r->banner, image_data + banner_off, max);
        r->banner[sizeof(r->banner) - 1] = 0;
        char *nl = strchr(r->banner, '\n');
        if (nl) *nl = 0;
    }
    return 0;
}
