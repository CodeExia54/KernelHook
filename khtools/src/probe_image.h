/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KHTOOLS_PROBE_IMAGE_H
#define KHTOOLS_PROBE_IMAGE_H

#include <stdint.h>
#include <stddef.h>
#include "kh_strategies/strategies.h"

struct kh_probe_report {
    char     banner[128];
    uint64_t kallsyms_count;
    kh_ksymtab_variant_t ksymtab_variant;
    int      kcfi_initcall_typeid;       /* 1=present (graft needed), 0=not */
    uint8_t  init_module_kcfi_hash[4];
};

int kh_probe_image(const uint8_t *image_data, size_t image_len,
                   struct kh_probe_report *out_report);

#endif
