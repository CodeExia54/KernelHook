/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KH_STRATEGIES_H
#define KH_STRATEGIES_H

#include <stddef.h>
#include <stdint.h>

/* ksymtab variant identifier — covers all 4 historical layouts. */
typedef enum {
    KH_KSYMTAB_PREL32 = 0,
    KH_KSYMTAB_ABS64,
    KH_KSYMTAB_ABS64_LEGACY,
    KH_KSYMTAB_ABS64_LEGACY_U32,
    KH_KSYMTAB_UNKNOWN = -1,
} kh_ksymtab_variant_t;

const char *kh_ksymtab_variant_name(kh_ksymtab_variant_t v);

/* Probe operations on an Image / vmlinux blob. */
struct kh_probe_image {
    const uint8_t *data;
    size_t         len;
    /* Caller fills these from kallsyms scan; library only inspects layout. */
    uint64_t       text_va;       /* CONFIG_RELOCATABLE base */
    uint64_t       ksymtab_va;
    uint64_t       kcrctab_va;
};

kh_ksymtab_variant_t kh_probe_image_ksymtab(const struct kh_probe_image *img);

#endif /* KH_STRATEGIES_H */
