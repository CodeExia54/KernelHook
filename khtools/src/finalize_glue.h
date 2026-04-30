/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KHTOOLS_FINALIZE_GLUE_H
#define KHTOOLS_FINALIZE_GLUE_H

#include <stddef.h>
#include <stdint.h>
#include "probe_image.h"
#include "kallsym.h"

/* The plan that drives finalize: probe report + graft hint. */
struct kh_finalize_plan {
    struct kh_probe_report report;
    int  need_graft;             /* derived from probe: kCFI initcall typeid present */
    const char *graft_host_path; /* set by caller if --graft-host given */
};

int kh_make_finalize_plan(const uint8_t *image, size_t image_len,
                          struct kh_finalize_plan *out);

/* Callback-impl context: caller-owned image buffer + parsed kallsyms info. */
struct kh_finalize_ctx {
    const uint8_t *image;
    size_t         image_len;
    kallsym_t      kallsyms;
    char           vermagic[128];
    int            kcfi_present;
    uint8_t        kcfi_init_module_hash[4];
};

/* Initialise ctx from an Image — parses kallsyms + extracts vermagic + kCFI. */
int kh_finalize_ctx_init(struct kh_finalize_ctx *ctx,
                         const uint8_t *image, size_t image_len);
void kh_finalize_ctx_free(struct kh_finalize_ctx *ctx);

#endif /* KHTOOLS_FINALIZE_GLUE_H */
