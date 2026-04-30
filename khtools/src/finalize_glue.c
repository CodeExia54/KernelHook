/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include "finalize_glue.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int kh_make_finalize_plan(const uint8_t *image, size_t image_len,
                          struct kh_finalize_plan *out) {
    memset(out, 0, sizeof(*out));
    int rc = kh_probe_image(image, image_len, &out->report);
    if (rc != 0) return rc;
    out->need_graft = out->report.kcfi_initcall_typeid;
    return 0;
}

int kh_finalize_ctx_init(struct kh_finalize_ctx *ctx,
                         const uint8_t *image, size_t image_len) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->image = image;
    ctx->image_len = image_len;
    if (analyze_kallsym_info(&ctx->kallsyms, (char *)image, (int32_t)image_len, ARM64, 1) != 0)
        return -1;
    /* vermagic: from `vermagic` symbol (not `linux_banner` — those differ). */
    int off = get_symbol_offset(&ctx->kallsyms, (char *)image, "vermagic");
    if (off > 0 && (size_t)off < image_len) {
        size_t max = image_len - (size_t)off;
        if (max > sizeof(ctx->vermagic) - 1) max = sizeof(ctx->vermagic) - 1;
        memcpy(ctx->vermagic, image + off, max);
        ctx->vermagic[sizeof(ctx->vermagic) - 1] = 0;
        char *nl = strchr(ctx->vermagic, '\n');
        if (nl) *nl = 0;
    }
    /* kCFI hash: present if __kcfi_typeid_init_module symbol exists. */
    int kcfi_off = get_symbol_offset(&ctx->kallsyms, (char *)image,
                                     "__kcfi_typeid_init_module");
    if (kcfi_off > 0 && (size_t)kcfi_off + 4 <= image_len) {
        ctx->kcfi_present = 1;
        memcpy(ctx->kcfi_init_module_hash, image + kcfi_off, 4);
    }
    return 0;
}

void kh_finalize_ctx_free(struct kh_finalize_ctx *ctx) {
    /* kallsym_t in KP doesn't have a destructor — its internal allocations are
     * tied to ctx lifetime. Zero the struct for hygiene. */
    memset(ctx, 0, sizeof(*ctx));
}
