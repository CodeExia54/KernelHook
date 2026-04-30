/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <elf.h>
#include "cmd_dispatch.h"
#include "finalize_glue.h"
#include "kh_strategies/finalize.h"

static int read_file(const char *path, uint8_t **out_buf, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return -1; }
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)n);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f); free(buf); return -1;
    }
    fclose(f); *out_buf = buf; *out_len = (size_t)n; return 0;
}

static int write_file(const char *p, const uint8_t *b, size_t l) {
    FILE *f = fopen(p, "wb");
    if (!f) return -1;
    if (fwrite(b, 1, l, f) != l) { fclose(f); return -1; }
    fclose(f); return 0;
}

/* Callbacks bridging kh_strategies into our offline ctx. */
static int kt_crc_lookup_cb(const char *sym, uint32_t *out_crc, void *userdata) {
    (void)sym; (void)out_crc; (void)userdata;
    /* TODO(task-2.2-followup): scan target Image's __kcrctab section. */
    return -1;
}

static int kt_vermagic_get_cb(char *out, size_t out_cap, void *userdata) {
    struct kh_finalize_ctx *ctx = userdata;
    if (!ctx->vermagic[0]) return -1;
    strncpy(out, ctx->vermagic, out_cap - 1);
    out[out_cap - 1] = 0;
    return 0;
}

/* module_layout_preset: not available from offline Image — return -1. */
static int kt_module_layout_preset_cb(uint32_t *init_off, uint32_t *exit_off,
                                      uint32_t *mod_size, void *userdata) {
    (void)init_off; (void)exit_off; (void)mod_size; (void)userdata;
    return -1;
}

int cmd_finalize(int argc, char **argv) {
    static struct option opts[] = {
        {"image",      required_argument, 0, 'i'},
        {"in",         required_argument, 0, 'I'},
        {"out",        required_argument, 0, 'o'},
        {"graft-host", required_argument, 0, 'H'},
        {0, 0, 0, 0}
    };
    const char *image_p = NULL, *in_p = NULL, *out_p = NULL, *graft_p = NULL;
    int c, idx;
    optind = 1;
    while ((c = getopt_long(argc, argv, "i:I:o:H:", opts, &idx)) != -1) {
        if      (c == 'i') image_p = optarg;
        else if (c == 'I') in_p    = optarg;
        else if (c == 'o') out_p   = optarg;
        else if (c == 'H') graft_p = optarg;
        else if (c == '?') return 2;
    }
    if (!image_p || !in_p || !out_p) {
        fprintf(stderr, "khtools finalize: --image, --in, --out are required\n");
        return 2;
    }

    uint8_t *image, *ko;
    size_t image_len, ko_len;
    if (read_file(image_p, &image, &image_len) < 0) {
        fprintf(stderr, "khtools finalize: cannot read %s\n", image_p);
        return 2;
    }
    if (read_file(in_p, &ko, &ko_len) < 0) {
        fprintf(stderr, "khtools finalize: cannot read %s\n", in_p);
        free(image);
        return 2;
    }

    struct kh_finalize_plan plan;
    int rc = kh_make_finalize_plan(image, image_len, &plan);
    if (rc != 0) { free(image); free(ko); return rc; }

    if (plan.need_graft && !graft_p) {
        fprintf(stderr,
                "kh: finalize: kCFI initcall typeid present; "
                "pass --graft-host PATH and re-run after Task 2.4\n");
        free(image); free(ko); return 4;
    }
    plan.graft_host_path = graft_p;

    struct kh_finalize_ctx ctx;
    if (kh_finalize_ctx_init(&ctx, image, image_len) != 0) {
        fprintf(stderr, "kh: finalize: kallsyms parse failed on Image\n");
        free(image); free(ko); return 2;
    }

    struct kh_finalize_callbacks cb = {
        .crc_lookup           = kt_crc_lookup_cb,
        .vermagic_get         = kt_vermagic_get_cb,
        .module_layout_preset = kt_module_layout_preset_cb,
        .userdata             = &ctx,
    };

    Elf64_Ehdr *eh = (Elf64_Ehdr *)ko;
    if (eh->e_ident[0] != 0x7f) {
        fprintf(stderr, "kh: finalize: input ko is not ELF\n");
        kh_finalize_ctx_free(&ctx); free(image); free(ko); return 2;
    }

    /* Apply patch primitives. Order mirrors kmod_loader's pre-finit flow.
     * Best-effort: per-step failures are non-fatal (some patches are optional,
     * e.g. kCFI hashes on non-kCFI kernels). */
    (void)kh_patch_kcfi_hashes(ko, ko_len, eh, &cb);
    (void)kh_patch_crcs(ko, eh, &cb);
    kh_patch_vermagic(ko, eh, &cb);
    (void)kh_patch_module_layout(ko, ko_len, eh, &cb);
    kh_patch_printk_symbol(ko, eh, &cb);

    if (plan.need_graft) {
        fprintf(stderr,
                "kh: finalize: graft path required but not yet implemented "
                "(Task 2.4)\n");
        kh_finalize_ctx_free(&ctx); free(image); free(ko); return 4;
    }

    if (write_file(out_p, ko, ko_len) < 0) {
        fprintf(stderr, "kh: finalize: cannot write %s\n", out_p);
        kh_finalize_ctx_free(&ctx); free(image); free(ko); return 2;
    }
    fprintf(stderr, "kh: finalize: wrote %s (%zu bytes)\n", out_p, ko_len);
    kh_finalize_ctx_free(&ctx); free(image); free(ko);
    return 0;
}
