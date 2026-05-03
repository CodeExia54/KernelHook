/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khtools patch-image — raw kernel Image → patched kernel Image (no boot.img).
 *
 * Sibling to `khtools patch`. The boot.img path-2 flow goes:
 *
 *   boot.img  -unpack->  Image  -inject->  patched-Image  -repack->  patched-boot.img
 *
 * On AVD targets the kernel is already a raw `kernel-ranchu` Image (gzip
 * is fine — emulator -kernel accepts both). Going through magiskboot
 * just to immediately throw the boot.img wrapper away is wasted work and
 * an extra dep that fails on hosts without magiskboot. This subcommand
 * skips the unpack/repack and writes the patched Image directly. The
 * intended consumer is `scripts/test_avd_path2.sh`:
 *
 *   khtools patch-image \
 *       --image  $ANDROID_HOME/system-images/<x>/kernel-ranchu \
 *       --in     /tmp/fat-Pixel_31.ko \
 *       --khimg  khimg/khimg \
 *       --out    /tmp/patched-Pixel_31-Image \
 *       [--ksu-lkm /path/to/kernelsu.ko]
 *
 *   emulator -no-window -show-kernel -avd Pixel_31 \
 *            -kernel /tmp/patched-Pixel_31-Image
 *
 * The kernel-side transform (kh_image_inject) is identical to cmd_patch's;
 * only the I/O wrapper changes.
 *
 * Note: kh_image_inject expects a *decompressed* arm64 Image (magic bytes
 * `ARM\x64` at offset 0x38). If the input is gzip-compressed (AVD's
 * kernel-ranchu typically is), the caller is responsible for gunzipping
 * before invoking this subcommand. The wrapper script does that step.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include "cmd_dispatch.h"
#include "file_io.h"
#include "embed_blob.h"
#include "image_inject.h"

int cmd_patch_image(int argc, char **argv)
{
    static struct option opts[] = {
        {"image",   required_argument, 0, 'i'},
        {"in",      required_argument, 0, 'I'},
        {"khimg",   required_argument, 0, 'g'},
        {"ksu-lkm", required_argument, 0, 'K'},
        {"out",     required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };
    const char *image_p = NULL, *fat_in = NULL, *khimg_p = NULL,
               *ksu = NULL, *out = NULL;
    int c, idx;
    optind = 1;
    while ((c = getopt_long(argc, argv, "i:I:g:K:o:", opts, &idx)) != -1) {
        if      (c == 'i') image_p = optarg;
        else if (c == 'I') fat_in  = optarg;
        else if (c == 'g') khimg_p = optarg;
        else if (c == 'K') ksu     = optarg;
        else if (c == 'o') out     = optarg;
        else if (c == '?') return 2;
    }
    if (!image_p || !fat_in || !khimg_p || !out) {
        fprintf(stderr,
                "khtools patch-image: --image --in --khimg --out are required\n"
                "  --image    raw arm64 Image (gunzipped)\n"
                "  --in       fat.ko produced by `make -C kmod module KH_FAT_LINK=1`\n"
                "  --khimg    khimg/khimg blob\n"
                "  --ksu-lkm  optional KSU LKM to embed in trailer\n"
                "  --out      patched Image output\n");
        return 5;
    }

    /* Read all inputs upfront so we can fail fast. */
    uint8_t *kernel = NULL, *fat = NULL, *khimg = NULL, *ksu_buf = NULL;
    size_t kernel_len = 0, fat_len = 0, khimg_len = 0, ksu_len = 0;
    if (kh_read_file(image_p, &kernel, &kernel_len) < 0) {
        fprintf(stderr, "kh: patch-image: cannot read %s\n", image_p);
        return 5;
    }
    if (kh_read_file(fat_in, &fat, &fat_len) < 0) {
        fprintf(stderr, "kh: patch-image: cannot read %s\n", fat_in);
        free(kernel); return 5;
    }
    if (kh_read_file(khimg_p, &khimg, &khimg_len) < 0) {
        fprintf(stderr, "kh: patch-image: cannot read %s\n", khimg_p);
        free(kernel); free(fat); return 5;
    }
    if (ksu && kh_read_file(ksu, &ksu_buf, &ksu_len) < 0) {
        fprintf(stderr, "kh: patch-image: cannot read %s\n", ksu);
        free(kernel); free(fat); free(khimg); return 5;
    }

    /* Build the trailer (kh_blob_table_v1 + fat.ko + optional ksu.ko). */
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (kh_make_blob(fat, fat_len, ksu_buf, ksu_len, &blob, &blob_len) != 0) {
        fprintf(stderr, "kh: patch-image: kh_make_blob failed\n");
        free(kernel); free(fat); free(khimg); free(ksu_buf);
        return 5;
    }

    /* Run the kallsyms scan + PAC-NOP + setup_preset population + B@_stext. */
    uint8_t *new_kernel = NULL;
    size_t new_kernel_len = 0;
    if (kh_image_inject(kernel, kernel_len,
                        khimg, khimg_len,
                        blob,  blob_len,
                        &new_kernel, &new_kernel_len) != 0) {
        fprintf(stderr, "kh: patch-image: kh_image_inject failed\n");
        free(kernel); free(fat); free(khimg); free(ksu_buf); free(blob);
        return 5;
    }

    if (kh_write_file(out, new_kernel, new_kernel_len) < 0) {
        fprintf(stderr, "kh: patch-image: cannot write %s\n", out);
        free(kernel); free(fat); free(khimg); free(ksu_buf); free(blob);
        free(new_kernel);
        return 5;
    }

    fprintf(stderr,
            "kh: patch-image: wrote %s (%zu bytes, +%zu over original)\n",
            out, new_kernel_len, new_kernel_len - kernel_len);

    free(kernel); free(fat); free(khimg); free(ksu_buf); free(blob);
    free(new_kernel);
    return 0;
}
