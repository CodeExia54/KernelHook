/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khtools patch — boot.img → patched-boot.img with embedded kh_blob trailer
 * AND a hook installed in the kernel Image so boot transfers control to the
 * appended khimg setup_entry (port of KernelPatch tools/patch.c::patch_update_img,
 * see image_inject.{h,c}).
 *
 * Layout produced inside the boot.img kernel section:
 *   [ kernel (B@_stext rewritten) | 4K pad | khimg | kh_blob_table | fat.ko | optional ksu.ko ]
 *
 * The trailer is consumed by Task 4.5 (khtools verify), khtools list, and
 * khimg/src/kh_load.c at boot.
 *
 * Path-quoting note: --boot, --in, --khimg, --ksu-lkm, --out paths are
 * passed to magiskboot via system() with single-quote wrapping. Paths
 * containing a literal single quote will break the shell command. This
 * matches the project's existing kmod_loader scripts and is acceptable
 * for dev / CI workflows where paths are pipeline-controlled. A future
 * hardening could switch to posix_spawn(argv).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "cmd_dispatch.h"
#include "file_io.h"
#include "embed_blob.h"
#include "image_inject.h"

int cmd_patch(int argc, char **argv)
{
    static struct option opts[] = {
        {"boot",    required_argument, 0, 'b'},
        {"in",      required_argument, 0, 'I'},
        {"khimg",   required_argument, 0, 'g'},
        {"ksu-lkm", required_argument, 0, 'K'},
        {"out",     required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };
    const char *boot = NULL, *fat_in = NULL, *khimg_p = NULL,
               *ksu = NULL, *out = NULL;
    int c, idx;
    optind = 1;
    while ((c = getopt_long(argc, argv, "b:I:g:K:o:", opts, &idx)) != -1) {
        if      (c == 'b') boot    = optarg;
        else if (c == 'I') fat_in  = optarg;
        else if (c == 'g') khimg_p = optarg;
        else if (c == 'K') ksu     = optarg;
        else if (c == 'o') out     = optarg;
        else if (c == '?') return 2;
    }
    if (!boot || !fat_in || !khimg_p || !out) {
        fprintf(stderr, "khtools patch: --boot --in --khimg --out are required\n");
        return 5;
    }

    /* Read inputs. */
    uint8_t *fat = NULL, *khimg = NULL, *ksu_buf = NULL;
    size_t fat_len = 0, khimg_len = 0, ksu_len = 0;
    if (kh_read_file(fat_in, &fat, &fat_len) < 0) {
        fprintf(stderr, "kh: patch: cannot read %s\n", fat_in);
        return 5;
    }
    if (kh_read_file(khimg_p, &khimg, &khimg_len) < 0) {
        fprintf(stderr, "kh: patch: cannot read %s\n", khimg_p);
        free(fat); return 5;
    }
    if (ksu && kh_read_file(ksu, &ksu_buf, &ksu_len) < 0) {
        fprintf(stderr, "kh: patch: cannot read %s\n", ksu);
        free(fat); free(khimg); return 5;
    }

    /* Build the trailer: kh_blob_table_v1 header + fat.ko + optional ksu.ko. */
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (kh_make_blob(fat, fat_len, ksu_buf, ksu_len, &blob, &blob_len) != 0) {
        fprintf(stderr, "kh: patch: kh_make_blob failed\n");
        free(fat); free(khimg); free(ksu_buf); return 5;
    }

    /* Unpack boot.img via magiskboot into a temporary directory. */
    char tmpdir[] = "/tmp/khtools-patch-XXXXXX";
    if (!mkdtemp(tmpdir)) {
        free(fat); free(khimg); free(ksu_buf); free(blob); return 5;
    }

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "cd '%s' && magiskboot unpack '%s' >/dev/null 2>&1", tmpdir, boot);
    if (system(cmd) != 0) {
        fprintf(stderr, "kh: patch: magiskboot unpack failed\n");
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir); system(cmd);
        free(fat); free(khimg); free(ksu_buf); free(blob); return 5;
    }

    /* Read the kernel section, run the full hook-injection pipeline, write back. */
    char kernel_path[512];
    snprintf(kernel_path, sizeof(kernel_path), "%s/kernel", tmpdir);
    uint8_t *kernel = NULL;
    size_t kernel_len = 0;
    if (kh_read_file(kernel_path, &kernel, &kernel_len) < 0) {
        fprintf(stderr, "kh: patch: cannot read kernel from unpack dir\n");
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir); system(cmd);
        free(fat); free(khimg); free(ksu_buf); free(blob); return 5;
    }

    /* Run the port of KP's patch_update_img: parse kallsyms, NOP PAC,
     * resolve memblock_*, build setup_preset_t, install B@_stext. */
    uint8_t *new_kernel = NULL;
    size_t new_kernel_len = 0;
    if (kh_image_inject(kernel, kernel_len,
                        khimg, khimg_len,
                        blob,  blob_len,
                        &new_kernel, &new_kernel_len) != 0) {
        fprintf(stderr, "kh: patch: kh_image_inject failed\n");
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir); system(cmd);
        free(fat); free(khimg); free(ksu_buf); free(blob); free(kernel);
        return 5;
    }

    if (kh_write_file(kernel_path, new_kernel, new_kernel_len) < 0) {
        fprintf(stderr, "kh: patch: cannot write modified kernel\n");
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir); system(cmd);
        free(fat); free(khimg); free(ksu_buf); free(blob); free(kernel); free(new_kernel); return 5;
    }
    fprintf(stderr,
            "kh: patch: hook installed at b_stext_insn_offset, "
            "redirect to khimg setup_entry\n");

    /* Repack into the caller's output path. */
    snprintf(cmd, sizeof(cmd),
             "cd '%s' && magiskboot repack '%s' '%s' >/dev/null 2>&1",
             tmpdir, boot, out);
    int rc_sys = system(cmd);

    char rm_cmd[1024];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf '%s'", tmpdir);
    system(rm_cmd);

    free(fat); free(khimg); free(ksu_buf); free(blob); free(kernel); free(new_kernel);
    if (rc_sys != 0) {
        fprintf(stderr, "kh: patch: magiskboot repack failed\n");
        return 5;
    }
    fprintf(stderr, "kh: patch: wrote %s\n", out);
    return 0;
}
