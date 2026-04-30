/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cmd_dispatch.h"
#include "probe_image.h"

static int read_file(const char *path, uint8_t **out_buf, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    uint8_t *buf = malloc((size_t)n);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f); free(buf); return -1;
    }
    fclose(f);
    *out_buf = buf;
    *out_len = (size_t)n;
    return 0;
}

int cmd_probe(int argc, char **argv) {
    static struct option opts[] = {
        {"image", required_argument, 0, 'i'},
        {0,0,0,0}
    };
    const char *image_path = NULL;
    int c, idx;
    /* Reset getopt state in case probe is re-called by tests. */
    optind = 1;
    while ((c = getopt_long(argc, argv, "i:", opts, &idx)) != -1) {
        if (c == 'i') image_path = optarg;
        else if (c == '?') return 2;
    }
    if (!image_path) {
        fprintf(stderr, "khtools probe: --image PATH required\n");
        return 2;
    }
    uint8_t *buf;
    size_t len;
    if (read_file(image_path, &buf, &len) < 0) {
        fprintf(stderr, "khtools probe: cannot read %s\n", image_path);
        return 2;
    }
    struct kh_probe_report r;
    int rc = kh_probe_image(buf, len, &r);
    free(buf);
    if (rc != 0) return rc;

    printf("kh probe report\n");
    printf("  banner          : %s\n", r.banner);
    printf("  kallsyms count  : %llu\n", (unsigned long long)r.kallsyms_count);
    printf("  ksymtab variant : %s\n", kh_ksymtab_variant_name(r.ksymtab_variant));
    printf("  kCFI initcall   : %s\n", r.kcfi_initcall_typeid ? "yes (graft needed)" : "no");
    if (r.kcfi_initcall_typeid)
        printf("  init_module hash: %02x %02x %02x %02x\n",
               r.init_module_kcfi_hash[0], r.init_module_kcfi_hash[1],
               r.init_module_kcfi_hash[2], r.init_module_kcfi_hash[3]);
    return 0;
}
