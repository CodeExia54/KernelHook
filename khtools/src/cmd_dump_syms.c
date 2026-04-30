/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cmd_dispatch.h"
#include "kallsym.h"

static int read_file(const char *path, char **out_buf, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    char *buf = malloc((size_t)n);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        fclose(f); free(buf); return -1;
    }
    fclose(f);
    *out_buf = buf;
    *out_len = (size_t)n;
    return 0;
}

int cmd_dump_syms(int argc, char **argv) {
    static struct option opts[] = {
        {"image", required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };
    const char *image_path = NULL;
    int c, idx;
    optind = 1;
    while ((c = getopt_long(argc, argv, "i:", opts, &idx)) != -1) {
        if (c == 'i') image_path = optarg;
        else if (c == '?') return 2;
    }
    if (!image_path) {
        fprintf(stderr, "khtools dump-syms: --image PATH required\n");
        return 2;
    }
    char *buf;
    size_t len;
    if (read_file(image_path, &buf, &len) < 0) {
        fprintf(stderr, "khtools dump-syms: cannot read %s\n", image_path);
        return 2;
    }
    kallsym_t info = {0};
    if (analyze_kallsym_info(&info, buf, (int32_t)len, ARM64, 1) != 0) {
        fprintf(stderr, "kh: dump-syms: parse failed\n");
        free(buf);
        return 2;
    }
    int rc = dump_all_symbols(&info, buf);
    free(buf);
    return rc;
}
