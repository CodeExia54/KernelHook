/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "cmd_dispatch.h"
#include "file_io.h"
#include "kallsym.h"

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
    uint8_t *buf;
    size_t len;
    if (kh_read_file(image_path, &buf, &len) < 0) {
        fprintf(stderr, "khtools dump-syms: cannot read %s\n", image_path);
        return 2;
    }
    kallsym_t info = {0};
    if (analyze_kallsym_info(&info, (char *)buf, (int32_t)len, ARM64, 1) != 0) {
        fprintf(stderr, "kh: dump-syms: parse failed\n");
        free(buf);
        return 2;
    }
    int rc = dump_all_symbols(&info, (char *)buf);
    free(buf);
    return rc;
}
