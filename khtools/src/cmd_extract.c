/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khtools extract — pull the kernel Image out of a boot.img via magiskboot.
 *
 * Requires `magiskboot` in PATH. Acceptable for dev workflow; CI / release
 * pipelines should pin a magiskboot binary in fixtures.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "cmd_dispatch.h"

int cmd_extract(int argc, char **argv)
{
    static struct option opts[] = {
        {"boot", required_argument, 0, 'b'},
        {"out",  required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };
    const char *boot = NULL, *out = NULL;
    int c, idx;
    optind = 1;
    while ((c = getopt_long(argc, argv, "b:o:", opts, &idx)) != -1) {
        if      (c == 'b') boot = optarg;
        else if (c == 'o') out  = optarg;
        else if (c == '?') return 2;
    }
    if (!boot || !out) {
        fprintf(stderr, "khtools extract: --boot and --out are required\n");
        return 5;
    }

    char tmpdir[] = "/tmp/khtools-extract-XXXXXX";
    if (!mkdtemp(tmpdir)) {
        fprintf(stderr, "khtools extract: mkdtemp failed\n");
        return 5;
    }

    char cmd[1024];
    int n = snprintf(cmd, sizeof(cmd),
                     "cd '%s' && magiskboot unpack '%s' >/dev/null 2>&1",
                     tmpdir, boot);
    if (n < 0 || (size_t)n >= sizeof(cmd)) goto fail_cleanup;
    if (system(cmd) != 0) {
        fprintf(stderr, "khtools extract: magiskboot unpack failed\n");
        goto fail_cleanup;
    }

    /* Copy kernel section to caller's output path. Use cp rather than
     * rename(2) because tmpdir may be on a different filesystem than out. */
    char cp_cmd[2048];
    snprintf(cp_cmd, sizeof(cp_cmd), "cp '%s/kernel' '%s'", tmpdir, out);
    if (system(cp_cmd) != 0) {
        fprintf(stderr, "khtools extract: copy to %s failed\n", out);
        goto fail_cleanup;
    }

    {
        char rm_cmd[1024];
        snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf '%s'", tmpdir);
        system(rm_cmd);
    }

    fprintf(stderr, "kh: extract: wrote %s\n", out);
    return 0;

fail_cleanup:
    {
        char rm_cmd[1024];
        snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf '%s'", tmpdir);
        system(rm_cmd);
    }
    return 5;
}
