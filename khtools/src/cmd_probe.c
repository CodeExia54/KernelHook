/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include <stdio.h>
#include "cmd_dispatch.h"

int cmd_probe(int argc, char **argv) {
    (void)argc; (void)argv;
    fprintf(stderr, "khtools probe: not yet implemented\n");
    return 2; /* per spec §6.1 exit codes */
}
