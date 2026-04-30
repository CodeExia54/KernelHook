/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include <stdio.h>
#include <string.h>
#include "cmd_dispatch.h"

static void usage(void) {
    fprintf(stderr,
        "khtools — KernelHook PC build tool\n"
        "Usage: khtools <subcommand> [args...]\n"
        "\n"
        "Subcommands (Phase 1):\n"
        "  probe         Detect kernel image properties (ksymtab variant, kCFI mode, ...)\n"
        "  dump-syms     Print kallsyms parsed from a kernel Image\n"
        "\n"
        "Subcommands (later phases):\n"
        "  finalize      Adapt fat.ko for a target image\n"
        "  patch         Patch a boot.img with khimg + fat.ko\n"
        "  extract       Extract Image from boot.img\n"
        "  list          Inspect a KH artifact\n"
        "  verify        Verify a patched boot.img\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help")) { usage(); return 0; }
    if (!strcmp(cmd, "probe"))     return cmd_probe(argc - 1, argv + 1);
    if (!strcmp(cmd, "dump-syms")) return cmd_dump_syms(argc - 1, argv + 1);
#ifdef KH_HAS_ELF_H
    if (!strcmp(cmd, "finalize"))  return cmd_finalize(argc - 1, argv + 1);
#endif
    if (!strcmp(cmd, "patch"))   return cmd_patch(argc - 1, argv + 1);
    if (!strcmp(cmd, "extract")) return cmd_extract(argc - 1, argv + 1);
    if (!strcmp(cmd, "verify"))  return cmd_verify(argc - 1, argv + 1);
    fprintf(stderr, "khtools: unknown subcommand '%s'\n", cmd);
    usage();
    return 1;
}
