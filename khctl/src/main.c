/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khctl — KernelHook control CLI.
 *
 * Status / log / version subcommands read from /sys/kernel/kh nodes
 * (the sysfs surface registered by fat.ko). When the node is absent —
 * fat.ko not loaded, or a pre-Task-5.3 build that hasn't wired sysfs
 * yet — the CLI prints "kh: not loaded" and returns rc=1.
 *
 * Subcommands beyond status/log/version (apd / khm / sc) land in the
 * C subspec when individual consumers need user-facing controls.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd_dispatch.h"

static void usage(void)
{
	fprintf(stderr,
		"khctl — KernelHook control CLI\n"
		"Usage: khctl <subcommand>\n"
		"\n"
		"Subcommands:\n"
		"  status    Show whether fat.ko is loaded + SDK version.\n"
		"  log       Dump fat.ko's recent log buffer.\n"
		"  version   Show fat.ko's compile-time KH_VERSION.\n");
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 1;
	}
	const char *cmd = argv[1];
	if (!strcmp(cmd, "-h") || !strcmp(cmd, "--help")) {
		usage();
		return 0;
	}
	if (!strcmp(cmd, "status"))
		return cmd_status(argc - 1, argv + 1);
	if (!strcmp(cmd, "log"))
		return cmd_log(argc - 1, argv + 1);
	if (!strcmp(cmd, "version"))
		return cmd_version(argc - 1, argv + 1);

	fprintf(stderr, "khctl: unknown subcommand '%s'\n", cmd);
	usage();
	return 1;
}

int kh_cat_sysfs_node(const char *node_name)
{
	char path[128];
	int n = snprintf(path, sizeof(path), "/sys/kernel/kh/%s", node_name);
	if (n < 0 || (size_t)n >= sizeof(path))
		return 2;

	FILE *f = fopen(path, "r");
	if (!f) {
		if (errno == ENOENT) {
			fprintf(stderr, "kh: not loaded\n");
			return 1;
		}
		fprintf(stderr, "kh: cannot read %s: %s\n", path, strerror(errno));
		return 2;
	}

	char buf[4096];
	size_t rd;
	while ((rd = fread(buf, 1, sizeof(buf), f)) > 0) {
		size_t off = 0;
		while (off < rd) {
			size_t w = fwrite(buf + off, 1, rd - off, stdout);
			if (w == 0) {
				fclose(f);
				return 2;
			}
			off += w;
		}
	}
	fclose(f);
	return 0;
}
