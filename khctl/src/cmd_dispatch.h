/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KHCTL_CMD_DISPATCH_H
#define KHCTL_CMD_DISPATCH_H

int cmd_status(int argc, char **argv);
int cmd_log(int argc, char **argv);
int cmd_version(int argc, char **argv);

/* Reads the contents of /sys/kernel/kh/<node> to stdout. Returns 0 on
 * success, 1 if the node doesn't exist (fat.ko not loaded), 2 on other
 * I/O failure. Shared by status/log/version subcommands. */
int kh_cat_sysfs_node(const char *node_name);

#endif
