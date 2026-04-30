/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include "cmd_dispatch.h"

int cmd_log(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	return kh_cat_sysfs_node("log");
}
