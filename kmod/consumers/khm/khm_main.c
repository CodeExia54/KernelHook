/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khm — KernelHook minimal consumer skeleton.
 *
 * Proves the .kh_consumer_table dispatch + kh_consumer_init macro work
 * end-to-end. Real KP-equivalent functionality (kpms/) lands in a later
 * phase / subspec; this commit only ships the marker pr_info pair so
 * Task 3.4 path-1 AVD e2e can verify the dispatcher invoked us.
 *
 * Builds two ways:
 *   - Under KH_FAT_LINK: kh_consumer_init expands to a static struct in
 *     .kh_consumer_table; fat_main.c walks the table and calls our init.
 *   - Standalone: kh_consumer_init expands to module_init/module_exit, so
 *     `make module` against this file alone produces khm.ko.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include "kernelhook/kh_consumer.h"

static int kh_khm_init(void)
{
	pr_info("kh: khm: hello from khm consumer\n");
	return 0;
}

static void kh_khm_exit(void)
{
	pr_info("kh: khm: bye\n");
}

kh_consumer_init("khm", kh_khm_init, kh_khm_exit);

#ifndef KH_FAT_LINK
MODULE_LICENSE("GPL");
MODULE_AUTHOR("KernelHook");
MODULE_DESCRIPTION("KernelHook khm consumer (standalone build)");
#endif
