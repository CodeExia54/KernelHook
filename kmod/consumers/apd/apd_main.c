/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * apd — KernelHook minimal apd consumer skeleton.
 *
 * Source reference: APatch apd kernel-side ABI (sysfs node + ioctl
 * handler + app-profile lookup). The user-side daemon is NOT ported
 * here; that lives behind a future C subspec.
 *
 * For Phase 5 Task 5.1, we only need the dispatch wiring proven —
 * the init/exit pr_info pair confirms fat_main's .kh_consumer_table
 * walker invoked us. Real app-profile + sysfs registration lands in
 * Phase 5b (per spec note).
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include "kernelhook/kh_consumer.h"

static int kh_apd_init(void)
{
	pr_info("kh: apd: init\n");
	/* TODO(phase-5b): register sysfs node, app profile table. */
	return 0;
}

static void kh_apd_exit(void)
{
	pr_info("kh: apd: exit\n");
}

kh_consumer_register("apd", kh_apd_init, kh_apd_exit, KH_PRIO_NORMAL);

#ifndef KH_FAT_LINK
MODULE_LICENSE("GPL");
MODULE_AUTHOR("KernelHook");
MODULE_DESCRIPTION("KernelHook apd consumer (standalone build)");
#endif
