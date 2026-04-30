/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * supercall — KernelHook minimal supercall consumer skeleton.
 *
 * Source reference: KernelPatch user/sc.* + kernel/patch/common/sc.c
 * (kernel-side syscall hook + key-verify entry point). The KP-specific
 * superkey is NOT ported — Pure loader stance: no superkey at this
 * layer. Real syscall hook + ABI lands in C subspec / Phase 5b.
 *
 * Registers with KH_PRIO_SUBSYS so init runs BEFORE apd / khm — apd
 * may depend on supercall ABI in future revisions.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include "kernelhook/kh_consumer.h"

static int kh_supercall_init(void)
{
	pr_info("kh: supercall: init\n");
	/* TODO(phase-5b / C subspec): hook a chosen syscall, register
	 * sc dispatch table. */
	return 0;
}

static void kh_supercall_exit(void)
{
	pr_info("kh: supercall: exit\n");
}

kh_consumer_register("supercall", kh_supercall_init, kh_supercall_exit,
		     KH_PRIO_SUBSYS);

#ifndef KH_FAT_LINK
MODULE_LICENSE("GPL");
MODULE_AUTHOR("KernelHook");
MODULE_DESCRIPTION("KernelHook supercall consumer (standalone build)");
#endif
