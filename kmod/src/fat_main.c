/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * fat_main.c — fat.ko top-level module entry.
 *
 * Compiled only under KH_FAT_LINK. Walks the .kh_consumer_table section
 * (populated by kh_consumer_register) and dispatches init/exit in
 * priority order (ascending: SUBSYS=100 < NORMAL=500 < LATE=900).
 *
 * The SDK init/exit (kernelhook_init / kernelhook_exit, defined in
 * src/main.c) wraps consumer init/exit with the hook engine bring-up.
 *
 * Design constraints (project-specific):
 *
 *   The project's freestanding shim (kmod/shim/shim.h) does NOT expose
 *   kmalloc_array / kfree / GFP_KERNEL / sort() — fat-link must work in
 *   the same freestanding-NDK build path that produces kernelhook.ko, so
 *   we cannot depend on those kernel-API helpers. We work around this
 *   with a fixed-size stack array (KH_MAX_CONSUMERS) plus a hand-rolled
 *   insertion sort. KH_MAX_CONSUMERS=32 is far above the realistic
 *   consumer count (Phase 5 ships 3: apd / khm / supercall).
 *
 *   We also avoid EXPORT_SYMBOL_GPL — the project routes its module
 *   symbol exports through the kh_crc-generated kh_exports.S table so
 *   the on-disk __ksymtab/__kcrctab layout matches the target kernel
 *   variant. kh_pending_ksu_blob is therefore a plain global (not
 *   EXPORT_SYMBOL'd here); consumers reference it via the header
 *   declaration, and the kh_crc manifest gets its export wiring in
 *   Task 5.3 when KSU loader logic lands.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/printk.h>
#include "kernelhook/kh_consumer.h"
#include "kernelhook/kh_ksu_blob.h"
#include "kernelhook/kh_ksu_load.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KernelHook");
MODULE_DESCRIPTION("KernelHook fat.ko — SDK + consumers static-linked");

/* Existing SDK entry/exit defined in src/main.c. */
int  kernelhook_init(void);
void kernelhook_exit(void);

/* Hard cap on consumers static-linked into fat.ko. Bumping this only
 * costs stack space at module load. */
#define KH_MAX_CONSUMERS 32

/* Linker-emitted bounds for the `kh_consumer_table` section. Because
 * the section name is a valid C identifier (no leading dot), ld and
 * lld synthesise these two symbols pointing at the real start/end of
 * the merged section in module memory. This is the standard Linux
 * idiom (e.g. __start_kh_strategies in built-in modules); it's the
 * only portable way to bracket a section that has been allocated by
 * the kernel module loader. */
extern const struct kh_consumer_entry __start_kh_consumer_table[];
extern const struct kh_consumer_entry __stop_kh_consumer_table[];

/* Aliases used in dispatcher math. */
#define __kh_consumer_table_start __start_kh_consumer_table
#define __kh_consumer_table_end   __stop_kh_consumer_table

/* In-module global owner of the pending KSU blob. Populated either by
 * ksu_path module_param (file ingest in kh_init below) or by the
 * khimg blob trailer when path-2 lands the bytes pre-init.
 *
 * Path-2 sysfs (/sys/kernel/kh/pending_ksu) was the original design
 * but cross-version struct bin_attribute layout drift makes that
 * untenable in the freestanding shim — see PATH1_KSU_SURFACE_BLOCKER.md.
 * The replacement is finit_module(2) args: khinsmod passes
 * `args = "ksu_path=/data/local/tmp/kernelsu.ko"` and the kernel
 * sets ksu_path before module_init runs, so kh_init can simply
 * filp_open + kernel_read in modprobe's process context. */
struct kh_pending_blob kh_pending_ksu_blob;

/* Module parameter: KSU LKM path to ingest before consumer dispatch.
 * Empty / NULL means "no KSU injection requested". */
static const char *ksu_path;
module_param(ksu_path, charp, 0);
MODULE_PARM_DESC(ksu_path,
	"Path to a KernelSU .ko to load after fat.ko's consumers come up. "
	"Replaces the deferred /sys/kernel/kh/pending_ksu sysfs surface "
	"with a one-shot file ingest in fat.ko's module_init context.");

/* No explicit anchor arrays needed — the linker provides
 * __start_kh_consumer_table / __stop_kh_consumer_table from the
 * `kh_consumer_table` section name (must be a valid C identifier).
 * The dispatcher uses the typedef'd aliases above. */

/* Hand-rolled insertion sort over a fixed-size stack copy. n <= KH_MAX_CONSUMERS.
 * Stable; ascending by priority. Pure C — no <linux/sort.h> dependency. */
static void kh_consumer_isort(struct kh_consumer_entry *a, size_t n)
{
	size_t i, j;
	for (i = 1; i < n; i++) {
		struct kh_consumer_entry tmp = a[i];
		j = i;
		while (j > 0 && a[j - 1].priority > tmp.priority) {
			a[j] = a[j - 1];
			j--;
		}
		a[j] = tmp;
	}
}

static int __init kh_init(void)
{
	int rc;
	size_t n = (size_t)(__kh_consumer_table_end - __kh_consumer_table_start);
	struct kh_consumer_entry sorted[KH_MAX_CONSUMERS];
	size_t i;

	rc = kernelhook_init();
	if (rc) {
		pr_err("kh: sdk: kernelhook_init failed: %d\n", rc);
		return rc;
	}

	if (n == 0) {
		pr_info("kh: sdk: fat.ko loaded with 0 consumers\n");
		return 0;
	}
	if (n > KH_MAX_CONSUMERS) {
		/* Use -EINVAL (the shim's minimal errno set) instead of -EOVERFLOW;
		 * the freestanding shim doesn't define EOVERFLOW and we don't
		 * pull in <linux/errno.h> here. */
		pr_err("kh: sdk: %zu consumers exceeds KH_MAX_CONSUMERS=%d; "
		       "rebuild fat.ko with a larger cap\n",
		       n, KH_MAX_CONSUMERS);
		kernelhook_exit();
		return -EINVAL;
	}

	/* Copy the section's read-only contents onto the stack so we can
	 * sort in place. Then dispatch ascending by priority. */
	memcpy(sorted, __kh_consumer_table_start, n * sizeof(sorted[0]));
	kh_consumer_isort(sorted, n);

	for (i = 0; i < n; i++) {
		rc = sorted[i].init();
		if (rc) {
			pr_err("kh: sdk: consumer '%s' init failed: %d\n",
			       sorted[i].name, rc);
			goto undo;
		}
		pr_info("kh: sdk: consumer '%s' init ok\n", sorted[i].name);
	}
	pr_info("kh: sdk: fat.ko loaded with %zu consumers\n", n);

	/* If khinsmod passed ksu_path=..., ingest the file now. Failure to
	 * ingest is logged but does not gate fat.ko itself — the KSU
	 * injection is best-effort, fat.ko's consumers stay armed. */
	if (ksu_path && ksu_path[0]) {
		int ingest_rc = kh_stage_ksu_from_path(ksu_path);
		if (ingest_rc < 0)
			pr_err("kh: sdk: ksu_path ingest failed: %d "
			       "(KSU injection skipped)\n", ingest_rc);
	}

	/* Kick the KSU secondary loader. No-op when no blob is pending
	 * (typical khinsmod path-1 without --ksu, ingest failure above,
	 * or khimg path-2 without ksu.ko in the trailer). */
	try_load_ksu();
	return 0;

undo:
	while (i--) {
		if (sorted[i].exit)
			sorted[i].exit();
	}
	kernelhook_exit();
	return rc;
}

static void __exit kh_exit(void)
{
	size_t n = (size_t)(__kh_consumer_table_end - __kh_consumer_table_start);
	struct kh_consumer_entry sorted[KH_MAX_CONSUMERS];
	size_t i;

	/* Tear down any deferred KSU hook before consumer shutdown so the
	 * before-callback's hook handle does not outlive the function code
	 * we patched. */
	kh_ksu_loader_shutdown();

	if (n > KH_MAX_CONSUMERS) {
		/* Mirror the kh_init guard. We can't have arrived here via
		 * kh_init since it would have refused to load — but stay
		 * defensive in case the caller skipped init. */
		pr_err("kh: sdk: %zu consumers > KH_MAX_CONSUMERS=%d on exit\n",
		       n, KH_MAX_CONSUMERS);
		kernelhook_exit();
		return;
	}
	if (n > 0) {
		memcpy(sorted, __kh_consumer_table_start, n * sizeof(sorted[0]));
		kh_consumer_isort(sorted, n);
		i = n;
		while (i--) {
			if (sorted[i].exit)
				sorted[i].exit();
		}
	}
	kernelhook_exit();
	pr_info("kh: sdk: fat.ko unloaded\n");
}

module_init(kh_init);
module_exit(kh_exit);
