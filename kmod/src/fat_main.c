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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("KernelHook");
MODULE_DESCRIPTION("KernelHook fat.ko — SDK + consumers static-linked");

/* Existing SDK entry/exit defined in src/main.c. */
int  kernelhook_init(void);
void kernelhook_exit(void);

/* Hard cap on consumers static-linked into fat.ko. Bumping this only
 * costs stack space at module load. */
#define KH_MAX_CONSUMERS 32

/* Section anchor symbols. The .kh_consumer_table section sits between
 * the start/end via lexicographic ordering during link:
 *   .kh_consumer_table_start < .kh_consumer_table < .kh_consumer_table_end
 *
 * The anchor symbol names match the static [] arrays defined below. We
 * forward-declare them here as extern so the dispatcher can compute the
 * pointer-difference range. */
extern const struct kh_consumer_entry __kh_consumer_table_start_anchor[];
extern const struct kh_consumer_entry __kh_consumer_table_end_anchor[];

/* Aliases used in dispatcher math. */
#define __kh_consumer_table_start __kh_consumer_table_start_anchor
#define __kh_consumer_table_end   __kh_consumer_table_end_anchor

/* In-module global owner of the pending KSU blob. Real wiring (sysfs +
 * try_load_ksu) lands in Task 5.3; for now the symbol exists so the
 * header declaration resolves. */
struct kh_pending_blob kh_pending_ksu_blob;

/* Anchors. Lexicographic section sort ensures the layout above.
 * Non-static so the extern decls above can resolve to them — `static`
 * gives them internal linkage and the extern would fail to bind. */
const struct kh_consumer_entry __kh_consumer_table_start_anchor[]
    __attribute__((used, section(".kh_consumer_table_start"))) = {};
const struct kh_consumer_entry __kh_consumer_table_end_anchor[]
    __attribute__((used, section(".kh_consumer_table_end"))) = {};

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
