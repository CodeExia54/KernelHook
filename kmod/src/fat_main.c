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
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sort.h>
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

/* Section anchor symbols. The .kh_consumer_table section sits between
 * the start/end via lexicographic ordering during link:
 *   .kh_consumer_table_start < .kh_consumer_table < .kh_consumer_table_end */
extern const struct kh_consumer_entry __kh_consumer_table_start[];
extern const struct kh_consumer_entry __kh_consumer_table_end[];

/* In-module BSS owner of the pending KSU blob. Real wiring of this
 * sysfs node + try_load_ksu lands in Task 5.3. For 3.1 we ship the
 * symbol so consumers can compile against the header. */
struct kh_pending_blob kh_pending_ksu_blob;
EXPORT_SYMBOL_GPL(kh_pending_ksu_blob);

/* Anchors. Lexicographic section sort ensures the layout above. */
static const struct kh_consumer_entry __kh_consumer_table_start_anchor[]
    __attribute__((used, section(".kh_consumer_table_start"))) = {};
static const struct kh_consumer_entry __kh_consumer_table_end_anchor[]
    __attribute__((used, section(".kh_consumer_table_end"))) = {};

static int kh_consumer_cmp(const void *a, const void *b)
{
    const struct kh_consumer_entry *ea = a;
    const struct kh_consumer_entry *eb = b;
    if (ea->priority < eb->priority) return -1;
    if (ea->priority > eb->priority) return 1;
    return 0;
}

static int __init kh_init(void)
{
    int rc;
    size_t n = (size_t)(__kh_consumer_table_end - __kh_consumer_table_start);
    size_t i;
    struct kh_consumer_entry *sorted;

    rc = kernelhook_init();
    if (rc) {
        pr_err("kh: sdk: kernelhook_init failed: %d\n", rc);
        return rc;
    }

    if (n == 0) {
        pr_info("kh: sdk: fat.ko loaded with 0 consumers\n");
        return 0;
    }

    /* Copy + sort by priority; the section is read-only so we can't sort in
     * place. n is bounded by the number of registered consumers (small). */
    sorted = kmalloc_array(n, sizeof(*sorted), GFP_KERNEL);
    if (!sorted) {
        kernelhook_exit();
        return -ENOMEM;
    }
    memcpy(sorted, __kh_consumer_table_start, n * sizeof(*sorted));
    sort(sorted, n, sizeof(*sorted), kh_consumer_cmp, NULL);

    for (i = 0; i < n; i++) {
        rc = sorted[i].init();
        if (rc) {
            pr_err("kh: sdk: consumer '%s' init failed: %d\n", sorted[i].name, rc);
            goto undo;
        }
        pr_info("kh: sdk: consumer '%s' init ok\n", sorted[i].name);
    }
    kfree(sorted);
    pr_info("kh: sdk: fat.ko loaded with %zu consumers\n", n);
    return 0;

undo:
    while (i--) {
        if (sorted[i].exit)
            sorted[i].exit();
    }
    kfree(sorted);
    kernelhook_exit();
    return rc;
}

static void __exit kh_exit(void)
{
    size_t n = (size_t)(__kh_consumer_table_end - __kh_consumer_table_start);

    if (n > 0) {
        struct kh_consumer_entry *sorted = kmalloc_array(n, sizeof(*sorted), GFP_KERNEL);
        if (sorted) {
            memcpy(sorted, __kh_consumer_table_start, n * sizeof(*sorted));
            sort(sorted, n, sizeof(*sorted), kh_consumer_cmp, NULL);
            /* Reverse order on exit. */
            size_t i = n;
            while (i--) {
                if (sorted[i].exit)
                    sorted[i].exit();
            }
            kfree(sorted);
        }
    }
    kernelhook_exit();
    pr_info("kh: sdk: fat.ko unloaded\n");
}

module_init(kh_init);
module_exit(kh_exit);
