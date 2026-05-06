/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khimg path-2 entry: parse the kh_blob_table trailer, verify the
 * fat.ko SHA-256, locate kallsyms_lookup_name via the start_preset,
 * print a kh: marker so AVD console can confirm the hook fired, and
 * install a one-shot inline hook on a userspace syscall path so the
 * actual fat.ko init_module call happens later in process context
 * with current->mm valid.
 *
 * khimg fires at _stext, way before kernel_init has a process mm —
 * __do_sys_init_module is unreachable from this context because its
 * copy_from_user requires user mm. The deferred hook (see
 * kh_lkm_load.c) sidesteps that by waiting for userspace to make a
 * syscall.
 *
 * Blob anchor: cmd_patch appends the kh_blob_table_v1 immediately
 * after khimg.bin in the kernel image. After setup1.S/map.c
 * relocation, the linker symbol _kp_end maps to the runtime VA of
 * that trailer.
 */

#include <setup.h>
#include <start.h>
#include <ktypes.h>
#include <compiler.h>
#include <sha256.h>
#include "kernelhook/kh_blob_table.h"

typedef int  (*printk_f)(const char *fmt, ...);
typedef unsigned long (*kallsyms_lookup_name_f)(const char *name);

/* Forward decl from kh_lkm_load.c. */
int kh_lkm_install_hook(const uint8_t *fat_bytes, unsigned long fat_len,
                        kallsyms_lookup_name_f kallsyms,
                        printk_f printk);
void kh_lkm_set_map_restore(unsigned long dst_va,
                            const uint8_t *src_bytes,
                            unsigned long len);

int khimg_main(uint64_t kimage_voffset, uint64_t linear_voffset,
               start_preset_t *preset)
{
    (void)linear_voffset;

    /* kernel_va: runtime VA of the kernel image base. */
    uint64_t kernel_va = kimage_voffset + preset->kernel_pa;

    kallsyms_lookup_name_f kallsyms_lookup_name = (kallsyms_lookup_name_f)
        (kernel_va + preset->kallsyms_lookup_name_offset);

    /* printk first so subsequent failures are visible. */
    printk_f printk = (printk_f)kallsyms_lookup_name("printk");
    if (!printk) {
        printk = (printk_f)kallsyms_lookup_name("_printk");
    }

    /* Hand off map-restore info to the deferred-load hook. We CANNOT
     * restore here: paging_init.S itself was splatted into the dst region
     * (.setup.map = map.o + paging_init.o; paging_init's BLR-to-start
     * site and ret epilogue live within the splatted bytes). At this
     * point start() has called us via that BLR; control will return to
     * paging_init's epilogue when we ret. Restoring now overwrites that
     * epilogue with the original tcp_init_sock bytes, and the kernel
     * silent-hangs on the corrupted return path.
     *
     * Defer restore to kh_lkm_hook_handler — fires on first userspace
     * finit_module (timestamp ~5s, well after paging_init returned and
     * before inet6_create's first socket() at ~8.5s that hits
     * tcp_init_sock). */
    if (preset->map_backup_len > 0 && preset->map_backup_len <= MAP_MAX_SIZE) {
        unsigned long dst_va = (unsigned long)kernel_va +
                               (unsigned long)preset->map_offset;
        kh_lkm_set_map_restore(dst_va, preset->map_backup,
                               (unsigned long)preset->map_backup_len);
        if (printk)
            printk("kh: khimg: deferred map restore: %lld bytes at %lx\n",
                   (long long)preset->map_backup_len, dst_va);
    }

    /* Locate the trailing kh_blob_table_v1. setup.h forward-declares
     * _kp_end as a function symbol; cast its address to a byte pointer. */
    uint8_t *blob_bytes = (uint8_t *)(uintptr_t)&_kp_end;
    struct kh_blob_table_v1 *blob = (struct kh_blob_table_v1 *)blob_bytes;

    if (printk) {
        printk("kh: khimg: entered, blob @ %p magic=%x ver=%u fat_len=%u\n",
               (void *)blob, (unsigned)blob->magic,
               (unsigned)blob->version, (unsigned)blob->fat_len);
    }

    if (blob->magic != KHBL_MAGIC || blob->version != 1) {
        if (printk) printk("kh: khimg: bad blob magic/version, abort load\n");
        return 0;
    }

    if (blob->fat_len == 0) {
        if (printk) printk("kh: khimg: empty fat.ko in trailer, nothing to load\n");
        return 0;
    }

    /* Verify SHA-256 over fat.ko bytes. The producer pinned the
     * digest at patch time; mismatch means the trailer has been
     * tampered with. */
    uint8_t *fat = blob_bytes + blob->fat_off;
    {
        uint8_t computed[SHA256_BLOCK_SIZE];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, fat, blob->fat_len);
        sha256_final(&ctx, computed);
        for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
            if (computed[i] != blob->fat_sha256[i]) {
                if (printk) printk("kh: khimg: fat.ko sha256 mismatch byte %d, abort\n", i);
                return 0;
            }
        }
    }
    if (printk) printk("kh: khimg: fat.ko sha256 verified (%u bytes)\n",
                       (unsigned)blob->fat_len);

    /* Install the deferred-load inline hook. The fat.ko bytes stay
     * resident in the trailer (same kernel-mapped region khimg lives
     * in); the hook keeps a pointer + length in a static struct. */
    if (kh_lkm_install_hook(fat, blob->fat_len,
                             kallsyms_lookup_name, printk) != 0) {
        if (printk) printk("kh: khimg: deferred-load hook install failed\n");
    } else {
        if (printk) printk("kh: khimg: deferred-load hook armed; "
                           "fat.ko will init_module on first userspace syscall\n");
    }

    return 0;
}
