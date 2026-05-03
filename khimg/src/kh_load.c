/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khimg path-2 entry: parse the kh_blob_table trailer, verify the fat.ko
 * SHA-256, locate the kernel's kallsyms_lookup_name via the start_preset,
 * print a kh: marker so AVD console can confirm the hook fired, and
 * best-effort invoke init_module on the embedded fat.ko.
 *
 * Blob anchor: cmd_patch appends the kh_blob_table_v1 immediately after
 * khimg.bin in the kernel image. After setup1.S/map.c relocation, the
 * linker symbol _kp_end (last byte the lds reserves for khimg, *after*
 * the trailing 64K alignment) maps to the runtime VA of that trailer.
 *
 *   linker: _kp_start = 0x10000, _kp_end = 0x30000  (start_size = 0x20000)
 *   runtime: start_va corresponds to _kp_start,
 *            map.c copies extra_size bytes to (start_va + start_size),
 *            so &_kp_end ≡ start_va + start_size ≡ blob runtime VA.
 *
 * The fat.ko load itself is best-effort. Modern ARM64 GKI kernels make
 * load_module() a static, struct-load_info-driven function inside
 * kernel/module.c that is not directly callable from a raw byte buffer.
 * KP ships a ~thousand-line custom module loader for this; that port is
 * deferred. For now we resolve __do_sys_init_module / init_module and
 * call it with the fat.ko bytes — on older kernels (with set_fs) this
 * works; on newer ones it returns -EFAULT and we continue boot. The
 * "kh: khimg:" markers in dmesg are the proof that the hook succeeded.
 */

#include <setup.h>
#include <start.h>
#include <ktypes.h>
#include <compiler.h>
#include <sha256.h>

/* Shared trailer layout — single source of truth shared with khtools'
 * embed_blob.c producer. */
#include "kernelhook/kh_blob_table.h"

/* Kernel-side function prototypes we resolve via kallsyms_lookup_name. */
typedef int (*printk_f)(const char *fmt, ...);
typedef unsigned long (*kallsyms_lookup_name_f)(const char *name);
typedef int (*init_module_f)(void *umod, unsigned long len, const char *uargs);

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

    /* Verify SHA-256 over fat.ko bytes. The producer pinned the digest
     * at patch time; mismatch means the trailer has been tampered with. */
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

    /* Best-effort init_module. Symbol naming differs by kernel version:
     *   - 5.10+ ARM64 GKI: __arm64_sys_init_module / __do_sys_init_module
     *   - older / non-arm64: init_module
     * Resolve the first that hits, then call. Return value is logged but
     * does not gate boot. */
    init_module_f init_module = (init_module_f)
        kallsyms_lookup_name("__arm64_sys_init_module");
    if (!init_module)
        init_module = (init_module_f)kallsyms_lookup_name("__do_sys_init_module");
    if (!init_module)
        init_module = (init_module_f)kallsyms_lookup_name("init_module");

    if (!init_module) {
        if (printk) printk("kh: khimg: no init_module symbol resolved, fat.ko deferred\n");
        return 0;
    }

    if (printk) printk("kh: khimg: invoking init_module(%p, %u, \"\")\n",
                       (void *)fat, (unsigned)blob->fat_len);
    int rc = init_module((void *)fat, (unsigned long)blob->fat_len, "");
    if (printk) printk("kh: khimg: init_module rc=%d\n", rc);

    return 0;
}
