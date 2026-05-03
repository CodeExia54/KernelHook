/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * KSU secondary loader API. Owned by fat.ko.
 *
 * Two trigger paths feed kh_pending_ksu_blob:
 *   - path-1 (khinsmod --ksu): userspace writes the KSU.ko bytes to
 *     /sys/kernel/kh/pending_ksu after fat.ko is online.
 *   - path-2 (khimg blob trailer): khimg parses the kh_blob_table_v1
 *     trailer at boot and stashes the bytes into kh_pending_ksu_blob
 *     before fat.ko's init runs.
 *
 * In either case fat.ko's kh_init calls try_load_ksu() at the end of
 * consumer dispatch. If the kernel is already past initcalls
 * (system_state >= SYSTEM_RUNNING), we resolve and call load_module
 * synchronously. Otherwise we install a one-shot kh_hook_wrap on the
 * latest available init-stage symbol (run_init_process /
 * try_to_run_init_process / kernel_init_freeable) so the load happens
 * in process context after all initcalls finish but before /init exec.
 *
 * KSU load failures (no symbol, vermagic mismatch, kCFI mismatch) are
 * logged and isolated — fat.ko itself stays online so consumer hooks
 * keep working.
 */
#ifndef KERNELHOOK_KH_KSU_LOAD_H
#define KERNELHOOK_KH_KSU_LOAD_H

/* Called from fat.ko's kh_init after consumer init. Inspects
 * kh_pending_ksu_blob and either loads KSU now or arms a deferred
 * hook. No-op when the blob is empty. */
void try_load_ksu(void);

/* Called from fat.ko's kh_exit. Tears down the deferred hook if
 * it was armed and never fired. */
void kh_ksu_loader_shutdown(void);

#endif /* KERNELHOOK_KH_KSU_LOAD_H */
