/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * KSU secondary loader implementation. See kh_ksu_load.h for the
 * trigger model.
 *
 * Resolves load_module / vfree / system_state from kallsyms at runtime
 * — the freestanding shim does not link them directly. The deferred
 * hook target is selected from a fallback chain because kernel_init
 * symbol layout drifts across versions:
 *
 *   - run_init_process              4.4 .. 6.12 stable
 *   - try_to_run_init_process       a few intermediate versions
 *   - kernel_init_freeable          last-resort; itself .init.text but
 *                                   the *return* point is still live
 *
 * load_module() inside kernel/module.c is static, but full kallsyms
 * builds (CONFIG_KALLSYMS_ALL=y, the GKI default) still expose its
 * address. The signature we declare matches the (umod, len, uargs)
 * triple used by the syscall entry; this works for older kernels
 * where load_module took raw bytes, and the spec accepts that newer
 * kernels may need a follow-up port (init_module syscall path with a
 * proper struct load_info).
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <kh_hook.h>
#include <symbol.h>
#include "kernelhook/kh_ksu_blob.h"
#include "kernelhook/kh_ksu_load.h"
#include "kernelhook/kh_call_init_module.h"

/* fat.ko's pending-blob global; defined in fat_main.c. */
extern struct kh_pending_blob kh_pending_ksu_blob;

typedef void  (*vfree_fn_t)(const void *addr);
typedef void *(*vmalloc_fn_t)(unsigned long size);
typedef void *(*filp_open_fn_t)(const char *filename, int flags, unsigned short mode);
typedef int   (*filp_close_fn_t)(void *filp, void *id);
typedef long  (*kernel_read_fn_t)(void *file, void *buf, unsigned long count, long long *pos);

/* O_RDONLY / S_IRUSR octals — freestanding shim doesn't define them. */
#define KH_O_RDONLY 0x0000
#define KH_S_IRUSR  0400

/* Maximum LKM size we'll accept on the path-1 file ingest. KSU v3.2.4
 * is ~600 KiB; cap at 4 MiB so a malformed path can't OOM the kernel. */
#define KH_KSU_MAX_LEN (4UL * 1024 * 1024)

KCFI_EXEMPT
int kh_stage_ksu_from_path(const char *path)
{
	filp_open_fn_t   filp_open_fn;
	filp_close_fn_t  filp_close_fn;
	kernel_read_fn_t kernel_read_fn;
	vmalloc_fn_t     vmalloc_fn;
	vfree_fn_t       vfree_fn;
	void            *filp;
	void            *buf       = NULL;
	long long        pos       = 0;
	long             total     = 0;
	long             rd;

	if (!path || !*path)
		return -22; /* -EINVAL */

	if (kh_pending_ksu_blob.len != 0 || kh_pending_ksu_blob.data) {
		pr_err("kh: ksu: pending blob already populated; path ingest skipped\n");
		return -16; /* -EBUSY */
	}

	filp_open_fn   = (filp_open_fn_t)ksyms_lookup("filp_open");
	filp_close_fn  = (filp_close_fn_t)ksyms_lookup("filp_close");
	kernel_read_fn = (kernel_read_fn_t)ksyms_lookup("kernel_read");
	vmalloc_fn     = (vmalloc_fn_t)ksyms_lookup("vmalloc");
	vfree_fn       = (vfree_fn_t)ksyms_lookup("vfree");
	if (!filp_open_fn || !filp_close_fn || !kernel_read_fn ||
	    !vmalloc_fn || !vfree_fn) {
		pr_err("kh: ksu: file-ingest ksyms missing\n");
		return -38; /* -ENOSYS */
	}

	filp = filp_open_fn(path, KH_O_RDONLY, 0);
	/* IS_ERR check: filp_open returns ERR_PTR on failure. */
	if ((unsigned long)filp >= (unsigned long)-4095) {
		pr_err("kh: ksu: filp_open('%s') failed: %ld\n",
		       path, (long)(unsigned long)filp);
		return (int)(long)(unsigned long)filp;
	}

	/* Read in 64 KiB chunks. We don't know the file size upfront
	 * without parsing struct file (kernel_file_get_size isn't
	 * exported; vfs_getattr layout drifts). Fixed step + cap. */
	buf = vmalloc_fn(KH_KSU_MAX_LEN);
	if (!buf) {
		pr_err("kh: ksu: vmalloc(%lu) failed\n", KH_KSU_MAX_LEN);
		filp_close_fn(filp, NULL);
		return -12; /* -ENOMEM */
	}

	for (;;) {
		unsigned long want = 64UL * 1024;
		if ((unsigned long)total + want > KH_KSU_MAX_LEN)
			want = KH_KSU_MAX_LEN - (unsigned long)total;
		if (want == 0) {
			pr_err("kh: ksu: file '%s' exceeds %lu byte cap\n",
			       path, KH_KSU_MAX_LEN);
			vfree_fn(buf);
			filp_close_fn(filp, NULL);
			return -27; /* -EFBIG */
		}
		rd = kernel_read_fn(filp, (char *)buf + total, want, &pos);
		if (rd < 0) {
			pr_err("kh: ksu: kernel_read('%s') at %ld returned %ld\n",
			       path, total, rd);
			vfree_fn(buf);
			filp_close_fn(filp, NULL);
			return (int)rd;
		}
		if (rd == 0) break; /* EOF */
		total += rd;
	}

	filp_close_fn(filp, NULL);

	if (total <= 0) {
		pr_err("kh: ksu: file '%s' is empty\n", path);
		vfree_fn(buf);
		return -22;
	}

	kh_pending_ksu_blob.data = buf;
	kh_pending_ksu_blob.len  = (unsigned long)total;
	pr_info("kh: ksu: staged %ld bytes from %s\n", total, path);
	return 0;
}

/* enum system_states value from include/linux/kernel.h, stable since 2.6.x.
 * We compare against the resolved system_state global; the freestanding
 * shim does not expose the enum so we hard-code the int constant. */
#define KH_SYSTEM_RUNNING 4

/* Single-shot guard. The deferred hook may fire from multiple paths
 * (run_init_process is called once per init candidate, but
 * kernel_init_freeable can return through several code paths). The
 * load itself must run exactly once. */
static int           ksu_loaded     = 0;
static void         *ksu_late_target = NULL;

static void do_load_ksu_now(void)
{
	vfree_fn_t vfree_fn;
	int        rc;

	if (kh_pending_ksu_blob.len == 0 || !kh_pending_ksu_blob.data) {
		pr_info("kh: ksu: nothing to load\n");
		return;
	}

	/* kh_call_init_module stages the bytes through user-VA in the
	 * caller's mm before invoking __do_sys_init_module — see
	 * include/kernelhook/kh_call_init_module.h.
	 *
	 * Hot path (called from fat.ko's kh_init in modprobe context):
	 *   current->mm is valid, so vm_mmap succeeds and load proceeds.
	 *
	 * Cold path (called from run_init_process_pre hook before
	 * kernel_execve hands kernel_init its first user mm): vm_mmap
	 * returns -EINVAL, we log "kh: load: vm_mmap(payload, ...) failed"
	 * and bail. The blob is still vfree'd below — same behavior the
	 * old broken load_module_fn path had on lookup failure. */
	rc = kh_call_init_module(kh_pending_ksu_blob.data,
	                         kh_pending_ksu_blob.len, "");
	if (rc < 0)
		pr_err("kh: ksu: kh_call_init_module returned %d\n", rc);
	else
		pr_info("kh: ksu: loaded\n");

	/* Free the blob regardless of load outcome. On success the kernel
	 * has copied the bytes into its own module memory; on failure we
	 * have nothing to retry with anyway. */
	vfree_fn = (vfree_fn_t)ksyms_lookup("vfree");
	if (vfree_fn)
		vfree_fn(kh_pending_ksu_blob.data);
	kh_pending_ksu_blob.data = NULL;
	kh_pending_ksu_blob.len  = 0;
}

/* Single-arg before-callback for run_init_process / variants. Each of
 * the candidate targets takes one pointer argument
 *   int run_init_process(const char *init_filename)
 * so kh_hook_fargs1_t gives us the right shape. */
static void run_init_process_pre(kh_hook_fargs1_t *fargs, void *udata)
{
	(void)fargs;
	(void)udata;

	if (ksu_loaded) return;
	ksu_loaded = 1;
	do_load_ksu_now();

	/* Self-disarm so subsequent retries of run_init_process don't
	 * re-trigger an empty load. We can't unhook from inside the
	 * before-callback safely — the hook engine is mid-dispatch — so
	 * we just rely on the ksu_loaded flag. kh_ksu_loader_shutdown()
	 * cleans up on module unload. */
}

void try_load_ksu(void)
{
	int  *system_state_p;
	void *target;

	if (kh_pending_ksu_blob.len == 0)
		return;

	/* path-1 hot path: blob just arrived via /sys/kernel/kh/pending_ksu
	 * after the kernel is fully up. Skip the hook dance and load now. */
	system_state_p = (int *)ksyms_lookup("system_state");
	if (system_state_p && *system_state_p >= KH_SYSTEM_RUNNING) {
		do_load_ksu_now();
		return;
	}

	/* path-2: blob was delivered by khimg before kernel finished init.
	 * Defer until process context is safe (run_init_process et al). */
	target = (void *)ksyms_lookup("run_init_process");
	if (!target) target = (void *)ksyms_lookup("try_to_run_init_process");
	if (!target) target = (void *)ksyms_lookup("kernel_init_freeable");

	if (!target) {
		pr_warn("kh: ksu: no late init hook target found, ksu deferred indefinitely\n");
		return;
	}

	if (kh_hook_wrap1(target, run_init_process_pre, NULL, NULL) != HOOK_NO_ERR) {
		pr_err("kh: ksu: hook install failed at %p\n", target);
		return;
	}
	ksu_late_target = target;
	pr_info("kh: ksu: hook armed at %p, awaiting late init\n", target);
}

void kh_ksu_loader_shutdown(void)
{
	if (ksu_late_target) {
		kh_hook_unwrap(ksu_late_target,
		               (void *)run_init_process_pre, NULL);
		ksu_late_target = NULL;
	}
}
