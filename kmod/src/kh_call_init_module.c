/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * In-kernel init_module(2) staging — see
 * include/kernelhook/kh_call_init_module.h for design.
 *
 * Resolves vm_mmap / vm_munmap / __do_sys_init_module via kallsyms,
 * stages the .ko bytes through a temporary user-VA mapping in the
 * caller's mm, and invokes the syscall body.
 *
 * KCFI: indirect calls via ksyms-resolved fn ptrs need __no_sanitize
 * (KCFI_EXEMPT) — the kernel's CFI shadow knows the upstream type
 * hash, not ours.
 */
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <symbol.h>
#include <kh_hook.h>
#include "kernelhook/kh_call_init_module.h"

/* mmap(2) constants we need but the freestanding shim does not expose. */
#define KH_MAP_PRIVATE   0x02
#define KH_MAP_ANONYMOUS 0x20
#define KH_PROT_READ     0x1
#define KH_PROT_WRITE    0x2

/* Sentinel for vm_mmap's errno-encoded return values. */
static inline int kh_is_err_value(unsigned long x)
{
	return ((long)x) < 0 && ((long)x) >= -4095;
}

/* Local strlen — the freestanding shim doesn't export one. */
static unsigned long kh_strlen(const char *s)
{
	const char *p = s;
	while (*p) p++;
	return (unsigned long)(p - s);
}

typedef unsigned long (*vm_mmap_fn_t)(void *file, unsigned long addr,
                                      unsigned long len, unsigned long prot,
                                      unsigned long flag, unsigned long off);
typedef int (*vm_munmap_fn_t)(unsigned long start, unsigned long len);
typedef int (*do_sys_init_module_fn_t)(void __user *umod, unsigned long len,
                                       const char __user *uargs);

KCFI_EXEMPT
int kh_call_init_module(const void *buf, unsigned long len, const char *args)
{
	vm_mmap_fn_t              vm_mmap_fn;
	vm_munmap_fn_t            vm_munmap_fn;
	do_sys_init_module_fn_t   do_init_fn;
	unsigned long             uaddr_payload;
	unsigned long             uaddr_args;
	unsigned long             arg_len;
	const char                empty = '\0';
	const char               *args_src;
	int                       rc;

	if (!buf || len == 0)
		return -22; /* -EINVAL */

	vm_mmap_fn = (vm_mmap_fn_t)ksyms_lookup("vm_mmap");
	if (!vm_mmap_fn) {
		pr_err("kh: load: vm_mmap not resolvable\n");
		return -38; /* -ENOSYS */
	}
	vm_munmap_fn = (vm_munmap_fn_t)ksyms_lookup("vm_munmap");
	if (!vm_munmap_fn) {
		pr_err("kh: load: vm_munmap not resolvable\n");
		return -38;
	}

	/* SYSCALL_DEFINE3(init_module, ...) emits __do_sys_init_module as
	 * the actual function body on modern kernels. Older kernels
	 * exposed a flat `init_module` symbol; try both. */
	do_init_fn = (do_sys_init_module_fn_t)ksyms_lookup("__do_sys_init_module");
	if (!do_init_fn)
		do_init_fn = (do_sys_init_module_fn_t)ksyms_lookup("sys_init_module");
	if (!do_init_fn)
		do_init_fn = (do_sys_init_module_fn_t)ksyms_lookup("init_module");
	if (!do_init_fn) {
		pr_err("kh: load: init_module syscall body not resolvable\n");
		return -38;
	}

	/* Stage the .ko payload in a fresh user-VA range. vm_mmap with
	 * file=NULL + MAP_PRIVATE|MAP_ANONYMOUS gives anonymous user
	 * memory in current->mm. Caller must be in process context. */
	uaddr_payload = vm_mmap_fn(NULL, 0, len,
	                           KH_PROT_READ | KH_PROT_WRITE,
	                           KH_MAP_PRIVATE | KH_MAP_ANONYMOUS, 0);
	if (kh_is_err_value(uaddr_payload)) {
		pr_err("kh: load: vm_mmap(payload, %lu) failed: %ld\n",
		       len, (long)uaddr_payload);
		return (int)(long)uaddr_payload;
	}

	if (copy_to_user((void __user *)uaddr_payload, buf, len) != 0) {
		pr_err("kh: load: copy_to_user(payload) failed\n");
		vm_munmap_fn(uaddr_payload, len);
		return -14; /* -EFAULT */
	}

	/* Stage args. NULL args is treated as empty string per
	 * init_module(2) spec — the syscall body does strndup_user
	 * regardless. */
	args_src = args ? args : &empty;
	arg_len = kh_strlen(args_src) + 1;
	uaddr_args = vm_mmap_fn(NULL, 0, arg_len,
	                        KH_PROT_READ | KH_PROT_WRITE,
	                        KH_MAP_PRIVATE | KH_MAP_ANONYMOUS, 0);
	if (kh_is_err_value(uaddr_args)) {
		pr_err("kh: load: vm_mmap(args, %lu) failed: %ld\n",
		       arg_len, (long)uaddr_args);
		vm_munmap_fn(uaddr_payload, len);
		return (int)(long)uaddr_args;
	}

	if (copy_to_user((void __user *)uaddr_args, args_src, arg_len) != 0) {
		pr_err("kh: load: copy_to_user(args) failed\n");
		vm_munmap_fn(uaddr_payload, len);
		vm_munmap_fn(uaddr_args, arg_len);
		return -14;
	}

	/* Hand off to the kernel. On success it copies the bytes into
	 * its own module memory before returning, so we can free the
	 * staging mappings unconditionally. */
	rc = do_init_fn((void __user *)uaddr_payload, len,
	                (const char __user *)uaddr_args);

	vm_munmap_fn(uaddr_payload, len);
	vm_munmap_fn(uaddr_args, arg_len);

	return rc;
}
