/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KERNELHOOK_KH_CALL_INIT_MODULE_H
#define KERNELHOOK_KH_CALL_INIT_MODULE_H

/*
 * In-kernel staging wrapper around the kernel's own init_module(2)
 * implementation. Modern GKI rejects calls into __do_sys_init_module
 * with kernel pointers because the syscall body uses copy_from_user;
 * we work around that by allocating a user-space VA range in the
 * caller's mm with vm_mmap, copying the .ko bytes there with
 * copy_to_user, and only THEN invoking the syscall body.
 *
 *   kh_call_init_module(buf, len, "")
 *     1. vm_mmap(NULL, 0, len, PROT_RW, MAP_PRIVATE|MAP_ANON, 0) -> uaddr
 *     2. copy_to_user(uaddr, buf, len)
 *     3. vm_mmap small range for args, copy "" or args bytes there
 *     4. __do_sys_init_module(uaddr, len, uargs)  // kernel-managed
 *     5. vm_munmap(uaddr, len) + vm_munmap(uargs)
 *
 * Caller invariants:
 *   - current->mm MUST be valid. fat.ko's module_init runs in the
 *     insmod/modprobe process context, which satisfies this. Calling
 *     from a kernel kthread or before kernel_init's exec hand-off
 *     will return -EINVAL from vm_mmap.
 *   - The buffer `buf` must already have been finalized for the
 *     running kernel (vermagic / __versions / kCFI / struct module
 *     layout patches applied). kh_strategies/finalize is the canonical
 *     in-process patcher; this primitive does not patch.
 *
 * Return:
 *   0          — module loaded successfully
 *   -ENOSYS    — required ksyms (vm_mmap / __do_sys_init_module / ...)
 *                not resolvable
 *   -EFAULT    — copy_to_user staging failed
 *   <other>    — propagated negative errno from __do_sys_init_module
 *                (typically -ENOEXEC, -EINVAL, -EBUSY)
 *
 * This function does NOT manage `kh_pending_ksu_blob`. Callers are
 * responsible for freeing their own buffer regardless of return value.
 *
 * Header is freestanding-safe (no linux header includes).
 */
int kh_call_init_module(const void *buf, unsigned long len,
                        const char *args);

#endif /* KERNELHOOK_KH_CALL_INIT_MODULE_H */
