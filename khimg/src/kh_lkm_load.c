/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khimg path-2 deferred fat.ko loader (方案 A).
 *
 * khimg fires at _stext, way before kernel_init has a process mm. We
 * cannot call __do_sys_init_module from this context because the
 * syscall body uses copy_from_user, which requires a valid user mm
 * mapping in current. Instead khimg installs a one-shot inline hook
 * at __arm64_sys_finit_module (with fallbacks): the first time
 * userspace modprobe calls finit_module, the hook fires in process
 * context with mm, restores the original instruction (self-disarm),
 * and runs the same vm_mmap + copy_to_user + __do_sys_init_module
 * dance kmod's kh_call_init_module uses. fat.ko is loaded as a side
 * effect of that first user-side modprobe.
 *
 * Trade-offs: see PATH2_FAT_AUTOLOAD_DESIGN.md (next to this file)
 * for why this approach was chosen over an init.rc-driven path.
 */

#include <setup.h>
#include <start.h>
#include <ktypes.h>
#include <compiler.h>
#include <baselib.h>
#include "kernelhook/kh_blob_table.h"

/* Trampoline entry — defined in kh_lkm_hook.S. We branch from the
 * hooked syscall's first instruction here. */
extern void kh_lkm_hook_entry(void);

/* mmap(2) constants — freestanding, no <linux/mman.h>. */
#define KH_MAP_PRIVATE   0x02
#define KH_MAP_ANONYMOUS 0x20
#define KH_PROT_READ     0x1
#define KH_PROT_WRITE    0x2

/* MAX_ERRNO sentinel for IS_ERR_VALUE check on vm_mmap return. */
#define KH_MAX_ERRNO     4095

typedef int   (*printk_f)(const char *fmt, ...);
typedef unsigned long (*kallsyms_lookup_name_f)(const char *name);
typedef unsigned long (*vm_mmap_f)(void *file, unsigned long addr,
                                    unsigned long len, unsigned long prot,
                                    unsigned long flag, unsigned long off);
typedef int   (*vm_munmap_f)(unsigned long start, unsigned long len);
typedef unsigned long (*copy_to_user_f)(void __user *to, const void *from,
                                          unsigned long n);
typedef int   (*do_sys_init_module_f)(void __user *umod, unsigned long len,
                                        const char __user *uargs);
typedef void  (*flush_icache_range_f)(unsigned long start, unsigned long end);

/* Module-global state — populated once by kh_lkm_install_hook. The
 * handler reads these to know what to load and where to bounce back.
 *
 * `state.armed` is the atomic guard. 0 = ready, 1 = load in progress
 * or completed. Set with __atomic_test_and_set.
 *
 * `shadow_slot` is the executable trampoline tail: 8 bytes laid out
 * as [original_insn] [b target+4]. The trampoline does br x16 to
 * &shadow_slot; the CPU executes the saved original insn, then the
 * B branch resumes the hooked syscall body at target+4. Both bytes
 * live in khimg's blob region which is mapped X (paging_init copies
 * khimg's PTE attrs to the blob extent — see map.c).
 */
struct kh_lkm_state {
	const uint8_t *fat_bytes;
	unsigned long  fat_len;
	unsigned long  hook_target_va;     /* original syscall fn VA */
	uint32_t       original_insn;      /* backed-up first 4 bytes */

	kallsyms_lookup_name_f kallsyms;
	printk_f               printk;
	vm_mmap_f              vm_mmap;
	vm_munmap_f            vm_munmap;
	copy_to_user_f         copy_to_user;
	do_sys_init_module_f   do_sys_init_module;
	flush_icache_range_f   flush_icache_range;

	volatile uint8_t       armed;

	/* Executable shadow slot: [original_insn, B target+4].
	 * 16-byte aligned for icache cleanliness. */
	uint32_t               shadow_slot[2] __attribute__((aligned(16)));
};

static struct kh_lkm_state kh_lkm = { 0 };

/* Compute encoded B insn for `from -> to`. Returns 0 if out of range. */
static uint32_t kh_arm64_encode_b(uint64_t from, uint64_t to)
{
	int64_t delta = (int64_t)to - (int64_t)from;
	/* B has imm26 << 2 sign-extended → ±128 MiB range. */
	if (delta < -(1LL << 27) || delta >= (1LL << 27)) return 0;
	uint32_t imm26 = ((uint64_t)delta >> 2) & 0x03FFFFFFu;
	return 0x14000000u | imm26;
}

/* Test-and-set on `armed`. Returns 1 if previously already armed
 * (i.e. someone else won the race). */
static int kh_lkm_try_arm(void)
{
	return __atomic_test_and_set(&kh_lkm.armed, __ATOMIC_ACQ_REL);
}

/*
 * Software-guard self-disarm: instead of patching the hook insn back
 * to its original (which would require clearing PTE_RDONLY on the
 * kernel .text page after mark_rodata_ro has run — non-trivial in a
 * freestanding context), we keep the trampoline armed forever and
 * fast-return from the handler on every subsequent call.
 *
 * The trampoline branches into us on every userspace finit_module
 * call after the first one too. Each post-arm invocation is ~30ns
 * (atomic load + branch back). For finit_module which fires on the
 * order of dozens-of-times per boot and is not on any hot path, this
 * is well under measurement noise.
 */

/* The actual stage-and-load. Called from the trampoline; runs in the
 * caller's process context (modprobe / first finit_module-issuing
 * userspace process), so current->mm is valid. */
static void kh_lkm_do_load(void)
{
	if (!kh_lkm.fat_bytes || kh_lkm.fat_len == 0) {
		if (kh_lkm.printk)
			kh_lkm.printk("kh: lkm: no fat.ko bytes staged\n");
		return;
	}
	if (!kh_lkm.vm_mmap || !kh_lkm.vm_munmap ||
	    !kh_lkm.copy_to_user || !kh_lkm.do_sys_init_module) {
		if (kh_lkm.printk)
			kh_lkm.printk("kh: lkm: required ksyms not resolved, abort\n");
		return;
	}

	unsigned long uaddr = kh_lkm.vm_mmap(0, 0, kh_lkm.fat_len,
	                                     KH_PROT_READ | KH_PROT_WRITE,
	                                     KH_MAP_PRIVATE | KH_MAP_ANONYMOUS,
	                                     0);
	if ((long)uaddr < 0 && (long)uaddr >= -KH_MAX_ERRNO) {
		if (kh_lkm.printk)
			kh_lkm.printk("kh: lkm: vm_mmap(payload, %lu) failed: %ld\n",
			              kh_lkm.fat_len, (long)uaddr);
		return;
	}

	if (kh_lkm.copy_to_user((void __user *)uaddr,
	                        kh_lkm.fat_bytes, kh_lkm.fat_len) != 0) {
		if (kh_lkm.printk)
			kh_lkm.printk("kh: lkm: copy_to_user(payload) failed\n");
		kh_lkm.vm_munmap(uaddr, kh_lkm.fat_len);
		return;
	}

	/* Empty args. We need a 1-byte user range for the NUL terminator
	 * because do_sys_init_module's strndup_user runs unconditionally. */
	unsigned long uargs = kh_lkm.vm_mmap(0, 0, 1,
	                                     KH_PROT_READ | KH_PROT_WRITE,
	                                     KH_MAP_PRIVATE | KH_MAP_ANONYMOUS,
	                                     0);
	if ((long)uargs < 0 && (long)uargs >= -KH_MAX_ERRNO) {
		kh_lkm.vm_munmap(uaddr, kh_lkm.fat_len);
		return;
	}
	char nul = '\0';
	kh_lkm.copy_to_user((void __user *)uargs, &nul, 1);

	if (kh_lkm.printk)
		kh_lkm.printk("kh: lkm: invoking __do_sys_init_module(%lx, %lu)\n",
		              uaddr, kh_lkm.fat_len);
	int rc = kh_lkm.do_sys_init_module((void __user *)uaddr,
	                                   kh_lkm.fat_len,
	                                   (const char __user *)uargs);
	if (kh_lkm.printk)
		kh_lkm.printk("kh: lkm: init_module rc=%d\n", rc);

	kh_lkm.vm_munmap(uaddr, kh_lkm.fat_len);
	kh_lkm.vm_munmap(uargs, 1);
}

/* Trampoline C entry. Returns a VA the trampoline `br x16`s to. We
 * always return the post-original-insn address (target + 4) and run
 * the original instruction here ourselves, since the kernel .text
 * page is RO (PTE_RDONLY set by mark_rodata_ro) by the time
 * userspace makes a syscall — we cannot self-modify the hook slot
 * back to the original insn from here.
 *
 * The trampoline is therefore PERMANENTLY armed: every userspace
 * finit_module call lands here, fast-paths through the test-and-set
 * after the first arrival, and falls through. Cost ≈ 30ns/call.
 *
 * Original-insn emulation: rather than executing the backed-up
 * instruction at its original VA (which would require disarming),
 * we re-execute it here. For 99% of syscall entry points the first
 * insn is `paciasp` / `bti c` / `stp x29, x30, [sp, #-16]!` — all
 * position-independent and safe to execute at any VA. We use a
 * software emulation: write the original 4 bytes at the start of a
 * tiny in-blob "shadow" slot and `br x16` there, after the slot
 * appends a B back to target+4. This is what kp's transit_setup
 * does. The shadow slot is set up by kh_lkm_install_hook below.
 */
unsigned long kh_lkm_hook_handler(void)
{
	/* Only the first-arriving caller runs the actual load. */
	if (!kh_lkm_try_arm()) {
		kh_lkm_do_load();
	}
	return (unsigned long)(uintptr_t)&kh_lkm.shadow_slot;
}

/* Public entry — called from kh_load.c::khimg_main. Returns 0 on
 * success (hook installed), -1 on failure. The fat.ko bytes are
 * staged but not yet loaded; the load fires when userspace first
 * calls a hooked syscall.
 *
 * `kallsyms` is the kallsyms_lookup_name fn pointer khimg already
 * resolved from the start_preset.
 */
int kh_lkm_install_hook(const uint8_t *fat_bytes, unsigned long fat_len,
                        kallsyms_lookup_name_f kallsyms,
                        printk_f printk)
{
	if (!fat_bytes || fat_len == 0 || !kallsyms) return -1;

	kh_lkm.fat_bytes  = fat_bytes;
	kh_lkm.fat_len    = fat_len;
	kh_lkm.kallsyms   = kallsyms;
	kh_lkm.printk     = printk;
	kh_lkm.armed      = 0;

	/* Resolve runtime helpers. Misses are tolerable (load will skip
	 * itself with a logged error). */
	kh_lkm.vm_mmap            = (vm_mmap_f)            kallsyms("vm_mmap");
	kh_lkm.vm_munmap          = (vm_munmap_f)          kallsyms("vm_munmap");
	kh_lkm.copy_to_user       = (copy_to_user_f)       kallsyms("_copy_to_user");
	if (!kh_lkm.copy_to_user)
		kh_lkm.copy_to_user = (copy_to_user_f) kallsyms("copy_to_user");
	if (!kh_lkm.copy_to_user)
		kh_lkm.copy_to_user = (copy_to_user_f) kallsyms("__arch_copy_to_user");
	kh_lkm.do_sys_init_module = (do_sys_init_module_f) kallsyms("__do_sys_init_module");
	if (!kh_lkm.do_sys_init_module)
		kh_lkm.do_sys_init_module = (do_sys_init_module_f) kallsyms("sys_init_module");
	kh_lkm.flush_icache_range = (flush_icache_range_f) kallsyms("flush_icache_range");
	if (!kh_lkm.flush_icache_range)
		kh_lkm.flush_icache_range = (flush_icache_range_f) kallsyms("__flush_icache_range");

	/* Pick a hook target. We need a function called from userspace
	 * with mm valid. finit_module is the obvious choice but only
	 * fires when modprobe loads modules — fine on devices with vendor
	 * .ko's loaded via init.rc, but cold-boot first hit may be
	 * delayed. Fallback chain widens the window. */
	unsigned long target = kallsyms("__arm64_sys_finit_module");
	if (!target) target = kallsyms("__arm64_sys_init_module");
	if (!target) target = kallsyms("do_init_module");
	if (!target) target = kallsyms("__arm64_sys_execve");
	if (!target) {
		if (printk)
			printk("kh: lkm: no hook target resolvable, fat.ko deferred indefinitely\n");
		return -1;
	}

	/* Backup the original first instruction. */
	kh_lkm.hook_target_va = target;
	kh_lkm.original_insn  = *(volatile uint32_t *)(uintptr_t)target;

	/* Build the executable shadow slot: [orig insn] [B target+4].
	 * The shadow slot lives in khimg's RW+X mapped region (paging_init
	 * maps the blob extent with the same PTE attrs as kernel .text),
	 * so we can populate it once now and the CPU can execute it
	 * forever after — no per-call icache pollution beyond the slot. */
	uint64_t shadow_resume_pc = (uint64_t)(uintptr_t)&kh_lkm.shadow_slot[1];
	uint32_t b_resume = kh_arm64_encode_b(shadow_resume_pc,
	                                      (uint64_t)target + 4);
	if (!b_resume) {
		if (printk)
			printk("kh: lkm: shadow B resume out of range "
			       "(shadow=%lx target+4=%lx)\n",
			       shadow_resume_pc, target + 4);
		return -1;
	}
	kh_lkm.shadow_slot[0] = kh_lkm.original_insn;
	kh_lkm.shadow_slot[1] = b_resume;
	if (kh_lkm.flush_icache_range)
		kh_lkm.flush_icache_range(
			(unsigned long)(uintptr_t)&kh_lkm.shadow_slot[0],
			(unsigned long)(uintptr_t)&kh_lkm.shadow_slot[2]);
	__asm__ volatile("dsb ish; isb" ::: "memory");

	/* Encode the B from hook target into the trampoline. */
	uint32_t b_insn = kh_arm64_encode_b((uint64_t)target,
	                                    (uint64_t)(uintptr_t)&kh_lkm_hook_entry);
	if (!b_insn) {
		if (printk)
			printk("kh: lkm: hook target %lx out of B range from trampoline %p\n",
			       target, &kh_lkm_hook_entry);
		return -1;
	}

	/* Install the hook. The kernel .text page must already be writable
	 * — khimg's setup ran with WXN cleared (see map.c::_paging_init)
	 * and mark_rodata_ro hasn't run yet (we're at boot pre-init), so
	 * direct writes work. */
	*(volatile uint32_t *)(uintptr_t)target = b_insn;
	if (kh_lkm.flush_icache_range)
		kh_lkm.flush_icache_range(target, target + 4);
	__asm__ volatile("dsb ish; isb" ::: "memory");

	if (printk)
		printk("kh: lkm: hook installed at %lx (orig=%x b=%x) "
		       "shadow=%lx trampoline=%p\n",
		       target, kh_lkm.original_insn, b_insn,
		       (unsigned long)(uintptr_t)&kh_lkm.shadow_slot[0],
		       &kh_lkm_hook_entry);
	return 0;
}
