/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khimg path-2 deferred fat.ko loader.
 *
 * khimg fires at _stext, way before kernel_init has a process mm. We
 * cannot call __do_sys_init_module from this context because the
 * syscall body uses copy_from_user, which requires a valid user mm
 * mapping in current. Instead khimg installs an inline hook at
 * __arm64_sys_finit_module: the first time userspace modprobe calls
 * finit_module, the hook fires in process context with mm valid, and
 * runs the same vm_mmap + copy_to_user + sys_init_module dance.
 *
 * Hook trampoline mechanics
 * -------------------------
 * 1. Patch first 4 instructions of the target with an absolute jump
 *    (LDR X17, #8 ; BR X17 ; .quad &kh_lkm_hook_entry). 4 insns is
 *    needed because B-imm26's ±128 MiB range can't reach kh_lkm_hook_entry
 *    in our khimg vmalloc copy (delta ~2 GiB on Linux 6.x).
 * 2. kh_lkm_hook_entry (asm in kh_lkm_hook.S) saves x29/x30/x0, calls
 *    the C handler, gets back the shadow_slot VA, then `br x16` to it.
 * 3. shadow_slot (lives in our khimg .data) executes a copy of the
 *    original 4 instructions, then absolute-jumps back to target+16
 *    so the kernel function continues normally.
 *
 * Known limitation: shadow_slot lives in own khimg's vmalloc copy,
 * which can fall under an L1 BLOCK descriptor with PXN=1 after
 * kernel post-init perm refinement. First hook fire works (block
 * still exec at that point); a later fire may NX-fault. Future
 * work: relocate trampoline+shadow into module_alloc'd memory
 * (when that symbol is exported by the target kernel).
 */

#include <setup.h>
#include <start.h>
#include <ktypes.h>
#include <compiler.h>
#include <baselib.h>
#include "kernelhook/kh_blob_table.h"

extern void kh_lkm_hook_entry(void);

#define KH_MAP_PRIVATE   0x02
#define KH_MAP_ANONYMOUS 0x20
#define KH_PROT_READ     0x1
#define KH_PROT_WRITE    0x2
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
typedef long  (*sys_init_module_pt_regs_f)(const void *pt_regs);
typedef void  (*flush_icache_range_f)(unsigned long start, unsigned long end);
typedef int   (*set_memory_x_f)(unsigned long addr, int numpages);
typedef int   (*set_memory_rw_f)(unsigned long addr, int numpages);
typedef int   (*set_memory_ro_f)(unsigned long addr, int numpages);

/* Absolute branch trampoline (KP base/hook.c::branch_absolute style):
 *   LDR X17, #8     ; load 8 bytes from PC+8 into x17
 *   BR  X17         ; branch to x17
 *   .quad target    ; literal
 * 4 × u32 = 16 bytes. No range limit. x17 is AAPCS64 IP1 — caller-save. */
#define ARM64_LDR_X17_PC8   0x58000051u
#define ARM64_BR_X17        0xD61F0220u
#define ABS_BRANCH_INSN_NUM 4

static inline void kh_arm64_emit_abs_branch(uint32_t *buf, uint64_t target)
{
	buf[0] = ARM64_LDR_X17_PC8;
	buf[1] = ARM64_BR_X17;
	buf[2] = (uint32_t)(target & 0xFFFFFFFFu);
	buf[3] = (uint32_t)(target >> 32);
}

/* Reject prologue insns that depend on PC. We back up the original 4
 * instructions verbatim and re-execute them in the shadow slot at a
 * different VA — any PC-relative insn would compute the wrong address. */
static int kh_arm64_is_pc_dependent(uint32_t insn)
{
	uint32_t top8 = insn >> 24;
	if ((top8 & 0x7C) == 0x14) return 1;          /* B / BL */
	if (top8 == 0x54) return 1;                   /* B.cond */
	if (top8 == 0x34 || top8 == 0x35) return 1;   /* CBZ/CBNZ 32 */
	if (top8 == 0xB4 || top8 == 0xB5) return 1;   /* CBZ/CBNZ 64 */
	if (top8 == 0x36 || top8 == 0x37) return 1;   /* TBZ/TBNZ 32 */
	if (top8 == 0xB6 || top8 == 0xB7) return 1;   /* TBZ/TBNZ 64 */
	if ((top8 & 0x9F) == 0x10) return 1;          /* ADR */
	if ((top8 & 0x9F) == 0x90) return 1;          /* ADRP */
	if (top8 == 0x18 || top8 == 0x58 || top8 == 0x98) return 1;   /* LDR literal */
	if (top8 == 0x1C || top8 == 0x5C || top8 == 0x9C) return 1;
	return 0;
}

struct kh_lkm_state {
	const uint8_t *fat_bytes;
	unsigned long  fat_len;
	unsigned long  hook_target_va;
	uint32_t       original_insns[ABS_BRANCH_INSN_NUM];

	kallsyms_lookup_name_f kallsyms;
	printk_f               printk;
	vm_mmap_f              vm_mmap;
	vm_munmap_f            vm_munmap;
	copy_to_user_f         copy_to_user;
	do_sys_init_module_f   do_sys_init_module;       /* raw ABI: (umod, len, args) */
	sys_init_module_pt_regs_f arm64_sys_init_module; /* arm64 wrapper: (pt_regs *) */
	flush_icache_range_f   flush_icache_range;
	set_memory_x_f         set_memory_x;
	set_memory_rw_f        set_memory_rw;
	set_memory_ro_f        set_memory_ro;

	volatile uint8_t       armed;

	/* Deferred map_backup restore. khimg_main can't restore at boot —
	 * paging_init.S itself lives at map_va and we'd corrupt its return
	 * path. We restore on the first hook fire instead, before the
	 * deferred init_module load runs. */
	unsigned long          map_restore_dst;
	const uint8_t         *map_restore_src;
	unsigned long          map_restore_len;

	/* Shadow slot: 4 original insns (PACIASP→BTI C if needed) + abs
	 * jump back to target+16. 16-byte aligned for icache cleanliness. */
	uint32_t shadow_slot[ABS_BRANCH_INSN_NUM + ABS_BRANCH_INSN_NUM]
		__attribute__((aligned(16)));
};

static struct kh_lkm_state kh_lkm = { 0 };

static int kh_lkm_try_arm(void)
{
	return __atomic_test_and_set(&kh_lkm.armed, __ATOMIC_ACQ_REL);
}

static void kh_lkm_do_load(void)
{
	if (!kh_lkm.fat_bytes || kh_lkm.fat_len == 0) {
		if (kh_lkm.printk)
			kh_lkm.printk("kh: lkm: no fat.ko bytes staged\n");
		return;
	}
	if (!kh_lkm.vm_mmap || !kh_lkm.vm_munmap || !kh_lkm.copy_to_user ||
	    (!kh_lkm.do_sys_init_module && !kh_lkm.arm64_sys_init_module)) {
		if (kh_lkm.printk)
			kh_lkm.printk("kh: lkm: required ksyms missing: "
			              "vm_mmap=%lx vm_munmap=%lx copy_to_user=%lx "
			              "do_sys_init_module=%lx arm64_sys_init_module=%lx\n",
			              (unsigned long)(uintptr_t)kh_lkm.vm_mmap,
			              (unsigned long)(uintptr_t)kh_lkm.vm_munmap,
			              (unsigned long)(uintptr_t)kh_lkm.copy_to_user,
			              (unsigned long)(uintptr_t)kh_lkm.do_sys_init_module,
			              (unsigned long)(uintptr_t)kh_lkm.arm64_sys_init_module);
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

	long rc;
	if (kh_lkm.do_sys_init_module) {
		if (kh_lkm.printk)
			kh_lkm.printk("kh: lkm: invoking __do_sys_init_module(%lx, %lu)\n",
			              uaddr, kh_lkm.fat_len);
		rc = kh_lkm.do_sys_init_module((void __user *)uaddr,
		                               kh_lkm.fat_len,
		                               (const char __user *)uargs);
	} else {
		uint64_t fake_pt_regs[35] = { 0 };
		fake_pt_regs[0] = (uint64_t)uaddr;
		fake_pt_regs[1] = (uint64_t)kh_lkm.fat_len;
		fake_pt_regs[2] = (uint64_t)uargs;
		if (kh_lkm.printk)
			kh_lkm.printk("kh: lkm: invoking __arm64_sys_init_module(pt_regs={%lx,%lu,%lx})\n",
			              uaddr, kh_lkm.fat_len, uargs);
		rc = kh_lkm.arm64_sys_init_module(fake_pt_regs);
	}
	if (kh_lkm.printk)
		kh_lkm.printk("kh: lkm: init_module rc=%ld\n", rc);

	kh_lkm.vm_munmap(uaddr, kh_lkm.fat_len);
	kh_lkm.vm_munmap(uargs, 1);
}

/* Restore original 4 instructions at hook target. Kernel .text is
 * RO post mark_rodata_ro by the time userspace makes a syscall, so
 * we flip RW → patch → RO using set_memory_rw / set_memory_ro
 * (kallsyms-resolved). This makes subsequent syscalls bypass our
 * hook entirely — no more shadow_slot/trampoline traversal, no NX
 * fault risk on later page-perm refinement. */
static void kh_lkm_disarm_trampoline(void)
{
	unsigned long target = kh_lkm.hook_target_va;
	if (!target) return;

	unsigned long target_pg = target & ~(unsigned long)0xFFFu;
	int rc;
	if (kh_lkm.set_memory_rw) {
		rc = kh_lkm.set_memory_rw(target_pg, 1);
		if (kh_lkm.printk && rc)
			kh_lkm.printk("kh: lkm: set_memory_rw(%lx) rc=%d (proceeding)\n",
			              target_pg, rc);
	}

	for (int i = 0; i < ABS_BRANCH_INSN_NUM; i++) {
		*(volatile uint32_t *)(uintptr_t)(target + i * 4) =
			kh_lkm.original_insns[i];
	}
	if (kh_lkm.flush_icache_range)
		kh_lkm.flush_icache_range(target,
		                          target + ABS_BRANCH_INSN_NUM * 4);
	__asm__ volatile("dsb ish; isb" ::: "memory");

	if (kh_lkm.set_memory_ro) {
		rc = kh_lkm.set_memory_ro(target_pg, 1);
		if (kh_lkm.printk && rc)
			kh_lkm.printk("kh: lkm: set_memory_ro(%lx) rc=%d\n",
			              target_pg, rc);
	}

	if (kh_lkm.printk)
		kh_lkm.printk("kh: lkm: trampoline disarmed at %lx\n", target);
}

/* Public setter — khimg_main fills these so we can restore on first
 * hook fire (kernel boot is well past paging_init by then). */
void kh_lkm_set_map_restore(unsigned long dst_va,
                            const uint8_t *src_bytes,
                            unsigned long len)
{
	kh_lkm.map_restore_dst = dst_va;
	kh_lkm.map_restore_src = src_bytes;
	kh_lkm.map_restore_len = len;
}

/* Restore the splatted .setup.map area back to its original kernel
 * bytes. Called from the hook handler on first fire — paging_init has
 * long since returned, but no caller has touched tcp_init_sock yet
 * (first socket() lands a few seconds after first finit_module). */
static void kh_lkm_run_map_restore(void)
{
	unsigned long dst_va = kh_lkm.map_restore_dst;
	const uint8_t *src   = kh_lkm.map_restore_src;
	unsigned long len    = kh_lkm.map_restore_len;
	if (!dst_va || !src || len == 0) return;

	/* Volatile + per-iteration preset deref defeats clang's memcpy
	 * idiom recognition (no libc memcpy in this freestanding binary). */
	volatile uint8_t *dst = (volatile uint8_t *)(uintptr_t)dst_va;
	for (unsigned long i = 0; i < len; i++) {
		dst[i] = src[i];
	}

	if (kh_lkm.flush_icache_range) {
		kh_lkm.flush_icache_range(dst_va, dst_va + len);
	} else {
		__asm__ volatile("dsb ish; ic ialluis; dsb ish; isb"
		                 ::: "memory");
	}

	if (kh_lkm.printk)
		kh_lkm.printk("kh: lkm: restored %lu map_backup bytes at %lx\n",
		              len, dst_va);

	/* One-shot: clear so we don't redo on later hook fires (we disarm
	 * the trampoline anyway, but defense-in-depth). */
	kh_lkm.map_restore_dst = 0;
}

unsigned long kh_lkm_hook_handler(void)
{
	if (!kh_lkm_try_arm()) {
		/* Restore tcp_init_sock area BEFORE doing anything else. The
		 * first socket() in userspace boot will hit it within seconds. */
		kh_lkm_run_map_restore();
		kh_lkm_do_load();
		/* After first fire, restore target's original 4 insns so
		 * subsequent syscalls don't traverse our trampoline /
		 * shadow_slot — those live in own khimg vmalloc which can
		 * NX-fault after kernel post-init perm refinement. */
		kh_lkm_disarm_trampoline();
	}
	return (unsigned long)(uintptr_t)&kh_lkm.shadow_slot[0];
}

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

	kh_lkm.vm_mmap            = (vm_mmap_f)            kallsyms("vm_mmap");
	kh_lkm.vm_munmap          = (vm_munmap_f)          kallsyms("vm_munmap");
	kh_lkm.copy_to_user       = (copy_to_user_f)       kallsyms("_copy_to_user");
	if (!kh_lkm.copy_to_user)
		kh_lkm.copy_to_user = (copy_to_user_f) kallsyms("copy_to_user");
	if (!kh_lkm.copy_to_user)
		kh_lkm.copy_to_user = (copy_to_user_f) kallsyms("__arch_copy_to_user");
	kh_lkm.do_sys_init_module = (do_sys_init_module_f) kallsyms("__do_sys_init_module");
	if (!kh_lkm.do_sys_init_module)
		kh_lkm.do_sys_init_module = (do_sys_init_module_f) kallsyms("__se_sys_init_module");
	if (!kh_lkm.do_sys_init_module)
		kh_lkm.do_sys_init_module = (do_sys_init_module_f) kallsyms("sys_init_module");
	kh_lkm.arm64_sys_init_module =
		(sys_init_module_pt_regs_f) kallsyms("__arm64_sys_init_module");
	kh_lkm.flush_icache_range = (flush_icache_range_f) kallsyms("flush_icache_range");
	if (!kh_lkm.flush_icache_range)
		kh_lkm.flush_icache_range = (flush_icache_range_f) kallsyms("__flush_icache_range");
	kh_lkm.set_memory_x = (set_memory_x_f) kallsyms("set_memory_x");
	kh_lkm.set_memory_rw = (set_memory_rw_f) kallsyms("set_memory_rw");
	kh_lkm.set_memory_ro = (set_memory_ro_f) kallsyms("set_memory_ro");

	unsigned long target = kallsyms("__arm64_sys_finit_module");
	if (!target) target = kallsyms("__arm64_sys_init_module");
	if (!target) target = kallsyms("do_init_module");
	if (!target) target = kallsyms("__arm64_sys_execve");
	if (!target) {
		if (printk)
			printk("kh: lkm: no hook target resolvable, fat.ko deferred indefinitely\n");
		return -1;
	}

	kh_lkm.hook_target_va = target;
	for (int i = 0; i < ABS_BRANCH_INSN_NUM; i++) {
		uint32_t ins = *(volatile uint32_t *)(uintptr_t)(target + i * 4);
		kh_lkm.original_insns[i] = ins;
		if (kh_arm64_is_pc_dependent(ins)) {
			if (printk)
				printk("kh: lkm: target %lx insn[%d]=%x is PC-relative, "
				       "cannot relocate verbatim\n",
				       target, i, ins);
			return -1;
		}
	}

	/* Keep PACIASP/PACIBSP intact in shadow — PAC is PC-independent
	 * (signs x30 with sp + IA/IB key), so re-running it at shadow's VA
	 * produces the same signed value as the target's original PACIASP
	 * would have. Function epilogue's RETAA/RETAB then authenticates
	 * correctly. */
	for (int i = 0; i < ABS_BRANCH_INSN_NUM; i++) {
		kh_lkm.shadow_slot[i] = kh_lkm.original_insns[i];
	}
	kh_arm64_emit_abs_branch(&kh_lkm.shadow_slot[ABS_BRANCH_INSN_NUM],
	                         (uint64_t)target + ABS_BRANCH_INSN_NUM * 4);
	if (kh_lkm.flush_icache_range)
		kh_lkm.flush_icache_range(
			(unsigned long)(uintptr_t)&kh_lkm.shadow_slot[0],
			(unsigned long)(uintptr_t)&kh_lkm.shadow_slot[
				ABS_BRANCH_INSN_NUM + ABS_BRANCH_INSN_NUM]);
	__asm__ volatile("dsb ish; isb" ::: "memory");

	/* Force-set exec perm on the shadow_slot page. Defends against
	 * kernel post-init perm refinement (mark_rodata_ro, BLOCK split,
	 * etc.) that may otherwise NX-mark our khimg vmalloc page. */
	if (kh_lkm.set_memory_x) {
		unsigned long shadow_pg = (unsigned long)(uintptr_t)&kh_lkm.shadow_slot[0]
		                          & ~(unsigned long)0xFFFu;
		int rc = kh_lkm.set_memory_x(shadow_pg, 1);
		if (printk)
			printk("kh: lkm: set_memory_x(shadow_page=%lx) rc=%d\n",
			       shadow_pg, rc);
		/* Also cover the trampoline page (kh_lkm_hook_entry). */
		unsigned long trampoline_pg = (unsigned long)(uintptr_t)&kh_lkm_hook_entry
		                              & ~(unsigned long)0xFFFu;
		if (trampoline_pg != shadow_pg) {
			rc = kh_lkm.set_memory_x(trampoline_pg, 1);
			if (printk)
				printk("kh: lkm: set_memory_x(trampoline_page=%lx) rc=%d\n",
				       trampoline_pg, rc);
		}
	}

	uint32_t tramp_insns[ABS_BRANCH_INSN_NUM];
	kh_arm64_emit_abs_branch(tramp_insns,
	                         (uint64_t)(uintptr_t)&kh_lkm_hook_entry);
	for (int i = 0; i < ABS_BRANCH_INSN_NUM; i++) {
		*(volatile uint32_t *)(uintptr_t)(target + i * 4) = tramp_insns[i];
	}
	if (kh_lkm.flush_icache_range)
		kh_lkm.flush_icache_range(target,
		                          target + ABS_BRANCH_INSN_NUM * 4);
	__asm__ volatile("dsb ish; isb" ::: "memory");

	if (printk) {
		printk("kh: lkm: hook installed at %lx (LDR/BR abs jump) "
		       "shadow=%lx trampoline=%lx target+%d resume\n",
		       target,
		       (unsigned long)(uintptr_t)&kh_lkm.shadow_slot[0],
		       (unsigned long)(uintptr_t)&kh_lkm_hook_entry,
		       ABS_BRANCH_INSN_NUM * 4);
	}
	return 0;
}
