/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khimg path-2 deferred fat.ko loader — trampoline asm.
 *
 * Hook flow:
 *   __arm64_sys_finit_module (or fallback) first 4 bytes →
 *      B kh_lkm_hook_entry          (installed by kh_lkm_install_hook)
 *
 *   kh_lkm_hook_entry:
 *      save x0 (syscall arg = struct pt_regs *) + FP/LR
 *      bl  kh_lkm_hook_handler      ; returns target VA in x0
 *      stash target into x16 (caller-save)
 *      restore x0 + FP/LR
 *      br  x16                       ; resume hooked syscall at its
 *                                    ; (now-restored) first instruction
 *
 * We deliberately preserve only x0 + LR + FP. AArch64 AAPCS64 specifies
 * x1..x18 are caller-save: the syscall entry path that called our
 * hooked function did not expect anything specific in those registers
 * across the call, so the C handler is free to clobber them. Likewise
 * the hooked function's own prologue (now reached via br x16) will
 * re-establish whatever state it needs.
 *
 * Re-entrancy: the C handler uses an atomic test-and-set so only the
 * first-arriving caller does the load. Subsequent callers (a possible
 * race window between hook-fire and self-disarm) take the same path
 * but the handler short-circuits the load.
 */

	.text
	.global kh_lkm_hook_entry
	.type   kh_lkm_hook_entry, %function
kh_lkm_hook_entry:
	stp	x29, x30, [sp, #-16]!
	str	x0,  [sp, #-16]!         /* save syscall arg (16-byte aligned) */

	bl	kh_lkm_hook_handler
	mov	x16, x0                  /* target VA returned by handler */

	ldr	x0,  [sp], #16
	ldp	x29, x30, [sp], #16

	br	x16
	.size   kh_lkm_hook_entry, . - kh_lkm_hook_entry
