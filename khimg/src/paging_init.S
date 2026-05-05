/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 *
 * Hand-written aarch64 assembly _paging_init + helpers — replaces the
 * map.c C version. NDK clang's codegen for the C version hangs kernel
 * after trampoline; this asm version sidesteps the codegen issues by
 * controlling every instruction.
 *
 * Provides:
 *   _paging_init       — kernel paging_init() trampoline target. Restores
 *                        original paging_init byte, calls original, then
 *                        re-relocates kpimg into a fresh memblock-allocated
 *                        kernel VA range, copies trailer, installs PTEs,
 *                        finally calls start() at the new VA.
 *   get_myva           — returns aligned VA of the calling code.
 *   get_data           — returns map_data ptr (in .map.data).
 *   _kh_mem_proc       — fills map_data buf, applies kernel_va relocations.
 *   _kh_pte_walk       — get_or_create_pte equivalent (4-level walk).
 *
 * Helpers (flush_tlb_all, flush_icache_all) inlined as macros below.
 *
 * map_data_t field offsets (NO MAP_DEBUG) — see include/setup.h.
 */

#define MD_paging_init_backup   0x00
#define MD_map_offset           0x08
#define MD_start_offset         0x10
#define MD_start_size           0x18
#define MD_start_img_size       0x20
#define MD_extra_size           0x28
#define MD_alloc_size           0x30
#define MD_kernel_pa            0x38
#define MD_paging_init_relo     0x40
#define MD_mb_reserve           0x48
#define MD_mb_free              0x50
#define MD_mb_phys_alloc        0x58
#define MD_mb_virt_alloc        0x60
#define MD_mb_mark_nomap        0x68
#define MD_va1_bits             0x70
#define MD_page_shift           0x78
#define MD_kimage_voffset       0x80
#define MD_linear_voffset       0x88
#define MD_map_backup_va        0x90
#define MD_map_backup_len       0x98
#define MD_SIZE                 0xA0   /* with our extra fields */

#define MAP_SYMBOL_SIZE         0x28   /* 5 * 8 bytes */

/* ============================================================== */
/* helpers in .map.text (called via PC-relative BL within section) */
/* ============================================================== */

.section .map.text, "ax"

/* uint64_t get_myva(void) — returns aligned-down VA of this insn.
 * Aligned to 16 (MAP_ALIGN). */
.align 4
.global get_myva
.type get_myva, %function
get_myva:
    adr x0, .
    and x0, x0, #~0xF
    ret
.size get_myva, . - get_myva

/* map_data_t *get_data(void) — returns ptr to map_data (lives at the
 * start of .setup.map runtime location, immediately before .map.text).
 *
 * Must call get_myva so we anchor on the FIRST .map.text function's
 * address (= .map.text start), not get_data's own address. Otherwise
 * the subtract lands inside .map.data padding, not at &map_data. */
.align 4
.global get_data
.type get_data, %function
get_data:
    stp x29, x30, [sp, #-16]!
    bl get_myva
    sub x0, x0, #MD_SIZE
    and x0, x0, #~0xF
    ldp x29, x30, [sp], #16
    ret
.size get_data, . - get_data

/* ============================================================== */
/* _kh_mem_proc — equivalent of C mem_proc.
 * Args: x0 = data (target buf, on stack)
 * Trashes: x1..x18 (caller-save).
 * Side effects: copies map_data, applies kernel_va relocations,
 *               reads tcr_el1, calls memblock_{phys,virt}_alloc to
 *               detect linear_voffset.
 * ============================================================== */
.align 4
.global _kh_mem_proc
.type _kh_mem_proc, %function
_kh_mem_proc:
    stp x29, x30, [sp, #-32]!
    stp x19, x20, [sp, #16]
    mov x29, sp

    mov x19, x0                /* x19 = data (dst) */

    /* x20 = src = get_data() */
    bl get_data
    mov x20, x0

    /* memcpy(data, src, MD_SIZE) — 8-byte loads/stores */
    mov x9, #0
1:  ldr x10, [x20, x9]
    str x10, [x19, x9]
    add x9, x9, #8
    cmp x9, #MD_SIZE
    b.lo 1b

    /* kernel_va = (uint64_t)data_src - data_src->map_offset
     * (use x20 = src, before x20 is reloaded) */
    ldr x9, [x20, #MD_map_offset]
    sub x9, x20, x9            /* x9 = kernel_va */

    /* data->kimage_voffset = kernel_va - data->kernel_pa */
    ldr x10, [x19, #MD_kernel_pa]
    sub x10, x9, x10
    str x10, [x19, #MD_kimage_voffset]

    /* data->paging_init_relo += kernel_va */
    ldr x10, [x19, #MD_paging_init_relo]
    add x10, x10, x9
    str x10, [x19, #MD_paging_init_relo]

    /* Walk map_symbol[5]: each non-zero entry += kernel_va */
    add x10, x19, #MD_mb_reserve   /* &data->map_symbol[0] */
    add x11, x10, #MAP_SYMBOL_SIZE
2:  ldr x12, [x10]
    cbz x12, 3f
    add x12, x12, x9
    str x12, [x10]
3:  add x10, x10, #8
    cmp x10, x11
    b.lo 2b

    /* read tcr_el1 → t1sz = bits[21:16], va1_bits = 64 - t1sz */
    mrs x10, tcr_el1
    lsr x11, x10, #16          /* t1sz at low bits */
    and x11, x11, #0x3F        /* keep 6 bits */
    mov x12, #64
    sub x12, x12, x11
    str x12, [x19, #MD_va1_bits]

    /* tg1 = bits[31:30] of tcr_el1 → page_shift: tg1==1 → 14, ==3 → 16, else 12 */
    lsr x11, x10, #30
    and x11, x11, #3
    mov x12, #12
    cmp x11, #1
    b.ne 4f
    mov x12, #14
    b 5f
4:  cmp x11, #3
    b.ne 5f
    mov x12, #16
5:  str x12, [x19, #MD_page_shift]

    /* detect linear_voffset (mirrors KP base/map.c::mem_proc):
     *   phys = memblock_phys_alloc_try_nid(0, 0x10, NUMA_NO_NODE=-1)
     *   virt = memblock_alloc_try_nid(0, 0x10, phys, phys, -1)
     *   linear_voffset = virt - phys */
    mov x0, #0
    mov x1, #0x10
    mov x2, #-1
    ldr x9, [x19, #MD_mb_phys_alloc]
    blr x9
    mov x20, x0                /* x20 = phys */

    mov x0, #0
    mov x1, #0x10
    mov x2, x20
    mov x3, x20
    mov x4, #-1
    ldr x9, [x19, #MD_mb_virt_alloc]
    blr x9
    /* x0 = virt */

    sub x9, x0, x20
    str x9, [x19, #MD_linear_voffset]

    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #32
    ret
.size _kh_mem_proc, . - _kh_mem_proc

/* ============================================================== */
/* uint64_t _kh_pte_walk(map_data_t *data, uint64_t va, uint64_t pa,
 *                       uint64_t attr_indx)
 *   Returns the VA of the leaf PTE entry. Allocates intermediate page
 *   tables on demand (memblock_phys_alloc + zero).
 *
 *   Args: x0=data, x1=va, x2=pa, x3=attr_indx
 *   Returns: x0 = pxd_entry_va
 *   Trashes: x4..x18
 * ============================================================== */
.align 4
.global _kh_pte_walk
.type _kh_pte_walk, %function
_kh_pte_walk:
    stp x29, x30, [sp, #-128]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]
    mov x29, sp

    mov x19, x0                /* data */
    mov x20, x1                /* va */
    mov x21, x2                /* pa */
    mov x22, x3                /* attr_indx */

    ldr x23, [x19, #MD_page_shift]    /* page_shift */
    ldr x9,  [x19, #MD_va1_bits]      /* va_bits */

    /* page_level = (va_bits - 4) / (page_shift - 3) */
    sub x10, x9, #4
    sub x11, x23, #3
    udiv x24, x10, x11                /* x24 = page_level */

    /* pxd_bits = page_shift - 3 */
    sub x25, x23, #3
    /* pxd_ptrs = 1 << pxd_bits */
    mov x9, #1
    lsl x26, x9, x25                  /* x26 = pxd_ptrs */

    /* baddr = ttbr1_el1 & 0xFFFFFFFFFFFE */
    mrs x9, ttbr1_el1
    movz x10, #0xFFFE, lsl #0
    movk x10, #0xFFFF, lsl #16
    movk x10, #0xFFFF, lsl #32
    movk x10, #0x0000, lsl #48
    and x9, x9, x10                   /* baddr (low 48 bits, & ~1) */

    /* page_size = 1 << page_shift */
    mov x10, #1
    lsl x27, x10, x23                 /* x27 = page_size */
    sub x10, x27, #1
    mvn x10, x10                      /* x10 = ~(page_size - 1) */
    and x9, x9, x10                   /* pxd_pa = baddr & page_size_mask */

    /* x28 = pxd_pa, x9 = pxd_va = phys_to_lm(data, pxd_pa) */
    mov x28, x9
    ldr x10, [x19, #MD_linear_voffset]
    add x9, x28, x10                  /* x9 = pxd_va */
    /* save pxd_va in slot [sp+96] */
    str x9, [sp, #96]

    /* attr_prot = 0x40000000000703 | attr_indx
     * 0x40000000000703 nibbles: 4,0,0,0,0,0,0,0,0,0,0,7,0,3
     * → 0x4 at nibble pos 13 = bit 54 (UXN). 0x40 (bit 6) shifted by 48
     *   gives bit 54. */
    movz x10, #0x0703
    movz x11, #0x0040
    lsl x11, x11, #48
    orr x10, x10, x11
    orr x10, x10, x22                 /* x10 = attr_prot */
    /* save attr_prot in slot [sp+104] */
    str x10, [sp, #104]

    /* pxd_entry_va = 0 — saved on stack [sp+112] */
    str xzr, [sp, #112]

    /* lv = 4 - page_level */
    mov x9, #4
    sub x9, x9, x24                   /* x9 = lv */

.Lloop:
    cmp x9, #4
    b.hs .Lloop_done

    /* pxd_shift = (page_shift - 3) * (4 - lv) + 3 */
    mov x10, #4
    sub x10, x10, x9                  /* 4 - lv */
    mul x10, x25, x10                 /* (page_shift - 3) * (4 - lv) */
    add x10, x10, #3                  /* + 3 = pxd_shift */
    /* save pxd_shift in slot [sp+120] */
    str x10, [sp, #120]

    /* pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1) */
    lsr x11, x20, x10                 /* va >> pxd_shift */
    sub x12, x26, #1                  /* pxd_ptrs - 1 */
    and x11, x11, x12                 /* pxd_index */

    /* pxd_entry_va = pxd_va + pxd_index * 8 */
    ldr x12, [sp, #96]                /* pxd_va */
    add x12, x12, x11, lsl #3
    str x12, [sp, #112]               /* save pxd_entry_va */

    /* pxd_desc = *(uint64_t *)pxd_entry_va */
    ldr x13, [x12]

    /* low 2 bits classify */
    and x14, x13, #0b11

    cmp x14, #0b11
    b.ne .Lcheck_block
    /* table: pxd_pa = pxd_desc & ((1<<(48-page_shift))-1) << page_shift */
    mov x15, #48
    sub x15, x15, x23                 /* 48 - page_shift */
    mov x16, #1
    lsl x16, x16, x15
    sub x16, x16, #1                  /* (1 << (48-ps)) - 1 */
    lsl x16, x16, x23                 /* << page_shift */
    and x28, x13, x16                 /* x28 = pxd_pa */
    mov x17, #0                       /* alloc_flag = 0 */
    mov x18, #0                       /* block_flag = 0 */
    b .Ltail

.Lcheck_block:
    cmp x14, #0b01
    b.ne .Linvalid
    /* block: block_bits = (3 - lv) * pxd_bits + page_shift */
    mov x15, #3
    sub x15, x15, x9                  /* 3 - lv */
    mul x15, x15, x25                 /* * pxd_bits */
    add x15, x15, x23                 /* + page_shift */
    mov x16, #1
    mov x17, #48
    sub x17, x17, x15                 /* 48 - block_bits */
    lsl x16, x16, x17                 /* 1 << (48 - bb) */
    sub x16, x16, #1                  /* - 1 */
    lsl x16, x16, x15                 /* << block_bits */
    and x28, x13, x16
    mov x17, #0                       /* alloc_flag = 0 */
    mov x18, #1                       /* block_flag = 1 */
    b .Ltail

.Linvalid:
    /* invalid: alloc unless lv==3 */
    cmp x9, #3
    b.eq .Linvalid_leaf
    /* alloc intermediate page table.
     * x9 (lv) is caller-save and gets clobbered by BL — stash it in
     * the now-unused pxd_shift slot. Same for any other x10..x18 we
     * still need (none here; x16 is just the function pointer). */
    str x9, [sp, #120]                /* save lv */
    mov x0, x27                       /* page_size */
    mov x1, x27                       /* page_size align */
    mov x2, #0                        /* nid=0 */
    ldr x16, [x19, #MD_mb_phys_alloc]
    blr x16
    ldr x9, [sp, #120]                /* restore lv */
    mov x28, x0                       /* pxd_pa = newly alloc'd */
    mov x17, #1                       /* alloc_flag = 1 */
    b .Ldesc_write

.Linvalid_leaf:
    mov x28, x21                      /* leaf: pxd_pa = pa (caller arg) */
    mov x17, #0                       /* alloc_flag = 0 (don't zero leaf) */

.Ldesc_write:
    /* pxd_desc = pxd_pa | attr_prot; *pxd_entry_va = pxd_desc */
    ldr x10, [sp, #104]               /* attr_prot */
    orr x13, x28, x10
    ldr x12, [sp, #112]               /* pxd_entry_va */
    str x13, [x12]
    mov x18, #0                       /* block_flag = 0 */

.Ltail:
    /* pxd_va = phys_to_lm(data, pxd_pa) = pxd_pa + linear_voffset */
    ldr x10, [x19, #MD_linear_voffset]
    add x10, x28, x10
    str x10, [sp, #96]                /* update pxd_va */

    /* if (alloc_flag) zero new page */
    cbz x17, .Lcheck_block_break
    mov x11, x10
    add x12, x11, x27                 /* end = pxd_va + page_size */
.Lzero:
    cmp x11, x12
    b.hs .Lcheck_block_break
    str xzr, [x11], #8
    b .Lzero

.Lcheck_block_break:
    cbnz x18, .Lloop_done             /* break on block */
    add x9, x9, #1                    /* lv++ */
    b .Lloop

.Lloop_done:
    ldr x0, [sp, #112]                /* return pxd_entry_va */

    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #128
    ret
.size _kh_pte_walk, . - _kh_pte_walk

/* ============================================================== */
/* _paging_init — main orchestrator. Replaces the C version.
 *
 *   1. Allocate stack frame for map_data_t buf
 *   2. Call _kh_mem_proc to populate buf
 *   3. Compute layout vars: old_start_pa, reserve_size, all_size
 *   4. Call memblock_reserve, memblock_phys_alloc, memblock_mark_nomap
 *   5. Restore paging_init's first byte, flush icache, call paging_init
 *   6. _kh_pte_walk(paging_init_relo) → get attr_indx
 *   7. Clear WXN in sctlr_el1
 *   8. For each page: _kh_pte_walk to install RW PTE for new vmalloc area
 *   9. flush_tlb_all
 *  10. Zero new vmalloc area
 *  11. Copy old khimg → new vmalloc
 *  12. Copy trailer → new vmalloc + start_size
 *  13. flush_icache_all (inline asm — code below us is about to be freed)
 *  14. memblock_free
 *  15. Branch to start() at start_va
 * ============================================================== */
.align 4
.global _paging_init
.type _paging_init, %function
_paging_init:
    /* Frame: 0x140 bytes
     *   [sp+0x000, +0x0A0): map_data_t buf
     *   [sp+0x0A0, +0x0A8): start_pa
     *   [sp+0x0A8, +0x0B0): all_size
     *   [sp+0x0B0, +0x0B8): start_va
     *   [sp+0x0B8, +0x0C0): old_start_va
     *   [sp+0x0C0, +0x0C8): attr_indx
     *   [sp+0x0C8, +0x100): scratch / pad
     *   [sp+0x100, +0x140): callee-save reg pairs
     */
    sub sp, sp, #0x140
    stp x19, x20, [sp, #0x100]
    stp x21, x22, [sp, #0x110]
    stp x23, x24, [sp, #0x120]
    stp x29, x30, [sp, #0x130]
    add x29, sp, #0x130

    mov x19, sp                              /* x19 = data (buf) */

    /* mem_proc(data) */
    mov x0, x19
    bl _kh_mem_proc

#ifdef KH_ASM_MID_CUT
    /* MID variant: stop after mem_proc, do paging_init + ret only.
     * Used to bisect which post-mem_proc step is the hang trigger. */
    ldr x22, [x19, #MD_paging_init_relo]
    ldr w9,  [x19, #MD_paging_init_backup]
    str w9,  [x22]
    dsb ish
    ic ialluis
    dsb ish
    isb
    blr x22
    ldp x29, x30, [sp, #0x130]
    ldp x23, x24, [sp, #0x120]
    ldp x21, x22, [sp, #0x110]
    ldp x19, x20, [sp, #0x100]
    add sp, sp, #0x140
    ret
#endif

#ifdef KH_ASM_MID4C_CUT
    /* MID4C: Same as MID4B but DON'T modify *entry. Just call walk
     * once and ret. Bisects walk vs mod step. */
    ldr x9, [x19, #MD_page_shift]
    mov x20, #1
    lsl x20, x20, x9
    ldr x9,  [x19, #MD_start_offset]
    ldr x10, [x19, #MD_kernel_pa]
    add x21, x9, x10
    ldr x9,  [x19, #MD_start_img_size]
    ldr x10, [x19, #MD_extra_size]
    add x22, x9, x10
    ldr x9, [x19, #MD_extra_size]
    sub x10, x20, #1
    add x9,  x9,  x10
    mvn x10, x10
    and x23, x9, x10
    ldr x24, [x19, #MD_start_size]
    add x24, x24, x23
    ldr x9,  [x19, #MD_alloc_size]
    add x24, x24, x9
    str x24, [sp, #0x0A8]
    mov x0, x21
    mov x1, x22
    ldr x9, [x19, #MD_mb_reserve]
    blr x9
    mov x0, x24
    mov x1, x20
    mov x2, #-1
    ldr x9, [x19, #MD_mb_phys_alloc]
    blr x9
    str x0, [sp, #0x0A0]
    mov x21, x0
    ldr x9, [x19, #MD_mb_mark_nomap]
    cbz x9, 3f
    mov x0, x21
    mov x1, x24
    blr x9
3:
    ldr x22, [x19, #MD_paging_init_relo]
    ldr w9,  [x19, #MD_paging_init_backup]
    str w9,  [x22]
    dsb ish
    ic ialluis
    dsb ish
    isb
    blr x22
    mov x0, x19
    mov x1, x22
    mov x2, #0
    mov x3, #0
    bl _kh_pte_walk
    ldr x9, [x0]
    and x9, x9, #0x1C
    str x9, [sp, #0x0C0]
    mrs x10, sctlr_el1
    movz x11, #0x0008, lsl #16
    bic x10, x10, x11
    msr sctlr_el1, x10
    ldr x9, [sp, #0x0A0]
    ldr x10, [x19, #MD_kimage_voffset]
    add x9, x9, x10
    str x9, [sp, #0x0B0]
    /* call _kh_pte_walk for new vmalloc VA but DO NOT modify entry */
    mov x0, x19
    ldr x1, [sp, #0x0B0]
    ldr x2, [sp, #0x0A0]
    ldr x3, [sp, #0x0C0]
    bl _kh_pte_walk
    /* discard return */
    ldp x29, x30, [sp, #0x130]
    ldp x23, x24, [sp, #0x120]
    ldp x21, x22, [sp, #0x110]
    ldp x19, x20, [sp, #0x100]
    add sp, sp, #0x140
    ret
#endif

#ifdef KH_ASM_MID4B_CUT
    /* MID4B: Same as MID4A but only ONE iteration of PTE setup loop. */
    ldr x9, [x19, #MD_page_shift]
    mov x20, #1
    lsl x20, x20, x9
    ldr x9,  [x19, #MD_start_offset]
    ldr x10, [x19, #MD_kernel_pa]
    add x21, x9, x10
    ldr x9,  [x19, #MD_start_img_size]
    ldr x10, [x19, #MD_extra_size]
    add x22, x9, x10
    ldr x9, [x19, #MD_extra_size]
    sub x10, x20, #1
    add x9,  x9,  x10
    mvn x10, x10
    and x23, x9, x10
    ldr x24, [x19, #MD_start_size]
    add x24, x24, x23
    ldr x9,  [x19, #MD_alloc_size]
    add x24, x24, x9
    str x24, [sp, #0x0A8]
    mov x0, x21
    mov x1, x22
    ldr x9, [x19, #MD_mb_reserve]
    blr x9
    mov x0, x24
    mov x1, x20
    mov x2, #-1
    ldr x9, [x19, #MD_mb_phys_alloc]
    blr x9
    str x0, [sp, #0x0A0]
    mov x21, x0
    ldr x9, [x19, #MD_mb_mark_nomap]
    cbz x9, 4f
    mov x0, x21
    mov x1, x24
    blr x9
4:
    ldr x22, [x19, #MD_paging_init_relo]
    ldr w9,  [x19, #MD_paging_init_backup]
    str w9,  [x22]
    dsb ish
    ic ialluis
    dsb ish
    isb
    blr x22
    mov x0, x19
    mov x1, x22
    mov x2, #0
    mov x3, #0
    bl _kh_pte_walk
    ldr x9, [x0]
    and x9, x9, #0x1C
    str x9, [sp, #0x0C0]
    mrs x10, sctlr_el1
    movz x11, #0x0008, lsl #16
    bic x10, x10, x11
    msr sctlr_el1, x10
    ldr x9, [sp, #0x0A0]
    ldr x10, [x19, #MD_kimage_voffset]
    add x9, x9, x10
    str x9, [sp, #0x0B0]
    /* SINGLE iteration of PTE setup */
    mov x0, x19
    ldr x1, [sp, #0x0B0]
    ldr x2, [sp, #0x0A0]
    ldr x3, [sp, #0x0C0]
    bl _kh_pte_walk
    ldr x9, [x0]
    movz x10, #0x0008, lsl #48
    orr x9, x9, x10
    movz x11, #0x0020, lsl #48
    movk x11, #0x0080, lsl #0
    bic x9, x9, x11
    str x9, [x0]
    ldp x29, x30, [sp, #0x130]
    ldp x23, x24, [sp, #0x120]
    ldp x21, x22, [sp, #0x110]
    ldp x19, x20, [sp, #0x100]
    add sp, sp, #0x140
    ret
#endif

#ifdef KH_ASM_MID4A_CUT
    /* MID4A: same as MID4 but WITHOUT flush_tlb_all. Bisects whether
     * the PTE setup loop or flush_tlb_all is the trigger. */
    ldr x9, [x19, #MD_page_shift]
    mov x20, #1
    lsl x20, x20, x9
    ldr x9,  [x19, #MD_start_offset]
    ldr x10, [x19, #MD_kernel_pa]
    add x21, x9, x10
    ldr x9,  [x19, #MD_start_img_size]
    ldr x10, [x19, #MD_extra_size]
    add x22, x9, x10
    ldr x9, [x19, #MD_extra_size]
    sub x10, x20, #1
    add x9,  x9,  x10
    mvn x10, x10
    and x23, x9, x10
    ldr x24, [x19, #MD_start_size]
    add x24, x24, x23
    ldr x9,  [x19, #MD_alloc_size]
    add x24, x24, x9
    str x24, [sp, #0x0A8]
    mov x0, x21
    mov x1, x22
    ldr x9, [x19, #MD_mb_reserve]
    blr x9
    mov x0, x24
    mov x1, x20
    mov x2, #-1
    ldr x9, [x19, #MD_mb_phys_alloc]
    blr x9
    str x0, [sp, #0x0A0]
    mov x21, x0
    ldr x9, [x19, #MD_mb_mark_nomap]
    cbz x9, 5f
    mov x0, x21
    mov x1, x24
    blr x9
5:
    ldr x22, [x19, #MD_paging_init_relo]
    ldr w9,  [x19, #MD_paging_init_backup]
    str w9,  [x22]
    dsb ish
    ic ialluis
    dsb ish
    isb
    blr x22
    mov x0, x19
    mov x1, x22
    mov x2, #0
    mov x3, #0
    bl _kh_pte_walk
    ldr x9, [x0]
    and x9, x9, #0x1C
    str x9, [sp, #0x0C0]
    mrs x10, sctlr_el1
    movz x11, #0x0008, lsl #16
    bic x10, x10, x11
    msr sctlr_el1, x10
    ldr x9, [sp, #0x0A0]
    ldr x10, [x19, #MD_kimage_voffset]
    add x9, x9, x10
    str x9, [sp, #0x0B0]
    mov x22, #0
.Lm4a_pte:
    ldr x9, [sp, #0x0A8]
    cmp x22, x9
    b.hs .Lm4a_pte_done
    mov x0, x19
    ldr x9, [sp, #0x0B0]
    add x1, x9, x22
    ldr x9, [sp, #0x0A0]
    add x2, x9, x22
    ldr x3, [sp, #0x0C0]
    bl _kh_pte_walk
    ldr x9, [x0]
    movz x10, #0x0008, lsl #48
    orr x9, x9, x10
    movz x11, #0x0020, lsl #48
    movk x11, #0x0080, lsl #0
    bic x9, x9, x11
    str x9, [x0]
    add x22, x22, x20
    b .Lm4a_pte
.Lm4a_pte_done:
    ldp x29, x30, [sp, #0x130]
    ldp x23, x24, [sp, #0x120]
    ldp x21, x22, [sp, #0x110]
    ldp x19, x20, [sp, #0x100]
    add sp, sp, #0x140
    ret
#endif

#ifdef KH_ASM_MID4_CUT
    /* MID4: do mem_proc + memblock + paging_init + ktext PTE walk + WXN
     * + PTE setup loop (for new vmalloc) + flush_tlb, then ret. */
    ldr x9, [x19, #MD_page_shift]
    mov x20, #1
    lsl x20, x20, x9
    ldr x9,  [x19, #MD_start_offset]
    ldr x10, [x19, #MD_kernel_pa]
    add x21, x9, x10
    ldr x9,  [x19, #MD_start_img_size]
    ldr x10, [x19, #MD_extra_size]
    add x22, x9, x10
    ldr x9, [x19, #MD_extra_size]
    sub x10, x20, #1
    add x9,  x9,  x10
    mvn x10, x10
    and x23, x9, x10
    ldr x24, [x19, #MD_start_size]
    add x24, x24, x23
    ldr x9,  [x19, #MD_alloc_size]
    add x24, x24, x9
    str x24, [sp, #0x0A8]
    mov x0, x21
    mov x1, x22
    ldr x9, [x19, #MD_mb_reserve]
    blr x9
    mov x0, x24
    mov x1, x20
    mov x2, #-1
    ldr x9, [x19, #MD_mb_phys_alloc]
    blr x9
    str x0, [sp, #0x0A0]
    mov x21, x0
    ldr x9, [x19, #MD_mb_mark_nomap]
    cbz x9, 6f
    mov x0, x21
    mov x1, x24
    blr x9
6:
    ldr x22, [x19, #MD_paging_init_relo]
    ldr w9,  [x19, #MD_paging_init_backup]
    str w9,  [x22]
    dsb ish
    ic ialluis
    dsb ish
    isb
    blr x22
    mov x0, x19
    mov x1, x22
    mov x2, #0
    mov x3, #0
    bl _kh_pte_walk
    ldr x9, [x0]
    and x9, x9, #0x1C
    str x9, [sp, #0x0C0]
    mrs x10, sctlr_el1
    movz x11, #0x0008, lsl #16
    bic x10, x10, x11
    msr sctlr_el1, x10
    ldr x9, [sp, #0x0A0]
    ldr x10, [x19, #MD_kimage_voffset]
    add x9, x9, x10
    str x9, [sp, #0x0B0]
    /* PTE setup loop */
    mov x22, #0
.Lm4_pte:
    ldr x9, [sp, #0x0A8]
    cmp x22, x9
    b.hs .Lm4_pte_done
    mov x0, x19
    ldr x9, [sp, #0x0B0]
    add x1, x9, x22
    ldr x9, [sp, #0x0A0]
    add x2, x9, x22
    ldr x3, [sp, #0x0C0]
    bl _kh_pte_walk
    ldr x9, [x0]
    movz x10, #0x0008, lsl #48
    orr x9, x9, x10
    movz x11, #0x0020, lsl #48
    movk x11, #0x0080, lsl #0
    bic x9, x9, x11
    str x9, [x0]
    add x22, x22, x20
    b .Lm4_pte
.Lm4_pte_done:
    /* flush_tlb_all inline */
    dsb ishst
    tlbi vmalle1is
    dsb ish
    tlbi vmalle1is
    dsb ish
    isb
    ldp x29, x30, [sp, #0x130]
    ldp x23, x24, [sp, #0x120]
    ldp x21, x22, [sp, #0x110]
    ldp x19, x20, [sp, #0x100]
    add sp, sp, #0x140
    ret
#endif

#ifdef KH_ASM_MID3_CUT
    /* MID3: do mem_proc + memblock_reserve/alloc/mark + paging_init +
     * _kh_pte_walk(paging_init_relo) + WXN clear, then ret. Bisects
     * whether _kh_pte_walk or sctlr_el1 mutation is the trigger. */
    /* compute as in MID2 */
    ldr x9, [x19, #MD_page_shift]
    mov x20, #1
    lsl x20, x20, x9
    ldr x9,  [x19, #MD_start_offset]
    ldr x10, [x19, #MD_kernel_pa]
    add x21, x9, x10
    ldr x9,  [x19, #MD_start_img_size]
    ldr x10, [x19, #MD_extra_size]
    add x22, x9, x10
    ldr x9, [x19, #MD_extra_size]
    sub x10, x20, #1
    add x9,  x9,  x10
    mvn x10, x10
    and x23, x9, x10
    ldr x24, [x19, #MD_start_size]
    add x24, x24, x23
    ldr x9,  [x19, #MD_alloc_size]
    add x24, x24, x9
    mov x0, x21
    mov x1, x22
    ldr x9, [x19, #MD_mb_reserve]
    blr x9
    mov x0, x24
    mov x1, x20
    mov x2, #-1
    ldr x9, [x19, #MD_mb_phys_alloc]
    blr x9
    ldr x9, [x19, #MD_mb_mark_nomap]
    cbz x9, 7f
    mov x1, x24
    blr x9
7:
    ldr x22, [x19, #MD_paging_init_relo]
    ldr w9,  [x19, #MD_paging_init_backup]
    str w9,  [x22]
    dsb ish
    ic ialluis
    dsb ish
    isb
    blr x22
    /* _kh_pte_walk for paging_init_relo */
    mov x0, x19
    mov x1, x22
    mov x2, #0
    mov x3, #0
    bl _kh_pte_walk
    ldr x9, [x0]
    and x9, x9, #0x1C
    /* WXN clear */
    mrs x10, sctlr_el1
    movz x11, #0x0008, lsl #16
    bic x10, x10, x11
    msr sctlr_el1, x10
    ldp x29, x30, [sp, #0x130]
    ldp x23, x24, [sp, #0x120]
    ldp x21, x22, [sp, #0x110]
    ldp x19, x20, [sp, #0x100]
    add sp, sp, #0x140
    ret
#endif

#ifdef KH_ASM_MID2_CUT
    /* MID2: also do memblock_reserve + memblock_phys_alloc +
     * memblock_mark_nomap BEFORE paging_init. Bisect: if boots, those
     * three calls are fine; if hangs, one of them is the trigger. */
    /* x20 = page_size = 1 << page_shift */
    ldr x9, [x19, #MD_page_shift]
    mov x20, #1
    lsl x20, x20, x9
    /* x21 = old_start_pa = start_offset + kernel_pa */
    ldr x9,  [x19, #MD_start_offset]
    ldr x10, [x19, #MD_kernel_pa]
    add x21, x9, x10
    /* x22 = reserve_size = start_img_size + extra_size */
    ldr x9,  [x19, #MD_start_img_size]
    ldr x10, [x19, #MD_extra_size]
    add x22, x9, x10
    /* align_extra_size */
    ldr x9, [x19, #MD_extra_size]
    sub x10, x20, #1
    add x9,  x9,  x10
    mvn x10, x10
    and x23, x9, x10
    /* all_size */
    ldr x24, [x19, #MD_start_size]
    add x24, x24, x23
    ldr x9,  [x19, #MD_alloc_size]
    add x24, x24, x9
    /* memblock_reserve */
    mov x0, x21
    mov x1, x22
    ldr x9, [x19, #MD_mb_reserve]
    blr x9
    /* memblock_phys_alloc */
    mov x0, x24
    mov x1, x20
    mov x2, #-1
    ldr x9, [x19, #MD_mb_phys_alloc]
    blr x9
    /* memblock_mark_nomap */
    ldr x9, [x19, #MD_mb_mark_nomap]
    cbz x9, 8f
    mov x1, x24
    blr x9
8:
    /* paging_init + ret */
    ldr x22, [x19, #MD_paging_init_relo]
    ldr w9,  [x19, #MD_paging_init_backup]
    str w9,  [x22]
    dsb ish
    ic ialluis
    dsb ish
    isb
    blr x22
    ldp x29, x30, [sp, #0x130]
    ldp x23, x24, [sp, #0x120]
    ldp x21, x22, [sp, #0x110]
    ldp x19, x20, [sp, #0x100]
    add sp, sp, #0x140
    ret
#endif

    /* x20 = page_size = 1 << page_shift */
    ldr x9, [x19, #MD_page_shift]
    mov x20, #1
    lsl x20, x20, x9

    /* x21 = old_start_pa = start_offset + kernel_pa */
    ldr x9,  [x19, #MD_start_offset]
    ldr x10, [x19, #MD_kernel_pa]
    add x21, x9, x10

    /* x22 = reserve_size = start_img_size + extra_size */
    ldr x9,  [x19, #MD_start_img_size]
    ldr x10, [x19, #MD_extra_size]
    add x22, x9, x10

    /* align_extra_size = (extra_size + page_size - 1) & ~(page_size - 1) */
    ldr x9, [x19, #MD_extra_size]
    sub x10, x20, #1
    add x9,  x9,  x10
    mvn x10, x10
    and x23, x9, x10                          /* x23 = align_extra_size */

    /* all_size = start_size + align_extra_size + alloc_size */
    ldr x24, [x19, #MD_start_size]
    add x24, x24, x23
    ldr x9,  [x19, #MD_alloc_size]
    add x24, x24, x9
    str x24, [sp, #0x0A8]                     /* save all_size */

    /* memblock_reserve(old_start_pa, reserve_size) */
    mov x0, x21
    mov x1, x22
    ldr x9, [x19, #MD_mb_reserve]
    blr x9

    /* start_pa = memblock_phys_alloc_try_nid(all_size, page_size, -1) */
    mov x0, x24
    mov x1, x20
    mov x2, #-1
    ldr x9, [x19, #MD_mb_phys_alloc]
    blr x9
    /* x0 = start_pa */
    str x0, [sp, #0x0A0]                      /* save */
    mov x21, x0                               /* reuse x21 = start_pa */

    /* if (mb_mark_nomap) memblock_mark_nomap(start_pa, all_size) */
    ldr x9, [x19, #MD_mb_mark_nomap]
    cbz x9, 1f
    mov x0, x21
    mov x1, x24
    blr x9
1:
    /* paging_init_va = data->paging_init_relo (already runtime VA) */
    ldr x22, [x19, #MD_paging_init_relo]
    /* *(u32 *)paging_init_va = data->paging_init_backup */
    ldr w9, [x19, #MD_paging_init_backup]
    str w9, [x22]

    /* flush_icache_all (inline) */
    dsb ish
    ic ialluis
    dsb ish
    isb

    /* call original paging_init */
    blr x22

    /* ktext_pte = _kh_pte_walk(data, paging_init_relo, 0, 0) */
    mov x0, x19
    mov x1, x22
    mov x2, #0
    mov x3, #0
    bl _kh_pte_walk
    /* attrs = *(u64 *)pte; attr_indx = attrs & 0b11100 */
    ldr x9, [x0]
    and x9, x9, #0x1C
    str x9, [sp, #0x0C0]                      /* save attr_indx */

    /* clear WXN bit (bit 19) in sctlr_el1 */
    mrs x10, sctlr_el1
    movz x11, #0x0008, lsl #16
    bic x10, x10, x11
    msr sctlr_el1, x10

    /* old_start_va = old_start_pa + linear_voffset */
    ldr x9, [x19, #MD_linear_voffset]
    /* recompute old_start_pa (lost in x21) */
    ldr x10, [x19, #MD_start_offset]
    ldr x11, [x19, #MD_kernel_pa]
    add x10, x10, x11                         /* old_start_pa */
    add x9, x10, x9                           /* old_start_va */
    str x9, [sp, #0x0B8]

    /* start_va = start_pa + kimage_voffset */
    ldr x9, [sp, #0x0A0]                      /* start_pa */
    ldr x10, [x19, #MD_kimage_voffset]
    add x9, x9, x10
    str x9, [sp, #0x0B0]

    /* PTE setup loop:
     *   for off in [0, all_size, page_size):
     *     entry = _kh_pte_walk(data, start_va+off, start_pa+off, attr_indx)
     *     *entry = (*entry | 0x8000000000000) & ~(0x0020000000000080)
     */
    mov x22, #0                               /* off */
.Lpte_loop:
    ldr x9, [sp, #0x0A8]                      /* all_size */
    cmp x22, x9
    b.hs .Lpte_done

    mov x0, x19
    ldr x9, [sp, #0x0B0]
    add x1, x9, x22                           /* start_va+off */
    ldr x9, [sp, #0x0A0]
    add x2, x9, x22                           /* start_pa+off */
    ldr x3, [sp, #0x0C0]                      /* attr_indx */
    bl _kh_pte_walk

    /* mutate entry */
    ldr x9, [x0]
    movz x10, #0x0008, lsl #48
    orr x9, x9, x10
    /* mask = 0x0020000000000080; clear */
    movz x11, #0x0020, lsl #48
    movk x11, #0x0080, lsl #0
    bic x9, x9, x11
    str x9, [x0]

    add x22, x22, x20                         /* off += page_size */
    b .Lpte_loop
.Lpte_done:

    /* flush_tlb_all (inline) */
    dsb ishst
    tlbi vmalle1is
    dsb ish
    tlbi vmalle1is
    dsb ish
    isb

    /* zero new vmalloc area */
    ldr x9, [sp, #0x0B0]                      /* start_va */
    ldr x10, [sp, #0x0A8]                     /* all_size */
    add x10, x9, x10
.Lzero_va:
    cmp x9, x10
    b.hs .Lzero_done
    str xzr, [x9], #8
    b .Lzero_va
.Lzero_done:

    /* copy old khimg → new vmalloc:
     *   for i in [0, start_img_size, 8): *(start_va + i) = *(old_start_va + i)
     */
    mov x22, #0
    ldr x23, [x19, #MD_start_img_size]
    ldr x24, [sp, #0x0B0]                     /* dst = start_va */
    ldr x9,  [sp, #0x0B8]                     /* src = old_start_va */
.Lcopy1:
    cmp x22, x23
    b.hs .Lcopy1_done
    ldr x10, [x9, x22]
    str x10, [x24, x22]
    add x22, x22, #8
    b .Lcopy1
.Lcopy1_done:

    /* copy trailer:
     *   for i in [0, extra_size, 8):
     *     *(start_va + start_size + i) = *(old_start_va + start_img_size + i)
     */
    mov x22, #0
    ldr x23, [x19, #MD_extra_size]
    ldr x10, [x19, #MD_start_size]
    add x24, x24, x10                         /* dst base = start_va + start_size */
    ldr x10, [x19, #MD_start_img_size]
    add x9,  x9, x10                          /* src base = old_start_va + start_img_size */
.Lcopy2:
    cmp x22, x23
    b.hs .Lcopy2_done
    ldr x10, [x9, x22]
    str x10, [x24, x22]
    add x22, x22, #8
    b .Lcopy2
.Lcopy2_done:

    /* flush_icache_all (inline) */
    dsb ish
    ic ialluis
    dsb ish
    isb

    /* memblock_free(old_start_pa, reserve_size)
     * reserve_size = start_img_size + extra_size (not saved in reg) */
    ldr x9,  [x19, #MD_start_offset]
    ldr x10, [x19, #MD_kernel_pa]
    add x0, x9, x10                           /* old_start_pa */
    ldr x9,  [x19, #MD_start_img_size]
    ldr x10, [x19, #MD_extra_size]
    add x1, x9, x10                           /* reserve_size */
    ldr x9, [x19, #MD_mb_free]
    blr x9

    /* call start(kimage_voffset, linear_voffset) at start_va */
    ldr x0, [x19, #MD_kimage_voffset]
    ldr x1, [x19, #MD_linear_voffset]
    ldr x9, [sp, #0x0B0]                      /* start_va */
    blr x9

    /* return to caller (kernel setup_arch) */
    ldp x29, x30, [sp, #0x130]
    ldp x23, x24, [sp, #0x120]
    ldp x21, x22, [sp, #0x110]
    ldp x19, x20, [sp, #0x100]
    add sp, sp, #0x140
    ret
.size _paging_init, . - _paging_init
