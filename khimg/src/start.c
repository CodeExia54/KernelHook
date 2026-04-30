/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2023 bmax121. All Rights Reserved. */
/* Adapted for KernelHook by bmax121, 2026 — slim form: no hotpatch, no
 * fphook, no self-rolled module loader. Just KP setup handoff + load_module
 * call to bring fat.ko online. */

#include <setup.h>
#include <start.h>
#include <ktypes.h>
#include <compiler.h>

extern int khimg_main(uint64_t kimage_voffset, uint64_t linear_voffset,
                      start_preset_t *preset);

/* start_preset is placed by the linker in .kp.data (same as KP's start.c).
 * setup1.S sets up start_preset before map.c's _paging_init relocates us
 * and calls start(). */
start_preset_t start_preset __attribute__((section(".start.data")));

/*
 * map.c invokes us as: ((start_f)start_va)(kimage_voffset, linear_voffset)
 * where start_f = int (*)(uint64_t, uint64_t).
 * Must be in .start.text so the linker script places it at _kp_start.
 */
int __attribute__((section(".start.text"))) __noinline
start(uint64_t kimage_voff, uint64_t linear_voff)
{
    return khimg_main(kimage_voff, linear_voff, &start_preset);
}
