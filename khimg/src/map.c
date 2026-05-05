/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Adapted for KernelHook by bmax121, 2026.
 *
 * The page-table walking + paging_init hook logic moved to
 * src/paging_init.S (NDK clang's codegen for the C version hangs
 * kernel after trampoline; hand-written asm sidesteps this).
 *
 * This file now only defines the .map.data slot used by setup1.S
 * map_prepare — the asm in paging_init.S references it via .setup.map
 * relative addressing.
 */

#include <setup.h>

map_data_t map_data __section(.map.data) __aligned(MAP_ALIGN) = {
#ifdef MAP_DEBUG
    .str_fmt_px = "KP: %x-%llx\n",
#endif
};
