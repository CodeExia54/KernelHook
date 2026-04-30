/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khimg path-2 entry: parse the kh_blob_table trailer, find load_module
 * via kallsyms_lookup_name, hand off to it.
 */

#include <setup.h>
#include <start.h>
#include <ktypes.h>
#include <compiler.h>

/* Shared trailer layout — single source of truth so khtools' producer
 * (embed_blob.c) and khimg's consumer agree on every byte. */
#include "kernelhook/kh_blob_table.h"

/*
 * khimg_main — called from start.c with the kimage/linear offsets and the
 * start_preset populated by setup1.S.
 *
 * For the skeleton (Task 4.1) this is intentionally a stub returning 0.
 * Actual blob-parse + load_module wiring lands in Task 4.2 once the
 * kh_blob_table embedding pipeline is in place.
 */
int khimg_main(uint64_t kimage_voffset, uint64_t linear_voffset,
               start_preset_t *preset)
{
    /*
     * Step 1: resolve kallsyms_lookup_name from start_preset.
     *
     * The exact field is:
     *   kernel_va + start_preset.kallsyms_lookup_name_offset
     * where kernel_va = kimage_voffset + start_preset.kernel_pa.
     * As a stub for the skeleton commit, defer actual setup-ctx parsing to
     * the Task 4.2 Discovery task.
     *
     * TODO(task-4.2-followup): implement actual blob parse + load_module
     * call once Task 4.2 lands the kh_blob_table embedding pipeline.
     */
    (void)kimage_voffset;
    (void)linear_voffset;
    (void)preset;
    return 0;
}
