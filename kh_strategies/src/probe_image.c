/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include "kh_strategies/strategies.h"

kh_ksymtab_variant_t kh_probe_image_ksymtab(const struct kh_probe_image *img) {
    (void)img;
    /* TODO(task-2.1): real ksymtab variant detection — the algorithm
     * currently lives in tools/kmod_loader/kmod_loader.c and gets carved
     * into kh_strategies in Task 2.1. Until then, return UNKNOWN so the
     * probe report stays honest. */
    return KH_KSYMTAB_UNKNOWN;
}
