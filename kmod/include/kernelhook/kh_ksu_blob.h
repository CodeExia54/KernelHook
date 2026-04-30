/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KERNELHOOK_KH_KSU_BLOB_H
#define KERNELHOOK_KH_KSU_BLOB_H

#include <linux/types.h>

/* Per-pending-blob payload metadata. fat.ko exports a single instance
 * (kh_pending_ksu_blob) that gets populated by khinsmod (--ksu) or the
 * khimg blob loader before try_load_ksu() reads it. */
struct kh_pending_blob {
    void   *data;
    size_t  len;
    u64     flags;
};

#endif /* KERNELHOOK_KH_KSU_BLOB_H */
