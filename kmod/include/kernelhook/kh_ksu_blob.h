/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KERNELHOOK_KH_KSU_BLOB_H
#define KERNELHOOK_KH_KSU_BLOB_H

#include <stddef.h>
#include <stdint.h>

/* Per-pending-blob payload metadata. fat.ko owns a single instance
 * (kh_pending_ksu_blob) that gets populated by khinsmod (--ksu) or the
 * khimg blob loader before try_load_ksu() reads it.
 *
 * uint*_t (project core types.h) instead of u*_t (kernel-only alias the
 * freestanding shim doesn't provide). */
struct kh_pending_blob {
    void    *data;
    size_t   len;
    uint64_t flags;
};

#endif /* KERNELHOOK_KH_KSU_BLOB_H */
