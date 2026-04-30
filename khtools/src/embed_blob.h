/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KHTOOLS_EMBED_BLOB_H
#define KHTOOLS_EMBED_BLOB_H

#include <stddef.h>
#include <stdint.h>

/* On-disk trailer block layout. khimg's kh_load.c parses this same
 * struct; keep the layout in sync. */
struct kh_blob_table_v1 {
    uint32_t magic;        /* 'K' 'H' 'B' 'L' little-endian = 0x4C42484B */
    uint32_t version;      /* 1 */
    uint32_t fat_off;      /* offset of fat.ko bytes from blob start */
    uint32_t fat_len;
    uint32_t ksu_off;      /* 0 if no KSU */
    uint32_t ksu_len;
    uint8_t  fat_sha256[32];
    uint8_t  ksu_sha256[32];
};

#define KHBL_MAGIC 0x4C42484Bu

/* Concatenate kh_blob_table + fat.ko bytes (+ optional ksu.ko) into a
 * blob suitable for appending to a kernel section. Caller frees *out. */
int kh_make_blob(const uint8_t *fat_ko, size_t fat_len,
                 const uint8_t *ksu_ko, size_t ksu_len,
                 uint8_t **out, size_t *out_len);

#endif /* KHTOOLS_EMBED_BLOB_H */
