/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include "embed_blob.h"
#include "sha256.h"

#include <stdlib.h>
#include <string.h>

static void compute_sha256(const uint8_t *in, size_t n, uint8_t out[32])
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, in, n);
    sha256_final(&ctx, out);
}

int kh_make_blob(const uint8_t *fat_ko, size_t fat_len,
                 const uint8_t *ksu_ko, size_t ksu_len,
                 uint8_t **out, size_t *out_len)
{
    if (!fat_ko || fat_len == 0 || !out || !out_len) return -1;

    size_t hdr   = sizeof(struct kh_blob_table_v1);
    size_t total = hdr + fat_len + ksu_len;
    uint8_t *buf = calloc(1, total);
    if (!buf) return -1;

    struct kh_blob_table_v1 *t = (struct kh_blob_table_v1 *)buf;
    t->magic   = KHBL_MAGIC;
    t->version = 1;
    t->fat_off = (uint32_t)hdr;
    t->fat_len = (uint32_t)fat_len;
    memcpy(buf + t->fat_off, fat_ko, fat_len);
    compute_sha256(fat_ko, fat_len, t->fat_sha256);

    if (ksu_ko && ksu_len) {
        t->ksu_off = (uint32_t)(hdr + fat_len);
        t->ksu_len = (uint32_t)ksu_len;
        memcpy(buf + t->ksu_off, ksu_ko, ksu_len);
        compute_sha256(ksu_ko, ksu_len, t->ksu_sha256);
    }

    *out     = buf;
    *out_len = total;
    return 0;
}
