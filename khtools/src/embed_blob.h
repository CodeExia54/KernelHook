/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KHTOOLS_EMBED_BLOB_H
#define KHTOOLS_EMBED_BLOB_H

#include <stddef.h>
#include <stdint.h>

/* On-disk trailer layout pulled from the shared header so producers
 * (this file's kh_make_blob) and consumers (cmd_verify, cmd_list,
 * khimg/src/kh_load.c) agree on every byte without duplication. */
#include "kernelhook/kh_blob_table.h"

/* Concatenate kh_blob_table + fat.ko bytes (+ optional ksu.ko) into a
 * blob suitable for appending to a kernel section. Caller frees *out. */
int kh_make_blob(const uint8_t *fat_ko, size_t fat_len,
                 const uint8_t *ksu_ko, size_t ksu_len,
                 uint8_t **out, size_t *out_len);

#endif /* KHTOOLS_EMBED_BLOB_H */
