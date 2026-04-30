/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * kh_blob_table.h — on-disk trailer block layout shared by:
 *   - khtools/src/embed_blob.c (host-side; produced by `khtools patch`)
 *   - khtools/src/cmd_verify.c, cmd_list.c (host-side; consumers)
 *   - khimg/src/kh_load.c (freestanding aarch64; reads at boot to load fat.ko)
 *
 * Single-source-of-truth header. If a field is added or its type changes,
 * the version field MUST bump and both producers and consumers must be
 * updated in lockstep. Pinning the layout here prevents the silent drift
 * that would otherwise occur between the host-side ELF tools and the
 * freestanding boot blob.
 *
 * Header is freestanding-clean: only stddef.h + stdint.h, no
 * Linux kernel or OpenSSL dependencies, so it can be included from
 * either build.
 */
#ifndef KERNELHOOK_KH_BLOB_TABLE_H
#define KERNELHOOK_KH_BLOB_TABLE_H

#include <stddef.h>
#include <stdint.h>

struct kh_blob_table_v1 {
	uint32_t magic;        /* 'K' 'H' 'B' 'L' little-endian */
	uint32_t version;      /* must be 1 for this layout */
	uint32_t fat_off;      /* offset of fat.ko bytes from blob start */
	uint32_t fat_len;
	uint32_t ksu_off;      /* 0 if no KSU LKM embedded */
	uint32_t ksu_len;
	uint8_t  fat_sha256[32];
	uint8_t  ksu_sha256[32];
};

/* 'K' 'H' 'B' 'L' little-endian = 0x4C42484B. */
#define KHBL_MAGIC 0x4C42484Bu

#endif /* KERNELHOOK_KH_BLOB_TABLE_H */
