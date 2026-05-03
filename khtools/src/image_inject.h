/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/* Adapted for KernelHook by bmax121, 2026 — host-side hook injection
 * port of KernelPatch tools/{image,common,symbol}.c, simplified for
 * arm64 little-endian targets only (Android GKI). */
#ifndef KH_IMAGE_INJECT_H
#define KH_IMAGE_INJECT_H

#include <stddef.h>
#include <stdint.h>
#include "kallsym.h"

struct kh_kernel_info {
    int32_t is_uefi;             /* 1 if "MZ" signature present */
    int32_t b_stext_insn_offset; /* 0 or 4 — where the boot B lives */
    int32_t primary_entry_offset;
    int64_t load_offset;
    int64_t kernel_size;
    int32_t page_shift;
};

/* Parse the arm64 kernel image header. Returns 0 on success, -1 on bad
 * magic / endianness mismatch. */
int kh_get_kernel_info(struct kh_kernel_info *out,
                       const uint8_t *img, size_t imglen);

/* Patch khdr->kernel_size_le to the new size. */
int kh_kernel_resize(uint8_t *img, size_t imglen, int64_t new_size);

/* Write an arm64 unconditional B at buf, branching from `from` to `to`
 * (both byte addresses within the same image). Returns 4 on success, 0
 * on out-of-range (>128MiB). */
int kh_arm64_b(uint32_t *buf, uint64_t from, uint64_t to);

/* If img[func_offset] is a B insn, follow it once and return the resolved
 * offset; otherwise return func_offset. Mirrors KP relo_branch_func. */
int32_t kh_relo_branch_func(const uint8_t *img, int32_t func_offset);

/* Find the map_area (NOPed PAC region used by khimg's _paging_init) and
 * NOP the PAC pairs. img_buf MUST be writable. */
int kh_select_map_area(kallsym_t *info, uint8_t *img_buf,
                       int32_t *map_start, int32_t *max_size);

/* Resolve the 5 memblock_* symbols into a 5-uint64 buffer matching khimg's
 * map_symbol_t layout. `out` must point to at least 40 bytes. Returns 0 on
 * success, -1 if a required symbol is missing. */
int kh_fillin_map_symbol(kallsym_t *info, const uint8_t *img,
                         uint8_t out[40]);

/* High-level pipeline: take a freshly-unpacked kernel buffer + khimg image
 * + kh_blob_table trailer, produce a new kernel buffer with:
 *   - 4K-aligned kernel | khimg | blob layout
 *   - setup_preset_t at (out + align_kimg_len + 0x40) fully populated
 *   - kernel _stext first B redirected to (align_kimg_len + 0x1000)
 *
 * On success: *out_buf is malloc'd (caller frees), *out_len set, returns 0.
 * On failure: returns -1 and sets *out_buf=NULL.
 */
int kh_image_inject(const uint8_t *kernel, size_t kernel_len,
                    const uint8_t *khimg,  size_t khimg_len,
                    const uint8_t *blob,   size_t blob_len,
                    uint8_t **out_buf, size_t *out_len);

#endif /* KH_IMAGE_INJECT_H */
