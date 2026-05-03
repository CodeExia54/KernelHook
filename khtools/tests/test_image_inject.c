/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/* Unit tests for image_inject — pure-logic helpers; no fixture needed. */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../src/image_inject.h"

static void test_arm64_b_basic(void)
{
    uint32_t buf = 0;
    int rc = kh_arm64_b(&buf, 0x100, 0x1000);
    assert(rc == 4);
    /* (0x1000 - 0x100) >> 2 = 0xF00 / 4 = 0x3C0 */
    uint32_t expect = 0x14000000u | 0x000003C0u;
    assert(buf == expect);
}

static void test_arm64_b_backwards(void)
{
    uint32_t buf = 0;
    int rc = kh_arm64_b(&buf, 0x1000, 0x100);
    assert(rc == 4);
    /* delta = 0x100 - 0x1000 = -0xF00 → masked to 0x0FFFF100 → >>2 = 0x03FFFC40 */
    uint64_t delta = (uint64_t)((int64_t)0x100 - (int64_t)0x1000);
    uint32_t expect = 0x14000000u | (uint32_t)((delta & 0x0FFFFFFFu) >> 2u);
    assert(buf == expect);

    /* Sanity: top 6 bits of insn must be 0b000101 (B opcode). */
    assert((buf & 0xFC000000u) == 0x14000000u);
}

static void test_arm64_b_out_of_range(void)
{
    uint32_t buf = 0xDEADBEEFu;
    int rc = kh_arm64_b(&buf, 0, 0x10000000); /* 256 MiB > 128 MiB limit */
    assert(rc == 0);
    /* Buffer must remain untouched on failure. */
    assert(buf == 0xDEADBEEFu);
}

static void test_relo_branch_func_no_b(void)
{
    /* MOV X0, X1 — encoding 0xAA0103E0 (top bits != B). */
    uint8_t img[16] = {0};
    uint32_t mov = 0xAA0103E0u;
    memcpy(img + 4, &mov, 4);
    int32_t rc = kh_relo_branch_func(img, 4);
    assert(rc == 4);
}

static void test_relo_branch_func_with_b(void)
{
    /* B +0x1000 at offset 8: insn = 0x14000000 | (0x1000 >> 2) = 0x14000400 */
    uint8_t img[8192] = {0};
    uint32_t insn = 0x14000000u | (uint32_t)(0x1000u >> 2);
    memcpy(img + 8, &insn, 4);
    int32_t rc = kh_relo_branch_func(img, 8);
    assert(rc == 8 + 0x1000);
}

static void test_relo_branch_func_with_b_backward(void)
{
    /* B -0x10 at offset 0x100. delta = -0x10, imm26 = (-0x10 & 0x0FFFFFFF) >> 2. */
    uint8_t img[0x1000] = {0};
    int64_t delta = -0x10;
    uint32_t imm26 = (uint32_t)((uint64_t)delta & 0x0FFFFFFFu) >> 2;
    uint32_t insn = 0x14000000u | imm26;
    memcpy(img + 0x100, &insn, 4);
    int32_t rc = kh_relo_branch_func(img, 0x100);
    assert(rc == 0x100 - 0x10);
}

/* Build a minimal arm64 image header at the head of a buffer. */
static void make_header(uint8_t *buf, int uefi,
                        uint64_t kernel_size_le, uint64_t flag_le)
{
    /* Layout matches kh_arm64_hdr_t (offsets):
     *   0  : 4 bytes "MZ" + 4 bytes b_insn (uefi)  OR  4 bytes b_insn + 4 reserved
     *   8  : kernel_offset
     *   16 : kernel_size_le
     *   24 : kernel_flag_le
     *   32 : reserved0
     *   40 : reserved1
     *   48 : reserved2
     *   56 : magic[4] = "ARM\x64"
     *   60 : pe_offset (low 4) — full 64 bits at 60..67
     */
    memset(buf, 0, 64);
    if (uefi) {
        buf[0] = 'M';
        buf[1] = 'Z';
        /* b_insn at offset 4 — encode B to offset 0x40. */
        uint32_t b_insn = 0x14000000u | (uint32_t)((0x40u - 4u) >> 2u);
        memcpy(buf + 4, &b_insn, 4);
    } else {
        /* b_insn at offset 0 — encode B to offset 0x40. */
        uint32_t b_insn = 0x14000000u | (uint32_t)(0x40u >> 2u);
        memcpy(buf, &b_insn, 4);
    }
    memcpy(buf + 16, &kernel_size_le, 8);
    memcpy(buf + 24, &flag_le, 8);
    memcpy(buf + 56, "ARM\x64", 4);
}

static void test_get_kernel_info_minimal(void)
{
    uint8_t buf[128] = {0};
    make_header(buf, /*uefi=*/0, /*kernel_size=*/0x10000ULL, /*flag=*/0x1ULL);
    /* flag = 0b001 → page_shift defaults to 12 (4K), is_be=1?
     * Actually flag bit 0 is endian (1 = BE). 0x1 → is_be=1 → reject.
     * Use 0x2 instead: bit0=0 (LE), bits[2:1]=01 → 4K page. */
    make_header(buf, 0, 0x10000ULL, 0x2ULL);

    struct kh_kernel_info kinfo;
    int rc = kh_get_kernel_info(&kinfo, buf, sizeof(buf));
    assert(rc == 0);
    assert(kinfo.is_uefi == 0);
    assert(kinfo.b_stext_insn_offset == 0);
    assert(kinfo.kernel_size == 0x10000);
    assert(kinfo.page_shift == 12);
    /* primary_entry: B from 0 to 0x40 → primary_entry_offset = 0x40. */
    assert(kinfo.primary_entry_offset == 0x40);
}

static void test_get_kernel_info_uefi(void)
{
    uint8_t buf[128] = {0};
    make_header(buf, 1, 0x20000ULL, 0x2ULL);

    struct kh_kernel_info kinfo;
    int rc = kh_get_kernel_info(&kinfo, buf, sizeof(buf));
    assert(rc == 0);
    assert(kinfo.is_uefi == 1);
    assert(kinfo.b_stext_insn_offset == 4);
    assert(kinfo.kernel_size == 0x20000);
    /* primary_entry: B from offset 4 to 0x40 → offset 0x40 - 4 imm + b_stext = 0x40. */
    assert(kinfo.primary_entry_offset == 0x40);
}

static void test_get_kernel_info_bad_magic(void)
{
    uint8_t buf[128] = {0};
    make_header(buf, 0, 0x10000ULL, 0x2ULL);
    /* Corrupt the ARM64 magic. */
    memcpy(buf + 56, "XXXX", 4);

    struct kh_kernel_info kinfo;
    int rc = kh_get_kernel_info(&kinfo, buf, sizeof(buf));
    assert(rc == -1);
}

static void test_get_kernel_info_be_rejected(void)
{
    /* flag bit0 = 1 → big-endian → must be rejected. */
    uint8_t buf[128] = {0};
    make_header(buf, 0, 0x10000ULL, 0x3ULL); /* bit0=1 (BE), bit2:1=01 (4K) */

    struct kh_kernel_info kinfo;
    int rc = kh_get_kernel_info(&kinfo, buf, sizeof(buf));
    assert(rc == -1);
}

static void test_get_kernel_info_16k_page(void)
{
    /* flag bits[2:1] = 10 → 16K page (shift=14). */
    uint8_t buf[128] = {0};
    make_header(buf, 0, 0x10000ULL, 0x4ULL); /* bit0=0 LE, bit2:1=10 */

    struct kh_kernel_info kinfo;
    int rc = kh_get_kernel_info(&kinfo, buf, sizeof(buf));
    assert(rc == 0);
    assert(kinfo.page_shift == 14);
}

static void test_kernel_resize(void)
{
    uint8_t buf[128] = {0};
    make_header(buf, 0, 0x10000ULL, 0x2ULL);
    int rc = kh_kernel_resize(buf, sizeof(buf), 0x80000);
    assert(rc == 0);
    uint64_t new_size = 0;
    memcpy(&new_size, buf + 16, 8);
    assert(new_size == 0x80000);
}

int main(void)
{
    test_arm64_b_basic();
    test_arm64_b_backwards();
    test_arm64_b_out_of_range();
    test_relo_branch_func_no_b();
    test_relo_branch_func_with_b();
    test_relo_branch_func_with_b_backward();
    test_get_kernel_info_minimal();
    test_get_kernel_info_uefi();
    test_get_kernel_info_bad_magic();
    test_get_kernel_info_be_rejected();
    test_get_kernel_info_16k_page();
    test_kernel_resize();
    fprintf(stderr, "test_image_inject: 12/12 OK\n");
    return 0;
}
