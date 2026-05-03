/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * Host-side ctest for kmod/loader subset port.
 *
 * Verifies the two pure routines:
 *   - kh_aarch64_insn_encode_immediate (insn.c subset)
 *   - kh_apply_relocate_add            (relo.c full port)
 *
 * No kernel headers, no kallsyms — these are environment-agnostic
 * functions and must produce the same bit-exact output anywhere.
 *
 * Build env macro: KH_LOADER_UNITTEST.
 */

#define KH_LOADER_UNITTEST 1

#include "../kh_loader.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int failures = 0;

#define EXPECT_EQ(a, b, label) do {                                            \
        unsigned long long _a = (unsigned long long)(a);                       \
        unsigned long long _b = (unsigned long long)(b);                       \
        if (_a != _b) {                                                        \
            fprintf(stderr, "[FAIL] %s: %s got 0x%llx, want 0x%llx\n",         \
                    __func__, (label), _a, _b);                                \
            failures++;                                                        \
        } else {                                                               \
            fprintf(stderr, "[ok]   %s: %s = 0x%llx\n",                        \
                    __func__, (label), _a);                                    \
        }                                                                      \
    } while (0)

/* ---------------------------------------------------------------------- */
/* insn: immediate encoder spot-checks.                                   */
/* ---------------------------------------------------------------------- */

static void test_insn_imm_12(void)
{
    /* IMM_12 occupies bits [10:21]. Splice 0xabc into a zeroed insn. */
    uint32_t got = kh_aarch64_insn_encode_immediate(KH_AARCH64_INSN_IMM_12,
                                                    0u, 0xabcULL);
    EXPECT_EQ(got, ((uint32_t)0xabc) << 10, "IMM_12 splice into zero insn");
}

static void test_insn_imm_19(void)
{
    /* IMM_19 occupies bits [5:23]. */
    uint32_t got = kh_aarch64_insn_encode_immediate(KH_AARCH64_INSN_IMM_19,
                                                    0u, 0x1234ULL);
    EXPECT_EQ(got, ((uint32_t)0x1234) << 5, "IMM_19 splice");
}

static void test_insn_imm_26(void)
{
    /* IMM_26 occupies bits [0:25]. */
    uint32_t got = kh_aarch64_insn_encode_immediate(KH_AARCH64_INSN_IMM_26,
                                                    0u, 0x0001234ULL);
    EXPECT_EQ(got, (uint32_t)0x0001234, "IMM_26 splice");
}

static void test_insn_imm_overwrite(void)
{
    /* IMM_12 should clear the existing field, not OR over it. */
    uint32_t base = (uint32_t)0xfff << 10;     /* all-ones in IMM_12 slot */
    uint32_t got  = kh_aarch64_insn_encode_immediate(KH_AARCH64_INSN_IMM_12,
                                                     base, 0x100ULL);
    EXPECT_EQ(got, ((uint32_t)0x100) << 10, "IMM_12 overwrite clears prior bits");
}

static void test_insn_imm_adr(void)
{
    /* ADR encoding splits 21-bit imm: low 2 bits at [29:30], high 19 at [5:23]. */
    /* Pick imm = 0x1003 → immlo=3 (bits [1:0]), immhi=0x400 ... actually
     * imm shifts >>2 first per spec. For imm=0x100003:
     *   immlo = 0x100003 & 0x3 = 0x3
     *   imm >>= 2 → 0x40000
     *   immhi = 0x40000 & 0x7ffff = 0x40000
     * combined = (immlo << 24) | immhi = 0x03000000 | 0x40000 = 0x03040000
     * shifted left 5 → 0x60800000 */
    uint32_t got = kh_aarch64_insn_encode_immediate(KH_AARCH64_INSN_IMM_ADR,
                                                    0u, 0x100003ULL);
    EXPECT_EQ(got, 0x60800000u, "IMM_ADR splice");
}

/* ---------------------------------------------------------------------- */
/* relo: build a tiny in-memory ELF section table and verify each relocator */
/* writes the right bytes/instruction.                                    */
/* ---------------------------------------------------------------------- */

/* AArch64 RELA type constants used in tests. */
#define R_ABS64                 257
#define R_PREL32                261
#define R_CALL26                283
#define R_JUMP26                282
#define R_ABS32                 258
#define R_ADR_PREL_PG_HI21      275
#define R_ADD_ABS_LO12_NC       277

#define ELF64_R_INFO(sym, type) (((uint64_t)(sym) << 32) | ((type) & 0xffffffff))

static uint64_t pack_rela_info(uint32_t sym, uint32_t type)
{
    return ELF64_R_INFO(sym, type);
}

/* Set up a minimal sechdrs[] with three sections:
 *   [0] = null
 *   [1] = .text          (target of the relocation)
 *   [2] = .symtab
 *   [3] = .rela.text     (the RELA entries)
 *
 * Symbol table has 2 entries: undef (resolved by caller) at idx 0,
 * a defined "external" at idx 1 with st_value = exernal_addr.
 */
static void test_reloc_abs64(void)
{
    /* .text holds 8 bytes that get rewritten to abs64 of sym->st_value + addend. */
    uint64_t text_bytes = 0;
    struct kh_elf64_sym syms[2] = {0};
    struct kh_elf64_rela rels[1] = {0};
    struct kh_elf64_shdr shdrs[4] = {0};

    syms[1].st_value = 0x1234567890abcdefULL;

    rels[0].r_offset = 0;
    rels[0].r_info   = pack_rela_info(1, R_ABS64);
    rels[0].r_addend = 0x10;

    shdrs[1].sh_addr = (uint64_t)(uintptr_t)&text_bytes;
    shdrs[1].sh_size = sizeof(text_bytes);

    shdrs[2].sh_addr = (uint64_t)(uintptr_t)syms;
    shdrs[2].sh_size = sizeof(syms);

    shdrs[3].sh_addr = (uint64_t)(uintptr_t)rels;
    shdrs[3].sh_size = sizeof(rels);
    shdrs[3].sh_info = 1;  /* applies to section 1 (.text) */
    shdrs[3].sh_link = 2;  /* uses symtab in section 2 */

    int rc = kh_apply_relocate_add(shdrs, /*strtab*/"", /*symindex*/2, /*relsec*/3);
    EXPECT_EQ(rc, 0, "ABS64 reloc rc");
    EXPECT_EQ(text_bytes, 0x1234567890abcdefULL + 0x10, "ABS64 written value");
}

static void test_reloc_abs32(void)
{
    uint32_t text_words[2] = {0};
    struct kh_elf64_sym syms[2] = {0};
    struct kh_elf64_rela rels[1] = {0};
    struct kh_elf64_shdr shdrs[4] = {0};

    /* st_value must fit in 32 bits or ABS32 will overflow. */
    syms[1].st_value = 0xdeadbeefULL;

    rels[0].r_offset = 4;                                   /* second word */
    rels[0].r_info   = pack_rela_info(1, R_ABS32);
    rels[0].r_addend = 0;

    shdrs[1].sh_addr = (uint64_t)(uintptr_t)text_words;
    shdrs[1].sh_size = sizeof(text_words);
    shdrs[2].sh_addr = (uint64_t)(uintptr_t)syms;
    shdrs[2].sh_size = sizeof(syms);
    shdrs[3].sh_addr = (uint64_t)(uintptr_t)rels;
    shdrs[3].sh_size = sizeof(rels);
    shdrs[3].sh_info = 1;
    shdrs[3].sh_link = 2;

    /* Note: 0xdeadbeef has top bit set, so the overflow check will treat
     * it as "not representable in 32-bit signed" and bounce. ABS32 in KP
     * does the overflow check; expect -8. We change st_value to a small
     * positive integer to take the success path. */
    syms[1].st_value = 0x01020304ULL;

    int rc = kh_apply_relocate_add(shdrs, "", 2, 3);
    EXPECT_EQ(rc, 0, "ABS32 reloc rc");
    EXPECT_EQ(text_words[1], 0x01020304u, "ABS32 written value (low word)");
    EXPECT_EQ(text_words[0], 0u, "ABS32 first word untouched");
}

static void test_reloc_call26(void)
{
    /* CALL26 is a BL with 26-bit signed PC-relative immediate scaled by 4.
     * Place a BL at addr P, target T; expect insn = 0x94000000 | ((T-P)/4 & 0x03ffffff). */
    uint32_t text = 0x94000000;  /* BL <unresolved> */
    struct kh_elf64_sym syms[2] = {0};
    struct kh_elf64_rela rels[1] = {0};
    struct kh_elf64_shdr shdrs[4] = {0};

    /* Target = P + 0x100. */
    uintptr_t P = (uintptr_t)&text;
    syms[1].st_value = (uint64_t)(P + 0x100);

    rels[0].r_offset = 0;
    rels[0].r_info   = pack_rela_info(1, R_CALL26);
    rels[0].r_addend = 0;

    shdrs[1].sh_addr = (uint64_t)(uintptr_t)&text;
    shdrs[1].sh_size = sizeof(text);
    shdrs[2].sh_addr = (uint64_t)(uintptr_t)syms;
    shdrs[2].sh_size = sizeof(syms);
    shdrs[3].sh_addr = (uint64_t)(uintptr_t)rels;
    shdrs[3].sh_size = sizeof(rels);
    shdrs[3].sh_info = 1;
    shdrs[3].sh_link = 2;

    int rc = kh_apply_relocate_add(shdrs, "", 2, 3);
    EXPECT_EQ(rc, 0, "CALL26 reloc rc");
    /* Offset / 4 = 0x40, splice into bits[0:25]. */
    EXPECT_EQ(text, 0x94000000u | 0x40u, "CALL26 written insn");
}

static void test_reloc_unsupported(void)
{
    /* Bogus RELA type → -22. */
    uint64_t text_bytes = 0;
    struct kh_elf64_sym syms[2] = {0};
    struct kh_elf64_rela rels[1] = {0};
    struct kh_elf64_shdr shdrs[4] = {0};

    rels[0].r_offset = 0;
    rels[0].r_info   = pack_rela_info(1, 0xffffffff);
    rels[0].r_addend = 0;

    shdrs[1].sh_addr = (uint64_t)(uintptr_t)&text_bytes;
    shdrs[1].sh_size = sizeof(text_bytes);
    shdrs[2].sh_addr = (uint64_t)(uintptr_t)syms;
    shdrs[2].sh_size = sizeof(syms);
    shdrs[3].sh_addr = (uint64_t)(uintptr_t)rels;
    shdrs[3].sh_size = sizeof(rels);
    shdrs[3].sh_info = 1;
    shdrs[3].sh_link = 2;

    int rc = kh_apply_relocate_add(shdrs, "", 2, 3);
    EXPECT_EQ(rc, -22, "unsupported RELA returns -22");
}

static void test_relocate_rel_is_noop(void)
{
    /* AArch64 SHT_REL is unused; our wrapper returns 0. */
    int rc = kh_apply_relocate(NULL, NULL, 0, 0);
    EXPECT_EQ(rc, 0, "kh_apply_relocate (SHT_REL) noop returns 0");
}

int main(void)
{
    test_insn_imm_12();
    test_insn_imm_19();
    test_insn_imm_26();
    test_insn_imm_overwrite();
    test_insn_imm_adr();

    test_reloc_abs64();
    test_reloc_abs32();
    test_reloc_call26();
    test_reloc_unsupported();
    test_relocate_rel_is_noop();

    if (failures) {
        fprintf(stderr, "[FAILED] %d assertion(s) failed\n", failures);
        return 1;
    }
    fprintf(stderr, "[PASS] all kh_loader assertions passed\n");
    return 0;
}
