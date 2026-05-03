/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 * Adapted for KernelHook by bmax121, 2026.
 *
 * Port of KernelPatch's kernel/patch/module/relo.c — the AArch64 ELF
 * RELA relocation engine. This file is ENVIRONMENT-AGNOSTIC: it does
 * not call kallsyms, does not allocate, and does not touch PTEs.
 * Caller pre-resolves SHN_UNDEF symbols and stamps runtime addresses
 * into sechdrs[i].sh_addr; we just walk the RELA section and apply
 * each entry.
 *
 * One change from the KP original: we hard-code R_AARCH64_* numeric
 * constants rather than #include <asm/elf.h>, so the file builds in
 * khimg's freestanding environment too. The constants match the
 * AArch64 ELF ABI and are stable across all kernel versions.
 *
 * Error returns:
 *   -8  (-ERANGE  equivalent) — relocation overflow
 *   -22 (-EINVAL  equivalent) — unsupported RELA type / bad reloc data
 *
 * KP returns -ENOEXEC and -ERANGE which on Linux happen to be -8 / -8
 * (ERANGE is 34, ENOEXEC is 8) — we use the stable numeric -8/-22
 * here so the freestanding side does not need <uapi/asm-generic/errno.h>.
 */

#include "kh_loader.h"

/* AArch64 ELF ABI relocation type constants. Stable since the AArch64
 * ELF spec was first published; mirrored from <uapi/linux/elf.h>. */
#define KH_R_AARCH64_NONE                   0
#define KH_R_ARM_NONE                       0  /* alias kept for parity */
#define KH_R_AARCH64_ABS64                  257
#define KH_R_AARCH64_ABS32                  258
#define KH_R_AARCH64_ABS16                  259
#define KH_R_AARCH64_PREL64                 260
#define KH_R_AARCH64_PREL32                 261
#define KH_R_AARCH64_PREL16                 262
#define KH_R_AARCH64_MOVW_UABS_G0           263
#define KH_R_AARCH64_MOVW_UABS_G0_NC        264
#define KH_R_AARCH64_MOVW_UABS_G1           265
#define KH_R_AARCH64_MOVW_UABS_G1_NC        266
#define KH_R_AARCH64_MOVW_UABS_G2           267
#define KH_R_AARCH64_MOVW_UABS_G2_NC        268
#define KH_R_AARCH64_MOVW_UABS_G3           269
#define KH_R_AARCH64_MOVW_SABS_G0           270
#define KH_R_AARCH64_MOVW_SABS_G1           271
#define KH_R_AARCH64_MOVW_SABS_G2           272
#define KH_R_AARCH64_LD_PREL_LO19           273
#define KH_R_AARCH64_ADR_PREL_LO21          274
#define KH_R_AARCH64_ADR_PREL_PG_HI21       275
#define KH_R_AARCH64_ADR_PREL_PG_HI21_NC    276
#define KH_R_AARCH64_ADD_ABS_LO12_NC        277
#define KH_R_AARCH64_LDST8_ABS_LO12_NC      278
#define KH_R_AARCH64_TSTBR14                279
#define KH_R_AARCH64_CONDBR19               280
#define KH_R_AARCH64_JUMP26                 282
#define KH_R_AARCH64_CALL26                 283
#define KH_R_AARCH64_LDST16_ABS_LO12_NC     284
#define KH_R_AARCH64_LDST32_ABS_LO12_NC     285
#define KH_R_AARCH64_LDST64_ABS_LO12_NC     286
#define KH_R_AARCH64_MOVW_PREL_G0           287
#define KH_R_AARCH64_MOVW_PREL_G0_NC        288
#define KH_R_AARCH64_MOVW_PREL_G1           289
#define KH_R_AARCH64_MOVW_PREL_G1_NC        290
#define KH_R_AARCH64_MOVW_PREL_G2           291
#define KH_R_AARCH64_MOVW_PREL_G2_NC        292
#define KH_R_AARCH64_MOVW_PREL_G3           293
#define KH_R_AARCH64_LDST128_ABS_LO12_NC    299

/* ELF64_R_TYPE / ELF64_R_SYM live in <linux/elf.h>; redefined here. */
#define KH_ELF64_R_SYM(i)   ((i) >> 32)
#define KH_ELF64_R_TYPE(i)  ((i) & 0xffffffff)

#define KH_BIT(n)            (((uint64_t)1) << (n))

/* Internal sentinel values that map onto the immediate-encoder enum.
 * MOVNZ does not have a hardware encoding — relocator picks MOVZ vs
 * MOVN at relocation time based on the sign of the immediate, then
 * encodes via the IMM_16 case below. */
#define KH_IMM_MOVNZ KH_AARCH64_INSN_IMM_MAX
#define KH_IMM_MOVK  KH_AARCH64_INSN_IMM_16

enum kh_aarch64_reloc_op {
    KH_RELOC_OP_NONE,
    KH_RELOC_OP_ABS,
    KH_RELOC_OP_PREL,
    KH_RELOC_OP_PAGE,
};

static uint64_t kh_do_reloc(enum kh_aarch64_reloc_op op, void *place, uint64_t val)
{
    switch (op) {
    case KH_RELOC_OP_ABS:
        return val;
    case KH_RELOC_OP_PREL:
        return val - (uint64_t)place;
    case KH_RELOC_OP_PAGE:
        return (val & ~(uint64_t)0xfff) - ((uint64_t)place & ~(uint64_t)0xfff);
    case KH_RELOC_OP_NONE:
        return 0;
    }
    return 0;
}

static int kh_reloc_data(enum kh_aarch64_reloc_op op, void *place, uint64_t val, int len)
{
    uint64_t imm_mask = (((uint64_t)1) << len) - 1;
    int64_t sval = (int64_t)kh_do_reloc(op, place, val);

    switch (len) {
    case 16:
        *(int16_t *)place = (int16_t)sval;
        break;
    case 32:
        *(int32_t *)place = (int32_t)sval;
        break;
    case 64:
        *(int64_t *)place = (int64_t)sval;
        break;
    default:
        return -22;
    }

    /* Overflow check — extract sign-bit-and-above and shift to bit 0. */
    sval = (int64_t)((uint64_t)sval & ~(imm_mask >> 1)) >> (len - 1);
    if ((uint64_t)(sval + 1) > 2) return -8;
    return 0;
}

static int kh_reloc_insn_movw(enum kh_aarch64_reloc_op op, void *place, uint64_t val,
                              int lsb, enum kh_aarch64_insn_imm_type imm_type)
{
    uint64_t imm, limit = 0;
    int64_t sval;
    uint32_t insn = *(uint32_t *)place;

    sval = (int64_t)kh_do_reloc(op, place, val);
    sval >>= lsb;
    imm = (uint64_t)sval & 0xffff;

    if (imm_type == KH_IMM_MOVNZ) {
        /* For signed MOVW relocations, swap MOVZ/MOVN opcode based on
         * the sign of the immediate. */
        insn &= ~((uint32_t)3 << 29);
        if ((int64_t)imm >= 0) {
            insn |= (uint32_t)2 << 29;   /* MOVZ */
        } else {
            imm = ~imm;                   /* MOVN: invert immediate */
        }
        imm_type = KH_IMM_MOVK;
    }

    insn = kh_aarch64_insn_encode_immediate(imm_type, insn, imm);
    *(uint32_t *)place = insn;

    sval >>= 16;

    /* Signed immediates: sign bit lives one past the MSB of the field. */
    if (imm_type != KH_AARCH64_INSN_IMM_16) {
        sval++;
        limit++;
    }
    if ((uint64_t)sval > limit) return -8;
    return 0;
}

static int kh_reloc_insn_imm(enum kh_aarch64_reloc_op op, void *place, uint64_t val,
                             int lsb, int len, enum kh_aarch64_insn_imm_type imm_type)
{
    uint64_t imm, imm_mask;
    int64_t sval;
    uint32_t insn = *(uint32_t *)place;

    sval = (int64_t)kh_do_reloc(op, place, val);
    sval >>= lsb;

    imm_mask = (KH_BIT(lsb + len) - 1) >> lsb;
    imm = (uint64_t)sval & imm_mask;

    insn = kh_aarch64_insn_encode_immediate(imm_type, insn, imm);
    *(uint32_t *)place = insn;

    sval = (int64_t)((uint64_t)sval & ~(imm_mask >> 1)) >> (len - 1);
    if ((uint64_t)(sval + 1) >= 2) return -8;
    return 0;
}

int kh_apply_relocate(struct kh_elf64_shdr *sechdrs,
                      const char *strtab,
                      unsigned int symindex,
                      unsigned int relsec)
{
    /* AArch64 is RELA-only; SHT_REL is never emitted. KP returns 0 here
     * for parity with arch/arm64/kernel/module.c. */
    (void)sechdrs;
    (void)strtab;
    (void)symindex;
    (void)relsec;
    return 0;
}

int kh_apply_relocate_add(struct kh_elf64_shdr *sechdrs,
                          const char *strtab,
                          unsigned int symindex,
                          unsigned int relsec)
{
    unsigned int i;
    int ovf;
    int overflow_check;
    struct kh_elf64_sym *sym;
    void *loc;
    uint64_t val;
    struct kh_elf64_rela *rel = (struct kh_elf64_rela *)(uintptr_t)sechdrs[relsec].sh_addr;

    (void)strtab; /* only used for diagnostic logging upstream */

    for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
        /* loc corresponds to P in the AArch64 ELF document. */
        loc = (void *)(uintptr_t)(sechdrs[sechdrs[relsec].sh_info].sh_addr +
                                  rel[i].r_offset);
        /* sym is the ELF symbol we're referring to. */
        sym = (struct kh_elf64_sym *)(uintptr_t)sechdrs[symindex].sh_addr +
              KH_ELF64_R_SYM(rel[i].r_info);
        /* val corresponds to (S + A). */
        val = sym->st_value + (uint64_t)rel[i].r_addend;

        overflow_check = 1;
        ovf = 0;

        switch (KH_ELF64_R_TYPE(rel[i].r_info)) {
        case KH_R_AARCH64_NONE:
            ovf = 0;
            break;

        /* Data relocations. */
        case KH_R_AARCH64_ABS64:
            overflow_check = 0;
            ovf = kh_reloc_data(KH_RELOC_OP_ABS, loc, val, 64);
            break;
        case KH_R_AARCH64_ABS32:
            ovf = kh_reloc_data(KH_RELOC_OP_ABS, loc, val, 32);
            break;
        case KH_R_AARCH64_ABS16:
            ovf = kh_reloc_data(KH_RELOC_OP_ABS, loc, val, 16);
            break;
        case KH_R_AARCH64_PREL64:
            overflow_check = 0;
            ovf = kh_reloc_data(KH_RELOC_OP_PREL, loc, val, 64);
            break;
        case KH_R_AARCH64_PREL32:
            ovf = kh_reloc_data(KH_RELOC_OP_PREL, loc, val, 32);
            break;
        case KH_R_AARCH64_PREL16:
            ovf = kh_reloc_data(KH_RELOC_OP_PREL, loc, val, 16);
            break;

        /* MOVW relocations. */
        case KH_R_AARCH64_MOVW_UABS_G0_NC:
            overflow_check = 0;
            /* fallthrough */
        case KH_R_AARCH64_MOVW_UABS_G0:
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_ABS, loc, val, 0,
                                     KH_AARCH64_INSN_IMM_16);
            break;
        case KH_R_AARCH64_MOVW_UABS_G1_NC:
            overflow_check = 0;
            /* fallthrough */
        case KH_R_AARCH64_MOVW_UABS_G1:
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_ABS, loc, val, 16,
                                     KH_AARCH64_INSN_IMM_16);
            break;
        case KH_R_AARCH64_MOVW_UABS_G2_NC:
            overflow_check = 0;
            /* fallthrough */
        case KH_R_AARCH64_MOVW_UABS_G2:
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_ABS, loc, val, 32,
                                     KH_AARCH64_INSN_IMM_16);
            break;
        case KH_R_AARCH64_MOVW_UABS_G3:
            overflow_check = 0;
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_ABS, loc, val, 48,
                                     KH_AARCH64_INSN_IMM_16);
            break;
        case KH_R_AARCH64_MOVW_SABS_G0:
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_ABS, loc, val, 0, KH_IMM_MOVNZ);
            break;
        case KH_R_AARCH64_MOVW_SABS_G1:
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_ABS, loc, val, 16, KH_IMM_MOVNZ);
            break;
        case KH_R_AARCH64_MOVW_SABS_G2:
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_ABS, loc, val, 32, KH_IMM_MOVNZ);
            break;
        case KH_R_AARCH64_MOVW_PREL_G0_NC:
            overflow_check = 0;
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_PREL, loc, val, 0, KH_IMM_MOVK);
            break;
        case KH_R_AARCH64_MOVW_PREL_G0:
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_PREL, loc, val, 0, KH_IMM_MOVNZ);
            break;
        case KH_R_AARCH64_MOVW_PREL_G1_NC:
            overflow_check = 0;
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_PREL, loc, val, 16, KH_IMM_MOVK);
            break;
        case KH_R_AARCH64_MOVW_PREL_G1:
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_PREL, loc, val, 16, KH_IMM_MOVNZ);
            break;
        case KH_R_AARCH64_MOVW_PREL_G2_NC:
            overflow_check = 0;
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_PREL, loc, val, 32, KH_IMM_MOVK);
            break;
        case KH_R_AARCH64_MOVW_PREL_G2:
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_PREL, loc, val, 32, KH_IMM_MOVNZ);
            break;
        case KH_R_AARCH64_MOVW_PREL_G3:
            overflow_check = 0;
            ovf = kh_reloc_insn_movw(KH_RELOC_OP_PREL, loc, val, 48, KH_IMM_MOVNZ);
            break;

        /* Immediate-instruction relocations. */
        case KH_R_AARCH64_LD_PREL_LO19:
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_PREL, loc, val, 2, 19,
                                    KH_AARCH64_INSN_IMM_19);
            break;
        case KH_R_AARCH64_ADR_PREL_LO21:
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_PREL, loc, val, 0, 21,
                                    KH_AARCH64_INSN_IMM_ADR);
            break;
        case KH_R_AARCH64_ADR_PREL_PG_HI21_NC:
            overflow_check = 0;
            /* fallthrough */
        case KH_R_AARCH64_ADR_PREL_PG_HI21:
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_PAGE, loc, val, 12, 21,
                                    KH_AARCH64_INSN_IMM_ADR);
            break;
        case KH_R_AARCH64_ADD_ABS_LO12_NC:
        case KH_R_AARCH64_LDST8_ABS_LO12_NC:
            overflow_check = 0;
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_ABS, loc, val, 0, 12,
                                    KH_AARCH64_INSN_IMM_12);
            break;
        case KH_R_AARCH64_LDST16_ABS_LO12_NC:
            overflow_check = 0;
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_ABS, loc, val, 1, 11,
                                    KH_AARCH64_INSN_IMM_12);
            break;
        case KH_R_AARCH64_LDST32_ABS_LO12_NC:
            overflow_check = 0;
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_ABS, loc, val, 2, 10,
                                    KH_AARCH64_INSN_IMM_12);
            break;
        case KH_R_AARCH64_LDST64_ABS_LO12_NC:
            overflow_check = 0;
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_ABS, loc, val, 3, 9,
                                    KH_AARCH64_INSN_IMM_12);
            break;
        case KH_R_AARCH64_LDST128_ABS_LO12_NC:
            overflow_check = 0;
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_ABS, loc, val, 4, 8,
                                    KH_AARCH64_INSN_IMM_12);
            break;
        case KH_R_AARCH64_TSTBR14:
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_PREL, loc, val, 2, 14,
                                    KH_AARCH64_INSN_IMM_14);
            break;
        case KH_R_AARCH64_CONDBR19:
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_PREL, loc, val, 2, 19,
                                    KH_AARCH64_INSN_IMM_19);
            break;
        case KH_R_AARCH64_JUMP26:
        case KH_R_AARCH64_CALL26:
            ovf = kh_reloc_insn_imm(KH_RELOC_OP_PREL, loc, val, 2, 26,
                                    KH_AARCH64_INSN_IMM_26);
            break;
        default:
            return -22;
        }

        if (overflow_check && ovf == -8) return -8;
    }
    return 0;
}
