/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 * Adapted for KernelHook by bmax121, 2026.
 *
 * Subset port of KernelPatch's kernel/patch/module/insn.c. We keep ONLY
 * the immediate-field encoder (aarch64_insn_encode_immediate); KP's
 * stop_machine / cpu_relax / patch_text / hotpatch helpers are not
 * portable to the freestanding khimg environment and are not needed by
 * the ELF relocator.
 *
 * The ported routine is mechanical bit shuffling — no kallsyms, no
 * allocator, no kernel headers required. Compiles identically in
 * KH_LOADER_FREESTANDING / KH_LOADER_HOST / KH_LOADER_UNITTEST.
 *
 * Original copyright lines preserved per project convention (KP source
 * was MIT-style with no header — KernelHook tree is GPL-2.0-or-later).
 */

#include "kh_loader.h"

/* GENMASK / BIT mirror Linux's <linux/bits.h> exactly. We re-define
 * locally because <linux/bits.h> is not available in freestanding mode
 * and pulling in <ktypes.h> from khimg side would tie this file to one
 * environment. */
#define KH_BIT(n)              (((uint64_t)1) << (n))
#define KH_BITS_PER_LONG_LONG  64
#define KH_GENMASK(h, l) \
    ((~(uint64_t)0 << (l)) & (~(uint64_t)0 >> (KH_BITS_PER_LONG_LONG - 1 - (h))))

/*
 * Splice an `imm` of the given encoding type into an existing 32-bit
 * AArch64 instruction. Returns the new instruction word, or 0 on bad
 * type (matching KP's behavior).
 *
 * Each case below is verbatim from KP insn.c::aarch64_insn_encode_immediate
 * with the project-namespaced enum values substituted in.
 */
uint32_t kh_aarch64_insn_encode_immediate(enum kh_aarch64_insn_imm_type type,
                                          uint32_t insn, uint64_t imm)
{
    uint32_t immlo, immhi, lomask, himask, mask;
    int shift;

    switch (type) {
    case KH_AARCH64_INSN_IMM_ADR:
        /* ADR/ADRP: 21-bit signed immediate split as immlo[1:0] @24
         * and immhi[20:2] @5. */
        lomask = 0x3;
        himask = 0x7ffff;
        immlo = (uint32_t)(imm & lomask);
        imm >>= 2;
        immhi = (uint32_t)(imm & himask);
        imm = ((uint64_t)immlo << 24) | (uint64_t)immhi;
        mask = (lomask << 24) | himask;
        shift = 5;
        break;
    case KH_AARCH64_INSN_IMM_26:
        mask = (uint32_t)(KH_BIT(26) - 1);
        shift = 0;
        break;
    case KH_AARCH64_INSN_IMM_19:
        mask = (uint32_t)(KH_BIT(19) - 1);
        shift = 5;
        break;
    case KH_AARCH64_INSN_IMM_16:
        mask = (uint32_t)(KH_BIT(16) - 1);
        shift = 5;
        break;
    case KH_AARCH64_INSN_IMM_14:
        mask = (uint32_t)(KH_BIT(14) - 1);
        shift = 5;
        break;
    case KH_AARCH64_INSN_IMM_12:
        mask = (uint32_t)(KH_BIT(12) - 1);
        shift = 10;
        break;
    case KH_AARCH64_INSN_IMM_9:
        mask = (uint32_t)(KH_BIT(9) - 1);
        shift = 12;
        break;
    case KH_AARCH64_INSN_IMM_7:
        mask = (uint32_t)(KH_BIT(7) - 1);
        shift = 15;
        break;
    case KH_AARCH64_INSN_IMM_6:
    case KH_AARCH64_INSN_IMM_S:
        mask = (uint32_t)(KH_BIT(6) - 1);
        shift = 10;
        break;
    case KH_AARCH64_INSN_IMM_R:
        mask = (uint32_t)(KH_BIT(6) - 1);
        shift = 16;
        break;
    default:
        /* Unknown type. KP would logke() and return 0; we return 0
         * silently — relocator surfaces this as a downstream overflow. */
        return 0;
    }

    /* Stamp the immediate. */
    insn &= ~(mask << shift);
    insn |= ((uint32_t)imm & mask) << shift;
    return insn;
}
