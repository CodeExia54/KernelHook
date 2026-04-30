/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include "kh_strategies/strategies.h"

const char *kh_ksymtab_variant_name(kh_ksymtab_variant_t v) {
    switch (v) {
    case KH_KSYMTAB_PREL32:           return "prel32";
    case KH_KSYMTAB_ABS64:            return "abs64";
    case KH_KSYMTAB_ABS64_LEGACY:     return "abs64-legacy";
    case KH_KSYMTAB_ABS64_LEGACY_U32: return "abs64-legacy-u32";
    default:                          return "unknown";
    }
}
