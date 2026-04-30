/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "resolver.h"
#include <string.h>

#define RET_U64(v) do { out.available = 1; out.u64_val = (v); \
    strncpy(out.source_label, "cli_override", sizeof(out.source_label) - 1); \
    return out; } while (0)
#define RET_STR(s) do { out.available = 1; \
    strncpy(out.str_val, (s), sizeof(out.str_val) - 1); \
    strncpy(out.source_label, "cli_override", sizeof(out.source_label) - 1); \
    return out; } while (0)

resolved_t strategy_cli_override(value_id_t id, resolve_ctx_t *ctx)
{
    resolved_t out = { .available = 0 };
    switch (id) {
    case VAL_MODULE_LAYOUT_CRC:
        if (ctx->have_module_layout_crc) RET_U64(ctx->cli_module_layout_crc);
        break;
    case VAL_PRINTK_CRC:
        if (ctx->have_printk_crc) RET_U64(ctx->cli_printk_crc);
        break;
    case VAL_MEMCPY_CRC:
        if (ctx->have_memcpy_crc) RET_U64(ctx->cli_memcpy_crc);
        break;
    case VAL_MEMSET_CRC:
        if (ctx->have_memset_crc) RET_U64(ctx->cli_memset_crc);
        break;
    case VAL_VERMAGIC:
        if (ctx->have_vermagic) RET_STR(ctx->cli_vermagic);
        break;
    case VAL_THIS_MODULE_SIZE:
        if (ctx->have_this_module_size) RET_U64(ctx->cli_this_module_size);
        break;
    case VAL_MODULE_INIT_OFFSET:
        if (ctx->have_module_init_offset) RET_U64(ctx->cli_module_init_offset);
        break;
    case VAL_MODULE_EXIT_OFFSET:
        if (ctx->have_module_exit_offset) RET_U64(ctx->cli_module_exit_offset);
        break;
    case VAL_KALLSYMS_LOOKUP_NAME_ADDR:
        if (ctx->have_kallsyms_addr) RET_U64(ctx->cli_kallsyms_addr);
        break;
    default:
        break;
    }
    return out;
}
