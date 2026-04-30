/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "resolver.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern int probe_init_offset_binary(const char *self_path, uint8_t *main_mod,
                                    size_t main_mod_size, const Elf64_Ehdr *main_eh,
                                    const char *params, uint32_t *out_init);

resolved_t strategy_probe_binary_search(value_id_t id, resolve_ctx_t *ctx)
{
    resolved_t out = { .available = 0 };
    if (id != VAL_MODULE_INIT_OFFSET) return out;
    if (!ctx->mod_buf) return out;

    uint32_t init_off = 0;
    /* NOTE: self_path is NULL here — persistent probe state won't be
     * saved during Milestone B. Milestone C will route argv[0] through
     * resolve_ctx_t and fix this. */
    if (probe_init_offset_binary(NULL, ctx->mod_buf, ctx->mod_size,
                                 ctx->mod_eh, "", &init_off) == 0 && init_off) {
        out.available = 1;
        out.u64_val = init_off;
        strncpy(out.source_label, "probe_binary_search",
                sizeof(out.source_label) - 1);
    }
    return out;
}
