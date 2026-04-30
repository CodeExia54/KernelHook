/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "resolver.h"
#include <stdint.h>
#include <string.h>

extern int probe_init_offset_disasm(uint32_t *out_init);

resolved_t strategy_probe_disasm(value_id_t id, resolve_ctx_t *ctx)
{
    resolved_t out = { .available = 0 };
    (void)ctx;
    if (id != VAL_MODULE_INIT_OFFSET) return out;

    uint32_t init_off = 0;
    if (probe_init_offset_disasm(&init_off) == 0 && init_off) {
        out.available = 1;
        out.u64_val = init_off;
        strncpy(out.source_label, "probe_disasm:kernel_image",
                sizeof(out.source_label) - 1);
    }
    return out;
}
