/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "resolver.h"
#include <stdint.h>
#include <string.h>

/* Defined in kmod_loader.c for now (Phase 4 will consolidate). */
extern const char *get_vermagic(void);
extern uint64_t auto_fetch_kallsyms_addr(void);

resolved_t strategy_probe_procfs(value_id_t id, resolve_ctx_t *ctx)
{
    resolved_t out = { .available = 0 };
    (void)ctx;

    if (id == VAL_VERMAGIC) {
        const char *vm = get_vermagic();
        if (vm && *vm) {
            out.available = 1;
            strncpy(out.str_val, vm, sizeof(out.str_val) - 1);
            strncpy(out.source_label, "probe_procfs:/proc/version",
                    sizeof(out.source_label) - 1);
        }
    } else if (id == VAL_KALLSYMS_LOOKUP_NAME_ADDR) {
        uint64_t a = auto_fetch_kallsyms_addr();
        if (a) {
            out.available = 1;
            out.u64_val = a;
            strncpy(out.source_label, "probe_procfs:/proc/kallsyms",
                    sizeof(out.source_label) - 1);
        }
    }
    return out;
}
