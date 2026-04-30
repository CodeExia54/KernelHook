/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "resolver.h"
#include "devices_table.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static resolved_t from_entry(value_id_t id, const struct device_entry *d,
                             const char *label_prefix)
{
    resolved_t out = { .available = 0 };
    if (!d) return out;
    out.available = 1;
    snprintf(out.source_label, sizeof(out.source_label), "%s:%s", label_prefix, d->name);
    switch (id) {
    case VAL_MODULE_LAYOUT_CRC:   out.u64_val = d->module_layout_crc; break;
    case VAL_PRINTK_CRC:          out.u64_val = d->printk_crc; break;
    case VAL_MEMCPY_CRC:          out.u64_val = d->memcpy_crc; break;
    case VAL_MEMSET_CRC:          out.u64_val = d->memset_crc; break;
    case VAL_VERMAGIC:
        strncpy(out.str_val, d->vermagic, sizeof(out.str_val) - 1);
        break;
    case VAL_THIS_MODULE_SIZE:    out.u64_val = d->this_module_size; break;
    case VAL_MODULE_INIT_OFFSET:  out.u64_val = d->module_init_offset; break;
    case VAL_MODULE_EXIT_OFFSET:  out.u64_val = d->module_exit_offset; break;
    default:
        out.available = 0; /* kallsyms_addr never comes from config */
    }
    return out;
}

resolved_t strategy_config_explicit(value_id_t id, resolve_ctx_t *ctx)
{
    if (!ctx->device_override) return (resolved_t){ .available = 0 };
    if (!ctx->selected_device) {
        for (const struct device_entry *d = g_devices; d->name; d++) {
            if (strcmp(d->name, ctx->device_override) == 0) {
                ctx->selected_device = d;
                break;
            }
        }
    }
    return from_entry(id, ctx->selected_device, "config_explicit");
}

resolved_t strategy_config_automatch(value_id_t id, resolve_ctx_t *ctx)
{
    if (ctx->device_override) return (resolved_t){ .available = 0 };

    if (!ctx->selected_device) {
        const struct device_entry *best = NULL;
        int ambiguous = 0;
        for (const struct device_entry *d = g_devices; d->name; d++) {
            size_t pref_len = strlen(d->match_kernelrelease);
            if (strncmp(ctx->uname_release, d->match_kernelrelease, pref_len) == 0) {
                if (best) ambiguous = 1;
                best = d;
            }
        }
        if (ambiguous) {
            fprintf(stderr, "kmod_loader: ambiguous config_automatch for '%s', "
                            "use --device=<name> to disambiguate\n",
                    ctx->uname_release);
            return (resolved_t){ .available = 0 };
        }
        ctx->selected_device = best;
    }
    return from_entry(id, ctx->selected_device, "config_automatch");
}

resolved_t strategy_config_fuzzy(value_id_t id, resolve_ctx_t *ctx)
{
    if (ctx->device_override || ctx->strict_config) return (resolved_t){ .available = 0 };
    if (ctx->selected_device) return from_entry(id, ctx->selected_device, "config_fuzzy");

    /* Nearest-neighbor by numeric version distance. */
    int want_major = ctx->kmajor, want_minor = ctx->kminor;
    const struct device_entry *best = NULL;
    long best_dist = -1;
    for (const struct device_entry *d = g_devices; d->name; d++) {
        int maj = 0, min = 0;
        if (sscanf(d->match_kernelrelease, "%d.%d", &maj, &min) != 2) continue;
        long dist = (long)(want_major - maj) * 10000 + (long)(want_minor - min);
        if (dist < 0) dist = -dist;
        if (best_dist < 0 || dist < best_dist) {
            best = d;
            best_dist = dist;
        }
    }
    if (best) {
        fprintf(stderr, "kmod_loader: WARNING: no exact match for kernel %d.%d, "
                        "using closest profile '%s' (%s)\n",
                want_major, want_minor, best->name, best->match_kernelrelease);
        ctx->selected_device = best;
    }
    return from_entry(id, ctx->selected_device, "config_fuzzy");
}
