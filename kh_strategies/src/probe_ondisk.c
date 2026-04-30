/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "resolver.h"
#include <stdint.h>
#include <string.h>

/* Defined in kmod_loader.c */
extern int crc_from_vendor_ko(const char *sym, uint32_t *out);
extern int crc_from_kallsyms(const char *sym, uint32_t *out);
extern int crc_from_boot_image(const char *sym, uint32_t *out);
extern int sizeof_struct_module_from_vendor_ko(uint32_t *out);
extern int init_offset_from_vendor_ko(uint32_t *out);
extern int exit_offset_from_vendor_ko(uint32_t *out);

static const char *sym_for_value(value_id_t id)
{
    switch (id) {
    case VAL_MODULE_LAYOUT_CRC: return "module_layout";
    case VAL_PRINTK_CRC:        return "_printk";
    case VAL_MEMCPY_CRC:        return "memcpy";
    case VAL_MEMSET_CRC:        return "memset";
    default: return NULL;
    }
}

resolved_t strategy_probe_ondisk_module(value_id_t id, resolve_ctx_t *ctx)
{
    resolved_t out = { .available = 0 };
    (void)ctx;
    const char *sym = sym_for_value(id);
    uint32_t crc;

    if (sym) {
        if (crc_from_vendor_ko(sym, &crc) == 0) {
            out.available = 1;
            out.u64_val = crc;
            strncpy(out.source_label, "probe_ondisk:vendor_ko",
                    sizeof(out.source_label) - 1);
            return out;
        }
        if (crc_from_boot_image(sym, &crc) == 0) {
            out.available = 1;
            out.u64_val = crc;
            strncpy(out.source_label, "probe_ondisk:boot_image",
                    sizeof(out.source_label) - 1);
            return out;
        }
    }

    /* VAL_THIS_MODULE_SIZE: probe from vendor .ko's .gnu.linkonce.this_module */
    if (id == VAL_THIS_MODULE_SIZE) {
        uint32_t mod_size;
        if (sizeof_struct_module_from_vendor_ko(&mod_size) == 0) {
            out.available = 1;
            out.u64_val = mod_size;
            strncpy(out.source_label, "probe_ondisk:vendor_ko_this_module",
                    sizeof(out.source_label) - 1);
            return out;
        }
    }

    /* VAL_MODULE_INIT_OFFSET / VAL_MODULE_EXIT_OFFSET: probe from vendor .ko's
     * .rela.gnu.linkonce.this_module. This is the only source that survives
     * Google's in-stable-release struct module layout changes (e.g. 6.1.23
     * keeps init at 0x140 but 6.1.99 moves it to 0x170). devices_table
     * entries only index by x.y prefix so they can't distinguish. */
    if (id == VAL_MODULE_INIT_OFFSET) {
        uint32_t v;
        if (init_offset_from_vendor_ko(&v) == 0) {
            out.available = 1;
            out.u64_val = v;
            strncpy(out.source_label, "probe_ondisk:vendor_ko_init_reloc",
                    sizeof(out.source_label) - 1);
            return out;
        }
    }
    if (id == VAL_MODULE_EXIT_OFFSET) {
        uint32_t v;
        if (exit_offset_from_vendor_ko(&v) == 0) {
            out.available = 1;
            out.u64_val = v;
            strncpy(out.source_label, "probe_ondisk:vendor_ko_exit_reloc",
                    sizeof(out.source_label) - 1);
            return out;
        }
    }

    return out;
}
