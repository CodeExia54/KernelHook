/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "resolver.h"
#include <dirent.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

extern int crc_from_vendor_ko_file(const char *path, const char *sym, uint32_t *out);

static int try_module_path(const char *modname, const char *sym, uint32_t *out,
                           char *source_label, size_t label_sz)
{
    static const char *roots[] = {
        "/lib/modules/%s/kernel",
        "/vendor/lib/modules",
        "/vendor_dlkm/lib/modules",
        "/system/lib/modules",
        "/odm/lib/modules",
        NULL
    };
    struct utsname u;
    char rel[128] = "";
    if (uname(&u) == 0) strncpy(rel, u.release, sizeof(rel) - 1);

    for (int i = 0; roots[i]; i++) {
        char expanded[PATH_MAX];
        char path[PATH_MAX];
        snprintf(expanded, sizeof(expanded), roots[i], rel);
        snprintf(path, sizeof(path), "%s/%s.ko", expanded, modname);
        if (crc_from_vendor_ko_file(path, sym, out) == 0) {
            snprintf(source_label, label_sz, "probe_loaded:%s", path);
            return 0;
        }
    }
    return -1;
}

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

resolved_t strategy_probe_loaded_module(value_id_t id, resolve_ctx_t *ctx)
{
    resolved_t out = { .available = 0 };
    const char *sym = sym_for_value(id);
    if (!sym) return out;

    DIR *dp = opendir("/sys/module");
    if (!dp) return out;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.') continue;
        if (strcmp(de->d_name, "kernelhook") == 0) continue; /* skip our own */
        uint32_t crc;
        char label[KH_SOURCE_LABEL_MAX];
        if (try_module_path(de->d_name, sym, &crc, label, sizeof(label)) == 0) {
            out.available = 1;
            out.u64_val = crc;
            strncpy(out.source_label, label, sizeof(out.source_label) - 1);
            break;
        }
    }
    closedir(dp);
    (void)ctx;
    return out;
}
