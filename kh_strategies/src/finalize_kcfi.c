/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * finalize_kcfi.c — kCFI hash patching.
 *
 * Scans /vendor/lib/modules and /vendor_dlkm/lib/modules for a .ko that has
 * both init_module and cleanup_module, extracts their kCFI hashes (the 4-byte
 * type hash stored immediately before the function entry), and patches our
 * module.  No callbacks needed — all lookups are filesystem-based.
 */

#include <elf.h>
#include "elf_helpers.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#include "kh_strategies/finalize.h"

/* Get file offset of the kCFI hash (4 bytes before function entry). */
static uint64_t elf_kcfi_hash_offset(const uint8_t *mod, const Ehdr *eh,
                                      const char *func_name)
{
    Shdr *symtab_sh = NULL;
    for (int i = 0; i < eh->e_shnum; i++) {
        Shdr *sh = (Shdr *)(mod + eh->e_shoff + i * eh->e_shentsize);
        if (sh->sh_type == SHT_SYMTAB) { symtab_sh = sh; break; }
    }
    if (!symtab_sh || symtab_sh->sh_link >= (unsigned)eh->e_shnum) return 0;

    Shdr *strtab_sh = (Shdr *)(mod + eh->e_shoff +
                                symtab_sh->sh_link * eh->e_shentsize);
    int num_syms = (int)(symtab_sh->sh_size / symtab_sh->sh_entsize);
    Elf64_Sym *syms = (Elf64_Sym *)(mod + symtab_sh->sh_offset);
    const char *strs = (const char *)(mod + strtab_sh->sh_offset);

    for (int i = 0; i < num_syms; i++) {
        if (strcmp(strs + syms[i].st_name, func_name) != 0) continue;
        if (syms[i].st_shndx == SHN_UNDEF ||
            syms[i].st_shndx >= (unsigned)eh->e_shnum)
            continue;

        Shdr *sec = (Shdr *)(mod + eh->e_shoff +
                             syms[i].st_shndx * eh->e_shentsize);
        uint64_t func_file_off = sec->sh_offset + syms[i].st_value;
        if (func_file_off < 4) return 0;
        return func_file_off - 4;
    }
    return 0;
}

/* Extract kCFI hash for a function from a vendor .ko. */
static uint32_t vendor_kcfi_hash(const uint8_t *ko, const Ehdr *keh,
                                  const char *func_name)
{
    uint64_t off = elf_kcfi_hash_offset(ko, keh, func_name);
    if (!off) return 0;
    uint32_t hash;
    memcpy(&hash, ko + off, 4);
    return hash;
}

int kh_patch_kcfi_hashes(uint8_t *mod, size_t mod_size, const Ehdr *eh,
                          const struct kh_finalize_callbacks *cb)
{
    (void)cb;  /* reserved for future use */

    uint64_t our_init_off = elf_kcfi_hash_offset(mod, eh, "init_module");
    uint64_t our_exit_off = elf_kcfi_hash_offset(mod, eh, "cleanup_module");
    if (!our_init_off && !our_exit_off) return 0;

    static const char *vendor_dirs[] = {
        "/vendor/lib/modules",
        "/vendor_dlkm/lib/modules",
        NULL
    };

    for (int d = 0; vendor_dirs[d]; d++) {
        DIR *dp = opendir(vendor_dirs[d]);
        if (!dp) continue;

        struct dirent *de;
        while ((de = readdir(dp)) != NULL) {
            size_t nlen = strlen(de->d_name);
            if (nlen < 4 || strcmp(de->d_name + nlen - 3, ".ko") != 0)
                continue;

            char path[512];
            snprintf(path, sizeof(path), "%s/%s", vendor_dirs[d], de->d_name);
            int fd = open(path, O_RDONLY);
            if (fd < 0) continue;

            struct stat st;
            if (fstat(fd, &st) < 0 || st.st_size < 256) {
                close(fd);
                continue;
            }

            uint8_t *ko = malloc((size_t)st.st_size);
            if (!ko) { close(fd); continue; }
            if (read(fd, ko, (size_t)st.st_size) != st.st_size) {
                free(ko); close(fd); continue;
            }
            close(fd);

            Ehdr *keh = (Ehdr *)ko;
            if (memcmp(keh->e_ident, ELFMAG, SELFMAG) != 0) {
                free(ko); continue;
            }

            uint32_t ref_init_hash = vendor_kcfi_hash(ko, keh, "init_module");
            uint32_t ref_exit_hash = vendor_kcfi_hash(ko, keh, "cleanup_module");
            free(ko);

            if (!ref_init_hash && !ref_exit_hash) continue;

            int patched = 0;
            if (our_init_off && ref_init_hash &&
                our_init_off + 4 <= mod_size) {
                uint32_t old;
                memcpy(&old, mod + our_init_off, 4);
                if (old != ref_init_hash) {
                    memcpy(mod + our_init_off, &ref_init_hash, 4);
                    fprintf(stderr,
                            "kh_strategies: kCFI init_module: "
                            "0x%08x -> 0x%08x (from %s)\n",
                            old, ref_init_hash, de->d_name);
                    patched++;
                }
            }
            if (our_exit_off && ref_exit_hash &&
                our_exit_off + 4 <= mod_size) {
                uint32_t old;
                memcpy(&old, mod + our_exit_off, 4);
                if (old != ref_exit_hash) {
                    memcpy(mod + our_exit_off, &ref_exit_hash, 4);
                    fprintf(stderr,
                            "kh_strategies: kCFI cleanup_module: "
                            "0x%08x -> 0x%08x (from %s)\n",
                            old, ref_exit_hash, de->d_name);
                    patched++;
                }
            }

            closedir(dp);
            return patched;
        }
        closedir(dp);
    }

    return 0;
}
