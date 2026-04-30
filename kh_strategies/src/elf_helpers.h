/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * Internal ELF section-lookup helpers shared by finalize_*.c.
 * Requires <elf.h> — included by each finalize_*.c before this header.
 */
#ifndef KH_STRATEGIES_ELF_HELPERS_H
#define KH_STRATEGIES_ELF_HELPERS_H

#include <string.h>
#include <stdint.h>

/* Convenience typedefs matching kmod_loader.c usage. */
typedef Elf64_Ehdr Ehdr;
typedef Elf64_Shdr Shdr;
typedef Elf64_Rela Rela;

static inline const char *kh_elf_shname(const uint8_t *buf, const Ehdr *eh,
                                         int idx)
{
    const Shdr *shstrtab =
        (const Shdr *)(buf + eh->e_shoff + eh->e_shstrndx * eh->e_shentsize);
    return (const char *)(buf + shstrtab->sh_offset + idx);
}

static inline Shdr *kh_elf_find_section(uint8_t *buf, const Ehdr *eh,
                                         const char *name)
{
    for (int i = 0; i < eh->e_shnum; i++) {
        Shdr *sh = (Shdr *)(buf + eh->e_shoff + i * eh->e_shentsize);
        if (strcmp(kh_elf_shname(buf, eh, sh->sh_name), name) == 0)
            return sh;
    }
    return NULL;
}

#endif /* KH_STRATEGIES_ELF_HELPERS_H */
