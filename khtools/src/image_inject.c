/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/* Adapted for KernelHook by bmax121, 2026 — host-side hook injection
 * port of KernelPatch tools/{image,common,symbol}.c, simplified for
 * arm64 little-endian targets only (Android GKI). */

#include "image_inject.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "kallsym.h"

/* khimg layout constants — mirrored verbatim from khimg/include/preset.h.
 * khimg/include cannot be put on the host include path (it ships
 * freestanding stdint.h/stddef.h that clash with host SDK), so we
 * replicate the small set we need. The _Static_assert block below
 * locks the offsets against drift. */
#define KP_HEADER_SIZE   0x40
#define HDR_BACKUP_SIZE  0x8
#define MAP_SYMBOL_SIZE  (5 * 8)

/* setup_preset_t byte offsets (matching preset.h #define ladder lines 249-263). */
#define KH_OFF_kernel_version             0
#define KH_OFF_kimg_size                  8
#define KH_OFF_kpimg_size                 16
#define KH_OFF_kernel_size                24
#define KH_OFF_page_shift                 32
#define KH_OFF_setup_offset               40
#define KH_OFF_start_offset               48
#define KH_OFF_extra_size                 56
#define KH_OFF_map_offset                 64
#define KH_OFF_map_max_size               72
#define KH_OFF_kallsyms_lookup_name_off   80
#define KH_OFF_paging_init_offset         88
#define KH_OFF_printk_offset              96
#define KH_OFF_map_symbol                 104
#define KH_OFF_header_backup              (KH_OFF_map_symbol + MAP_SYMBOL_SIZE)

#define EFI_MAGIC_SIG "MZ"
#define KERNEL_MAGIC "ARM\x64"

typedef struct {
    union {
        struct {
            uint8_t mz[4];     /* "MZ" signature required by UEFI */
            uint32_t b_insn;   /* branch to kernel start */
        } efi;
        struct {
            uint32_t b_insn;
            uint32_t reserved0;
        } nefi;
    } hdr;
    uint64_t kernel_offset;
    uint64_t kernel_size_le;
    uint64_t kernel_flag_le;
    uint64_t reserved0;
    uint64_t reserved1;
    uint64_t reserved2;
    char magic[4];   /* "ARM\x64" */
    uint64_t pe_offset;
} kh_arm64_hdr_t;

int kh_get_kernel_info(struct kh_kernel_info *out, const uint8_t *img, size_t imglen)
{
    if (!out || !img || imglen < sizeof(kh_arm64_hdr_t)) return -1;

    const kh_arm64_hdr_t *khdr = (const kh_arm64_hdr_t *)img;
    if (memcmp(khdr->magic, KERNEL_MAGIC, 4) != 0) {
        fprintf(stderr, "kh: image_inject: kernel magic mismatch\n");
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->is_uefi = (memcmp(khdr->hdr.efi.mz, EFI_MAGIC_SIG, 2) == 0) ? 1 : 0;

    uint32_t b_primary_entry_insn;
    if (out->is_uefi) {
        b_primary_entry_insn = khdr->hdr.efi.b_insn;
        out->b_stext_insn_offset = 4;
    } else {
        b_primary_entry_insn = khdr->hdr.nefi.b_insn;
        out->b_stext_insn_offset = 0;
    }

    if ((b_primary_entry_insn & 0xFC000000u) != 0x14000000u) {
        fprintf(stderr, "kh: image_inject: primary entry not B insn (0x%08x)\n",
                b_primary_entry_insn);
        return -1;
    }
    uint32_t imm = (b_primary_entry_insn & 0x03ffffffu) << 2;
    out->primary_entry_offset = (int32_t)imm + out->b_stext_insn_offset;

    out->load_offset = (int64_t)khdr->kernel_offset;
    out->kernel_size = (int64_t)khdr->kernel_size_le;

    uint8_t flag = (uint8_t)(khdr->kernel_flag_le & 0x0fu);
    if (flag & 0x01u) {
        fprintf(stderr, "kh: image_inject: big-endian kernel not supported\n");
        return -1;
    }
    switch ((flag & 0x06u) >> 1) {
    case 2: out->page_shift = 14; break;       /* 16K */
    case 3: out->page_shift = 16; break;       /* 64K */
    case 1: default: out->page_shift = 12;     /* 4K */
    }
    return 0;
}

int kh_kernel_resize(uint8_t *img, size_t imglen, int64_t new_size)
{
    if (!img || imglen < sizeof(kh_arm64_hdr_t)) return -1;
    kh_arm64_hdr_t *khdr = (kh_arm64_hdr_t *)img;
    khdr->kernel_size_le = (uint64_t)new_size;
    return 0;
}

int kh_arm64_b(uint32_t *buf, uint64_t from, uint64_t to)
{
    /* Mirror KP common.c::b() — 128MiB B-imm range, LE encoding. */
    const uint64_t imm26_max = (uint64_t)1 << 27; /* 128 MiB */
    int in_range = (to >= from && to - from <= imm26_max) ||
                   (from >= to && from - to <= imm26_max);
    if (!in_range) return 0;
    buf[0] = 0x14000000u | (uint32_t)(((to - from) & 0x0FFFFFFFu) >> 2u);
    return 4;
}

int32_t kh_relo_branch_func(const uint8_t *img, int32_t func_offset)
{
    /* Mirror KP common.c::relo_branch_func() — single-hop B follow. */
    uint32_t inst = *(const uint32_t *)(img + func_offset);
    if ((inst & 0xFC000000u) != 0x14000000u) return func_offset;

    /* imm26 = inst[25:0]; sign-extend (imm26 << 2) at bit 28. */
    uint64_t imm26 = inst & 0x03ffffffu;
    uint64_t shifted = imm26 << 2;
    uint64_t signbit = (uint64_t)1 << 27;
    int64_t imm64;
    if (shifted & signbit) {
        imm64 = (int64_t)(shifted | (uint64_t)0xFFFFFFFFF0000000ULL);
    } else {
        imm64 = (int64_t)shifted;
    }
    return func_offset + (int32_t)imm64;
}

int kh_select_map_area(kallsym_t *info, uint8_t *img_buf,
                       int32_t *map_start, int32_t *max_size)
{
    /* Port of KP symbol.c::select_map_area() — finds tcp_init_sock and
     * NOPs the PAC pairs (PAC pattern 0xD503211F mask 0xFFFFFD1F).
     * Mutates img_buf in place. */
    if (!info || !img_buf || !map_start || !max_size) return -1;

    int32_t addr = get_symbol_offset(info, (char *)img_buf, "tcp_init_sock");
    if (addr < 0) {
        fprintf(stderr, "kh: image_inject: tcp_init_sock symbol missing\n");
        return -1;
    }

    *map_start = (int32_t)align_floor(addr, 16);
    *max_size = 0x800;

    const uint32_t NOP = 0xD503201Fu;
    const uint32_t PAC = 0xd503233fu;
    const uint32_t PAC_MASK = 0xFFFFFD1Fu;
    const uint32_t PAC_PATTERN = 0xD503211Fu;

    uint32_t pos = 0;
    uint32_t count = 0;
    const uint32_t asmbit = (uint32_t)sizeof(uint32_t);
    int is_first_pac = 0;
    for (uint32_t i = 0; i < (uint32_t)*max_size; i += asmbit) {
        uint32_t insn = *(uint32_t *)(img_buf + addr + i);
        if (!is_first_pac && insn == PAC && i < asmbit * 5) {
            is_first_pac = 1;
        }
        if ((insn & PAC_MASK) == PAC_PATTERN) {
            pos = i;
            count++;
            *(uint32_t *)(img_buf + addr + pos) = NOP;
        }
    }

    /* If pairing failed, look further for a stray PAC and NOP it too. */
    if (count % 2 != 0) {
        uint32_t second_pos = 0;
        for (uint32_t j = (uint32_t)*max_size;
             j < (uint32_t)(*max_size) * 2; j += asmbit) {
            uint32_t insn = *(uint32_t *)(img_buf + addr + j);
            if ((insn & PAC_MASK) == PAC_PATTERN) {
                second_pos = j;
                break;
            }
        }
        if (second_pos) {
            *(uint32_t *)(img_buf + addr + second_pos) = NOP;
        }
    }

    (void)is_first_pac; /* informational only */
    return 0;
}

int kh_fillin_map_symbol(kallsym_t *info, const uint8_t *img, uint8_t out[40])
{
    /* Layout matches map_symbol_t (preset.h:81-95):
     *   [ 0]  memblock_reserve_relo      (required)
     *   [ 8]  memblock_free_relo         (required)
     *   [16]  memblock_phys_alloc_relo   (try _try_nid, fallback alloc_try_nid)
     *   [24]  memblock_virt_alloc_relo   (try _try_nid, fallback alloc_try_nid)
     *   [32]  memblock_mark_nomap_relo   (optional)
     */
    if (!info || !img || !out) return -1;

    int32_t reserve = get_symbol_offset(info, (char *)img, "memblock_reserve");
    int32_t free_off = get_symbol_offset(info, (char *)img, "memblock_free");
    if (reserve < 0 || free_off < 0) {
        fprintf(stderr, "kh: image_inject: memblock_reserve/free missing\n");
        return -1;
    }

    int32_t phys = get_symbol_offset(info, (char *)img, "memblock_phys_alloc_try_nid");
    int32_t virt = get_symbol_offset(info, (char *)img, "memblock_virt_alloc_try_nid");
    int32_t fallback = get_symbol_offset(info, (char *)img, "memblock_alloc_try_nid");
    if (phys < 0) phys = fallback;
    if (virt < 0) virt = fallback;
    if (phys < 0 || virt < 0) {
        fprintf(stderr, "kh: image_inject: no memblock_*alloc symbol\n");
        return -1;
    }

    int32_t nomap = get_symbol_offset(info, (char *)img, "memblock_mark_nomap");
    if (nomap < 0) nomap = 0;  /* optional */

    uint64_t fields[5] = {
        (uint64_t)(uint32_t)reserve,
        (uint64_t)(uint32_t)free_off,
        (uint64_t)(uint32_t)phys,
        (uint64_t)(uint32_t)virt,
        (uint64_t)(uint32_t)nomap,
    };
    memcpy(out, fields, sizeof(fields));
    return 0;
}

/* Compile-time sanity: a local mirror of the relevant prefix of
 * setup_preset_t. Keeping this in sync with khimg/include/preset.h
 * is mandatory; if khimg changes layout, the offsets above must too. */
struct kh_setup_preset_mirror {
    uint32_t kernel_version;            /* 0..3  (version_t = 4 bytes) */
    int32_t  _pad;                      /* 4..7  (int32_t _) */
    int64_t  kimg_size;                 /* 8 */
    int64_t  kpimg_size;                /* 16 */
    int64_t  kernel_size;               /* 24 */
    int64_t  page_shift;                /* 32 */
    int64_t  setup_offset;              /* 40 */
    int64_t  start_offset;              /* 48 */
    int64_t  extra_size;                /* 56 */
    int64_t  map_offset;                /* 64 */
    int64_t  map_max_size;              /* 72 */
    int64_t  kallsyms_lookup_name_off;  /* 80 */
    int64_t  paging_init_offset;        /* 88 */
    int64_t  printk_offset;             /* 96 */
    uint8_t  map_symbol[MAP_SYMBOL_SIZE]; /* 104 */
    uint8_t  header_backup[HDR_BACKUP_SIZE]; /* 144 */
};
_Static_assert(offsetof(struct kh_setup_preset_mirror, kimg_size) == KH_OFF_kimg_size, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, kpimg_size) == KH_OFF_kpimg_size, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, kernel_size) == KH_OFF_kernel_size, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, page_shift) == KH_OFF_page_shift, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, setup_offset) == KH_OFF_setup_offset, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, start_offset) == KH_OFF_start_offset, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, extra_size) == KH_OFF_extra_size, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, map_offset) == KH_OFF_map_offset, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, map_max_size) == KH_OFF_map_max_size, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, kallsyms_lookup_name_off) == KH_OFF_kallsyms_lookup_name_off, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, paging_init_offset) == KH_OFF_paging_init_offset, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, printk_offset) == KH_OFF_printk_offset, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, map_symbol) == KH_OFF_map_symbol, "");
_Static_assert(offsetof(struct kh_setup_preset_mirror, header_backup) == KH_OFF_header_backup, "");

/* Write a little-endian int64 at out + off. */
static void write_le64(uint8_t *out, size_t off, int64_t val)
{
    uint64_t u = (uint64_t)val;
    for (int i = 0; i < 8; i++) {
        out[off + i] = (uint8_t)(u >> (i * 8));
    }
}

/* Pack version_t (4 bytes: pad/patch/minor/major). */
static void write_version(uint8_t *out, size_t off,
                          uint8_t major, uint8_t minor, uint8_t patch)
{
    out[off + 0] = 0;
    out[off + 1] = patch;
    out[off + 2] = minor;
    out[off + 3] = major;
}

int kh_image_inject(const uint8_t *kernel, size_t kernel_len,
                    const uint8_t *khimg,  size_t khimg_len,
                    const uint8_t *blob,   size_t blob_len,
                    uint8_t **out_buf, size_t *out_len)
{
    if (!out_buf || !out_len) return -1;
    *out_buf = NULL;
    *out_len = 0;

    if (!kernel || !khimg || kernel_len < 0x40 || khimg_len < KP_HEADER_SIZE) {
        fprintf(stderr, "kh: image_inject: bad input sizes\n");
        return -1;
    }

    /* 1. Mutable working copy of the kernel for kallsyms analysis +
     *    PAC NOPing. Keep `kernel` itself untouched. */
    uint8_t *kallsym_kimg = (uint8_t *)malloc(kernel_len);
    if (!kallsym_kimg) {
        fprintf(stderr, "kh: image_inject: malloc kallsym_kimg failed\n");
        return -1;
    }
    memcpy(kallsym_kimg, kernel, kernel_len);

    kallsym_t info = {0};
    if (analyze_kallsym_info(&info, (char *)kallsym_kimg,
                             (int32_t)kernel_len, ARM64, 1) != 0) {
        fprintf(stderr, "kh: image_inject: analyze_kallsym_info failed\n");
        free(kallsym_kimg);
        return -1;
    }

    struct kh_kernel_info kinfo;
    if (kh_get_kernel_info(&kinfo, kernel, kernel_len) != 0) {
        free(kallsym_kimg);
        return -1;
    }

    /* 2. Required symbols. */
    int32_t paging_init_off = get_symbol_offset(&info, (char *)kallsym_kimg, "paging_init");
    int32_t kallsyms_lookup_name_off = get_symbol_offset(&info, (char *)kallsym_kimg, "kallsyms_lookup_name");
    int32_t printk_off = get_symbol_offset(&info, (char *)kallsym_kimg, "printk");
    if (printk_off < 0) printk_off = get_symbol_offset(&info, (char *)kallsym_kimg, "_printk");
    int32_t tcp_init_sock_off = get_symbol_offset(&info, (char *)kallsym_kimg, "tcp_init_sock");

    if (paging_init_off < 0 || kallsyms_lookup_name_off < 0 ||
        printk_off < 0 || tcp_init_sock_off < 0) {
        fprintf(stderr,
                "kh: image_inject: required symbols missing "
                "(paging_init=%d kallsyms_lookup_name=%d printk=%d tcp_init_sock=%d)\n",
                paging_init_off, kallsyms_lookup_name_off, printk_off, tcp_init_sock_off);
        free(kallsym_kimg);
        return -1;
    }

    /* 3. NOP PAC region inside kallsym_kimg. */
    int32_t map_start = 0, map_max_size = 0;
    if (kh_select_map_area(&info, kallsym_kimg, &map_start, &map_max_size) != 0) {
        free(kallsym_kimg);
        return -1;
    }

    /* 4. Resolve the 5 memblock_* symbols. */
    uint8_t map_symbol_bytes[40] = {0};
    if (kh_fillin_map_symbol(&info, kallsym_kimg, map_symbol_bytes) != 0) {
        free(kallsym_kimg);
        return -1;
    }

    /* 5. Resolve paging_init's first B if any. */
    int32_t paging_init_resolved = kh_relo_branch_func(kallsym_kimg, paging_init_off);

    /* 6. Layout: [ kernel | pad | khimg | blob ]. */
    size_t align_kimg_len = (kernel_len + 0xFFFu) & ~(size_t)0xFFFu;
    if (align_kimg_len > SIZE_MAX - khimg_len ||
        align_kimg_len + khimg_len > SIZE_MAX - blob_len) {
        fprintf(stderr, "kh: image_inject: combined size overflow\n");
        free(kallsym_kimg);
        return -1;
    }
    size_t total_len = align_kimg_len + khimg_len + blob_len;
    int32_t start_offset = (int32_t)(align_kimg_len + 0x1000);

    uint8_t *out = (uint8_t *)malloc(total_len);
    if (!out) {
        fprintf(stderr, "kh: image_inject: malloc out_buf failed\n");
        free(kallsym_kimg);
        return -1;
    }
    /* Original kernel bytes (untouched by NOP). */
    memcpy(out, kernel, kernel_len);
    /* 4K alignment pad. */
    if (align_kimg_len > kernel_len) {
        memset(out + kernel_len, 0, align_kimg_len - kernel_len);
    }
    /* khimg payload. */
    memcpy(out + align_kimg_len, khimg, khimg_len);
    /* trailer blob. */
    if (blob_len) {
        memcpy(out + align_kimg_len + khimg_len, blob, blob_len);
    }

    /* 7. Sync NOPed PAC region from kallsym_kimg back to out. */
    size_t sync_start = (size_t)tcp_init_sock_off;
    size_t sync_size = (size_t)map_max_size * 2;
    if (sync_start < kernel_len) {
        if (sync_start + sync_size > kernel_len) {
            sync_size = kernel_len - sync_start;
        }
        memcpy(out + sync_start, kallsym_kimg + sync_start, sync_size);
    }

    /* 8. Fill setup_preset_t at out + align_kimg_len + KP_HEADER_SIZE. */
    size_t preset_base = align_kimg_len + KP_HEADER_SIZE;

    /* version_t at offset 0 (kernel_version). */
    write_version(out, preset_base + KH_OFF_kernel_version,
                  info.version.major, info.version.minor, info.version.patch);
    /* The 4-byte trailing pad of version_t + the int32_t _ field together
     * occupy bytes [4..8) — already zero from malloc-then-memcpy, but be
     * explicit. */
    memset(out + preset_base + 4, 0, 4);

    write_le64(out, preset_base + KH_OFF_kimg_size,                (int64_t)kernel_len);
    write_le64(out, preset_base + KH_OFF_kpimg_size,               (int64_t)khimg_len);
    write_le64(out, preset_base + KH_OFF_kernel_size,              kinfo.kernel_size);
    write_le64(out, preset_base + KH_OFF_page_shift,               (int64_t)kinfo.page_shift);
    write_le64(out, preset_base + KH_OFF_setup_offset,             (int64_t)align_kimg_len);
    write_le64(out, preset_base + KH_OFF_start_offset,             (int64_t)start_offset);
    write_le64(out, preset_base + KH_OFF_extra_size,               (int64_t)blob_len);
    write_le64(out, preset_base + KH_OFF_map_offset,               (int64_t)map_start);
    write_le64(out, preset_base + KH_OFF_map_max_size,             (int64_t)map_max_size);
    write_le64(out, preset_base + KH_OFF_kallsyms_lookup_name_off, (int64_t)kallsyms_lookup_name_off);
    write_le64(out, preset_base + KH_OFF_paging_init_offset,       (int64_t)paging_init_resolved);
    write_le64(out, preset_base + KH_OFF_printk_offset,            (int64_t)printk_off);

    /* map_symbol_t — 40 bytes. */
    memcpy(out + preset_base + KH_OFF_map_symbol, map_symbol_bytes, sizeof(map_symbol_bytes));

    /* header_backup — first 8 bytes of original kernel header. */
    memcpy(out + preset_base + KH_OFF_header_backup, kernel, HDR_BACKUP_SIZE);

    /* 9. Redirect the kernel boot B to khimg's setup_entry. */
    if (kh_arm64_b((uint32_t *)(out + kinfo.b_stext_insn_offset),
                   (uint64_t)kinfo.b_stext_insn_offset,
                   (uint64_t)start_offset) != 4) {
        fprintf(stderr, "kh: image_inject: B encode out of range\n");
        free(out);
        free(kallsym_kimg);
        return -1;
    }

    /* 10. Update kernel header kernel_size_le to reflect total payload. */
    kh_kernel_resize(out, total_len, (int64_t)total_len);

    free(kallsym_kimg);
    *out_buf = out;
    *out_len = total_len;
    return 0;
}
