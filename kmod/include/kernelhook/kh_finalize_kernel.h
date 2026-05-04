/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KERNELHOOK_KH_FINALIZE_KERNEL_H
#define KERNELHOOK_KH_FINALIZE_KERNEL_H

/*
 * In-kernel finalize for incoming third-party LKM buffers.
 *
 * Userspace tools/kmod_loader handles the full finalize pipeline
 * (CRCs / vermagic / struct module layout / kCFI / printk / extable)
 * before insmod when running fat.ko itself. fat.ko's path-1 KSU
 * ingest happens after we are already loaded — we must do (at least
 * the most common slice of) finalize on the .ko bytes ourselves.
 *
 * Currently implemented:
 *   __versions CRC patch — driven by `__crc_<sym>` kallsyms entries
 *
 * Deferred (next slices):
 *   vermagic, struct module layout, kCFI, extable format
 *
 * `mod` is mutated in place; caller owns the buffer. Returns 0 on
 * success (including the no-__versions case), -1 on a malformed ELF.
 * Per-symbol CRC lookup misses are logged but do not fail the call —
 * the kernel's syscall body will reject them with a clear "disagrees
 * about version of symbol X" if any are unfixable.
 */
int kh_finalize_versions_in_place(unsigned char *mod, unsigned long mod_size);

#endif /* KERNELHOOK_KH_FINALIZE_KERNEL_H */
