/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KHTOOLS_FILE_IO_H
#define KHTOOLS_FILE_IO_H

#include <stddef.h>
#include <stdint.h>

/* Read entire file at `path` into a freshly-allocated buffer. Caller frees
 * *out_buf on success. Returns 0 on success, -1 on any I/O / allocation
 * failure (errno set by libc). */
int kh_read_file(const char *path, uint8_t **out_buf, size_t *out_len);

/* Write `len` bytes of `buf` to `path`. Returns 0 on success, -1 on any
 * I/O failure (errno set by libc). */
int kh_write_file(const char *path, const uint8_t *buf, size_t len);

#endif
