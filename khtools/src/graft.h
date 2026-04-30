/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KHTOOLS_GRAFT_H
#define KHTOOLS_GRAFT_H

#include <stddef.h>
#include <stdint.h>

/* Replace *ko_buf in-place with the result of grafting the payload (current
 * *ko_buf bytes) into the host module read from host_path. On success,
 * *ko_buf points to a freshly-allocated buffer (caller frees) and *ko_len
 * is updated. On failure, *ko_buf is unchanged. */
int kh_graft_in_place(uint8_t **ko_buf, size_t *ko_len, const char *host_path);

/* Lower-level: caller supplies both buffers; returns a fresh out_buf
 * (caller frees). */
int kh_graft_compose(const uint8_t *host, size_t host_size,
                     const uint8_t *payload, size_t payload_size,
                     uint64_t kallsyms_addr, int have_kallsyms_addr,
                     uint8_t **out_buf, size_t *out_size);

#endif /* KHTOOLS_GRAFT_H */
