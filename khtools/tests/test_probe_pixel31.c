/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/probe_image.h"

int main(void) {
    const char *fixture = "khtools/tests/fixtures/pixel31.Image";
    FILE *f = fopen(fixture, "rb");
    if (!f) { fprintf(stderr, "skip: %s not present\n", fixture); return 77; }
    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); return 1; }
    long len = ftell(f);
    if (len < 0) { perror("ftell"); fclose(f); return 1; }
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)len);
    if (!buf) { fclose(f); return 1; }
    size_t nread = fread(buf, 1, (size_t)len, f);
    fclose(f);
    if (nread != (size_t)len) { free(buf); return 1; }

    struct kh_probe_report r;
    int rc = kh_probe_image(buf, (size_t)len, &r);
    free(buf);
    assert(rc == 0);
    assert(r.kallsyms_count > 1000);
    assert(r.kcfi_initcall_typeid == 0);  /* Pixel_31 (5.10) — no kCFI initcall hardening */
    return 0;
}
