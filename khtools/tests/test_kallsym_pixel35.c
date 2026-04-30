/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/kallsym.h"
#include "../src/common.h"

int main(void)
{
    const char *fixture = "khtools/tests/fixtures/pixel35.Image";
    FILE *f = fopen(fixture, "rb");
    if (!f) {
        fprintf(stderr, "skip: fixture %s not present\n", fixture);
        return 77; /* ctest SKIP */
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len);
    if (!buf) { perror("malloc"); fclose(f); return 1; }
    /* fread return checked via assertion below */
    size_t nread = fread(buf, 1, len, f);
    fclose(f);
    if (nread != (size_t)len) { perror("fread"); free(buf); return 1; }

    kallsym_t info = { 0 };
    int rc = analyze_kallsym_info(&info, buf, (int32_t)len, ARM64, 1);
    assert(rc == 0);
    assert(info.kallsyms_num_syms > 1000); /* sanity: kernel has many syms */

    int off = get_symbol_offset(&info, buf, "kallsyms_lookup_name");
    assert(off > 0);
    printf("kallsyms_lookup_name @ +0x%x, total %d syms\n",
           off, info.kallsyms_num_syms);
    free(buf);
    return 0;
}
