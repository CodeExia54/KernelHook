/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khtools verify — sanity-check a boot.img patched by `khtools patch`.
 *
 * Walks the patched kernel section trailer:
 *   1. magiskboot unpack <patched_boot.img> → tmp/kernel.
 *   2. Scan kernel from end-of-file backwards for the kh_blob_table_v1
 *      magic ('KHBL'). The trailer sits at known offset
 *      (kernel_size - sizeof(table) - fat_len - ksu_len), but we don't
 *      know fat_len / ksu_len up front, so the check is: read
 *      sizeof(table) bytes from a candidate offset and verify magic.
 *      For the MVP we scan a limited window from the end.
 *   3. Verify table->magic == KHBL_MAGIC and table->version == 1.
 *   4. Recompute SHA-256 of the embedded fat.ko bytes; compare with
 *      table->fat_sha256. Same for ksu if present.
 *
 * This is a CI / pre-flash sanity gate. It does NOT verify that khimg
 * is wired into a kernel boot hook (that wiring lands in Task 4.2's
 * follow-up). The verify subcommand answers "is the trailer well-formed
 * and unmodified" only.
 *
 * Path-quoting note: --boot path is wrapped in '...' for system() —
 * paths with literal single quotes will break the command. Same caveat
 * as cmd_patch.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "cmd_dispatch.h"
#include "embed_blob.h"
#include "file_io.h"
#include "sha256.h"

static int sha256_eq(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, 32) == 0;
}

static void compute_sha256(const uint8_t *in, size_t n, uint8_t out[32])
{
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, in, n);
	sha256_final(&ctx, out);
}

/* Search backward from end-of-buffer for the KHBL magic. Returns
 * offset (0 ≤ offset ≤ buf_len - sizeof(struct)) or -1 if absent. */
static long find_blob_magic(const uint8_t *buf, size_t buf_len)
{
	const size_t hdr = sizeof(struct kh_blob_table_v1);
	if (buf_len < hdr)
		return -1;

	/* Scan a generous window — boot.img kernels are at most ~256MB
	 * but the trailer always sits in the last ~64MB. */
	size_t scan_window = buf_len < (64UL << 20) ? buf_len : (64UL << 20);
	size_t start = buf_len - scan_window;

	for (size_t off = buf_len - hdr; off >= start; off -= 4) {
		uint32_t cand;
		memcpy(&cand, buf + off, 4);
		if (cand == KHBL_MAGIC) {
			/* Sanity: version must be 1, offsets must fit. */
			const struct kh_blob_table_v1 *t =
				(const struct kh_blob_table_v1 *)(buf + off);
			if (t->version != 1)
				continue;
			if ((uint64_t)t->fat_off + t->fat_len > buf_len - off)
				continue;
			if (t->ksu_len &&
			    (uint64_t)t->ksu_off + t->ksu_len > buf_len - off)
				continue;
			return (long)off;
		}
		if (off < 4)
			break;
	}
	return -1;
}

int cmd_verify(int argc, char **argv)
{
	static struct option opts[] = {
		{"boot", required_argument, 0, 'b'},
		{0, 0, 0, 0}
	};
	const char *boot = NULL;
	int c, idx;
	optind = 1;
	while ((c = getopt_long(argc, argv, "b:", opts, &idx)) != -1) {
		if (c == 'b')
			boot = optarg;
		else if (c == '?')
			return 2;
	}
	if (!boot) {
		fprintf(stderr, "khtools verify: --boot PATH is required\n");
		return 5;
	}

	char tmpdir[] = "/tmp/khtools-verify-XXXXXX";
	if (!mkdtemp(tmpdir)) {
		fprintf(stderr, "khtools verify: mkdtemp failed\n");
		return 5;
	}

	char cmd[2048];
	snprintf(cmd, sizeof(cmd),
	         "cd '%s' && magiskboot unpack '%s' >/dev/null 2>&1",
	         tmpdir, boot);
	int rc_sys = system(cmd);
	if (rc_sys != 0) {
		fprintf(stderr, "kh: verify: magiskboot unpack failed\n");
		snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
		system(cmd);
		return 5;
	}

	char kernel_path[512];
	snprintf(kernel_path, sizeof(kernel_path), "%s/kernel", tmpdir);
	uint8_t *kernel = NULL;
	size_t kernel_len = 0;
	int rc = kh_read_file(kernel_path, &kernel, &kernel_len);

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpdir);
	system(cmd);

	if (rc < 0) {
		fprintf(stderr, "kh: verify: cannot read unpacked kernel\n");
		return 5;
	}

	long blob_off = find_blob_magic(kernel, kernel_len);
	if (blob_off < 0) {
		fprintf(stderr,
		        "kh: verify: KHBL magic not found in trailer "
		        "(boot.img not patched, or trailer corrupted)\n");
		free(kernel);
		return 6;
	}

	const struct kh_blob_table_v1 *t =
		(const struct kh_blob_table_v1 *)(kernel + blob_off);

	uint8_t hash[32];
	const uint8_t *fat_bytes = (const uint8_t *)t + t->fat_off;
	compute_sha256(fat_bytes, t->fat_len, hash);
	if (!sha256_eq(hash, t->fat_sha256)) {
		fprintf(stderr, "kh: verify: fat.ko SHA-256 mismatch\n");
		free(kernel);
		return 6;
	}

	if (t->ksu_len) {
		const uint8_t *ksu_bytes = (const uint8_t *)t + t->ksu_off;
		compute_sha256(ksu_bytes, t->ksu_len, hash);
		if (!sha256_eq(hash, t->ksu_sha256)) {
			fprintf(stderr, "kh: verify: KSU SHA-256 mismatch\n");
			free(kernel);
			return 6;
		}
	}

	printf("kh verify: OK\n");
	printf("  trailer offset : %ld\n", blob_off);
	printf("  fat.ko bytes   : %u\n", t->fat_len);
	printf("  ksu.ko bytes   : %u%s\n",
	       t->ksu_len, t->ksu_len ? "" : " (absent)");

	free(kernel);
	return 0;
}
