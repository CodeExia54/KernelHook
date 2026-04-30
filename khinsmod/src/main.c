/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khinsmod — KernelHook path-1 device-side loader.
 *
 * Wraps finit_module(2) for fat.ko loading. Optionally injects a
 * KernelSU LKM by writing its bytes to /sys/kernel/kh/pending_ksu
 * (sysfs node registered by fat.ko / Task 5.3).
 *
 * Usage: khinsmod [--probe] [--force] [--ksu PATH] fat.ko
 *
 * Exit codes (per spec §6.1):
 *   0  ok
 *   1  usage error / unknown option
 *   2  argument validation
 *   7  finit_module / load failure
 *   8  build-id mismatch (override with --force)
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int sys_finit_module(int fd, const char *args, int flags) {
    return (int)syscall(__NR_finit_module, fd, args, flags);
}

static int read_proc_kernel_version(char *buf, size_t buflen) {
    FILE *f = fopen("/proc/version", "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, buflen - 1, f);
    fclose(f);
    if (n == 0) return -1;
    buf[n] = 0;
    /* Trim trailing whitespace/newlines. */
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r' || buf[n-1] == ' ')) {
        buf[--n] = 0;
    }
    return 0;
}

/* Stub for now: real ELF section walker for .kh_meta lands in
 * Discovery 7 follow-up (per plan). Returns -1 (not extracted) so the
 * --probe path with no .kh_meta yields "no embedded build-id" rather
 * than spurious mismatches. */
static int extract_kh_meta_buildid(const char *ko_path, char *out, size_t outlen) {
    (void)ko_path; (void)out; (void)outlen;
    /* TODO(discovery-7): minimal ELF parser to read .kh_meta build-id. */
    return -1;
}

static void usage(void) {
    fprintf(stderr,
        "khinsmod — KernelHook path-1 device-side loader\n"
        "Usage: khinsmod [--probe] [--force] [--ksu PATH] fat.ko\n"
        "\n"
        "Options:\n"
        "  --probe      Don't load; just check build-id match.\n"
        "  --force      Load even if build-id doesn't match running kernel.\n"
        "  --ksu PATH   After fat.ko loads, push PATH into /sys/kernel/kh/pending_ksu.\n"
        "  -h, --help   This text.\n");
}

int main(int argc, char **argv) {
    bool probe = false, force = false;
    const char *ksu_path = NULL;

    static struct option opts[] = {
        {"probe", no_argument,       0, 'p'},
        {"force", no_argument,       0, 'f'},
        {"ksu",   required_argument, 0, 'k'},
        {"help",  no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    int c, idx;
    while ((c = getopt_long(argc, argv, "pfk:h", opts, &idx)) != -1) {
        switch (c) {
        case 'p': probe = true; break;
        case 'f': force = true; break;
        case 'k': ksu_path = optarg; break;
        case 'h': usage(); return 0;
        default: usage(); return 1;
        }
    }
    if (optind >= argc) {
        usage();
        return 1;
    }
    const char *ko_path = argv[optind];

    /* Build-id check (best-effort — extractor is a stub for now). */
    char ko_id[128] = "", run_id[256] = "";
    int have_ko_id = (extract_kh_meta_buildid(ko_path, ko_id, sizeof(ko_id)) == 0);
    int have_run_id = (read_proc_kernel_version(run_id, sizeof(run_id)) == 0);
    if (have_ko_id && have_run_id && strcmp(ko_id, run_id) != 0) {
        if (!force) {
            fprintf(stderr,
                    "kh: insmod: fat.ko built for kernel '%s', running '%s'; use --force to override\n",
                    ko_id, run_id);
            return 8;
        }
        fprintf(stderr, "kh: insmod: build-id mismatch but --force given, continuing\n");
    }
    if (probe) {
        if (have_ko_id && have_run_id) {
            printf("kh: insmod: fat.ko build-id matches running kernel\n");
        } else if (!have_ko_id) {
            printf("kh: insmod: no embedded build-id (extractor stub — discovery-7 pending)\n");
        } else {
            printf("kh: insmod: cannot read /proc/version\n");
        }
        return 0;
    }

    int fd = open(ko_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "kh: insmod: open '%s' failed: %s\n", ko_path, strerror(errno));
        return 7;
    }
    int rc = sys_finit_module(fd, "", 0);
    int saved_errno = errno;
    close(fd);
    if (rc != 0) {
        fprintf(stderr,
                "kh: insmod: finit_module returned %d (errno=%d: %s)\n",
                rc, saved_errno, strerror(saved_errno));
        return 7;
    }

    if (ksu_path) {
        int sysfs_fd = open("/sys/kernel/kh/pending_ksu", O_WRONLY);
        if (sysfs_fd < 0) {
            fprintf(stderr,
                    "kh: insmod: cannot open /sys/kernel/kh/pending_ksu (%s); "
                    "fat.ko loaded but KSU injection skipped\n",
                    strerror(errno));
            /* fat.ko itself loaded — return 0 with a warning. */
        } else {
            int ksu_fd = open(ksu_path, O_RDONLY);
            if (ksu_fd < 0) {
                fprintf(stderr, "kh: insmod: open '%s' failed: %s\n",
                        ksu_path, strerror(errno));
                close(sysfs_fd);
                return 7;
            }
            char buf[8192];
            ssize_t n;
            while ((n = read(ksu_fd, buf, sizeof(buf))) > 0) {
                ssize_t off = 0;
                while (off < n) {
                    ssize_t w = write(sysfs_fd, buf + off, (size_t)(n - off));
                    if (w < 0) {
                        fprintf(stderr, "kh: insmod: write to pending_ksu failed: %s\n",
                                strerror(errno));
                        close(ksu_fd); close(sysfs_fd);
                        return 7;
                    }
                    off += w;
                }
            }
            close(ksu_fd);
            close(sysfs_fd);
        }
    }
    fprintf(stderr, "kh: insmod: fat.ko loaded\n");
    return 0;
}
