/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * khimg slim setup.c — replaces KP kernel/base/setup.c.
 * Defines the three linker-placed objects that setup1.S references:
 *   header       (.setup.header section)
 *   setup_preset (.setup.preset section)
 *   stack        (.setup.data section)
 *
 * Version fields are left zero for the skeleton; Task 4.2 will stamp them
 * during boot.img embedding via the kh_blob_table trailer.
 */

#include <setup.h>

setup_header_t header __attribute__((section(".setup.header"))) = {
    .magic       = KP_MAGIC,
    .config_flags = 0,
    /* kp_version, compile_time left zero — stamped at embed time */
};

setup_preset_t setup_preset __attribute__((section(".setup.preset"))) = { 0 };

struct {
    uint8_t fp[STACK_SIZE];
    uint8_t sp[0];
} stack __attribute__((section(".setup.data"))) __attribute__((aligned(16)));
