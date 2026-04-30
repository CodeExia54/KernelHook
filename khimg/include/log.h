/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
/*
 * Stub log.h for khimg freestanding blob.
 * At early boot there is no printk; all log macros are no-ops.
 * The tlsf.c printf usage (re-mapped to logkd) is compiled out.
 */

#ifndef _KHIMG_LOG_H_
#define _KHIMG_LOG_H_

/* tlsf.c maps printf -> logkd; make it a no-op for the freestanding blob. */
#define logkd(fmt, ...) do {} while (0)
#define logkfd(fmt, ...) do {} while (0)
#define logkv(fmt, ...) do {} while (0)
#define logkfv(fmt, ...) do {} while (0)
#define logki(fmt, ...) do {} while (0)
#define logkfi(fmt, ...) do {} while (0)
#define logkw(fmt, ...) do {} while (0)
#define logkfw(fmt, ...) do {} while (0)
#define logke(fmt, ...) do {} while (0)
#define logkfe(fmt, ...) do {} while (0)

/* Stub declarations matching the KP originals (never called in khimg). */
static inline void log_boot(const char *fmt, ...) { (void)fmt; }
static inline const char *get_boot_log(void) { return ""; }

#endif /* _KHIMG_LOG_H_ */
