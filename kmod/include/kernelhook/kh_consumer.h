/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KERNELHOOK_KH_CONSUMER_H
#define KERNELHOOK_KH_CONSUMER_H

#include <linux/init.h>
#include <linux/module.h>
#include <stdint.h>

/* Use uint16_t (project's core typedefs in include/types.h) rather than the
 * kernel-only `u16` alias — the freestanding shim does not provide it.
 *
 * NULL-exit caveat: the .exit field is allowed to be NULL only in the
 * fat-link build mode (kh_consumer_register expands to a section table
 * entry; fat_main.c null-checks before calling). In the standalone build
 * mode the macro expands to module_exit(exit_fn) which does NOT tolerate
 * a NULL pointer — every standalone-mode consumer must supply a real
 * exit function. */
struct kh_consumer_entry {
    int       (*init)(void);  /* required */
    void      (*exit)(void);  /* may be NULL only in fat-link mode */
    uint16_t   priority;      /* lower runs first; default 500 */
    const char *name;         /* for log */
};

#define KH_PRIO_SUBSYS  100
#define KH_PRIO_NORMAL  500
#define KH_PRIO_LATE    900

#ifdef KH_FAT_LINK
  #define kh_consumer_register(name_str, init_fn, exit_fn, prio)                 \
      static const struct kh_consumer_entry __kh_consumer_##init_fn               \
      __attribute__((used, section(".kh_consumer_table"))) = {                    \
          .init = (init_fn), .exit = (exit_fn),                                   \
          .priority = (prio), .name = (name_str),                                 \
      }
  #define kh_consumer_init(name_str, init_fn, exit_fn) \
      kh_consumer_register(name_str, init_fn, exit_fn, KH_PRIO_NORMAL)
#else
  /* Standalone build: each consumer is its own .ko with module_init/exit. */
  #define kh_consumer_register(name_str, init_fn, exit_fn, prio) \
      module_init(init_fn); module_exit(exit_fn)
  #define kh_consumer_init(name_str, init_fn, exit_fn) \
      kh_consumer_register(name_str, init_fn, exit_fn, 0)
#endif

#endif /* KERNELHOOK_KH_CONSUMER_H */
