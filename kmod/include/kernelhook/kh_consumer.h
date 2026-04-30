/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 bmax121. All Rights Reserved. */
#ifndef KERNELHOOK_KH_CONSUMER_H
#define KERNELHOOK_KH_CONSUMER_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

struct kh_consumer_entry {
    int  (*init)(void);     /* required */
    void (*exit)(void);     /* may be NULL */
    u16   priority;         /* lower runs first; default 500 */
    const char *name;       /* for log */
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
