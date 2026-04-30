/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kernelhook.ko — ARM64 function hooking kernel module.
 *
 * Usage:
 *   insmod kernelhook.ko [kallsyms_addr=0x...]
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <types.h>
#include <kh_hook.h>
#include <sync.h>
#include <memory.h>
#include <symbol.h>
#include <linux/printk.h>

#include <arch/arm64/pgtable.h>

#include "compat.h"
#include "mem_ops.h"

#if !defined(KH_PAYLOAD) && !defined(KH_FAT_LINK)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelHook: ARM64 function hooking framework");
#endif

#if defined(KMOD_FREESTANDING) && !defined(KH_PAYLOAD)
MODULE_VERSIONS();
MODULE_VERMAGIC();
MODULE_THIS_MODULE();
#endif

/* Force into .data (not .bss) so kmod_loader's patch_elf_symbol can write
 * the resolved address into the file-backed section. See exporter.c for the
 * full rationale (Plan 2 M-E T17 fix).
 *
 * KH_PAYLOAD: non-static so graft tools / kmod_loader can locate the symbol
 * in the merged vendor-ko symtab; no module_param because the payload is
 * invoked via a vendor .ko's init_module, not the kernel's module-param
 * machinery — the address is injected via patch_elf_symbol after graft. */
#ifdef KH_PAYLOAD
unsigned long kallsyms_addr __attribute__((used, section(".data"))) = 0;
#else
static unsigned long kallsyms_addr __attribute__((used, section(".data"))) = 0;
module_param(kallsyms_addr, ulong, 0444);
MODULE_PARM_DESC(kallsyms_addr, "Address of kallsyms_lookup_name (hex, required for freestanding builds)");
#endif

extern void kh_hook_chain_setup_transit(kh_hook_chain_rox_t *rox);
extern void kh_fp_hook_chain_setup_transit(kh_fp_hook_chain_rox_t *rox);
extern void kh_write_insts_init(void);
extern void kh_write_insts_cleanup(void);
extern int  kh_strategy_boot(void);
extern int  kh_strategy_post_init(void);

static int kh_initialized = 0;

/* Non-static so KH_PAYLOAD mode can alias `kh_entry` to it. `__attribute__((alias))`
 * requires the target to have external linkage. */
#if defined(KH_PAYLOAD) || defined(KH_FAT_LINK)
int __init kernelhook_init(void)
#else
static int __init kernelhook_init(void)
#endif
{
    int rc;

    pr_info("kernelhook: loading...\n");

#ifdef KH_PAYLOAD_SMOKE
    /* Level-0 smoke: return 0 immediately.  No pr_info, no symbol lookup,
     * no stack work beyond the BL return.  If the kernel still panics
     * loading this, the problem is in the ELF load path (relocation,
     * CFI, BTI), not in our code. */
    (void)rc;
    return 0;
#endif

    rc = kmod_compat_init(kallsyms_addr);
    if (rc) {
        pr_err("kernelhook: compat init failed (%d)\n", rc);
        return rc;
    }

    /* Strategy registry: register link-time strategies, apply module params,
     * run optional consistency check.  Must run before hook-mem init so any
     * future strategy that resolves a capability (e.g. alias-page path) is
     * available to kmod_hook_mem_init(). */
    rc = kh_strategy_boot();
    if (rc) {
        pr_err("kernelhook: strategy boot failed (%d)\n", rc);
        return rc;
    }

    rc = kmod_hook_mem_init();
    if (rc) {
        pr_err("kernelhook: hook_mem init failed (%d)", rc);
        return rc;
    }

    /* Initialize page table walker — required for kh_hook_install() to
     * modify kernel code pages via PTE manipulation. */
    rc = kh_pgtable_init();
    if (rc) {
        pr_err("kernelhook: kh_pgtable_init failed (%d)", rc);
        kmod_hook_mem_cleanup();
        return rc;
    }

    /* Resolve set_memory_rw/ro/x for write_insts_at */
    kh_write_insts_init();

    /* Run consistency check now that pgtable globals are populated.
     * No-op unless kh_consistency_check=1 was set at load time. */
    kh_strategy_post_init();

    rc = kh_sync_init();
    if (rc) {
        pr_err("kernelhook: sync init failed (%d)\n", rc);
        kmod_hook_mem_cleanup();
        return rc;
    }

    /* Syscall infra + uaccess helpers. Non-fatal: the framework still
     * provides inline/fp kh_hook APIs if these fail to initialise. */
    {
        extern int kh_syscall_init(void);
        extern int kh_uaccess_init(void);
        int srv = kh_syscall_init();
        int urv = kh_uaccess_init();
        if (srv) pr_warn("kernelhook: kh_syscall_init returned %d\n", srv);
        if (urv) pr_warn("kernelhook: kh_uaccess_init returned %d\n", urv);
    }

    kh_initialized = 1;
    pr_info("kernelhook: loaded successfully (kernel %d.%d.%d)",
          kmod_kernel_major, kmod_kernel_minor, kmod_kernel_patch);

    return 0;
}

/*
 * IMPORTANT: Consumer modules MUST call kh_hook_unwrap()/kh_unhook() for all
 * their hooks before kernelhook.ko is unloaded. This module does not
 * track or teardown hooks registered by other modules.
 */
#if defined(KH_PAYLOAD) || defined(KH_FAT_LINK)
void __exit kernelhook_exit(void)
#else
static void __exit kernelhook_exit(void)
#endif
{
    if (kh_initialized) {
        sync_cleanup();
        kh_write_insts_cleanup();
        kmod_hook_mem_cleanup();
        pr_info("kernelhook: unloaded");
    }
}

#ifdef KH_PAYLOAD
/* Payload entry/exit — graft tools rewrite a host vendor .ko's
 * .rela.gnu.linkonce.this_module init/exit relocations to point at these
 * aliases.  The host's existing init_module/cleanup_module kCFI hash
 * prefixes are preserved (they hash to the initcall_t typeid, which
 * matches kh_entry's `int (*)(void)` prototype). */
int  kh_entry(void) __attribute__((alias("kernelhook_init")));
void kh_exit(void)  __attribute__((alias("kernelhook_exit")));
#elif defined(KH_FAT_LINK)
/* Under KH_FAT_LINK, fat_main.c owns module_init/exit and calls
 * kernelhook_init/kernelhook_exit explicitly. Don't register here. */
#else
module_init(kernelhook_init);
module_exit(kernelhook_exit);
#endif
