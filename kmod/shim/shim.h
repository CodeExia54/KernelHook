/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Minimal kernel shims for freestanding .ko build (Approach B).
 *
 * Replaces <linux/module.h>, <linux/kernel.h>, etc. for builds
 * that don't have access to the kernel source tree.
 *
 * The module loader only needs:
 *   - .modinfo section entries (license, description, etc.)
 *   - init_module / cleanup_module symbols
 *   - Proper ELF relocatable format (ET_REL)
 */

#ifndef _SHIM_H_
#define _SHIM_H_

#ifndef KMOD_FREESTANDING
#error "shim.h is freestanding-only; kbuild code must include <linux/*> directly"
#endif

#include <types.h>

/* SDK-consumer builds automatically emit __versions entries for every
 * kh_* export they might import (see MODULE_VERSIONS() macro below).
 * Guarded on KH_SDK_MODE so kernelhook.ko's own build (which defines the
 * exports, not imports them) doesn't pick up self-referential entries. */
#ifdef KH_SDK_MODE
#include <kernelhook/kh_symvers.h>
#endif

/* ---- .modinfo section entries ---- */

#define __MODULE_INFO(tag, name, info)                                  \
    static const char __UNIQUE_ID(name)[]                               \
        __used __section(".modinfo") __aligned(1) = #tag "=" info

#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__unique_, prefix), __COUNTER__)
#define __PASTE(a, b) __PASTE2(a, b)
#define __PASTE2(a, b) a##b

#define MODULE_LICENSE(x)       __MODULE_INFO(license, license, x)
#define MODULE_AUTHOR(x)        __MODULE_INFO(author, author, x)
#define MODULE_DESCRIPTION(x)   __MODULE_INFO(description, description, x)
#define MODULE_PARM_DESC(parm, desc) __MODULE_INFO(parm, parm, #parm ":" desc)

/* ---- Module init/exit via aliases ---- */

#define module_init(fn) \
    int init_module(void) __attribute__((alias(#fn)));
#define module_exit(fn) \
    void cleanup_module(void) __attribute__((alias(#fn)));

/* THIS_MODULE — pointer to this module's struct module instance.
 * In freestanding builds, __this_module is defined by MODULE_THIS_MODULE()
 * (called from the main translation unit). We expose it as extern here and
 * define THIS_MODULE as &__this_module, matching the real kernel macro from
 * include/linux/export.h. */
struct module;
extern struct module __this_module;
#ifndef THIS_MODULE
#define THIS_MODULE (&__this_module)
#endif

/* ---- Module parameter ----
 *
 * Freestanding module_param implementation. The kernel's parse_args()
 * iterates the __param section looking for matching kernel_param entries.
 * Each entry has a name, a set callback, and a pointer to the variable.
 *
 * We only support 'ulong' type (enough for kallsyms_addr). The set
 * callback must be resolved at runtime via ksyms because param_set_ulong
 * is not exported. Instead we provide a minimal inline parser.
 */

/* Minimal kernel_param struct (must match kernel's layout exactly).
 * See include/linux/moduleparam.h in kernel source. */
struct kernel_param;

/* param_set/get function pointer types */
typedef int (*param_set_fn)(const char *val, const struct kernel_param *kp);
typedef int (*param_get_fn)(char *buffer, const struct kernel_param *kp);

struct kernel_param_ops {
    unsigned int flags;
    param_set_fn set;
    param_get_fn get;
    void (*free)(void *arg);
};

struct kernel_param {
    const char *name;
    struct module *mod;            /* unused in freestanding */
    const struct kernel_param_ops *ops;
    uint16_t perm;
    int8_t level;                  /* -1 = early, 0+ = normal */
    uint8_t flags;
    union {
        void *arg;
        const void *str;           /* kparam_string */
    };
};

/* Simple ulong parser for module_param(x, ulong, ...) */
static int __kmod_param_set_ulong(const char *val, const struct kernel_param *kp)
{
    unsigned long result = 0;
    const char *p = val;

    /* Skip leading whitespace */
    while (*p == ' ' || *p == '\t') p++;

    /* Parse hex (0x prefix) or decimal */
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
        while (*p) {
            unsigned int digit;
            if (*p >= '0' && *p <= '9') digit = *p - '0';
            else if (*p >= 'a' && *p <= 'f') digit = *p - 'a' + 10;
            else if (*p >= 'A' && *p <= 'F') digit = *p - 'A' + 10;
            else break;
            result = (result << 4) | digit;
            p++;
        }
    } else {
        while (*p >= '0' && *p <= '9') {
            result = result * 10 + (*p - '0');
            p++;
        }
    }

    *(unsigned long *)kp->arg = result;
    return 0;
}

static const struct kernel_param_ops __kmod_param_ops_ulong = {
    .flags = 0,
    .set = __kmod_param_set_ulong,
    .get = (param_get_fn)0,
    .free = (void (*)(void *))0,
};

/* int parser — same numeric parsing as ulong, narrowed to 4 bytes.
 * Pre-existing module_param(name, int, ...) callers (log_level,
 * kh_consistency_check) used to silently route through the ulong
 * setter, which 8-byte-wrote into a 4-byte int slot. This dedicated
 * setter prevents that overrun. */
static int __kmod_param_set_int(const char *val, const struct kernel_param *kp)
{
    long sign = 1;
    if (*val == '-') { sign = -1; val++; }
    unsigned long u = 0;
    long r = 0;
    if (__kmod_param_set_ulong(val, &(struct kernel_param){
        .name = kp->name, .ops = kp->ops, .arg = &u
    }) == 0) {
        r = sign * (long)u;
    }
    *(int *)kp->arg = (int)r;
    return 0;
}

/* charp parser — points the *char slot at the kernel-supplied raw
 * string. Kernel guarantees args strings are stable for the module's
 * lifetime. */
static int __kmod_param_set_charp(const char *val, const struct kernel_param *kp)
{
    *(const char **)kp->arg = val;
    return 0;
}

static const struct kernel_param_ops __kmod_param_ops_int = {
    .flags = 0,
    .set = __kmod_param_set_int,
    .get = (param_get_fn)0,
    .free = (void (*)(void *))0,
};

static const struct kernel_param_ops __kmod_param_ops_charp = {
    .flags = 0,
    .set = __kmod_param_set_charp,
    .get = (param_get_fn)0,
    .free = (void (*)(void *))0,
};

/* Token-pasted ops selector so module_param(name, T, ...) picks
 * the right setter at compile time. Add new types here. */
#define __KMOD_PARAM_OPS_ulong  (&__kmod_param_ops_ulong)
#define __KMOD_PARAM_OPS_int    (&__kmod_param_ops_int)
#define __KMOD_PARAM_OPS_charp  (&__kmod_param_ops_charp)

/* Helper macro to avoid C preprocessor expanding `name` in `.name = ...` */
#define __KMOD_PARAM(var_name, str_name, ops_val, perm_val)             \
    static const struct kernel_param __param_##var_name                  \
        __used __aligned(sizeof(void *))                                \
        __section("__param") = {                                        \
            .name = str_name,                                           \
            .mod = (struct module *)0,                                  \
            .ops = (ops_val),                                           \
            .perm = (perm_val),                                         \
            .level = -1,                                                \
            .flags = 0,                                                 \
            .arg = &var_name,                                           \
        }

#define module_param(name, type, perm)                                  \
    __MODULE_INFO(parmtype, name##type, #name ":" #type);               \
    __KMOD_PARAM(name, #name, __KMOD_PARAM_OPS_##type, perm)

/* module_param_named(exposed_name, var, type, perm) — exposes `var` to
 * userspace under a different parameter name. Freestanding: like module_param
 * but decouples the parameter name from the variable name, e.g. for a
 * namespaced global like kh_loader_injected_* visible as a short insmod
 * argument like iomem_textpa. Routes through the same __kmod_param_ops_ulong
 * setter regardless of `type` (see the caveat on module_param above). */
#define module_param_named(exposed_name, var, type, perm)                  \
    __MODULE_INFO(parmtype, var##type, #exposed_name ":" #type);           \
    __KMOD_PARAM(var, #exposed_name, __KMOD_PARAM_OPS_##type, perm)

/* ---- Kernel PAGE_SIZE ---- */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096UL
#endif

/* ---- printk / pr_xxx ---- */
#include <linux/printk.h>

/* ---- Minimal bool ---- */
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

/* ---- Minimal errno ---- */
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOENT
#define ENOENT 2
#endif
#ifndef ENOMEM
#define ENOMEM 12
#endif

/* ---- memset / memcpy / memmove ----
 *
 * Defined in kmod/shim/shim_libc.c (freestanding self-implementations).
 * Declared here as plain prototypes so callers link to our definitions
 * rather than treating them as extern-kernel references. See
 * memory/feedback_ksyms_over_extern.md for the rule. */
void *memset(void *s, int c, unsigned long n);
void *memcpy(void *dst, const void *src, unsigned long n);
void *memmove(void *dst, const void *src, unsigned long n);

/* ---- __init / __exit section attributes ---- */
#define __init __section(".init.text")
#define __exit __section(".exit.text")

/* ---- __versions (modversion CRC table) ----
 *
 * When CONFIG_MODVERSIONS=y the kernel checks CRCs for every IMPORTED
 * (undefined) symbol against entries in the module's __versions section.
 * If an imported symbol has no matching entry, try_to_force_load falls
 * through and the kernel refuses to load the module.
 *
 * Since 2026-04-16 this project keeps the UND-symbol set minimal by:
 *   1. Self-implementing pure-algorithm libc (memcpy, memset, memmove,
 *      memcmp, strcmp, strncmp, strchr, strlcpy) in kmod/shim/shim_libc.c.
 *   2. Wrapping every genuinely-kernel function (add_taint, copy_to_user,
 *      copy_from_user, kstrtol, snprintf, vprintk, etc.) in a
 *      ksyms_lookup + static-cache shim in kmod/shim/shim_ksyms.c and
 *      kmod/src/log.c.
 *
 * The only remaining UND symbol that the kernel's module loader checks
 * against __versions is `module_layout`: the kernel's
 * check_modstruct_version() asserts that the module was compiled against
 * a compatible struct module layout. That single entry stays as a
 * sentinel (0xDEADBE01) to be patched at load time by kmod_loader from
 * a reference vendor .ko. See memory/feedback_ksyms_over_extern.md for
 * the full rationale.
 */

struct modversion_info {
    unsigned int crc;
    unsigned int pad;
    char name[56];
};

#define _MODVER_ENTRY(var, crc_val, sym_name)                           \
    static const struct modversion_info var                              \
        __used __section("__versions") __aligned(8) = {                 \
            .crc = (crc_val), .pad = 0, .name = (sym_name),            \
        }

/* MODULE_VERSIONS — baseline __versions entries every freestanding .ko
 * needs.  On pre-5.8 kernels with CONFIG_MODVERSIONS=y the module loader
 * rejects UND symbols that have no matching __versions entry, so every
 * kernel symbol we might import needs a placeholder here.  CRCs are
 * sentinel 0xDEADBE01; kmod_loader rewrites them via --crc <sym>=<val>
 * at load time.  We declare both `printk` and `_printk` (only one resolves
 * on any given kernel — 4.x has `printk`, 5.8+ has `_printk`; the other
 * stays unresolved but is not referenced by any UND symbol so the loader
 * skips the version check for it).
 *
 * KH_SDK_MODE builds (consumer .ko's) additionally emit frozen-CRC
 * entries for every kh_* export from kernelhook.ko via KH_DECLARE_VERSIONS()
 * — without those, pre-5.8 loaders reject consumer imports with
 * "no symbol version for kh_…". */
#ifdef KH_SDK_MODE
#define MODULE_VERSIONS()                                                \
    _MODVER_ENTRY(__modver_module_layout, 0xDEADBE01u, "module_layout"); \
    _MODVER_ENTRY(__modver_printk,        0xDEADBE01u, "printk");        \
    _MODVER_ENTRY(__modver__printk,       0xDEADBE01u, "_printk");       \
    KH_DECLARE_VERSIONS()
#else
#define MODULE_VERSIONS()                                                \
    _MODVER_ENTRY(__modver_module_layout, 0xDEADBE01u, "module_layout"); \
    _MODVER_ENTRY(__modver_printk,        0xDEADBE01u, "printk");        \
    _MODVER_ENTRY(__modver__printk,       0xDEADBE01u, "_printk")
#endif

/* ---- vermagic ---- */
#ifndef VERMAGIC_STRING
#define VERMAGIC_STRING "unknown SMP preempt mod_unload aarch64"
#endif

/*
 * MODULE_VERMAGIC — emit exactly once in the main translation unit.
 * Call this macro from test_main.c (not from a header included by
 * multiple .c files) to avoid duplicate .modinfo entries.
 */
/* Module name — needed by the kernel to name kobject/sysfs entries */
#ifndef MODULE_NAME
#define MODULE_NAME "kh_test"
#endif

/* Pad vermagic with trailing spaces so kmod_loader can replace it at load
 * time with any kernel's vermagic string (which may be longer than the
 * compiled-in value). The kernel's check_modinfo() uses strcmp on vermagic,
 * so the trailing spaces are not tolerated at match time — kmod_loader MUST
 * rewrite the slot before calling init_module. */
#define _KH_VM_PAD \
    "                                                                "

#define MODULE_VERMAGIC()                                               \
    __MODULE_INFO(vermagic, vermagic, VERMAGIC_STRING _KH_VM_PAD);       \
    __MODULE_INFO(name, modulename, MODULE_NAME)

/* Shadow-CFI permissive stub (CONFIG_CFI_CLANG + CONFIG_CFI_CLANG_SHADOW).
 *
 * On 5.4/5.10/5.15 GKI kernels, shadow-based CFI uses mod->cfi_check to
 * validate indirect calls into modules. find_module_sections() sets it by
 * looking up the GLOBAL symbol "__cfi_check" in the module's symtab. Without
 * it, any indirect call (including do_one_initcall → mod->init) panics with
 * "CFI failure (target: init_module)" in __cfi_slowpath.
 *
 * On 6.1+ kCFI kernels, this symbol is found but the field is unused — kCFI
 * validates calls via inline type-hash checks, not the shadow + callback
 * mechanism. So this stub is harmless (and redundant) on kCFI.
 *
 * Must be non-weak GLOBAL: 5.4 GKI's find_module_sections() skips weak
 * symbols when setting mod->cfi_check. Emitted via MODULE_THIS_MODULE() to
 * guarantee exactly one definition per module. */
#define MODULE_CFI_CHECK()                                                    \
    void __attribute__((used, visibility("default"), section(".text")))        \
    __cfi_check(unsigned long id, void *ptr, void *diag) { (void)id; (void)ptr; (void)diag; } \
    void __attribute__((weak, used, visibility("default"), section(".text")))  \
    __cfi_check_fail(void *data, void *ptr) { (void)data; (void)ptr; }

/*
 * MODULE_THIS_MODULE — define the __this_module symbol with init/exit
 * function pointers so the kernel module loader can call them.
 *
 * The kernel reads mod->init and mod->exit from __this_module, NOT
 * from the ELF symbol table.  Kbuild's modpost generates
 * .rela.gnu.linkonce.this_module with R_AARCH64_ABS64 relocations
 * for init_module at offset MODULE_INIT_OFFSET and cleanup_module
 * at offset MODULE_EXIT_OFFSET.  We replicate this by placing
 * function pointers at the correct struct offsets.
 *
 * Call this macro exactly once from test_main.c.
 */
/*
 * Struct offsets for GKI 6.1 ARM64 (sizeof(struct module) = 0x440):
 *   name[56]          @ offset 24   (MODULE_NAME_OFFSET)
 *   int (*init)(void) @ offset 0x170 (MODULE_INIT_OFFSET)
 *   void (*exit)(void)@ offset 0x3d8 (MODULE_EXIT_OFFSET)
 *
 * Override at build time: -DTHIS_MODULE_SIZE=0x440 etc.
 */
#ifndef THIS_MODULE_SIZE
#define THIS_MODULE_SIZE 0x800
#endif

#ifndef MODULE_NAME_OFFSET
#define MODULE_NAME_OFFSET 24
#endif

#ifndef MODULE_INIT_OFFSET
#define MODULE_INIT_OFFSET 0x170
#endif

#ifndef MODULE_EXIT_OFFSET
#define MODULE_EXIT_OFFSET 0x3d8
#endif

#define MODULE_THIS_MODULE()                                            \
    extern int  init_module(void);                                      \
    extern void cleanup_module(void);                                   \
    struct module {                                                     \
        char __pre_name[MODULE_NAME_OFFSET];                            \
        char name[56];                                                  \
        char __pad1[MODULE_INIT_OFFSET - MODULE_NAME_OFFSET - 56];     \
        int (*init)(void);                                              \
        char __pad2[MODULE_EXIT_OFFSET - MODULE_INIT_OFFSET - 8];      \
        void (*exit)(void);                                             \
        char __pad3[THIS_MODULE_SIZE - MODULE_EXIT_OFFSET - 8];        \
    };                                                                  \
    /* Use .kh.this_module instead of .gnu.linkonce.this_module to avoid
     * lld discarding the section during -r linking (linkonce semantics).
     * The linker script renames it to .gnu.linkonce.this_module. */     \
    struct module __this_module                                         \
        __used __aligned(64) __section(".kh.this_module") = {           \
            .__pre_name = {0},                                          \
            .name = MODULE_NAME,                                        \
            .init = init_module,                                        \
            .exit = cleanup_module,                                     \
        };                                                              \
    MODULE_CFI_CHECK();                                                 \
    /* Force a 1-byte _error_injection_whitelist section.                \
     * CONFIG_FUNCTION_ERROR_INJECTION kernels call                      \
     * populate_error_injection_list() which does section_objs() /       \
     * sizeof(struct error_injection_entry). Missing section causes a    \
     * NULL deref on some builds; emitting exactly 1 byte makes          \
     * section_objs() return 0 entries (1/sizeof(entry) = 0). */         \
    __asm__(".pushsection _error_injection_whitelist, \"aw\"\n"         \
            ".byte 0\n"                                                 \
            ".popsection\n");                                           \
    /* Shadow-CFI jump table stubs for 5.4/5.10/5.15 GKI.               \
     * The kernel's module loader replaces init_module/cleanup_module    \
     * function pointers with their .cfi_jt jump table entries when      \
     * applying relocations to .gnu.linkonce.this_module. Without these  \
     * symbols, mod->init is set to NULL and do_init_module → 0 deref. */\
    __asm__(                                                            \
        ".pushsection .text, \"ax\"\n"                                  \
        ".global init_module.cfi_jt\n"                                  \
        ".type init_module.cfi_jt, %function\n"                         \
        "init_module.cfi_jt: b init_module\n"                           \
        ".size init_module.cfi_jt, . - init_module.cfi_jt\n"           \
        ".global cleanup_module.cfi_jt\n"                               \
        ".type cleanup_module.cfi_jt, %function\n"                      \
        "cleanup_module.cfi_jt: b cleanup_module\n"                     \
        ".size cleanup_module.cfi_jt, . - cleanup_module.cfi_jt\n"     \
        ".popsection\n"                                                 \
    )

#endif /* _SHIM_H_ */
