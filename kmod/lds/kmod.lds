/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Linker script for freestanding .ko build (Approach B).
 *
 * A .ko is an ET_REL (relocatable) ELF. We use ld -r (partial link)
 * so this script only orders sections — all relocations are preserved.
 */

SECTIONS
{
    /* arm64 GNU property note + Linux note — required by Android 15 GKI
     * 6.6+ module loader.  Must be placed before any other SECTIONS rule
     * so ld.lld's -r mode keeps them in the output; late placement lets
     * an earlier catch-all merge them into DISCARD (observed: silent
     * drop in kernelhook.ko.tmp even when rules exist after the last
     * real section).
     *
     * .note.Linux carries per-module "OPEN"/"func" markers; the kernel
     * pre-load check rejects .ko's missing it with -ENOEXEC silently.
     * .note.gnu.property declares FEAT_BTI (pr_data=1) — emitted by
     * the hand-rolled note in kmod/plt/plt_stub.S to anchor the
     * section in the relocatable link, AND-merged with clang's
     * BTI-only auto-notes from C TUs.  No FEAT_PAC declaration: see
     * kmod/mk/kmod.mk for why pac-ret was dropped, and the comment
     * above the .note.gnu.property block in plt_stub.S for why the
     * declaration must match the emitted instructions. */
    .note.gnu.property : ALIGN(8) {
        KEEP(*(.note.gnu.property))
    }
    .note.Linux : ALIGN(4) {
        KEEP(*(.note.Linux))
    }
    /* Empty .altinstructions — placeholder section header required on
     * some Android 15 common-kernel branches (vendor modules always
     * ship the header, the kernel walks apply_alternatives() with zero
     * entries when sh_size=0). KEEP prevents ld.lld from folding the
     * empty section away. */
    .altinstructions : ALIGN(8) {
        KEEP(*(.altinstructions))
    }
    /* .text.ftrace_trampoline — REQUIRED by arm64 module_init_ftrace_plt()
     * on every CONFIG_DYNAMIC_FTRACE=y kernel (Android GKI 6.1+).  Missing
     * → module_finalize() returns -ENOEXEC silently before init_module()
     * runs. See arch/arm64/kernel/module.c:module_init_ftrace_plt in
     * android15-6.6. Kernel writes a struct plt_entry (16B) into this
     * region at insmod. */
    .text.ftrace_trampoline : ALIGN(4) {
        KEEP(*(.text.ftrace_trampoline))
    }

    .text : {
        *(.text .text.*)
    }

    .plt : {
        *(.plt)
    }

    .init.plt : {
        *(.init.plt)
    }

    .init.text : {
        *(.init.text)
    }

    .exit.text : {
        *(.exit.text)
    }

    .transit.data : {
        *(.transit.data)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .modinfo : {
        *(.modinfo)
    }

    __versions : {
        *(__versions)
    }

    __param : {
        __start___param = .;
        *(__param)
        __stop___param = .;
    }

    .gnu.linkonce.this_module : {
        *(.kh.this_module)
    }

    .data : {
        *(.data .data.*)
    }

    /* Link-time strategy registry — iterated via __start___kh_strategies /
       __stop___kh_strategies at module init by src/kh_strategy.c (Task 3).
       KEEP prevents --gc-sections from dropping otherwise-unreferenced
       strategy entries that are only found via the anchor symbols. */
    .kh_strategies : ALIGN(8) {
        __start___kh_strategies = .;
        KEEP(*(.kh_strategies))
        __stop___kh_strategies = .;
    }

    /* Fat-link consumer registry — iterated via __start_kh_consumer_table /
       __stop_kh_consumer_table at module init by src/fat_main.c (Task 3.1).
       Same anchor pattern as .kh_strategies above; lds explicitly emits
       the bracketing symbols because the kernel module loader does NOT
       synthesise __start_/__stop_<sec> for relocatable .ko output (only
       vmlinux's static link does). KEEP prevents --gc-sections from
       dropping consumer entries that are only reached via the anchors. */
    kh_consumer_table : ALIGN(8) {
        __start_kh_consumer_table = .;
        KEEP(*(kh_consumer_table))
        __stop_kh_consumer_table = .;
    }

    .bss : {
        *(.bss .bss.*)
    }

    /* Exception table: registered automatically by the kernel module loader
     * at insmod time. Contains PC-relative entries for fault sites in
     * kh_inline_copy_to/from_user (ldtr/sttr paths). Needed for inline
     * uaccess to survive bad user addresses gracefully. */
    __ex_table : ALIGN(4) {
        *(__ex_table)
    }

    /* KernelHook exports (freestanding EXPORT_SYMBOL via kh_crc).
     * Populated by kmod/generated/kh_exports.o, emitted by tools/kh_crc
     * from kmod/exports.manifest. See spec §6.5.
     * SORT ensures deterministic ordering by symbol name. */
    __ksymtab : ALIGN(8) {
        *(SORT(___ksymtab+*))
        *(__ksymtab)
    }
    __ksymtab_strings : {
        *(__ksymtab_strings)
    }
    __kcrctab : ALIGN(4) {
        *(SORT(___kcrctab+*))
        *(__kcrctab)
    }

    /* Required by CONFIG_FUNCTION_ERROR_INJECTION (5.4 GKI).
     * The kernel's ei_module_callback dereferences this section;
     * missing → NULL pointer oops in populate_error_injection_list. */
    _error_injection_whitelist : {
        *(_error_injection_whitelist)
    }

    /DISCARD/ : {
        *(.comment)
        *(.note.GNU-stack)
        *(.note.gnu.build-id)
    }
}
