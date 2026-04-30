/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2023 bmax121. All Rights Reserved. */
/* Adapted for KernelHook by bmax121, 2026. */
/*
 * khimg linker script — derived from KP kpimg.lds with hook/fphook sections
 * removed (fat.ko brings its own hook engine; kernel load_module is reused).
 */

OUTPUT_ARCH(aarch64)
ENTRY(setup_entry)

_link_base = 64k - 3 * 4k;

SECTIONS
{
    /DISCARD/ : { *(.discard) *(.discard.*) }
    /DISCARD/ : {
        *(.interp .dynamic)
        *(.dynsym .dynstr .hash .gnu.hash)
    }
    . = _link_base;
    _link_base = .;

    .setup.data : {
        _setup_start = .;
        src/setup.o(.setup.header)
        . = _setup_start + 64;
        src/setup.o(.setup.preset)
        src/setup.o(.setup.data)
        . = _setup_start + 4K;
    }

    .setup.text : {
        src/setup1.o(.entry.text)
        src/setup1.o(.text)
        src/setup.o(.text)
        _setup_end = .;
    }

    . = ALIGN(16);
    .setup.map : {
        _map_start = .;
        src/map.o(.map.data)
        src/map.o(.map.text)
        src/map.o(.text)
        src/map1.o(.text)
        . = ALIGN(16);
        _map_end = .;
    }
    ASSERT(SIZEOF(.setup.map) < 0xa00, "Size too large of .setup.map!")

    . = ALIGN(64K);
    _kp_start = .;
    .kp.text : {
        _kp_text_start = .;

        src/start.o(.start.text)
        src/start.o(.text)

        src/*(.text)
        src/*(.rodata*)

        *(.text)
        *(.rodata*)

        . = ALIGN(16);
        _kp_text_end = .;
    }

    . = ALIGN(64k);
    .kp.data : {
        _kp_data_start = .;
        src/start.o(.start.data)
        src/*(.data)
        src/*(.bss)
        *(.data)
        *(.bss)
        . = ALIGN(16);
        _kp_data_end = .;
    }

    .got.plt : { *(.got.plt) }
    ASSERT(SIZEOF(.got.plt) == 0, "Unexpected GOT/PLT entries detected!")

    . = ALIGN(64k);
    _kp_end = .;

    _link_end = .;

    .got : {
        *(.got)
    }
    ASSERT(SIZEOF(.got) == 0, "Unexpected GOT detected!")

    .plt : {
        *(.plt) *(.plt.*) *(.iplt) *(.igot .igot.plt)
    }
    ASSERT(SIZEOF(.plt) == 0, "Unexpected run-time procedure linkages detected!")

    .data.rel.ro : {
        *(.data.rel.ro)
    }
    ASSERT(SIZEOF(.data.rel.ro) == 0, "Unexpected RELRO detected!")

    .rela.dyn : {
        *(.rela .rela*)
    }
    ASSERT(SIZEOF(.rela.dyn) == 0, "Unexpected RELRDYN detected!")
}
