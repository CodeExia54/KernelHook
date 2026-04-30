# SPDX-License-Identifier: GPL-2.0-or-later
include(CheckIncludeFile)
check_include_file(elf.h KH_HAS_ELF_H)

add_library(kh_strategies STATIC
    src/variant_name.c
    src/probe_image.c
)

if(KH_HAS_ELF_H)
    target_sources(kh_strategies PRIVATE
        src/finalize_kcfi.c
        src/finalize_versions.c
        src/finalize_vermagic.c
        src/finalize_layout.c
        src/finalize_printk.c
        src/finalize_misc.c
    )
else()
    message(STATUS "kh_strategies: <elf.h> not found — finalize_*.c excluded from CMake build (Makefile path still compiles them).")
endif()

target_include_directories(kh_strategies PUBLIC include)
# Internal headers (elf_helpers.h) are in src/
target_include_directories(kh_strategies PRIVATE src)
target_compile_options(kh_strategies PRIVATE -Wall -Wextra -Werror)
