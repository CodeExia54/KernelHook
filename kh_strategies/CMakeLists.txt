# SPDX-License-Identifier: GPL-2.0-or-later
add_library(kh_strategies STATIC
    src/variant_name.c
    src/probe_image.c
    # The probe_*.c / cli.c / config.c files migrated from tools/kmod_loader
    # are KMOD_FREESTANDING-only and reference resolver.h / devices_table.h
    # which live in tools/kmod_loader. They are built via tools/kmod_loader/
    # Makefile, not via CMake. CMake-side kh_strategies will gain real shared
    # sources (finalize_*.c) in Task 2.1.
)
target_include_directories(kh_strategies PUBLIC include)
target_compile_options(kh_strategies PRIVATE -Wall -Wextra -Werror)
