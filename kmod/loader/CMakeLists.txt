# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 bmax121. All Rights Reserved.
#
# Host-side build hook for the kmod/loader subset port.
#
# Two production callers (khimg, fat.ko) build kh_loader_*.c via their
# own Makefiles when (and only when) a future end-to-end loader needs
# them. Today neither Makefile pulls these files because the existing
# init_module / load_module callsites in khimg/src/kh_load.c and
# kmod/src/ksu_load.c are unchanged. See loader/BLOCKER.md.
#
# This CMakeLists exists ONLY to register a host ctest that exercises
# the pure functions (insn encoder, RELA relocator). Adding/removing
# the test does not affect production .ko / .bin builds.

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_loader.c)
    return()
endif()

# Bail out gracefully on non-Linux/Darwin hosts; the test only needs a
# regular hosted compiler with libc.
if(NOT (CMAKE_SYSTEM_NAME STREQUAL "Linux" OR
        CMAKE_SYSTEM_NAME STREQUAL "Darwin"))
    return()
endif()

add_executable(kh_loader_tests
    tests/test_loader.c
    kh_loader_insn.c
    kh_loader_relo.c
)
target_include_directories(kh_loader_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(kh_loader_tests PRIVATE KH_LOADER_UNITTEST=1)
target_compile_options(kh_loader_tests PRIVATE
    -Wall -Wextra -Werror
    -Wno-unused-parameter
)

# Register with ctest. enable_testing() is called by the userspace test
# subdir; if it has not been called yet (e.g. running this subdir alone)
# we call it here so add_test does not silently skip.
enable_testing()
add_test(NAME kh_loader_tests COMMAND kh_loader_tests)
