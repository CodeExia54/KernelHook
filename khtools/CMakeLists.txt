# SPDX-License-Identifier: GPL-2.0-or-later
add_executable(khtools
    src/main.c
    src/cmd_probe.c
    src/cmd_dump_syms.c
    src/kallsym.c
    src/order.c
    src/insn.c
    src/common.c
)
target_link_libraries(khtools PRIVATE kh_strategies z)
target_include_directories(khtools PRIVATE src)
target_compile_options(khtools PRIVATE -Wall -Wextra -Werror)
# kallsym.c is ported verbatim from KernelPatch; it has unused variables, params,
# and static helper functions that belong to its internal callback API.
# Suppress -Werror for this file only; the host project applies -Werror to its own code.
set_source_files_properties(src/kallsym.c PROPERTIES COMPILE_FLAGS
    "-Wno-unused-variable -Wno-unused-parameter -Wno-unused-function")
# insn.c is ported verbatim from KernelPatch (Linux arch/arm64/kernel/insn.c origin);
# __check_al has an unused pstate param that is part of the upstream function signature.
set_source_files_properties(src/insn.c PROPERTIES COMPILE_FLAGS
    "-Wno-unused-parameter")

if(NOT ANDROID AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    enable_testing()
    add_executable(test_kallsym_pixel35
        tests/test_kallsym_pixel35.c
        src/kallsym.c
        src/order.c
        src/insn.c
        src/common.c
    )
    target_include_directories(test_kallsym_pixel35 PRIVATE src)
    target_link_libraries(test_kallsym_pixel35 PRIVATE z)
    # Suppress the same ported-code warnings in the duplicate compile units
    set_source_files_properties(src/kallsym.c PROPERTIES COMPILE_FLAGS
        "-Wno-unused-variable -Wno-unused-parameter -Wno-unused-function")
    set_source_files_properties(src/insn.c PROPERTIES COMPILE_FLAGS
        "-Wno-unused-parameter")
    add_test(NAME khtools_kallsym_pixel35 COMMAND test_kallsym_pixel35)
    set_tests_properties(khtools_kallsym_pixel35 PROPERTIES SKIP_RETURN_CODE 77)
endif()
