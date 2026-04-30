# SPDX-License-Identifier: GPL-2.0-or-later
add_executable(khtools
    src/main.c
    src/cmd_probe.c
    src/cmd_dump_syms.c
    src/cmd_extract.c
    src/cmd_patch.c
    src/cmd_verify.c
    src/embed_blob.c
    src/sha256.c
    src/file_io.c
    src/probe_image.c
    src/finalize_glue.c
    src/kallsym.c
    src/order.c
    src/insn.c
    src/common.c
)
# cmd_finalize.c includes <elf.h> and calls kh_patch_* — only available when
# elf.h is present (Linux/Android NDK targets; excluded on macOS CMake builds).
if(KH_HAS_ELF_H)
    target_sources(khtools PRIVATE
        src/cmd_finalize.c
        src/graft.c
    )
    target_compile_definitions(khtools PRIVATE KH_HAS_ELF_H=1)
endif()
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

    add_executable(test_probe_pixel31
        tests/test_probe_pixel31.c
        src/probe_image.c
        src/kallsym.c
        src/order.c
        src/insn.c
        src/common.c
    )
    target_include_directories(test_probe_pixel31 PRIVATE src)
    target_link_libraries(test_probe_pixel31 PRIVATE kh_strategies z)
    # Suppress the same ported-code warnings in the duplicate compile units
    set_source_files_properties(src/kallsym.c PROPERTIES COMPILE_FLAGS
        "-Wno-unused-variable -Wno-unused-parameter -Wno-unused-function")
    set_source_files_properties(src/insn.c PROPERTIES COMPILE_FLAGS
        "-Wno-unused-parameter")
    add_test(NAME khtools_probe_pixel31 COMMAND test_probe_pixel31)
    set_tests_properties(khtools_probe_pixel31 PROPERTIES SKIP_RETURN_CODE 77)

    add_test(NAME khtools_dump_syms_pixel31
             COMMAND ${CMAKE_SOURCE_DIR}/khtools/tests/test_dump_syms_pixel31.sh)
    set_tests_properties(khtools_dump_syms_pixel31 PROPERTIES SKIP_RETURN_CODE 77)

    add_test(NAME khtools_finalize_smoke
             COMMAND ${CMAKE_SOURCE_DIR}/khtools/tests/test_finalize_smoke.sh)
    set_tests_properties(khtools_finalize_smoke PROPERTIES SKIP_RETURN_CODE 77)

    add_test(NAME khtools_finalize_golden
             COMMAND ${CMAKE_SOURCE_DIR}/khtools/tests/test_finalize_golden.sh)
    set_tests_properties(khtools_finalize_golden PROPERTIES SKIP_RETURN_CODE 77)

    add_test(NAME khtools_extract_smoke
             COMMAND ${CMAKE_SOURCE_DIR}/khtools/tests/test_extract_smoke.sh)
    set_tests_properties(khtools_extract_smoke PROPERTIES SKIP_RETURN_CODE 77)

    add_test(NAME khtools_patch_smoke
             COMMAND ${CMAKE_SOURCE_DIR}/khtools/tests/test_patch_smoke.sh)
    set_tests_properties(khtools_patch_smoke PROPERTIES SKIP_RETURN_CODE 77)

    add_test(NAME khtools_verify_smoke
             COMMAND ${CMAKE_SOURCE_DIR}/khtools/tests/test_verify_smoke.sh)
    set_tests_properties(khtools_verify_smoke PROPERTIES SKIP_RETURN_CODE 77)
endif()
