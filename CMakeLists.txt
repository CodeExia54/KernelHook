# SPDX-License-Identifier: GPL-2.0-or-later
# KernelHook userspace build — does NOT replace the kernel Makefile.
cmake_minimum_required(VERSION 3.16)
project(KernelHook C)

# --- Architecture check ---
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(ARCH_ARM64 TRUE)
else()
    message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}. Only ARM64 is supported.")
endif()

# --- Platform detection ---
if(ANDROID)
    set(PLATFORM_SOURCE src/platform/linux.c)
    set(REMOTE_SOURCE src/platform/remote_stub.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PLATFORM_SOURCE src/platform/linux.c)
    set(REMOTE_SOURCE src/platform/remote_linux.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(PLATFORM_SOURCE src/platform/darwin.c)
    set(REMOTE_SOURCE src/platform/remote_stub.c)
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}. Only Linux, Android, and macOS are supported.")
endif()

# --- Library sources ---
set(LIB_SOURCES
    src/memory.c
    src/arch/arm64/inline.c
    src/arch/arm64/insn.c
    src/arch/arm64/transit.c
    ${PLATFORM_SOURCE}
    src/platform/hmem_user.c
    src/platform/hook_install.c
    src/platform/log.c
    src/hook.c
    src/sync.c
    ${REMOTE_SOURCE}
    src/platform/section_fence.c
    src/kh_strategy.c
    src/strategies/swapper_pg_dir.c
    src/strategies/kimage_voffset.c
    src/strategies/memstart_addr.c
    src/strategies/cred_task.c
    src/strategies/uaccess_copy.c
    src/strategies/cross_cpu.c
    src/strategies/runtime_sizes.c
)

add_library(kernelhook STATIC ${LIB_SOURCES})

add_subdirectory(kh_strategies)
add_subdirectory(khtools)

target_include_directories(kernelhook PUBLIC
    include
    include/arch/arm64
)

target_compile_definitions(kernelhook PUBLIC __USERSPACE__)

# --- Page isolation: keep library .text in its own page-aligned section ---
if(NOT DEFINED KH_PAGE_ALIGN)
    set(KH_PAGE_ALIGN 16384)
endif()

# Generate page alignment header (used by section_fence.c on all platforms)
configure_file(
    ${CMAKE_SOURCE_DIR}/scripts/kh_page_align.h.in
    ${CMAKE_BINARY_DIR}/kh_page_align.h
    @ONLY
)
target_include_directories(kernelhook PRIVATE ${CMAKE_BINARY_DIR})

target_compile_options(kernelhook PRIVATE -ffunction-sections)

target_compile_options(kernelhook PRIVATE
    -Wall -Wextra -Werror
    -Wno-unused-parameter
)

# --- Branch protection (BTI + PAC) ---
# The transit stub in transit.c requires -mbranch-protection=standard (or at
# minimum =bti) so the compiler emits a BTI C landing pad as the first
# instruction of _transit/_fp_transit. That instruction is memcpy'd into the
# transit buffer at transit[2]; the asm uses "sub x16, x16, #12" relative to
# the adr at transit[3] to locate the self-pointer at transit[0..1].
# Without BTI C, the adr lands at transit[2] and the arithmetic is off by 4,
# producing a corrupt rox pointer and a crash in the transit stub.
include(CheckCCompilerFlag)
check_c_compiler_flag(-mbranch-protection=standard KH_HAS_BRANCH_PROTECTION)
if(KH_HAS_BRANCH_PROTECTION)
    target_compile_options(kernelhook PRIVATE -mbranch-protection=standard)
else()
    message(WARNING "Compiler does not support -mbranch-protection=standard; "
                    "transit stub may malfunction on ARM64e/BTI-enabled systems.")
endif()

# --- Build type flags ---
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG" CACHE STRING "" FORCE)

# Disable ASan for Android (NDK static ASan requires specific runtime setup)
if(ANDROID)
    set(CMAKE_C_FLAGS_DEBUG "-O0 -g" CACHE STRING "" FORCE)
else()
    set(CMAKE_C_FLAGS_DEBUG "-O0 -g -fsanitize=address" CACHE STRING "" FORCE)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_link_options(kernelhook PUBLIC -fsanitize=address)
    endif()
endif()

# --- Page isolation: linker configuration ---
if(APPLE)
    target_link_options(kernelhook PUBLIC
        -Wl,-order_file,${CMAKE_SOURCE_DIR}/scripts/kh_order_darwin.txt
    )
else()
    configure_file(
        ${CMAKE_SOURCE_DIR}/scripts/kh_text.lds.in
        ${CMAKE_BINARY_DIR}/kh_text.lds
        @ONLY
    )
    target_link_options(kernelhook PUBLIC
        -T ${CMAKE_BINARY_DIR}/kh_text.lds
    )
endif()

# --- Tests (if present) ---
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/userspace/CMakeLists.txt)
    enable_testing()
    add_subdirectory(tests/userspace)
endif()
