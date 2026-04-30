# SPDX-License-Identifier: GPL-2.0-or-later
add_executable(khtools
    src/main.c
    src/cmd_probe.c
    src/cmd_dump_syms.c
)
target_link_libraries(khtools PRIVATE kh_strategies)
target_include_directories(khtools PRIVATE src)
target_compile_options(khtools PRIVATE -Wall -Wextra -Werror)
