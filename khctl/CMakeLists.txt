# SPDX-License-Identifier: GPL-2.0-or-later
add_executable(khctl
    src/main.c
    src/cmd_status.c
    src/cmd_log.c
    src/cmd_version.c
)
target_compile_options(khctl PRIVATE -Wall -Wextra -Werror)
# Static link so the binary runs on bare Android device images without
# needing libc.so paths to resolve. Same constraints as khinsmod —
# targets API≥30, post-MADV_WIPEONFORK kernels.
target_link_options(khctl PRIVATE -static)
