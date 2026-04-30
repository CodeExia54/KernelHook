# SPDX-License-Identifier: GPL-2.0-or-later
add_executable(khinsmod src/main.c)
target_compile_options(khinsmod PRIVATE -Wall -Wextra -Werror)
# Static link so the binary runs on bare Android device images without
# needing libc.so paths to resolve. NDK r30 static bionic on pre-5.10
# kernels has known issues (madvise(MADV_WIPEONFORK)) — kmod_loader_dyn
# documents this. khinsmod targets API>=30 by default, so static is OK.
target_link_options(khinsmod PRIVATE -static)
