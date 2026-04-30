# SPDX-License-Identifier: GPL-2.0-or-later
add_library(kh_strategies STATIC
    src/variant_name.c
)
target_include_directories(kh_strategies PUBLIC include)
target_compile_options(kh_strategies PRIVATE -Wall -Wextra -Werror)
