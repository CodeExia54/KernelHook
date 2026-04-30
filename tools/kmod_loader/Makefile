# SPDX-License-Identifier: GPL-2.0-or-later
# Build kmod_loader — adaptive kernel module loader with embedded probe.
#
# Usage:
#   make                    — build kmod_loader (uses pre-committed probe_embed.h)
#   make regenerate         — regenerate probe_embed.h from source (needs cross-compiler)
#   make clean              — remove build artifacts

KH_ROOT := $(shell cd ../.. && pwd)

.DEFAULT_GOAL := all

# Cross-compiler (only needed for 'regenerate' target)
# Resolved by shared detector. See kmod/mk/detect_toolchain.mk.
include $(KH_ROOT)/kmod/mk/detect_toolchain.mk

CROSS_CC := $(KH_CC)
CROSS_LD := $(KH_LD)

# Two separate compilers:
#   HOSTCC     — real host compiler (native mac/linux). Used for graft_vendor_ko
#                which runs on the developer machine.
#   LOADER_CC  — cross-compiler producing aarch64-android binaries for
#                kmod_loader / kmod_loader_dyn (target device). Defaults to the
#                detected NDK ($(KH_CC)) so a bare `make` works out-of-the-box.
# Historically this Makefile overloaded HOSTCC to mean both; scripts passed
# HOSTCC=$NDK-clang which then broke graft_vendor_ko (compiled for
# aarch64-android) or, on macOS with HOSTCC=cc, broke kmod_loader (no <elf.h>
# in macOS SDK for aarch64 output).  Splitting the two lets `make all` succeed
# on macOS hosts too. Earlier this file defaulted LOADER_CC to HOSTCC, which
# made `make` on glibc hosts try to build kmod_loader with system gcc — that
# fails on `strlcat` (bionic-only) and produces a non-aarch64 binary anyway.
HOSTCC    ?= cc
LOADER_CC ?= $(KH_CC)

# Device database codegen (Plan 2 Milestone A).
GEN_DEVICES := $(realpath ../gen_devices_table.py)
DEVICES_DIR := $(realpath ../../kmod/devices)
DEVICES_TABLE_C := devices_table.generated.c
DEVICES_TABLE_H := devices_table.h

.PHONY: devices_table
devices_table: $(DEVICES_TABLE_C)

$(DEVICES_TABLE_C): $(wildcard $(DEVICES_DIR)/*.conf) $(GEN_DEVICES)
	$(GEN_DEVICES) --devices-dir $(DEVICES_DIR) --output $@

FS_CFLAGS := -DKMOD_FREESTANDING \
             -ffreestanding -fno-builtin -fno-stack-protector -fno-common \
             -fno-PIE -fno-pic \
             -I$(KH_ROOT)/include -I$(KH_ROOT)/include/arch/arm64 \
             -march=armv8.5-a -O2 -Wall -Wextra -Werror \
             -Wno-unused-parameter -Wno-unused-function
FS_CFLAGS += -I$(KH_ROOT)/kh_strategies/include
FS_CFLAGS += -I$(KH_ROOT)/tools/kmod_loader

.PHONY: all regenerate clean test graft

# Default: build kmod_loader using pre-committed probe_embed.h
all: kmod_loader kmod_loader_dyn graft_vendor_ko
	@echo "Built kmod_loader (static) + kmod_loader_dyn (dynamic) + graft_vendor_ko successfully"

# graft_vendor_ko: host-side ELF merger.  Lives here because it shares
# the same ELF-manipulation style as kmod_loader and consumes the same
# KernelHook payload object.  Requires <elf.h> — Linux or Android NDK
# host only.  macOS developers can build/run via docker.
graft_vendor_ko: graft_vendor_ko.c
	$(HOSTCC) -O2 -Wall -Wextra -Werror -o $@ $<

graft: graft_vendor_ko
	@echo "graft_vendor_ko built.  Usage: ./graft_vendor_ko --help"

FINALIZE_SRCS := $(KH_ROOT)/kh_strategies/src/finalize_kcfi.c \
                 $(KH_ROOT)/kh_strategies/src/finalize_versions.c \
                 $(KH_ROOT)/kh_strategies/src/finalize_vermagic.c \
                 $(KH_ROOT)/kh_strategies/src/finalize_layout.c \
                 $(KH_ROOT)/kh_strategies/src/finalize_printk.c \
                 $(KH_ROOT)/kh_strategies/src/finalize_misc.c

RESOLVER_SRCS := resolver.c \
                 $(KH_ROOT)/kh_strategies/src/cli.c \
                 $(KH_ROOT)/kh_strategies/src/probe_procfs.c \
                 $(KH_ROOT)/kh_strategies/src/probe_loaded.c \
                 $(KH_ROOT)/kh_strategies/src/probe_ondisk.c \
                 $(KH_ROOT)/kh_strategies/src/probe_disasm.c \
                 $(KH_ROOT)/kh_strategies/src/probe_binary.c \
                 $(KH_ROOT)/kh_strategies/src/config.c

SUBCOMMAND_SRCS := subcommands.c

RESOLVER_HDRS := resolver.h devices_table.h subcommands.h

# Include path so migrated kh_strategies/src/*.c can find resolver.h, devices_table.h,
# and internal helpers (elf_helpers.h in kh_strategies/src/).
RESOLVER_IFLAGS := -I$(KH_ROOT)/tools/kmod_loader \
                   -I$(KH_ROOT)/kh_strategies/include \
                   -I$(KH_ROOT)/kh_strategies/src

kmod_loader: kmod_loader.c probe_embed.h $(DEVICES_TABLE_C) $(DEVICES_TABLE_H) \
             $(FINALIZE_SRCS) $(RESOLVER_SRCS) $(SUBCOMMAND_SRCS) $(RESOLVER_HDRS)
	$(LOADER_CC) -DEMBED_PROBE_KO -DKH_RESOLVER_DEFINE_SPECS -static -O2 \
		$(RESOLVER_IFLAGS) -o $@ \
		kmod_loader.c $(DEVICES_TABLE_C) $(FINALIZE_SRCS) $(RESOLVER_SRCS) $(SUBCOMMAND_SRCS)

# kmod_loader_dyn — dynamic-link variant (~63 KB) for pre-5.10 Android kernels.
# Rationale: NDK r30's static bionic calls madvise(MADV_WIPEONFORK) during
# arc4random init, which 4.4 and earlier kernels don't implement — bionic's
# async_safe_fatal() then aborts before main(). Dynamic linking binds to the
# device's own libc.so (Android 9 kernel 4.4 included), which avoids that code
# path entirely. Scripts that target API ≤ 29 should push this variant
# instead of the static one.
kmod_loader_dyn: kmod_loader.c probe_embed.h $(DEVICES_TABLE_C) $(DEVICES_TABLE_H) \
                 $(FINALIZE_SRCS) $(RESOLVER_SRCS) $(SUBCOMMAND_SRCS) $(RESOLVER_HDRS)
	$(LOADER_CC) -DEMBED_PROBE_KO -DKH_RESOLVER_DEFINE_SPECS -O2 \
		$(RESOLVER_IFLAGS) -o $@ \
		kmod_loader.c $(DEVICES_TABLE_C) $(FINALIZE_SRCS) $(RESOLVER_SRCS) $(SUBCOMMAND_SRCS)

test: kmod_loader test_resolver test_patch_this_module
	@./tests/test_config_parser.sh
	@./test_resolver
	@./test_patch_this_module

# test_resolver must run on the build host, so compile with the native
# host compiler (TEST_CC), not the aarch64 NDK cross compiler. Defaults
# to `cc`. resolver.h falls back to an opaque Elf64_Ehdr when <elf.h>
# is unavailable, so this builds cleanly on macOS too.
TEST_CC ?= cc
test_resolver: tests/test_resolver.c resolver.c resolver.h
	$(TEST_CC) -O2 -o $@ tests/test_resolver.c resolver.c

test_patch_this_module: tests/test_patch_this_module.c patch_this_module.h
	$(TEST_CC) -O2 -Wall -Wextra -Werror -o $@ tests/test_patch_this_module.c

# Regenerate probe_embed.h from source (requires cross-compiler)
regenerate: probe.ko
	@echo "// Auto-generated — do not edit" > probe_embed.h
	@echo "static const unsigned char probe_ko_data[] = {" >> probe_embed.h
	@xxd -i < probe.ko >> probe_embed.h
	@echo "};" >> probe_embed.h
	@echo "static const unsigned int probe_ko_size = sizeof(probe_ko_data);" >> probe_embed.h
	@echo "probe_embed.h regenerated — commit if changed"

probe.ko: probe.c
	$(CROSS_CC) $(FS_CFLAGS) -DMODULE_NAME='"kh_probe"' -c probe.c -o probe.fs.o
	$(CROSS_CC) $(FS_CFLAGS) -c $(KH_ROOT)/kmod/plt/plt_stub.S -o probe_plt.fs.o
	$(CROSS_LD) -r -T $(KH_ROOT)/kmod/lds/kmod.lds -o $@ probe.fs.o probe_plt.fs.o

clean:
	rm -f kmod_loader kmod_loader_dyn graft_vendor_ko test_resolver test_patch_this_module probe.ko probe.fs.o probe_plt.fs.o $(DEVICES_TABLE_C)
