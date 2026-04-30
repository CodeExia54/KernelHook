# SPDX-License-Identifier: GPL-2.0-or-later
# Build kernelhook.ko — the prebuilt KernelHook kernel module.
#
# Usage:
#   make module        — build kernelhook.ko (freestanding, no kernel headers)
#   make loader        — build kmod_loader helper
#   make clean         — remove build artifacts

MODULE_NAME  := kernelhook
MODULE_SRCS  := src/main.c
KERNELHOOK_DIR := $(shell pwd)

# --- Fat-link mode (KH_FAT_LINK=1) ---
# Pulls in fat_main.c (master init walking .kh_consumer_table) plus the
# consumer objects selected by KH_MODULES (comma-separated). Each selected
# consumer's source is appended to MODULE_SRCS so mk/kmod.mk picks it up.
#
# Example: make module KH_FAT_LINK=1 KH_MODULES=khm,apd,supercall
#
# Supported consumers in this revision: khm (apd/supercall land in 5.1/5.2).
comma := ,
ifdef KH_FAT_LINK
  EXTRA_CFLAGS += -DKH_FAT_LINK=1
  MODULE_SRCS += src/fat_main.c

  ifneq ($(filter khm,$(subst $(comma), ,$(KH_MODULES))),)
    EXTRA_CFLAGS += -DKH_HAVE_KHM=1
    MODULE_SRCS += consumers/khm/khm_main.c
  endif
endif

include mk/kmod.mk

# ---------- Multi-layout build ----------
# module-dual produces every ksymtab layout so kmod_loader can pick the right
# variant at insmod time:
#   - prel32             : GKI 6.1+ (CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y, 12 B ksymtab + 4 B crc)
#   - abs64              : GKI 5.4..5.15 (24 B ksymtab with namespace + 4 B crc)
#   - abs64_legacy       : Android 9 / mainline 4.4 (16 B ksymtab + 8 B unsigned long crc)
#   - abs64_legacy_u32   : Android 4.14+ / 4.19 / 5.0..5.3 (16 B ksymtab + 4 B u32 crc —
#                          Google backport of commit 71810db27c1d treats CRCs as u32)
# extable-format + kCFI-hash differences are patched live by kmod_loader; only
# the ksymtab + kcrctab layout ships as multiple binaries because the on-disk
# entry stride is encoded into the section (sh_size, reloc count) — a full ELF
# rewrite at load time would be considerably more complex than shipping the
# four prebuilt variants.
.PHONY: module-dual
module-dual:
	@# Build all four ksymtab/kcrctab layouts.  Each build wipes the
	@# previous kmod object tree to avoid stale kh_exports.kmod.o (which
	@# encodes the layout choice and must regenerate).  The final `module`
	@# run uses prel32 so the default kernelhook.ko is the prel32 variant
	@# (matches GKI 6.1+, the most common SDK-consumer target).
	$(MAKE) module KH_KSYMTAB_LAYOUT=abs64_legacy
	@mv kernelhook.ko kernelhook-abs64-legacy.ko
	@rm -rf _kh_core _kh_kmod generated
	$(MAKE) module KH_KSYMTAB_LAYOUT=abs64_legacy_u32
	@mv kernelhook.ko kernelhook-abs64-legacy-u32.ko
	@rm -rf _kh_core _kh_kmod generated
	$(MAKE) module KH_KSYMTAB_LAYOUT=abs64
	@mv kernelhook.ko kernelhook-abs64.ko
	@rm -rf _kh_core _kh_kmod generated
	$(MAKE) module KH_KSYMTAB_LAYOUT=prel32
	@cp kernelhook.ko kernelhook-prel32.ko
	@echo "Built multi-layout: prel32 + abs64 + abs64-legacy-u32 + abs64-legacy"

# ---------- Vendor-ko graft payload ----------
# Produces kh_payload.o — a self-contained ET_REL blob that tools/kmod_loader/
# graft_vendor_ko merges into a vendor .ko's ELF.  See mk/kmod.mk KH_PAYLOAD
# comment for the full rationale.  Existing .kmod.o files were compiled
# without -DKH_PAYLOAD and are missing the alias declarations, so wipe them
# first.  The recursive `make` reuses this Makefile with KH_PAYLOAD=1 set,
# which activates the payload branches in mk/kmod.mk.
#
# The outer target intentionally differs from the inner rule name (`payload`
# vs `kh_payload.o`): make treats them as distinct, avoiding infinite
# recursion from a self-referential .PHONY target.
.PHONY: payload
payload:
	@# src/main.kmod.o lives in the source tree (not under _kh_core/_kh_kmod)
	@# so it survives the subdir wipe.  Remove it explicitly, otherwise a
	@# previously built non-payload main.o is reused and kh_entry/kh_exit
	@# never appear in the final kh_payload.o.
	@rm -rf _kh_core _kh_kmod generated
	@rm -f src/main.kmod.o
	$(MAKE) kh_payload.o KH_PAYLOAD=1
