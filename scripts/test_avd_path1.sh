#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 bmax121. All Rights Reserved.
#
# AVD path-1 e2e: build fat.ko, boot the AVD with -show-kernel, push the
# fat.ko, run khinsmod, and confirm the consumer markers fired in the
# kernel console (read directly from the emulator's log, not dmesg).
#
# Replaces the dmesg-poll-based scripts/test_avd_kmod.sh for the path-1
# scenario. The legacy script remains in place for the freestanding
# kh_test.ko developer flow until that flow gets its own slim wrapper.
#
# Usage:
#   ./scripts/test_avd_path1.sh                       # Pixel_31, default consumers
#   ./scripts/test_avd_path1.sh Pixel_34              # explicit AVD
#   ./scripts/test_avd_path1.sh Pixel_31 khm,apd      # AVD + consumer set
#   ./scripts/test_avd_path1.sh Pixel_31 khm --ksu    # +KSU LKM (auto-fetched fixture)
#
# Env knobs:
#   KH_PATH1_TIMEOUT  marker wait timeout in seconds (default 120)
#   KH_PATH1_KSU_TAG  KSU GKI tag override (default android12-5.10 for Pixel_31)
#
# Exit codes: 0 PASS, 1 marker timeout, 2 setup failure, 3 fetch failure.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$ROOT/scripts"
source "$SCRIPT_DIR/lib/avd_console.sh"

avd="${1:-Pixel_31}"
modules="${2:-khm}"
ksu_flag="${3:-}"
timeout="${KH_PATH1_TIMEOUT:-120}"

logfile="/tmp/avd-${avd}-path1-console.log"
fat_path="/tmp/fat-${avd}-path1.ko"

echo "kh: path1: avd=$avd modules=$modules ksu=${ksu_flag:-no}"

# 1. Build fat.ko (KH_FAT_LINK + the requested consumers).
make -C "$ROOT/kmod" clean >/dev/null 2>&1 || true
if ! make -C "$ROOT/kmod" module KH_FAT_LINK=1 KH_MODULES="$modules" >/dev/null 2>&1; then
    echo "kh: path1: fat.ko build failed for modules=$modules" >&2
    exit 2
fi
cp "$ROOT/kmod/kernelhook.ko" "$fat_path"

# 2. Optionally materialize the KSU LKM fixture.
ksu_path=""
if [[ $ksu_flag == "--ksu" ]]; then
    ksu_tag="${KH_PATH1_KSU_TAG:-android12-5.10}"
    if ! "$ROOT/khtools/fixtures/ksu_lkm/fetch.sh" "$ksu_tag" >/dev/null; then
        echo "kh: path1: KSU fixture fetch failed for $ksu_tag" >&2
        exit 3
    fi
    ksu_path="$ROOT/khtools/fixtures/ksu_lkm/$ksu_tag/kernelsu.ko"
    [[ -f $ksu_path ]] || { echo "kh: path1: KSU .ko missing after fetch" >&2; exit 3; }
fi

# 3. Pick a free port pair so we don't collide with parallel emulator
# instances (e.g. the kp-debug / kp-df rigs at 5554..5558), then boot.
KH_AVD_PORT=$(avd_pick_free_port_pair)
export KH_AVD_PORT
# Android emulator convention: -ports console,adb produces a device
# whose ADB serial is `emulator-<console_port>` (the lower of the
# pair). The adb port is one above. Don't add 1 here.
serial="emulator-$KH_AVD_PORT"
echo "kh: path1: pinned ports console=$KH_AVD_PORT adb=$((KH_AVD_PORT + 1)) serial=$serial"

emu_pid=$(avd_boot_show_kernel "$avd" "" "$logfile")
trap '[[ -n ${emu_pid:-} ]] && kill "$emu_pid" 2>/dev/null; adb -s "$serial" emu kill 2>/dev/null || true' EXIT

if ! avd_emulator_running "$emu_pid"; then
    echo "kh: path1: emulator failed to start (see $logfile)" >&2
    exit 2
fi

# 4. Wait for adb device on our specific serial.
if ! adb -s "$serial" wait-for-device 2>/dev/null; then
    echo "kh: path1: adb wait-for-device(\"$serial\") timed out" >&2
    exit 2
fi
sleep 5  # let early init settle so su 0 is available

# 5. Push fat.ko + KSU + the userspace finalize-and-load tool (kmod_loader).
# tools/kmod_loader handles fat.ko's own CRC / vermagic / struct module
# layout patching before finit_module. khinsmod is the thin wrapper for
# environments where fat.ko was already finalized at build time; for a
# generic AVD lane we always go through kmod_loader so the test does not
# rely on a kernel-specific fat.ko.
adb -s "$serial" push "$fat_path" /data/local/tmp/fat.ko >/dev/null
loader_arm64="$ROOT/tools/kmod_loader/kmod_loader_arm64"
if [[ ! -f $loader_arm64 ]]; then
    loader_arm64="$ROOT/tools/kmod_loader/kmod_loader"
fi
[[ -f $loader_arm64 ]] || {
    echo "kh: path1: tools/kmod_loader/kmod_loader[_arm64] missing — run 'make -C tools/kmod_loader'" >&2
    exit 2
}
adb -s "$serial" push "$loader_arm64" /data/local/tmp/kmod_loader >/dev/null
adb -s "$serial" shell chmod +x /data/local/tmp/kmod_loader >/dev/null

ksu_arg=""
if [[ -n $ksu_path ]]; then
    adb -s "$serial" push "$ksu_path" /data/local/tmp/kernelsu.ko >/dev/null
    # Path-1 KSU: kmod_loader passes the path through as a finit_module
    # arg ("ksu_path=..."); fat.ko's `ksu_path` module_param picks it
    # up in module_init context and runs filp_open + kernel_read +
    # in-kernel finalize + kh_call_init_module. See PATH1_KSU_SURFACE_HISTORY.md.
    ksu_arg="ksu_path=/data/local/tmp/kernelsu.ko"
fi

adb -s "$serial" shell "su 0 sh -c '/data/local/tmp/kmod_loader /data/local/tmp/fat.ko $ksu_arg'" >/dev/null

# 6. Wait for the consumer marker. khm always logs `kh: khm: hello`; if
# only non-khm consumers were requested, fall back to the SDK-level
# "fat.ko loaded" marker.
if [[ ",$modules," == *,khm,* ]]; then
    primary_marker="kh: khm: hello from khm consumer"
else
    primary_marker="kh: sdk: fat.ko loaded with"
fi

if avd_wait_marker "$logfile" "$primary_marker" "$timeout"; then
    echo "kh: path1: PASS ($primary_marker observed)"
    [[ -n $ksu_path ]] && {
        if avd_wait_marker "$logfile" "kh: ksu: (loaded|hook armed|nothing to load)" 30; then
            echo "kh: path1: KSU side observable in console"
        else
            echo "kh: path1: WARN — KSU marker not seen within 30s"
        fi
    }
    exit 0
fi

echo "kh: path1: FAIL — marker '$primary_marker' not seen within ${timeout}s" >&2
echo "kh: path1: console tail:" >&2
tail -40 "$logfile" >&2 || true
exit 1
