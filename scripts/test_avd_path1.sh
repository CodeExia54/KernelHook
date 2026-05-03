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

# 3. Boot the AVD with kernel console attached to $logfile.
emu_pid=$(avd_boot_show_kernel "$avd" "" "$logfile")
trap '[[ -n ${emu_pid:-} ]] && kill "$emu_pid" 2>/dev/null; adb -e emu kill 2>/dev/null || true' EXIT

if ! avd_emulator_running "$emu_pid"; then
    echo "kh: path1: emulator failed to start (see $logfile)" >&2
    exit 2
fi

# 4. Wait for adb device.
if ! adb wait-for-device 2>/dev/null; then
    echo "kh: path1: adb wait-for-device timed out" >&2
    exit 2
fi
sleep 5  # let early init settle so su 0 is available

# 5. Push fat.ko + khinsmod, then load.
adb push "$fat_path" /data/local/tmp/fat.ko >/dev/null
if [[ ! -x $ROOT/build_android/khinsmod/khinsmod ]]; then
    echo "kh: path1: build_android/khinsmod/khinsmod missing — run scripts/run_android_tests.sh first" >&2
    exit 2
fi
adb push "$ROOT/build_android/khinsmod/khinsmod" /data/local/tmp/khinsmod >/dev/null
adb shell chmod +x /data/local/tmp/khinsmod >/dev/null

ksu_arg=""
if [[ -n $ksu_path ]]; then
    adb push "$ksu_path" /data/local/tmp/kernelsu.ko >/dev/null
    ksu_arg="--ksu /data/local/tmp/kernelsu.ko"
fi

adb shell "su 0 sh -c '/data/local/tmp/khinsmod /data/local/tmp/fat.ko $ksu_arg'" >/dev/null

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
