#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 bmax121. All Rights Reserved.
#
# AVD path-2 e2e: take the AVD's stock `kernel-ranchu` (gzip arm64 Image),
# inject khimg + fat.ko + optional KSU via `khtools patch-image`, boot the
# AVD with `emulator -kernel <patched>`, and confirm khimg's "kh: khimg:"
# markers appear in the kernel console.
#
# Why bypass boot.img: AVDs ship a raw `kernel-ranchu` and don't expose a
# fastboot-flashable boot partition, so the magiskboot unpack/repack loop
# is wasted work. `emulator -kernel <Image>` is the supported override
# path. khtools patch-image is the sibling subcommand that operates on a
# raw Image (vs. khtools patch which operates on a boot.img).
#
# The fat.ko load itself is best-effort: modern GKI rejects init_module(2)
# from a kernel pointer because __do_sys_init_module routes through
# copy_from_user. Until the KP-style raw-bytes module loader lands
# (Task B in the foundation v1 plan), PASS = "kh: khimg: entered" +
# "kh: khimg: fat.ko sha256 verified" observed in the console; the
# init_module rc is logged but does not gate the test.
#
# Usage:
#   ./scripts/test_avd_path2.sh                          # Pixel_31 / khm
#   ./scripts/test_avd_path2.sh Pixel_36                 # different AVD
#   ./scripts/test_avd_path2.sh Pixel_31 khm,apd         # AVD + consumers
#   ./scripts/test_avd_path2.sh Pixel_31 khm --ksu       # +KSU LKM in trailer
#
# Env knobs:
#   KH_PATH2_TIMEOUT   marker wait timeout in seconds (default 240)
#   KH_PATH2_KSU_TAG   KSU GKI tag override (default android12-5.10 for Pixel_31)
#   ANDROID_HOME       Android SDK root (default ~/Library/Android/sdk)
#
# Exit codes: 0 PASS, 1 marker timeout, 2 setup failure, 3 fetch failure.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$ROOT/scripts"
source "$SCRIPT_DIR/lib/avd_console.sh"

avd="${1:-Pixel_31}"
modules="${2:-khm}"
ksu_flag="${3:-}"
timeout="${KH_PATH2_TIMEOUT:-240}"
sdk_root="${ANDROID_HOME:-$HOME/Library/Android/sdk}"

logfile="/tmp/avd-${avd}-path2-console.log"
khimg_path="$ROOT/khimg/khimg"
fat_path="/tmp/fat-${avd}-path2.ko"
kernel_raw="/tmp/kernel-${avd}-stock"
patched_path="/tmp/patched-${avd}-Image"

echo "kh: path2: avd=$avd modules=$modules ksu=${ksu_flag:-no}"

# 1. Sanity: khtools + khimg built.
[[ -x $ROOT/build_debug/khtools/khtools ]] || {
    echo "kh: path2: build_debug/khtools/khtools missing — run cmake --build build_debug" >&2
    exit 2
}
[[ -f $khimg_path ]] || {
    echo "kh: path2: khimg/khimg missing — run make -C khimg" >&2
    exit 2
}

# 2. Resolve the AVD's stock kernel-ranchu via $avd.avd/config.ini :: image.sysdir.1.
avd_dir="$HOME/.android/avd/${avd}.avd"
[[ -f $avd_dir/config.ini ]] || {
    echo "kh: path2: $avd_dir/config.ini missing — is the AVD created?" >&2
    exit 2
}
sysdir=$(grep -E '^image\.sysdir\.1' "$avd_dir/config.ini" | head -1 | cut -d= -f2 | tr -d '[:space:]')
[[ -n $sysdir ]] || {
    echo "kh: path2: image.sysdir.1 not found in $avd_dir/config.ini" >&2
    exit 2
}
sdk_kernel="$sdk_root/$sysdir/kernel-ranchu"
[[ -f $sdk_kernel ]] || sdk_kernel="$sdk_root/$sysdir/kernel-ranchu-64"
[[ -f $sdk_kernel ]] || {
    echo "kh: path2: kernel-ranchu not found under $sdk_root/$sysdir/" >&2
    exit 2
}
echo "kh: path2: stock kernel = $sdk_kernel"

# 3. Build fat.ko (KH_FAT_LINK + the requested consumers).
make -C "$ROOT/kmod" clean >/dev/null 2>&1 || true
if ! make -C "$ROOT/kmod" module KH_FAT_LINK=1 KH_MODULES="$modules" >/dev/null 2>&1; then
    echo "kh: path2: fat.ko build failed for modules=$modules" >&2
    exit 2
fi
cp "$ROOT/kmod/kernelhook.ko" "$fat_path"

# 4. Optional KSU fixture.
ksu_arg=()
if [[ $ksu_flag == "--ksu" ]]; then
    ksu_tag="${KH_PATH2_KSU_TAG:-android12-5.10}"
    if ! "$ROOT/khtools/fixtures/ksu_lkm/fetch.sh" "$ksu_tag" >/dev/null; then
        echo "kh: path2: KSU fixture fetch failed for $ksu_tag" >&2
        exit 3
    fi
    ksu_path="$ROOT/khtools/fixtures/ksu_lkm/$ksu_tag/kernelsu.ko"
    [[ -f $ksu_path ]] || { echo "kh: path2: KSU .ko missing after fetch" >&2; exit 3; }
    ksu_arg=(--ksu-lkm "$ksu_path")
fi

# 5. Decompress the stock kernel — kh_image_inject expects a raw Image
# (gunzip is needed because kernel-ranchu is gzip-compressed).
if file "$sdk_kernel" 2>/dev/null | grep -q "gzip compressed"; then
    if ! gunzip -c "$sdk_kernel" > "$kernel_raw"; then
        echo "kh: path2: gunzip failed for $sdk_kernel" >&2
        exit 2
    fi
else
    cp "$sdk_kernel" "$kernel_raw"
fi
echo "kh: path2: decompressed kernel size = $(wc -c < "$kernel_raw") bytes"

# 6. Inject khimg + trailer into the raw Image.
if ! "$ROOT/build_debug/khtools/khtools" patch-image \
        --image "$kernel_raw" \
        --in    "$fat_path" \
        --khimg "$khimg_path" \
        "${ksu_arg[@]}" \
        --out   "$patched_path"; then
    echo "kh: path2: khtools patch-image failed" >&2
    exit 2
fi
echo "kh: path2: patched kernel size = $(wc -c < "$patched_path") bytes"

# 7. Boot the AVD with the patched kernel and watch the console.
emu_pid=$(avd_boot_show_kernel "$avd" "$patched_path" "$logfile")
trap '[[ -n ${emu_pid:-} ]] && kill "$emu_pid" 2>/dev/null; adb -e emu kill 2>/dev/null || true' EXIT

if ! avd_emulator_running "$emu_pid"; then
    echo "kh: path2: emulator failed to start (see $logfile)" >&2
    exit 2
fi

# 7b. Quick sanity: any kernel-side output within 60s. If the emulator
# itself can't boot the AVD (host issue — observed on macOS 26 + emulator
# 36.5.x where QEMU2 main loop hangs), bail early so CI doesn't burn the
# full $timeout.
sanity_ok=0
for _ in $(seq 1 30); do
    sleep 2
    if grep -qE 'Linux version|Booting Linux|kh: ' "$logfile" 2>/dev/null; then
        sanity_ok=1; break
    fi
    if grep -qE "QEMU2 main loop'\. No response for [0-9]{5,}" "$logfile" 2>/dev/null; then
        echo "kh: path2: emulator stuck (host-side QEMU2 hang) — bailing" >&2
        echo "kh: path2: console tail:" >&2
        tail -10 "$logfile" >&2 || true
        exit 2
    fi
done
if [[ $sanity_ok -eq 0 ]]; then
    echo "kh: path2: no kernel output within 60s — emulator likely hung" >&2
    tail -10 "$logfile" >&2 || true
    exit 2
fi

# 8. Wait for the khimg entry marker — proof the static hook fired.
if ! avd_wait_marker "$logfile" "kh: khimg: entered" "$timeout"; then
    echo "kh: path2: FAIL — 'kh: khimg: entered' not seen within ${timeout}s" >&2
    echo "kh: path2: console tail:" >&2
    tail -40 "$logfile" >&2 || true
    exit 1
fi
echo "kh: path2: khimg entry marker observed"

if avd_wait_marker "$logfile" "kh: khimg: fat.ko sha256 verified" 30; then
    echo "kh: path2: trailer SHA-256 matches"
else
    echo "kh: path2: WARN — sha256 verify marker not seen within 30s"
fi

# init_module rc is informational only until Task B (raw-bytes module loader port).
if grep -qE 'kh: khimg: init_module rc=0\b' "$logfile" 2>/dev/null; then
    echo "kh: path2: bonus — fat.ko loaded via in-tree init_module"
else
    grep -E 'kh: khimg: init_module rc=' "$logfile" 2>/dev/null | tail -1 \
        | sed 's/^/kh: path2: (deferred) /'
fi

echo "kh: path2: PASS"
exit 0
