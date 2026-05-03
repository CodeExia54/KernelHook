#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 bmax121. All Rights Reserved.
#
# AVD path-2 e2e: pull the AVD's stock boot.img, run khtools patch to
# embed khimg + fat.ko (+ optional KSU), flash the patched image, reboot,
# and confirm khimg's "kh: khimg:" markers appear in the kernel console.
#
# This script exercises the static-hook side. The actual fat.ko load via
# init_module is deferred until the KP-style raw-bytes module loader
# port lands (see commits 3dbdfea / fb3d566 commit messages). For now
# PASS = "kh: khimg: entered" + "kh: khimg: fat.ko sha256 verified"
# observed in the console log; the init_module rc is logged but does not
# gate the test.
#
# Usage:
#   ./scripts/test_avd_path2.sh                           # Pixel_31, default consumers
#   ./scripts/test_avd_path2.sh Pixel_36 khm,apd          # AVD + consumer set
#   ./scripts/test_avd_path2.sh Pixel_31 khm --ksu        # +KSU in trailer
#
# Env knobs:
#   KH_PATH2_TIMEOUT   marker wait timeout in seconds (default 240)
#   KH_PATH2_KSU_TAG   KSU GKI tag override (default android12-5.10 for Pixel_31)
#   MAGISKBOOT         path to magiskboot binary (default: PATH lookup)
#
# Exit codes: 0 PASS, 1 marker timeout, 2 setup failure, 3 fetch failure,
# 4 not yet implemented (fastboot flash on AVD path).

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$ROOT/scripts"
source "$SCRIPT_DIR/lib/avd_console.sh"

avd="${1:-Pixel_31}"
modules="${2:-khm}"
ksu_flag="${3:-}"
timeout="${KH_PATH2_TIMEOUT:-240}"

logfile="/tmp/avd-${avd}-path2-console.log"
khimg_path="$ROOT/khimg/khimg"
fat_path="/tmp/fat-${avd}-path2.ko"
boot_path="/tmp/boot-${avd}.img"
patched_path="/tmp/boot-${avd}-patched.img"

echo "kh: path2: avd=$avd modules=$modules ksu=${ksu_flag:-no}"

# 1. Sanity: khimg + khtools must be built; fat.ko built with KH_FAT_LINK.
[[ -x $ROOT/build_debug/khtools/khtools ]] || {
    echo "kh: path2: build_debug/khtools/khtools missing — run cmake --build build_debug" >&2
    exit 2
}
[[ -f $khimg_path ]] || {
    echo "kh: path2: khimg/khimg missing — run make -C khimg" >&2
    exit 2
}
make -C "$ROOT/kmod" clean >/dev/null 2>&1 || true
if ! make -C "$ROOT/kmod" module KH_FAT_LINK=1 KH_MODULES="$modules" >/dev/null 2>&1; then
    echo "kh: path2: fat.ko build failed for modules=$modules" >&2
    exit 2
fi
cp "$ROOT/kmod/kernelhook.ko" "$fat_path"

magiskboot="${MAGISKBOOT:-$(command -v magiskboot 2>/dev/null || true)}"
[[ -x $magiskboot ]] || {
    echo "kh: path2: magiskboot not found in PATH or via \$MAGISKBOOT" >&2
    exit 2
}

# 2. Optional KSU fixture.
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

# 3. Pull a stock boot.img from the AVD. AVDs do not have a fastboot
# partition we can re-flash directly via `fastboot flash boot`; the
# canonical path is to swap the system image's kernel offline. That
# offline-swap helper is the next deferred chunk. For now stop here
# with a clear "not implemented" marker so CI can wire the lane up,
# and once the helper lands the test light up.
echo "kh: path2: NOT_IMPLEMENTED — AVD boot.img pull + fastboot flash glue is the next deferred follow-up" >&2
echo "kh: path2: artifacts ready for offline use:" >&2
echo "    fat.ko = $fat_path" >&2
echo "    khimg  = $khimg_path" >&2
exit 4

# Below is the intended flow once the AVD glue lands. Left in place as
# a self-documenting plan; not executed (script exits above).

# 4. Patch boot.img.
"$ROOT/build_debug/khtools/khtools" patch \
    --boot "$boot_path" --in "$fat_path" --khimg "$khimg_path" \
    "${ksu_arg[@]}" --out "$patched_path"

# 5. Flash + reboot via emulator's fastboot mode (TBD).
emu_pid=$(avd_boot_show_kernel "$avd" "" "$logfile")
trap '[[ -n ${emu_pid:-} ]] && kill "$emu_pid" 2>/dev/null' EXIT

if ! avd_wait_marker "$logfile" "kh: khimg: entered" "$timeout"; then
    echo "kh: path2: FAIL — 'kh: khimg: entered' not seen within ${timeout}s" >&2
    tail -40 "$logfile" >&2 || true
    exit 1
fi
if ! avd_wait_marker "$logfile" "kh: khimg: fat.ko sha256 verified" 30; then
    echo "kh: path2: FAIL — sha256 verify marker not seen" >&2
    exit 1
fi
echo "kh: path2: PASS (khimg fired and trailer verified)"
exit 0
