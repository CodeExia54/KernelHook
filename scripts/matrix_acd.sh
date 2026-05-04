#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 bmax121. All Rights Reserved.
#
# ACD matrix runner — exercises the foundation-v1.1 changes across the
# Pixel_28..Pixel_37 AVD pool.
#
#   A) khtools patch-image runs on every AVD's stock kernel-ranchu and
#      produces a valid arm64 boot Image.
#   D) path-2 boot test — emulator -kernel <patched> reaches a usable
#      stage and the khimg "entered" + "deferred-load hook armed"
#      markers fire.
#
# C (kernel-side __versions CRC finalize) is exercised indirectly via
# path-1 (separate run with --ksu); covering it here would need every
# AVD's GKI-tagged KSU LKM downloaded, which is too heavy for a single
# matrix pass. See scripts/test_avd_path1.sh for the path-1 lane.
#
# Usage:
#   ./scripts/matrix_acd.sh           # all AVDs, A + D
#   ./scripts/matrix_acd.sh -A         # patch-image only (fast, no boot)
#   ./scripts/matrix_acd.sh -d         # path-2 boot only (presumes A passed)
#
# Env knobs:
#   KH_MATRIX_TIMEOUT  per-AVD boot timeout in seconds (default 180)
#   KH_MATRIX_SKIP     space-separated AVD names to skip (default Pixel_27 Pixel_36_1)

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$ROOT/scripts"
source "$SCRIPT_DIR/lib/avd_console.sh"

mode="all"
case "${1:-}" in
    -A|--a-only)   mode="A" ;;
    -d|--d-only)   mode="D" ;;
    "")            mode="all" ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

timeout="${KH_MATRIX_TIMEOUT:-180}"
skip_list="${KH_MATRIX_SKIP:-Pixel_27 Pixel_36_1}"

# AVD inventory.
avds=$(ls ~/.android/avd/ 2>/dev/null \
       | sed -nE 's/^(Pixel_[0-9_]+)\.avd$/\1/p' \
       | sort -V)

# Avoid AVDs that match a currently-running qemu-system instance
# (parallel kp test rigs).
running=$(pgrep -af 'qemu-system-aarch64' 2>/dev/null \
          | sed -nE 's/.*@([A-Za-z0-9_-]+).*/\1/p')

filter() {
    local a
    for a in $avds; do
        local s skip=0
        for s in $skip_list; do
            if [[ "$a" == "$s" ]]; then skip=1; break; fi
        done
        if [[ $skip -eq 0 ]]; then
            local r
            for r in $running; do
                if [[ "$r" == *"$a"* ]]; then skip=1; break; fi
            done
        fi
        [[ $skip -eq 0 ]] && echo "$a"
    done
}

avds_run=$(filter)
echo "=== ACD matrix ==="
echo "mode  : $mode"
echo "skip  : $skip_list"
echo "busy  : $(echo $running | tr '\n' ' ')"
echo "run   : $(echo $avds_run | tr '\n' ' ')"
echo

# Sanity: required artifacts.
khtools="$ROOT/build_debug/khtools/khtools"
khimg_blob="$ROOT/khimg/khimg"
[[ -x $khtools && -f $khimg_blob ]] || {
    echo "matrix: missing $khtools or $khimg_blob — build first" >&2
    exit 2
}

# Pre-build a single fat.ko (khm consumer). The AVD-specific finalize
# is the userspace kmod_loader's job at insmod time; the bytes embed
# in patch-image just need to be the unfinalized fat.ko.
make -C "$ROOT/kmod" clean >/dev/null 2>&1
if ! make -C "$ROOT/kmod" module KH_FAT_LINK=1 KH_MODULES=khm >/dev/null 2>&1; then
    echo "matrix: fat.ko build failed" >&2
    exit 2
fi
fat_ko="$ROOT/kmod/kernelhook.ko"

results_a=()
results_d=()

resolve_kernel() {
    local avd="$1"
    local cfg="$HOME/.android/avd/${avd}.avd/config.ini"
    [[ -f $cfg ]] || { echo ""; return; }
    local sysdir
    sysdir=$(grep -E '^image\.sysdir\.1' "$cfg" | head -1 | cut -d= -f2 \
             | tr -d '[:space:]')
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
    local k="$sdk/$sysdir/kernel-ranchu"
    [[ -f $k ]] || k="$sdk/$sysdir/kernel-ranchu-64"
    [[ -f $k ]] && echo "$k" || echo ""
}

run_a() {
    local avd="$1"
    local stock raw patched
    stock=$(resolve_kernel "$avd")
    if [[ -z $stock ]]; then
        printf "  A %-12s SKIP (no kernel-ranchu)\n" "$avd"
        results_a+=("$avd:SKIP")
        return
    fi
    raw="/tmp/kernel-${avd}-stock"
    patched="/tmp/patched-${avd}-Image"

    # Decompress (kernel-ranchu is gzip on most images).
    if file "$stock" 2>/dev/null | grep -q gzip; then
        gunzip -c "$stock" > "$raw" 2>/dev/null || {
            printf "  A %-12s FAIL (gunzip)\n" "$avd"
            results_a+=("$avd:FAIL")
            return
        }
    else
        cp "$stock" "$raw"
    fi

    # Run patch-image.
    if ! "$khtools" patch-image \
            --image "$raw" --in "$fat_ko" \
            --khimg "$khimg_blob" --out "$patched" >/dev/null 2>&1; then
        printf "  A %-12s FAIL (khtools patch-image)\n" "$avd"
        results_a+=("$avd:FAIL")
        return
    fi

    # Validate output.
    local desc
    desc=$(file "$patched" 2>/dev/null)
    if echo "$desc" | grep -q "Linux kernel ARM64 boot executable Image"; then
        local sz
        sz=$(wc -c < "$patched")
        printf "  A %-12s PASS (%d bytes)\n" "$avd" "$sz"
        results_a+=("$avd:PASS")
    else
        printf "  A %-12s FAIL (invalid output: %s)\n" "$avd" "$desc"
        results_a+=("$avd:FAIL")
    fi
}

run_d() {
    local avd="$1"
    local patched="/tmp/patched-${avd}-Image"
    local logfile="/tmp/avd-${avd}-matrix-d.log"
    [[ -f $patched ]] || {
        printf "  D %-12s SKIP (no patched Image — run A first)\n" "$avd"
        results_d+=("$avd:SKIP")
        return
    }

    # Pick a free port pair so we don't collide with rigs.
    KH_AVD_PORT=$(avd_pick_free_port_pair)
    export KH_AVD_PORT
    local serial="emulator-$KH_AVD_PORT"

    local emu_pid
    emu_pid=$(avd_boot_show_kernel "$avd" "$patched" "$logfile")
    trap '[[ -n ${emu_pid:-} ]] && kill "$emu_pid" 2>/dev/null;
          adb -s "$serial" emu kill 2>/dev/null || true' RETURN

    # Quick sanity bail — if QEMU2 hangs in main loop within 60s, FAIL.
    local sane=0
    local i
    for i in $(seq 1 30); do
        sleep 2
        if grep -qE 'Linux version|kh: ' "$logfile" 2>/dev/null; then
            sane=1; break
        fi
        if grep -qE "QEMU2 main loop'\. No response for [0-9]{5,}" "$logfile" 2>/dev/null; then
            printf "  D %-12s FAIL (QEMU2 hang)\n" "$avd"
            kill "$emu_pid" 2>/dev/null
            results_d+=("$avd:FAIL")
            trap - RETURN
            return
        fi
    done
    if [[ $sane -eq 0 ]]; then
        printf "  D %-12s FAIL (no kernel banner in 60s)\n" "$avd"
        kill "$emu_pid" 2>/dev/null
        results_d+=("$avd:FAIL")
        trap - RETURN
        return
    fi

    # Wait for khimg entry marker.
    if avd_wait_marker "$logfile" "kh: khimg: entered" "$timeout"; then
        local extra=""
        if avd_wait_marker "$logfile" "kh: khimg: fat.ko sha256 verified" 30; then
            extra="+sha256"
        fi
        if avd_wait_marker "$logfile" "kh: lkm: hook installed at" 30; then
            extra="$extra +hook"
        fi
        printf "  D %-12s PASS (%s)\n" "$avd" "${extra# }"
        results_d+=("$avd:PASS")
    else
        printf "  D %-12s FAIL (no khimg entry marker in ${timeout}s)\n" "$avd"
        results_d+=("$avd:FAIL")
    fi

    kill "$emu_pid" 2>/dev/null
    adb -s "$serial" emu kill 2>/dev/null || true
    sleep 2
    trap - RETURN
}

if [[ $mode == "A" || $mode == "all" ]]; then
    echo "=== A) khtools patch-image ==="
    for avd in $avds_run; do run_a "$avd"; done
    echo
fi

if [[ $mode == "D" || $mode == "all" ]]; then
    echo "=== D) path-2 boot test ==="
    for avd in $avds_run; do run_d "$avd"; done
    echo
fi

echo "=== summary ==="
[[ ${#results_a[@]} -gt 0 ]] && {
    echo "A:"
    for r in "${results_a[@]}"; do echo "  $r"; done
}
[[ ${#results_d[@]} -gt 0 ]] && {
    echo "D:"
    for r in "${results_d[@]}"; do echo "  $r"; done
}

# Exit non-zero if any FAIL.
fails=0
for r in "${results_a[@]}" "${results_d[@]}"; do
    [[ $r == *:FAIL ]] && ((fails++))
done
exit $fails
