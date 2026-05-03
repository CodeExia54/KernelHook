#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 bmax121. All Rights Reserved.
#
# Helpers for AVD-based testing that read the kernel console directly via
# `emulator -no-window -show-kernel` rather than polling `dmesg` over adb.
# Reading the console avoids the dmesg-eviction race that bit the old
# test_avd_kmod.sh / test_avd_graft.sh on Pixel_3{4,5} when the kernel
# log buffer wraps before the test can read it.
#
# Source from a test script:
#   source "$(dirname "$0")/lib/avd_console.sh"
#
# Functions provided:
#   avd_boot_show_kernel <avd> <kernel_or_empty> <logfile>
#       → echoes the emulator PID; redirects all kernel/console output to
#         <logfile>. Caller is responsible for backgrounding cleanup
#         (trap 'kill <pid>' EXIT).
#
#   avd_wait_marker <logfile> <marker> [timeout_seconds=90]
#       → grep -q polls <logfile> until <marker> appears or <timeout>
#         elapses. Returns 0 on hit, 1 on timeout.
#
#   avd_emulator_running <pid>
#       → returns 0 if the process is still alive (sanity check before
#         issuing adb commands).
#
# All helpers are pure POSIX-ish bash; no GNU coreutils-specific flags.
# Tested on macOS 14 + Linux Ubuntu 22.04 hosts.

set -uo pipefail

# Resolve emulator binary once. Set EMULATOR= in the env to override.
: "${EMULATOR:=${ANDROID_HOME:-${HOME}/Library/Android/sdk}/emulator/emulator}"
if [[ ! -x $EMULATOR ]]; then
    if command -v emulator >/dev/null 2>&1; then
        EMULATOR=$(command -v emulator)
    fi
fi

avd_boot_show_kernel() {
    local avd="$1"; local kernel="${2:-}"; local logfile="$3"
    if [[ ! -x $EMULATOR ]]; then
        echo "avd_boot_show_kernel: \$EMULATOR not executable: $EMULATOR" >&2
        return 1
    fi
    local args=(-no-window -show-kernel -avd "$avd")
    [[ -n $kernel ]] && args+=(-kernel "$kernel")
    "$EMULATOR" "${args[@]}" >"$logfile" 2>&1 &
    echo $!
}

avd_wait_marker() {
    local logfile="$1"; local marker="$2"; local timeout="${3:-90}"
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if [[ -f $logfile ]] && grep -qE -- "$marker" "$logfile"; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

avd_emulator_running() {
    local pid="$1"
    [[ -n $pid ]] && kill -0 "$pid" 2>/dev/null
}
