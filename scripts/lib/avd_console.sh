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
    # The flag set below is the one the parallel KP test rigs use and
    # is the only combo that boots Pixel_31..37 reliably on macOS 26 +
    # emulator 36.5.x. Plain `-no-window -show-kernel` hangs in the
    # QEMU2 main loop. Specifically:
    #   -no-snapshot-save / -no-snapshot-load — full cold boot
    #   -no-audio / -no-boot-anim — drops drivers that race on macOS 26
    #   -gpu swiftshader_indirect — software GPU (HVF GL path is broken)
    local args=(
        -no-window -show-kernel
        -no-snapshot-save -no-snapshot-load
        -no-audio -no-boot-anim
        -gpu swiftshader_indirect
        -avd "$avd"
    )
    [[ -n $kernel ]] && args+=(-kernel "$kernel")
    # If KH_AVD_PORT is set, pin the console+adb pair so we know the
    # serial up front and don't collide with parallel emulator
    # instances (e.g. the kp-debug / kp-df rigs that grab 5554/5556).
    [[ -n ${KH_AVD_PORT:-} ]] && args+=(-ports "$KH_AVD_PORT,$((KH_AVD_PORT + 1))")
    "$EMULATOR" "${args[@]}" >"$logfile" 2>&1 &
    echo $!
}

# Pick a free console+adb port pair via netstat, falling back to 5570
# if the scan turns up empty. Port pairs are (telnet, adb) = (port, port+1);
# emulator's serial is `emulator-<adb_port>` for the started instance.
# We only consider 5570..5582 so the kp-debug / kp-df rigs (5554..5558)
# stay out of our way.
avd_pick_free_port_pair() {
    local in_use
    in_use=$(netstat -an -p tcp 2>/dev/null \
             | awk '/LISTEN/ {n=split($4,a,"."); print a[n]}' | sort -u)
    local p
    for p in 5570 5572 5574 5576 5578 5580 5582; do
        if ! echo "$in_use" | grep -qx "$p" && \
           ! echo "$in_use" | grep -qx "$((p + 1))"; then
            echo "$p"
            return 0
        fi
    done
    echo "5570"
    return 0
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
