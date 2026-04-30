#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# CLI smoke test for `khtools verify`. Skips when magiskboot is absent
# (no way to round-trip a boot.img). When magiskboot exists, exercises
# the error paths only — full end-to-end verify against a real patched
# boot.img requires a binary fixture and is left for integration runs.

set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"

if ! command -v magiskboot >/dev/null 2>&1; then
    echo "skip: magiskboot not in PATH"
    exit 77
fi

# Missing args
out=$(./build_debug/khtools/khtools verify 2>&1 || true)
echo "$out" | grep -q "required" || { echo "verify no-args: expected 'required'"; exit 1; }

# Dispatch wired (not "unknown subcommand")
echo "$out" | grep -q "unknown subcommand" && { echo "verify dispatch missing"; exit 1; }

# Unparseable boot.img → magiskboot unpack failure
out=$(./build_debug/khtools/khtools verify --boot /dev/null 2>&1 || true)
echo "$out" | grep -q "magiskboot unpack failed" || { echo "verify bad-boot: expected unpack-failure message"; exit 1; }

echo "verify smoke: dispatch wired + arg validation OK"
