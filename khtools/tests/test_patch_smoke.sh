#!/usr/bin/env bash
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"

if ! command -v magiskboot >/dev/null 2>&1; then
    echo "skip: magiskboot not in PATH"
    exit 77
fi

# Missing args: should print "required", not "unknown subcommand".
out=$(./build_debug/khtools/khtools patch 2>&1 || true)
if echo "$out" | grep -q "unknown subcommand"; then
    echo "patch dispatch missing — got 'unknown subcommand'"
    exit 1
fi
if ! echo "$out" | grep -q "required"; then
    echo "patch no-args: expected 'required', got: $out"
    exit 1
fi

echo "patch smoke: dispatch wired + arg validation OK"
