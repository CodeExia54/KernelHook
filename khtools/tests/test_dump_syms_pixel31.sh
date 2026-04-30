#!/usr/bin/env bash
set -euo pipefail
# Run from project root.
cd "$(cd "$(dirname "$0")/../.." && pwd)"

fixture=khtools/tests/fixtures/pixel31.Image
if [ ! -f "$fixture" ]; then
    echo "skip: $fixture not present"
    exit 77   # ctest SKIP
fi

out=$(./build_debug/khtools/khtools dump-syms --image "$fixture" 2>&1 | wc -l)
if [ "$out" -gt 1000 ]; then
    echo "dump-syms: $out lines"
    exit 0
fi
echo "expected >1000 syms, got $out"
exit 1
