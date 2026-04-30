#!/usr/bin/env bash
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"

img=khtools/tests/fixtures/pixel31.Image
ko=khtools/tests/fixtures/kernelhook.ko
if [ ! -f "$img" ] || [ ! -f "$ko" ]; then
    echo "skip: fixtures absent ($img and $ko)"
    exit 77
fi

out=$(mktemp)
trap "rm -f $out" EXIT
./build_debug/khtools/khtools finalize --image "$img" --in "$ko" --out "$out"
[ -s "$out" ] || { echo "empty output"; exit 1; }
file "$out" | grep -q "ELF 64-bit" || { echo "not ELF: $(file $out)"; exit 1; }
echo "finalize smoke: ELF produced, $(stat -f%z "$out" 2>/dev/null || stat -c%s "$out") bytes"
