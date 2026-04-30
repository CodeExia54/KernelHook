#!/usr/bin/env bash
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"

# Skip if magiskboot not in PATH.
if ! command -v magiskboot >/dev/null 2>&1; then
    echo "skip: magiskboot not in PATH"
    exit 77
fi

out=$(mktemp)
trap "rm -f '$out'" EXIT

# Missing args: expect "required" in error output.
err=$(./build_debug/khtools/khtools extract 2>&1 || true)
if echo "$err" | grep -q "required"; then
    :
else
    echo "extract no-args: expected 'required' error, got: $err"
    exit 1
fi

# Bad boot.img: expect either "magiskboot unpack failed" message or rc=5.
set +e
./build_debug/khtools/khtools extract --boot /nonexistent --out "$out" 2>&1
rc=$?
set -e
if [ "$rc" != "5" ]; then
    echo "extract bad-boot: expected rc=5, got rc=$rc"
    exit 1
fi

echo "extract smoke: CLI error paths OK"
