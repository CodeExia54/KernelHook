#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Golden test for `khtools finalize` across the 4 ksymtab variants.
#
# For each fixture directory `khtools/fixtures/strategy_matrix/Pixel_*/`,
# expects three files:
#   - Image          : target kernel image to feed `--image`
#   - kernelhook.ko  : input consumer ko to feed `--in`
#   - golden.ko      : reference output (captured manually from a prior
#                      stable khtools finalize run on the same fixture)
#
# Test logic: run `khtools finalize` and `cmp` the result against golden.ko.
# Any byte difference is a regression.
#
# When fixtures are absent (the common case in CI without a binary fixture
# checkout), the test exits 77 (ctest SKIP). Bootstrap workflow:
#   1. On a real build host with access to Pixel_NN boot.img, extract
#      Image, build kernelhook.ko, run khtools finalize.
#   2. Save the resulting fat.ko as golden.ko in the matching fixture dir.
#   3. Future runs catch regressions automatically.
#
# Note: Goldens are self-referential (khtools-vs-prior-khtools), NOT
# byte-equivalent to kmod_loader's runtime-patched output. Lookup paths
# differ — kmod_loader uses /proc/kallsyms; khtools parses the offline
# Image. See feat(khtools): implement 'finalize' subcommand commit body
# (Task 2.2) for full rationale.

set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"

khtools_bin=./build_debug/khtools/khtools
[ -x "$khtools_bin" ] || { echo "skip: khtools not built ($khtools_bin missing)"; exit 77; }

fixtures_dir=khtools/fixtures/strategy_matrix
variant_dirs=$(find "$fixtures_dir" -maxdepth 1 -mindepth 1 -type d | sort)
[ -n "$variant_dirs" ] || { echo "skip: no fixture variants under $fixtures_dir"; exit 77; }

# If no fixture has all three required files, skip wholesale.
have_any=0
for d in $variant_dirs; do
    if [ -f "$d/Image" ] && [ -f "$d/kernelhook.ko" ] && [ -f "$d/golden.ko" ]; then
        have_any=1
        break
    fi
done
[ $have_any -eq 1 ] || { echo "skip: no fixture has Image+kernelhook.ko+golden.ko"; exit 77; }

fail=0
ran=0
for d in $variant_dirs; do
    name=$(basename "$d")
    if [ ! -f "$d/Image" ] || [ ! -f "$d/kernelhook.ko" ] || [ ! -f "$d/golden.ko" ]; then
        echo "[$name] skip: incomplete fixture"
        continue
    fi
    out=$(mktemp)
    "$khtools_bin" finalize \
        --image "$d/Image" --in "$d/kernelhook.ko" --out "$out"
    if cmp -s "$d/golden.ko" "$out"; then
        echo "[$name] OK"
    else
        echo "[$name] DIFFER (first byte diff:)"
        cmp "$d/golden.ko" "$out" | head -1 || true
        fail=1
    fi
    rm -f "$out"
    ran=$((ran + 1))
done

[ $ran -gt 0 ] || { echo "skip: no fixtures complete"; exit 77; }
exit $fail
