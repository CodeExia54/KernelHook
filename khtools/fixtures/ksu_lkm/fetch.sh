#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 bmax121. All Rights Reserved.
#
# Materialize the KernelSU LKM fixtures listed in MANIFEST.txt. Idempotent:
# if a target .ko already exists and matches the pinned SHA-256, no
# network request is made. The .ko binaries are not committed; this
# script is the only supported way to produce them under
# khtools/fixtures/ksu_lkm/.
#
# Usage:
#   fetch.sh                # fetch every GKI tag in MANIFEST.txt
#   fetch.sh android12-5.10 # fetch only the named tag
#
# Exit codes: 0 OK, 2 sha256 mismatch, 3 download failure, 4 manifest
# parse failure.

set -euo pipefail

cd "$(dirname "$0")"

# Parse the URLs and SHA-256 sums out of MANIFEST.txt — single source of
# truth. The format is fixed: indented "tag  url" lines under "URLs:" and
# indented "tag  sha256" lines under "SHA-256 (verified by fetch.sh):".
MANIFEST=MANIFEST.txt
[[ -f $MANIFEST ]] || { echo "fetch.sh: MANIFEST.txt not found" >&2; exit 4; }

declare -A URL_OF SHA_OF
section=
while IFS= read -r line; do
    case "$line" in
        URLs:*) section=urls; continue ;;
        SHA-256*) section=sha; continue ;;
        Sizes*|Notes:*|"") section=; continue ;;
    esac
    [[ -z $section ]] && continue
    # Indented entry: "tag  value"
    tag="$(echo "$line" | awk '{print $1}')"
    val="$(echo "$line" | awk '{print $2}')"
    [[ -z $tag || -z $val ]] && continue
    case $section in
        urls) URL_OF[$tag]=$val ;;
        sha)  SHA_OF[$tag]=$val ;;
    esac
done < $MANIFEST

if [[ ${#URL_OF[@]} -eq 0 ]]; then
    echo "fetch.sh: no URLs parsed from $MANIFEST" >&2
    exit 4
fi

# Pick which tags to fetch
if [[ $# -gt 0 ]]; then
    tags=("$@")
else
    tags=("${!URL_OF[@]}")
fi

# sha256 helper that works on Linux and macOS (CI + dev hosts).
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

rc=0
for tag in "${tags[@]}"; do
    url="${URL_OF[$tag]:-}"
    want="${SHA_OF[$tag]:-}"
    if [[ -z $url || -z $want ]]; then
        echo "fetch.sh: tag '$tag' not in MANIFEST" >&2
        rc=4; continue
    fi

    out_dir="$tag"
    out="$out_dir/kernelsu.ko"
    mkdir -p "$out_dir"

    if [[ -f $out ]]; then
        have="$(sha256_of "$out")"
        if [[ $have == "$want" ]]; then
            echo "fetch.sh: $tag already pinned ($have)"
            continue
        fi
        echo "fetch.sh: $tag stale (have=$have want=$want), refetching"
        rm -f "$out"
    fi

    echo "fetch.sh: $tag <- $url"
    if ! curl -fsSL "$url" -o "$out"; then
        echo "fetch.sh: $tag download failed" >&2
        rc=3; continue
    fi

    have="$(sha256_of "$out")"
    if [[ $have != "$want" ]]; then
        echo "fetch.sh: $tag sha256 mismatch (have=$have want=$want)" >&2
        rm -f "$out"
        rc=2; continue
    fi
    echo "fetch.sh: $tag verified ($have)"
done

exit $rc
