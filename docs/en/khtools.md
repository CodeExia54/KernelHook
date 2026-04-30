# khtools — KernelHook PC Build Tool

`khtools` is a host-side CLI that adapts the KernelHook payload (`fat.ko`) for a specific target kernel and packages it for the install path you choose.

> **Note**: This document tracks Phase 4 of the foundation rollout. The `finalize`, `patch`, and `verify` subcommands depend on `<elf.h>`; on macOS hosts they emit a stub error and need a Linux build host (or NDK target).

## Subcommands

| Subcommand | Purpose |
|---|---|
| `probe`     | Detect kernel image properties (ksymtab variant, kCFI mode, banner) |
| `dump-syms` | Print kallsyms parsed from a kernel Image |
| `finalize`  | Adapt a `fat.ko` for a target Image (path 1) |
| `patch`     | Patch a `boot.img` with `khimg` + `fat.ko` (path 2) |
| `extract`   | Extract the kernel `Image` from a `boot.img` (via magiskboot) |
| `list`      | Inspect a KernelHook artifact (fat.ko or patched kernel section) |
| `verify`    | Sanity-check a patched `boot.img` (CI gate) |

## Examples

```sh
# Probe a kernel image
khtools probe --image boot.img

# Dump kallsyms (useful for offline symbol lookups)
khtools dump-syms --image boot.img | head

# Finalize fat.ko for path-1 install on a known target
khtools finalize \
    --image boot.img \
    --in    kmod/kernelhook.ko \
    --out   fat.ko \
    [--graft-host vendor_host.ko]

# Patch a boot.img for path-2 install
khtools patch \
    --boot     boot.img \
    --in       fat.ko \
    --khimg    khimg/khimg \
    [--ksu-lkm ksu.ko] \
    --out      patched-boot.img

# Verify integrity of a patched boot.img
khtools verify --boot patched-boot.img

# List the consumers compiled into a fat.ko
khtools list --in kmod/kernelhook.ko
```

## Exit codes

| Code | Meaning |
|---|---|
| 0   | success |
| 1   | usage / unknown subcommand |
| 2   | argument validation / I/O failure |
| 4   | graft path required but graft host not provided / graft failed |
| 5   | external tool (e.g. `magiskboot`) failure |
| 6   | trailer missing or SHA-256 mismatch (verify only) |

## Dependencies

- **magiskboot** in `PATH` — for `boot.img` unpack/repack (`extract`, `patch`, `verify`)
- **`<elf.h>`** at build time (Linux / NDK) — for `finalize`, `patch`, `verify`, `list` ELF inspection. macOS host builds expose a stub.

## Known limitations

- Hook injection (port of KernelPatch `tools/patch.c::find_hook_offset`) is **deferred**. The patched `boot.img` produced by `khtools patch` carries a valid trailer that `khimg` could parse, but the kernel's setup path is not yet hooked to actually run `khimg`. Path-2 end-to-end works once that lands.
- `khtools finalize` CRC-table extraction from the offline target Image is a no-op stub; on kernels with `CONFIG_MODVERSIONS=y` and `__versions` references, fat.ko load may fail with "disagrees about version of symbol module_layout" until a follow-up wires the real `__kcrctab` walker.
