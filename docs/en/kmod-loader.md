# kmod_loader -- Adaptive Module Loader

> **Note (2026-04+)**: This document describes the **developer-mode loader**. For production install, use `khtools finalize` + `khinsmod` (path 1) or `khtools patch` (path 2). See [khtools.md](khtools.md), [path1-quickstart.md](path1-quickstart.md), and [path2-bootpatch.md](path2-bootpatch.md). `kmod_loader` is preserved for dev workflows where you want runtime patching without a PC-side finalize pass.

`kmod_loader` is a userspace tool that patches a freestanding `.ko` binary at load time to match the running kernel's ABI. It enables cross-kernel module loading without recompilation.

## Usage

```
kmod_loader <module.ko> [options] [param=value ...]
```

`kallsyms_lookup_name` is auto-fetched from `/proc/kallsyms`. The loader must
already run as root (loading a module requires `CAP_SYS_MODULE`) and the
kernel must expose symbol addresses to root (`kptr_restrict <= 1`). Pass
`kallsyms_addr=0xHEX` to override.

## What It Patches

| Field | How |
|-------|-----|
| **vermagic** | Replaced with running kernel's `uname -r` + standard suffix |
| **CRC values** | `__versions` section patched with correct CRCs for `module_layout`, `printk`, etc. |
| **init/exit offsets** | Relocations in `.rela.gnu.linkonce.this_module` adjusted to match `struct module` layout |
| **struct module size** | `.gnu.linkonce.this_module` section resized |
| **printk symbol** | `_printk` (6.1+) vs `printk` (5.10) auto-detected and renamed in `__versions` + strtab |
| **kallsyms_addr** | Patched directly into ELF `.data` section (avoids `module_param` / shadow CFI issues) |
| **this_module section** | Zeroed before patching to prevent `ei_funcs`/`num_ei_funcs` garbage |

## CLI Options

| Option | Description |
|--------|-------------|
| `kallsyms_addr=0xHEX` | Override auto-fetched `kallsyms_lookup_name` address |
| `--init-off 0xHEX` | Override `struct module` init function offset |
| `--exit-off 0xHEX` | Override `struct module` exit function offset |
| `--probe` | Force re-probe of init/exit offsets (ignore cache) |
| `--crc sym=0xHEX` | Override CRC for a specific symbol (repeatable) |
| `param=value` | Module parameters passed through to `init_module` |

## Init/Exit Offset Resolution

`kmod_loader` uses a tiered strategy to find the correct `init` and `exit` offsets in `struct module`:

1. **CLI override** -- `--init-off` / `--exit-off` / `--mod-size` take precedence
2. **Vendor introspection** -- reads a vendor `.ko` on the device to extract the actual `struct module` size and init/exit offsets from `.rela.gnu.linkonce.this_module` relocations. Most accurate for physical devices (e.g. Pixel) where GKI presets may not match. Searches `/vendor_dlkm/lib/modules`, `/vendor/lib/modules`, `/system/lib/modules`.
3. **Version presets** -- hardcoded offsets for known GKI kernel versions (verified on AVD emulators)
4. **Persistent cache** -- previously probed offsets stored in the `kmod_loader` binary itself
5. **Method A (kcore disasm)** -- reads `do_init_module` from `/proc/kcore`, scans for `LDR X0, [Xn, #imm]; CBZ X0` pattern
6. **Method B (binary probe)** -- embeds a minimal `probe.ko` (init returns `-EINVAL`), tries candidate offsets 0x100-0x200 step 8. `EINVAL` = init ran = correct offset. Crash-resilient via companion state file.

### Version Preset Table

| Kernel | struct module size | init offset | exit offset | Status |
|--------|--------------------|-------------|-------------|--------|
| 4.4    | 0x340              | 0x158       | 0x2d0       | AVD verified |
| 4.9    | 0x358              | 0x150       | 0x2e8       | Computed |
| 4.14   | 0x370              | 0x150       | 0x2f8       | AVD verified (init) |
| 4.19   | 0x390              | 0x168       | 0x318       | Computed |
| 5.4    | 0x400              | 0x178       | 0x340       | AVD verified |
| 5.10   | 0x440              | 0x190       | 0x3c8       | AVD verified |
| 5.15   | 0x3c0              | 0x178       | 0x378       | AVD verified |
| 6.1    | 0x400              | 0x140       | 0x3d8       | AVD verified |
| 6.6    | 0x600              | 0x188       | 0x5b8       | AVD verified |
| 6.12   | 0x640              | 0x188       | 0x5f8       | AVD verified |

**Note:** Physical devices often have different offsets than GKI AVDs (e.g., Pixel on 6.1 uses init=0x170/size=0x440 vs AVD init=0x140/size=0x400). The vendor introspection tier handles this automatically.

## CRC Resolution

CRC values are resolved in order:

1. `--crc` command-line overrides
2. kallsyms `__crc_*` symbols (from `/proc/kallsyms`)
3. Vendor `.ko` files on device (parse `__versions` section)
4. Boot partition kernel image
5. `finit_module` with `MODULE_INIT_IGNORE_MODVERSIONS` flag (if kernel supports it)

## AVD-Specific Usage

Android Virtual Devices lack `/proc/kcore` and vendor `.ko` files. CRCs must be extracted from the host-side kernel image using `extract_avd_crcs.py`:

```bash
# Extract CRCs from AVD kernel image (auto-detects ksymtab format)
CRC_ARGS=$(python3 scripts/extract_avd_crcs.py -s emulator-5554)

# Load with extracted CRCs
adb shell "/data/local/tmp/kmod_loader /data/local/tmp/my_hook.ko \
    kallsyms_addr=0x... $CRC_ARGS"
```

The CRC extraction tool supports three ksymtab entry formats:
- **12-byte prel32** (5.10+) -- relative offset entries
- **16-byte absolute** (4.x) -- `{ ulong value, const char *name }` with 4 or 8-byte CRCs
- **24-byte absolute+CFI** (5.4) -- `{ ulong value, const char *name, ulong cfi_type }` with 4-byte CRCs

For unrelocated kernel images (4.14 and earlier), where ksymtab name pointers are zero, the tool falls back to using `__ksymtab_<sym>` addresses from `/proc/kallsyms` to compute the CRC table index.

## Build

```bash
cd tools/kmod_loader
make              # build kmod_loader (needs cross-compiler to emit aarch64 binary)
make regenerate   # rebuild embedded probe.ko (only if probe.c or toolchain changes)
```

`probe.ko` is embedded into the `kmod_loader` binary at compile time via
`probe_embed.h` — generated by `xxd -i` and committed to the repo — so you
**only push `kmod_loader` and your own `.ko`** to the device; there is no
separate `probe.ko` to ship. At runtime, Method B offset probing writes the
embedded bytes to a temp file and `finit_module`s it.

`make regenerate` is only needed when you modify `probe.c` itself or switch
cross-compiler versions; everyday builds don't need it.

## Example

```bash
# Physical device (Pixel 6, kernel 6.1) — loader auto-fetches kallsyms_addr
adb push kmod_loader hello_hook.ko /data/local/tmp/
adb shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/hello_hook.ko'"

# AVD (kernel 5.10) — CRCs come from the host-side kernel image
CRC_ARGS=$(python3 scripts/extract_avd_crcs.py -s emulator-5554)
adb shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/hello_hook.ko $CRC_ARGS'"
```
