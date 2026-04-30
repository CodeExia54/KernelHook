# KernelHook

> ⚠️ Under active development. APIs unstable. **Not for production.**
> 探索开发阶段，接口随时变更，**请勿用于生产**。

ARM64 function hooking framework for Linux kernels.

## Features

- **Inline kh_hook** — replace any kernel function, call original via backup pointer
- **Hook chain** — multiple before/after callbacks per function, priority-ordered
- **Syscall-level kh_hook** — `kh_hook_syscalln(nr, …)` over `__arm64_sys_<name>`, handles pt_regs wrapper ABI; [user-pointer helpers](docs/en/api-reference.md#user-pointer-helpers) (`kh_strncpy_from_user`, `kh_copy_to_user_stack`) for rewriting syscall args
- **Alias-page write path** — vmalloc alias + `aarch64_insn_patch_text_nosync` (KernelPatch-style); bypasses `__ro_after_init` + kCFI; PTE-direct fallback
- **RCU-safe dispatch** — chain state snapshotted onto stack before origin call; validated under 27.8M syscalls × 67K add/remove races in 3 s
- **Adaptive loader** — `kmod_loader` patches .ko binaries for cross-kernel loading; auto-picks ksymtab layout (`prel32` / `abs64` / `abs64-legacy` / `abs64-legacy-u32`) from live kernel
- **Vendor-ko graft** — splices KernelHook payload into a vendor .ko to defeat the Android 15+ GKI kCFI initcall typeid check
- **Featured demo** — [`kh_root`](docs/en/kh-root-demo.md): full privilege-escalation via 3 syscall hooks (~350 LOC)

## Kernel Compatibility

Verified on AVD emulators (Pixel_28..Pixel_37) and a Pixel USB device:

| Kernel    | Android | API     | Path                                       |
|-----------|---------|---------|--------------------------------------------|
| 4.4–4.14  | 9–10    | 28–29   | kmod, `abs64-legacy[-u32]`, `-mcmodel=large` |
| 5.4–5.15  | 11–13   | 30–33   | kmod, `abs64` / `prel32`, shadow-CFI       |
| 6.1       | 14      | 34      | kmod, `prel32`, kCFI                       |
| 6.6+      | 15/16   | 35–37   | vendor-ko graft (kCFI initcall typeid)     |

`kmod_loader` introspects vendor .ko files on the device to auto-select the right layout; physical devices and AVDs share the same code path.

> **Note**: AVD coverage is GKI-pinned (e.g. Pixel_34 = 6.1.23-android14-4). Real devices on later 6.1 sub-versions (e.g. Pixel 6 / 6.1.99-android14-11) inherit Android 15+ kCFI initcall checks and need the graft path even though their major.minor still says 6.1.

## Installation Paths

KernelHook installs via two paths to the same end state — kernel running with a fat.ko payload that exposes consumer modules (apd / khm / supercall) and optional KernelSU integration.

| | Path 1 (rooted device) | Path 2 (boot.img patch) |
|---|---|---|
| Prereq | Existing root | Bootloader unlocked |
| PC tool | `khtools finalize` | `khtools patch` |
| Device tool | `khinsmod fat.ko` | (boot loads automatically) |
| KSU integration | `khinsmod fat.ko --ksu ksu.ko` | `khtools patch --ksu-lkm ksu.ko ...` |

See [docs/en/path1-quickstart.md](docs/en/path1-quickstart.md) and [docs/en/path2-bootpatch.md](docs/en/path2-bootpatch.md). The PC build tool reference lives at [docs/en/khtools.md](docs/en/khtools.md).

## Documentation

- [Getting Started](docs/en/getting-started.md) · [API Reference](docs/en/api-reference.md) · [kh_root Demo](docs/en/kh-root-demo.md)
- [Build Modes](docs/en/build-modes.md) · [kmod_loader](docs/en/kmod-loader.md) · [AVD Testing](docs/en/avd-testing.md) · [Examples](docs/en/examples.md)
- [khtools (PC build tool)](docs/en/khtools.md) · [Path 1 quickstart](docs/en/path1-quickstart.md) · [Path 2 boot.img patch](docs/en/path2-bootpatch.md)
- [中文文档](README_zh.md)

## Build & Test

```bash
# SDK base + sample consumer
make -C kmod module
make -C examples/hello_hook module

# Host unit tests
cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug && cmake --build build_debug
ctest --test-dir build_debug

# Full AVD regression (Pixel_28..34 kmod + Pixel_35..37 graft)
./scripts/test.sh avd-sdk-all
# or scoped: ./scripts/test_avd_kmod.sh Pixel_31 Pixel_34
```

Three build modes — SDK (default, shared `kernelhook.ko`), Freestanding (no `kernelhook.ko` on target), Kbuild (demo only). See [build-modes.md](docs/en/build-modes.md).

## Contributing

File-header conventions: [`docs/style/file-header.md`](docs/style/file-header.md). Public API namespace (`kh_` prefix) enforced by `scripts/lint_exports.sh` (wired into `scripts/test.sh sdk-consumer`).

## License

GPL-2.0-or-later
