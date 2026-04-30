# Build Modes

KernelHook supports three build modes for kernel modules. Choose based on your constraints.

## Comparison

| | Mode A (Freestanding) | Mode B (SDK) | Mode C (Kbuild) |
|---|---|---|---|
| Kernel headers | Not needed | Not needed | Required |
| kernelhook.ko | Not needed | Must load first | Optional |
| Core lib in .ko | Yes (compiled in) | No (linked at runtime) | Optional |
| Load method | insmod / kmod_loader | insmod / kmod_loader | insmod |
| .ko size | Large (~200KB) | Small (~10KB) | Depends |
| Best for | Single-module deployment | Multi-module deployment | Standard kernel dev |

## Mode A -- Freestanding

No kernel headers required. Uses `shim.h` as a minimal kernel header replacement. The core hooking library is compiled directly into your `.ko`.

### Build

```bash
cd examples/hello_hook
make module
```

The Makefile includes `kmod/mk/kmod.mk`, which handles cross-compilation, linker scripts, and the shim layer automatically.

### Makefile Template

```makefile
MODULE_NAME  := my_hook
MODULE_SRCS  := my_hook.c
KERNELHOOK_DIR := /path/to/KernelHook/kmod
include $(KERNELHOOK_DIR)/mk/kmod.mk
```

### Source Includes

```c
#include "../../kmod/shim/shim.h"
#include <types.h>
#include <kh_hook.h>
#include <symbol.h>
#include <memory.h>
#include <arch/arm64/pgtable.h>
#include "../../kmod/src/compat.h"
#include "../../kmod/src/mem_ops.h"
```

### Init Sequence

Mode A modules must initialize the subsystems manually:

```c
static int __init my_hook_init(void)
{
    int rc;

    rc = kmod_compat_init(kallsyms_addr);    /* symbol resolution */
    if (rc) return rc;

    rc = kmod_hook_mem_init();               /* memory pools */
    if (rc) return rc;

    rc = pgtable_init();                     /* page table ops */
    if (rc) { kmod_hook_mem_cleanup(); return rc; }

    extern void kh_write_insts_init(void);
    kh_write_insts_init();                   /* code patching */

    /* ... install hooks ... */
    return 0;
}
```

### Loading

Use `insmod` if CRC/vermagic matches, or `kmod_loader` for cross-kernel compatibility:

```bash
kmod_loader my_hook.ko    # auto-fetches kallsyms_addr from /proc/kallsyms
```

## Mode B -- SDK

Depends on `kernelhook.ko` being loaded first. Your module links against the exported symbols at runtime, resulting in a much smaller `.ko`.

### Build

```bash
cd examples/hello_hook
make -f Makefile.sdk module
```

Uses `kmod/mk/kmod_sdk.mk`. Defines `-DKH_SDK_MODE` automatically.

### Makefile Template

```makefile
MODULE_NAME  := my_hook
MODULE_SRCS  := my_hook.c
KERNELHOOK_DIR := /path/to/KernelHook/kmod
include $(KERNELHOOK_DIR)/mk/kmod_sdk.mk
```

### Source Includes

```c
#include <kernelhook/kh_hook.h>
#include <kernelhook/types.h>
#include <kernelhook/kh_symvers.h>   /* auto-generated, provides KH_DECLARE_VERSIONS() */
```

### Module Metadata

The consumer `.ko`'s main translation unit (the same `.c` file that carries
`module_init`) must declare version info for both kernel and KernelHook
symbols:

```c
MODULE_VERSIONS();       /* kernel symbols (module_layout / _printk / memcpy / memset) */
KH_DECLARE_VERSIONS();   /* KernelHook exports (kh_hook_wrap / ksyms_lookup / ...) */
MODULE_VERMAGIC();
MODULE_THIS_MODULE();
```

`KH_DECLARE_VERSIONS()` comes from the auto-generated
`<kernelhook/kh_symvers.h>`, produced by `tools/kh_crc` out of
`kmod/exports.manifest`. Every KernelHook symbol's CRC is frozen under
Contract 4: upgrading `kernelhook.ko` will never break an already-built
consumer `.ko`, as long as the symbol's manifest entry stays unchanged the
CRC stays unchanged.

### Init Sequence

No subsystem init needed -- `kernelhook.ko` handles it:

```c
static int __init my_hook_init(void)
{
    void *target = (void *)ksyms_lookup("do_sys_openat2");
    kh_hook_err_t err = kh_hook_wrap4(target, my_before, my_after, NULL);
    /* ... */
    return 0;
}
```

### Loading

Load `kernelhook.ko` first, then your module:

```bash
insmod kernelhook.ko kallsyms_addr=0x...
insmod my_hook.ko
```

## Mode C -- Kbuild

Standard Linux out-of-tree kernel module build via a real kernel source tree.
Unlike Mode A, each `.ko` is tied to one exact kernel (CRC + vermagic match),
which is the tradeoff for zero runtime patching.

Authoritative working references (covered by CI in
`.github/workflows/kbuild.yml` on GKI 6.1):

- [`kmod/Kbuild`](../../kmod/Kbuild) — builds `kernelhook.ko` + `Module.symvers`
- [`examples/kbuild_hello/`](../../examples/kbuild_hello/) — SDK consumer
  linking against those exports via `KBUILD_EXTRA_SYMBOLS`
- [`examples/hello_hook/Kbuild`](../../examples/hello_hook/Kbuild) —
  contrasting static-link style (core library compiled into the consumer)

### Prerequisites

- A Linux kernel source tree with `modules_prepare` run.
- `CONFIG_KPROBES=y` on the target kernel if you load `kernelhook.ko` without
  passing `kallsyms_addr=` — `kmod_compat_init()` uses a kprobes fallback to
  resolve `kallsyms_lookup_name` at module load time.

### Building `kernelhook.ko`

```bash
make -C /path/to/kernel ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     M=$(pwd)/kmod modules
```

Produces:

- `kmod/kernelhook.ko`
- `kmod/Module.symvers` — carries the 17 SDK exports from
  `kmod/exports.manifest` via real `EXPORT_SYMBOL()` (dispatched by the
  `KH_EXPORT` macro in `kmod/src/export.c`).

### Consumer module via `KBUILD_EXTRA_SYMBOLS`

See [`examples/kbuild_hello/`](../../examples/kbuild_hello/) for a minimal
working consumer. The essential Kbuild wiring is:

```makefile
obj-m := my_hook.o
my_hook-y := my_hook_main.o

ccflags-y := \
    -I$(KERNELHOOK)/include \
    -I$(KERNELHOOK)/include/arch/arm64 \
    -I$(KERNELHOOK)/kmod/include

KBUILD_EXTRA_SYMBOLS := $(KERNELHOOK)/kmod/Module.symvers
```

Build after `kernelhook.ko` is produced:

```bash
make -C /path/to/kernel ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
     M=$(pwd)/examples/kbuild_hello \
     KBUILD_EXTRA_SYMBOLS=$(pwd)/kmod/Module.symvers modules
```

Verify the dependency landed:

```bash
modinfo examples/kbuild_hello/kbuild_hello.ko | grep depends
# -> depends: kernelhook
```

### Loading

```bash
insmod kernelhook.ko                 # or kallsyms_addr=0x... if no kprobes
insmod kbuild_hello.ko
```

### Running the kbuild path locally

CI builds Mode C modules inside pre-built DDK containers
(`ghcr.io/ylarod/ddk-min:<branch>`), so you don't need to clone or compile the
kernel yourself. Reproduce any CI build locally with Docker:

```bash
# One-liner: build kh_test.ko against GKI 6.1
bash scripts/build/build_with_docker.sh android14-6.1

# Build for all five GKI branches
for branch in android12-5.10 android13-5.15 android14-6.1 android15-6.6 android16-6.12; do
    bash scripts/build/build_with_docker.sh $branch
done

# Build kernelhook.ko + the SDK consumer (kbuild_hello.ko)
bash scripts/build/build_with_docker.sh android14-6.1 kernelhook kbuild_hello
```

Output lands in `build/output/<branch>/`. The first run downloads the DDK
image (~500 MB, cached locally afterwards).

See [`scripts/build/README.md`](../../scripts/build/README.md) for full
options including custom registries, Linux-host-without-Docker builds, and
troubleshooting.

### Important compatibility note

A Mode C `kernelhook.ko` uses real kernel-emitted CRCs and **cannot** be
mixed with a Mode A (freestanding) consumer `.ko`, and vice versa — the CRC
spaces are independent. Pick one mode per deployment.

## Host platform support

KernelHook builds on macOS and Linux hosts. The build system auto-detects a
cross-compiler using this decision order (first match wins):

1. **User override** — if you set `CC`+`LD`, or `CROSS_COMPILE`, they are
   used as-is. This lets you plug in any toolchain without editing files.
2. **Android NDK** — searched in: `$ANDROID_NDK_ROOT`, `$ANDROID_NDK_HOME`,
   `$ANDROID_SDK_ROOT/ndk/<ver>`, and the platform default
   (`~/Library/Android/sdk/ndk/<ver>` on macOS, `~/Android/Sdk/ndk/<ver>`
   on Linux). The highest installed NDK version wins. API level is
   auto-detected as the maximum supported by the NDK sysroot; override with
   `$ANDROID_API_LEVEL` if you need a specific level.
3. **System cross-compiler** — `aarch64-linux-gnu-gcc`, or
   `clang --target=aarch64-linux-gnu` with `ld.lld`. This fallback only
   produces glibc-ABI binaries, which are **safe for freestanding `.ko`
   modules and probe.ko** but **not** for Android userspace binaries
   (`tests/userspace/test_android.c` et al.), which require bionic ABI.
4. **Error** — if none of the above, the build aborts with the list of
   environment variables you can set to unblock it.

Every invocation prints one `[toolchain] using <kind>: ...` line to stderr
naming the compiler actually selected. Fallback reasons are also logged.

### Environment variables

| Variable | Purpose |
|---|---|
| `CC`, `LD` | Explicit compiler/linker paths (highest priority) |
| `CROSS_COMPILE` | Toolchain prefix, e.g. `aarch64-linux-gnu-` |
| `ANDROID_NDK_ROOT` | Direct path to an NDK |
| `ANDROID_NDK_HOME` | Legacy alias for `ANDROID_NDK_ROOT` |
| `ANDROID_SDK_ROOT` | SDK root; NDK resolved via `$SDK/ndk/<ver>` |
| `ANDROID_HOME` | Legacy alias for `ANDROID_SDK_ROOT` |
| `ANDROID_API_LEVEL` | Override auto-detected API level |

### Linux host examples

Install the NDK under `~/Android/Sdk/ndk/<ver>` (Android Studio default) and
nothing else is needed:

```bash
./scripts/run_android_tests.sh   # auto-detects NDK
```

Or use a system cross-compiler for freestanding builds without an NDK:

```bash
sudo apt install gcc-aarch64-linux-gnu
make -C examples/hello_hook KDIR=/path/to/linux-headers-arm64
```

Android userspace tests still require an NDK — they will fail fast with a
clear error if only system cross-gcc is available.

## Fat-link mode (KH_FAT_LINK=1)

Builds a single `kernelhook.ko` (the *fat* `.ko`) that statically links the SDK base **plus** any consumers selected via `KH_MODULES`. The consumers register themselves into a `.kh_consumer_table` ELF section via the `kh_consumer_register` macro; a master init in `fat_main.c` walks the section in priority order and dispatches each consumer's init/exit.

```bash
make -C kmod module KH_FAT_LINK=1 KH_MODULES=apd,khm,supercall
```

This is the build mode for the path-1 / path-2 install flows in `khtools`. Without `KH_FAT_LINK`, `kernelhook.ko` is the standalone SDK base and consumers compile separately as their own `.ko` files — that path remains the dev-mode workflow.

`KH_MODULES` accepts a comma-separated list. Currently supported consumers (skeletons that prove dispatch wiring; full functionality lands in Phase 5b / C subspec):

| Module | Priority | Source |
|---|---|---|
| `supercall` | `KH_PRIO_SUBSYS` (100) | `kmod/consumers/supercall/` |
| `apd`       | `KH_PRIO_NORMAL` (500) | `kmod/consumers/apd/` |
| `khm`       | `KH_PRIO_NORMAL` (500) | `kmod/consumers/khm/` |

When `KH_FAT_LINK` is unset, each consumer's `kh_consumer_init(...)` macro expands to its own `module_init / module_exit`, so existing `examples/*` and any consumer's `make module` continue to produce a separate `.ko` with no source changes.
