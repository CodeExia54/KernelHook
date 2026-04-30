# Path 2 — boot.img Patch

Prerequisite: bootloader unlocked (`fastboot oem unlock` or vendor-specific equivalent). Root is **not** required — the patched `boot.img` brings everything online at boot.

> ⚠️ **Status**: This path is **not yet end-to-end** in the foundation rollout. `khtools patch` produces a valid trailer-bearing `boot.img`, but the kernel-side hook injection (port of KernelPatch `tools/patch.c::find_hook_offset`) is a deferred follow-up. Until that lands, the patched image boots normally and ignores the trailer. Use Path 1 for a working install today.

## Steps

1. **Pull the factory boot.img** (or extract from an OEM image):
   ```sh
   adb reboot bootloader
   fastboot getvar current-slot   # e.g. 'a' or 'b'
   fastboot fetch boot_a:boot.img boot.img
   ```

2. **Build all PC-side artifacts**:
   ```sh
   # Host CMake build (khtools)
   cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug
   cmake --build build_debug --target khtools

   # fat.ko with consumers
   make -C kmod module KH_FAT_LINK=1 KH_MODULES=apd,khm,supercall

   # khimg freestanding blob
   make -C khimg
   ```

3. **Optionally pre-finalize fat.ko** for the target — same as Path 1 step 3. Skip if `khtools patch` should embed the unfinalized SDK base (the in-flight finalize logic lands in a follow-up).

4. **Patch the boot.img**:
   ```sh
   khtools patch \
       --boot     boot.img \
       --in       fat.ko \
       --khimg    khimg/khimg \
       [--ksu-lkm kernelsu.ko] \
       --out      patched-boot.img
   ```

5. **Verify the trailer**:
   ```sh
   khtools verify --boot patched-boot.img
   # Prints "OK" with trailer offset, fat.ko bytes, ksu.ko bytes
   ```

6. **Flash** (via fastboot):
   ```sh
   fastboot flash boot patched-boot.img
   fastboot reboot
   ```

7. **Verify on device** — once the hook injection follow-up lands, you'll see `kh: khimg:` early-boot markers in the console (`adb shell dmesg | grep "kh:"`) followed by the SDK init + consumer markers.

## Boot-not-bricked invariant

If the trailer is corrupted (wrong magic, mismatched SHA-256), `khimg`'s entry path early-returns and the kernel continues booting normally. This is verified end-to-end in the test plan (Task 4.3, deferred). You can also flash the original `boot.img` back at any time via `fastboot flash boot boot.img`.

## See also

- [khtools reference](khtools.md)
- [Path 1 (rooted device)](path1-quickstart.md)
- [Architecture](architecture.md)
