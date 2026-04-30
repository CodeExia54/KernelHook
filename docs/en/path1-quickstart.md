# Path 1 Quickstart — Rooted Device Install

Prerequisite: device is already rooted (Magisk / KernelSU / APatch / etc.) so that `su 0` works in `adb shell`.

## Steps

1. **Pull your kernel image** so `khtools` can inspect it:
   ```sh
   adb shell "su 0 sh -c 'cat /dev/block/by-name/boot'" > boot.img
   ```

2. **Build the SDK + the consumers you want**, in fat-link mode:
   ```sh
   make -C kmod module KH_FAT_LINK=1 KH_MODULES=apd,khm,supercall
   ```

3. **Finalize fat.ko for your target kernel** (PC-side):
   ```sh
   khtools finalize \
       --image boot.img \
       --in    kmod/kernelhook.ko \
       --out   fat.ko \
       [--graft-host vendor_host.ko]   # only if probe says kCFI initcall typeid present
   ```

4. **Build the device-side loader** for Android arm64:
   ```sh
   cmake -B build_android \
       -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
       -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 \
       -DCMAKE_BUILD_TYPE=Release
   cmake --build build_android --target khinsmod khctl
   ```

5. **Push and load**:
   ```sh
   adb push fat.ko build_android/khinsmod/khinsmod build_android/khctl/khctl /data/local/tmp/
   adb shell "su 0 sh -c '/data/local/tmp/khinsmod /data/local/tmp/fat.ko'"
   ```

6. **Verify** via `khctl`:
   ```sh
   adb shell "su 0 sh -c '/data/local/tmp/khctl status'"
   adb shell "su 0 sh -c '/data/local/tmp/khctl version'"
   ```

   On success the console (or the sysfs `status` node) shows the SDK version + each consumer's init marker.

## Optional: KernelSU integration

Pin a KernelSU LKM that matches your GKI tag (see `khtools/fixtures/ksu_lkm/MANIFEST.txt`), then:

```sh
adb push kernelsu.ko /data/local/tmp/
adb shell "su 0 sh -c '/data/local/tmp/khinsmod /data/local/tmp/fat.ko --ksu /data/local/tmp/kernelsu.ko'"
```

`khinsmod` writes the KSU bytes into `/sys/kernel/kh/pending_ksu`; fat.ko's `try_load_ksu()` reads them and calls `load_module()` directly, so no separate `insmod` is needed.

## Troubleshooting

- **`finit_module: ENOEXEC`** — the on-disk `__versions` CRCs don't match the running kernel. Either rebuild fat.ko from a kernel image that exactly matches the device, or wait for the `khtools finalize` CRC walker follow-up (Task 2.2 follow-up tracked in the foundation plan).
- **`disagrees about version of symbol module_layout`** — same root cause as above.
- **`khinsmod` rc=8** — fat.ko was built for a different kernel; pass `--force` if you're sure or rebuild for this kernel.
- **`khinsmod` rc=7 with "—ksu request was NOT honored"** — fat.ko loaded but `/sys/kernel/kh/pending_ksu` isn't there yet (Task 5.3 wiring not landed).

## See also

- [khtools reference](khtools.md)
- [Path 2 (boot.img patch)](path2-bootpatch.md)
- [Build Modes](build-modes.md) (fat-link section)
