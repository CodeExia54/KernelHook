# 路径 1 快速上手——已 root 设备

前置条件：设备已 root（Magisk / KernelSU / APatch 等），`adb shell` 里 `su 0` 可用。

## 步骤

1. **拉取设备 boot 镜像**，给 `khtools` 分析：
   ```sh
   adb shell "su 0 sh -c 'cat /dev/block/by-name/boot'" > boot.img
   ```

2. **构建 SDK + 选定 consumer**（fat-link 模式）：
   ```sh
   make -C kmod module KH_FAT_LINK=1 KH_MODULES=apd,khm,supercall
   ```

3. **PC 端 finalize fat.ko 以适配目标内核**：
   ```sh
   khtools finalize \
       --image boot.img \
       --in    kmod/kernelhook.ko \
       --out   fat.ko \
       [--graft-host vendor_host.ko]   # 仅当 probe 报告 kCFI initcall typeid 存在时
   ```

4. **构建 Android arm64 设备端工具**：
   ```sh
   cmake -B build_android \
       -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
       -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-30 \
       -DCMAKE_BUILD_TYPE=Release
   cmake --build build_android --target khinsmod khctl
   ```

5. **推送并加载**：
   ```sh
   adb push fat.ko build_android/khinsmod/khinsmod build_android/khctl/khctl /data/local/tmp/
   adb shell "su 0 sh -c '/data/local/tmp/khinsmod /data/local/tmp/fat.ko'"
   ```

6. **用 `khctl` 验证**：
   ```sh
   adb shell "su 0 sh -c '/data/local/tmp/khctl status'"
   adb shell "su 0 sh -c '/data/local/tmp/khctl version'"
   ```

   成功时控制台（或 sysfs `status` 节点）会显示 SDK 版本 + 各 consumer 的 init marker。

## 可选：KernelSU 集成

按 GKI tag 钉一个 KernelSU LKM（参见 `khtools/fixtures/ksu_lkm/MANIFEST.txt`），然后：

```sh
adb push kernelsu.ko /data/local/tmp/
adb shell "su 0 sh -c '/data/local/tmp/khinsmod /data/local/tmp/fat.ko --ksu /data/local/tmp/kernelsu.ko'"
```

`khinsmod` 把 KSU 字节写到 `/sys/kernel/kh/pending_ksu`；fat.ko 的 `try_load_ksu()` 读取后直接调用 `load_module()`，不再需要单独 `insmod`。

## 排错

- **`finit_module: ENOEXEC`**——磁盘上 `__versions` CRC 跟运行中 kernel 不匹配。要么用真正匹配设备的 kernel image 重新 build fat.ko，要么等 `khtools finalize` 的 CRC 扫描后续提交（基础设施 plan 里 Task 2.2 follow-up 跟踪）。
- **`disagrees about version of symbol module_layout`**——根因同上。
- **`khinsmod` rc=8**——fat.ko 是为另一个内核 build 的；如果你确定可以加 `--force`，否则重 build。
- **`khinsmod` rc=7 报 "—ksu request was NOT honored"**——fat.ko 加载了但 `/sys/kernel/kh/pending_ksu` 还不存在（Task 5.3 sysfs 接线还没落地）。

## 参考

- [khtools 命令参考](khtools.md)
- [路径 2（boot.img 修补）](path2-bootpatch.md)
- [构建模式](build-modes.md)（fat-link 章节）
