# 路径 2 —— boot.img 修补

前置条件：bootloader 已解锁（`fastboot oem unlock` 或厂商对应命令）。**不需要** root——修补过的 `boot.img` 在开机时把一切自动起来。

> ⚠️ **状态**：基础设施阶段路径 2 **暂时还跑不完整**。`khtools patch` 能产出带合法 trailer 的 `boot.img`，但 kernel 侧的 hook 注入（移植 KernelPatch `tools/patch.c::find_hook_offset`）是一个延后跟进项。在它落地之前，修补后的 image 正常开机但会忽略 trailer。当前实际可用走路径 1。

## 步骤

1. **拉取出厂 boot.img**（或从 OEM image 中解出）：
   ```sh
   adb reboot bootloader
   fastboot getvar current-slot   # 比如 'a' 或 'b'
   fastboot fetch boot_a:boot.img boot.img
   ```

2. **构建所有 PC 侧制品**：
   ```sh
   # 宿主 CMake build（khtools）
   cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug
   cmake --build build_debug --target khtools

   # fat.ko + consumers
   make -C kmod module KH_FAT_LINK=1 KH_MODULES=apd,khm,supercall

   # khimg freestanding blob
   make -C khimg
   ```

3. **可选：预先 finalize fat.ko**——同路径 1 第 3 步。如果让 `khtools patch` 嵌入未 finalize 的 SDK 基底也行（in-flight finalize 的接线放在 follow-up）。

4. **修补 boot.img**：
   ```sh
   khtools patch \
       --boot     boot.img \
       --in       fat.ko \
       --khimg    khimg/khimg \
       [--ksu-lkm kernelsu.ko] \
       --out      patched-boot.img
   ```

5. **校验 trailer**：
   ```sh
   khtools verify --boot patched-boot.img
   # 输出 "OK" 以及 trailer offset、fat.ko 字节数、ksu.ko 字节数
   ```

6. **刷入**（fastboot）：
   ```sh
   fastboot flash boot patched-boot.img
   fastboot reboot
   ```

7. **设备端验证**——hook 注入 follow-up 落地后，控制台（`adb shell dmesg | grep "kh:"`）会先看到 `kh: khimg:` 的早期 boot marker，随后是 SDK 的 init + consumer marker。

## 不变量：开机不变砖

如果 trailer 损坏（magic 错、SHA-256 不匹配），`khimg` 入口会提前 return，kernel 正常继续启动。测试计划里端到端验证这一点（Task 4.3，延后）。任何时候都可以 `fastboot flash boot boot.img` 把原始镜像刷回去。

## 参考

- [khtools 命令参考](khtools.md)
- [路径 1（已 root 设备）](path1-quickstart.md)
- [架构](architecture.md)
