# KernelHook

> ⚠️ 探索开发阶段，接口随时变更，**请勿用于生产**。
> Active development; APIs unstable; **not for production.**

面向 Linux 内核的 ARM64 函数 kh_hook 框架。

## 功能特性

- **内联 kh_hook** —— 替换任意内核函数，通过备份指针调用原函数
- **Hook 链** —— 同一函数注册多个 before/after 回调，按优先级有序执行
- **系统调用级 kh_hook** —— `kh_hook_syscalln(nr, …)` 通过 `__arm64_sys_<name>` 操作，处理 pt_regs 包装器 ABI；[用户指针辅助](docs/zh/api-reference.md#用户指针辅助)（`kh_strncpy_from_user`、`kh_copy_to_user_stack`）支持改写 syscall 参数
- **Alias-page 写入** —— vmalloc alias + `aarch64_insn_patch_text_nosync`（KernelPatch 风格），绕过 `__ro_after_init` + kCFI；PTE 直改作为 fallback
- **RCU 安全调度** —— 进入原函数前把链状态 snapshot 到栈；3 秒内 2780 万次 syscall × 67000 次 add/remove 并发压测零 Oops
- **自适应加载器** —— `kmod_loader` 修补 .ko 二进制；通过实时内核探测自动挑选 ksymtab 布局（`prel32` / `abs64` / `abs64-legacy` / `abs64-legacy-u32`）
- **Vendor-ko graft** —— 将 KernelHook payload 嵌入 vendor .ko，绕过 Android 15+ GKI 的 kCFI initcall typeid 检查
- **主打 demo** —— [`kh_root`](docs/zh/kh-root-demo.md)：3 个 syscall kh_hook 完整提权（~350 LOC）

## 内核兼容性

已在 AVD 模拟器（Pixel_28..Pixel_37）+ Pixel USB 真机验证：

| 内核版本   | Android | API     | 路径                                       |
|-----------|---------|---------|--------------------------------------------|
| 4.4–4.14  | 9–10    | 28–29   | kmod，`abs64-legacy[-u32]`，`-mcmodel=large` |
| 5.4–5.15  | 11–13   | 30–33   | kmod，`abs64` / `prel32`，shadow-CFI       |
| 6.1       | 14      | 34      | kmod，`prel32`，kCFI                       |
| 6.6+      | 15/16   | 35–37   | vendor-ko graft（kCFI initcall typeid）   |

`kmod_loader` 在设备上解析 vendor .ko 自动选择布局；真机与 AVD 共用同一路径。

> **注意**：AVD 覆盖范围按 GKI 镜像版本钉死（如 Pixel_34 = 6.1.23-android14-4）。真机如果跑的是更新的 6.1 sub-version（如 Pixel 6 / 6.1.99-android14-11），即便主次版本号还叫 6.1，也已带上 Android 15+ 的 kCFI initcall 检查，需要走 graft 路径。

## 安装路径

KernelHook 通过两条路径达到同一终态——kernel 加载 fat.ko payload，对外暴露 consumer 模块（apd / khm / supercall）以及可选的 KernelSU 集成。

| | 路径 1（已 root 设备） | 路径 2（boot.img 修补） |
|---|---|---|
| 前置条件 | 已有 root 权限 | bootloader 已解锁 |
| PC 工具 | `khtools finalize` | `khtools patch` |
| 设备端工具 | `khinsmod fat.ko` | （开机自动加载） |
| KSU 集成 | `khinsmod fat.ko --ksu ksu.ko` | `khtools patch --ksu-lkm ksu.ko ...` |

详见 [docs/zh/path1-quickstart.md](docs/zh/path1-quickstart.md) 和 [docs/zh/path2-bootpatch.md](docs/zh/path2-bootpatch.md)。PC 构建工具命令参考：[docs/zh/khtools.md](docs/zh/khtools.md)。

## 文档

- [快速上手](docs/zh/getting-started.md) · [API 参考](docs/zh/api-reference.md) · [kh_root Demo](docs/zh/kh-root-demo.md)
- [构建模式](docs/zh/build-modes.md) · [kmod_loader](docs/zh/kmod-loader.md) · [AVD 测试](docs/zh/avd-testing.md) · [示例](docs/zh/examples.md)
- [khtools (PC 构建工具)](docs/zh/khtools.md) · [路径 1 快速上手](docs/zh/path1-quickstart.md) · [路径 2 boot.img 修补](docs/zh/path2-bootpatch.md)
- [English](README.md)

## 构建与测试

```bash
# SDK 基座 + 示例 consumer
make -C kmod module
make -C examples/hello_hook module

# 宿主单元测试
cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug && cmake --build build_debug
ctest --test-dir build_debug

# 全量 AVD 回归（Pixel_28..34 kmod + Pixel_35..37 graft）
./scripts/test.sh avd-sdk-all
# 或指定子集：./scripts/test_avd_kmod.sh Pixel_31 Pixel_34
```

三种构建模式 —— SDK（默认，共享 `kernelhook.ko`）、Freestanding（目标无 `kernelhook.ko`）、Kbuild（仅演示）。详见 [build-modes.md](docs/zh/build-modes.md)。

## 贡献指南

文件头约定见 [`docs/style/file-header.md`](docs/style/file-header.md)；公共 API 命名空间（`kh_` 前缀）由 `scripts/lint_exports.sh` 守门（已接入 `scripts/test.sh sdk-consumer`）。

## 许可证

GPL-2.0-or-later
