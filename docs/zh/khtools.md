# khtools — KernelHook PC 构建工具

`khtools` 是宿主侧 CLI，针对指定目标内核适配 KernelHook 负载 (`fat.ko`)，并按所选安装路径打包。

> **说明**：本文档对应基础设施第 4 阶段。`finalize`、`patch`、`verify` 这几个子命令依赖 `<elf.h>`；在 macOS 上会返回 stub 错误，需要在 Linux 主机或 NDK 目标上构建。

## 子命令

| 子命令 | 用途 |
|---|---|
| `probe`     | 探测内核镜像属性（ksymtab variant、kCFI 模式、banner） |
| `dump-syms` | 打印从内核镜像解析出的 kallsyms |
| `finalize`  | 针对目标镜像适配一份 `fat.ko`（路径 1） |
| `patch`     | 用 `khimg` + `fat.ko` 修补 `boot.img`（路径 2） |
| `extract`   | 从 `boot.img` 中提取 `Image`（依赖 magiskboot） |
| `list`      | 检查 KernelHook 制品（fat.ko 或修补过的 kernel section） |
| `verify`    | CI 关卡——检查修补后 `boot.img` 的完整性 |

## 用法示例

```sh
# 探测一个内核镜像
khtools probe --image boot.img

# Dump kallsyms（用于离线符号查找）
khtools dump-syms --image boot.img | head

# 路径 1 安装：针对目标内核 finalize fat.ko
khtools finalize \
    --image boot.img \
    --in    kmod/kernelhook.ko \
    --out   fat.ko \
    [--graft-host vendor_host.ko]

# 路径 2 安装：修补 boot.img
khtools patch \
    --boot     boot.img \
    --in       fat.ko \
    --khimg    khimg/khimg \
    [--ksu-lkm ksu.ko] \
    --out      patched-boot.img

# 校验修补后的 boot.img 完整性
khtools verify --boot patched-boot.img

# 列出 fat.ko 静态链接进来的 consumer
khtools list --in kmod/kernelhook.ko
```

## 退出码

| 退出码 | 含义 |
|---|---|
| 0   | 成功 |
| 1   | 用法错误 / 未知子命令 |
| 2   | 参数校验 / I/O 失败 |
| 4   | 需要 graft 但未提供 graft host / graft 失败 |
| 5   | 外部工具（如 `magiskboot`）失败 |
| 6   | trailer 缺失或 SHA-256 不一致（仅 verify） |

## 依赖

- **magiskboot** 在 `PATH` 中——`extract`、`patch`、`verify` 用它处理 `boot.img` 的拆解打包。
- **`<elf.h>`**（构建时，Linux / NDK 提供）——`finalize`、`patch`、`verify`、`list` 的 ELF 检查路径需要它，macOS 宿主只编出 stub。

## 已知限制

- Kernel image 的 hook 注入（移植 KernelPatch `tools/patch.c::find_hook_offset`）**延后**。`khtools patch` 产出的 `boot.img` 自带合法 trailer，`khimg` 也能解析，但 kernel 的 setup 路径还没钩进 khimg，所以路径 2 的 end-to-end 在 hook 注入落地前跑不通。
- `khtools finalize` 的 CRC 表离线提取是 no-op stub；如果目标 kernel `CONFIG_MODVERSIONS=y` 并且 fat.ko 的 `__versions` 引用了符号，加载时可能因 "disagrees about version of symbol module_layout" 失败——等待后续提交补上真正的 `__kcrctab` 扫描。
