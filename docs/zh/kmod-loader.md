# kmod_loader -- 自适应模块加载器

> **说明（2026-04+）**：本文档描述的是**开发者模式加载器**。生产安装请走 `khtools finalize` + `khinsmod`（路径 1）或 `khtools patch`（路径 2），详见 [khtools.md](khtools.md)、[path1-quickstart.md](path1-quickstart.md) 和 [path2-bootpatch.md](path2-bootpatch.md)。`kmod_loader` 仍保留下来用于「不想在 PC 上做 finalize、只想运行时修补」的开发流程。

`kmod_loader` 是一个用户态工具，在加载时动态修补 freestanding `.ko` 二进制文件，使其适配当前运行内核的 ABI，实现跨内核版本加载，无需重新编译。

## 用法

```
kmod_loader <module.ko> [选项] [param=value ...]
```

`kallsyms_lookup_name` 由 loader 自动从 `/proc/kallsyms` 获取。loader 本身
必须以 root 运行（加载内核模块需要 `CAP_SYS_MODULE`），且内核要对 root 暴露
符号地址（`kptr_restrict <= 1`）。需要覆盖时显式追加 `kallsyms_addr=0xHEX`。

## 修补内容

| 字段 | 方式 |
|------|------|
| **vermagic** | 替换为当前内核的 `uname -r` + 标准后缀 |
| **CRC 值** | 修补 `__versions` 段中的 CRC，匹配 `module_layout`、`printk` 等符号 |
| **init/exit 偏移** | 调整 `.rela.gnu.linkonce.this_module` 中的重定位，匹配 `struct module` 布局 |
| **struct module 大小** | 调整 `.gnu.linkonce.this_module` 段大小 |
| **printk 符号名** | 自动检测 `_printk`（6.1+）或 `printk`（5.10），修改 `__versions` 和字符串表 |
| **kallsyms_addr** | 直接修补 ELF `.data` 段（绕过 `module_param` / shadow CFI 问题） |
| **this_module 段** | 修补前清零，防止 `ei_funcs`/`num_ei_funcs` 垃圾数据 |

## 命令行选项

| 选项 | 说明 |
|------|------|
| `kallsyms_addr=0xHEX` | 覆盖自动获取的 `kallsyms_lookup_name` 地址 |
| `--init-off 0xHEX` | 手动指定 `struct module` 中 init 函数的偏移 |
| `--exit-off 0xHEX` | 手动指定 `struct module` 中 exit 函数的偏移 |
| `--probe` | 强制重新探测 init/exit 偏移（忽略缓存） |
| `--crc sym=0xHEX` | 手动指定某个符号的 CRC（可重复使用） |
| `param=value` | 模块参数，透传给 `init_module` |

## init/exit 偏移解析策略

`kmod_loader` 采用分级策略查找 `struct module` 中正确的 `init` 和 `exit` 偏移：

1. **命令行指定** -- `--init-off` / `--exit-off` / `--mod-size` 优先级最高
2. **Vendor 模块内省** -- 读取设备上的 vendor `.ko` 文件，从 `.rela.gnu.linkonce.this_module` 重定位中提取实际的 `struct module` 大小和 init/exit 偏移。对物理设备（如 Pixel）最准确，因为 GKI 预设可能不匹配。搜索 `/vendor_dlkm/lib/modules`、`/vendor/lib/modules`、`/system/lib/modules`。
3. **版本预设** -- 已知 GKI 内核版本的硬编码偏移（已在 AVD 模拟器上验证）
4. **持久缓存** -- 之前探测的偏移存储在 `kmod_loader` 二进制自身中
5. **方法 A（kcore 反汇编）** -- 从 `/proc/kcore` 读取 `do_init_module`，扫描 `LDR X0, [Xn, #imm]; CBZ X0` 指令模式
6. **方法 B（二进制探测）** -- 内嵌一个最小的 `probe.ko`（init 返回 `-EINVAL`），在 0x100-0x200 范围内以步长 8 尝试各候选偏移。返回 `EINVAL` 表示 init 被调用，即偏移正确。支持崩溃恢复。

### 版本预设表

| 内核版本 | struct module 大小 | init 偏移 | exit 偏移 | 状态 |
|---------|-------------------|----------|----------|------|
| 4.4     | 0x340             | 0x158    | 0x2d0    | AVD 已验证 |
| 4.9     | 0x358             | 0x150    | 0x2e8    | 源码推算 |
| 4.14    | 0x370             | 0x150    | 0x2f8    | AVD 已验证 (init) |
| 4.19    | 0x390             | 0x168    | 0x318    | 源码推算 |
| 5.4     | 0x400             | 0x178    | 0x340    | AVD 已验证 |
| 5.10    | 0x440             | 0x190    | 0x3c8    | AVD 已验证 |
| 5.15    | 0x3c0             | 0x178    | 0x378    | AVD 已验证 |
| 6.1     | 0x400             | 0x140    | 0x3d8    | AVD 已验证 |
| 6.6     | 0x600             | 0x188    | 0x5b8    | AVD 已验证 |
| 6.12    | 0x640             | 0x188    | 0x5f8    | AVD 已验证 |

**注意：** 物理设备的偏移通常与 GKI AVD 不同（如 Pixel 6.1 使用 init=0x170/size=0x440，而 AVD 使用 init=0x140/size=0x400）。vendor 模块内省层会自动处理。

## CRC 解析顺序

CRC 值按以下顺序解析：

1. `--crc` 命令行参数
2. kallsyms 中的 `__crc_*` 符号（来自 `/proc/kallsyms`）
3. 设备上的厂商 `.ko` 文件（解析 `__versions` 段）
4. Boot 分区的内核镜像
5. `finit_module` 的 `MODULE_INIT_IGNORE_MODVERSIONS` 标志（如果内核支持）

## AVD 专用说明

Android 虚拟设备没有 `/proc/kcore` 和厂商 `.ko` 文件，CRC 需要使用 `extract_avd_crcs.py` 从宿主机的内核镜像中提取：

```bash
# 从 AVD 内核镜像提取 CRC（自动检测 ksymtab 格式）
CRC_ARGS=$(python3 scripts/extract_avd_crcs.py -s emulator-5554)

# 使用提取的 CRC 加载
adb shell "/data/local/tmp/kmod_loader /data/local/tmp/my_hook.ko \
    kallsyms_addr=0x... $CRC_ARGS"
```

CRC 提取工具支持三种 ksymtab 条目格式：
- **12 字节 prel32**（5.10+）—— 相对偏移条目
- **16 字节绝对指针**（4.x）—— `{ ulong value, const char *name }` + 4 或 8 字节 CRC
- **24 字节绝对指针+CFI**（5.4）—— `{ ulong value, const char *name, ulong cfi_type }` + 4 字节 CRC

对于未重定位的内核镜像（4.14 及更早版本），ksymtab 中的名称指针为零，工具会回退到使用 `/proc/kallsyms` 中的 `__ksymtab_<sym>` 地址计算 CRC 表索引。

## 构建

```bash
cd tools/kmod_loader
make              # 构建 kmod_loader（需要交叉编译器生成 aarch64 二进制）
make regenerate   # 重新生成内嵌的 probe.ko（仅当 probe.c 或工具链改变时需要）
```

`probe.ko` 在编译期通过 `probe_embed.h` 直接内嵌到 `kmod_loader` 二进制里
（由 `xxd -i` 生成并 commit 进仓库），所以**只需要 push `kmod_loader` 和你
自己的 `.ko`** 到设备，不需要单独推 `probe.ko`。运行时 Method B 偏移探测
会把内嵌的字节写入临时文件再 `finit_module` 加载。

`make regenerate` 只在你修改了 `probe.c` 或切换交叉编译器版本时才需要执行；
日常构建用不到。

## 示例

```bash
# 物理设备（Pixel 6，内核 6.1）— loader 自动获取 kallsyms_addr
adb push kmod_loader hello_hook.ko /data/local/tmp/
adb shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/hello_hook.ko'"

# AVD（内核 5.10）— CRC 由 host 端从内核镜像提取
CRC_ARGS=$(python3 scripts/extract_avd_crcs.py -s emulator-5554)
adb shell "su -c '/data/local/tmp/kmod_loader /data/local/tmp/hello_hook.ko $CRC_ARGS'"
```
