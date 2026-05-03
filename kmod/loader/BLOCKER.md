# kh_loader BLOCKER 报告 / BLOCKER report

> **TL;DR (中文):** KernelPatch 的 `module.c` 是 KPM (KernelPatch Module) 加载器，不是普通 LKM `.ko` 加载器。直接照搬过来既不能在 khimg freestanding 环境分配可执行内存，也不能加载真正的 KernelSU LKM。两边的 `init_module` / `load_module` 调用因此**保留不动**。本目录只交付了可重用的 ARM64 ELF 重定位基础（`insn` + `relo`），并把后续 end-to-end loader 的接口在 `kh_loader.h` 占位。

> **TL;DR (English):** KernelPatch's `module.c` is a KPM (KernelPatch Module) loader, not a generic LKM `.ko` loader. Porting it verbatim would (a) be unable to allocate executable memory in the khimg freestanding context and (b) be unable to load real KernelSU LKMs. The existing `init_module` / `load_module` call sites in `khimg/src/kh_load.c` and `kmod/src/ksu_load.c` are therefore **not changed**. This directory ships the reusable AArch64 ELF relocation primitives (`insn` + `relo`) and reserves the API surface in `kh_loader.h` for a future end-to-end loader.

---

## 1. 为什么不直接把 KP `module.c` 搬过来 / Why we did not lift KP `module.c`

### 1.1 KP 的 loader 是 KPM-only / KP's loader is KPM-only

`third_party/KernelPatch/kernel/patch/module/module.c` 在 `setup_load_info()`（第 327 行附近）做硬性检查：

```c
if (!find_sec(info, ".kpm.init") || !find_sec(info, ".kpm.exit")) {
    logke("no .kpm.init or .kpm.exit section\n");
    return -ENOEXEC;
}
```

KPM 的入口/出口靠**自定义 section** `.kpm.init` / `.kpm.exit` 提供，签名是 KP 自定义的 `mod_initcall_t / mod_exitcall_t`。普通 Linux LKM（包括 KernelSU 的 `kernelsu.ko`）使用的是 `__init_array` / `__init_calls` / `module_init()` 注册 + `__this_module` 自描述结构 + `__ksymtab*` 符号表 + `__versions` CRC 表。这两套机制完全不重合，KP loader 拒绝普通 `.ko` 是设计就是这样。

### 1.2 真正加载 GKI `.ko` 还需要的东西 / What real GKI `.ko` loading actually needs

下面这些 KP `module.c` **完全不处理**：

| 必需项 | KP 处理? | KernelHook 现状 |
|--------|----------|-----------------|
| `vermagic` 校验跳过/绕过 | ❌ | `tools/kmod_loader` 里已有 strategy |
| `__versions` (`MODVERSIONS`) CRC | ❌ | `kmod/exports.manifest` + `KH_DECLARE_VERSIONS` 已处理 |
| `__ksymtab*` / `__kcrctab*` 多变体 (prel32 / abs64 / abs64_legacy / abs64_legacy_u32) | ❌ | `kmod/Makefile::module-dual` 产 4 个变体；`kmod_loader` 选 |
| kCFI typeid hash 修补（`__kcfi_typeid_init_module`） | ❌ | `tools/kmod_loader/strategies/probe_binary.c` 抓 hash，`graft_vendor_ko` 注入 |
| PLT (跨 ±128MB 跳转) 动态生成 | ❌ | `kmod/plt/` 已实现 |
| `mod_arch_specific` (PLT count, etc.) | ❌ | 同上 |
| `__init_array` / `init_module()` ELF entry pickup | ❌ (KP 只看 `.kpm.init`) | 内核自己处理 |
| `__exitcall_*` 注册 | ❌ | 内核自己处理 |
| kernel 自带的 `module` 结构填充 (`mod->core_layout`, `mod->state`, list-add 进 `modules`) | ❌ (KP 维护自己的 `modules` 链表) | 内核自己处理 |
| `find_module()` 重复检测 走内核全局表 | ❌ (KP 只看自己链表) | 内核自己处理 |
| RCU + module ref 计数 | ❌ | 内核自己处理 |

KP 的 ~2255 行只覆盖了 `setup_load_info` + `layout_sections` + `move_module` + `simplify_symbols` + `apply_relocations`，**全部针对 KPM-only 的简化对象模型**。把它完整移过来再加上以上每一项，就是从头实现一个 `kernel/module.c` —— 是 5–10k 行级别的工作，**远超** prompt 里 "~2255 lines" 的预估。

### 1.3 khimg 阶段还有内存问题 / khimg has the alloc problem too

KP 在 `move_module()` 里调 `kp_malloc_exec(mod->size)`，依赖 `kp_rox_mem` tlsf 池子已被早期 boot 代码用一段 RWX 物理页初始化过。当前 `khimg/`：

- `khimg/src/start.c` 里 `start()` 直接调 `khimg_main()` 然后返回，khimg 阶段只跑这么一次。
- 全工程 grep 不到任何 `tlsf_create_with_pool` 调用，`kp_rox_mem` / `kp_rw_mem` 没有初始化的代码路径。
- 即使初始化了，也得有"哪段物理内存可分配且 RWX"的早期页表设置，目前 `khimg/src/map.c` 不做这件事。

也就是说，把 KP 的 `move_module` 拉过来，第一次 `kp_malloc_exec` 就是 NULL；进一步 fix 要做一段 paging-init 期间预留 RWX 的工作，那是另一个完整的子项目。

### 1.4 现有 graft 路径已经走通 / The graft path already works

memory note `project_pivot_graft.md` 记录了：
> 2026-04-22：Pixel_35 (android15 6.6.30) 完整 KernelHook + hello_hook 成功 hook do_sys_open。graft_vendor_ko + kCFI hash stamp + kallsyms_addr 注入 + payload 保留 __ksymtab。

说明 `tools/kmod_loader` + `graft_vendor_ko` 链路在 GKI 6.6 上已经能加载真正的 LKM。引入 KP 的简化 KPM loader **不会改善**这条链路，反而会引入两条平行实现。

---

## 2. 替代方案：未来如果真要做 in-kernel `.ko` loader / Alternative path forward

如果将来确实需要"在内核态拿到一段 byte buffer 就能加载普通 `.ko`"的能力（比如 path-2 boot 路径下 `init_module` 因 `copy_from_user` 失败的场景），正确方向不是把 KP 的 KPM loader 扩成 LKM loader，而是：

**选项 A — 走 user-buffer 临时映射:**

khimg 期/fat.ko 期把 fat.ko 的 bytes 拷到一段用户态可见的临时 vma（比如 `vm_mmap` + `copy_to_user` 反向逆用），然后正常调 `__do_sys_init_module`。这条路不需要复刻 LKM loader，只需要解决"如何在内核里搞出一段 user mapping"。

**选项 B — 直接走内核 `load_module()` + 构造 `struct load_info`:**

`kernel/module.c::load_module()` (static) 接受 `struct load_info`，里面是 kernel 指针。从 GKI 5.0+ 起这个签名稳定。kallsyms 拿到 `load_module` 地址后，在 kernel 侧自己构造 `load_info`（其实就是把 `setup_load_info` 那段做完）然后调进去。这跳过了 `__do_sys_init_module` 的 `copy_from_user`。

工作量估计：~600-800 行（不需要重新发明 layout/move/relocate，因为这些是 kernel 自己做的），主要是 `setup_load_info` 等价物。

**选项 C — 扩 `tools/kmod_loader` strategy 系统:**

继续走 graft 路径，把"生成可加载 .ko" 的工作搬到 PC 端 `khtools` 完成（这本来就是 plan 里 §3.x 写的方向）。device-side 不再需要任何 in-kernel loader。

---

## 3. 当前交付 / What this directory ships

| 文件 | 行数 | 说明 |
|------|------|------|
| `kh_loader.h` | ~140 | 公开 API 头：`kh_aarch64_insn_encode_immediate`, `kh_apply_relocate{,_add}`，外加 `kh_load_module` 占位（intentional link-fail） |
| `kh_loader_insn.c` | ~110 | KP `insn.c` 的 immediate-encoder 子集移植 |
| `kh_loader_relo.c` | ~280 | KP `relo.c` 完整移植，去 KP-deps，内置 R_AARCH64_* 常量 |
| `tests/test_loader.c` | (见目录) | host ctest，验 immediate encoding + 一个小 RELA 重定位 |
| `BLOCKER.md` | 本文件 | 解释为什么没有 end-to-end loader |
| `README.md` | (见目录) | 用户向的快速上手 |

**编译契约 / Build contract:**
- `kh_loader_insn.c` / `kh_loader_relo.c` 在 khimg / kmod / host ctest 三个环境下都应该编译通过。
- 不依赖 `<linux/elf.h>`（自带 `kh_elf64_*` 类型）、不依赖 `<linux/string.h>`、不调任何 allocator / kallsyms。
- 调用方负责把 SHN_UNDEF 的符号在传入前替换成 runtime 地址。

---

## 4. 给后来者的提示 / Notes for follow-up work

如果你要继续推进 in-kernel `.ko` loader，**先读 memory `project_pivot_graft.md` 和 `tools/kmod_loader/strategies/`**。那里已经有大量真正的 GKI 4.4–6.12 LKM 加载经验，包括：

- 4 种 ksymtab 布局的运行时检测和选择
- kCFI hash 在不同 build 之间的自动 stamp
- PLT 表的动态生成（覆盖 `±128MB` 之外的 BL 跳转）
- vermagic / __versions / kallsyms_addr 的注入
- `do_init_module` panic 在不同 Pixel 设备上的手段差异

任何重新发明轮子的尝试都需要先复现这些工作。**把 KP `module.c` 直接移过来不能跳过这些**——它本来就没解决任何一个。
