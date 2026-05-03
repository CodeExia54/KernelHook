# `/sys/kernel/kh/pending_ksu` 表面 BLOCKER 报告 / Surface BLOCKER report

> **TL;DR (中文):** path-1 KSU 注入入口 `/sys/kernel/kh/pending_ksu`（khinsmod 源码已经在写）当前**没有内核侧实现**。Foundation v1 计划里 Task 5.3 把它标 deferred，原因是 `struct bin_attribute` 在 GKI 5.10 / 6.1 / 6.6 三个布局之间字段重排（特别是 6.7 在 read 之前插了 `f_mapping`），freestanding shim 没有可移植的方式声明这个结构，写错一个 8 字节就会 corrupt 别人的 kobject。chrdev / procfs 替代路线撞同款 `struct file_operations` 跨版本字段重排问题。本会话决定**和 KP loader 一起 defer**，因为：（1）即使表面打通，`load_module_fn` 在 modern GKI 仍然 `-ENOEXEC`（subagent 的 `kmod/loader/BLOCKER.md` 已论证）；（2）path-1 KSU 真要落地走的是已有的 `tools/kmod_loader + graft` 路线，那条路无 sysfs 依赖。
>
> **TL;DR (English):** The path-1 KSU injection surface `/sys/kernel/kh/pending_ksu` (which `khinsmod --ksu` already writes) has **no kernel-side implementation**. Foundation v1 Task 5.3 marked it deferred because `struct bin_attribute` reorders fields across GKI 5.10 / 6.1 / 6.6 (notably 6.7 inserts `f_mapping` before `read`), and the freestanding shim has no portable way to declare it without a one-off-per-version layout file. chrdev / procfs alternatives hit the same `struct file_operations` cross-version reorder. We **defer alongside the KP loader port**, because (1) even with a working surface, `load_module_fn` returns `-ENOEXEC` on modern GKI (see `kmod/loader/BLOCKER.md`); (2) the production KSU path-1 flow uses the existing `tools/kmod_loader + graft` pipeline, which has no sysfs dependency.

---

## 1. 为什么不直接做 sysfs / Why not just implement sysfs

### 1.1 `struct bin_attribute` 的字段在 6.7 重排 / Field reorder in 6.7

`include/linux/sysfs.h` 在 v6.7 之前 / 之后 长这样：

```c
/* GKI 5.10 / 6.1 / 6.6 */
struct bin_attribute {
    struct attribute attr;          /* 16 bytes */
    size_t size;                    /* off 0x10 */
    void *private;                  /* off 0x18 */
    ssize_t (*read) (...);          /* off 0x20 */
    ssize_t (*write)(...);          /* off 0x28 */
    int     (*mmap) (...);          /* off 0x30 */
};

/* v6.7+ adds f_mapping before read */
struct bin_attribute {
    struct attribute attr;
    size_t size;
    void *private;
    struct address_space *(*f_mapping)(void);  /* NEW @ off 0x20 */
    ssize_t (*read) (...);          /* off 0x28 */
    ssize_t (*write)(...);          /* off 0x30 */
    int     (*mmap) (...);          /* off 0x38 */
};
```

矩阵覆盖范围里的 GKI 内核：

| AVD       | GKI tag         | bin_attribute layout |
|-----------|-----------------|----------------------|
| Pixel_31  | android12-5.10  | pre-6.7              |
| Pixel_33  | android13-5.15  | pre-6.7              |
| Pixel_34  | android14-6.1   | pre-6.7              |
| Pixel_35  | android15-6.6   | pre-6.7              |
| Pixel_36  | android15-6.6   | pre-6.7              |
| Pixel_37  | android16-6.12  | **post-6.7**         |

不是单一布局。如果用 pre-6.7 layout 注册到 6.12 内核，我们的 `read` 函数指针就被内核当成 `f_mapping` 调用 — 直接 panic。反过来同样烂。

### 1.2 kobj_attribute 文本表面绕不开 PAGE_SIZE / kobj_attribute is text-only and PAGE_SIZE-bounded

`struct kobj_attribute` 跨版本稳定，但它是 `show/store` 文本接口，单次 `store` 不能超过 `PAGE_SIZE`（4 KiB）。KernelSU v3.2.4 的 `kernelsu.ko` 是 600 KiB+，分块 store 需要 stateful 拼接 + 边界处理，再加上 mode rw 需要 root capability — 路径还是脆。

### 1.3 chrdev / procfs 撞同款问题 / chrdev and procfs hit the same wall

`register_chrdev(major, name, fops)` 要 `struct file_operations *`。`file_operations` 在 v5.10 / v6.0 / v6.1 / v6.5 / v6.7 都有字段增删（`iopoll`、`iterate_shared` → `iterate_dir`、`uring_cmd` 等）。同款字段重排，同款 panic 风险。

`miscdevice` 内部还是要 `file_operations`，绕不开。

`proc_create_data(name, mode, parent, fops)` v5.6 起 fops 改成 `proc_ops`，v6.x 又加了字段；同款问题。

---

## 2. 即使做对表面，下游也断 / Even with a perfect surface, the downstream is broken

`kmod/src/ksu_load.c::do_load_ksu_now` 用：

```c
load_module_fn = (load_module_fn_t)kh_resolve_ksym("load_module");
rc = load_module_fn(kh_pending_ksu_blob.data, kh_pending_ksu_blob.len, "");
```

按 `kmod/loader/BLOCKER.md` §1：modern GKI 的 `load_module()` 是 `kernel/module/main.c` 里的 static 函数，签名是 `int load_module(struct load_info *info, const char __user *uargs, int flags)`，**不接 raw bytes**。即便 kallsyms 里碰巧有它（现代 GKI 通常没有），调过去也会因为 `info` 是 NULL pointer 立刻挂掉。

`__do_sys_init_module` 接 raw bytes 但里面 `copy_from_user` 强制把指针当 user pointer，传 kernel 指针返回 `-EFAULT`。

所以 path-1 KSU **真的能加载** 需要先 ship `kh_load_module()`（subagent 已经把接口占位 + 把 insn / relo 基元 ship 出来）。在那之前给 surface 等于：

- userspace 写入成功
- 内核 stash 到 `kh_pending_ksu_blob.{data, len}`
- `try_load_ksu()` 调过 `load_module_fn` 拿到非零 rc
- 在 dmesg 打 "load_module rc=-X"，KSU 没起来

这 surface 对 user 没意义，对 dev 等于多一个没用 plumbing。

---

## 3. 现状下 path-1 KSU 怎么走 / What path-1 KSU actually uses today

production 流程（已工作）：

1. **用户态**：把 KSU LKM 文件路径作为参数传 khinsmod (`khinsmod fat.ko --ksu kernelsu.ko`)
2. **khinsmod**：现在 fail-fast — `open("/sys/kernel/kh/pending_ksu")` 返回 `-ENOENT`，打 "fat.ko loaded but --ksu request was NOT honored"，rc=7
3. **真正加载 KSU 的路径**：用 `tools/kmod_loader` 在 userspace 做 ELF 重定位 + ksymtab 解析 + finit_module(2) 走 user pointer。这条路 path-1 graft 链已经验证 (`memory project_pivot_graft.md`)。

khinsmod `--ksu` 参数现在是一个**前向声明**，等 `kh_load_module()` ship 后才会真正连通。

---

## 4. 解锁条件 / Unblock prerequisites

- **必要条件**：subagent 写的 `kh_loader_insn` + `kh_loader_relo` 之上做出真正的 `kh_load_module(buf, len, args, ops)`。这个工作单独成 PR，估算 600–800 行（详见 `kmod/loader/BLOCKER.md` §2 选项 B）。
- **充分条件 + 可选项**：选 sysfs / chrdev / procfs 中的一条，外加每个目标 GKI 版本的 layout shim。最简单的路径：写一个 `kobject_create_and_add` + 自维护 cdev minor + 一段 stateful 拼接 buffer 接收分段 write。条件分支按 `init_uts_ns.name.release`（kallsyms 拿到 `init_uts_ns` 里 utsname 字段）的 major.minor 派发 layout。

整套估算 ~400–500 行新代码 + 每个内核 minor 一份 `bin_attribute` layout 表。**这个工作只在第一个条件满足后才有意义**。

---

## 5. 本会话的决定 / This session's decision

不写一段会按错版本踩 kobject 内存的"看起来工作的" sysfs。把 BLOCKER 写下来 + 标 deferred。后续 PR 顺序应该是：

1. ship `kh_load_module()`（依赖现有 `tools/kmod_loader` 能力 in-kernel 化 — 不是再港 KP 的 module.c）
2. 然后 ship 多版本 `struct bin_attribute` shim + sysfs 注册
3. 把 khinsmod `--ksu` 的失败码从 7 → 0（成功路径打通）

每个都是独立 PR。Foundation v1 不卡这个。

---

## 6. 参考 / References

- `docs/superpowers/specs/2026-04-30-khtools-khimg-design.md` §5 (sysfs ABI 设计原意)
- `docs/superpowers/plans/2026-04-30-khtools-khimg-foundation.md` §Task 5.3 (deferred reason)
- `kmod/loader/BLOCKER.md` (loader port 的 BLOCKER — 同源问题)
- `kmod/include/kernelhook/kh_ksu_load.h` (try_load_ksu 接口)
- `khinsmod/src/main.c:140-149` (userspace 失败处理)
