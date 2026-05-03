# kmod/loader — KernelHook 模块加载基元 / KernelHook module-loading primitives

> **状态 / Status:** 子集移植 (subset port)。这里只交付 ARM64 ELF 重定位的可重用基元 (`insn` + `relo`)，**没有**端到端的 `kh_load_module()`。详见 `BLOCKER.md`。
>
> **Status:** subset port — only the AArch64 ELF relocation primitives (`insn` + `relo`) are shipped here. There is **no** end-to-end `kh_load_module()`. See `BLOCKER.md` for the rationale.

---

## 中文 / Chinese

### 这是什么 / What this is

从 KernelPatch (`third_party/KernelPatch/kernel/patch/module/{insn,relo,module}.c`) 移植的子集，移植对象是**纯函数性**的两块：

- `kh_aarch64_insn_encode_immediate` — 把任意立即数塞进 AArch64 32 位指令字的指定子字段（ADR / 12 位 / 16 位 / 19 位 / 21 位 / 26 位 等）。
- `kh_apply_relocate{,_add}` — 走一遍 ELF64 RELA section，对每个 `R_AARCH64_*` 重定位类型做对应的写。

这两块在 khimg freestanding（无 libc、无内核 header）和 kmod fat.ko 实模块（freestanding shim）和 host 单元测试里**用同一份 .c 编译**。

### 为什么不是完整的 `kh_load_module()`

简而言之：KP 的 `module.c` 是 KernelPatch Module 加载器（要求 `.kpm.init` / `.kpm.exit` 自定义 section），不是普通 LKM `.ko` 加载器。直接搬过来既不能加载 KSU LKM，也不能在 khimg freestanding 阶段分配可执行内存。

完整理由见 `BLOCKER.md`。

### 怎么用 / How callers use this

```c
#include "../../kmod/loader/kh_loader.h"

/* 调用方负责：
 *   1. ELF header check
 *   2. 把每个 SHF_ALLOC section 移到运行时地址，回填 sechdrs[i].sh_addr
 *   3. 走完 SHN_UNDEF 符号查表，把内核地址写进 sym->st_value
 *   4. 对每个 SHT_RELA section 调下面这个函数 */
int rc = kh_apply_relocate_add((struct kh_elf64_shdr *)sechdrs, strtab,
                               symtab_idx, rela_section_idx);
if (rc < 0) {
    /* rc == -8 : overflow ; rc == -22 : 不支持的 RELA 类型 */
}
```

调用方还**没有**：

- `khimg/src/kh_load.c` — path-2 boot 阶段；当前调 `init_module(...)` 的代码不变。
- `kmod/src/ksu_load.c` — path-1 fat.ko；当前调 `load_module(...)` 的代码不变。

未来如果要把这两个调用换成 `kh_load_module()`，需要先按 `BLOCKER.md` §2 选定方向并实现剩下的 90% 工作（layout / move / 符号解析 / vermagic / ksymtab / kCFI / PLT 等等），不在本次提交范围内。

### 单元测试 / Unit test

`tests/test_loader.c` 是 host-side ctest：
- 验证 `kh_aarch64_insn_encode_immediate` 的几个关键 case（IMM_12 / IMM_19 / IMM_26 / IMM_ADR）。
- 构造一个最小的 RELA fixture，调用 `kh_apply_relocate_add`，验写出来的字节正确。

构建：

```bash
cd /Users/bmax/workspace/github/KernelHook
cmake -S . -B build_debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build_debug --target kh_loader_tests
ctest --test-dir build_debug -R kh_loader -V
```

---

## English

### What this is

A pure-function subset ported from KernelPatch's
`kernel/patch/module/{insn,relo,module}.c`:

- `kh_aarch64_insn_encode_immediate` — encode an immediate into an
  AArch64 32-bit instruction's sub-field (ADR / 12 / 16 / 19 / 21 / 26 / etc).
- `kh_apply_relocate{,_add}` — iterate an ELF64 RELA section, applying
  every `R_AARCH64_*` relocation.

Both compile from the same `.c` source in three environments:
khimg freestanding, fat.ko shim, and host ctest.

### Why no end-to-end `kh_load_module()`

KP's `module.c` is a KPM (KernelPatch-Module) loader — it requires
custom `.kpm.init` / `.kpm.exit` sections and KP-specific entry/exit
function signatures. It cannot load a real Linux LKM (no vermagic, no
`__versions`, no `__ksymtab*`, no kCFI typeid stamping, no PLT). It
also cannot allocate executable memory in the khimg freestanding
context (no `kp_rox_mem` initialization). See `BLOCKER.md` for the
full breakdown and recommended forward paths.

### Existing callers stay on `init_module` / `load_module`

This port does **not** modify:

- `khimg/src/kh_load.c` (path-2 boot, calls `init_module` via kallsyms)
- `kmod/src/ksu_load.c` (path-1 fat.ko, calls `load_module` via kallsyms)

A future end-to-end loader can land at the `kh_load_module(...)`
declaration reserved in `kh_loader.h` without churning these callers
again.

### Build

The `.c` files build standalone via host CMake (see top-level
`CMakeLists.txt` `kh_loader_tests` target — added in this PR). For
the freestanding khimg and fat.ko paths, they are added to the
respective Makefiles only when a future end-to-end loader actually
needs them; today they are not linked into either binary because the
existing `init_module` / `load_module` callers don't use them.
