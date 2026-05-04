# ACD Matrix Run — 2026-05-04

Run via `scripts/matrix_acd.sh` against the local AVD pool, skipping
`Pixel_27` (pre-arm64) and `Pixel_36_1` (held by the kp-df parallel
rig).

## A) `khtools patch-image` — 9/9 PASS

| AVD       | Stock kernel       | Patched output |
|-----------|--------------------|----------------|
| Pixel_28  | android-28 / 4.4   | 15.2 MB ✓      |
| Pixel_29  | android-29 / 4.14  | 14.4 MB ✓      |
| Pixel_30  | android-30 / 5.4   | 26.2 MB ✓      |
| Pixel_31  | android-31 / 5.10  | 47.1 MB ✓      |
| Pixel_32  | android-32 / 5.10  | 47.1 MB ✓      |
| Pixel_33  | android-33 / 5.15  | 44.8 MB ✓      |
| Pixel_34  | android-34 / 6.1   | 30.3 MB ✓      |
| Pixel_35  | android-35 / 6.6   | 34.8 MB ✓      |
| Pixel_37  | android-37 / 6.12  | 39.8 MB ✓      |

Every output is recognized by `file(1)` as
`Linux kernel ARM64 boot executable Image, little-endian, 4K pages`.
The kallsyms scan, PAC NOP pass, setup_preset population, and
`B@_stext` install all succeed across the GKI 4.4 → 6.12 range.

## C) In-kernel `__versions` CRC finalize — UNTESTED

`kh_finalize_versions_in_place` only runs after a KSU LKM is staged
into `kh_pending_ksu_blob` via the path-1 `ksu_path` module_param. It
cannot be exercised without a working path-1 e2e, which depends on
fat.ko being loadable on the AVD. The build-side machinery is
verified (32/32 host CTest PASS, fat.ko links clean, KSU bytes are
read via filp_open + kernel_read), but the runtime CRC patching
never executes in this matrix run.

## D) path-2 boot test — 0/9 PASS (regression)

All 9 patched kernels hang silently when loaded via
`emulator -kernel <patched>`. The emulator process boots, advances
through its userland setup, but the kernel never produces a printk
banner — no "Linux version", no "Booting Linux", no `kh: khimg:`
markers.

### Validation that the issue is patch-specific, not infrastructure

| What we ran                                                    | Outcome |
|----------------------------------------------------------------|---------|
| `emulator -avd Pixel_31` (no `-kernel`)                        | boots ✓ |
| `emulator -avd Pixel_31 -kernel <stock-gunzipped-Image>`       | boots ✓ |
| `emulator -avd Pixel_31 -kernel <patched-Image>`               | hangs ✗ |
| `emulator -avd Pixel_31 -kernel <patched-Image>` + `-memory 4096` | hangs ✗ |
| Reverting `image_size_le` from `total_len` to stock value      | hangs ✗ |
| KP's parallel rig: `emulator -kernel kernel-ranchu.kp`         | boots ✓ |

The kp rig (`~/.kp-avd/kp-df-Pixel_36_1/kernel-ranchu.kp`) uses the
same `emulator` binary, same flags, and a kernel patched by
KernelPatch's own `kpimg`-flavor flow — it boots into Linux 6.12
fine. So `-kernel <patched>` is supported by the emulator; it's
specifically our `khtools patch-image` output that the kernel can't
boot from.

### Static analysis of the patched output

Header fields look correct:

```
KP raw patched (Pixel_36_1):
  code0=0xfa405a4d code1=0x149873ff text_offset=0x0 image_size=0x26d0000

Our patched (Pixel_31):
  code0=0x91005a4d code1=0x14bb63ff text_offset=0x0 image_size=0x2cc0000
```

`code0` is unchanged from stock for both KP and our flow (just the
`MZ` PE/COFF compatibility insn). `code1` is a B redirecting to each
flow's setup_entry inside the appended blob. Targets decode to:

- KP patched: B → 0x261d000 (38.1 MB, inside KP-extended image_size)
- Our patched: B → 0x2ed9000 (46.85 MB, inside our khimg blob region)

Disassembling our setup_entry at file offset 0x2ED9000 matches what
the linker emitted for `khimg/src/setup1.S::setup_entry`:

```
+00: mov x9, sp           (910003e9)
+04: nop                  (d503201f)   ← linker adrp→nop relaxation
+08: adr x11, stack       (10ffabcb)
+0c: add x11, x11, #0x800
+10: mov sp, x11
+14: stp x9, x10, [sp, -16]!
+18: b setup
```

Code is structurally fine. The hang must be deeper in the
kh_image_inject pipeline — likely one of:

  - `paging_init_resolved` (the followed-B address kh_relo_branch_func
    finds in `paging_init`'s body) being wrong for this kernel layout
  - `tcp_init_sock` PAC NOP region landing on something that's not
    PAC pairs on this kernel
  - `setup_preset` field offsets or values mismatching what khimg's
    setup1.S reads

### Why this is a regression we missed

The "foundation-v1" Pixel_31/33/34 PASS in `MEMORY.md
(project_pivot_graft.md)` referred to the **graft pipeline** —
`tools/kmod_loader/graft_vendor_ko` + `tools/kmod_loader` running on
a fat.ko after the AVD has booted with its stock kernel. That path
does NOT exercise `khtools patch-image` at all; the kernel side is
just stock. Path-2 (boot from a patched Image) was a separate "to be
written" lane until commit 2d2f872 added `test_avd_path2.sh`, and
even that stopped at "patch-image rc=0" without booting.

This matrix run is the first time `emulator -kernel <patched>`
has been attempted across the AVD pool. Result: the patch-image
flow has a latent bug that needs investigation.

## Next-step debugging plan (deferred)

1. Bisect against KP's `kpimg`: build a minimal khimg variant whose
   only difference from KP's `kpimg` is the linker base layout, and
   see if it boots. If yes, the divergence is in khimg-vs-kpimg
   source. If no, the divergence is in `kh_image_inject` (which is
   how we use kpimg, vs how KP uses kpimg).
2. Inspect `paging_init_resolved` and `map_start` for Pixel_31:
   compare to the equivalent values KP computes on
   `kp-df-Pixel_36_1` (different kernel, same logic should apply).
3. Add an early-stage `printk` (using `kallsyms_lookup_name(printk)`
   directly from setup1.S, before any paging setup) so we can prove
   setup_entry is even being entered.

This is independent of the foundation-v1.1 commits in this session
(surface, finalize, kh_call_init_module, deferred hook). Those all
build clean and don't regress `khtools patch-image`'s output (it's
the kernel-side runtime that hangs, not the patch tooling).
