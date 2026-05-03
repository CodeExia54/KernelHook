#!/usr/bin/env python3
"""Extract symbol CRCs from an AVD kernel for kmod_loader.

For AVDs where kmod_loader's built-in CRC resolution fails (no vendor .ko,
no /proc/kcore, no __crc_* in kallsyms).

Reads ksymtab/kcrctab addresses from the device via kallsyms, then extracts
CRC values from the host-side kernel-ranchu image.

Usage:
  extract_avd_crcs.py -s emulator-5554
  extract_avd_crcs.py -s emulator-5554 module_layout printk memcpy memset

Output: --crc arguments for kmod_loader
"""
import gzip, struct, sys, os, subprocess, argparse


def decompress_kernel(path):
    with open(path, 'rb') as f:
        magic = f.read(2)
    if magic == b'\x1f\x8b':
        return gzip.open(path, 'rb').read()
    with open(path, 'rb') as f:
        return f.read()


def adb(serial, cmd):
    # Wrap in `su 0 sh -c '...'` so privileged operations (kptr_restrict
    # toggle + reading /proc/kallsyms after that toggle) work on AVDs
    # where `adb root` is denied (Pixel_31..34 production GKI images)
    # but the system image ships a Magisk-style su binary.
    # Single-quote escape: each `'` in the original becomes `'"'"'`.
    escaped = cmd.replace("'", """'"'"'""")
    wrapped = "su 0 sh -c '%s'" % escaped
    r = subprocess.run(['adb', '-s', serial, 'shell', wrapped],
                       capture_output=True, text=True, timeout=10)
    return r.stdout.strip()


def adb_ksym(serial, name):
    out = adb(serial, f'grep " {name}$" /proc/kallsyms')
    if out:
        return int(out.split()[0], 16)
    return 0


def _resolve_android_sdk():
    """Ordered SDK root resolution matching scripts/lib/detect_toolchain.sh."""
    for var in ('ANDROID_SDK_ROOT', 'ANDROID_HOME'):
        v = os.environ.get(var)
        if v and os.path.isdir(v):
            return v
    import platform
    if platform.system() == 'Darwin':
        p = os.path.expanduser('~/Library/Android/sdk')
        if os.path.isdir(p):
            return p
    p = os.path.expanduser('~/Android/Sdk')
    if os.path.isdir(p):
        return p
    return None


def find_kernel_for_avd(serial):
    """Find host-side kernel-ranchu matching the running AVD.

    Algorithm: collect every arm64-v8a kernel-ranchu under the SDK's
    system-images/ tree, decompress each, and check whether the FULL
    device release string (`uname -r`) appears as a contiguous run of
    bytes inside the kernel image. Return the first exact match.

    The previous implementation sorted entries reverse-alphabetically
    which made `android-36.1` win over `android-31` for a 5.10.110-
    android12 device — short substrings (`5.10.110`) accidentally hit
    inside other images' compressed data. We now require the device
    release suffix (`-android12-9-...-ab8731800`) which is unique
    enough to rule that out, and we don't bias the search order.
    """
    sdk = _resolve_android_sdk()
    if not sdk:
        return None, None

    device_release = adb(serial, 'uname -r').strip()
    if not device_release:
        return None, None

    needle = device_release.encode()
    sysimg_dir = f'{sdk}/system-images'
    if not os.path.isdir(sysimg_dir):
        return None, None

    # Collect candidate paths first so we can iterate deterministically
    # without leaking the iteration order into the match decision.
    candidates = []
    for entry in sorted(os.listdir(sysimg_dir)):
        for variant in ['google_apis', 'google_apis_playstore',
                        'google_apis_ps16k', 'default']:
            path = f'{sysimg_dir}/{entry}/{variant}/arm64-v8a/kernel-ranchu'
            if os.path.exists(path):
                candidates.append(path)

    for path in candidates:
        data = decompress_kernel(path)
        # Full device-release string must appear verbatim in the kernel
        # image (kallsyms / version banner). Substring of just the
        # major.minor would match too many images; the device suffix
        # (-androidN-...) is what gives us a unique hit.
        if needle in data:
            return path, data

    return None, None


def detect_format(sym_size, crc_size):
    """Detect ksymtab entry size and CRC width from section sizes.

    Returns (sym_entry_size, crc_entry_size).

    Formats:
      (12, 4) — prel32 (5.10+): { i32 value, i32 name, i32 ns } + u32 CRC
      (16, 8) — absolute arm64 (4.x): { u64 value, u64 name } + u64 CRC
      (24, 4) — absolute+CFI (5.4): { u64 value, u64 name, u64 cfi } + u32 CRC
    """
    for esz, csz in ((12, 4), (16, 8), (24, 4), (16, 4)):
        if crc_size // csz > 0 and sym_size // esz == crc_size // csz:
            return esz, csz
    return 12, 4  # default to prel32


def extract_crcs(data, text_base, sym_start, sym_stop, crc_start, crc_stop, targets):
    """Extract CRCs via ksymtab + parallel kcrctab (auto-detect entry format)."""
    sym_off = sym_start - text_base
    sym_size = sym_stop - sym_start
    crc_off = crc_start - text_base
    crc_size = crc_stop - crc_start
    fsz = len(data)
    target_set = set(targets)
    results = {}

    esz, csz = detect_format(sym_size, crc_size)
    n = sym_size // esz

    for i in range(n):
        off = sym_off + i * esz
        if off + esz > fsz:
            break

        if esz == 12:
            # prel32 format: name is at (entry_va + 4 + name_prel32)
            entry_va = sym_start + i * 12
            _, name_prel, _ = struct.unpack_from('<iii', data, off)
            name_foff = (entry_va + 4 + name_prel) - text_base
        else:
            # Absolute pointer format (16 or 24 bytes): { ulong value, ulong name, ... }
            _, name_va = struct.unpack_from('<QQ', data, off)
            name_foff = name_va - text_base

        if not (0 <= name_foff < fsz - 1):
            continue
        end = data.find(b'\x00', name_foff, name_foff + 64)
        if end <= name_foff:
            continue
        name = data[name_foff:end].decode('ascii', errors='replace')

        if name in target_set:
            c_off = crc_off + i * csz
            if c_off + 4 <= fsz:
                # CRC is always the lower 32 bits regardless of entry width
                results[name] = struct.unpack_from('<I', data, c_off)[0]

    return results


def main():
    p = argparse.ArgumentParser(description='Extract AVD kernel CRCs')
    p.add_argument('-s', '--serial', required=True, help='ADB serial')
    p.add_argument('symbols', nargs='*',
                   default=['module_layout', 'printk', '_printk', 'memcpy', 'memset'])
    args = p.parse_args()

    s = args.serial
    adb(s, 'echo 0 > /proc/sys/kernel/kptr_restrict')

    text_base = adb_ksym(s, '_text')
    if not text_base:
        sys.exit("ERROR: cannot read _text from kallsyms")

    kernel_path, data = find_kernel_for_avd(s)
    if not data:
        sys.exit("ERROR: cannot find matching kernel-ranchu on host")
    print(f"# kernel: {kernel_path}", file=sys.stderr)

    crcs = {}
    # Method 1: scan ksymtab entries to match names and read parallel kcrctab
    for prefix in ['', '_gpl']:
        start = adb_ksym(s, f'__start___ksymtab{prefix}')
        stop = adb_ksym(s, f'__stop___ksymtab{prefix}')
        crc_start = adb_ksym(s, f'__start___kcrctab{prefix}')
        crc_stop = adb_ksym(s, f'__stop___kcrctab{prefix}')
        if start and crc_start:
            missing = [sym for sym in args.symbols if sym not in crcs]
            if missing:
                crcs.update(extract_crcs(data, text_base,
                                         start, stop, crc_start, crc_stop, missing))

    # Method 2: fallback for unrelocated images (name pointers are zero).
    # Use __ksymtab_<sym> addresses from kallsyms to compute ksymtab index,
    # then read the corresponding kcrctab entry.
    missing = [sym for sym in args.symbols if sym not in crcs]
    if missing:
        for prefix in ['', '_gpl']:
            start = adb_ksym(s, f'__start___ksymtab{prefix}')
            stop = adb_ksym(s, f'__stop___ksymtab{prefix}')
            crc_start = adb_ksym(s, f'__start___kcrctab{prefix}')
            crc_stop = adb_ksym(s, f'__stop___kcrctab{prefix}')
            if not (start and stop and crc_start): continue
            sym_size = stop - start
            crc_size = crc_stop - crc_start
            esz, csz = detect_format(sym_size, crc_size)
            crc_off = crc_start - text_base
            for sym in list(missing):
                entry_addr = adb_ksym(s, f'__ksymtab_{sym}')
                if not entry_addr or entry_addr < start or entry_addr >= stop:
                    continue
                idx = (entry_addr - start) // esz
                c_off = crc_off + idx * csz
                if 0 <= c_off < len(data) - 4:
                    crcs[sym] = struct.unpack_from('<I', data, c_off)[0]
                    missing.remove(sym)

    parts = []
    for sym in args.symbols:
        if sym in crcs:
            parts.append(f"--crc {sym}=0x{crcs[sym]:08x}")
        else:
            print(f"# WARNING: {sym} not found", file=sys.stderr)

    if parts:
        print(" ".join(parts))
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
