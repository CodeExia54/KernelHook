// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * graft_vendor_ko — merge a KernelHook payload object into a vendor .ko
 *                   while preserving the host ELF skeleton.
 *
 * Motivation
 *   Android 15/16 GKI kernels (6.6+) reject KernelHook's hand-built .ko at
 *   do_init_module → do_one_initcall(mod->init) with a silent indirect-call
 *   integrity panic — even when init_module is a bare `return 0;`.  The
 *   rejection originates inside the kernel's CFI / BTI / ftrace / PLT /
 *   modversions machinery and is not externally patchable from our side.
 *
 *   Vendor .ko files already on the device (e.g. in /vendor/lib/modules/)
 *   *are* accepted by the same kernel — they carry the correct notes,
 *   ftrace trampoline, altinstructions, kCFI hash prefixes, module_sig
 *   (stripped here), and ksymtab/__versions layout.  Rather than continue
 *   rebuilding an ELF the kernel will trust, this tool takes a known-good
 *   vendor .ko (the host) and grafts KernelHook's runtime (the payload)
 *   into it: a merged binary that loads as the vendor module but executes
 *   KernelHook's kh_entry from init_module's slot.
 *
 * Usage
 *   graft_vendor_ko --host host.ko --payload kh_payload.o --out grafted.ko
 *
 * Output layout
 *   - Host file bytes 0 .. original_e_shoff are copied verbatim.  All host
 *     section *data* stays in place; only the section-header table moves.
 *   - Trailing module signature (if present) is stripped: the kernel accepts
 *     unsigned out-of-tree modules on all AVDs we target (CONFIG_MODULE_
 *     SIG_FORCE is not set), but a broken signature triggers EKEYREJECTED
 *     under CONFIG_MODULE_SIG_PROTECT.
 *   - After the host body we append:
 *       (A) payload raw section data (.text.*, .data, .rodata, .bss-spacer,
 *           .init.text, .exit.text, .kh_strategies, __ex_table, plt-stub-
 *           less rela sections)
 *       (B) merged .symtab        (host syms first, payload syms appended)
 *       (C) merged .strtab        (host strs first, payload strs appended)
 *       (D) merged .shstrtab      (host names first, payload names appended,
 *           each payload name prefixed with ".kh" to avoid collision with
 *           host sections of the same name)
 *       (E) payload-originated .rela.* sections, with symbol indices shifted
 *           by host_sym_count and sh_info retargeted at the new (appended)
 *           section numbers
 *       (F) rewritten .rela.gnu.linkonce.this_module (same byte size) whose
 *           init and exit entries now reference the merged symtab indices of
 *           kh_entry and kh_exit
 *       (G) new section-header table
 *   - e_shoff is updated to point at (G).  e_shnum grows by the number of
 *     payload sections brought in.  e_shstrndx is left pointing at host's
 *     shstrtab index, but that header's sh_offset is now (D).
 *
 * Constraints for the payload object
 *   - Built with KH_PAYLOAD=1 (see kmod/mk/kmod.mk).  This suppresses
 *     MODULE_LICENSE, MODULE_VERSIONS, MODULE_VERMAGIC, MODULE_THIS_MODULE,
 *     module_param, module_init, module_exit, plt_stub and kh_exports — the
 *     host vendor .ko already provides every section those macros would
 *     emit.
 *   - Exports two external symbols: kh_entry (alias of kernelhook_init) and
 *     kh_exit (alias of kernelhook_exit).  Both are resolved by name at
 *     graft time; absent either aborts the graft.
 *
 * Constraints for the host .ko
 *   - MODULE_LICENSE("GPL") (must be a GPL module; graft inherits the
 *     kernel's GPL-symbol visibility on behalf of payload code).
 *   - Has init_module and cleanup_module symbols in its symtab.
 *   - Has a .rela.gnu.linkonce.this_module section with relocations for the
 *     struct module `init` and `exit` fields.
 *   - Has a module signature appended (optional — stripped if present).
 *
 * Portability
 *   - ELF64 little-endian only (arm64).  Errors cleanly on any other arch.
 *   - Requires host <elf.h> at build time (Linux / Android NDK host tool).
 *     A macOS host can run the tool via docker or via the device-side
 *     kmod_loader which links against Android libc.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* <elf.h> is a Linux/glibc (+ Android NDK) header, not present on macOS.
 * This tool compiles and runs as a host-side build step; on macOS we fall
 * back to minimal ELF64 type + constant definitions verbatim from the
 * System V ABI (which is also what <elf.h> carries).  ELF64 layouts do
 * not change across hosts — this is purely a typedef surface. */
#if defined(__has_include)
#  if __has_include(<elf.h>)
#    include <elf.h>
#    define GRAFT_HAVE_ELF_H 1
#  endif
#endif

#ifndef GRAFT_HAVE_ELF_H
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Section;

#define EI_NIDENT     16
#define EI_CLASS      4
#define EI_DATA       5
#define ELFCLASS64    2
#define ELFDATA2LSB   1
#define ELFMAG        "\177ELF"
#define SELFMAG       4
#define EM_AARCH64    183
#define ET_REL        1
#define SHT_NULL      0
#define SHT_PROGBITS  1
#define SHT_SYMTAB    2
#define SHT_STRTAB    3
#define SHT_RELA      4
#define SHT_NOBITS    8
#define SHN_UNDEF     0
#define SHN_LORESERVE 0xff00
#define SHN_ABS       0xfff1
#define SHN_COMMON    0xfff2

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off  e_phoff;
    Elf64_Off  e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word  sh_name;
    Elf64_Word  sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr  sh_addr;
    Elf64_Off   sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word  sh_link;
    Elf64_Word  sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
} Elf64_Shdr;

typedef struct {
    Elf64_Word    st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Section st_shndx;
    Elf64_Addr    st_value;
    Elf64_Xword   st_size;
} Elf64_Sym;

typedef struct {
    Elf64_Addr   r_offset;
    Elf64_Xword  r_info;
    Elf64_Sxword r_addend;
} Elf64_Rela;

#define ELF64_R_SYM(i)        ((i) >> 32)
#define ELF64_R_TYPE(i)       ((i) & 0xffffffffULL)
#define ELF64_R_INFO(sym, t)  (((Elf64_Xword)(sym) << 32) | ((Elf64_Xword)(t) & 0xffffffffULL))
#endif /* !GRAFT_HAVE_ELF_H */

typedef Elf64_Ehdr Ehdr;
typedef Elf64_Shdr Shdr;
typedef Elf64_Sym  Sym;
typedef Elf64_Rela Rela;

#define MODULE_SIG_TRAILER  "~Module signature appended~\n"
#define MODULE_SIG_TRAILER_LEN 28   /* sizeof minus the NUL */

/* Android / kernel mod-sig trailer struct (reproduced here — no kernel
 * headers on the host side). Precedes the trailer magic string. */
struct module_signature {
    uint8_t  algo;
    uint8_t  hash;
    uint8_t  id_type;
    uint8_t  signer_len;
    uint8_t  key_id_len;
    uint8_t  __pad[3];
    uint32_t sig_len;               /* big-endian on wire */
};

static int verbose = 0;

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "graft_vendor_ko: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static void vlog(const char *fmt, ...)
{
    if (!verbose) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* ---------------------------------------------------------------------- */
/*  File I/O                                                              */
/* ---------------------------------------------------------------------- */

static uint8_t *read_file(const char *path, size_t *out_size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) die("open('%s'): %s", path, strerror(errno));

    struct stat st;
    if (fstat(fd, &st) < 0) die("stat('%s'): %s", path, strerror(errno));
    if (st.st_size <= (off_t)sizeof(Ehdr))
        die("'%s' is too small (%lld bytes)", path, (long long)st.st_size);
    if (st.st_size > 64 * 1024 * 1024)
        die("'%s' is > 64 MiB, refusing to load", path);

    uint8_t *buf = (uint8_t *)malloc((size_t)st.st_size);
    if (!buf) die("oom (%lld bytes)", (long long)st.st_size);

    ssize_t n = read(fd, buf, (size_t)st.st_size);
    if (n != st.st_size) die("read('%s') short: %zd != %lld", path, n, (long long)st.st_size);
    close(fd);

    *out_size = (size_t)st.st_size;
    return buf;
}

static void write_file(const char *path, const uint8_t *buf, size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) die("open('%s'): %s", path, strerror(errno));
    ssize_t n = write(fd, buf, size);
    if (n != (ssize_t)size) die("write('%s') short: %zd != %zu", path, n, size);
    close(fd);
}

/* ---------------------------------------------------------------------- */
/*  Module-signature strip                                                */
/* ---------------------------------------------------------------------- */

/*
 * Kernel sig-trailer format (scripts/sign-file + kernel/module/signing.c):
 *
 *     ... ELF body ...
 *     signature bytes (sig_len)
 *     struct module_signature (12 B, sig_len big-endian)
 *     "~Module signature appended~\n" (28 B, no NUL)
 *
 * If the trailer magic is present, return the ELF-only length.  Otherwise
 * return size unchanged.
 */
static size_t strip_module_sig(const uint8_t *buf, size_t size)
{
    if (size < MODULE_SIG_TRAILER_LEN + sizeof(struct module_signature))
        return size;
    size_t magic_off = size - MODULE_SIG_TRAILER_LEN;
    if (memcmp(buf + magic_off, MODULE_SIG_TRAILER, MODULE_SIG_TRAILER_LEN) != 0)
        return size;

    struct module_signature ms;
    size_t ms_off = magic_off - sizeof(ms);
    memcpy(&ms, buf + ms_off, sizeof(ms));

    /* sig_len is big-endian on wire */
    uint32_t sig_len = ((uint32_t)buf[ms_off + 8]  << 24)
                     | ((uint32_t)buf[ms_off + 9]  << 16)
                     | ((uint32_t)buf[ms_off + 10] << 8)
                     | ((uint32_t)buf[ms_off + 11]);

    size_t trailer_total = MODULE_SIG_TRAILER_LEN + sizeof(ms)
                         + sig_len + ms.signer_len + ms.key_id_len;
    if (trailer_total >= size) {
        vlog("strip_module_sig: declared trailer (%zu) >= file (%zu), ignoring",
             trailer_total, size);
        return size;
    }
    vlog("strip_module_sig: stripped %zu bytes (sig_len=%u, signer=%u, key_id=%u)",
         trailer_total, sig_len, ms.signer_len, ms.key_id_len);
    return size - trailer_total;
}

/* ---------------------------------------------------------------------- */
/*  ELF helpers                                                           */
/* ---------------------------------------------------------------------- */

static void elf_validate(const uint8_t *buf, size_t size, const char *label)
{
    if (size < sizeof(Ehdr)) die("%s: smaller than ELF header", label);
    const Ehdr *eh = (const Ehdr *)buf;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0)
        die("%s: bad ELF magic", label);
    if (eh->e_ident[EI_CLASS] != ELFCLASS64)
        die("%s: not ELF64", label);
    if (eh->e_ident[EI_DATA] != ELFDATA2LSB)
        die("%s: not little-endian", label);
    if (eh->e_machine != EM_AARCH64)
        die("%s: machine %u, expected EM_AARCH64(183)", label, eh->e_machine);
    if (eh->e_type != ET_REL)
        die("%s: e_type %u, expected ET_REL(1)", label, eh->e_type);
    if (eh->e_shoff == 0 || eh->e_shnum == 0)
        die("%s: no section header table", label);
    if (eh->e_shentsize != sizeof(Shdr))
        die("%s: e_shentsize %u != sizeof(Shdr) %zu", label,
            eh->e_shentsize, sizeof(Shdr));
    if ((size_t)eh->e_shoff + (size_t)eh->e_shnum * sizeof(Shdr) > size)
        die("%s: section header table runs past file end", label);
}

static const char *shstrtab_name(const uint8_t *buf, const Ehdr *eh, uint32_t sh_name)
{
    const Shdr *sh_strs = (const Shdr *)(buf + eh->e_shoff
                                         + eh->e_shstrndx * sizeof(Shdr));
    return (const char *)(buf + sh_strs->sh_offset + sh_name);
}

static const Shdr *find_section(const uint8_t *buf, const Ehdr *eh, const char *name)
{
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        const Shdr *sh = (const Shdr *)(buf + eh->e_shoff + i * sizeof(Shdr));
        if (strcmp(shstrtab_name(buf, eh, sh->sh_name), name) == 0)
            return sh;
    }
    return NULL;
}

/* find_section_index: kept as a ready-to-use helper for future merger
 * refinements (e.g. targeted section replacement).  Not currently called. */
__attribute__((unused))
static int find_section_index(const uint8_t *buf, const Ehdr *eh, const char *name)
{
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        const Shdr *sh = (const Shdr *)(buf + eh->e_shoff + i * sizeof(Shdr));
        if (strcmp(shstrtab_name(buf, eh, sh->sh_name), name) == 0)
            return i;
    }
    return -1;
}

/* Return the symbol-table section and its associated string table. */
static void locate_symtab(const uint8_t *buf, const Ehdr *eh,
                          const Shdr **out_symtab, const Shdr **out_strtab,
                          int *out_symtab_idx)
{
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        const Shdr *sh = (const Shdr *)(buf + eh->e_shoff + i * sizeof(Shdr));
        if (sh->sh_type == SHT_SYMTAB) {
            if (sh->sh_link >= eh->e_shnum)
                die("symtab sh_link out of range");
            *out_symtab = sh;
            *out_strtab = (const Shdr *)(buf + eh->e_shoff
                                         + sh->sh_link * sizeof(Shdr));
            *out_symtab_idx = i;
            return;
        }
    }
    die("no .symtab section");
}

static int find_symbol_index(const uint8_t *buf, const Shdr *symtab,
                             const Shdr *strtab, const char *name)
{
    uint32_t n = symtab->sh_size / symtab->sh_entsize;
    const Sym *syms = (const Sym *)(buf + symtab->sh_offset);
    const char *strs = (const char *)(buf + strtab->sh_offset);
    for (uint32_t i = 0; i < n; i++) {
        if (strcmp(strs + syms[i].st_name, name) == 0) return (int)i;
    }
    return -1;
}

/* ---------------------------------------------------------------------- */
/*  CLI                                                                   */
/* ---------------------------------------------------------------------- */

static void usage(void)
{
    fprintf(stderr,
        "Usage: graft_vendor_ko --host HOST.ko --payload PAYLOAD.o --out OUT.ko\n"
        "                       [--kallsyms-addr 0xADDR] [-v]\n"
        "\n"
        "Merges a KernelHook KH_PAYLOAD=1 object into a vendor .ko so the\n"
        "grafted module loads on kernels that reject hand-built KernelHook .kos.\n"
        "\n"
        "--kallsyms-addr writes the given 64-bit value into the merged symtab's\n"
        "  'kallsyms_addr' symbol (whose storage lives in payload's .data).  The\n"
        "  value must be the running kernel's &kallsyms_lookup_name — it's what\n"
        "  kernelhook_init reads in order to bootstrap kmod_compat_init.  Without\n"
        "  this option the field stays zero and kernelhook_init will fail early.\n"
        "\n"
        "See the header block of graft_vendor_ko.c for the output-layout contract.\n");
    exit(2);
}

/* Forward declaration of the core merger. */
int kh_graft_compose(const uint8_t *host, size_t host_size,
                     const uint8_t *payload, size_t payload_size,
                     uint64_t kallsyms_addr, int have_kallsyms_addr,
                     uint8_t **out_buf, size_t *out_size);

int kh_graft_in_place(uint8_t **ko_buf, size_t *ko_len, const char *host_path)
{
    if (!ko_buf || !*ko_buf || !ko_len || !host_path) return -1;

    size_t host_size = 0;
    uint8_t *host = read_file(host_path, &host_size);
    /* read_file calls die() on failure — never reach here with a failed read.
     * Acceptable for the standalone CLI path; non-fatal failure can be added
     * later if lib callers need it. */

    size_t host_body = strip_module_sig(host, host_size);
    elf_validate(host, host_body, "host");
    elf_validate(*ko_buf, *ko_len, "payload");

    uint8_t *out = NULL;
    size_t out_size = 0;
    int rc = kh_graft_compose(host, host_body, *ko_buf, *ko_len,
                              0, 0,  /* kallsyms_addr — not provided in this path */
                              &out, &out_size);
    free(host);
    if (rc != 0) return rc;

    free(*ko_buf);
    *ko_buf = out;
    *ko_len = out_size;
    return 0;
}

#ifdef KH_GRAFT_STANDALONE
int main(int argc, char **argv)
{
    const char *host_path = NULL, *payload_path = NULL, *out_path = NULL;
    uint64_t kallsyms_addr = 0;
    int have_kallsyms_addr = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            host_path = argv[++i];
        else if (strcmp(argv[i], "--payload") == 0 && i + 1 < argc)
            payload_path = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
            out_path = argv[++i];
        else if (strcmp(argv[i], "--kallsyms-addr") == 0 && i + 1 < argc) {
            const char *s = argv[++i];
            char *end = NULL;
            kallsyms_addr = strtoull(s, &end, 0);
            if (!end || *end != '\0' || kallsyms_addr == 0)
                die("--kallsyms-addr '%s' must be a non-zero integer (e.g. 0xffffffc008123456)", s);
            have_kallsyms_addr = 1;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
            verbose = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
            usage();
        else
            die("unknown argument '%s' (use --help)", argv[i]);
    }
    if (!host_path || !payload_path || !out_path) usage();

    size_t host_size = 0, payload_size = 0;
    uint8_t *host = read_file(host_path, &host_size);
    uint8_t *payload = read_file(payload_path, &payload_size);

    size_t host_body_size = strip_module_sig(host, host_size);
    vlog("host: %zu bytes (ELF body %zu)", host_size, host_body_size);
    vlog("payload: %zu bytes", payload_size);

    elf_validate(host, host_body_size, "host");
    elf_validate(payload, payload_size, "payload");

    uint8_t *out_buf = NULL;
    size_t   out_size = 0;
    int rc = kh_graft_compose(host, host_body_size, payload, payload_size,
                              kallsyms_addr, have_kallsyms_addr, &out_buf, &out_size);
    if (rc != 0) die("graft failed (rc=%d)", rc);

    write_file(out_path, out_buf, out_size);
    fprintf(stderr, "graft_vendor_ko: wrote %zu bytes to %s\n", out_size, out_path);

    free(out_buf);
    free(host);
    free(payload);
    return 0;
}
#endif /* KH_GRAFT_STANDALONE */

/* ---------------------------------------------------------------------- */
/*  Core merger                                                           */
/* ---------------------------------------------------------------------- */

static size_t align_up(size_t x, size_t a)
{
    if (a <= 1) return x;
    return (x + a - 1) & ~(a - 1);
}

/*
 * graft() — merge payload sections and symbols into a copy of host.ko,
 * rewriting the host's .rela.gnu.linkonce.this_module so that mod->init and
 * mod->exit point at the payload's kh_entry and kh_exit.
 *
 * Output layout (appended past host body):
 *   host body verbatim [0 .. host_size) - except .rela.gnu.linkonce.this_module
 *   which is rewritten in-place inside the copy (same byte size, different
 *   r_info symbol indices)
 *   --- 8-byte align ---
 *   merged shstrtab  (host shstrtab + payload names with ".kh" prefix)
 *   merged strtab    (host strtab + payload strtab verbatim)
 *   merged symtab    (host syms + payload syms with remapped st_name, st_shndx)
 *   per-payload-section data, each at its sh_addralign (rela sections with
 *       rewritten r_info symbol indices)
 *   new section header table (host headers with sh_offset/sh_size updated
 *       for symtab/strtab/shstrtab, plus new payload section headers)
 *
 * The host's .symtab section header is reused: its index stays at h_symidx,
 * its sh_link still points at the strtab index, only its sh_offset/sh_size
 * change to cover the larger merged area.  Same idea for strtab and
 * shstrtab.  Existing host rela sections (which reference host syms by
 * index) are untouched because their symbol indices are still valid in the
 * merged symtab (the merge appends; it does not reorder).
 */
int kh_graft_compose(const uint8_t *host, size_t host_size,
                     const uint8_t *payload, size_t payload_size,
                     uint64_t kallsyms_addr, int have_kallsyms_addr,
                     uint8_t **out_buf, size_t *out_size)
{
    const Ehdr *h_eh = (const Ehdr *)host;
    const Ehdr *p_eh = (const Ehdr *)payload;
    (void)payload_size;  /* validated in elf_validate(); graft uses section sizes */

    /* -------- Host preflight -------- */
    if (!find_section(host, h_eh, ".gnu.linkonce.this_module"))
        die("host: missing .gnu.linkonce.this_module");
    const Shdr *h_rela_tm = find_section(host, h_eh, ".rela.gnu.linkonce.this_module");
    if (!h_rela_tm)
        die("host: missing .rela.gnu.linkonce.this_module "
            "(the graft relocates init/exit via this section)");

    const Shdr *h_sym = NULL, *h_str = NULL;
    int h_symidx = -1;
    locate_symtab(host, h_eh, &h_sym, &h_str, &h_symidx);
    int h_stridx = (int)h_sym->sh_link;
    int h_shstridx = (int)h_eh->e_shstrndx;

    int h_init_sym = find_symbol_index(host, h_sym, h_str, "init_module");
    int h_exit_sym = find_symbol_index(host, h_sym, h_str, "cleanup_module");
    if (h_init_sym < 0) die("host: no init_module symbol");
    if (h_exit_sym < 0) die("host: no cleanup_module symbol");

    size_t h_sym_count = h_sym->sh_size / h_sym->sh_entsize;
    size_t h_str_size  = h_str->sh_size;
    const Shdr *h_shstr_sh = (const Shdr *)(host + h_eh->e_shoff + (size_t)h_shstridx * sizeof(Shdr));
    size_t h_shstr_size = h_shstr_sh->sh_size;

    /* -------- Payload preflight -------- */
    const Shdr *p_sym = NULL, *p_str = NULL;
    int p_symidx = -1;
    locate_symtab(payload, p_eh, &p_sym, &p_str, &p_symidx);

    int p_entry_sym = find_symbol_index(payload, p_sym, p_str, "kh_entry");
    int p_exit_sym  = find_symbol_index(payload, p_sym, p_str, "kh_exit");
    int p_kallsyms_sym = find_symbol_index(payload, p_sym, p_str, "kallsyms_addr");
    if (p_entry_sym < 0 || p_exit_sym < 0 || p_kallsyms_sym < 0)
        die("payload: missing kh_entry / kh_exit / kallsyms_addr "
            "— built without KH_PAYLOAD=1?");

    size_t p_sym_count = p_sym->sh_size / p_sym->sh_entsize;
    const Shdr *p_shstr_sh = (const Shdr *)(payload + p_eh->e_shoff
                                            + (size_t)p_eh->e_shstrndx * sizeof(Shdr));
    const char *p_shstrs = (const char *)(payload + p_shstr_sh->sh_offset);

    /* -------- Payload section mapping: old_idx -> new_idx_in_output -------- */
    /* Drop SHT_NULL, SHT_SYMTAB, SHT_STRTAB (which also covers shstrtab).
     * Every other section is appended as a new section in the output. */
    int *p_new_shndx   = (int *)calloc(p_eh->e_shnum, sizeof(int));
    uint64_t *p_new_sh_offset = (uint64_t *)calloc(p_eh->e_shnum, sizeof(uint64_t));
    uint32_t *p_new_sh_name   = (uint32_t *)calloc(p_eh->e_shnum, sizeof(uint32_t));
    if (!p_new_shndx || !p_new_sh_offset || !p_new_sh_name) die("oom");
    for (int i = 0; i < p_eh->e_shnum; i++) p_new_shndx[i] = -1;
    int p_shcount = 0;
    for (uint16_t i = 0; i < p_eh->e_shnum; i++) {
        const Shdr *sh = (const Shdr *)(payload + p_eh->e_shoff + (size_t)i * sizeof(Shdr));
        if (sh->sh_type == SHT_NULL) continue;
        if (sh->sh_type == SHT_SYMTAB) continue;
        if (sh->sh_type == SHT_STRTAB) continue;
        p_new_shndx[i] = h_eh->e_shnum + p_shcount;
        p_shcount++;
    }

    /* -------- Payload symbol mapping: old_idx -> new_idx_in_output -------- */
    /* Drop only sym[0] (the mandatory SHN_UNDEF anchor; host has one). */
    int *p_new_symidx = (int *)calloc(p_sym_count, sizeof(int));
    if (!p_new_symidx) die("oom");
    for (size_t i = 0; i < p_sym_count; i++) p_new_symidx[i] = -1;
    int p_sym_new_count = 0;
    for (size_t i = 1; i < p_sym_count; i++) {
        p_new_symidx[i] = (int)(h_sym_count + (size_t)p_sym_new_count);
        p_sym_new_count++;
    }

    vlog("host: %u sections, %zu syms, init@[%d] exit@[%d]",
         h_eh->e_shnum, h_sym_count, h_init_sym, h_exit_sym);
    vlog("payload: %u sections -> +%d appended, %zu syms -> +%d appended",
         p_eh->e_shnum, p_shcount, p_sym_count, p_sym_new_count);

    /* -------- Compute extra shstrtab size (sum of ".kh" + name + NUL) -------- */
    size_t extra_shstr_bytes = 0;
    for (uint16_t i = 0; i < p_eh->e_shnum; i++) {
        if (p_new_shndx[i] < 0) continue;
        const Shdr *sh = (const Shdr *)(payload + p_eh->e_shoff + (size_t)i * sizeof(Shdr));
        const char *name = p_shstrs + sh->sh_name;
        extra_shstr_bytes += 3 /*.kh*/ + strlen(name) + 1 /*NUL*/;
    }
    size_t new_shstrtab_size = h_shstr_size + extra_shstr_bytes;
    size_t new_strtab_size   = h_str_size + p_str->sh_size;
    size_t new_symtab_size   = (h_sym_count + (size_t)p_sym_new_count) * sizeof(Sym);

    /* -------- First pass: compute output offsets (and total size) -------- */
    size_t off = align_up(host_size, 8);
    size_t off_shstrtab = off;
    off += new_shstrtab_size;

    off = align_up(off, 8);
    size_t off_strtab = off;
    off += new_strtab_size;

    off = align_up(off, 8);
    size_t off_symtab = off;
    off += new_symtab_size;

    /* Payload section data */
    for (uint16_t i = 0; i < p_eh->e_shnum; i++) {
        if (p_new_shndx[i] < 0) continue;
        const Shdr *sh = (const Shdr *)(payload + p_eh->e_shoff + (size_t)i * sizeof(Shdr));
        if (sh->sh_type == SHT_NOBITS) {
            p_new_sh_offset[i] = 0;
            continue;
        }
        size_t align = sh->sh_addralign ? sh->sh_addralign : 1;
        off = align_up(off, align);
        p_new_sh_offset[i] = off;
        off += sh->sh_size;
    }

    off = align_up(off, 8);
    size_t new_shoff = off;
    size_t new_shnum = (size_t)h_eh->e_shnum + (size_t)p_shcount;
    off += new_shnum * sizeof(Shdr);

    size_t out_cap = off;

    /* -------- Allocate and fill output buffer -------- */
    uint8_t *out = (uint8_t *)calloc(1, out_cap);
    if (!out) die("oom");

    /* Host body verbatim */
    memcpy(out, host, host_size);

    /* Rewrite .rela.gnu.linkonce.this_module in-place inside out[].
     * Each Rela in this section references a host symbol by index via
     * r_info.  Entries whose current sym index equals h_init_sym get
     * rewritten to point at the appended kh_entry's merged index; same
     * for h_exit_sym -> kh_exit. */
    {
        Rela *rela = (Rela *)(out + h_rela_tm->sh_offset);
        size_t n = h_rela_tm->sh_size / sizeof(Rela);
        int patched = 0;
        for (size_t i = 0; i < n; i++) {
            uint32_t type = (uint32_t)ELF64_R_TYPE(rela[i].r_info);
            uint64_t sym  = ELF64_R_SYM(rela[i].r_info);
            if ((int)sym == h_init_sym) {
                int new_sym = p_new_symidx[p_entry_sym];
                rela[i].r_info = ELF64_R_INFO((uint64_t)new_sym, type);
                patched |= 1;
            } else if ((int)sym == h_exit_sym) {
                int new_sym = p_new_symidx[p_exit_sym];
                rela[i].r_info = ELF64_R_INFO((uint64_t)new_sym, type);
                patched |= 2;
            }
        }
        if ((patched & 3) != 3)
            die(".rela.gnu.linkonce.this_module: init+exit rewrite "
                "failed (patched mask = 0x%x; expected 0x3)", patched);
        vlog("rewrote .rela.gnu.linkonce.this_module init -> merged[%d], exit -> merged[%d]",
             p_new_symidx[p_entry_sym], p_new_symidx[p_exit_sym]);
    }

    /* Merged shstrtab: host shstrtab then payload section names.
     * Payload sections whose name matches a kernel-well-known export
     * section (__ksymtab, __kcrctab, __ksymtab_strings, ...) are written
     * with their ORIGINAL name so the kernel's find_sec("__ksymtab")
     * locates payload data.  All other payload sections are prefixed with
     * ".kh" to avoid name collisions with host sections. */
    {
        static const char *const keep_original_name[] = {
            "__ksymtab", "__ksymtab_gpl", "__ksymtab_strings",
            "__kcrctab", "__kcrctab_gpl",
            NULL
        };
        uint8_t *dst = out + off_shstrtab;
        memcpy(dst, host + h_shstr_sh->sh_offset, h_shstr_size);
        size_t pos = h_shstr_size;
        for (uint16_t i = 0; i < p_eh->e_shnum; i++) {
            if (p_new_shndx[i] < 0) continue;
            const Shdr *sh = (const Shdr *)(payload + p_eh->e_shoff + (size_t)i * sizeof(Shdr));
            const char *name = p_shstrs + sh->sh_name;
            int keep_original = 0;
            for (int k = 0; keep_original_name[k]; k++) {
                if (strcmp(name, keep_original_name[k]) == 0) { keep_original = 1; break; }
            }
            p_new_sh_name[i] = (uint32_t)pos;
            if (!keep_original) {
                memcpy(dst + pos, ".kh", 3); pos += 3;
            }
            size_t nlen = strlen(name);
            memcpy(dst + pos, name, nlen); pos += nlen;
            dst[pos++] = '\0';
        }
        if (pos > new_shstrtab_size)
            die("internal: shstrtab pos %zu > expected %zu", pos, new_shstrtab_size);
        /* Actual size may be smaller than pre-computed (kept-original names
         * skip the 3-byte ".kh" prefix).  Trim the section declaration. */
        new_shstrtab_size = pos;
    }

    /* Merged strtab: host strtab then payload strtab verbatim */
    {
        memcpy(out + off_strtab, host + h_str->sh_offset, h_str_size);
        memcpy(out + off_strtab + h_str_size, payload + p_str->sh_offset, p_str->sh_size);
    }

    /* Merged symtab: host syms verbatim, then payload syms with remapped
     * st_name (offset by h_str_size) and st_shndx (mapped via p_new_shndx).
     *
     * While walking host syms we rewrite two bindings:
     *   (A) UNDEF GLOBAL -> WEAK: host code paths are never reached (kh_entry
     *       replaces init_module; host .text becomes dead weight).  Weakening
     *       lets the kernel resolve unresolvable externs (e.g. tipc_*) to
     *       NULL without aborting the load.
     *   (B) GLOBAL DEFINED with kernel-exportable name -> LOCAL: Android
     *       15's CONFIG_MODULE_SIG_PROTECT=y rejects any unsigned module
     *       that exports a "protected" symbol.  Protected-ness is detected
     *       by name — it's enough for our host to have a GLOBAL FUNC
     *       `lowpan_nhc_add`.  Since our graft's only job is to run
     *       kh_entry, we can hide every host GLOBAL DEFINED symbol by
     *       demoting its bind to LOCAL.  init_module and cleanup_module
     *       stay GLOBAL so the kernel still finds the module's entry. */
    {
        Sym *dst = (Sym *)(out + off_symtab);
        memcpy(dst, host + h_sym->sh_offset, h_sym_count * sizeof(Sym));
        const char *h_strs = (const char *)(host + h_str->sh_offset);
        size_t weakened = 0, localized = 0;
        for (size_t i = 1; i < h_sym_count; i++) {
            unsigned bind = dst[i].st_info >> 4;
            unsigned type = dst[i].st_info & 0xf;
            if (dst[i].st_shndx == SHN_UNDEF && bind == 1 /* STB_GLOBAL */) {
                dst[i].st_info = (unsigned char)((2u /* STB_WEAK */ << 4) | type);
                weakened++;
            } else if (dst[i].st_shndx != SHN_UNDEF && bind == 1 /* STB_GLOBAL */) {
                const char *nm = h_strs + dst[i].st_name;
                if (strcmp(nm, "init_module") == 0 ||
                    strcmp(nm, "cleanup_module") == 0 ||
                    strcmp(nm, "__this_module") == 0)
                    continue;
                dst[i].st_info = (unsigned char)((0u /* STB_LOCAL */ << 4) | type);
                localized++;
            }
        }
        if (weakened || localized)
            vlog("graft: weakened %zu UNDEF + localized %zu GLOBAL host syms",
                 weakened, localized);

        const Sym *src = (const Sym *)(payload + p_sym->sh_offset);
        for (size_t i = 1; i < p_sym_count; i++) {
            int new_idx = p_new_symidx[i];
            if (new_idx < 0) continue;
            Sym s = src[i];
            if (s.st_shndx != SHN_UNDEF && s.st_shndx < SHN_LORESERVE
                && s.st_shndx < p_eh->e_shnum) {
                int mapped = p_new_shndx[s.st_shndx];
                s.st_shndx = (mapped >= 0) ? (uint16_t)mapped : (uint16_t)SHN_UNDEF;
            }
            s.st_name = (uint32_t)(h_str_size + s.st_name);
            dst[new_idx] = s;
        }
    }

    /* Payload data sections — copy raw bytes (rewrite r_info for rela). */
    for (uint16_t i = 0; i < p_eh->e_shnum; i++) {
        if (p_new_shndx[i] < 0) continue;
        const Shdr *sh = (const Shdr *)(payload + p_eh->e_shoff + (size_t)i * sizeof(Shdr));
        if (sh->sh_type == SHT_NOBITS) continue;
        if (sh->sh_type == SHT_RELA) {
            Rela *dst = (Rela *)(out + p_new_sh_offset[i]);
            const Rela *src = (const Rela *)(payload + sh->sh_offset);
            size_t n = sh->sh_size / sizeof(Rela);
            for (size_t k = 0; k < n; k++) {
                uint64_t type = ELF64_R_TYPE(src[k].r_info);
                uint64_t osym = ELF64_R_SYM(src[k].r_info);
                int nsym = (osym < p_sym_count) ? p_new_symidx[osym] : -1;
                if (nsym < 0) nsym = 0;   /* should not happen in practice */
                dst[k].r_offset = src[k].r_offset;
                dst[k].r_info   = ELF64_R_INFO((uint64_t)nsym, type);
                dst[k].r_addend = src[k].r_addend;
            }
        } else {
            memcpy(out + p_new_sh_offset[i], payload + sh->sh_offset, sh->sh_size);
        }
    }

    /* kallsyms_addr injection (optional): write the caller-provided value
     * into payload's kallsyms_addr storage.  The symbol is in payload's
     * .data section (not merged with host .data), so its file offset in
     * the output is p_new_sh_offset[st_shndx] + st_value.  8 bytes
     * (uint64_t).  If not provided, the value stays at 0 and
     * kernelhook_init will fail fast in kmod_compat_init — preserving
     * the old module-param semantics for operators who feed it via a
     * separate loader step. */
    if (have_kallsyms_addr) {
        int p_ks_idx = find_symbol_index(payload, p_sym, p_str, "kallsyms_addr");
        if (p_ks_idx < 0)
            die("payload: kallsyms_addr symbol not found (built without KH_PAYLOAD=1?)");
        const Sym *p_syms = (const Sym *)(payload + p_sym->sh_offset);
        uint64_t p_shndx = p_syms[p_ks_idx].st_shndx;
        if (p_shndx == SHN_UNDEF || p_shndx >= p_eh->e_shnum)
            die("payload kallsyms_addr has unexpected st_shndx %lu", (unsigned long)p_shndx);
        uint64_t p_off = p_new_sh_offset[p_shndx] + p_syms[p_ks_idx].st_value;
        if (p_off + sizeof(uint64_t) > out_cap)
            die("payload kallsyms_addr offset %lu past output end", (unsigned long)p_off);
        memcpy(out + p_off, &kallsyms_addr, sizeof(uint64_t));
        vlog("graft: injected kallsyms_addr = 0x%016llx at payload .data offset %lu",
             (unsigned long long)kallsyms_addr, (unsigned long)p_off);
    }

    /* kCFI hash copy: overwrite the 4 bytes immediately preceding kh_entry
     * and kh_exit with the vendor's init_module / cleanup_module hashes.
     *
     * Clang kCFI prefixes every indirect-call target with a 4-byte typeid
     * hash.  At `do_one_initcall(mod->init)` the kernel loads the 4 bytes
     * before `mod->init` and compares against the `initcall_t` typeid
     * embedded at the call site.  Our payload's clang (NDK) and the
     * vendor's clang (Android build server) disagree on what that hash
     * should be — payload emits 0x36b1c5a6 for `int(*)(void)` whereas the
     * running kernel expects 0x6fbb3035.  Mismatch triggers a CFI panic
     * the moment the kernel tries to invoke our kh_entry.
     *
     * The host's existing init_module / cleanup_module bytes are already
     * the "right" hashes (the running kernel accepted the same host .ko
     * before the graft).  Look up those 4-byte prefixes in host .text and
     * stamp them onto our kh_entry / kh_exit prefixes. */
    {
        const Sym *h_syms = (const Sym *)(host + h_sym->sh_offset);
        const Sym *p_syms = (const Sym *)(payload + p_sym->sh_offset);

        struct {
            const char *host_name;
            const char *payload_name;
        } kcfi_pairs[] = {
            { "init_module",    "kh_entry" },
            { "cleanup_module", "kh_exit" },
            { NULL, NULL }
        };

        for (int pair = 0; kcfi_pairs[pair].host_name; pair++) {
            int h_idx = find_symbol_index(host, h_sym, h_str, kcfi_pairs[pair].host_name);
            int p_idx = find_symbol_index(payload, p_sym, p_str, kcfi_pairs[pair].payload_name);
            if (h_idx < 0 || p_idx < 0) continue;

            /* Read host's 4-byte hash prefix (at st_value - 4 inside the
             * section that holds the host symbol).  Host bytes live in
             * the output buffer at the same file offset as in the input
             * (we copied host verbatim). */
            uint64_t h_shndx = h_syms[h_idx].st_shndx;
            if (h_shndx == SHN_UNDEF || h_shndx >= h_eh->e_shnum) continue;
            const Shdr *h_sec = (const Shdr *)(host + h_eh->e_shoff + h_shndx * sizeof(Shdr));
            if (h_syms[h_idx].st_value < 4) continue;
            uint64_t h_hash_off = h_sec->sh_offset + h_syms[h_idx].st_value - 4;
            if (h_hash_off + 4 > host_size) continue;
            uint32_t hash;
            memcpy(&hash, out + h_hash_off, 4);   /* read from our output copy of host bytes */

            /* Write the hash at the payload-side prefix location in our
             * output buffer.  Payload section data was copied to
             * p_new_sh_offset[payload_shndx]; within that region, the
             * symbol sits at st_value, so the 4-byte prefix is at
             * st_value - 4. */
            uint64_t p_shndx = p_syms[p_idx].st_shndx;
            if (p_shndx == SHN_UNDEF || p_shndx >= p_eh->e_shnum) continue;
            if (p_syms[p_idx].st_value < 4) continue;
            uint64_t p_hash_off = p_new_sh_offset[p_shndx] + p_syms[p_idx].st_value - 4;
            if (p_hash_off + 4 > out_cap) continue;
            memcpy(out + p_hash_off, &hash, 4);
            vlog("graft: stamped kCFI hash 0x%08x from host %s onto payload %s",
                 hash, kcfi_pairs[pair].host_name, kcfi_pairs[pair].payload_name);
        }
    }

    /* New section header table.  Host headers go first (indices 0..H-1);
     * payload headers go next (indices H..H+P-1). */
    {
        /* Host-side export tables: Android 15+ CONFIG_MODULE_SIG_PROTECT=y
         * rejects any unsigned module that exports a "protected" symbol
         * (protected-ness is a kernel-internal name list).  We stripped
         * the host's signature, so its original `lowpan_nhc_add` / `diag`
         * exports would trigger the check.
         *
         * Strategy — redirect rather than zero:
         *   - If the payload brings its own `__ksymtab` / `__ksymtab_gpl` /
         *     `__ksymtab_strings` / `__kcrctab` / `__kcrctab_gpl`, point the
         *     host's same-name section header at the payload's data (sh_offset
         *     and sh_size adopt the payload's).  Consumer modules loaded on
         *     top of the grafted .ko then see kh_hook_inline / kh_unhook /
         *     etc. via the kernel's `find_sec("__ksymtab")`.  KH-prefixed
         *     export names are not in the kernel's protected list, so
         *     SIG_PROTECT stays quiet.
         *   - If the payload does not bring the section (e.g. a minimal
         *     smoke payload), fall back to zeroing the host's header
         *     sh_size so the kernel sees zero entries.
         *
         * Per-symbol rela variants on Android 15+ (.rela___ksymtab+<name>)
         * and .export_symbol / its rela still get zeroed — they carry
         * host-owned exports we cannot safely present as our own, and our
         * payload's exports don't use that format. */
        static const char *const merge_section_names[] = {
            "__ksymtab", "__ksymtab_gpl", "__ksymtab_strings",
            "__kcrctab", "__kcrctab_gpl",
            NULL
        };
        static const char *const strip_prefixes[] = {
            ".export_symbol",
            ".rela.__ksymtab", ".rela.__kcrctab", ".rela.export_symbol",
            ".rela___ksymtab",      /* per-symbol rela on Android 15+ */
            ".rela___kcrctab",
            NULL
        };

        Shdr *sh_out = (Shdr *)(out + new_shoff);
        for (uint16_t i = 0; i < h_eh->e_shnum; i++) {
            Shdr s = *(const Shdr *)(host + h_eh->e_shoff + (size_t)i * sizeof(Shdr));
            if ((int)i == h_shstridx) {
                s.sh_offset = off_shstrtab;
                s.sh_size   = new_shstrtab_size;
            } else if ((int)i == h_stridx) {
                s.sh_offset = off_strtab;
                s.sh_size   = new_strtab_size;
            } else if ((int)i == h_symidx) {
                s.sh_offset = off_symtab;
                s.sh_size   = new_symtab_size;
                /* sh_link unchanged; sh_info (first global) unchanged — the
                 * appended payload syms are treated as globals by our
                 * convention and ST_BIND on each sym is honored. */
            } else {
                const char *nm = shstrtab_name(host, h_eh, s.sh_name);

                /* Try to merge: find a same-named section in payload and
                 * adopt its sh_offset/sh_size so kernel find_sec() reads
                 * payload's data through the host section header. */
                int merged = 0;
                for (int k = 0; merge_section_names[k]; k++) {
                    if (strcmp(nm, merge_section_names[k]) != 0) continue;
                    for (uint16_t pi = 0; pi < p_eh->e_shnum; pi++) {
                        const Shdr *psh = (const Shdr *)(payload + p_eh->e_shoff + (size_t)pi * sizeof(Shdr));
                        if (psh->sh_size == 0) continue;
                        const char *pname = (const char *)(payload + p_shstr_sh->sh_offset + psh->sh_name);
                        if (strcmp(pname, nm) != 0) continue;
                        s.sh_offset = p_new_sh_offset[pi];
                        s.sh_size   = psh->sh_size;
                        s.sh_addralign = psh->sh_addralign;
                        vlog("graft: redirected host [%u] '%s' -> payload (%lu bytes)",
                             i, nm, (unsigned long)psh->sh_size);
                        merged = 1;
                        break;
                    }
                    if (!merged) {
                        /* Payload doesn't have it — zero host's version. */
                        vlog("graft: zeroed host section [%u] '%s' (payload lacks it)",
                             i, nm);
                        s.sh_size = 0;
                    }
                    break;
                }

                if (!merged) {
                    /* Still a "strip-only" candidate (prefix match on known
                     * protected-export section families). */
                    for (int k = 0; strip_prefixes[k]; k++) {
                        size_t pl = strlen(strip_prefixes[k]);
                        if (strncmp(nm, strip_prefixes[k], pl) == 0) {
                            vlog("graft: zeroed host section [%u] '%s' (was %lu bytes)",
                                 i, nm, (unsigned long)s.sh_size);
                            s.sh_size = 0;
                            break;
                        }
                    }
                }
            }
            sh_out[i] = s;
        }
        for (uint16_t i = 0; i < p_eh->e_shnum; i++) {
            int new_idx = p_new_shndx[i];
            if (new_idx < 0) continue;
            const Shdr *src = (const Shdr *)(payload + p_eh->e_shoff + (size_t)i * sizeof(Shdr));
            Shdr s = *src;
            s.sh_name   = p_new_sh_name[i];
            s.sh_offset = (src->sh_type == SHT_NOBITS) ? 0 : p_new_sh_offset[i];
            if (src->sh_type == SHT_RELA) {
                s.sh_link = (uint32_t)h_symidx;    /* merged symtab */
                int mapped = (src->sh_info < p_eh->e_shnum)
                           ? p_new_shndx[src->sh_info] : -1;
                if (mapped < 0)
                    die("payload rela sh[%u]: target sh_info=%u maps to dropped section",
                        i, src->sh_info);
                s.sh_info = (uint32_t)mapped;
                s.sh_entsize = sizeof(Rela);
            }
            /* For non-rela data sections we keep sh_link/sh_info as-is.
             * They are zero for standard .text/.data/.rodata/.bss. */
            sh_out[new_idx] = s;
        }
    }

    /* Update ELF header */
    {
        Ehdr *eh_out = (Ehdr *)out;
        eh_out->e_shoff = new_shoff;
        eh_out->e_shnum = (uint16_t)new_shnum;
        /* e_shstrndx unchanged — still points at h_shstridx, whose
         * sh_offset we updated to the merged shstrtab. */
    }

    free(p_new_shndx);
    free(p_new_sh_offset);
    free(p_new_sh_name);
    free(p_new_symidx);

    *out_buf = out;
    *out_size = out_cap;
    return 0;
}
