// lt_mm — the Linux memory-management syscalls a real program leans on:
// mmap (hint, MAP_FIXED, MAP_FIXED_NOREPLACE, file-backed, PROT_NONE),
// munmap and mprotect on parts of a mapping, madvise(MADV_DONTNEED), brk,
// thousands of small mappings, and a large reserve touched sparsely.
// Run by boot mode 19 (src/test/linux_selftest.zig); exit 0 = every check
// passed, else the number of the first failed check.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define PG 4096UL

static int check_no;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        check_no++;                                                          \
        if (!(cond)) {                                                       \
            printf("lt_mm: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                  \
        }                                                                    \
    } while (0)

static void *map(void *hint, size_t len, int prot, int flags) {
    return mmap(hint, len, prot, flags | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static void fill(unsigned char *p, size_t len, unsigned char v) {
    for (size_t i = 0; i < len; i += PG) p[i] = v;
}

static int filled(const unsigned char *p, size_t len, unsigned char v) {
    for (size_t i = 0; i < len; i += PG)
        if (p[i] != v) return 0;
    return 1;
}

int main(void) {
    // Anonymous mapping: zero-filled, writable.
    unsigned char *a = map(NULL, 16 * PG, PROT_READ | PROT_WRITE, 0);
    CHECK(a != MAP_FAILED, "anon mmap");
    CHECK(((uintptr_t)a & (PG - 1)) == 0, "anon mmap page aligned");
    CHECK(filled(a, 16 * PG, 0), "anon mmap zero filled");
    fill(a, 16 * PG, 0x5A);
    CHECK(filled(a, 16 * PG, 0x5A), "anon mmap writable");

    // munmap of the middle punches a hole: MAP_FIXED_NOREPLACE fits exactly
    // there and nowhere that is still mapped.
    CHECK(munmap(a + 4 * PG, 2 * PG) == 0, "munmap middle");
    CHECK(filled(a, 4 * PG, 0x5A) && filled(a + 6 * PG, 10 * PG, 0x5A), "munmap middle keeps the rest");
    void *h = map(a + 4 * PG, 2 * PG, PROT_READ | PROT_WRITE, MAP_FIXED_NOREPLACE);
    CHECK(h == a + 4 * PG, "hole reusable");
    CHECK(filled(h, 2 * PG, 0), "hole comes back zeroed");
    errno = 0;
    void *clash = map(a + 7 * PG, PG, PROT_READ, MAP_FIXED_NOREPLACE);
    CHECK(clash == MAP_FAILED && errno == EEXIST, "MAP_FIXED_NOREPLACE refuses a mapped page");

    // MAP_FIXED replaces what was there.
    void *f = map(a + 8 * PG, 2 * PG, PROT_READ | PROT_WRITE, MAP_FIXED);
    CHECK(f == a + 8 * PG, "MAP_FIXED lands where asked");
    CHECK(filled(a + 8 * PG, 2 * PG, 0) && filled(a + 10 * PG, 6 * PG, 0x5A), "MAP_FIXED replaced only its range");

    // mprotect on a part: the rest stays writable.
    CHECK(mprotect(a + 12 * PG, PG, PROT_READ) == 0, "mprotect one page read-only");
    a[11 * PG] = 1;
    a[13 * PG] = 2;
    CHECK(a[11 * PG] == 1 && a[13 * PG] == 2 && a[12 * PG] == 0x5A, "mprotect left neighbors writable");
    CHECK(mprotect(a + 12 * PG, PG, PROT_READ | PROT_WRITE) == 0, "mprotect back to read-write");
    a[12 * PG] = 3;
    CHECK(a[12 * PG] == 3, "page writable again");
    errno = 0;
    CHECK(mprotect(a + 4 * PG - PG, 4 * PG, PROT_READ) == 0, "mprotect across the refilled hole");
    CHECK(mprotect(a, 16 * PG, PROT_READ | PROT_WRITE) == 0, "mprotect whole range back");

    // madvise(MADV_DONTNEED) on private anonymous memory reads back zero.
    fill(a, 16 * PG, 0x77);
    CHECK(madvise(a + 2 * PG, 2 * PG, MADV_DONTNEED) == 0, "madvise DONTNEED");
    CHECK(filled(a + 2 * PG, 2 * PG, 0) && filled(a, 2 * PG, 0x77) && filled(a + 4 * PG, 12 * PG, 0x77), "DONTNEED zeroed only its range");

    CHECK(munmap(a, 16 * PG) == 0, "munmap all");

    // A free hint is honored.
    unsigned char *probe = map(NULL, 4 * PG, PROT_READ | PROT_WRITE, 0);
    CHECK(probe != MAP_FAILED, "probe mmap");
    CHECK(munmap(probe, 4 * PG) == 0, "probe munmap");
    unsigned char *hinted = map(probe, 4 * PG, PROT_READ | PROT_WRITE, 0);
    CHECK(hinted == probe, "free hint honored");
    CHECK(munmap(hinted, 4 * PG) == 0, "hinted munmap");

    // PROT_NONE reserve, then mprotect a window into use (how allocators and
    // thread stacks with guard pages do it).
    unsigned char *res = map(NULL, 64 * PG, PROT_NONE, 0);
    CHECK(res != MAP_FAILED, "PROT_NONE reserve");
    CHECK(mprotect(res + 8 * PG, 8 * PG, PROT_READ | PROT_WRITE) == 0, "commit a window");
    fill(res + 8 * PG, 8 * PG, 9);
    CHECK(filled(res + 8 * PG, 8 * PG, 9), "window usable");
    CHECK(munmap(res, 64 * PG) == 0, "reserve munmap");

    // Many small mappings, freed in an interleaved order.
    enum { N = 3000 };
    static unsigned char *many[N];
    for (int i = 0; i < N; i++) {
        many[i] = map(NULL, PG, PROT_READ | PROT_WRITE, 0);
        if (many[i] == MAP_FAILED) break;
        many[i][0] = (unsigned char)i;
    }
    CHECK(many[N - 1] != MAP_FAILED && many[N - 1] != NULL, "3000 small mmaps");
    int ok = 1;
    for (int i = 0; i < N; i++) ok &= many[i][0] == (unsigned char)i;
    CHECK(ok, "3000 mappings keep their contents");
    for (int i = 0; i < N; i += 2) ok &= munmap(many[i], PG) == 0;
    for (int i = 1; i < N; i += 2) ok &= munmap(many[i], PG) == 0;
    CHECK(ok, "3000 munmaps");

    // A large reserve touched sparsely costs only the pages touched.
    size_t big = (size_t)1 << 30;
    unsigned char *g = map(NULL, big, PROT_READ | PROT_WRITE, MAP_NORESERVE);
    CHECK(g != MAP_FAILED, "1 GiB mmap");
    for (size_t off = 0; off < big; off += big / 16) g[off] = 0x42;
    ok = 1;
    for (size_t off = 0; off < big; off += big / 16) ok &= g[off] == 0x42;
    CHECK(ok, "1 GiB mapping sparse touch");
    CHECK(munmap(g, big) == 0, "1 GiB munmap");

    // brk grows and shrinks the heap after the program image. Raw syscalls:
    // musl's sbrk refuses nonzero increments (its malloc owns the break).
    uintptr_t b0 = (uintptr_t)syscall(SYS_brk, 0);
    CHECK(b0 != 0, "brk(0)");
    unsigned char *hp = (unsigned char *)((b0 + PG - 1) & ~(PG - 1));
    uintptr_t top = (uintptr_t)hp + 8 * PG;
    CHECK((uintptr_t)syscall(SYS_brk, top) == top, "brk grow");
    fill(hp, 8 * PG, 0x33);
    CHECK(filled(hp, 8 * PG, 0x33), "brk memory writable");
    CHECK((uintptr_t)syscall(SYS_brk, top - 4 * PG) == top - 4 * PG, "brk shrink");
    CHECK((uintptr_t)syscall(SYS_brk, top) == top && filled(hp + 4 * PG, 4 * PG, 0) && filled(hp, 4 * PG, 0x33),
          "brk regrow reads zero above the old break");
    CHECK((uintptr_t)syscall(SYS_brk, PG) == top, "brk below the image fails");
    CHECK((uintptr_t)syscall(SYS_brk, b0) == b0, "brk back to the start");

    // File-backed private mapping reads the file; writes stay private.
    int fd = open("/etc/motd", O_RDONLY);
    CHECK(fd >= 0, "open /etc/motd");
    char buf[64] = {0};
    ssize_t n = read(fd, buf, sizeof buf - 1);
    CHECK(n > 0, "read /etc/motd");
    char *fm = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(fm != MAP_FAILED, "file mmap");
    CHECK(memcmp(fm, buf, (size_t)n) == 0, "file mmap matches read()");
    fm[0] ^= 1;
    char again[64] = {0};
    CHECK(pread(fd, again, sizeof again - 1, 0) == n && memcmp(again, buf, (size_t)n) == 0, "private write didn't reach the file");
    CHECK(munmap(fm, PG) == 0, "file munmap");
    close(fd);

    // realloc of a large block keeps its bytes (musl may use mremap or
    // fall back to copying).
    size_t sz = 1 << 20;
    unsigned char *r = malloc(sz);
    CHECK(r != NULL, "malloc 1 MiB");
    for (size_t i = 0; i < sz; i += 997) r[i] = (unsigned char)(i * 7);
    r = realloc(r, 4 * sz);
    CHECK(r != NULL, "realloc to 4 MiB");
    ok = 1;
    for (size_t i = 0; i < sz; i += 997) ok &= r[i] == (unsigned char)(i * 7);
    CHECK(ok, "realloc kept the bytes");
    free(r);

    printf("lt_mm: PASS (%d checks)\n", check_no);
    return 0;
}
