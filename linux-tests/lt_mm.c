// lt_mm — the Linux memory-management syscalls a real program leans on:
// mmap (hint, MAP_FIXED, MAP_FIXED_NOREPLACE, file-backed, PROT_NONE),
// munmap and mprotect on parts of a mapping, madvise(MADV_DONTNEED), brk,
// thousands of small mappings, a large reserve touched sparsely, mremap,
// shared anonymous memory whole and in parts, a file cut short or unlinked
// under its mappings.
// Run by boot mode 19 (src/test/linux_selftest.zig); exit 0 = every check
// passed, else the number of the first failed check.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
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

static sigjmp_buf fault_jmp;

static void on_fault(int sig) {
    (void)sig;
    siglongjmp(fault_jmp, 1);
}

// 1 when reading (or, with `wr`, writing) *p raises SIGSEGV.
static int faults(volatile unsigned char *p, int wr) {
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_fault;
    sigaction(SIGSEGV, &sa, &old);
    int hit = 1;
    if (sigsetjmp(fault_jmp, 1) == 0) {
        if (wr)
            *p = *p;
        else
            (void)*p;
        hit = 0;
    }
    sigaction(SIGSEGV, &old, NULL);
    return hit;
}

// 1 when calling the code at p raises SIGSEGV.
static int call_faults(unsigned char *p) {
    struct sigaction sa, old;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_fault;
    sigaction(SIGSEGV, &sa, &old);
    int hit = 1;
    if (sigsetjmp(fault_jmp, 1) == 0) {
        ((void (*)(void))p)();
        hit = 0;
    }
    sigaction(SIGSEGV, &old, NULL);
    return hit;
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
    errno = 0;
    CHECK(madvise(a, PG, 9999) == -1 && errno == EINVAL, "madvise refuses advice it does not know");

    CHECK(munmap(a, 16 * PG) == 0, "munmap all");

    // /dev/zero maps as anonymous memory does: private pages of one's own,
    // shared ones a child's write shows up in.
    int zfd = open("/dev/zero", O_RDWR);
    CHECK(zfd >= 0, "open /dev/zero");
    unsigned char *z = mmap(NULL, 2 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE, zfd, 0);
    CHECK(z != MAP_FAILED && filled(z, 2 * PG, 0), "private /dev/zero mapping reads zero");
    z[0] = 9;
    CHECK(z[0] == 9 && munmap(z, 2 * PG) == 0, "and takes a write");
    z = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED, zfd, 0);
    CHECK(z != MAP_FAILED && z[0] == 0, "shared /dev/zero mapping");
    pid_t zc = fork();
    if (zc == 0) {
        z[0] = 7;
        _exit(0);
    }
    CHECK(zc > 0 && waitpid(zc, NULL, 0) == zc && z[0] == 7, "a child's write to it is seen");
    munmap(z, PG);
    close(zfd);

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

    // msync doubles as "is this mapped?" for a stack walker.
    unsigned char *ms = mmap(NULL, 2 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(ms != MAP_FAILED, "mmap for msync");
    CHECK(msync(ms, 2 * PG, MS_ASYNC) == 0, "msync of a mapped range");
    CHECK(munmap(ms + PG, PG) == 0, "unmap its second page");
    errno = 0;
    CHECK(msync(ms, 2 * PG, MS_ASYNC) == -1 && errno == ENOMEM, "msync across a hole is ENOMEM");
    CHECK(msync(ms, PG, MS_ASYNC) == 0 && munmap(ms, PG) == 0, "the first page alone is fine");

    // A file written through a shared mapping, the way a linker writes its
    // output: sized by ftruncate (all holes), filled through the mapping.
    size_t out_sz = 300 * PG + 123;
    int out = open("/ltmm.out", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(out >= 0 && ftruncate(out, (off_t)out_sz) == 0, "create and size a file");
    unsigned char *om = mmap(NULL, out_sz, PROT_READ | PROT_WRITE, MAP_SHARED, out, 0);
    CHECK(om != MAP_FAILED, "MAP_SHARED of the new file");
    for (size_t i = 0; i < out_sz; i += 61) om[i] = (unsigned char)(i * 13 + 1);
    CHECK(munmap(om, out_sz) == 0, "munmap of the shared mapping");
    ok = 1;
    for (size_t i = 0; i < out_sz && ok; i += 61 * 97) {
        unsigned char got = 0;
        ok = pread(out, &got, 1, (off_t)i) == 1 && got == (unsigned char)(i * 13 + 1);
    }
    CHECK(ok, "what the mapping wrote is in the file");
    close(out);
    CHECK(unlink("/ltmm.out") == 0, "remove the file");

    // A sparse file far bigger than anything cached: syncing it costs what
    // is dirty, not its size, and a page dirtied far in is still found.
    {
        int sp = open("/ltmm.sparse", O_CREAT | O_RDWR | O_TRUNC, 0644);
        CHECK(sp >= 0 && ftruncate(sp, (off_t)1 << 42) == 0, "size a sparse file to 4 TiB");
        CHECK(ftruncate(sp, (off_t)1 << 62) == -1 && errno == EFBIG, "a size no file can have is EFBIG");
        off_t far = (off_t)3 << 30;
        unsigned char *far_map = mmap(NULL, 2 * PG, PROT_READ | PROT_WRITE, MAP_SHARED, sp, far);
        CHECK(far_map != MAP_FAILED, "MAP_SHARED far into the sparse file");
        memcpy(far_map + 100, "far page", 8);
        CHECK(msync(far_map, 2 * PG, MS_SYNC) == 0 && fsync(sp) == 0, "msync and fsync of it return");
        CHECK(munmap(far_map, 2 * PG) == 0, "munmap of the far mapping");
        char back[8] = {0};
        CHECK(pread(sp, back, 8, far + 100) == 8 && memcmp(back, "far page", 8) == 0, "the far page reached the file");
        unsigned char gap = 1;
        CHECK(pread(sp, &gap, 1, far - 5) == 1 && gap == 0, "the hole beside it reads as zero");
        close(sp);
        CHECK(unlink("/ltmm.sparse") == 0, "remove the sparse file");
    }

    // A file's mappings and its read and write calls are one set of bytes:
    // what write puts into a page that is mapped shows in the mapping and
    // in a read, and no writeback of the mapping takes it back.
    {
        int fd = open("/ltmm.coh", O_CREAT | O_RDWR | O_TRUNC, 0644);
        unsigned char page[2 * PG];
        memset(page, 'x', sizeof page);
        CHECK(fd >= 0 && write(fd, page, sizeof page) == (ssize_t)sizeof page, "create a two-page file");
        unsigned char *ro = mmap(NULL, 2 * PG, PROT_READ, MAP_SHARED, fd, 0);
        CHECK(ro != MAP_FAILED && ro[100] == 'x', "a shared read-only mapping, its first page read");
        char back[8] = {0};
        CHECK(pwrite(fd, "NEWDATA", 7, 100) == 7 && pread(fd, back, 7, 100) == 7 && memcmp(back, "NEWDATA", 7) == 0,
              "a write into a mapped page is what a read returns");
        CHECK(memcmp(ro + 100, "NEWDATA", 7) == 0, "and what the mapping shows");
        CHECK(munmap(ro, 2 * PG) == 0, "munmap of the read-only mapping");

        unsigned char *pv = mmap(NULL, 2 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        CHECK(pv != MAP_FAILED && pv[PG + 5] == 'x', "a private mapping, its second page read");
        CHECK(pwrite(fd, "PRIV", 4, PG + 5) == 4 && memcmp(pv + PG + 5, "PRIV", 4) == 0,
              "a private page not yet written shows a later write to the file");
        CHECK(munmap(pv, 2 * PG) == 0, "munmap of the private mapping");

        unsigned char *rw = mmap(NULL, 2 * PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(rw != MAP_FAILED, "a shared writable mapping");
        memcpy(rw + 10, "MAPPED", 6);
        CHECK(pwrite(fd, "WRITTEN", 7, 200) == 7, "a write into a page the mapping dirtied");
        CHECK(msync(rw, 2 * PG, MS_SYNC) == 0 && munmap(rw, 2 * PG) == 0, "msync and munmap");
        close(fd);
        fd = open("/ltmm.coh", O_RDWR);
        char a6[6], b7[7], c7[7];
        CHECK(fd >= 0 && pread(fd, a6, 6, 10) == 6 && pread(fd, b7, 7, 200) == 7 && pread(fd, c7, 7, 100) == 7,
              "read the file back");
        CHECK(memcmp(a6, "MAPPED", 6) == 0 && memcmp(b7, "WRITTEN", 7) == 0 && memcmp(c7, "NEWDATA", 7) == 0,
              "the file holds what the mapping and the writes put there");

        // Cut short and grown again under a mapping that dirtied a page
        // past the cut: the file reads as zeros there.
        CHECK(ftruncate(fd, 16 * PG) == 0, "grow the file to 16 pages");
        rw = mmap(NULL, 16 * PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(rw != MAP_FAILED, "map all of it");
        memset(rw + 8 * PG, 'd', 64);
        memset(rw + PG / 2, 'e', PG / 2);
        CHECK(ftruncate(fd, PG / 2 + 100) == 0 && ftruncate(fd, 16 * PG) == 0, "cut it inside the first page and grow it back");
        unsigned char z[64];
        CHECK(pread(fd, z, 64, 8 * PG) == 64 && filled(z, 64, 0), "the page past the cut reads as zeros");
        CHECK(pread(fd, z, 64, PG / 2 + 100) == 64 && filled(z, 64, 0), "and so does the rest of the page the cut fell in");
        CHECK(pread(fd, z, 64, PG / 2) == 64 && filled(z, 64, 'e'), "what lay before the cut stays");
        CHECK(munmap(rw, 16 * PG) == 0, "munmap after the cut");
        CHECK(pread(fd, z, 64, 8 * PG) == 64 && filled(z, 64, 0), "still zeros once the mapping is gone");
        close(fd);
        CHECK(unlink("/ltmm.coh") == 0, "remove the file");
    }

    // A mapping that was there when the file was cut short is the file's
    // again once the file has grown back; so is another process's when the
    // file is emptied and written anew.
    {
        int fd = open("/ltmm.cut", O_CREAT | O_RDWR | O_TRUNC, 0644);
        CHECK(fd >= 0 && ftruncate(fd, 16 * PG) == 0, "a 16-page file to cut under a mapping");
        unsigned char *m = mmap(NULL, 16 * PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(m != MAP_FAILED, "map it shared");
        memset(m + 8 * PG, 'a', 64);
        CHECK(*(volatile unsigned char *)(m + 9 * PG) == 0, "one page written, the next one read");
        CHECK(ftruncate(fd, PG) == 0 && ftruncate(fd, 16 * PG) == 0, "cut it to one page and grow it back");
        CHECK(m[8 * PG] == 0 && m[8 * PG + 63] == 0, "the mapping reads zeros where it had written");
        memcpy(m + 8 * PG + 4, "MAP1", 4);
        char got[4] = {0};
        CHECK(pread(fd, got, 4, 8 * PG + 4) == 4 && memcmp(got, "MAP1", 4) == 0, "a store through it is what read returns");
        CHECK(pwrite(fd, "FILE", 4, 9 * PG + 8) == 4 && memcmp(m + 9 * PG + 8, "FILE", 4) == 0, "a write to the file shows in it");
        CHECK(msync(m, 16 * PG, MS_SYNC) == 0 && munmap(m, 16 * PG) == 0, "msync and munmap after the cut");
        CHECK(pread(fd, got, 4, 8 * PG + 4) == 4 && memcmp(got, "MAP1", 4) == 0, "the store stays in the file");

        unsigned char pages[4 * PG];
        memset(pages, 'A', sizeof pages);
        CHECK(ftruncate(fd, 0) == 0 && pwrite(fd, pages, sizeof pages, 0) == (ssize_t)sizeof pages, "the file anew, four pages of As");
        int go[2], ready[2];
        CHECK(pipe(go) == 0 && pipe(ready) == 0, "two pipes");
        pid_t c = fork();
        CHECK(c >= 0, "fork the one that maps it");
        if (c == 0) {
            char b;
            unsigned char *cm = mmap(NULL, 4 * PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (cm == MAP_FAILED || !filled(cm, 4 * PG, 'A')) _exit(1);
            if (write(ready[1], "r", 1) != 1 || read(go[0], &b, 1) != 1) _exit(2);
            if (!filled(cm, 4 * PG, 'B')) _exit(3);
            cm[2 * PG + 100] = 'C';
            _exit(0);
        }
        char b = 0;
        CHECK(read(ready[0], &b, 1) == 1, "it has the file mapped and read");
        memset(pages, 'B', sizeof pages);
        CHECK(ftruncate(fd, 0) == 0 && pwrite(fd, pages, sizeof pages, 0) == (ssize_t)sizeof pages, "empty the file and write four pages of Bs");
        CHECK(write(go[1], "g", 1) == 1, "let it look");
        int st = 0;
        CHECK(waitpid(c, &st, 0) == c, "wait for it");
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) printf("lt_mm: the mapper ended with status 0x%x\n", st);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "its mapping shows the new bytes");
        CHECK(pread(fd, &b, 1, 2 * PG + 100) == 1 && b == 'C', "and what it stored is in the file");
        close(go[0]);
        close(go[1]);
        close(ready[0]);
        close(ready[1]);
        close(fd);
        CHECK(unlink("/ltmm.cut") == 0, "remove the cut file");
    }

    // A mapping holds its file: with the name removed and the descriptor
    // closed the file is there under it, whatever new files are made, and
    // goes when its last mapping does.
    {
        int keep = open("/ltmm.fs", O_CREAT | O_RDWR | O_TRUNC, 0644);
        struct statfs sf;
        CHECK(keep >= 0 && fstatfs(keep, &sf) == 0, "a file to ask the file system through");
        long inodes = (long)sf.f_ffree;
        int fd = open("/ltmm.gone", O_CREAT | O_RDWR | O_TRUNC, 0644);
        CHECK(fd >= 0 && ftruncate(fd, 64 * PG) == 0, "a 64-page file");
        unsigned char *m = mmap(NULL, 64 * PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(m != MAP_FAILED, "map it shared");
        fill(m, 8 * PG, 0x31);
        CHECK(close(fd) == 0 && unlink("/ltmm.gone") == 0, "close it and remove its name");
        CHECK(fstatfs(keep, &sf) == 0 && (long)sf.f_ffree == inodes - 1, "its inode is still taken");
        // New files get the inode numbers and the blocks that are free.
        unsigned char junk[PG];
        memset(junk, 0xEE, PG);
        char name[32];
        int made = 1;
        for (int i = 0; i < 8; i++) {
            snprintf(name, sizeof name, "/ltmm.new%d", i);
            int nf = open(name, O_CREAT | O_RDWR | O_TRUNC, 0644);
            for (int k = 0; k < 16; k++) made &= nf >= 0 && write(nf, junk, PG) == (ssize_t)PG;
            if (nf >= 0) close(nf);
        }
        CHECK(made, "eight new files of 16 pages");
        CHECK(filled(m, 8 * PG, 0x31), "the pages written before are as they were");
        CHECK(filled(m + 8 * PG, 56 * PG, 0), "the pages not yet touched are the file's own: zeros");
        fill(m + 32 * PG, 8 * PG, 0x32);
        int go[2];
        CHECK(pipe(go) == 0, "a pipe");
        pid_t c = fork();
        CHECK(c >= 0, "fork with the mapping");
        if (c == 0) {
            char b;
            if (read(go[0], &b, 1) != 1) _exit(1);
            _exit(filled(m + 32 * PG, 8 * PG, 0x32) && filled(m + 40 * PG, 24 * PG, 0) ? 0 : 2);
        }
        CHECK(munmap(m, 16 * PG) == 0 && filled(m + 32 * PG, 8 * PG, 0x32), "a part unmapped, the rest is there");
        CHECK(munmap(m + 16 * PG, 48 * PG) == 0, "munmap the rest");
        CHECK(fstatfs(keep, &sf) == 0 && (long)sf.f_ffree == inodes - 9, "the child's mapping still holds the file");
        CHECK(write(go[1], "g", 1) == 1, "let the child look");
        int st = 0;
        CHECK(waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0, "the child read the file through its mapping");
        // The last mapping went with a process: the file goes soon after.
        int freed = 0;
        for (int waited = 0; waited < 100 && !freed; waited++) {
            freed = fstatfs(keep, &sf) == 0 && (long)sf.f_ffree == inodes - 8;
            if (!freed) usleep(100000);
        }
        CHECK(freed, "with the last mapping gone the inode is free again");
        close(go[0]);
        close(go[1]);

        // And at once when munmap takes the last mapping away.
        fd = open("/ltmm.gone", O_CREAT | O_RDWR | O_TRUNC, 0644);
        CHECK(fd >= 0 && ftruncate(fd, 4 * PG) == 0, "the file again, four pages");
        m = mmap(NULL, 4 * PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(m != MAP_FAILED, "map it shared");
        m[PG] = 7;
        CHECK(close(fd) == 0 && unlink("/ltmm.gone") == 0 && m[PG] == 7, "closed and unlinked, the mapping reads");
        CHECK(fstatfs(keep, &sf) == 0 && (long)sf.f_ffree == inodes - 9, "the inode is taken while it is mapped");
        CHECK(munmap(m, 4 * PG) == 0 && fstatfs(keep, &sf) == 0 && (long)sf.f_ffree == inodes - 8, "and free once it is unmapped");

        int removed = 1;
        for (int i = 0; i < 8; i++) {
            snprintf(name, sizeof name, "/ltmm.new%d", i);
            removed &= unlink(name) == 0;
        }
        close(keep);
        CHECK(removed && unlink("/ltmm.fs") == 0, "remove the new files");
    }

    // A hole read through shared mappings stays a hole; a store through a
    // mapping reaches the disk, also one that was read-only when its page
    // was read and made writable afterwards.
    {
        int fd = open("/ltmm.hole", O_CREAT | O_RDWR | O_TRUNC, 0644);
        CHECK(fd >= 0 && ftruncate(fd, 64 * PG) == 0, "a file that is one 64-page hole");
        unsigned char *ro = mmap(NULL, 64 * PG, PROT_READ, MAP_SHARED, fd, 0);
        unsigned char *rw = mmap(NULL, 64 * PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(ro != MAP_FAILED && rw != MAP_FAILED, "mapped shared twice, read-only and writable");
        CHECK(filled(ro, 32 * PG, 0) && filled(rw + 32 * PG, 32 * PG, 0), "all of it read through them: zeros");
        sleep(3); // the background writeback has come round
        struct stat sb;
        CHECK(msync(rw, 64 * PG, MS_SYNC) == 0 && fstat(fd, &sb) == 0, "msync, then its size on disk");
        if (sb.st_blocks != 0) printf("lt_mm: the hole takes %ld sectors after being read\n", (long)sb.st_blocks);
        CHECK(sb.st_blocks == 0, "reading a hole through mappings takes no blocks");
        CHECK(mprotect(ro, 64 * PG, PROT_READ | PROT_WRITE) == 0, "the read-only mapping made writable");
        ro[5 * PG] = 0x77;
        CHECK(munmap(ro, 64 * PG) == 0 && munmap(rw, 64 * PG) == 0 && fsync(fd) == 0, "a store through it; both unmapped; fsync");
        CHECK(fstat(fd, &sb) == 0, "its size on disk again");
        if (sb.st_blocks <= 0 || sb.st_blocks > 64) printf("lt_mm: one stored page takes %ld sectors\n", (long)sb.st_blocks);
        CHECK(sb.st_blocks > 0 && sb.st_blocks <= 64, "the store took a block and the hole around it none");
        unsigned char got = 0;
        CHECK(pread(fd, &got, 1, 5 * PG) == 1 && got == 0x77, "and is in the file");
        int rfd = open("/ltmm.hole", O_RDONLY);
        unsigned char *q = mmap(NULL, PG, PROT_READ, MAP_SHARED, rfd, 0);
        CHECK(rfd >= 0 && q != MAP_FAILED, "a shared mapping of the file opened read-only");
        CHECK(mprotect(q, PG, PROT_READ | PROT_WRITE) == -1 && errno == EACCES, "cannot be made writable: EACCES");
        CHECK(munmap(q, PG) == 0 && close(rfd) == 0, "unmap it");
        close(fd);
        CHECK(unlink("/ltmm.hole") == 0, "remove the hole file");
    }

    // A third of memory mapped shared from one file (a hole, so the disk is
    // not what limits it): every page maps, however many file pages the
    // system keeps cached of its own accord.
    {
        struct sysinfo si;
        CHECK(sysinfo(&si) == 0 && si.totalram > 0, "sysinfo for the size of memory");
        size_t big = (size_t)si.totalram * si.mem_unit / 3;
        if (big > (1UL << 30)) big = 1UL << 30;
        big &= ~(PG - 1);
        size_t pages = big / PG;
        int fd = open("/ltmm.big", O_CREAT | O_RDWR | O_TRUNC, 0644);
        CHECK(fd >= 0 && ftruncate(fd, (off_t)big) == 0, "a hole a third of memory long");
        unsigned char *m = mmap(NULL, big, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        CHECK(m != MAP_FAILED, "map all of it shared");
        int zeros = 1;
        for (size_t i = 0; i < pages; i++) zeros &= *(volatile unsigned char *)(m + i * PG) == 0;
        CHECK(zeros, "every page of it read through the mapping");
        m[0] = 1;
        m[(pages / 2) * PG] = 2;
        m[(pages - 1) * PG] = 3;
        unsigned char b3[3] = {0};
        CHECK(pread(fd, &b3[0], 1, 0) == 1 && pread(fd, &b3[1], 1, (off_t)((pages / 2) * PG)) == 1 &&
                  pread(fd, &b3[2], 1, (off_t)((pages - 1) * PG)) == 1 && b3[0] == 1 && b3[1] == 2 && b3[2] == 3,
              "three stores through it are what read returns");
        struct stat sb;
        CHECK(munmap(m, big) == 0 && fsync(fd) == 0 && fstat(fd, &sb) == 0, "munmap, fsync, its size on disk");
        // A file system may round what it allocates for a store up a good
        // deal (ext4 does); the hole as a whole stays one.
        long most = (long)(big / 512 / 8);
        if (sb.st_blocks <= 0 || sb.st_blocks >= most) printf("lt_mm: three stored pages of %zu take %ld sectors\n", pages, (long)sb.st_blocks);
        CHECK(sb.st_blocks > 0 && sb.st_blocks < most, "the three stored pages are on disk and the hole is still a hole");
        close(fd);
        CHECK(unlink("/ltmm.big") == 0, "remove the big file");
    }

    // Pages faulted in from the disk while another process keeps writing
    // the file: every fault ends, with the file's bytes.
    {
        enum { BUSY_PAGES = 1024 };
        int fd = open("/ltmm.busy", O_CREAT | O_RDWR | O_TRUNC, 0644);
        CHECK(fd >= 0, "create a file to read under a writer");
        unsigned char page[PG];
        int wrote = 1;
        for (int i = 0; i < BUSY_PAGES; i++) {
            memset(page, i * 7 + 1, PG);
            if (pwrite(fd, page, PG, (off_t)i * PG) != (ssize_t)PG) wrote = 0;
        }
        CHECK(wrote, "four megabytes written");
        pid_t writer = fork();
        CHECK(writer >= 0, "fork the writer");
        if (writer == 0) {
            // The byte page 0 has there already, over and over.
            unsigned char one = 1;
            for (;;) {
                if (pwrite(fd, &one, 1, 0) != 1) _exit(1);
            }
        }
        unsigned char *m = mmap(NULL, BUSY_PAGES * PG, PROT_READ, MAP_SHARED, fd, 0);
        CHECK(m != MAP_FAILED, "map it shared");
        int same = 1;
        for (int i = 0; i < BUSY_PAGES; i++) {
            if (*(volatile unsigned char *)(m + (size_t)i * PG + 5) != (unsigned char)(i * 7 + 1)) same = 0;
        }
        int st = 0;
        CHECK(kill(writer, SIGKILL) == 0 && waitpid(writer, &st, 0) == writer && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL,
              "the writer wrote until it was killed");
        CHECK(same, "pages faulted in under a steady writer are the file's");
        CHECK(munmap(m, BUSY_PAGES * PG) == 0, "munmap it");
        close(fd);
        CHECK(unlink("/ltmm.busy") == 0, "remove that file");
    }

    // mremap: shrink and grow in place, EFAULT where nothing is mapped.
    {
        unsigned char *m = map(NULL, 8 * PG, PROT_READ | PROT_WRITE, 0);
        CHECK(m != MAP_FAILED, "mmap for mremap");
        fill(m, 8 * PG, 0x33);
        CHECK(mremap(m, 8 * PG, 4 * PG, 0) == m, "mremap shrinks in place");
        CHECK(filled(m, 4 * PG, 0x33), "mremap shrink keeps the front");
        void *again = map(m + 4 * PG, 4 * PG, PROT_READ, MAP_FIXED_NOREPLACE);
        CHECK(again == m + 4 * PG, "mremap shrink freed the tail");
        CHECK(munmap(again, 4 * PG) == 0, "unmap the tail again");
        CHECK(mremap(m, 4 * PG, 6 * PG, 0) == m, "mremap grows in place into free pages");
        CHECK(filled(m, 4 * PG, 0x33) && filled(m + 4 * PG, 2 * PG, 0), "the grown part reads as zero");
        void *wall = map(m + 6 * PG, PG, PROT_READ, MAP_FIXED_NOREPLACE);
        CHECK(wall == m + 6 * PG, "a mapping right above");
        errno = 0;
        CHECK(mremap(m, 6 * PG, 8 * PG, 0) == MAP_FAILED && errno == ENOMEM, "no room to grow in place is ENOMEM");
        CHECK(munmap(m, 7 * PG) == 0, "unmap both");
        errno = 0;
        CHECK(mremap(m, PG, 2 * PG, 0) == MAP_FAILED && errno == EFAULT, "mremap of an unmapped page is EFAULT");
        // musl walks the main thread's stack this way.
        pthread_attr_t attr;
        void *stack_addr;
        size_t stack_size = 0;
        CHECK(pthread_getattr_np(pthread_self(), &attr) == 0, "pthread_getattr_np of the main thread");
        CHECK(pthread_attr_getstack(&attr, &stack_addr, &stack_size) == 0 && stack_size >= 64 * 1024 &&
                  stack_size <= ((size_t)1 << 30), "the main stack has a sane size");
        pthread_attr_destroy(&attr);
    }

    // PROT_NONE over pages already there: no access reaches them, from the
    // program or through the kernel, and they come back as they were.
    {
        unsigned char *n = map(NULL, 4 * PG, PROT_READ | PROT_WRITE, 0);
        CHECK(n != MAP_FAILED, "mmap for PROT_NONE");
        fill(n, 4 * PG, 0x6B);
        CHECK(mprotect(n + PG, 2 * PG, PROT_NONE) == 0, "PROT_NONE over two touched pages");
        CHECK(faults(n + PG, 0) && faults(n + 2 * PG, 1), "a read and a write of them fault");
        CHECK(!faults(n, 0) && !faults(n + 3 * PG, 1) && n[3 * PG] == 0x6B, "the neighbors do not");
        int pp[2];
        CHECK(pipe(pp) == 0, "pipe");
        errno = 0;
        CHECK(write(pp[1], n + PG, 16) == -1 && errno == EFAULT, "write() from them is EFAULT");
        errno = 0;
        CHECK(write(pp[1], "x", 1) == 1 && read(pp[0], n + 2 * PG, 1) == -1 && errno == EFAULT, "read() into them is EFAULT");
        close(pp[0]);
        close(pp[1]);
        CHECK(mprotect(n + PG, 2 * PG, PROT_READ) == 0, "back to read-only");
        CHECK(filled(n, 4 * PG, 0x6B) && faults(n + PG, 1), "the bytes are there, and a write still faults");
        CHECK(mprotect(n + PG, PG, PROT_NONE) == 0 && munmap(n, 4 * PG) == 0, "unmap with a page held by PROT_NONE");
    }

    // A page that was read-only (or PROT_NONE) at fork and is made writable
    // after: each side still has its own.
    {
        unsigned char *s = map(NULL, 2 * PG, PROT_READ | PROT_WRITE, 0);
        CHECK(s != MAP_FAILED, "mmap for fork");
        fill(s, 2 * PG, 0x41);
        CHECK(mprotect(s, PG, PROT_READ) == 0 && mprotect(s + PG, PG, PROT_NONE) == 0, "one page read-only, one PROT_NONE");
        int go[2], done[2];
        CHECK(pipe(go) == 0 && pipe(done) == 0, "pipes");
        pid_t kid = fork();
        CHECK(kid >= 0, "fork");
        if (kid == 0) {
            char c;
            if (read(go[0], &c, 1) != 1) _exit(10);
            if (mprotect(s, 2 * PG, PROT_READ | PROT_WRITE) != 0) _exit(11);
            if (s[0] != 0x41 || s[PG] != 0x41) _exit(12); // the parent's 0x42 reached us
            s[0] = s[PG] = 0x43;
            if (write(done[1], "k", 1) != 1) _exit(13);
            if (read(go[0], &c, 1) != 1) _exit(14);
            _exit(0);
        }
        CHECK(mprotect(s, 2 * PG, PROT_READ | PROT_WRITE) == 0, "writable again in the parent");
        s[0] = s[PG] = 0x42;
        char c;
        CHECK(write(go[1], "p", 1) == 1 && read(done[0], &c, 1) == 1, "the child looked and wrote");
        CHECK(s[0] == 0x42 && s[PG] == 0x42, "the child's writes stayed in the child");
        int st = -1;
        CHECK(write(go[1], "p", 1) == 1 && waitpid(kid, &st, 0) == kid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
              "the child saw its own copy");
        close(go[0]), close(go[1]), close(done[0]), close(done[1]);
        CHECK(munmap(s, 2 * PG) == 0, "unmap after the fork");
    }

    // Code runs only from a page that allows it: a call into a data page,
    // private or shared, is SIGSEGV, and returns once mprotect allows it.
    {
        unsigned char *x = map(NULL, PG, PROT_READ | PROT_WRITE, 0);
        unsigned char *sh = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        CHECK(x != MAP_FAILED && sh != MAP_FAILED, "mmap for a call");
        x[0] = sh[0] = 0xC3; // ret
        CHECK(call_faults(x) && call_faults(sh), "a call into a data page faults");
        CHECK(mprotect(x, PG, PROT_READ | PROT_EXEC) == 0 && !call_faults(x), "and returns once the page is executable");
        CHECK(munmap(x, PG) == 0 && munmap(sh, PG) == 0, "unmap after the call");
    }

    // Shared anonymous memory: a large mapping touched sparsely, the same
    // pages in a child, munmap and mprotect on parts of it. Byte 0 of
    // megabyte k holds k + 1.
    {
        const size_t M = 1UL << 20, len = 64 * M;
        unsigned char *s = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        CHECK(s != MAP_FAILED, "64 MB shared anon mmap");
        int zero = 1;
        for (size_t i = 0; i < len; i += M) {
            if (s[i] != 0) zero = 0;
            s[i] = (unsigned char)(i / M + 1);
        }
        CHECK(zero, "shared anon zero filled");
        pid_t kid = fork();
        CHECK(kid >= 0, "fork with a shared mapping");
        if (kid == 0) {
            for (size_t i = 0; i < len; i += M)
                if (s[i] != (unsigned char)(i / M + 1)) _exit(1);
            // A page the parent wrote, and two nobody touched yet.
            s[0] = 0xAA, s[5 * PG] = 0xCC, s[len - PG] = 0xBB;
            _exit(0);
        }
        int st = -1;
        CHECK(waitpid(kid, &st, 0) == kid && WIFEXITED(st) && WEXITSTATUS(st) == 0, "the child reads the parent's shared pages");
        CHECK(s[0] == 0xAA && s[5 * PG] == 0xCC && s[len - PG] == 0xBB, "and its writes reach the parent");

        CHECK(munmap(s + 8 * M, 8 * M) == 0, "munmap the middle of a shared mapping");
        CHECK(s[7 * M] == 8 && s[16 * M] == 17, "the pages on both sides stay");
        CHECK(faults(s + 8 * M, 0) && faults(s + 16 * M - PG, 0), "the hole faults");
        CHECK(mprotect(s + 32 * M, 4 * M, PROT_READ) == 0, "mprotect part of a shared mapping");
        CHECK(s[32 * M] == 33 && faults(s + 32 * M, 1) && !faults(s + 36 * M, 1) && !faults(s + 32 * M - PG, 1),
              "only that part is read-only");
        // Dropped and faulted in again, each piece finds its own pages.
        CHECK(madvise(s + 16 * M, 16 * M, MADV_DONTNEED) == 0 && madvise(s + 32 * M, 4 * M, MADV_DONTNEED) == 0 &&
                  madvise(s + 36 * M, 28 * M, MADV_DONTNEED) == 0,
              "MADV_DONTNEED on the pieces");
        int same = 1;
        for (size_t i = 16 * M; i < len; i += M)
            if (s[i] != (unsigned char)(i / M + 1)) same = 0;
        CHECK(same && s[len - PG] == 0xBB, "a shared page keeps its bytes through MADV_DONTNEED");
        kid = fork();
        CHECK(kid >= 0, "fork with the pieces");
        if (kid == 0) {
            if (s[16 * M] != 17 || s[40 * M] != 41 || s[len - PG] != 0xBB) _exit(1);
            s[16 * M] = 0x99, s[40 * M + PG] = 0x22;
            _exit(0);
        }
        CHECK(waitpid(kid, &st, 0) == kid && WIFEXITED(st) && WEXITSTATUS(st) == 0, "a child of the pieces sees the same pages");
        CHECK(s[16 * M] == 0x99 && s[40 * M + PG] == 0x22, "and they are still shared");
        CHECK(munmap(s, 4 * M) == 0 && s[4 * M] == 5 && faults(s, 0), "munmap the head of a shared mapping");
        CHECK(munmap(s + 60 * M, 4 * M) == 0 && s[59 * M] == 60 && faults(s + 60 * M, 0), "and the tail");
        CHECK(munmap(s, len) == 0 && faults(s + 4 * M, 0) && faults(s + 59 * M, 0), "unmap what is left of it");

        // More shared mappings than a handful, each its own memory.
        enum { N = 2000 };
        static unsigned char *m[N];
        int ok = 1;
        for (int i = 0; i < N && ok; i++) {
            m[i] = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
            if (m[i] == MAP_FAILED)
                ok = 0;
            else
                m[i][0] = (unsigned char)i, m[i][PG - 1] = (unsigned char)(i >> 8);
        }
        CHECK(ok, "2000 shared anon mappings");
        for (int i = 0; i < N; i++)
            if (m[i][0] != (unsigned char)i || m[i][PG - 1] != (unsigned char)(i >> 8)) ok = 0;
        CHECK(ok, "each with its own page");
        for (int i = 0; i < N; i++)
            if (munmap(m[i], PG) != 0) ok = 0;
        CHECK(ok, "and unmapped");

        // Far more than there is memory for: refused.
        errno = 0;
        CHECK(mmap(NULL, 1UL << 45, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED && errno == ENOMEM,
              "a 32 TB shared mapping is ENOMEM");
    }

    printf("lt_mm: PASS (%d checks)\n", check_no);
    return 0;
}
