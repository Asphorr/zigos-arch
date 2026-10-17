// lt_fs — the file-system calls a compiler's cache makes: names relative to
// directory fds (openat, mkdirat, fstatat, statx, faccessat, unlinkat,
// renameat2), getdents64 with long names, ftruncate both ways, rename of
// files and of directories across parents, preadv/pwritev, copy_file_range,
// flock and fsync. Works under /ltfs, which it removes first and last.
// Exit 0 = every check passed, else the number of the first failed check.

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static int check_no;

#define CHECK(cond, what)                                                     \
    do {                                                                      \
        check_no++;                                                           \
        if (!(cond)) {                                                        \
            printf("lt_fs: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                   \
        }                                                                     \
    } while (0)

#define ROOT "/ltfs"
#define LONG_NAME "a_file_name_well_past_thirty_two_characters.txt"

static void remove_tree(int dirfd, const char *name) {
    int fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY);
    if (fd < 0) {
        unlinkat(dirfd, name, 0);
        return;
    }
    DIR *d = fdopendir(fd);
    struct dirent *e;
    while (d && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        if (e->d_type == DT_DIR)
            remove_tree(fd, e->d_name);
        else
            unlinkat(fd, e->d_name, 0);
    }
    if (d) closedir(d);
    unlinkat(dirfd, name, AT_REMOVEDIR);
}

static off_t size_at(int dirfd, const char *name) {
    struct stat st;
    if (fstatat(dirfd, name, &st, 0) != 0) return -1;
    return st.st_size;
}

static int all_zero(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i]) return 0;
    return 1;
}

static int lists(int dirfd, const char *name) {
    int fd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY);
    DIR *d = fdopendir(fd);
    int found = 0;
    struct dirent *e;
    while (d && (e = readdir(d)) != NULL) found |= strcmp(e->d_name, name) == 0;
    if (d) closedir(d);
    return found;
}

static unsigned char big[100000];
static unsigned char back[200000];

int main(void) {
    remove_tree(AT_FDCWD, ROOT);
    CHECK(mkdir(ROOT, 0755) == 0, "mkdir " ROOT);
    errno = 0;
    CHECK(mkdir(ROOT, 0755) == -1 && errno == EEXIST, "mkdir of an existing name is EEXIST");
    int d = open(ROOT, O_RDONLY | O_DIRECTORY);
    CHECK(d >= 0, "open a directory fd");

    // Names relative to the directory fd.
    CHECK(mkdirat(d, "sub", 0755) == 0, "mkdirat");
    errno = 0;
    CHECK(mkdirat(d, "sub", 0755) == -1 && errno == EEXIST, "mkdirat again is EEXIST");
    errno = 0;
    CHECK(mkdirat(d, "nope/deeper", 0755) == -1 && errno == ENOENT, "mkdirat under a missing directory is ENOENT");
    int f = openat(d, "sub/a.txt", O_CREAT | O_RDWR | O_EXCL, 0644);
    CHECK(f >= 0, "openat O_CREAT|O_EXCL");
    CHECK(write(f, "hello", 5) == 5, "write");
    errno = 0;
    CHECK(openat(d, "sub/a.txt", O_CREAT | O_RDWR | O_EXCL, 0644) == -1 && errno == EEXIST, "O_EXCL on an existing file is EEXIST");
    errno = 0;
    CHECK(openat(d, "sub/missing", O_RDONLY) == -1 && errno == ENOENT, "openat of nothing is ENOENT");
    errno = 0;
    CHECK(openat(d, "sub/a.txt", O_RDONLY | O_DIRECTORY) == -1 && errno == ENOTDIR, "O_DIRECTORY on a file is ENOTDIR");
    errno = 0;
    CHECK(openat(d, "sub", O_WRONLY) == -1 && errno == EISDIR, "writing a directory is EISDIR");
    int sub = openat(d, "sub", O_RDONLY | O_DIRECTORY | O_PATH);
    CHECK(sub >= 0, "openat a directory with O_PATH");

    struct stat st;
    CHECK(fstatat(d, "sub/a.txt", &st, 0) == 0 && st.st_size == 5 && S_ISREG(st.st_mode), "fstatat through the dirfd");
    CHECK(fstatat(sub, "a.txt", &st, 0) == 0 && st.st_size == 5, "fstatat through a nested dirfd");
    struct stat st_sub;
    CHECK(fstatat(d, "sub", &st_sub, 0) == 0 && S_ISDIR(st_sub.st_mode), "fstatat of a directory");
    CHECK(fstatat(sub, "", &st, AT_EMPTY_PATH) == 0 && st.st_ino == st_sub.st_ino, "AT_EMPTY_PATH stats the fd");
    struct statx sx;
    CHECK(statx(d, "sub/a.txt", 0, STATX_BASIC_STATS, &sx) == 0 && sx.stx_size == 5 && S_ISREG(sx.stx_mode), "statx");
    struct stat st_a;
    CHECK(fstatat(d, "sub/a.txt", &st_a, 0) == 0, "fstatat a.txt");
    CHECK(statx(f, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &sx) == 0 && sx.stx_size == 5 && sx.stx_ino == st_a.st_ino, "statx of an fd");
    CHECK(faccessat(d, "sub/a.txt", F_OK, 0) == 0, "faccessat");
    errno = 0;
    CHECK(faccessat(d, "sub/nothing", F_OK, 0) == -1 && errno == ENOENT, "faccessat of nothing is ENOENT");

    // ftruncate both ways, across the direct-block boundary (48 KiB).
    for (size_t i = 0; i < sizeof big; i++) big[i] = (unsigned char)(i * 7 + 1);
    CHECK(pwrite(f, big, sizeof big, 0) == (ssize_t)sizeof big, "pwrite 100000 bytes");
    CHECK(ftruncate(f, 60000) == 0 && size_at(d, "sub/a.txt") == 60000, "ftruncate down");
    CHECK(ftruncate(f, 200000) == 0 && size_at(d, "sub/a.txt") == 200000, "ftruncate up");
    CHECK(pread(f, back, 200000, 0) == 200000, "pread it all");
    CHECK(memcmp(back, big, 60000) == 0, "the kept part is intact");
    CHECK(all_zero(back + 60000, 140000), "the regrown part reads zeros");
    CHECK(ftruncate(f, 3) == 0 && pread(f, back, 10, 0) == 3 && memcmp(back, big, 3) == 0, "ftruncate to 3 bytes");
    CHECK(ftruncate(f, 0) == 0 && size_at(d, "sub/a.txt") == 0, "ftruncate to empty");
    CHECK(pwrite(f, "hello", 5, 0) == 5, "pwrite hello");

    // Vectored and positioned I/O, file-to-file copies.
    struct iovec wv[2] = {{(void *)"abc", 3}, {(void *)"defg", 4}};
    CHECK(pwritev(f, wv, 2, 5) == 7, "pwritev");
    char r1[4] = {0}, r2[8] = {0};
    struct iovec rv[2] = {{r1, 3}, {r2, 7}};
    CHECK(preadv(f, rv, 2, 2) == 10 && memcmp(r1, "llo", 3) == 0 && memcmp(r2, "abcdefg", 7) == 0, "preadv");
    int g = openat(sub, "copy.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(g >= 0, "openat a copy target");
    off_t in_off = 5, out_off = 0;
    CHECK(copy_file_range(f, &in_off, g, &out_off, 7, 0) == 7 && in_off == 12 && out_off == 7, "copy_file_range between files");
    CHECK(pread(g, back, 16, 0) == 7 && memcmp(back, "abcdefg", 7) == 0, "... copies the bytes");
    in_off = 0;
    out_off = 12;
    CHECK(copy_file_range(f, &in_off, f, &out_off, 5, 0) == 5 && pread(f, back, 17, 0) == 17 && memcmp(back + 12, "hello", 5) == 0,
          "copy_file_range within a file");
    CHECK(flock(f, LOCK_EX) == 0 && flock(f, LOCK_UN) == 0 && flock(f, LOCK_SH | LOCK_NB) == 0, "flock");
    CHECK(fsync(f) == 0 && fdatasync(g) == 0, "fsync");
    close(g);
    close(f);

    // Long names through getdents64.
    int l = openat(d, LONG_NAME, O_CREAT | O_WRONLY, 0644);
    CHECK(l >= 0, "create a long name");
    close(l);
    CHECK(lists(d, LONG_NAME) && lists(d, "sub") && lists(d, ".") && lists(d, ".."), "readdir lists every name in full");

    // Renames: a file, a file over another, a directory across parents.
    CHECK(renameat(d, "sub/a.txt", d, "sub/b.txt") == 0, "renameat");
    errno = 0;
    CHECK(fstatat(d, "sub/a.txt", &st, 0) == -1 && errno == ENOENT && size_at(d, "sub/b.txt") == 17, "the file moved");
    CHECK(rename(ROOT "/sub/copy.txt", ROOT "/sub/b.txt") == 0 && size_at(d, "sub/b.txt") == 7, "rename replaces a file");
    CHECK(syscall(SYS_renameat2, d, LONG_NAME, d, "sub/b.txt", 1 /* RENAME_NOREPLACE */) == -1 && errno == EEXIST,
          "RENAME_NOREPLACE refuses an existing target");
    CHECK(mkdirat(d, "x", 0755) == 0 && mkdirat(d, "x/inner", 0755) == 0, "mkdirat x/inner");
    int in = openat(d, "x/inner/file", O_CREAT | O_WRONLY, 0644);
    CHECK(in >= 0, "create x/inner/file");
    close(in);
    int inner = openat(d, "x/inner", O_RDONLY | O_DIRECTORY);
    CHECK(inner >= 0, "open x/inner");
    errno = 0;
    CHECK(renameat(d, "x", d, "x/inner/x") == -1 && errno == EINVAL, "a directory can't move under itself");
    CHECK(renameat(d, "x/inner", d, "sub/inner") == 0, "rename a directory to another parent");
    CHECK(faccessat(d, "sub/inner/file", F_OK, 0) == 0, "its contents moved with it");
    CHECK(faccessat(inner, "file", F_OK, 0) == 0, "a dirfd opened before the move still works");
    CHECK(fstatat(d, "sub/inner/..", &st, 0) == 0 && st.st_ino == st_sub.st_ino, "its .. is the new parent");
    CHECK(fstatat(d, "x", &st, 0) == 0 && st.st_nlink == 2, "the old parent lost a link");
    CHECK(fstatat(d, "sub", &st, 0) == 0 && st.st_nlink == 3, "the new parent gained one");
    close(inner);

    // Removing.
    errno = 0;
    CHECK(unlinkat(d, "sub", 0) == -1 && errno == EISDIR, "unlinkat of a directory is EISDIR");
    errno = 0;
    CHECK(unlinkat(d, "sub", AT_REMOVEDIR) == -1 && errno == ENOTEMPTY, "rmdir of a full directory is ENOTEMPTY");
    errno = 0;
    CHECK(unlinkat(d, "sub/b.txt", AT_REMOVEDIR) == -1 && errno == ENOTDIR, "rmdir of a file is ENOTDIR");
    CHECK(unlinkat(d, "sub/b.txt", 0) == 0, "unlinkat a file");
    errno = 0;
    CHECK(unlinkat(d, "sub/b.txt", 0) == -1 && errno == ENOENT, "unlinkat it again is ENOENT");
    close(sub);
    close(d);
    remove_tree(AT_FDCWD, ROOT);
    errno = 0;
    CHECK(access(ROOT, F_OK) == -1 && errno == ENOENT, "the tree is gone");

    printf("lt_fs: PASS (%d checks)\n", check_no);
    return 0;
}
