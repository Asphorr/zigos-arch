// lt_fs — the file-system calls a compiler's cache makes: names relative to
// directory fds (openat, mkdirat, fstatat, statx, faccessat, unlinkat,
// renameat2), getdents64 with long names, ftruncate both ways, rename of
// files and of directories across parents, preadv/pwritev, copy_file_range,
// flock and fsync, chdir and fchdir. Works under /ltfs, which it removes
// first and last.
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
#include <sys/wait.h>
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

static int type_in(const char *dir, const char *name) {
    DIR *d = opendir(dir);
    int type = -1;
    struct dirent *e;
    while (d && (e = readdir(d)) != NULL)
        if (strcmp(e->d_name, name) == 0) type = e->d_type;
    if (d) closedir(d);
    return type;
}

static int count_entries(int dirfd) {
    int fd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY);
    DIR *d = fdopendir(fd);
    int n = 0;
    while (d && readdir(d) != NULL) n++;
    if (d) closedir(d);
    return n;
}

static unsigned char big[100000];
static unsigned char back[200000];

// What `name` holds, as a string in `out`; -1 if it can't be read.
static long slurp(const char *name, char *out, size_t cap) {
    int fd = open(name, O_RDONLY);
    if (fd < 0) return -1;
    long n = read(fd, out, cap - 1);
    close(fd);
    if (n >= 0) out[n] = 0;
    return n;
}

// One open file behind several descriptors: dup and fork share the offset
// and the status flags, a second open has its own.
static void check_shared_files(void) {
    const char *name = "/ltfs.shared";
    char got[64];
    int fd = open(name, O_CREAT | O_TRUNC | O_RDWR, 0644);
    CHECK(fd >= 0 && write(fd, "abcdef", 6) == 6, "a file to share");
    int twin = dup(fd);
    CHECK(twin >= 0 && lseek(twin, 0, SEEK_CUR) == 6, "a dup starts where the file is");
    CHECK(lseek(fd, 2, SEEK_SET) == 2 && lseek(twin, 0, SEEK_CUR) == 2, "a seek through one moves the other");
    char two[3] = {0};
    CHECK(read(twin, two, 2) == 2 && memcmp(two, "cd", 2) == 0 && lseek(fd, 0, SEEK_CUR) == 4, "a read through one moves the other");
    int other = open(name, O_RDONLY);
    CHECK(other >= 0 && lseek(other, 0, SEEK_CUR) == 0, "a second open has an offset of its own");
    close(other);
    CHECK(fcntl(twin, F_SETFL, O_NONBLOCK) == 0 && (fcntl(fd, F_GETFL) & O_NONBLOCK) != 0, "status flags are the file's");
    CHECK(fcntl(twin, F_SETFD, FD_CLOEXEC) == 0 && fcntl(fd, F_GETFD) == 0, "close-on-exec is the descriptor's");
    CHECK(close(fd) == 0 && write(twin, "XY", 2) == 2, "the file outlives the descriptor it was opened on");
    close(twin);
    CHECK(slurp(name, got, sizeof got) == 6 && strcmp(got, "abcdXY") == 0, "and wrote where the shared offset was");

    // A shell's `{ a; b; } > file`: children in turn on one inherited fd.
    fd = open(name, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    int ok = fd >= 0;
    const char *lines[3] = {"one\n", "two\n", "three\n"};
    for (int i = 0; i < 3 && ok; i++) {
        int st = 0;
        pid_t c = fork();
        if (c == 0) _exit(write(fd, lines[i], strlen(lines[i])) == (long)strlen(lines[i]) ? 0 : 1);
        ok = c > 0 && waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0;
    }
    CHECK(ok, "three children write through an inherited fd");
    CHECK(lseek(fd, 0, SEEK_CUR) == 14 && write(fd, "end\n", 4) == 4, "the parent's offset followed them");
    close(fd);
    CHECK(slurp(name, got, sizeof got) == 18 && strcmp(got, "one\ntwo\nthree\nend\n") == 0, "nothing was overwritten");

    // O_APPEND: every write goes to the end, wherever the offset is.
    int app = open(name, O_WRONLY | O_APPEND);
    int plain = open(name, O_WRONLY);
    CHECK(app >= 0 && plain >= 0 && (fcntl(app, F_GETFL) & O_APPEND) != 0, "an O_APPEND open says so");
    CHECK(lseek(app, 0, SEEK_SET) == 0 && write(app, "A", 1) == 1 && lseek(app, 0, SEEK_CUR) == 19, "an appending write ignores the offset");
    CHECK(write(plain, "ONE", 3) == 3 && write(app, "B", 1) == 1, "another writer in between");
    close(app);
    close(plain);
    CHECK(slurp(name, got, sizeof got) == 20 && strcmp(got, "ONE\ntwo\nthree\nend\nAB") == 0, "appends stayed at the end");

    // Offsets past 4 GiB.
    const off_t far = ((off_t)5 << 30) + 123;
    fd = open(name, O_RDWR | O_TRUNC);
    CHECK(fd >= 0 && lseek(fd, far, SEEK_SET) == far, "lseek past 4 GiB");
    CHECK(write(fd, "deep", 4) == 4 && lseek(fd, 0, SEEK_CUR) == far + 4, "a write out there");
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == far + 4, "the file is that long");
    CHECK(lseek(fd, -4, SEEK_END) == far && read(fd, got, 4) == 4 && memcmp(got, "deep", 4) == 0, "and reads back from there");
    CHECK(lseek(fd, far - 8, SEEK_SET) == far - 8 && read(fd, got, 8) == 8 && all_zero((unsigned char *)got, 8), "the hole before it is zeros");
    errno = 0;
    CHECK(lseek(fd, -1, SEEK_SET) == -1 && errno == EINVAL, "a negative offset is EINVAL");
    close(fd);
    CHECK(unlink(name) == 0, "unlink the shared file");
}

// A file unlinked while open: the name goes, the file stays until its last
// descriptor does, and its inode is nobody else's meanwhile.
static void check_unlinked_open(void) {
    const char *name = "/ltfs.gone";
    char got[64];
    struct stat st, ost;
    int fd = open(name, O_CREAT | O_TRUNC | O_RDWR, 0644);
    CHECK(fd >= 0 && write(fd, "still here", 10) == 10, "a file to unlink while open");
    CHECK(fstat(fd, &st) == 0 && st.st_nlink == 1, "one link while it has a name");
    ino_t ino = st.st_ino;
    CHECK(unlink(name) == 0, "unlink it");
    errno = 0;
    CHECK(access(name, F_OK) == -1 && errno == ENOENT, "the name is gone");
    CHECK(fstat(fd, &st) == 0 && st.st_nlink == 0 && st.st_ino == ino && st.st_size == 10, "the open file is not");
    int other = open(name, O_CREAT | O_RDWR, 0644);
    CHECK(other >= 0 && fstat(other, &ost) == 0 && ost.st_ino != ino, "a new file of that name is another inode");
    CHECK(write(other, "newcomer", 8) == 8, "write the new file");
    CHECK(pread(fd, got, 10, 0) == 10 && memcmp(got, "still here", 10) == 0, "the unlinked file kept its bytes");
    CHECK(pwrite(fd, "STILL", 5, 0) == 5 && lseek(fd, 0, SEEK_END) == 10, "and can be written");
    // An inherited descriptor keeps it alive past the parent's close.
    pid_t c = fork();
    if (c == 0) {
        char b[16];
        _exit(pread(fd, b, 10, 0) == 10 && memcmp(b, "STILL here", 10) == 0 ? 0 : 1);
    }
    close(fd);
    int wst = 0;
    CHECK(c > 0 && waitpid(c, &wst, 0) == c && WIFEXITED(wst) && WEXITSTATUS(wst) == 0, "a child reads it after the parent closed");
    CHECK(slurp(name, got, sizeof got) == 8 && strcmp(got, "newcomer") == 0, "the new file is untouched");
    close(other);
    CHECK(unlink(name) == 0, "unlink the new file");

    // A file replaced by a rename while open.
    fd = open(name, O_CREAT | O_TRUNC | O_RDWR, 0644);
    other = open("/ltfs.gone.new", O_CREAT | O_TRUNC | O_RDWR, 0644);
    CHECK(fd >= 0 && other >= 0 && write(fd, "old", 3) == 3 && write(other, "new", 3) == 3, "two files, one to replace the other");
    close(other);
    CHECK(rename("/ltfs.gone.new", name) == 0, "rename over the open file");
    CHECK(pread(fd, got, 3, 0) == 3 && memcmp(got, "old", 3) == 0, "its descriptor still reads the old bytes");
    CHECK(slurp(name, got, sizeof got) == 3 && strcmp(got, "new") == 0, "the name reads the new ones");
    close(fd);
    CHECK(unlink(name) == 0, "unlink the replacement");

    // A directory removed while open.
    CHECK(mkdir("/ltfs.gonedir", 0755) == 0, "mkdir");
    int d = open("/ltfs.gonedir", O_RDONLY | O_DIRECTORY);
    CHECK(d >= 0 && rmdir("/ltfs.gonedir") == 0, "rmdir an open directory");
    CHECK(fstat(d, &st) == 0 && S_ISDIR(st.st_mode), "its descriptor still stats");
    errno = 0;
    CHECK(openat(d, "x", O_CREAT | O_WRONLY, 0644) == -1 && errno == ENOENT, "nothing can be made in it");
    close(d);
}

// Symbolic and hard links.
static void check_links(void) {
    char got[300];
    struct stat st, lst;
    remove_tree(AT_FDCWD, "/ltln");
    CHECK(mkdir("/ltln", 0755) == 0 && mkdir("/ltln/dir", 0755) == 0, "a tree for the links");
    int fd = open("/ltln/dir/file", O_CREAT | O_WRONLY, 0644);
    CHECK(fd >= 0 && write(fd, "through", 7) == 7, "a file to point at");
    close(fd);

    // A link to a file, by a relative target.
    CHECK(symlink("dir/file", "/ltln/rel") == 0, "symlink with a relative target");
    CHECK(slurp("/ltln/rel", got, sizeof got) == 7 && strcmp(got, "through") == 0, "open follows it");
    CHECK(stat("/ltln/rel", &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 7, "stat follows it");
    CHECK(lstat("/ltln/rel", &lst) == 0 && S_ISLNK(lst.st_mode) && lst.st_size == 8 && lst.st_ino != st.st_ino, "lstat sees the link");
    long n = readlink("/ltln/rel", got, sizeof got);
    CHECK(n == 8 && memcmp(got, "dir/file", 8) == 0, "readlink gives the target");
    CHECK(readlink("/ltln/rel", got, 3) == 3 && memcmp(got, "dir", 3) == 0, "cut to the buffer");
    errno = 0;
    CHECK(readlink("/ltln/dir/file", got, sizeof got) == -1 && errno == EINVAL, "readlink of a file is EINVAL");
    CHECK(type_in("/ltln", "rel") == DT_LNK, "readdir calls it a link");
    errno = 0;
    CHECK(open("/ltln/rel", O_RDONLY | O_NOFOLLOW) == -1 && errno == ELOOP, "O_NOFOLLOW refuses it");
    errno = 0;
    CHECK(open("/ltln/rel", O_CREAT | O_EXCL | O_WRONLY, 0644) == -1 && errno == EEXIST, "O_EXCL finds the name taken");
    errno = 0;
    CHECK(symlink("x", "/ltln/rel") == -1 && errno == EEXIST, "symlink over a name is EEXIST");

    // A link to a directory, by an absolute target, in the middle of a path.
    CHECK(symlink("/ltln/dir", "/ltln/abs") == 0, "symlink with an absolute target");
    CHECK(slurp("/ltln/abs/file", got, sizeof got) == 7, "a path goes through it");
    CHECK(lstat("/ltln/abs/file", &lst) == 0 && S_ISREG(lst.st_mode), "lstat follows the links before the last name");
    fd = open("/ltln/abs/made", O_CREAT | O_WRONLY, 0644);
    CHECK(fd >= 0 && access("/ltln/dir/made", F_OK) == 0, "a file made through it lands in the directory");
    close(fd);
    char cwd[256];
    CHECK(chdir("/ltln/abs") == 0 && access("file", F_OK) == 0, "chdir through it");
    CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/ltln/dir") == 0, "the cwd is the directory, not the link");
    CHECK(chdir("..") == 0 && getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/ltln") == 0, ".. from it is the directory's parent");
    CHECK(chdir("abs/../dir/.") == 0 && getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/ltln/dir") == 0, "a path of links, . and ..");
    CHECK(chdir("../..") == 0 && getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/") == 0, "and up to the root");
    CHECK(symlink("../dir/file", "/ltln/dir/up") == 0 && slurp("/ltln/dir/up", got, sizeof got) == 7, "a target with ..");

    // A link to a link, a dangling one, a loop.
    CHECK(symlink("rel", "/ltln/twice") == 0 && slurp("/ltln/twice", got, sizeof got) == 7, "a link to a link");
    CHECK(symlink("nowhere", "/ltln/dangling") == 0 && lstat("/ltln/dangling", &lst) == 0, "a dangling link exists");
    errno = 0;
    CHECK(stat("/ltln/dangling", &st) == -1 && errno == ENOENT, "but leads to ENOENT");
    fd = open("/ltln/dangling", O_CREAT | O_WRONLY, 0644);
    CHECK(fd >= 0 && access("/ltln/nowhere", F_OK) == 0, "creating through it makes the target");
    close(fd);
    CHECK(symlink("loop_b", "/ltln/loop_a") == 0 && symlink("loop_a", "/ltln/loop_b") == 0, "two links at each other");
    CHECK(open("/ltln/loop_a", O_RDONLY) == -1, "a loop of links opens nothing");

    // A target too long for the inode: it lies in a block.
    char longt[200];
    memset(longt, 0, sizeof longt);
    strcpy(longt, "dir/");
    for (int i = 4; i < 150; i += 2) memcpy(longt + i, "./", 2);
    strcpy(longt + 150, "file");
    CHECK(symlink(longt, "/ltln/long") == 0, "symlink with a 154-byte target");
    n = readlink("/ltln/long", got, sizeof got);
    CHECK(n == 154 && memcmp(got, longt, 154) == 0, "readlink gives all of it");
    CHECK(slurp("/ltln/long", got, sizeof got) == 7 && strcmp(got, "through") == 0, "and it leads to the file");

    // Removing and renaming act on the link itself.
    CHECK(rename("/ltln/rel", "/ltln/moved") == 0 && lstat("/ltln/moved", &lst) == 0 && S_ISLNK(lst.st_mode), "rename moves the link");
    CHECK(unlink("/ltln/moved") == 0 && access("/ltln/dir/file", F_OK) == 0, "unlink removes the link, not the file");
    CHECK(unlink("/ltln/long") == 0 && unlink("/ltln/abs") == 0 && access("/ltln/dir/made", F_OK) == 0, "nor the directory");

    // Hard links: one file under two names.
    CHECK(link("/ltln/dir/file", "/ltln/hard") == 0, "link");
    CHECK(stat("/ltln/hard", &st) == 0 && st.st_nlink == 2 && lstat("/ltln/dir/file", &lst) == 0 && lst.st_ino == st.st_ino, "two names, one inode");
    fd = open("/ltln/hard", O_WRONLY | O_APPEND);
    CHECK(fd >= 0 && write(fd, "!", 1) == 1, "write through the second name");
    close(fd);
    CHECK(slurp("/ltln/dir/file", got, sizeof got) == 8 && strcmp(got, "through!") == 0, "the first name reads it");
    CHECK(unlink("/ltln/dir/file") == 0 && stat("/ltln/hard", &st) == 0 && st.st_nlink == 1, "unlinking one name leaves the other");
    CHECK(slurp("/ltln/hard", got, sizeof got) == 8, "with the bytes");
    errno = 0;
    CHECK(link("/ltln/dir", "/ltln/dirlink") == -1 && errno == EPERM, "a directory can't be hard-linked");
    errno = 0;
    CHECK(link("/ltln/hard", "/ltln/twice") == -1 && errno == EEXIST, "link over a name is EEXIST");

    remove_tree(AT_FDCWD, "/ltln");
    errno = 0;
    CHECK(access("/ltln", F_OK) == -1 && errno == ENOENT, "the tree of links is gone");
}

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

    // Entry types, for names the image came with (its entries carry none).
    CHECK(type_in("/", "etc") == DT_DIR && type_in("/etc", "motd") == DT_REG, "readdir reports entry types");

    // More entries than one getdents64 call returns.
    CHECK(mkdirat(d, "many", 0755) == 0, "mkdirat many");
    int many = openat(d, "many", O_RDONLY | O_DIRECTORY);
    int made = 0;
    for (int i = 0; i < 120; i++) {
        char name[64];
        snprintf(name, sizeof name, "entry_number_%03d_with_a_longer_name.txt", i);
        int e = openat(many, name, O_CREAT | O_WRONLY, 0644);
        if (e >= 0) {
            made++;
            close(e);
        }
    }
    CHECK(made == 120 && count_entries(many) == 122, "a directory of 120 files lists each once");
    close(many);

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

    // chdir and fchdir: relative names follow the cwd.
    char cwd[256];
    CHECK(chdir(ROOT) == 0 && getcwd(cwd, sizeof cwd) != NULL && strncmp(cwd, ROOT, strlen(ROOT)) == 0, "chdir");
    int rel = open("rel.txt", O_CREAT | O_WRONLY, 0644);
    CHECK(rel >= 0 && size_at(d, "rel.txt") == 0, "a relative name lands in the cwd");
    close(rel);
    CHECK(fchdir(sub) == 0, "fchdir");
    rel = open("in_sub.txt", O_CREAT | O_WRONLY, 0644);
    CHECK(rel >= 0 && size_at(sub, "in_sub.txt") == 0, "and names follow it");
    close(rel);
    errno = 0;
    CHECK(chdir("no-such-dir") == -1 && errno == ENOENT, "chdir to a missing directory is ENOENT");
    errno = 0;
    CHECK(chdir("in_sub.txt") == -1 && errno == ENOTDIR, "chdir to a file is ENOTDIR");
    CHECK(chdir("/") == 0, "back to the root");
    CHECK(unlinkat(d, "rel.txt", 0) == 0 && unlinkat(sub, "in_sub.txt", 0) == 0, "remove the two files");
    close(sub);
    close(d);
    remove_tree(AT_FDCWD, ROOT);
    errno = 0;
    CHECK(access(ROOT, F_OK) == -1 && errno == ENOENT, "the tree is gone");

    check_shared_files();
    check_unlinked_open();
    check_links();

    printf("lt_fs: PASS (%d checks)\n", check_no);
    return 0;
}
