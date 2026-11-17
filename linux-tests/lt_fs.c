// lt_fs — the file-system calls a compiler's cache makes: names relative to
// directory fds (openat, mkdirat, fstatat, statx, faccessat, unlinkat,
// renameat2), getdents64 with long names, ftruncate both ways, rename of
// files and of directories across parents, preadv/pwritev, copy_file_range,
// flock and fsync, chdir and fchdir; then files shared and unlinked while
// open, links, and advisory locks between processes. Works under /ltfs,
// which it removes first and last.
// Exit 0 = every check passed, else the number of the first failed check.

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
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

static int set_lock(int fd, int cmd, short type, off_t start, off_t len) {
    struct flock fl = {.l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len};
    return fcntl(fd, cmd, &fl);
}

// What F_GETLK (or F_OFD_GETLK) finds in the way of a write lock on the
// range; l_type -1 when the call failed.
static struct flock test_lock(int fd, int cmd, off_t start, off_t len) {
    struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = start, .l_len = len};
    if (fcntl(fd, cmd, &fl) != 0) fl.l_type = -1;
    return fl;
}

static int exit_status(pid_t c) {
    int wst;
    if (c <= 0 || waitpid(c, &wst, 0) != c || !WIFEXITED(wst)) return -1;
    return WEXITSTATUS(wst);
}

static long ms_since(const struct timespec *t0) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) * 1000 + (t.tv_nsec - t0->tv_nsec) / 1000000;
}

static void on_usr1(int sig) { (void)sig; }

static int perm_of(const char *name) {
    struct stat st;
    return stat(name, &st) == 0 ? (int)(st.st_mode & 07777) : -1;
}

// Permission bits: what a create asks less the umask, for files and
// directories; chmod, fchmod and fchmodat change them, and the type stays.
static void check_modes(void) {
    const char *f = "/ltmode", *g = "/ltmode2", *dir = "/ltmode.d";
    unlink(f);
    unlink(g);
    rmdir(dir);
    mode_t was = umask(022);
    int fd = open(f, O_CREAT | O_RDWR, 0666);
    CHECK(fd >= 0 && perm_of(f) == 0644, "a new file: 0666 less umask 022 is 0644");
    CHECK(fchmod(fd, 0600) == 0 && perm_of(f) == 0600, "fchmod 0600");
    CHECK(chmod(f, 04751) == 0 && perm_of(f) == 04751, "chmod 04751, setuid kept");
    CHECK(fchmodat(AT_FDCWD, f, 0640, 0) == 0 && perm_of(f) == 0640, "fchmodat 0640");
    struct stat st;
    CHECK(stat(f, &st) == 0 && S_ISREG(st.st_mode), "still a regular file");
    close(fd);
    umask(077);
    fd = open(g, O_CREAT | O_WRONLY | O_EXCL, 0666);
    CHECK(fd >= 0 && perm_of(g) == 0600, "umask 077: a new file is 0600");
    close(fd);
    CHECK(mkdir(dir, 0777) == 0 && perm_of(dir) == 0700, "and a new directory 0700");
    CHECK(stat(dir, &st) == 0 && S_ISDIR(st.st_mode), "a directory still");
    umask(022);
    fd = open(f, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    CHECK(fd >= 0 && perm_of(f) == 0640, "opening a file that is there leaves its permissions");
    close(fd);
    errno = 0;
    CHECK(chmod("/ltmode.none", 0600) == -1 && errno == ENOENT, "chmod of nothing is ENOENT");
    umask(was);
    CHECK(unlink(f) == 0 && unlink(g) == 0 && rmdir(dir) == 0, "remove them");
}

// F_SETLKW on a descriptor another thread closes while it waits.
struct closed_wait {
    int fd, result, err;
};
static void *wait_on_closed(void *arg) {
    struct closed_wait *w = arg;
    w->result = set_lock(w->fd, F_SETLKW, F_WRLCK, 90, 1);
    w->err = errno;
    return NULL;
}

// A child that holds a write lock on byte `at` for `ms`, then exits; the
// lock is taken by the time this returns.
static pid_t hold_lock_for(int fd, off_t at, long ms) {
    int ready[2];
    char byte;
    if (pipe(ready) != 0) return -1;
    pid_t c = fork();
    if (c == 0) {
        close(ready[0]);
        if (set_lock(fd, F_SETLK, F_WRLCK, at, 1) != 0) _exit(1);
        if (write(ready[1], "x", 1) != 1) _exit(2);
        usleep(ms * 1000);
        _exit(0);
    }
    close(ready[1]);
    if (read(ready[0], &byte, 1) != 1) c = -1;
    close(ready[0]);
    return c;
}

// Advisory locks: a process's record locks (POSIX) as another process sees
// them, what a close and an exit give back, a split, a wait and its end by
// a signal, ranges to the largest offset, a deadlock, a close during a
// wait; an open file's record locks (OFD) and flock's.
static void check_locks(void) {
    const char *name = "/ltlock";
    char zeros[100] = {0};
    unlink(name);
    int fd = open(name, O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0 && write(fd, zeros, sizeof zeros) == (ssize_t)sizeof zeros, "a file to lock");
    pid_t me = getpid();

    CHECK(set_lock(fd, F_SETLK, F_WRLCK, 10, 10) == 0, "F_SETLK a write lock on bytes 10..19");
    CHECK(test_lock(fd, F_GETLK, 0, 0).l_type == F_UNLCK, "F_GETLK doesn't see the caller's own lock");
    pid_t c = fork();
    if (c == 0) {
        struct flock fl = test_lock(fd, F_GETLK, 0, 100);
        if (fl.l_type != F_WRLCK || fl.l_start != 10 || fl.l_len != 10 || fl.l_pid != me) _exit(1);
        if (set_lock(fd, F_SETLK, F_RDLCK, 15, 1) != -1 || errno != EAGAIN) _exit(2);
        if (set_lock(fd, F_SETLK, F_WRLCK, 20, 10) != 0) _exit(3);
        _exit(0);
    }
    CHECK(exit_status(c) == 0, "another process sees it and its holder, can't share it, can lock beside it");
    CHECK(set_lock(fd, F_SETLK, F_WRLCK, 20, 10) == 0, "an exit gives back the process's locks");
    int other = open(name, O_RDONLY);
    CHECK(other >= 0 && close(other) == 0, "open and close another descriptor of the file");
    c = fork();
    if (c == 0) _exit(test_lock(fd, F_GETLK, 0, 0).l_type == F_UNLCK ? 0 : 1);
    CHECK(exit_status(c) == 0, "closing any descriptor of the file gives back the process's locks");

    CHECK(set_lock(fd, F_SETLK, F_WRLCK, 0, 100) == 0 && set_lock(fd, F_SETLK, F_UNLCK, 40, 20) == 0, "lock 0..99, unlock 40..59");
    CHECK(set_lock(fd, F_SETLK, F_RDLCK, 0, 40) == 0, "make 0..39 a read lock");
    c = fork();
    if (c == 0) {
        struct flock a = test_lock(fd, F_GETLK, 30, 20), b = test_lock(fd, F_GETLK, 60, 1);
        if (a.l_type != F_RDLCK || a.l_start != 0 || a.l_len != 40) _exit(1);
        if (b.l_type != F_WRLCK || b.l_start != 60 || b.l_len != 40) _exit(2);
        if (test_lock(fd, F_GETLK, 40, 20).l_type != F_UNLCK) _exit(3);
        if (set_lock(fd, F_SETLK, F_RDLCK, 0, 10) != 0) _exit(4);
        if (set_lock(fd, F_SETLK, F_WRLCK, 0, 10) != -1 || errno != EAGAIN) _exit(5);
        _exit(0);
    }
    CHECK(exit_status(c) == 0, "an unlock in the middle splits a lock; a read lock is shared");

    int ready[2];
    char byte;
    CHECK(pipe(ready) == 0, "a pipe to start a waiter");
    c = fork();
    if (c == 0) {
        struct timespec t0;
        close(ready[0]);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (write(ready[1], "x", 1) != 1) _exit(1);
        if (set_lock(fd, F_SETLKW, F_WRLCK, 70, 1) != 0) _exit(2);
        _exit(ms_since(&t0) >= 150 ? 0 : 3);
    }
    close(ready[1]);
    CHECK(read(ready[0], &byte, 1) == 1, "the waiter is about to wait");
    close(ready[0]);
    usleep(250 * 1000);
    CHECK(set_lock(fd, F_SETLK, F_UNLCK, 0, 0) == 0, "unlock the whole file");
    CHECK(exit_status(c) == 0, "F_SETLKW waits until the lock is free, then takes it");

    CHECK(set_lock(fd, F_SETLK, F_WRLCK, 0, 0) == 0, "lock the whole file");
    CHECK(pipe(ready) == 0, "a pipe to start a waiter");
    c = fork();
    if (c == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_usr1; // no SA_RESTART
        sigaction(SIGUSR1, &sa, NULL);
        close(ready[0]);
        if (write(ready[1], "x", 1) != 1) _exit(1);
        int r = set_lock(fd, F_SETLKW, F_WRLCK, 0, 1);
        _exit(r == -1 && errno == EINTR ? 0 : 2);
    }
    close(ready[1]);
    CHECK(read(ready[0], &byte, 1) == 1, "the waiter is about to wait");
    close(ready[0]);
    // A signal that lands before the wait begins is followed by another.
    int got = -1;
    for (int i = 0; i < 60 && got < 0; i++) {
        kill(c, SIGUSR1);
        usleep(50 * 1000);
        int wst;
        if (waitpid(c, &wst, WNOHANG) == c) got = WIFEXITED(wst) ? WEXITSTATUS(wst) : 99;
    }
    if (got < 0) {
        kill(c, SIGKILL);
        waitpid(c, NULL, 0);
    }
    CHECK(got == 0, "a signal ends the wait with EINTR");
    CHECK(set_lock(fd, F_SETLK, F_UNLCK, 0, 0) == 0, "unlock");

    // Bounds at the largest offset, and what F_GETLK says of them.
    CHECK(set_lock(fd, F_SETLK, F_WRLCK, 0, 0) == 0 && set_lock(fd, F_SETLK, F_UNLCK, 1, INT64_MAX) == 0, "lock to EOF, unlock 1..the largest offset");
    c = fork();
    if (c == 0) {
        struct flock fl = test_lock(fd, F_GETLK, 0, 0);
        _exit(fl.l_type == F_WRLCK && fl.l_start == 0 && fl.l_len == 1 ? 0 : 1);
    }
    CHECK(exit_status(c) == 0, "byte 0 is left");
    CHECK(set_lock(fd, F_SETLK, F_WRLCK, 1, INT64_MAX) == 0, "lock 1..the largest offset: one lock to EOF again");
    c = fork();
    if (c == 0) {
        struct flock fl = test_lock(fd, F_GETLK, 5, 1);
        _exit(fl.l_type == F_WRLCK && fl.l_start == 0 && fl.l_len == 0 ? 0 : 1);
    }
    CHECK(exit_status(c) == 0, "F_GETLK reports it as to EOF");
    errno = 0;
    CHECK(set_lock(fd, F_SETLK, F_WRLCK, 2, INT64_MAX) == -1 && errno == EOVERFLOW, "a range past the largest offset is EOVERFLOW");
    CHECK(set_lock(fd, F_SETLK, F_UNLCK, 0, 0) == 0, "unlock");

    // Two processes each waiting for the other's lock: whichever asks
    // second gets EDEADLK.
    CHECK(set_lock(fd, F_SETLK, F_WRLCK, 0, 1) == 0, "lock byte 0");
    CHECK(pipe(ready) == 0, "a pipe to start a waiter");
    c = fork();
    if (c == 0) {
        close(ready[0]);
        if (set_lock(fd, F_SETLK, F_WRLCK, 1, 1) != 0) _exit(1);
        if (write(ready[1], "x", 1) != 1) _exit(2);
        int r = set_lock(fd, F_SETLKW, F_WRLCK, 0, 1);
        _exit(r == 0 ? 0 : errno == EDEADLK ? 4 : 3);
    }
    close(ready[1]);
    CHECK(read(ready[0], &byte, 1) == 1, "a child holds byte 1 and is about to wait for byte 0");
    close(ready[0]);
    usleep(100 * 1000);
    errno = 0;
    int dl = set_lock(fd, F_SETLKW, F_WRLCK, 1, 1), dl_errno = errno;
    if (dl == -1) set_lock(fd, F_SETLK, F_UNLCK, 0, 1);
    int dl_child = exit_status(c);
    CHECK((dl == -1 && dl_errno == EDEADLK && dl_child == 0) || (dl == 0 && dl_child == 4), "one of the two gets EDEADLK, the other its lock");
    CHECK(set_lock(fd, F_SETLK, F_UNLCK, 0, 0) == 0, "unlock");

    // A descriptor closed while F_SETLKW waits on it: the lock it gets in
    // the end goes again, and the call says EBADF.
    c = hold_lock_for(fd, 90, 300);
    CHECK(c > 0, "a child holds byte 90 for a while");
    struct closed_wait cw = {.fd = dup(fd)};
    pthread_t waiter;
    CHECK(cw.fd >= 0 && pthread_create(&waiter, NULL, wait_on_closed, &cw) == 0, "a thread waits for byte 90");
    usleep(100 * 1000);
    CHECK(close(cw.fd) == 0 && pthread_join(waiter, NULL) == 0, "close its descriptor; the wait ends when the child's lock goes");
    CHECK(cw.result == -1 && cw.err == EBADF, "with EBADF");
    CHECK(exit_status(c) == 0, "the holder is gone");
    c = fork();
    if (c == 0) _exit(test_lock(fd, F_GETLK, 90, 1).l_type == F_UNLCK ? 0 : 1);
    CHECK(exit_status(c) == 0, "and the process holds no lock there");

    errno = 0;
    CHECK(set_lock(fd, F_SETLK, 7, 0, 1) == -1 && errno == EINVAL, "an unknown lock type is EINVAL");
    errno = 0;
    CHECK(set_lock(fd, F_SETLK, F_WRLCK, -5, 1) == -1 && errno == EINVAL, "a range before the file is EINVAL");
    int ro = open(name, O_RDONLY);
    errno = 0;
    CHECK(ro >= 0 && set_lock(ro, F_SETLK, F_WRLCK, 0, 1) == -1 && errno == EBADF, "a write lock needs a file open for writing");
    close(ro);

    int a = open(name, O_RDWR), b = open(name, O_RDWR);
    CHECK(a >= 0 && b >= 0 && set_lock(a, F_OFD_SETLK, F_WRLCK, 0, 10) == 0, "an open file's record lock (OFD)");
    errno = 0;
    CHECK(set_lock(b, F_OFD_SETLK, F_WRLCK, 5, 1) == -1 && errno == EAGAIN, "another open file of the same process can't have it");
    errno = 0;
    CHECK(set_lock(b, F_SETLK, F_WRLCK, 5, 1) == -1 && errno == EAGAIN, "nor can the process's own POSIX lock");
    struct flock ofl = test_lock(b, F_OFD_GETLK, 0, 1);
    CHECK(ofl.l_type == F_WRLCK && ofl.l_pid == -1, "F_OFD_GETLK finds it, with no process to name");
    int tmp = open(name, O_RDONLY);
    CHECK(tmp >= 0 && close(tmp) == 0 && set_lock(b, F_OFD_SETLK, F_WRLCK, 5, 1) == -1, "closing another descriptor leaves it");
    struct flock bad = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 50, .l_len = 1, .l_pid = 5};
    errno = 0;
    CHECK(fcntl(b, F_OFD_SETLK, &bad) == -1 && errno == EINVAL, "an OFD request with l_pid set is EINVAL");
    CHECK(close(a) == 0 && set_lock(b, F_OFD_SETLK, F_WRLCK, 5, 1) == 0, "the open file's last close gives it back");
    close(b);

    int x = open(name, O_RDWR), y = open(name, O_RDWR);
    CHECK(x >= 0 && y >= 0 && flock(x, LOCK_EX) == 0, "flock LOCK_EX");
    errno = 0;
    CHECK(flock(y, LOCK_SH | LOCK_NB) == -1 && errno == EWOULDBLOCK, "another open file can't share it");
    CHECK(set_lock(y, F_SETLK, F_WRLCK, 0, 0) == 0 && set_lock(y, F_SETLK, F_UNLCK, 0, 0) == 0, "flock and fcntl locks don't meet");
    c = fork();
    if (c == 0) _exit(flock(x, LOCK_EX | LOCK_NB) == 0 ? 0 : 1);
    CHECK(exit_status(c) == 0, "a child holds it through the inherited open file");
    errno = 0;
    CHECK(flock(y, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK, "the child's exit didn't give it back");
    CHECK(close(x) == 0 && flock(y, LOCK_EX | LOCK_NB) == 0, "the open file's last close does");
    close(y);

    // Two holders of a shared flock lock that both want it exclusive: a
    // conversion drops the old lock first, so neither waits for ever.
    int s = open(name, O_RDWR);
    CHECK(s >= 0 && flock(s, LOCK_SH) == 0, "a shared flock lock");
    CHECK(pipe(ready) == 0, "a pipe to start a waiter");
    c = fork();
    if (c == 0) {
        int mine = open(name, O_RDWR);
        close(ready[0]);
        if (mine < 0 || flock(mine, LOCK_SH) != 0) _exit(1);
        if (write(ready[1], "x", 1) != 1) _exit(2);
        _exit(flock(mine, LOCK_EX) == 0 ? 0 : 3);
    }
    close(ready[1]);
    CHECK(read(ready[0], &byte, 1) == 1, "a child shares it and asks for it exclusive");
    close(ready[0]);
    int converted = 0;
    for (int i = 0; i < 40 && !converted; i++) {
        converted = flock(s, LOCK_EX | LOCK_NB) == 0;
        if (!converted) usleep(25 * 1000);
    }
    CHECK(converted, "this one gets it exclusive: the waiter's shared lock went");
    CHECK(flock(s, LOCK_UN) == 0 && exit_status(c) == 0, "and the waiter gets it after");
    close(s);
    close(fd);
    CHECK(unlink(name) == 0, "unlink the locked file");
}

// A directory of several blocks, every name in it replaced by rename, as a
// package manager lays its files down: each name is there afterwards.
static void check_wide_directory(void) {
    enum { N = 300 };
    char from[128], to[128];
    remove_tree(AT_FDCWD, "/ltwide");
    CHECK(mkdir("/ltwide", 0755) == 0, "mkdir /ltwide");
    int made = 0;
    for (int i = 0; i < N; i++) {
        snprintf(from, sizeof from, "/ltwide/.tmp.%048d", i);
        int fd = open(from, O_CREAT | O_WRONLY | O_EXCL, 0644);
        if (fd < 0) break;
        made += write(fd, &i, sizeof i) == sizeof i;
        close(fd);
    }
    CHECK(made == N, "a directory takes 300 long names");
    int moved = 0;
    for (int i = 0; i < N; i++) {
        snprintf(from, sizeof from, "/ltwide/.tmp.%048d", i);
        snprintf(to, sizeof to, "/ltwide/f%d.h", i);
        moved += rename(from, to) == 0;
    }
    CHECK(moved == N, "each of them renames to a short name");
    int d = open("/ltwide", O_RDONLY | O_DIRECTORY);
    CHECK(d >= 0 && count_entries(d) == N + 2, "the directory lists them all");
    int right = 0;
    for (int i = 0; i < N; i++) {
        int got = -1;
        snprintf(to, sizeof to, "f%d.h", i);
        int fd = openat(d, to, O_RDONLY);
        if (fd < 0) continue;
        right += read(fd, &got, sizeof got) == sizeof got && got == i;
        close(fd);
    }
    CHECK(right == N, "each holds what was written under its first name");
    // Every other name goes, then as many new ones come: the freed room is used.
    int gone = 0;
    for (int i = 0; i < N; i += 2) {
        snprintf(to, sizeof to, "f%d.h", i);
        gone += unlinkat(d, to, 0) == 0;
    }
    made = 0;
    for (int i = 0; i < N; i += 2) {
        snprintf(to, sizeof to, "again_%d.txt", i);
        int fd = openat(d, to, O_CREAT | O_WRONLY | O_EXCL, 0644);
        made += fd >= 0;
        if (fd >= 0) close(fd);
    }
    CHECK(gone == N / 2 && made == N / 2 && count_entries(d) == N + 2, "names freed and taken again leave the count right");
    close(d);
    remove_tree(AT_FDCWD, "/ltwide");
    errno = 0;
    CHECK(access("/ltwide", F_OK) == -1 && errno == ENOENT, "the wide directory is removed whole");
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
    check_locks();
    check_modes();
    check_wide_directory();

    printf("lt_fs: PASS (%d checks)\n", check_no);
    return 0;
}
