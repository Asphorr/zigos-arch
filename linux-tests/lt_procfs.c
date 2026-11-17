// lt_procfs — /proc as Linux programs read it: self and its links, the
// process's stat, status, cmdline, environ and maps, fd/ and task/, the
// system's meminfo, cpuinfo, stat, uptime and sys/, another process's
// directory, and ttyname through fd/. Exit 0 = every check passed, else the
// number of the first failed check.

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static int check_no;

#define CHECK(cond, what)                                                        \
    do {                                                                         \
        check_no++;                                                              \
        if (!(cond)) {                                                           \
            printf("lt_procfs: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                      \
        }                                                                        \
    } while (0)

static char text[64 * 1024];

// The whole of a /proc file, NUL-terminated; its length, or -1.
static ssize_t slurp(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t have = 0;
    for (;;) {
        ssize_t n = read(fd, text + have, sizeof text - 1 - have);
        if (n < 0) {
            close(fd);
            return -1;
        }
        if (n == 0) break;
        have += (size_t)n;
    }
    close(fd);
    text[have] = 0;
    return (ssize_t)have;
}

static int has_entry(const char *dir, const char *name) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, name) == 0) found = 1;
    closedir(d);
    return found;
}

static int count_entries(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d)))
        if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

static volatile int thread_go;
static char thread_link[64];
static pid_t thread_tid;

static void *in_thread(void *arg) {
    (void)arg;
    thread_tid = (pid_t)syscall(SYS_gettid);
    ssize_t n = readlink("/proc/thread-self", thread_link, sizeof thread_link - 1);
    if (n > 0) thread_link[n] = 0;
    while (!thread_go) usleep(1000);
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pid_t me = getpid();
    char want[64], link[256], path[128];

    // self and its links
    snprintf(want, sizeof want, "%d", me);
    ssize_t n = readlink("/proc/self", link, sizeof link - 1);
    CHECK(n > 0 && (link[n] = 0, strcmp(link, want) == 0), "/proc/self names this process");
    char exe[256];
    n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    CHECK(n > 0 && (exe[n] = 0, strstr(exe, "lt_procfs") != NULL), "exe is this program");
    char cwd[256];
    CHECK(getcwd(cwd, sizeof cwd) != NULL, "getcwd");
    n = readlink("/proc/self/cwd", link, sizeof link - 1);
    CHECK(n > 0 && (link[n] = 0, strcmp(link, cwd) == 0), "cwd is getcwd's");
    struct stat st;
    CHECK(lstat("/proc/self", &st) == 0 && S_ISLNK(st.st_mode), "self is a link");
    CHECK(stat("/proc/self", &st) == 0 && S_ISDIR(st.st_mode), "to a directory");

    // stat, status, cmdline, environ, comm
    CHECK(slurp("/proc/self/stat") > 0, "read stat");
    int spid = 0, sppid = 0;
    char state = 0;
    char *close_paren = strrchr(text, ')');
    CHECK(sscanf(text, "%d", &spid) == 1 && spid == me && close_paren && sscanf(close_paren + 2, "%c %d", &state, &sppid) == 2, "stat: pid, state, ppid");
    CHECK(state == 'R' && sppid == getppid(), "running, its parent's");
    CHECK(slurp("/proc/self/status") > 0, "read status");
    snprintf(want, sizeof want, "\nPid:\t%d\n", me);
    CHECK(strstr(text, want) != NULL, "status: Pid");
    snprintf(want, sizeof want, "\nPPid:\t%d\n", getppid());
    CHECK(strstr(text, want) != NULL && strstr(text, "\nThreads:\t1\n") != NULL, "status: PPid, one thread");
    CHECK(strstr(text, "\nVmRSS:") != NULL && strstr(text, "\nSigBlk:\t") != NULL, "status: VmRSS, SigBlk");
    ssize_t len = slurp("/proc/self/cmdline");
    size_t args_len = 0;
    for (int i = 0; i < argc; i++) args_len += strlen(argv[i]) + 1;
    CHECK(len == (ssize_t)args_len && strcmp(text, argv[0]) == 0, "cmdline is argv, NUL after each");
    len = slurp("/proc/self/environ");
    CHECK(len > 0 && memchr(text, '=', (size_t)len) != NULL, "environ has the environment");
    CHECK(slurp("/proc/self/comm") > 0 && strncmp(text, "lt_procfs", 9) == 0, "comm");

    // A positioned read: the text from any offset, the fd's own left alone.
    int pfd = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);
    char at[16] = {0};
    CHECK(pfd >= 0 && pread(pfd, at, 9, 0) == 9 && memcmp(at, "lt_procfs", 9) == 0, "pread from the start");
    CHECK(pread(pfd, at, 6, 3) == 6 && memcmp(at, "procfs", 6) == 0, "pread from the middle");
    CHECK(pread(pfd, at, 4, 4096) == 0, "pread past the end");
    CHECK(read(pfd, at, 2) == 2 && memcmp(at, "lt", 2) == 0, "read starts at the fd's own offset");
    int pdir = open("/proc/self", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(pdir >= 0 && pread(pdir, at, 4, 0) < 0 && errno == EISDIR, "pread of a directory is EISDIR");
    close(pdir);
    close(pfd);

    // maps
    CHECK(slurp("/proc/self/maps") > 0, "read maps");
    CHECK(strstr(text, "[stack]") != NULL, "maps: the stack");
    CHECK(strstr(text, "lt_procfs") != NULL, "maps: the program's own pages");
    unsigned long lo = 0, hi = 0;
    char perms[5] = {0};
    CHECK(sscanf(text, "%lx-%lx %4s", &lo, &hi, perms) == 3 && lo < hi, "maps: a line's form");
    unsigned long here = (unsigned long)&check_no;
    int covered = 0;
    for (char *line = text; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perms) == 3 && lo <= here && here < hi && perms[0] == 'r' && perms[1] == 'w') covered = 1;
    }
    CHECK(covered, "maps: a variable lies in a rw region");

    // fd/
    int fd = open(exe, O_RDONLY);
    CHECK(fd >= 0, "open a file");
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    n = readlink(path, link, sizeof link - 1);
    CHECK(n > 0 && (link[n] = 0, strcmp(link, exe) == 0), "fd/N names the file");
    struct stat a, b;
    CHECK(stat(path, &a) == 0 && fstat(fd, &b) == 0 && a.st_ino == b.st_ino && S_ISREG(a.st_mode), "stat through fd/N is the file's");
    int again = open(path, O_RDONLY);
    CHECK(again >= 0 && again != fd, "open fd/N: a new descriptor");
    char x1[16], x2[16];
    CHECK(read(fd, x1, sizeof x1) > 0 && read(again, x2, sizeof x2) > 0 && memcmp(x1, x2, 8) == 0, "of the same file, at its own offset");
    close(again);
    snprintf(want, sizeof want, "%d", fd);
    CHECK(has_entry("/proc/self/fd", "0") && has_entry("/proc/self/fd", want), "fd/ lists the descriptors");
    int p[2];
    CHECK(pipe(p) == 0, "pipe");
    snprintf(path, sizeof path, "/proc/self/fd/%d", p[0]);
    n = readlink(path, link, sizeof link - 1);
    CHECK(n > 0 && (link[n] = 0, strncmp(link, "pipe:[", 6) == 0), "a pipe's name");
    close(p[0]);
    close(p[1]);
    close(fd);

    // a directory fd and the *at calls
    int dfd = open("/proc/self", O_RDONLY | O_DIRECTORY);
    CHECK(dfd >= 0, "open /proc/self as a directory");
    int sfd = openat(dfd, "status", O_RDONLY);
    CHECK(sfd >= 0 && read(sfd, x1, 5) == 5 && memcmp(x1, "Name:", 5) == 0, "openat under it");
    close(sfd);
    CHECK(read(dfd, x1, 1) == -1 && errno == EISDIR, "a directory reads EISDIR");
    close(dfd);
    errno = 0;
    CHECK(open("/proc/self/stat/x", O_RDONLY) == -1 && errno == ENOTDIR, "under a file: ENOTDIR");
    errno = 0;
    CHECK(open("/proc/no-such", O_RDONLY) == -1 && errno == ENOENT, "a name that isn't: ENOENT");
    errno = 0;
    CHECK(open("/proc/self/stat", O_WRONLY) == -1 && errno == EACCES, "stat can't be written");
    fd = open("/proc/self/oom_score_adj", O_WRONLY);
    CHECK(fd >= 0 && write(fd, "0\n", 2) == 2, "oom_score_adj takes a write");
    close(fd);

    // a name below a descriptor; the names fd/N gives: links replaced, a
    // rename followed, a /proc file by its path
    {
        char dir[64], p2[128], to[128], got[160], five[8];
        struct stat ls;
        mkdir("/tmp", 01777);
        snprintf(dir, sizeof dir, "/tmp/lt_procfs.%d", me);
        CHECK(mkdir(dir, 0700) == 0, "a directory to work in");
        int pin = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
        CHECK(pin >= 0, "open it with O_PATH");
        snprintf(p2, sizeof p2, "/proc/self/fd/%d/sub", pin);
        CHECK(mkdir(p2, 0700) == 0, "mkdir below fd/N");
        CHECK(lstat(p2, &ls) == 0 && S_ISDIR(ls.st_mode), "lstat below fd/N");
        snprintf(p2, sizeof p2, "%s/sub", dir);
        CHECK(stat(p2, &ls) == 0 && S_ISDIR(ls.st_mode), "it is in the directory");
        snprintf(p2, sizeof p2, "/proc/self/fd/%d/sub/real", pin);
        int wfd = open(p2, O_WRONLY | O_CREAT | O_EXCL, 0600);
        CHECK(wfd >= 0 && write(wfd, "below", 5) == 5, "create a file below fd/N");
        close(wfd);
        snprintf(p2, sizeof p2, "%s/link", dir);
        CHECK(symlink("sub/real", p2) == 0, "a link to the file");
        snprintf(p2, sizeof p2, "%s/sub/../link", dir);
        int rfd = open(p2, O_RDONLY);
        CHECK(rfd >= 0, "open it through the link and ..");
        snprintf(path, sizeof path, "/proc/self/fd/%d", rfd);
        snprintf(to, sizeof to, "%s/sub/real", dir);
        n = readlink(path, got, sizeof got - 1);
        CHECK(n > 0 && (got[n] = 0, strcmp(got, to) == 0), "fd/N names what the link leads to");
        snprintf(p2, sizeof p2, "/proc/self/fd/%d/x", rfd);
        errno = 0;
        CHECK(open(p2, O_RDONLY) == -1 && errno == ENOTDIR, "below a file's fd: ENOTDIR");
        int again2 = open(path, O_RDONLY);
        CHECK(again2 >= 0 && read(again2, five, sizeof five) == 5 && memcmp(five, "below", 5) == 0, "open fd/N reads the file");
        close(again2);
        snprintf(p2, sizeof p2, "%s/sub/real", dir);
        snprintf(to, sizeof to, "%s/sub/moved", dir);
        CHECK(rename(p2, to) == 0, "rename the file");
        n = readlink(path, got, sizeof got - 1);
        CHECK(n > 0 && (got[n] = 0, strcmp(got, to) == 0), "fd/N follows the rename");
        CHECK(unlink(to) == 0, "unlink the file");
        n = readlink(path, got, sizeof got - 1);
        CHECK(n > 10 && (got[n] = 0, strcmp(got + n - 10, " (deleted)") == 0), "fd/N of a file with no name: (deleted)");
        close(rfd);
        snprintf(p2, sizeof p2, "/proc/self/fd/%d/link", pin);
        CHECK(unlink(p2) == 0, "unlink below fd/N");
        snprintf(p2, sizeof p2, "/proc/self/fd/%d/sub", pin);
        CHECK(rmdir(p2) == 0, "rmdir below fd/N");
        // a directory on the inode a file just had
        snprintf(p2, sizeof p2, "%s/was", dir);
        int tfd = open(p2, O_WRONLY | O_CREAT, 0600);
        close(tfd);
        CHECK(tfd >= 0 && unlink(p2) == 0, "a file made and removed");
        snprintf(p2, sizeof p2, "%s/now", dir);
        CHECK(mkdir(p2, 0700) == 0, "a directory after it");
        int nfd = open(p2, O_PATH | O_DIRECTORY);
        snprintf(path, sizeof path, "/proc/self/fd/%d", nfd);
        n = readlink(path, got, sizeof got - 1);
        CHECK(nfd >= 0 && n > 0 && (got[n] = 0, strcmp(got, p2) == 0), "fd/N of a new directory is its own path");
        close(nfd);
        CHECK(rmdir(p2) == 0, "remove it");
        close(pin);
        CHECK(rmdir(dir) == 0, "the directory is empty again");

        int vfd = open("/proc/version", O_RDONLY | O_NOFOLLOW);
        snprintf(path, sizeof path, "/proc/self/fd/%d", vfd);
        n = readlink(path, got, sizeof got - 1);
        CHECK(vfd >= 0 && n > 0 && (got[n] = 0, strcmp(got, "/proc/version") == 0), "fd/N of a /proc file is its path");
        int v2 = open(path, O_RDONLY);
        CHECK(v2 >= 0 && read(v2, five, 5) == 5 && memcmp(five, "Linux", 5) == 0, "open fd/N of a /proc file reads it");
        close(v2);
        close(vfd);
        int cfd = open("/proc/self/comm", O_RDONLY);
        snprintf(path, sizeof path, "/proc/self/fd/%d", cfd);
        snprintf(want, sizeof want, "/proc/%d/comm", me);
        n = readlink(path, got, sizeof got - 1);
        CHECK(cfd >= 0 && n > 0 && (got[n] = 0, strcmp(got, want) == 0), "a process's file: under its number");
        close(cfd);
    }

    // the root lists this process; the system's files
    snprintf(want, sizeof want, "%d", me);
    CHECK(has_entry("/proc", want) && has_entry("/proc", "self") && has_entry("/proc", "meminfo"), "/proc lists this process");
    CHECK(slurp("/proc/meminfo") > 0, "read meminfo");
    unsigned long total = 0, avail = 0;
    char *m = strstr(text, "MemTotal:"), *v = strstr(text, "MemAvailable:");
    CHECK(m && v && sscanf(m, "MemTotal: %lu kB", &total) == 1 && sscanf(v, "MemAvailable: %lu kB", &avail) == 1 && total > 0 && avail <= total, "meminfo: MemTotal, MemAvailable");
    CHECK(slurp("/proc/cpuinfo") > 0 && strstr(text, "processor\t: 0") && strstr(text, "\nflags\t\t:") && strstr(text, " sse2"), "cpuinfo");
    CHECK(slurp("/proc/stat") > 0 && strncmp(text, "cpu ", 4) == 0 && strstr(text, "\ncpu0 ") && strstr(text, "\nbtime "), "stat: cpu lines, btime");
    double up = 0, idle = 0;
    CHECK(slurp("/proc/uptime") > 0 && sscanf(text, "%lf %lf", &up, &idle) == 2 && up > 0, "uptime");
    CHECK(slurp("/proc/loadavg") > 0 && strchr(text, '/') != NULL, "loadavg");
    struct utsname u;
    CHECK(uname(&u) == 0 && slurp("/proc/sys/kernel/osrelease") > 0 && strncmp(text, u.release, strlen(u.release)) == 0, "osrelease is uname's");
    char id1[40], id2[40];
    CHECK(slurp("/proc/sys/kernel/random/uuid") == 37 && (memcpy(id1, text, 36), slurp("/proc/sys/kernel/random/uuid") == 37), "uuid");
    memcpy(id2, text, 36);
    CHECK(memcmp(id1, id2, 36) != 0 && id1[8] == '-' && id1[14] == '4', "a fresh one each time");
    CHECK(slurp("/proc/self/mounts") > 0 && strstr(text, " / ext2 ") != NULL, "mounts: the root");
    CHECK(slurp("/proc/self/limits") > 0 && strstr(text, "Max open files") != NULL, "limits");

    // another process
    int ready[2];
    CHECK(pipe(ready) == 0, "a pipe to start the child");
    pid_t c = fork();
    if (c == 0) {
        close(ready[0]);
        if (write(ready[1], "x", 1) != 1) _exit(1);
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1, "the child is up");
    close(ready[0]);
    usleep(20 * 1000);
    snprintf(path, sizeof path, "/proc/%d/stat", c);
    CHECK(slurp(path) > 0, "read the child's stat");
    close_paren = strrchr(text, ')');
    CHECK(close_paren && sscanf(close_paren + 2, "%c %d", &state, &sppid) == 2 && state == 'S' && sppid == me, "it sleeps, its parent is this one");
    snprintf(path, sizeof path, "/proc/%d/cmdline", c);
    CHECK(slurp(path) == (ssize_t)args_len && strcmp(text, argv[0]) == 0, "a forked child's cmdline is its parent's");
    kill(c, SIGKILL);
    int ws;
    CHECK(waitpid(c, &ws, 0) == c, "reap it");
    errno = 0;
    CHECK(open(path, O_RDONLY) == -1 && errno == ENOENT, "gone: its directory too");

    // threads
    pthread_t th;
    CHECK(pthread_create(&th, NULL, in_thread, NULL) == 0, "pthread_create");
    while (!thread_tid) usleep(1000);
    snprintf(want, sizeof want, "%d/task/%d", me, thread_tid);
    CHECK(strcmp(thread_link, want) == 0, "thread-self in a thread");
    CHECK(count_entries("/proc/self/task") == 2, "task/ has both threads");
    CHECK(slurp("/proc/self/status") > 0 && strstr(text, "\nThreads:\t2\n") != NULL, "status: two threads");
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", thread_tid);
    CHECK(slurp(path) > 0 && sscanf(text, "%d", &spid) == 1 && spid == thread_tid, "the thread's own stat");
    thread_go = 1;
    pthread_join(th, NULL);

    // ttyname, through fd/
    int mfd = posix_openpt(O_RDWR | O_NOCTTY);
    CHECK(mfd >= 0 && grantpt(mfd) == 0 && unlockpt(mfd) == 0, "a pty");
    char *pts = ptsname(mfd);
    int s = pts ? open(pts, O_RDWR | O_NOCTTY) : -1;
    CHECK(s >= 0, "its slave");
    char *name = ttyname(s);
    CHECK(name && strcmp(name, pts) == 0, "ttyname of the slave is its /dev/pts name");
    CHECK(stat("/dev/null", &st) == 0 && S_ISCHR(st.st_mode) && major(st.st_rdev) == 1 && minor(st.st_rdev) == 3, "/dev/null is 1:3");
    close(s);
    close(mfd);

    printf("lt_procfs: all %d checks passed\n", check_no);
    return 0;
}
