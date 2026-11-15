// lt_proc — Linux processes and the plumbing a build driver uses between
// them: fork (from the main thread and from another one), wait4 statuses,
// kill, pipes, dup2 onto stdout, poll with and without timeouts, execve with
// argv, envp and close-on-exec (of a stamped image and of one that carries
// no OSABI stamp), the FP state across fork, process_vm_readv on itself,
// sysinfo, /dev/null as a child's stdin, tkill, pids that are not reused at
// once, process groups and sessions. Exit 0 = every check passed, else the
// number of the first failed check. Run as
// `lt_proc exec-child <fd-cloexec> <fd-kept>` it is the execve target instead.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <fenv.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int check_no;

#define CHECK(cond, what)                                                      \
    do {                                                                       \
        check_no++;                                                            \
        if (!(cond)) {                                                         \
            printf("lt_proc: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                    \
        }                                                                      \
    } while (0)

static long long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}

static void nap_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

// The execve target: argv and envp arrived, the close-on-exec fd is gone,
// the other one is still there.
static int exec_child(int argc, char **argv) {
    if (argc != 4) return 101;
    const char *foo = getenv("FOO");
    if (!foo || strcmp(foo, "bar") != 0) return 102;
    int gone = atoi(argv[2]), kept = atoi(argv[3]);
    if (fcntl(gone, F_GETFD) != -1 || errno != EBADF) return 103;
    if (fcntl(kept, F_GETFD) != 0) return 104;
    if (write(kept, "E", 1) != 1) return 105;
    return 7;
}

static int wait_exit(pid_t pid) {
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1;
    if (!WIFEXITED(st)) return -2;
    return WEXITSTATUS(st);
}

static pid_t forked_in_thread;

static void *fork_from_thread(void *arg) {
    (void)arg;
    pid_t p = fork();
    if (p == 0) _exit(33);
    forked_in_thread = p;
    return NULL;
}

static void *sleep_forever(void *arg) {
    (void)arg;
    for (;;) nap_ms(1000);
    return NULL;
}

static int run_exec(const char *image, int gone, int kept) {
    char a2[16], a3[16];
    snprintf(a2, sizeof a2, "%d", gone);
    snprintf(a3, sizeof a3, "%d", kept);
    pid_t p = fork();
    if (p == 0) {
        char *argv[] = {"lt_proc", "exec-child", a2, a3, NULL};
        char *envp[] = {"FOO=bar", "HOME=/", NULL};
        execve(image, argv, envp);
        _exit(100 + errno);
    }
    return wait_exit(p);
}

static void *report_ids(void *arg) {
    pid_t *ids = arg;
    ids[0] = getpid();
    ids[1] = syscall(SYS_gettid);
    return NULL;
}

// A child that sits in read() on `fd` until the parent closes `other`, the
// writing end, or it is killed.
static pid_t held_child(int fd, int other) {
    pid_t p = fork();
    if (p == 0) {
        char c;
        close(other);
        _exit(read(fd, &c, 1) == 0 ? 0 : 1);
    }
    return p;
}

// Whether waitpid(which) returns `a` and `b`, in either order, each ended by
// `sig`.
static int both_signalled(pid_t which, pid_t a, pid_t b, int sig) {
    int st = 0;
    pid_t r1 = waitpid(which, &st, 0);
    if ((r1 != a && r1 != b) || !WIFSIGNALED(st) || WTERMSIG(st) != sig) return 0;
    pid_t r2 = waitpid(which, &st, 0);
    return (r2 == a || r2 == b) && r2 != r1 && WIFSIGNALED(st) && WTERMSIG(st) == sig;
}

// Pids that are not handed out again at once, tids, process groups and
// sessions.
static void check_pids_and_groups(void) {
    int st;
    pid_t me = getpid();

    pid_t seen[40];
    int fresh = 1;
    for (int i = 0; i < 40; i++) {
        pid_t p = fork();
        if (p == 0) _exit(0);
        if (p <= 0 || waitpid(p, NULL, 0) != p) fresh = 0;
        for (int k = 0; k < i; k++)
            if (seen[k] == p) fresh = 0;
        seen[i] = p;
    }
    CHECK(fresh, "40 children one after another, 40 pids");
    pid_t gone = seen[0];
    errno = 0;
    CHECK(kill(gone, 0) == -1 && errno == ESRCH, "a reaped child's pid names nothing");
    errno = 0;
    CHECK(waitpid(gone, NULL, 0) == -1 && errno == ECHILD, "and no child to wait for");

    pid_t ids[2] = {0, 0};
    pthread_t th;
    CHECK(syscall(SYS_gettid) == me, "the first thread's tid is the pid");
    CHECK(pthread_create(&th, NULL, report_ids, ids) == 0 && pthread_join(th, NULL) == 0, "a thread to ask");
    CHECK(ids[0] == me && ids[1] > 0 && ids[1] != me, "it has the pid, and a tid of its own");
    CHECK(syscall(SYS_tgkill, me, me, 0) == 0, "tgkill finds a thread of the process");
    errno = 0;
    CHECK(syscall(SYS_tgkill, gone, me, 0) == -1 && errno == ESRCH, "but not under another pid");

    pid_t mygrp = getpgrp(), mysid = getsid(0);
    CHECK(mygrp > 0 && getpgid(0) == mygrp && getpgid(me) == mygrp && getsid(me) == mysid, "getpgid and getsid of itself");
    errno = 0;
    CHECK(getpgid(gone) == -1 && errno == ESRCH, "getpgid of nobody is ESRCH");

    // Two children in a group of their own, ended together from outside.
    int hold[2];
    CHECK(pipe(hold) == 0, "a pipe to hold children on");
    pid_t a = held_child(hold[0], hold[1]);
    pid_t b = held_child(hold[0], hold[1]);
    CHECK(a > 0 && b > 0 && getpgid(a) == mygrp, "a child starts in the parent's group");
    CHECK(setpgid(a, a) == 0 && getpgid(a) == a, "setpgid starts a group");
    CHECK(setpgid(b, a) == 0 && getpgid(b) == a, "and another child joins it");
    CHECK(getpgrp() == mygrp && getsid(a) == mysid, "the parent's group and the session stay");
    errno = 0;
    CHECK(setpgid(b, gone) == -1 && errno == EPERM, "no moving to a group that isn't there");
    errno = 0;
    CHECK(setpgid(1, 1) == -1 && errno == ESRCH, "nor moving what is not a child");
    CHECK(kill(-a, 0) == 0, "kill(-pgid, 0) finds the group");
    CHECK(waitpid(-a, &st, WNOHANG) == 0, "waitpid(-pgid) sees its children run");
    CHECK(kill(-a, SIGTERM) == 0, "kill(-pgid) signals the group");
    CHECK(both_signalled(-a, a, b, SIGTERM), "waitpid(-pgid) reaps both");
    errno = 0;
    CHECK(waitpid(-a, &st, 0) == -1 && errno == ECHILD, "then the group has no children");
    errno = 0;
    CHECK(kill(-a, 0) == -1 && errno == ESRCH, "and no members");

    // kill(0) from a member reaches its whole group.
    int go[2];
    CHECK(pipe(go) == 0, "a pipe to start a child on");
    pid_t k1 = fork();
    if (k1 == 0) {
        char c;
        close(go[1]);
        if (read(go[0], &c, 1) == 1) kill(0, SIGTERM);
        _exit(9);
    }
    pid_t k2 = held_child(hold[0], hold[1]);
    CHECK(k1 > 0 && k2 > 0 && setpgid(k1, k1) == 0 && setpgid(k2, k1) == 0, "another group of two");
    CHECK(write(go[1], "g", 1) == 1 && both_signalled(-k1, k1, k2, SIGTERM), "kill(0) ends the caller's group");
    CHECK(kill(me, 0) == 0, "and nobody outside it");
    close(go[0]);
    close(go[1]);

    // waitpid(0) is for the children in the caller's group.
    pid_t c = fork();
    if (c == 0) _exit(3);
    pid_t d = fork();
    if (d == 0) _exit(setpgid(0, 0) == 0 && getpgrp() == getpid() ? 4 : 5);
    CHECK(waitpid(0, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 3, "waitpid(0) reaps a child of the group");
    errno = 0;
    CHECK(waitpid(0, &st, 0) == -1 && errno == ECHILD, "and not one that left it");
    CHECK(waitpid(-1, &st, 0) == d && WIFEXITED(st) && WEXITSTATUS(st) == 4, "waitpid(-1) does");

    // A group goes on by its leader's pid after the leader.
    pid_t lead = held_child(hold[0], hold[1]);
    pid_t member = held_child(hold[0], hold[1]);
    CHECK(lead > 0 && member > 0 && setpgid(lead, lead) == 0 && setpgid(member, lead) == 0, "a leader and a member");
    CHECK(kill(lead, SIGKILL) == 0 && waitpid(lead, &st, 0) == lead, "the leader ends");
    CHECK(getpgid(member) == lead && kill(-lead, 0) == 0, "its group is still there");
    int reused = 0;
    for (int i = 0; i < 10; i++) {
        pid_t p = fork();
        if (p == 0) _exit(0);
        waitpid(p, NULL, 0);
        if (p == lead) reused = 1;
    }
    CHECK(!reused, "and no new process takes its pid");
    CHECK(kill(-lead, SIGKILL) == 0 && waitpid(member, &st, 0) == member && WTERMSIG(st) == SIGKILL, "the member ends with the group");

    // setsid in a child: a session and a group of its own.
    int up[2];
    CHECK(pipe(up) == 0, "a pipe for the child's word");
    pid_t s = fork();
    if (s == 0) {
        char ch;
        int bad = 0;
        pid_t self = getpid();
        close(hold[1]);
        close(up[0]);
        if (setsid() != self) bad |= 1;
        if (getsid(0) != self || getpgrp() != self) bad |= 2;
        errno = 0;
        if (setsid() != -1 || errno != EPERM) bad |= 4;
        errno = 0;
        if (setpgid(0, 0) != -1 || errno != EPERM) bad |= 8;
        if (write(up[1], "s", 1) != 1) bad |= 16;
        if (read(hold[0], &ch, 1) != 0) bad |= 32;
        _exit(bad);
    }
    char word;
    CHECK(s > 0 && read(up[0], &word, 1) == 1, "the child reports in");
    CHECK(getsid(s) == s && getpgid(s) == s && getsid(0) == mysid, "setsid starts a session and a group");
    errno = 0;
    CHECK(setpgid(s, mygrp) == -1 && errno == EPERM, "a process of another session is not moved");
    close(hold[1]);
    CHECK(wait_exit(s) == 0, "and the child saw it the same way");
    close(hold[0]);
    close(up[0]);
    close(up[1]);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "exec-child") == 0) return exec_child(argc, argv);
    setvbuf(stdout, NULL, _IONBF, 0);

    // fork, exit code, getppid
    pid_t me = getpid();
    pid_t p = fork();
    if (p == 0) _exit(getppid() == me ? 42 : 1);
    CHECK(p > 0, "fork");
    CHECK(wait_exit(p) == 42, "child exit code and getppid");

    // a child forked by another thread is the process's: main reaps it
    pthread_t th;
    CHECK(pthread_create(&th, NULL, fork_from_thread, NULL) == 0, "pthread_create");
    pthread_join(th, NULL);
    CHECK(forked_in_thread > 0 && wait_exit(forked_in_thread) == 33, "reap a child another thread forked");

    // no children left; WNOHANG on a running child
    CHECK(waitpid(-1, NULL, 0) == -1 && errno == ECHILD, "ECHILD with no children");
    p = fork();
    if (p == 0) {
        nap_ms(100);
        _exit(5);
    }
    CHECK(waitpid(p, NULL, WNOHANG) == 0, "WNOHANG on a running child");
    CHECK(wait_exit(p) == 5, "then reaped");

    // kill ends a sleeping child with the signal
    p = fork();
    if (p == 0) {
        for (;;) nap_ms(1000);
    }
    nap_ms(20);
    CHECK(kill(p, SIGKILL) == 0, "kill");
    int st = 0;
    CHECK(waitpid(p, &st, 0) == p && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "killed status");

    // the FP control state crosses fork
    fesetround(FE_UPWARD);
    p = fork();
    if (p == 0) _exit(fegetround() == FE_UPWARD ? 0 : 1);
    CHECK(wait_exit(p) == 0, "MXCSR inherited by the child");
    fesetround(FE_TONEAREST);

    // a pipe both ways
    int down[2], up[2];
    CHECK(pipe(down) == 0 && pipe(up) == 0, "pipe");
    p = fork();
    if (p == 0) {
        char buf[8] = {0};
        close(down[1]);
        close(up[0]);
        if (read(down[0], buf, 5) != 5 || memcmp(buf, "hello", 5) != 0) _exit(1);
        if (write(up[1], "world", 5) != 5) _exit(2);
        _exit(0);
    }
    close(down[0]);
    close(up[1]);
    CHECK(write(down[1], "hello", 5) == 5, "write to the child");
    char buf[16] = {0};
    CHECK(read(up[0], buf, 5) == 5 && memcmp(buf, "world", 5) == 0, "read from the child");
    CHECK(wait_exit(p) == 0, "pipe child");
    close(down[1]);
    CHECK(read(up[0], buf, 1) == 0, "EOF once the writer is gone");
    close(up[0]);

    // dup2 onto stdout, as a spawner wires its child's
    int out[2];
    CHECK(pipe2(out, O_CLOEXEC) == 0, "pipe2");
    CHECK(fcntl(out[0], F_GETFD) == FD_CLOEXEC, "O_CLOEXEC recorded");
    p = fork();
    if (p == 0) {
        if (dup2(out[1], 1) != 1) _exit(1);
        printf("via stdout");
        fflush(stdout);
        _exit(0);
    }
    close(out[1]);
    memset(buf, 0, sizeof buf);
    CHECK(read(out[0], buf, 10) == 10 && memcmp(buf, "via stdout", 10) == 0, "child's stdout through the pipe");
    CHECK(wait_exit(p) == 0, "dup2 child");
    close(out[0]);

    // fcntl / dup family
    int fds[2];
    CHECK(pipe(fds) == 0, "pipe for dups");
    CHECK(fcntl(fds[0], F_GETFD) == 0, "no FD_CLOEXEC by default");
    int d = fcntl(fds[0], F_DUPFD_CLOEXEC, 20);
    CHECK(d >= 20 && fcntl(d, F_GETFD) == FD_CLOEXEC, "F_DUPFD_CLOEXEC");
    CHECK(dup3(fds[0], 30, O_CLOEXEC) == 30 && fcntl(30, F_GETFD) == FD_CLOEXEC, "dup3 O_CLOEXEC");
    CHECK(fcntl(30, F_SETFD, 0) == 0 && fcntl(30, F_GETFD) == 0, "F_SETFD");
    close(d);
    close(30);
    CHECK(write(fds[1], "x", 1) == 1, "pipe still open after closing the dups");
    CHECK(read(fds[0], buf, 1) == 1, "read through the original");

    // poll: a timeout, data, a wake from another process, hang-up
    struct pollfd pf = {fds[0], POLLIN, 0};
    long long t0 = now_ms();
    CHECK(poll(&pf, 1, 50) == 0, "poll times out on an empty pipe");
    CHECK(now_ms() - t0 >= 40, "and waited");
    CHECK(write(fds[1], "y", 1) == 1 && poll(&pf, 1, 0) == 1 && (pf.revents & POLLIN), "POLLIN with data");
    CHECK(read(fds[0], buf, 1) == 1, "drain");
    p = fork();
    if (p == 0) {
        nap_ms(100);
        _exit(write(fds[1], "z", 1) == 1 ? 0 : 1);
    }
    t0 = now_ms();
    pf.revents = 0;
    CHECK(poll(&pf, 1, -1) == 1 && (pf.revents & POLLIN), "poll woken by a write in another process");
    CHECK(now_ms() - t0 < 2000, "promptly");
    CHECK(wait_exit(p) == 0, "poll child");
    CHECK(read(fds[0], buf, 1) == 1, "drain again");
    close(fds[1]);
    pf.revents = 0;
    CHECK(poll(&pf, 1, 0) == 1 && (pf.revents & POLLHUP), "POLLHUP once the writer is gone");
    close(fds[0]);
    struct pollfd bad = {63, POLLIN, 0};
    CHECK(poll(&bad, 1, 0) == 1 && bad.revents == POLLNVAL, "POLLNVAL for a closed fd");

    // execve: argv, envp, close-on-exec; a stamped image and a plain one
    int gone[2], kept[2];
    CHECK(pipe2(gone, O_CLOEXEC) == 0 && pipe(kept) == 0, "pipes for exec");
    CHECK(run_exec("/bin/lt_proc.elf", gone[1], kept[1]) == 7, "execve of a stamped image");
    CHECK(run_exec("/bin/lt_proc_plain.elf", gone[1], kept[1]) == 7, "execve of an unstamped image");
    CHECK(read(kept[0], buf, 2) == 2 && memcmp(buf, "EE", 2) == 0, "both wrote through the kept fd");
    // execve from a process with another thread: that one goes first
    p = fork();
    if (p == 0) {
        pthread_t sleeper;
        if (pthread_create(&sleeper, NULL, sleep_forever, NULL) != 0) _exit(90);
        nap_ms(20);
        char a2[16], a3[16];
        snprintf(a2, sizeof a2, "%d", gone[1]);
        snprintf(a3, sizeof a3, "%d", kept[1]);
        char *argv2[] = {"lt_proc", "exec-child", a2, a3, NULL};
        char *envp2[] = {"FOO=bar", NULL};
        execve("/bin/lt_proc.elf", argv2, envp2);
        _exit(91);
    }
    CHECK(wait_exit(p) == 7, "execve from a two-thread process");
    CHECK(read(kept[0], buf, 1) == 1 && buf[0] == 'E', "and it ran");

    // clone's fork shapes. glibc's fork: the child's tid stored in the
    // child's memory only, the parent told where it asks.
    static pid_t child_word, parent_word;
    child_word = -1;
    parent_word = -1;
    long cl = syscall(SYS_clone, CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | CLONE_PARENT_SETTID | SIGCHLD, 0,
                      &parent_word, &child_word, 0);
    if (cl == 0) _exit(child_word == getpid() ? 0 : 1);
    CHECK(cl > 0 && parent_word == cl && child_word == -1, "clone as a fork: the tid words go where they belong");
    CHECK(wait_exit(cl) == 0, "the child found its tid in its own word");
    // posix_spawn's: a child on a stack of its own that execs.
    char a2[16], a3[16];
    snprintf(a2, sizeof a2, "%d", gone[1]);
    snprintf(a3, sizeof a3, "%d", kept[1]);
    char *sargv[] = {"lt_proc", "exec-child", a2, a3, NULL};
    char *senvp[] = {"FOO=bar", NULL};
    pid_t sp = -1;
    CHECK(posix_spawn(&sp, "/bin/lt_proc.elf", NULL, NULL, sargv, senvp) == 0 && sp > 0, "posix_spawn");
    CHECK(wait_exit(sp) == 7 && read(kept[0], buf, 1) == 1 && buf[0] == 'E', "its child ran the image");
    CHECK(posix_spawn(&sp, "/bin/no-such-file", NULL, NULL, sargv, senvp) == ENOENT, "posix_spawn of a missing file says so");
    char *nav[] = {"nope", NULL};
    CHECK(execve("/bin/no-such-file", nav, nav) == -1 && errno == ENOENT, "execve of a missing file returns");

    // process_vm_readv on itself
    static const char secret[] = "readv me";
    char got[sizeof secret] = {0};
    struct iovec l = {got, sizeof got}, r = {(void *)secret, sizeof secret};
    CHECK(process_vm_readv(getpid(), &l, 1, &r, 1, 0) == (ssize_t)sizeof secret && memcmp(got, secret, sizeof secret) == 0, "process_vm_readv");
    struct iovec rbad = {(void *)16, 8};
    CHECK(process_vm_readv(getpid(), &l, 1, &rbad, 1, 0) == -1 && errno == EFAULT, "process_vm_readv of unmapped memory");
    static char span[24] = "0123456789abcdefghijklm";
    struct iovec lo = {span, 16}, ro = {span + 8, 16};
    CHECK(process_vm_readv(getpid(), &lo, 1, &ro, 1, 0) == 16 && memcmp(span, "89abcdefghijklm", 16) == 0, "process_vm_readv between overlapping ranges");

    // sysinfo
    struct sysinfo si;
    CHECK(sysinfo(&si) == 0 && si.totalram > 0 && si.freeram <= si.totalram, "sysinfo");

    // a child with /dev/null for stdin, as a build runner starts its tools
    int nul = open("/dev/null", O_RDWR);
    CHECK(nul >= 0, "open /dev/null");
    p = fork();
    if (p == 0) {
        char c;
        if (dup2(nul, 0) != 0) _exit(1);
        _exit(read(0, &c, 1) == 0 ? 0 : 2);
    }
    CHECK(wait_exit(p) == 0, "dup2 of /dev/null onto stdin, EOF from it");
    close(nul);

    // abort() raises SIGABRT with tkill: it ends the process
    p = fork();
    if (p == 0) {
        syscall(SYS_tkill, syscall(SYS_gettid), SIGABRT);
        _exit(0);
    }
    CHECK(waitpid(p, &st, 0) == p && WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT, "tkill(SIGABRT) status");

    check_pids_and_groups();

    // churn
    for (int i = 0; i < 20; i++) {
        p = fork();
        if (p == 0) _exit(i);
        CHECK(wait_exit(p) == i, "fork churn");
    }

    printf("lt_proc: all %d checks passed\n", check_no);
    return 0;
}
