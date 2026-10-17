// lt_proc — Linux processes and the plumbing a build driver uses between
// them: fork (from the main thread and from another one), wait4 statuses,
// kill, pipes, dup2 onto stdout, poll with and without timeouts, execve with
// argv, envp and close-on-exec (of a stamped image and of one that carries
// no OSABI stamp), the FP state across fork, process_vm_readv on itself,
// sysinfo. Exit 0 = every check passed, else the number of the first failed
// check. Run as `lt_proc exec-child <fd-cloexec> <fd-kept>` it is the
// execve target instead.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <fenv.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    char *nav[] = {"nope", NULL};
    CHECK(execve("/bin/no-such-file", nav, nav) == -1 && errno == ENOENT, "execve of a missing file returns");

    // process_vm_readv on itself
    static const char secret[] = "readv me";
    char got[sizeof secret] = {0};
    struct iovec l = {got, sizeof got}, r = {(void *)secret, sizeof secret};
    CHECK(process_vm_readv(getpid(), &l, 1, &r, 1, 0) == (ssize_t)sizeof secret && memcmp(got, secret, sizeof secret) == 0, "process_vm_readv");
    struct iovec rbad = {(void *)16, 8};
    CHECK(process_vm_readv(getpid(), &l, 1, &rbad, 1, 0) == -1 && errno == EFAULT, "process_vm_readv of unmapped memory");

    // sysinfo
    struct sysinfo si;
    CHECK(sysinfo(&si) == 0 && si.totalram > 0 && si.freeram <= si.totalram, "sysinfo");

    // churn
    for (int i = 0; i < 20; i++) {
        p = fork();
        if (p == 0) _exit(i);
        CHECK(wait_exit(p) == i, "fork churn");
    }

    printf("lt_proc: all %d checks passed\n", check_no);
    return 0;
}
