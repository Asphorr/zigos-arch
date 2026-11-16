// lt_signal — Linux signals: handlers with and without SA_SIGINFO, what a
// handler is told about the sender, the mask and the pending set, nesting,
// SA_RESETHAND and SA_NODEFER, ignoring, signals from another process and to
// one thread or any, a handler that cuts into a busy loop with every
// register and the FP state put back, the alternate stack, faults caught and
// not, SIGCHLD, a sleep cut short, the YMM registers in the frame. Exit 0 =
// every check passed, else the number of the first failed check.

#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int check_no;

#define CHECK(cond, what)                                                        \
    do {                                                                         \
        check_no++;                                                              \
        if (!(cond)) {                                                           \
            printf("lt_signal: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                      \
        }                                                                        \
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

// Wait for a handler to set `flag`, up to `ms`.
static int flag_set(volatile sig_atomic_t *flag, long ms) {
    long long until = now_ms() + ms;
    while (!*flag && now_ms() < until) nap_ms(1);
    return *flag != 0;
}

static void install(int sig, void (*fn)(int, siginfo_t *, void *), int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = fn;
    sa.sa_flags = SA_SIGINFO | flags;
    sigemptyset(&sa.sa_mask);
    if (sigaction(sig, &sa, NULL) != 0) {
        printf("lt_signal: sigaction(%d) failed (errno %d)\n", sig, errno);
        exit(200);
    }
}

static int blocked_now(int sig) {
    sigset_t cur;
    sigprocmask(SIG_BLOCK, NULL, &cur);
    return sigismember(&cur, sig);
}

// What the last handler saw.
static volatile sig_atomic_t seen_count, seen_sig, seen_code, seen_pid, seen_status, seen_tid;
static void *volatile seen_addr;

static void record(int sig, siginfo_t *info, void *uc) {
    (void)uc;
    seen_sig = sig;
    seen_code = info->si_code;
    seen_pid = info->si_pid;
    seen_status = info->si_status;
    seen_addr = info->si_addr;
    seen_tid = syscall(SYS_gettid);
    seen_count++;
}

static volatile sig_atomic_t plain_count;
static void plain(int sig) {
    plain_count += sig;
}

// --- masks inside a handler, nesting ---------------------------------------------

static volatile sig_atomic_t in_handler_self, in_handler_other;
static void look_at_mask(int sig, siginfo_t *info, void *uc) {
    (void)info;
    (void)uc;
    in_handler_self = blocked_now(sig);
    in_handler_other = blocked_now(SIGUSR2);
}

static volatile sig_atomic_t order[4], order_n;
static void inner(int sig, siginfo_t *info, void *uc) {
    (void)sig;
    (void)info;
    (void)uc;
    order[order_n++] = 2;
}
static void outer(int sig, siginfo_t *info, void *uc) {
    (void)sig;
    (void)info;
    (void)uc;
    order[order_n++] = 1;
    raise(SIGUSR2);
    order[order_n++] = 3;
}

static volatile sig_atomic_t reentered;
static void reenter(int sig, siginfo_t *info, void *uc) {
    (void)info;
    (void)uc;
    if (reentered++ == 0) raise(sig);
}

// --- a busy loop cut into ----------------------------------------------------------

static volatile int spin_done;
static void end_spin(int sig, siginfo_t *info, void *uc) {
    (void)sig;
    (void)info;
    (void)uc;
    // What the interrupted loop keeps live, a handler is free to use.
    __asm__ volatile("pxor %%xmm7, %%xmm7\n"
                     "xor %%ecx, %%ecx\n"
                     "xor %%r11d, %%r11d\n"
                     "xor %%r8d, %%r8d\n"
                     :
                     :
                     : "xmm7", "rcx", "r11", "r8", "cc");
    spin_done = 1;
}

static const double SPIN_FP = 1234.5678;

// Spin in user code, no call into the kernel, until a handler sets
// spin_done; 0 if every register the loop held came back as it was.
static int spin_keeping_registers(void) {
    unsigned long r[6] = {0};
    double d = 0;
    __asm__ volatile("movabs $0x1122334455667701, %%rcx\n"
                     "movabs $0x1122334455667702, %%r11\n"
                     "movabs $0x1122334455667703, %%r8\n"
                     "movabs $0x1122334455667704, %%r9\n"
                     "movabs $0x1122334455667705, %%r10\n"
                     "movabs $0x1122334455667706, %%rdx\n"
                     "movsd %[fp], %%xmm7\n"
                     "1: cmpl $0, %[done]\n"
                     "je 1b\n"
                     "movq %%rcx, 0(%[r])\n"
                     "movq %%r11, 8(%[r])\n"
                     "movq %%r8, 16(%[r])\n"
                     "movq %%r9, 24(%[r])\n"
                     "movq %%r10, 32(%[r])\n"
                     "movq %%rdx, 40(%[r])\n"
                     "movsd %%xmm7, %[d]\n"
                     : [d] "=m"(d)
                     : [done] "m"(spin_done), [r] "r"(r), [fp] "m"(SPIN_FP)
                     : "rcx", "r11", "r8", "r9", "r10", "rdx", "xmm7", "memory", "cc");
    for (int i = 0; i < 6; i++)
        if (r[i] != 0x1122334455667701UL + i) return 1 + i;
    return d == SPIN_FP ? 0 : 7;
}

// --- the alternate stack ------------------------------------------------------------

static char alt_stack[16384];
static volatile sig_atomic_t on_alt, alt_flag_in;
static void where_am_i(int sig, siginfo_t *info, void *uc) {
    (void)sig;
    (void)info;
    (void)uc;
    char here;
    stack_t st;
    on_alt = &here >= alt_stack && &here < alt_stack + sizeof alt_stack;
    sigaltstack(NULL, &st);
    alt_flag_in = st.ss_flags;
}

// --- faults ---------------------------------------------------------------------------

static sigjmp_buf fault_env;
static void fault_caught(int sig, siginfo_t *info, void *uc) {
    record(sig, info, uc);
    siglongjmp(fault_env, 1);
}

static int child_status(pid_t p) {
    int st = 0;
    if (waitpid(p, &st, 0) != p) return -1;
    return st;
}

// --- the YMM registers ----------------------------------------------------------------

static unsigned long long xgetbv0(void) {
    unsigned lo, hi;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(lo), "=d"(hi) : "c"(0)); // xgetbv
    return ((unsigned long long)hi << 32) | lo;
}

static int have_avx(void) {
    unsigned a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & bit_AVX) || !(c & bit_OSXSAVE)) return 0;
    return (xgetbv0() & 6) == 6;
}

#define LOAD_YMM(in)                   \
    "vmovdqu 0(" in "), %%ymm8\n\t"    \
    "vmovdqu 32(" in "), %%ymm9\n\t"   \
    "vmovdqu 64(" in "), %%ymm10\n\t"  \
    "vmovdqu 96(" in "), %%ymm11\n\t"  \
    "vmovdqu 128(" in "), %%ymm12\n\t" \
    "vmovdqu 160(" in "), %%ymm13\n\t" \
    "vmovdqu 192(" in "), %%ymm14\n\t" \
    "vmovdqu 224(" in "), %%ymm15\n\t"
#define STORE_YMM(out)                  \
    "vmovdqu %%ymm8, 0(" out ")\n\t"    \
    "vmovdqu %%ymm9, 32(" out ")\n\t"   \
    "vmovdqu %%ymm10, 64(" out ")\n\t"  \
    "vmovdqu %%ymm11, 96(" out ")\n\t"  \
    "vmovdqu %%ymm12, 128(" out ")\n\t" \
    "vmovdqu %%ymm13, 160(" out ")\n\t" \
    "vmovdqu %%ymm14, 192(" out ")\n\t" \
    "vmovdqu %%ymm15, 224(" out ")\n\t"
#define YMM_CLOBBERS "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"

// The FP state of a frame in Linux's XSAVE layout: the magic in the FXSAVE
// image's software bytes, the XSAVE header, the upper halves of the YMM
// registers 16 bytes each, the second magic after it all.
#define FX_SW 464
#define FX_HEADER 512
#define FX_YMM 576
#define FX_MAGIC1 0x46505853u
#define FX_MAGIC2 0x46505845u
#define UC_FP_XSTATE 1

static unsigned char ymm_in[256], ymm_junk[256], ymm_fresh[32];
static volatile sig_atomic_t ymm_frame_ok, ymm_flags_ok, ymm_done;

// Reads ymm8..15 in its frame, uses them for its own values, and flips the
// upper half of ymm15 in the frame, which is what the return loads.
__attribute__((target("avx"))) static void ymm_handler(int sig, siginfo_t *info, void *ucv) {
    (void)sig;
    (void)info;
    __asm__ volatile("vmovdqu %%ymm8, %[f]" : [f] "=m"(ymm_fresh) : : "memory");
    ucontext_t *uc = ucv;
    unsigned char *fx = (unsigned char *)uc->uc_mcontext.fpregs;
    unsigned magic1, size, magic2;
    unsigned long long bv;
    memcpy(&magic1, fx + FX_SW, 4);
    memcpy(&size, fx + FX_SW + 16, 4);
    int ok = magic1 == FX_MAGIC1 && size >= FX_YMM + 256;
    if (ok) {
        memcpy(&magic2, fx + size, 4);
        memcpy(&bv, fx + FX_HEADER, 8);
        ok = magic2 == FX_MAGIC2 && (bv & 4);
    }
    for (int r = 8; ok && r < 16; r++) ok = memcmp(fx + FX_YMM + 16 * r, ymm_in + 32 * (r - 8) + 16, 16) == 0;
    ymm_frame_ok = ok;
    ymm_flags_ok = (uc->uc_flags & UC_FP_XSTATE) != 0;
    __asm__ volatile(LOAD_YMM("%[j]") : : [j] "r"(ymm_junk) : "memory", YMM_CLOBBERS);
    if (ok)
        for (int i = 0; i < 16; i++) fx[FX_YMM + 16 * 15 + i] ^= 0xFF;
    ymm_done = 1;
}

// ymm8..15 from `in`, a tkill of `tid` as a raw system call, the registers
// into `out`: the handler runs on the way back from the call.
__attribute__((target("avx"))) static void ymm_through_signal(const unsigned char *in, unsigned char *out, long tid, long sig) {
    __asm__ volatile(LOAD_YMM("%[in]") "movl $200, %%eax\n\t" // SYS_tkill
                                       "syscall\n\t" STORE_YMM("%[out]")
                     :
                     : [in] "r"(in), [out] "r"(out), "D"(tid), "S"(sig)
                     : "rax", "rcx", "r11", "memory", YMM_CLOBBERS);
}

// ymm8..15 from `in`, a spin in user code until a handler sets ymm_done,
// the registers into `out`.
__attribute__((target("avx"))) static void ymm_spin(const unsigned char *in, unsigned char *out) {
    __asm__ volatile(LOAD_YMM("%[in]") "1: cmpl $0, %[done]\n\t"
                                       "je 1b\n\t" STORE_YMM("%[out]")
                     :
                     : [in] "r"(in), [out] "r"(out), [done] "m"(ymm_done)
                     : "memory", "cc", YMM_CLOBBERS);
}

// Where the CPU has AVX: the frame holds the YMM registers as Linux lays
// them out, the handler starts with them clear, the return loads them from
// the frame — by way of a system call and of an interrupt.
static void check_ymm(void) {
    if (!have_avx()) {
        printf("lt_signal: no AVX here, YMM checks skipped\n");
        return;
    }
    unsigned char want[256], out[256];
    static const unsigned char zero[16];
    for (int i = 0; i < 256; i++) {
        ymm_in[i] = (unsigned char)(i * 7 + 3);
        ymm_junk[i] = (unsigned char)(0xA5 ^ i);
    }
    memcpy(want, ymm_in, sizeof want);
    for (int i = 0; i < 16; i++) want[32 * 7 + 16 + i] ^= 0xFF;

    install(SIGUSR1, ymm_handler, 0);
    memset(out, 0, sizeof out);
    ymm_through_signal(ymm_in, out, syscall(SYS_gettid), SIGUSR1);
    CHECK(ymm_done == 1, "a handler between two halves of YMM code");
    CHECK(ymm_frame_ok && ymm_flags_ok, "its frame holds the YMM registers in the XSAVE layout");
    CHECK(memcmp(ymm_fresh + 16, zero, 16) == 0, "the handler starts with their upper halves clear");
    CHECK(memcmp(out, want, sizeof want) == 0, "the return loads them from the frame");

    install(SIGALRM, ymm_handler, 0);
    ymm_done = 0;
    ymm_frame_ok = 0;
    memset(out, 0, sizeof out);
    struct itimerval it = {{0, 0}, {0, 50000}};
    CHECK(setitimer(ITIMER_REAL, &it, NULL) == 0, "a timer to cut into a loop that holds YMM registers");
    long long t0 = now_ms();
    ymm_spin(ymm_in, out);
    CHECK(now_ms() - t0 < 2000 && ymm_frame_ok, "its handler cut in, the registers in its frame");
    CHECK(memcmp(out, want, sizeof want) == 0, "and they came back from it");
    signal(SIGALRM, SIG_DFL);
    signal(SIGUSR1, SIG_DFL);
}

// --- threads ------------------------------------------------------------------------

static volatile sig_atomic_t thread_tid, thread_stop;
static void *open_thread(void *arg) {
    sigset_t none;
    (void)arg;
    sigemptyset(&none);
    pthread_sigmask(SIG_SETMASK, &none, NULL);
    thread_tid = syscall(SYS_gettid);
    while (!thread_stop) nap_ms(1);
    return NULL;
}

// --- calls a signal cuts short --------------------------------------------------------

// A child that sends `sig` here after `ms`, and after `ms` more writes a
// byte to `fd` (if not -1).
static pid_t signal_me_later(int sig, long ms, int fd) {
    pid_t p = fork();
    if (p == 0) {
        nap_ms(ms);
        kill(getppid(), sig);
        if (fd >= 0) {
            nap_ms(ms);
            if (write(fd, "x", 1) != 1) _exit(1);
        }
        _exit(0);
    }
    return p;
}

static volatile sig_atomic_t ticks;
static void tick(int sig) {
    (void)sig;
    ticks++;
}

static void *nap_then_exit(void *arg) {
    (void)arg;
    nap_ms(200);
    return NULL;
}

// Waits a handler interrupts: EINTR, or the call again with SA_RESTART; the
// calls that wait for a signal itself; the timer; SIGPIPE.
static void check_waits_cut_short(void) {
    int fds[2], st;
    char c;
    sigset_t set, none, old;
    pid_t me = getpid();
    sigemptyset(&none);

    // read on an empty pipe.
    CHECK(pipe(fds) == 0, "a pipe to wait on");
    install(SIGUSR1, record, 0);
    seen_count = 0;
    pid_t p = signal_me_later(SIGUSR1, 50, fds[1]);
    errno = 0;
    CHECK(read(fds[0], &c, 1) == -1 && errno == EINTR && seen_count == 1, "a handler cuts read short: EINTR");
    CHECK(read(fds[0], &c, 1) == 1 && c == 'x', "the read tried again gets the byte");
    child_status(p);
    install(SIGUSR1, record, SA_RESTART);
    seen_count = 0;
    p = signal_me_later(SIGUSR1, 50, fds[1]);
    CHECK(read(fds[0], &c, 1) == 1 && c == 'x' && seen_count == 1, "with SA_RESTART the read goes on after the handler");
    child_status(p);

    // waitpid for a child that is still running.
    install(SIGUSR1, record, 0);
    pid_t slow = fork();
    if (slow == 0) {
        nap_ms(300);
        _exit(6);
    }
    p = signal_me_later(SIGUSR1, 50, -1);
    errno = 0;
    CHECK(waitpid(slow, &st, 0) == -1 && errno == EINTR, "a handler cuts waitpid short");
    install(SIGUSR1, record, SA_RESTART);
    kill(me, SIGUSR1);
    CHECK(waitpid(slow, &st, 0) == slow && WEXITSTATUS(st) == 6, "waitpid again reaps the child");
    child_status(p);
    slow = fork();
    if (slow == 0) {
        nap_ms(300);
        _exit(7);
    }
    seen_count = 0;
    p = signal_me_later(SIGUSR1, 50, -1);
    CHECK(waitpid(slow, &st, 0) == slow && WEXITSTATUS(st) == 7 && seen_count == 1, "with SA_RESTART waitpid waits on");
    child_status(p);

    // poll never runs again by itself.
    struct pollfd pf = {.fd = fds[0], .events = POLLIN};
    seen_count = 0;
    p = signal_me_later(SIGUSR1, 50, -1);
    long long t0 = now_ms();
    errno = 0;
    CHECK(poll(&pf, 1, 3000) == -1 && errno == EINTR && seen_count == 1, "a handler cuts poll short, SA_RESTART or not");
    CHECK(now_ms() - t0 < 2000, "at once");
    child_status(p);

    // pause and sigsuspend wait for the handler.
    install(SIGUSR1, record, 0);
    seen_count = 0;
    p = signal_me_later(SIGUSR1, 50, -1);
    errno = 0;
    CHECK(pause() == -1 && errno == EINTR && seen_count == 1, "pause returns once a handler has run");
    child_status(p);
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, &old);
    seen_count = 0;
    p = signal_me_later(SIGUSR1, 50, -1);
    nap_ms(120);
    CHECK(seen_count == 0, "blocked, the signal waits");
    errno = 0;
    CHECK(sigsuspend(&none) == -1 && errno == EINTR && seen_count == 1, "sigsuspend lets it in");
    CHECK(blocked_now(SIGUSR1), "and puts the mask back");
    child_status(p);

    // sigwaitinfo takes a blocked signal without a handler running.
    siginfo_t si;
    seen_count = 0;
    CHECK(kill(me, SIGUSR1) == 0 && seen_count == 0, "a signal sent while blocked");
    memset(&si, 0, sizeof si);
    CHECK(sigwaitinfo(&set, &si) == SIGUSR1 && si.si_signo == SIGUSR1 && si.si_pid == me && si.si_code == SI_USER, "sigwaitinfo takes it");
    CHECK(seen_count == 0 && sigpending(&set) == 0 && !sigismember(&set, SIGUSR1), "no handler ran, nothing is pending");
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    struct timespec brief = {0, 50 * 1000000L};
    t0 = now_ms();
    errno = 0;
    CHECK(sigtimedwait(&set, &si, &brief) == -1 && errno == EAGAIN && now_ms() - t0 >= 40, "sigtimedwait times out");
    p = signal_me_later(SIGUSR1, 50, -1);
    CHECK(sigwaitinfo(&set, &si) == SIGUSR1 && si.si_pid == p, "and waits for one from another process");
    child_status(p);
    sigprocmask(SIG_SETMASK, &old, NULL);

    // The real-time timer.
    signal(SIGALRM, tick);
    CHECK(alarm(5) == 0 && alarm(0) == 5, "alarm reports what was left");
    struct itimerval every = {.it_interval = {0, 20000}, .it_value = {0, 50000}}, was;
    ticks = 0;
    t0 = now_ms();
    CHECK(setitimer(ITIMER_REAL, &every, NULL) == 0, "setitimer");
    while (ticks < 3 && now_ms() - t0 < 3000) pause();
    CHECK(ticks >= 3 && now_ms() - t0 >= 60, "SIGALRM again and again");
    CHECK(getitimer(ITIMER_REAL, &was) == 0 && was.it_interval.tv_usec == 20000, "getitimer reads the interval");
    memset(&every, 0, sizeof every);
    CHECK(setitimer(ITIMER_REAL, &every, &was) == 0 && was.it_interval.tv_usec == 20000, "the timer is stopped");
    // One already on its way may still land.
    nap_ms(30);
    int had = ticks;
    nap_ms(80);
    CHECK(ticks == had && getitimer(ITIMER_REAL, &was) == 0 && was.it_value.tv_sec == 0 && was.it_value.tv_usec == 0, "and stays so");
    signal(SIGALRM, SIG_DFL);

    // A thread in a join: the handler runs, the join goes on.
    install(SIGUSR1, record, 0);
    pthread_t th;
    seen_count = 0;
    t0 = now_ms();
    CHECK(pthread_create(&th, NULL, nap_then_exit, NULL) == 0, "a thread to join");
    p = signal_me_later(SIGUSR1, 50, -1);
    CHECK(pthread_join(th, NULL) == 0 && seen_count == 1 && now_ms() - t0 >= 150, "pthread_join outlasts a handler");
    child_status(p);

    // A write nobody can read: SIGPIPE, or EPIPE when that is ignored.
    p = fork();
    if (p == 0) {
        int q[2];
        if (pipe(q) != 0) _exit(1);
        close(q[0]);
        if (write(q[1], "x", 1) == -1) _exit(2);
        _exit(3);
    }
    st = child_status(p);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGPIPE, "a write to a pipe with no reader is SIGPIPE");
    signal(SIGPIPE, SIG_IGN);
    int q[2];
    CHECK(pipe(q) == 0 && close(q[0]) == 0, "a pipe with no reader");
    errno = 0;
    CHECK(write(q[1], "x", 1) == -1 && errno == EPIPE, "ignored, the write fails with EPIPE");
    close(q[1]);
    signal(SIGPIPE, SIG_DFL);
    close(fds[0]);
    close(fds[1]);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pid_t me = getpid();
    sigset_t set, old, pend;
    struct sigaction sa, was;

    // A handler, by raise and by kill, and what it is told.
    install(SIGUSR1, record, 0);
    CHECK(raise(SIGUSR1) == 0 && seen_count == 1 && seen_sig == SIGUSR1, "raise runs the handler before it returns");
    CHECK(seen_code == SI_TKILL && seen_pid == me, "raise's signal is a tkill from the process itself");
    CHECK(kill(me, SIGUSR1) == 0 && seen_count == 2 && seen_code == SI_USER && seen_pid == me, "kill of itself, SI_USER");
    signal(SIGUSR2, plain);
    CHECK(raise(SIGUSR2) == 0 && plain_count == SIGUSR2, "a handler without SA_SIGINFO gets the number");

    // The calls say no to what makes no sense.
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = plain;
    errno = 0;
    CHECK(sigaction(SIGKILL, &sa, NULL) == -1 && errno == EINVAL, "SIGKILL takes no handler");
    errno = 0;
    CHECK(sigaction(SIGSTOP, &sa, NULL) == -1 && errno == EINVAL, "nor SIGSTOP");
    CHECK(sigaction(SIGKILL, NULL, &was) == 0 && was.sa_handler == SIG_DFL, "its disposition can be read");
    CHECK(sigaction(SIGRTMAX, NULL, &was) == 0 && was.sa_handler == SIG_DFL, "the last real-time signal is there");
    errno = 0;
    CHECK(syscall(SYS_rt_sigaction, 65, NULL, &was, 8) == -1 && errno == EINVAL, "signal 65 is not");
    CHECK(sigaction(SIGUSR1, NULL, &was) == 0 && was.sa_sigaction == record && (was.sa_flags & SA_SIGINFO), "sigaction reads back what was set");

    // Blocked: pending until unblocked.
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    CHECK(sigprocmask(SIG_BLOCK, &set, &old) == 0 && !sigismember(&old, SIGUSR1), "block SIGUSR1");
    CHECK(raise(SIGUSR1) == 0 && seen_count == 2, "a blocked signal waits");
    CHECK(sigpending(&pend) == 0 && sigismember(&pend, SIGUSR1) && !sigismember(&pend, SIGUSR2), "and shows as pending");
    CHECK(sigprocmask(SIG_UNBLOCK, &set, NULL) == 0 && seen_count == 3, "unblocking delivers it");
    CHECK(sigpending(&pend) == 0 && !sigismember(&pend, SIGUSR1), "and it is pending no more");
    errno = 0;
    CHECK(sigprocmask(77, &set, NULL) == -1 && errno == EINVAL, "an unknown how is EINVAL");
    sigfillset(&set);
    CHECK(sigprocmask(SIG_BLOCK, &set, &old) == 0 && sigprocmask(SIG_SETMASK, &old, &set) == 0, "block everything and back");
    CHECK(!sigismember(&set, SIGKILL) && !sigismember(&set, SIGSTOP) && sigismember(&set, SIGTERM), "SIGKILL and SIGSTOP stay unblocked");

    // In a handler its signal is blocked, with sa_mask's; after it, neither.
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = look_at_mask;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGUSR2);
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0 && raise(SIGUSR1) == 0, "a handler that looks at the mask");
    CHECK(in_handler_self == 1 && in_handler_other == 1, "its signal and sa_mask are blocked while it runs");
    CHECK(!blocked_now(SIGUSR1) && !blocked_now(SIGUSR2), "and not after");

    // Handlers nest.
    install(SIGUSR1, outer, 0);
    install(SIGUSR2, inner, 0);
    CHECK(raise(SIGUSR1) == 0 && order_n == 3 && order[0] == 1 && order[1] == 2 && order[2] == 3, "a handler interrupted by another");

    // SA_NODEFER lets a handler interrupt itself; without it the second waits.
    install(SIGUSR1, reenter, SA_NODEFER);
    CHECK(raise(SIGUSR1) == 0 && reentered == 2, "SA_NODEFER: the handler runs inside itself");
    reentered = 0;
    install(SIGUSR1, reenter, 0);
    CHECK(raise(SIGUSR1) == 0 && reentered == 2, "without it, again once the first is done");

    // SA_RESETHAND: one shot.
    install(SIGUSR1, record, SA_RESETHAND);
    seen_count = 0;
    CHECK(raise(SIGUSR1) == 0 && seen_count == 1, "a one-shot handler runs");
    CHECK(sigaction(SIGUSR1, NULL, &was) == 0 && was.sa_handler == SIG_DFL, "and is gone");

    // Ignored: nothing happens, and setting it drops what was pending.
    signal(SIGUSR1, SIG_IGN);
    CHECK(raise(SIGUSR1) == 0 && kill(me, SIGUSR1) == 0, "an ignored signal does nothing");
    install(SIGUSR1, record, 0);
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    raise(SIGUSR1);
    CHECK(sigpending(&pend) == 0 && sigismember(&pend, SIGUSR1), "pending again");
    signal(SIGUSR1, SIG_IGN);
    CHECK(sigpending(&pend) == 0 && !sigismember(&pend, SIGUSR1), "ignoring it drops the pending one");
    install(SIGUSR1, record, 0);
    seen_count = 0;
    CHECK(sigprocmask(SIG_UNBLOCK, &set, NULL) == 0 && seen_count == 0, "so unblocking delivers nothing");

    // A signal with no handler ends the process, and the parent reads which.
    pid_t p = fork();
    if (p == 0) {
        raise(SIGTERM);
        _exit(1);
    }
    int st = child_status(p);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM, "SIGTERM with no handler ends the process");
    p = fork();
    if (p == 0) {
        signal(SIGUSR1, SIG_DFL);
        sigset_t all;
        sigfillset(&all);
        sigprocmask(SIG_BLOCK, &all, NULL);
        kill(getpid(), SIGUSR1);
        sigprocmask(SIG_UNBLOCK, &all, NULL);
        _exit(1);
    }
    st = child_status(p);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGUSR1, "a blocked one ends it when unblocked");

    // From another process: the handler runs in a child asleep in nanosleep,
    // and in one spinning in user code, where only an interrupt gets in.
    install(SIGUSR1, record, 0);
    p = fork();
    if (p == 0) {
        seen_count = 0;
        if (!flag_set(&seen_count, 3000)) _exit(1);
        _exit(seen_code == SI_USER && seen_pid == getppid() ? 0 : 2);
    }
    nap_ms(20);
    CHECK(kill(p, SIGUSR1) == 0, "kill a child that has a handler");
    st = child_status(p);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "its handler ran and saw the sender");

    install(SIGUSR2, end_spin, 0);
    p = fork();
    if (p == 0) _exit(spin_keeping_registers());
    nap_ms(30);
    CHECK(kill(p, SIGUSR2) == 0, "kill a child that spins");
    long long t0 = now_ms();
    st = child_status(p);
    CHECK(WIFEXITED(st) && now_ms() - t0 < 2000, "the handler cut into the loop");
    CHECK(WEXITSTATUS(st) == 0, "and the loop's registers and FP state came back");

    // The same in this process, the signal coming from a child.
    spin_done = 0;
    p = fork();
    if (p == 0) {
        nap_ms(30);
        kill(getppid(), SIGUSR2);
        _exit(0);
    }
    CHECK(spin_keeping_registers() == 0, "a handler in the middle of a loop here");
    child_status(p);

    // A sleep cut short by a handler.
    install(SIGUSR1, record, 0);
    seen_count = 0;
    p = fork();
    if (p == 0) {
        nap_ms(50);
        kill(getppid(), SIGUSR1);
        _exit(0);
    }
    struct timespec want = {3, 0}, left = {0, 0};
    t0 = now_ms();
    errno = 0;
    int r = nanosleep(&want, &left);
    CHECK(r == -1 && errno == EINTR && seen_count == 1, "nanosleep is cut short with EINTR");
    CHECK(now_ms() - t0 < 2000 && left.tv_sec >= 1, "early, with the time left");
    child_status(p);

    // The alternate stack.
    stack_t ss = {.ss_sp = alt_stack, .ss_size = sizeof alt_stack, .ss_flags = 0}, oss;
    CHECK(sigaltstack(&ss, &oss) == 0 && (oss.ss_flags & SS_DISABLE), "sigaltstack, none before");
    install(SIGUSR1, where_am_i, SA_ONSTACK);
    CHECK(raise(SIGUSR1) == 0 && on_alt == 1 && alt_flag_in == SS_ONSTACK, "an SA_ONSTACK handler runs on it");
    CHECK(sigaltstack(NULL, &oss) == 0 && oss.ss_sp == (void *)alt_stack && oss.ss_flags == 0, "and the process is off it after");
    install(SIGUSR1, where_am_i, 0);
    CHECK(raise(SIGUSR1) == 0 && on_alt == 0, "a handler without the flag stays on the stack");
    ss.ss_flags = SS_DISABLE;
    CHECK(sigaltstack(&ss, NULL) == 0 && sigaltstack(NULL, &oss) == 0 && (oss.ss_flags & SS_DISABLE), "sigaltstack off");

    // Faults: caught with the address, and not caught.
    char *page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED, "a page nothing may touch");
    install(SIGSEGV, fault_caught, 0);
    seen_count = 0;
    if (sigsetjmp(fault_env, 1) == 0) {
        *(volatile char *)(page + 100) = 1;
        CHECK(0, "the write should have faulted");
    }
    CHECK(seen_count == 1 && seen_sig == SIGSEGV && seen_addr == (void *)(page + 100), "SIGSEGV's handler gets the address");
    CHECK(seen_code == SEGV_ACCERR || seen_code == SEGV_MAPERR, "and a SEGV code");
    CHECK(!blocked_now(SIGSEGV), "siglongjmp out of it puts the mask back");
    if (sigsetjmp(fault_env, 1) == 0) {
        *(volatile char *)(page + 200) = 1;
        CHECK(0, "the second write should have faulted");
    }
    CHECK(seen_count == 2 && seen_addr == (void *)(page + 200), "a second fault is caught too");
    signal(SIGSEGV, SIG_DFL);
    munmap(page, 4096);

    p = fork();
    if (p == 0) {
        *(volatile int *)8 = 1;
        _exit(0);
    }
    st = child_status(p);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV, "a fault nothing catches ends the process by SIGSEGV");
    p = fork();
    if (p == 0) {
        __asm__ volatile("ud2");
        _exit(0);
    }
    st = child_status(p);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGILL, "an undefined instruction by SIGILL");
    p = fork();
    if (p == 0) {
        // The instruction itself: the compiler's own check would trap first.
        __asm__ volatile("xor %%edx, %%edx\n"
                         "mov $100, %%eax\n"
                         "xor %%ecx, %%ecx\n"
                         "idiv %%ecx\n"
                         :
                         :
                         : "rax", "rcx", "rdx", "cc");
        _exit(0);
    }
    st = child_status(p);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGFPE, "a division by zero by SIGFPE");
    p = fork();
    if (p == 0) {
        // Blocked or ignored, a fault's signal still ends the process.
        signal(SIGSEGV, SIG_IGN);
        *(volatile int *)8 = 1;
        _exit(0);
    }
    st = child_status(p);
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV, "ignoring SIGSEGV doesn't survive a fault");

    // SIGCHLD says which child and how it ended.
    install(SIGCHLD, record, 0);
    seen_count = 0;
    p = fork();
    if (p == 0) _exit(3);
    CHECK(flag_set(&seen_count, 3000) && seen_sig == SIGCHLD, "SIGCHLD when a child ends");
    CHECK(seen_pid == p && seen_code == CLD_EXITED && seen_status == 3, "with its pid and exit code");
    CHECK(waitpid(p, &st, 0) == p && WEXITSTATUS(st) == 3, "the child is still to be reaped");
    seen_count = 0;
    p = fork();
    if (p == 0) {
        for (;;) nap_ms(100);
    }
    CHECK(kill(p, SIGKILL) == 0 && flag_set(&seen_count, 3000), "SIGCHLD for a killed child");
    CHECK(seen_pid == p && seen_code == CLD_KILLED && seen_status == SIGKILL, "with the signal that ended it");
    CHECK(waitpid(p, &st, 0) == p && WTERMSIG(st) == SIGKILL, "reaped");
    signal(SIGCHLD, SIG_DFL);

    // Threads: a process's signal goes to a thread that doesn't block it, a
    // thread's own only to it.
    install(SIGUSR1, record, 0);
    install(SIGUSR2, record, 0);
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set, NULL);
    pthread_t th;
    CHECK(pthread_create(&th, NULL, open_thread, NULL) == 0 && flag_set(&thread_tid, 3000), "a thread that blocks nothing");
    seen_count = 0;
    CHECK(kill(me, SIGUSR1) == 0 && flag_set(&seen_count, 3000), "a signal for the process, blocked by this thread");
    CHECK(seen_tid == thread_tid && seen_sig == SIGUSR1, "runs in the other one");
    seen_count = 0;
    CHECK(pthread_kill(th, SIGUSR2) == 0 && flag_set(&seen_count, 3000) && seen_tid == thread_tid, "pthread_kill reaches that thread");
    seen_count = 0;
    CHECK(pthread_kill(pthread_self(), SIGUSR2) == 0, "pthread_kill of this one");
    nap_ms(20);
    CHECK(seen_count == 0 && sigpending(&pend) == 0 && sigismember(&pend, SIGUSR2), "stays its own: pending while it blocks it");
    CHECK(sigprocmask(SIG_UNBLOCK, &set, NULL) == 0 && seen_count == 1 && seen_tid == me, "and runs here when unblocked");
    thread_stop = 1;
    CHECK(pthread_join(th, NULL) == 0, "the thread ends");

    // What fork keeps: the mask and the handlers — not a pending signal.
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set, NULL);
    raise(SIGUSR2);
    p = fork();
    if (p == 0) {
        struct sigaction got;
        if (!blocked_now(SIGUSR2)) _exit(1);
        if (sigaction(SIGUSR1, NULL, &got) != 0 || got.sa_sigaction != record) _exit(2);
        if (sigpending(&pend) != 0 || sigismember(&pend, SIGUSR2)) _exit(3);
        _exit(0);
    }
    st = child_status(p);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "fork keeps the mask and the handlers, not what was pending");
    sigprocmask(SIG_UNBLOCK, &set, NULL);

    check_waits_cut_short();
    check_ymm();

    printf("lt_signal: all %d checks passed\n", check_no);
    return 0;
}
