// lt_thread — Linux threads through musl's pthreads: clone, futex (wait,
// wake, timeouts), the clear-tid word pthread_join waits on, TLS per thread,
// one fd table for every thread, detached threads, thread churn, 90 threads
// alive at once (pids past 64), and exit_group taking down threads that
// sleep, spin or nanosleep. Exit 0 = every check passed, else the number of
// the first failed check.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int check_no;

#define CHECK(cond, what)                                                        \
    do {                                                                         \
        check_no++;                                                              \
        if (!(cond)) {                                                           \
            printf("lt_thread: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                      \
        }                                                                        \
    } while (0)

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_WAIT_BITSET 9
#define FUTEX_PRIVATE_FLAG 128
#define FUTEX_BITSET_MATCH_ANY 0xffffffff

static long gettid_raw(void) { return syscall(SYS_gettid); }

static long futex(atomic_int *word, int op, int val, const struct timespec *ts, int val3) {
    return syscall(SYS_futex, word, op, val, ts, NULL, val3);
}

static long long ns_between(const struct timespec *a, const struct timespec *b) {
    return (b->tv_sec - a->tv_sec) * 1000000000LL + (b->tv_nsec - a->tv_nsec);
}

static struct timespec after_ms(clockid_t clock, long ms) {
    struct timespec t;
    clock_gettime(clock, &t);
    t.tv_nsec += ms * 1000000L;
    t.tv_sec += t.tv_nsec / 1000000000L;
    t.tv_nsec %= 1000000000L;
    return t;
}

static void nap_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

// --- Counter under a mutex, TLS, tids ---------------------------------------

#define NTHREADS 4
#define ROUNDS 20000

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t all_up;
static long counter;
static __thread int my_index = -1;

struct worker {
    int index;
    long tid;
    pid_t pid;
    int tls_ok;
};

static void *count_worker(void *arg) {
    struct worker *w = arg;
    my_index = w->index;
    w->tid = gettid_raw();
    w->pid = getpid();
    // Every worker is alive past here, so the tids recorded are distinct.
    pthread_barrier_wait(&all_up);
    for (int i = 0; i < ROUNDS; i++) {
        pthread_mutex_lock(&mu);
        counter++;
        pthread_mutex_unlock(&mu);
        if (i % 1000 == 0) sched_yield();
    }
    w->tls_ok = my_index == w->index;
    return (void *)(long)(w->index + 100);
}

static void check_workers(void) {
    pid_t pid = getpid();
    CHECK(gettid_raw() == pid, "the main thread's tid is the pid");
    CHECK(pthread_barrier_init(&all_up, NULL, NTHREADS) == 0, "pthread_barrier_init");
    pthread_t th[NTHREADS];
    struct worker ws[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        ws[i] = (struct worker){.index = i};
        CHECK(pthread_create(&th[i], NULL, count_worker, &ws[i]) == 0, "pthread_create");
    }
    for (int i = 0; i < NTHREADS; i++) {
        void *ret = NULL;
        CHECK(pthread_join(th[i], &ret) == 0, "pthread_join");
        CHECK(ret == (void *)(long)(i + 100), "pthread_join returns the thread's result");
    }
    CHECK(counter == (long)NTHREADS * ROUNDS, "a mutex-protected counter adds up");
    for (int i = 0; i < NTHREADS; i++) {
        CHECK(ws[i].pid == pid, "getpid in a thread is the process id");
        CHECK(ws[i].tid > 0 && ws[i].tid != pid, "a thread has its own tid");
        CHECK(ws[i].tls_ok, "thread-local storage is per thread");
        for (int j = 0; j < i; j++) CHECK(ws[i].tid != ws[j].tid, "live threads' tids differ");
    }
    CHECK(my_index == -1, "the main thread's TLS is its own");
    pthread_barrier_destroy(&all_up);
}

// --- Condition variables ----------------------------------------------------

#define PINGS 2000

static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int turn;

static void *pong(void *arg) {
    (void)arg;
    for (int i = 0; i < PINGS; i++) {
        pthread_mutex_lock(&mu);
        while (turn != 1) pthread_cond_wait(&cv, &mu);
        turn = 0;
        pthread_cond_signal(&cv);
        pthread_mutex_unlock(&mu);
    }
    return NULL;
}

static void check_condvars(void) {
    pthread_t t;
    CHECK(pthread_create(&t, NULL, pong, NULL) == 0, "pthread_create pong");
    for (int i = 0; i < PINGS; i++) {
        pthread_mutex_lock(&mu);
        turn = 1;
        pthread_cond_signal(&cv);
        while (turn != 0) pthread_cond_wait(&cv, &mu);
        pthread_mutex_unlock(&mu);
    }
    CHECK(pthread_join(t, NULL) == 0, "condition variable ping-pong");

    struct timespec t0, t1;
    struct timespec until = after_ms(CLOCK_REALTIME, 50);
    pthread_mutex_lock(&mu);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int r = pthread_cond_timedwait(&cv, &mu, &until);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    pthread_mutex_unlock(&mu);
    CHECK(r == ETIMEDOUT, "pthread_cond_timedwait with no signal times out");
    long long waited = ns_between(&t0, &t1);
    if (waited < 45000000LL || waited >= 2000000000LL) printf("lt_thread: timed wait took %lld ns\n", waited);
    CHECK(waited >= 45000000LL && waited < 2000000000LL, "... after about its 50 ms");
}

// --- Raw futex --------------------------------------------------------------

static atomic_int word;
static atomic_int waiter_up;

static void *futex_waiter(void *arg) {
    (void)arg;
    atomic_store(&waiter_up, 1);
    while (atomic_load(&word) == 0) futex(&word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, NULL, 0);
    return NULL;
}

static void check_futex(void) {
    atomic_int w = 7;
    errno = 0;
    CHECK(futex(&w, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 8, NULL, 0) == -1 && errno == EAGAIN, "FUTEX_WAIT on a changed word is EAGAIN");
    CHECK(futex(&w, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, 0) == 0, "FUTEX_WAKE with no waiter wakes none");

    struct timespec t0, t1, ts = {0, 20000000};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    errno = 0;
    CHECK(futex(&w, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 7, &ts, 0) == -1 && errno == ETIMEDOUT, "FUTEX_WAIT times out");
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK(ns_between(&t0, &t1) >= 20000000LL, "... after at least its timeout");

    struct timespec zero = {0, 0};
    errno = 0;
    CHECK(futex(&w, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 7, &zero, 0) == -1 && errno == ETIMEDOUT, "a zero timeout expires at once");
    struct timespec bad = {0, 1000000000};
    errno = 0;
    CHECK(futex(&w, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 7, &bad, 0) == -1 && errno == EINVAL, "a denormal timeout is EINVAL");

    struct timespec until = after_ms(CLOCK_MONOTONIC, 20);
    errno = 0;
    CHECK(futex(&w, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 7, &until, FUTEX_BITSET_MATCH_ANY) == -1 && errno == ETIMEDOUT,
          "FUTEX_WAIT_BITSET times out at its absolute time");
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK(ns_between(&until, &t1) >= 0, "... not before it");

    pthread_t t;
    CHECK(pthread_create(&t, NULL, futex_waiter, NULL) == 0, "pthread_create futex waiter");
    while (!atomic_load(&waiter_up)) sched_yield();
    nap_ms(30);
    atomic_store(&word, 1);
    CHECK(futex(&word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, NULL, 0) == 1, "FUTEX_WAKE wakes the parked waiter");
    CHECK(pthread_join(t, NULL) == 0, "the woken waiter exits");
}

// --- One fd table -----------------------------------------------------------

static void *opener(void *arg) {
    (void)arg;
    return (void *)(long)open("/etc/motd", O_RDONLY);
}

static atomic_int open_failures;

static void open_failed(const char *step, long got) {
    if (atomic_fetch_add(&open_failures, 1) == 0)
        printf("lt_thread: open churn: %s failed (%ld, errno %d)\n", step, got, errno);
}

static void *open_churn(void *arg) {
    (void)arg;
    for (int i = 0; i < 50; i++) {
        int fd = open("/etc/motd", O_RDONLY);
        if (fd < 0) {
            open_failed("open", fd);
            continue;
        }
        char buf[32];
        long n = read(fd, buf, 4);
        if (n != 4)
            open_failed("read", n);
        else if (memcmp(buf, "ext2", 4) != 0) // the file opens "ext2 read test, hello from /etc/motd"
            open_failed("read data", buf[0]);
        if (close(fd) != 0) open_failed("close", fd);
    }
    return NULL;
}

static void check_shared_fds(void) {
    pthread_t t;
    void *ret;
    CHECK(pthread_create(&t, NULL, opener, NULL) == 0 && pthread_join(t, &ret) == 0, "a thread opens a file");
    int fd = (int)(long)ret;
    CHECK(fd >= 3, "... and gets an fd");
    char buf[64] = {0};
    CHECK(read(fd, buf, sizeof buf - 1) > 0 && strstr(buf, "hello from /etc/motd") != NULL, "the fd reads in another thread");
    CHECK(close(fd) == 0, "... and closes there");
    errno = 0;
    CHECK(close(fd) == -1 && errno == EBADF, "closed for every thread");

    pthread_t th[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) CHECK(pthread_create(&th[i], NULL, open_churn, NULL) == 0, "pthread_create open churn");
    for (int i = 0; i < NTHREADS; i++) CHECK(pthread_join(th[i], NULL) == 0, "pthread_join open churn");
    CHECK(atomic_load(&open_failures) == 0, "threads open, read and close files at once");
}

// --- Detached threads, churn ------------------------------------------------

static atomic_int detached_done;

static void *detached(void *arg) {
    (void)arg;
    atomic_fetch_add(&detached_done, 1);
    return NULL;
}

static void *nop(void *arg) { return arg; }

static void check_lifetimes(void) {
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    for (int i = 0; i < 8; i++) {
        pthread_t t;
        CHECK(pthread_create(&t, &a, detached, NULL) == 0, "pthread_create detached");
    }
    pthread_attr_destroy(&a);
    for (int i = 0; i < 5000 && atomic_load(&detached_done) < 8; i++) nap_ms(1);
    CHECK(atomic_load(&detached_done) == 8, "detached threads run and exit");

    int ok = 1;
    for (int i = 0; i < 200 && ok; i++) {
        pthread_t t;
        void *ret = NULL;
        ok = pthread_create(&t, NULL, nop, (void *)(long)i) == 0 && pthread_join(t, &ret) == 0 && ret == (void *)(long)i;
    }
    CHECK(ok, "200 threads created and joined in turn");
}

// --- More live threads than one 64-bit set of pids holds ----------------------

#define CROWD 90

static atomic_int crowd_ready;
static atomic_int crowd_bad;
static int crowd_pipe[2];

static void *crowd_worker(void *arg) {
    long idx = (long)arg;
    // The address-space lock, both sides: mmap edits the map, the touch
    // faults on it.
    unsigned char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        atomic_fetch_add(&crowd_bad, 1);
    } else {
        p[idx] = (unsigned char)idx;
    }
    atomic_fetch_add(&crowd_ready, 1);
    // Every poller is woken by pid when main writes.
    struct pollfd pf = {crowd_pipe[0], POLLIN, 0};
    if (poll(&pf, 1, 20000) != 1) atomic_fetch_add(&crowd_bad, 1);
    // A few of them wait for a child of their own.
    if (idx % 30 == 0) {
        int st = 0;
        pid_t c = fork();
        if (c == 0) _exit(9);
        if (c < 0 || waitpid(c, &st, 0) != c || !WIFEXITED(st) || WEXITSTATUS(st) != 9) atomic_fetch_add(&crowd_bad, 1);
    }
    if (p != MAP_FAILED) {
        if (p[idx] != (unsigned char)idx) atomic_fetch_add(&crowd_bad, 1);
        munmap(p, 4096);
    }
    return NULL;
}

static void check_crowd(void) {
    static pthread_t th[CROWD];
    CHECK(pipe(crowd_pipe) == 0, "pipe for the crowd");
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setstacksize(&a, 64 * 1024);
    int made = 0;
    while (made < CROWD && pthread_create(&th[made], &a, crowd_worker, (void *)(long)made) == 0) made++;
    pthread_attr_destroy(&a);
    CHECK(made == CROWD, "90 threads alive at once");
    for (int i = 0; i < 10000 && atomic_load(&crowd_ready) < CROWD; i++) nap_ms(1);
    nap_ms(20);
    CHECK(write(crowd_pipe[1], "x", 1) == 1, "one write for every poller");
    int joined = 0;
    while (joined < CROWD && pthread_join(th[joined], NULL) == 0) joined++;
    CHECK(joined == CROWD, "the crowd joins");
    CHECK(atomic_load(&crowd_bad) == 0, "they map, fault, poll and wait for children");
    close(crowd_pipe[0]);
    close(crowd_pipe[1]);
}

// --- A fork beside threads the kernel is writing to ---------------------------

#define WRITERS 3
#define FORKS 200

static atomic_int forking_done;
static atomic_int writer_bad;

static void *kernel_written(void *arg) {
    (void)arg;
    // Only the kernel writes these pages, so after each fork its write is
    // the one that meets them copy-on-write.
    char *buf = calloc(1, 8192);
    int fd = open("/etc/motd", O_RDONLY);
    if (buf == NULL || fd < 0) {
        atomic_fetch_add(&writer_bad, 1);
        return NULL;
    }
    while (!atomic_load(&forking_done)) {
        struct timespec *ts = (struct timespec *)(buf + 6144);
        if (clock_gettime(CLOCK_MONOTONIC, ts) != 0) atomic_fetch_add(&writer_bad, 1);
        if (pread(fd, buf, 4000, 0) <= 0 || strstr(buf, "hello from /etc/motd") == NULL) atomic_fetch_add(&writer_bad, 1);
        if (getcwd(buf + 4096, 2048) == NULL || buf[4096] != '/') atomic_fetch_add(&writer_bad, 1);
    }
    close(fd);
    free(buf);
    return NULL;
}

static void check_fork_beside_writers(void) {
    pthread_t th[WRITERS];
    for (int i = 0; i < WRITERS; i++) CHECK(pthread_create(&th[i], NULL, kernel_written, NULL) == 0, "pthread_create writer");
    int ok = 1;
    for (int i = 0; i < FORKS; i++) {
        int st = 0;
        pid_t c = fork();
        if (c == 0) _exit(3);
        if (c < 0 || waitpid(c, &st, 0) != c || !WIFEXITED(st) || WEXITSTATUS(st) != 3) ok = 0;
    }
    atomic_store(&forking_done, 1);
    for (int i = 0; i < WRITERS; i++) CHECK(pthread_join(th[i], NULL) == 0, "pthread_join writer");
    CHECK(ok, "200 forks beside threads in syscalls");
    CHECK(atomic_load(&writer_bad) == 0, "the kernel's writes to their memory all land");
}

// --- Pages that leave under a syscall -----------------------------------------

#define LEAVING_PAGES 4
#define LEAVING_LEN (LEAVING_PAGES * 4096)
#define DROPS 3000

static char *leaving;
static atomic_int dropping_done;
static atomic_int leaving_bad;

// Syscalls that write `buf` and read it, as the kernel does both directly.
static void use_buffer(char *buf, int motd, int scratch, int strict) {
    long r = clock_gettime(CLOCK_MONOTONIC, (struct timespec *)(buf + 4096 + 512));
    if (r != 0 && (strict || errno != EFAULT)) atomic_fetch_add(&leaving_bad, 1);
    r = pread(motd, buf, 4000, 0);
    if (r <= 0 && (strict || errno != EFAULT)) atomic_fetch_add(&leaving_bad, 1);
    // The raw call: libc's getcwd reads the buffer back itself.
    r = syscall(SYS_getcwd, buf + 2 * 4096, 2048);
    if (r <= 0 && (strict || errno != EFAULT)) atomic_fetch_add(&leaving_bad, 1);
    r = pwrite(scratch, buf, LEAVING_LEN, 0);
    if (r != LEAVING_LEN && (strict || errno != EFAULT)) atomic_fetch_add(&leaving_bad, 1);
}

static void *dropper(void *arg) {
    (void)arg;
    for (int i = 0; i < DROPS; i++) {
        if (madvise(leaving, LEAVING_LEN, MADV_DONTNEED) != 0) atomic_fetch_add(&leaving_bad, 1);
    }
    atomic_store(&dropping_done, 1);
    return NULL;
}

static void *unmapper(void *arg) {
    (void)arg;
    for (int i = 0; i < DROPS; i++) {
        munmap(leaving, LEAVING_LEN);
        if (mmap(leaving, LEAVING_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != leaving) _exit(4);
    }
    atomic_store(&dropping_done, 1);
    return NULL;
}

static void check_pages_leaving(void) {
    leaving = mmap(NULL, LEAVING_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int motd = open("/etc/motd", O_RDONLY);
    int scratch = open("/ltthread.leaving", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(leaving != MAP_FAILED && motd >= 0 && scratch >= 0, "a buffer and two files for the leaving pages");

    // Dropped pages come back as zero pages: every call still succeeds.
    pthread_t t;
    CHECK(pthread_create(&t, NULL, dropper, NULL) == 0, "pthread_create dropper");
    while (!atomic_load(&dropping_done)) use_buffer(leaving, motd, scratch, 1);
    CHECK(pthread_join(t, NULL) == 0, "pthread_join dropper");
    CHECK(atomic_load(&leaving_bad) == 0, "syscalls on a buffer whose pages are dropped under them");

    // A buffer unmapped under the call: EFAULT, or the process dies of it.
    // Nothing else may.
    pid_t c = fork();
    if (c == 0) {
        atomic_store(&dropping_done, 0);
        atomic_store(&leaving_bad, 0);
        if (pthread_create(&t, NULL, unmapper, NULL) != 0) _exit(5);
        while (!atomic_load(&dropping_done)) use_buffer(leaving, motd, scratch, 0);
        pthread_join(t, NULL);
        _exit(atomic_load(&leaving_bad) == 0 ? 0 : 6);
    }
    int st = 0;
    CHECK(c > 0 && waitpid(c, &st, 0) == c, "the unmapping child is reaped");
    CHECK((WIFEXITED(st) && WEXITSTATUS(st) == 0) || (WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV),
          "a buffer unmapped under a syscall costs at most its own process");
    close(motd);
    close(scratch);
    CHECK(unlink("/ltthread.leaving") == 0, "unlink the scratch file");
    munmap(leaving, LEAVING_LEN);
}

// --- exit_group with live peers ---------------------------------------------

static void *sleeper(void *arg) {
    (void)arg;
    atomic_int never = 0;
    for (;;) futex(&never, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, NULL, 0);
    return NULL;
}

static void *spinner(void *arg) {
    (void)arg;
    for (volatile unsigned long n = 0;; n++) {
    }
    return NULL;
}

static void *napper(void *arg) {
    (void)arg;
    for (;;) nap_ms(10000);
    return NULL;
}

int main(void) {
    check_workers();
    check_condvars();
    check_futex();
    check_shared_fds();
    check_lifetimes();
    check_crowd();
    check_fork_beside_writers();
    check_pages_leaving();

    // Returning from main is exit_group: these must go with the process.
    pthread_t t;
    CHECK(pthread_create(&t, NULL, sleeper, NULL) == 0, "pthread_create sleeper");
    CHECK(pthread_create(&t, NULL, spinner, NULL) == 0, "pthread_create spinner");
    CHECK(pthread_create(&t, NULL, napper, NULL) == 0, "pthread_create napper");
    nap_ms(20);
    printf("lt_thread: PASS (%d checks)\n", check_no);
    return 0;
}
