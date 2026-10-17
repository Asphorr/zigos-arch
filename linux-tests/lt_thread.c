// lt_thread — Linux threads through musl's pthreads: clone, futex (wait,
// wake, timeouts), the clear-tid word pthread_join waits on, TLS per thread,
// one fd table for every thread, detached threads, thread churn, and
// exit_group taking down threads that sleep, spin or nanosleep. Exit 0 =
// every check passed, else the number of the first failed check.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
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

    // Returning from main is exit_group: these must go with the process.
    pthread_t t;
    CHECK(pthread_create(&t, NULL, sleeper, NULL) == 0, "pthread_create sleeper");
    CHECK(pthread_create(&t, NULL, spinner, NULL) == 0, "pthread_create spinner");
    CHECK(pthread_create(&t, NULL, napper, NULL) == 0, "pthread_create napper");
    nap_ms(20);
    printf("lt_thread: PASS (%d checks)\n", check_no);
    return 0;
}
