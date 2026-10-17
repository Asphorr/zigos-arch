// lt_basic — what every static musl program needs before main does any
// work: the SysV initial stack (argc/argv/envp/auxv), TLS, stdio through
// writev, the ext2 root through open/read/getdents64/stat, and the clocks.
// Boot mode 19 runs it as `lt_basic one two three`; exit 0 = every check
// passed, else the number of the first failed check.

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int check_no;

#define CHECK(cond, what)                                                       \
    do {                                                                        \
        check_no++;                                                             \
        if (!(cond)) {                                                          \
            printf("lt_basic: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                     \
        }                                                                       \
    } while (0)

static __thread int tls_counter = 41;

static long long ns_between(const struct timespec *a, const struct timespec *b) {
    return (b->tv_sec - a->tv_sec) * 1000000000LL + (b->tv_nsec - a->tv_nsec);
}

static void check_clocks(void) {
    struct timespec t0, t1, res;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &t0) == 0, "clock_gettime monotonic");
    struct timespec nap = {0, 20 * 1000 * 1000};
    CHECK(nanosleep(&nap, NULL) == 0, "nanosleep");
    CHECK(clock_gettime(CLOCK_MONOTONIC, &t1) == 0, "clock_gettime monotonic again");
    long long slept = ns_between(&t0, &t1);
    CHECK(slept >= 20000000LL && slept < 2000000000LL, "nanosleep 20 ms on the monotonic clock");

    struct timespec rt;
    CHECK(clock_gettime(CLOCK_REALTIME, &rt) == 0 && rt.tv_sec > 1600000000, "realtime clock past 2020");
    struct timeval tv;
    CHECK(gettimeofday(&tv, NULL) == 0 && tv.tv_sec >= rt.tv_sec && tv.tv_sec - rt.tv_sec < 5, "gettimeofday agrees");
    CHECK(time(NULL) >= rt.tv_sec, "time");
    CHECK(clock_getres(CLOCK_MONOTONIC, &res) == 0 && res.tv_sec == 0 && res.tv_nsec > 0, "clock_getres");
    errno = 0;
    CHECK(clock_gettime((clockid_t)12345, &t0) == -1 && errno == EINVAL, "unknown clock is EINVAL");

    struct timespec until;
    clock_gettime(CLOCK_MONOTONIC, &until);
    until.tv_nsec += 15 * 1000 * 1000;
    if (until.tv_nsec >= 1000000000) {
        until.tv_sec++;
        until.tv_nsec -= 1000000000;
    }
    CHECK(clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until, NULL) == 0, "clock_nanosleep absolute");
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK(ns_between(&until, &t1) >= 0, "absolute sleep reaches its deadline");

    cpu_set_t set;
    CHECK(sched_getaffinity(0, sizeof set, &set) == 0 && CPU_COUNT(&set) >= 1, "sched_getaffinity");
    CHECK(sched_yield() == 0, "sched_yield");
}

int main(int argc, char **argv) {
    CHECK(argc == 4, "argc");
    CHECK(strcmp(argv[1], "one") == 0 && strcmp(argv[2], "two") == 0 && strcmp(argv[3], "three") == 0, "argv");
    CHECK(argv[4] == NULL, "argv terminator");

    tls_counter++;
    CHECK(tls_counter == 42, "thread-local storage");

    char *heap = malloc(100000);
    CHECK(heap != NULL, "malloc");
    memset(heap, 0xAB, 100000);
    free(heap);

    int fd = open("/etc/motd", O_RDONLY);
    CHECK(fd >= 0, "open /etc/motd");
    char buf[128] = {0};
    ssize_t n = read(fd, buf, sizeof buf - 1);
    CHECK(n > 0 && strstr(buf, "hello from /etc/motd") != NULL, "read /etc/motd");
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == n, "fstat size");
    close(fd);

    CHECK(stat("/bin", &st) == 0 && S_ISDIR(st.st_mode), "stat /bin is a directory");

    DIR *d = opendir("/etc");
    CHECK(d != NULL, "opendir /etc");
    int saw_motd = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) saw_motd |= strcmp(e->d_name, "motd") == 0;
    closedir(d);
    CHECK(saw_motd, "readdir /etc lists motd");

    check_clocks();

    printf("lt_basic: PASS (%d checks)\n", check_no);
    return 0;
}
