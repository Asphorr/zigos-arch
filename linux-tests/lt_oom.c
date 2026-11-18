// lt_oom — memory past the limit. A process that takes all there is is the
// one ended (SIGKILL); a bystander keeps forking, copying on write and
// mapping right through it; the memory is back afterwards. Then the same
// with two at once, one taking shared memory and one that forks; then
// beside a larger process that oom_score_adj keeps out of the choice.
// Run by boot mode 19 (src/test/linux_selftest.zig); exit 0 = every check
// passed, else the number of the first failed check.

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define PG 4096UL
#define MB (1UL << 20)

static int check_no;
static pid_t by; // the bystander, not left behind by a failed check

#define CHECK(cond, what)                                                     \
    do {                                                                      \
        check_no++;                                                           \
        if (!(cond)) {                                                        \
            printf("lt_oom: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            if (by > 0) kill(by, SIGKILL);                                    \
            exit(check_no);                                                   \
        }                                                                     \
    } while (0)

static long meminfo_kb(const char *field) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    char line[128];
    long kb = -1;
    size_t n = strlen(field);
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, field, n) == 0) {
            kb = atol(line + n);
            break;
        }
    }
    fclose(f);
    return kb;
}

// What the bystander reports, in a page it shares with the test.
struct report {
    volatile unsigned long rounds; // children that wrote their pages and left
    volatile unsigned long bad;    // children that ended any other way
    volatile int bad_status;
    volatile unsigned long refused; // fork or mmap answered "no memory"
    volatile int stop;
    volatile int guard_ready, guard_stop; // the process kept out of the choice
};

// Holds `mb` of memory with oom_score_adj at -1000 until told to leave.
static void guard(struct report *r, unsigned long mb, pid_t test) {
    FILE *f = fopen("/proc/self/oom_score_adj", "w");
    if (!f || fputs("-1000\n", f) < 0 || fclose(f) != 0) _exit(7);
    char *p = mmap(NULL, mb * MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) _exit(8);
    for (unsigned long o = 0; o < mb * MB; o += PG) p[o] = 1;
    r->guard_ready = 1;
    while (!r->guard_stop && getppid() == test) usleep(20000);
    _exit(0);
}

// Round after round: a child that writes 64 inherited pages (a copy each)
// and 64 new ones, as a shell's child does before its exec. Ends when told,
// or when the test is gone.
static void bystander(struct report *r, char *cow, size_t cow_len, pid_t test) {
    size_t at = 0;
    while (!r->stop && getppid() == test) {
        pid_t c = fork();
        if (c < 0) {
            r->refused++;
            usleep(2000);
            continue;
        }
        if (c == 0) {
            for (size_t i = 0; i < 64; i++) cow[(at + i * PG) % cow_len] ^= 1;
            char *m = mmap(NULL, 64 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (m == MAP_FAILED) _exit(errno == ENOMEM ? 2 : 3);
            for (size_t i = 0; i < 64; i++) m[i * PG] = 1;
            _exit(0);
        }
        int st = 0;
        if (waitpid(c, &st, 0) != c) {
            r->bad++;
            r->bad_status = -errno;
        } else if (WIFEXITED(st) && WEXITSTATUS(st) == 0) {
            r->rounds++;
        } else if (WIFEXITED(st) && WEXITSTATUS(st) == 2) {
            r->refused++;
        } else {
            r->bad++;
            r->bad_status = st;
        }
        at += 64 * PG;
        cow[at % cow_len] ^= 1;
        usleep(1000);
    }
    _exit(0);
}

static int wait_rounds(struct report *r, unsigned long target, int ms) {
    for (int waited = 0; r->rounds < target; waited += 10) {
        int st = 0;
        if (waited >= ms || waitpid(by, &st, WNOHANG) == by) {
            printf("lt_oom: the bystander is at round %lu of %lu, %lu refused, %lu bad (0x%x); its status 0x%x\n",
                   r->rounds, target, r->refused, r->bad, r->bad_status, st);
            return 0;
        }
        usleep(10000);
    }
    return 1;
}

// Takes memory until something stops it: 16 MB at a time, private or
// shared, every page written. `fork_at_mb`: from there on a child of it
// does the same.
static void hog(unsigned long cap_mb, unsigned long fork_at_mb, int shared) {
    int flags = MAP_ANONYMOUS | (shared ? MAP_SHARED : MAP_PRIVATE);
    for (unsigned long got = 0; got < cap_mb; got += 16) {
        if (fork_at_mb != 0 && got >= fork_at_mb) {
            fork_at_mb = 0;
            if (fork() < 0) _exit(6);
        }
        char *p = mmap(NULL, 16 * MB, PROT_READ | PROT_WRITE, flags, -1, 0);
        if (p == MAP_FAILED) _exit(4);
        for (unsigned long o = 0; o < 16 * MB; o += PG) p[o] = 1;
    }
    _exit(5);
}

static int killed(int st) { return WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL; }

static int memory_back(long want_kb, int ms) {
    for (int waited = 0; meminfo_kb("MemFree:") < want_kb; waited += 100) {
        if (waited >= ms) return 0;
        usleep(100000);
    }
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    long total_kb = meminfo_kb("MemTotal:"), free0_kb = meminfo_kb("MemFree:");
    CHECK(total_kb > 0 && free0_kb > 0, "/proc/meminfo names the memory");
    // More than there is, swap included: a hog that gets there was not stopped.
    unsigned long cap_mb = (unsigned long)total_kb / 1024 + 1024;
    long back_kb = free0_kb - 48 * 1024;

    struct report *r = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(r != MAP_FAILED, "a page shared with the bystander");
    size_t cow_len = 32 * MB;
    char *cow = mmap(NULL, cow_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(cow != MAP_FAILED, "32 MB to inherit");
    memset(cow, 0x5A, cow_len);

    pid_t test = getpid();
    by = fork();
    CHECK(by >= 0, "fork the bystander");
    if (by == 0) bystander(r, cow, cow_len, test);
    CHECK(wait_rounds(r, 5, 10000), "the bystander is at work");

    // One process takes everything.
    pid_t h = fork();
    CHECK(h >= 0, "fork the hog");
    if (h == 0) hog(cap_mb, 0, 0);
    int st = 0;
    CHECK(waitpid(h, &st, 0) == h, "wait for the hog");
    if (!killed(st)) printf("lt_oom: the hog's status is 0x%x\n", st);
    CHECK(killed(st), "the process that took all memory is the one killed");
    unsigned long seen = r->rounds;
    CHECK(wait_rounds(r, seen + 5, 20000), "the bystander goes on");
    // More than Linux promises inside a memory cgroup, where a second
    // process may be ended before the first one's memory is back.
    if (r->bad != 0) printf("lt_oom: %lu of the bystander's children failed, the last with status 0x%x\n", r->bad, r->bad_status);
    CHECK(r->bad == 0, "none of the bystander's children was hurt");
    CHECK(memory_back(back_kb, 30000), "the memory is back");
    unsigned long one_rounds = r->rounds, one_refused = r->refused;

    // Two at once: one takes shared memory, the other forks on the way.
    pid_t a = fork();
    CHECK(a >= 0, "fork the first of two");
    if (a == 0) hog(cap_mb, 0, 1);
    pid_t b = fork();
    CHECK(b >= 0, "fork the second of two");
    if (b == 0) hog(cap_mb, 64, 0);
    int sa = 0, sb = 0;
    CHECK(waitpid(a, &sa, 0) == a && waitpid(b, &sb, 0) == b, "wait for both");
    if (!killed(sa) || !killed(sb)) printf("lt_oom: the two ended with 0x%x and 0x%x\n", sa, sb);
    CHECK(killed(sa), "the one with shared memory is killed");
    CHECK(killed(sb), "the one that forked is killed");
    // Its child is nobody's to wait for: the memory coming back is its end.
    CHECK(memory_back(back_kb, 60000), "the memory is back again");
    seen = r->rounds;
    CHECK(wait_rounds(r, seen + 5, 20000), "the bystander still goes on");
    if (r->bad != 0) printf("lt_oom: %lu of the bystander's children failed, the last with status 0x%x\n", r->bad, r->bad_status);
    CHECK(r->bad == 0, "none of its children was hurt this time either");

    // The largest process is kept out of the choice (oom_score_adj -1000):
    // the one that takes the rest is ended, smaller as it is.
    unsigned long guard_mb = (unsigned long)meminfo_kb("MemFree:") / 1024 * 6 / 10;
    pid_t g = fork();
    CHECK(g >= 0, "fork the guarded one");
    if (g == 0) guard(r, guard_mb, test);
    int gone = 0;
    for (int waited = 0; !r->guard_ready && waited < 60000 && !gone; waited += 10) {
        gone = waitpid(g, &st, WNOHANG) == g;
        usleep(10000);
    }
    if (gone) printf("lt_oom: the guarded one ended early, status 0x%x\n", st);
    CHECK(r->guard_ready && !gone, "it holds most of the memory");
    h = fork();
    CHECK(h >= 0, "fork the hog beside it");
    if (h == 0) hog(cap_mb, 0, 0);
    CHECK(waitpid(h, &st, 0) == h, "wait for that hog");
    if (!killed(st)) printf("lt_oom: the hog's status is 0x%x\n", st);
    CHECK(killed(st), "the hog is killed, not the larger guarded one");
    CHECK(waitpid(g, &st, WNOHANG) == 0, "which is still there");
    r->guard_stop = 1;
    CHECK(waitpid(g, &st, 0) == g && WIFEXITED(st) && WEXITSTATUS(st) == 0, "and leaves when told");
    CHECK(memory_back(back_kb, 30000), "the memory is back once more");
    if (r->bad != 0) printf("lt_oom: %lu of the bystander's children failed, the last with status 0x%x\n", r->bad, r->bad_status);
    CHECK(r->bad == 0, "the bystander's children came through that too");

    r->stop = 1;
    CHECK(waitpid(by, &st, 0) == by && WIFEXITED(st) && WEXITSTATUS(st) == 0, "the bystander ends when told");
    int same = 1;
    for (size_t o = 0; o < cow_len; o++) {
        if (cow[o] != 0x5A) {
            same = 0;
            break;
        }
    }
    CHECK(same, "the parent's pages kept their bytes");

    printf("lt_oom: PASS (%d checks); the bystander ran %lu rounds through one hog (%lu refused), %lu through all (%lu refused)\n",
           check_no, one_rounds, one_refused, r->rounds, r->refused);
    return 0;
}
