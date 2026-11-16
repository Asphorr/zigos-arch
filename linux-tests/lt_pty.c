// lt_pty — pseudo-terminals as a terminal program or ssh uses them: a pty
// from /dev/ptmx and its slave by name; the modes, raw input, the window
// size set at the master; a child in a session of its own whose terminal
// the slave becomes (/dev/tty too), a line it reads with the echo the
// master sees, output with "\r\n", Ctrl+C from the master ending it, and
// the master's EIO once no slave is left. Exit 0 = every check passed,
// else the number of the first failed check.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static int check_no;

#define CHECK(cond, what)                                                     \
    do {                                                                      \
        check_no++;                                                           \
        if (!(cond)) {                                                        \
            printf("lt_pty: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                   \
        }                                                                     \
    } while (0)

// What the master reads until `want` shows up in it or `ms` pass.
static char seen[1024];
static size_t seen_len;
static int master_shows(int m, const char *want, int ms) {
    while (!strstr(seen, want)) {
        struct pollfd p = {.fd = m, .events = POLLIN};
        if (poll(&p, 1, ms) <= 0) return 0;
        ssize_t n = read(m, seen + seen_len, sizeof seen - 1 - seen_len);
        if (n <= 0) return 0;
        seen_len += (size_t)n;
        seen[seen_len] = 0;
    }
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    CHECK(m >= 0, "posix_openpt");
    CHECK(grantpt(m) == 0 && unlockpt(m) == 0, "grantpt, unlockpt");
    char name[64];
    CHECK(ptsname_r(m, name, sizeof name) == 0 && strncmp(name, "/dev/pts/", 9) == 0, "ptsname names /dev/pts/N");
    CHECK(isatty(m), "the master is a terminal");

    int s = open(name, O_RDWR | O_NOCTTY);
    CHECK(s >= 0 && isatty(s), "open the slave by its name");
    struct termios saved, raw;
    CHECK(tcgetattr(s, &saved) == 0 && (saved.c_lflag & ICANON) && (saved.c_lflag & ECHO), "the slave starts canonical, with echo");
    struct winsize ws = {.ws_row = 30, .ws_col = 100};
    CHECK(ioctl(m, TIOCSWINSZ, &ws) == 0, "set the window size at the master");
    memset(&ws, 0, sizeof ws);
    CHECK(ioctl(s, TIOCGWINSZ, &ws) == 0 && ws.ws_row == 30 && ws.ws_col == 100, "the slave has it");

    raw = saved;
    cfmakeraw(&raw);
    CHECK(tcsetattr(s, TCSANOW, &raw) == 0, "raw mode");
    CHECK(write(m, "ab", 2) == 2, "two keys at the master");
    // A read takes a key at a time here (proc/tty.zig); Linux may give both.
    char got[16] = {0};
    ssize_t have = 0;
    while (have < 2) {
        ssize_t r = read(s, got + have, sizeof got - (size_t)have);
        if (r <= 0) break;
        have += r;
    }
    CHECK(have == 2 && memcmp(got, "ab", 2) == 0, "the slave reads them as they are, no line wanted");
    struct pollfd p = {.fd = m, .events = POLLIN};
    CHECK(poll(&p, 1, 100) == 0, "and nothing was echoed");
    CHECK(write(s, "x\ny", 3) == 3 && master_shows(m, "x\ny", 2000), "raw output: no \\r added");
    CHECK(tcsetattr(s, TCSANOW, &saved) == 0, "back to canonical");
    close(s);
    seen_len = 0;
    seen[0] = 0;

    int ready[2];
    CHECK(pipe(ready) == 0, "a pipe to start the child");
    pid_t c = fork();
    if (c == 0) {
        close(ready[0]);
        if (setsid() < 0) _exit(10);
        int t = open(name, O_RDWR);
        if (t < 0) _exit(11);
        int ctty = open("/dev/tty", O_RDWR);
        if (ctty < 0) _exit(12);
        if (tcgetpgrp(t) != getpid()) _exit(13);
        if (write(ready[1], "x", 1) != 1) _exit(14);
        char line[64];
        ssize_t n = read(t, line, sizeof line - 1);
        if (n <= 0) _exit(15);
        line[n] = 0;
        dprintf(ctty, "got:%s", line);
        // Ctrl+C at the master ends this.
        for (;;) pause();
    }
    close(ready[1]);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1, "the child has the slave for its terminal, /dev/tty too");
    close(ready[0]);
    CHECK(write(m, "hello\n", 6) == 6, "a line typed at the master");
    CHECK(master_shows(m, "hello\r\n", 3000), "the master sees its echo, \\n as \\r\\n");
    CHECK(master_shows(m, "got:hello\r\n", 3000), "and what the child wrote to /dev/tty");
    usleep(50 * 1000);
    CHECK(write(m, "\x03", 1) == 1, "Ctrl+C at the master");
    int st = 0;
    CHECK(waitpid(c, &st, 0) == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGINT, "the child's group gets SIGINT");
    char rest[64];
    errno = 0;
    ssize_t n;
    while ((n = read(m, rest, sizeof rest)) > 0) {
    }
    CHECK(n == -1 && errno == EIO, "no slave left: the master reads EIO");
    CHECK(close(m) == 0, "close the master");

    errno = 0;
    CHECK(open("/dev/tty", O_RDWR) == -1 && errno == ENXIO, "no terminal for this session: /dev/tty is ENXIO");
    printf("lt_pty: all %d checks passed\n", check_no);
    return 0;
}
