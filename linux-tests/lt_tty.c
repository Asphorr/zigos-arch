// lt_tty — a terminal as a Linux program finds it: isatty, the modes, the
// size, the foreground group; a line edited before it is read (erase, kill,
// end of file); raw mode, a key at a time, the arrow keys as sequences, a
// read that doesn't wait. The harness types the keys (linux_selftest.zig,
// the case's `terminal`); they wait in the terminal until read, so nothing
// here depends on when. Exit 0 = every check passed, else the number of the
// first failed check.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

static int check_no;

#define CHECK(cond, what)                                                     \
    do {                                                                      \
        check_no++;                                                           \
        if (!(cond)) {                                                        \
            printf("lt_tty: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                   \
        }                                                                     \
    } while (0)

// One read of the terminal equal to `want`.
static int reads(const char *want) {
    char buf[64];
    ssize_t n = read(0, buf, sizeof buf);
    return n == (ssize_t)strlen(want) && memcmp(buf, want, n) == 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct termios t, raw;
    struct winsize ws;
    struct stat st;

    CHECK(isatty(0) && isatty(1) && isatty(2), "the three standard fds are a terminal");
    CHECK(fstat(0, &st) == 0 && S_ISCHR(st.st_mode), "a character device to fstat");
    CHECK(tcgetattr(0, &t) == 0 && (t.c_lflag & ICANON) && (t.c_lflag & ECHO) && (t.c_lflag & ISIG), "it starts with a line, echo and key signals");
    CHECK(t.c_cc[VINTR] == 3 && t.c_cc[VEOF] == 4 && t.c_cc[VMIN] == 1, "and the usual keys");
    CHECK(ioctl(1, TIOCGWINSZ, &ws) == 0 && ws.ws_row == 25 && ws.ws_col == 80, "25 rows of 80");
    CHECK(tcgetpgrp(0) == getpgrp(), "this process's group has it");
    int fd = open("/etc", O_RDONLY);
    errno = 0;
    CHECK(fd >= 0 && !isatty(fd) && errno == ENOTTY, "a directory is no terminal");
    close(fd);

    // Typed: a b X backspace c Enter. The line arrives whole, edited.
    CHECK(reads("abc\n"), "a line with an erased key");
    // Typed ahead: two lines, one read each.
    CHECK(reads("one\n"), "the first of two lines");
    CHECK(reads("two\n"), "the second");
    // Typed: j u n k ^U o k Enter.
    CHECK(reads("ok\n"), "^U takes the line back");
    // Typed: ^D on an empty line.
    CHECK(read(0, &st, 8) == 0, "^D at the start of a line is the end of input");
    // Typed: p a r t ^D.
    CHECK(reads("part"), "^D after keys gives them without a newline");

    // Raw: keys as they come, no echo.
    raw = t;
    raw.c_lflag &= ~(ICANON | ECHO | ISIG);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    CHECK(tcsetattr(0, TCSANOW, &raw) == 0 && tcgetattr(0, &t) == 0 && !(t.c_lflag & ICANON), "raw mode set and read back");
    // Typed: k, then the up arrow.
    CHECK(reads("k"), "one key, with no Enter");
    struct pollfd pf = {.fd = 0, .events = POLLIN};
    char seq[8];
    CHECK(read(0, seq, 1) == 1 && seq[0] == 0x1b, "the up arrow starts with ESC");
    CHECK(poll(&pf, 1, 0) == 1 && (pf.revents & POLLIN), "poll sees the rest of its sequence");
    CHECK(read(0, seq, sizeof seq) == 2 && seq[0] == '[' && seq[1] == 'A', "which is [A");
    CHECK(poll(&pf, 1, 0) == 0, "then nothing is waiting");
    raw.c_cc[VMIN] = 0;
    CHECK(tcsetattr(0, TCSANOW, &raw) == 0 && read(0, seq, 1) == 0, "with VMIN 0 a read with no key returns 0");
    fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
    raw.c_cc[VMIN] = 1;
    tcsetattr(0, TCSANOW, &raw);
    errno = 0;
    CHECK(read(0, seq, 1) == -1 && errno == EAGAIN, "O_NONBLOCK: EAGAIN");
    fcntl(0, F_SETFL, fcntl(0, F_GETFL) & ~O_NONBLOCK);

    raw.c_lflag |= ICANON | ECHO | ISIG;
    CHECK(tcsetattr(0, TCSAFLUSH, &raw) == 0, "back to a line");
    printf("lt_tty: all %d checks passed\n", check_no);
    return 0;
}
