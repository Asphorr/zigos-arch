// lt_net — sockets and the calls that wait on many files: eventfd, pipes
// that don't block, Unix sockets by pair and by name, TCP and UDP over
// loopback (TCP also many connections at once and in a row), epoll (level,
// edge, one shot) and select. Everything stays on
// this machine, so it runs with no network attached. Exit 0 = every check
// passed, else the number of the first failed check.

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int check_no;

#define CHECK(cond, what)                                                     \
    do {                                                                      \
        check_no++;                                                           \
        if (!(cond)) {                                                        \
            printf("lt_net: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                   \
        }                                                                     \
    } while (0)

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// The byte at position `i` of the stream a side sends.
static unsigned char pattern(size_t i, unsigned seed) {
    return (unsigned char)(i * 31 + (i >> 8) * 7 + seed);
}

static int write_all(int fd, const void *buf, size_t len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

// Wait for child `pid` and return its exit status, -1 if it didn't exit.
static int reap(pid_t pid) {
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

static void check_eventfd(void) {
    uint64_t v = 0;
    int fd = eventfd(3, EFD_NONBLOCK);
    CHECK(fd >= 0, "eventfd");
    CHECK(read(fd, &v, 8) == 8 && v == 3, "a read takes the whole count");
    CHECK(read(fd, &v, 8) == -1 && errno == EAGAIN, "and an empty one would block");
    v = 5;
    CHECK(write(fd, &v, 8) == 8 && write(fd, &v, 8) == 8, "writes add up");
    struct pollfd p = {.fd = fd, .events = POLLIN | POLLOUT};
    CHECK(poll(&p, 1, 0) == 1 && p.revents == (POLLIN | POLLOUT), "readable and writable");
    CHECK(read(fd, &v, 8) == 8 && v == 10, "to their sum");
    CHECK(read(fd, &v, 4) == -1 && errno == EINVAL, "eight bytes or nothing");
    close(fd);

    fd = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);
    CHECK(read(fd, &v, 8) == 8 && v == 1 && read(fd, &v, 8) == 8 && v == 1, "a semaphore gives one at a time");
    CHECK(read(fd, &v, 8) == -1 && errno == EAGAIN, "until none is left");
    close(fd);

    // A blocking read wakes on a child's write.
    fd = eventfd(0, 0);
    pid_t pid = fork();
    if (pid == 0) {
        usleep(50 * 1000);
        v = 7;
        _exit(write(fd, &v, 8) == 8 ? 0 : 1);
    }
    CHECK(read(fd, &v, 8) == 8 && v == 7, "a blocked read wakes on a write");
    CHECK(reap(pid) == 0, "the writer exited cleanly");
    close(fd);
}

static void check_pipe_nonblock(void) {
    int p[2];
    char buf[4096];
    CHECK(pipe2(p, O_NONBLOCK) == 0, "pipe2 O_NONBLOCK");
    CHECK(read(p[0], buf, sizeof buf) == -1 && errno == EAGAIN, "an empty pipe would block");
    memset(buf, 'x', sizeof buf);
    size_t total = 0;
    ssize_t n;
    while ((n = write(p[1], buf, sizeof buf)) > 0) total += (size_t)n;
    CHECK(n == -1 && errno == EAGAIN && total >= 4096, "a full one too");
    CHECK(read(p[0], buf, 100) == 100, "what is there is read");
    close(p[1]);
    while ((n = read(p[0], buf, sizeof buf)) > 0) total -= (size_t)n;
    CHECK(n == 0 && total == 100, "then the rest, then the end");
    close(p[0]);

    // The flag by fcntl and by ioctl.
    CHECK(pipe(p) == 0, "pipe");
    CHECK(fcntl(p[0], F_SETFL, O_NONBLOCK) == 0 && (fcntl(p[0], F_GETFL) & O_NONBLOCK), "F_SETFL O_NONBLOCK");
    CHECK(read(p[0], buf, 1) == -1 && errno == EAGAIN, "takes effect");
    int off = 0;
    CHECK(ioctl(p[0], FIONBIO, &off) == 0 && !(fcntl(p[0], F_GETFL) & O_NONBLOCK), "FIONBIO clears it");
    close(p[0]);
    close(p[1]);
}

static void check_socketpair(void) {
    int sv[2], val = 0;
    socklen_t len = sizeof val;
    char buf[64];
    struct stat st;
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    CHECK(fstat(sv[0], &st) == 0 && S_ISSOCK(st.st_mode), "a socket to fstat");
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_TYPE, &val, &len) == 0 && val == SOCK_STREAM, "SO_TYPE");
    CHECK(getsockopt(sv[0], SOL_SOCKET, SO_DOMAIN, &val, &len) == 0 && val == AF_UNIX, "SO_DOMAIN");
    CHECK(write(sv[0], "ping", 4) == 4 && read(sv[1], buf, sizeof buf) == 4 && memcmp(buf, "ping", 4) == 0, "one way");
    CHECK(write(sv[1], "pong!", 5) == 5, "the other way");
    CHECK(ioctl(sv[0], FIONREAD, &val) == 0 && val == 5, "FIONREAD counts it");
    CHECK(recv(sv[0], buf, 2, MSG_PEEK) == 2 && memcmp(buf, "po", 2) == 0, "a peek leaves it");
    CHECK(recv(sv[0], buf, sizeof buf, 0) == 5 && memcmp(buf, "pong!", 5) == 0, "for the read");
    CHECK(recv(sv[0], buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN, "MSG_DONTWAIT on nothing");
    CHECK(lseek(sv[0], 0, SEEK_CUR) == -1 && errno == ESPIPE, "no seeking");

    // One side done sending: the other reads the end, and can still send.
    CHECK(write(sv[0], "last", 4) == 4 && shutdown(sv[0], SHUT_WR) == 0, "shutdown(SHUT_WR)");
    CHECK(read(sv[1], buf, sizeof buf) == 4 && read(sv[1], buf, sizeof buf) == 0, "the data, then the end");
    CHECK(write(sv[1], "back", 4) == 4 && read(sv[0], buf, sizeof buf) == 4, "the open direction still carries");
    CHECK(send(sv[0], "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE, "the shut one is EPIPE");

    // The other end closed: readable for the end, hung up, EPIPE to write.
    close(sv[1]);
    struct pollfd p = {.fd = sv[0], .events = POLLIN | POLLOUT};
    CHECK(poll(&p, 1, 0) == 1 && (p.revents & POLLIN) && (p.revents & POLLHUP), "poll sees the peer go");
    CHECK(read(sv[0], buf, sizeof buf) == 0, "a read gets the end");
    close(sv[0]);

    // Datagrams keep their edges.
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) == 0, "socketpair SOCK_DGRAM");
    CHECK(send(sv[0], "one", 3, 0) == 3 && send(sv[0], "second", 6, 0) == 6, "two messages");
    CHECK(recv(sv[1], buf, sizeof buf, 0) == 3 && memcmp(buf, "one", 3) == 0, "arrive one");
    CHECK(recv(sv[1], buf, 2, MSG_TRUNC) == 6 && memcmp(buf, "se", 2) == 0, "by one, cut to the buffer");
    CHECK(recv(sv[1], buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN, "the cut-off rest is gone");
    close(sv[0]);
    close(sv[1]);

    // A blocked read wakes when a child writes, across fork.
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0, "socketpair SOCK_CLOEXEC");
    CHECK(fcntl(sv[0], F_GETFD) == FD_CLOEXEC, "sets the flag");
    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        usleep(50 * 1000);
        _exit(write(sv[1], "child", 5) == 5 ? 0 : 1);
    }
    close(sv[1]);
    CHECK(read(sv[0], buf, sizeof buf) == 5 && memcmp(buf, "child", 5) == 0, "a blocked read wakes");
    CHECK(read(sv[0], buf, sizeof buf) == 0, "and ends with the child");
    CHECK(reap(pid) == 0, "which exited cleanly");
    close(sv[0]);
}

static void unix_addr(struct sockaddr_un *a, socklen_t *len, const char *path, int abstract) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    size_t n = strlen(path);
    memcpy(a->sun_path + (abstract ? 1 : 0), path, n);
    // A path with its terminator; an abstract name with its leading zero.
    *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n + 1);
}

// A server at `path`, a forked client: connect, a request, a reply.
static void unix_exchange(const char *path, int abstract) {
    struct sockaddr_un a, got;
    socklen_t alen, glen = sizeof got;
    char buf[64];
    unix_addr(&a, &alen, path, abstract);
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(l >= 0 && bind(l, (struct sockaddr *)&a, alen) == 0, "bind a Unix socket");
    CHECK(listen(l, 4) == 0, "listen");
    CHECK(getsockname(l, (struct sockaddr *)&got, &glen) == 0 && got.sun_family == AF_UNIX &&
              memcmp(got.sun_path, a.sun_path, strlen(path) + (abstract ? 1 : 0)) == 0,
          "getsockname gives the name back");
    pid_t pid = fork();
    if (pid == 0) {
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(c, (struct sockaddr *)&a, alen) != 0) _exit(10);
        if (write(c, "request", 7) != 7) _exit(11);
        if (read(c, buf, sizeof buf) != 5 || memcmp(buf, "reply", 5) != 0) _exit(12);
        _exit(0);
    }
    int c = accept(l, NULL, NULL);
    CHECK(c >= 0, "accept");
    CHECK(read(c, buf, sizeof buf) == 7 && memcmp(buf, "request", 7) == 0, "the request");
    struct ucred cred;
    socklen_t clen = sizeof cred;
    CHECK(getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &clen) == 0 && cred.pid == pid, "SO_PEERCRED names the client");
    CHECK(write(c, "reply", 5) == 5, "the reply");
    CHECK(reap(pid) == 0, "the client got it");
    close(c);
    close(l);
}

static void check_unix_named(void) {
    const char *path = "/tmp/lt_net.sock";
    struct sockaddr_un a;
    socklen_t alen;
    struct stat st;
    mkdir("/tmp", 0777);
    unlink(path);
    unix_exchange(path, 0);

    // The name outlives the socket, as a file of its own kind.
    CHECK(stat(path, &st) == 0 && S_ISSOCK(st.st_mode), "the path is a socket file");
    unix_addr(&a, &alen, path, 0);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(s, (struct sockaddr *)&a, alen) == -1 && errno == ECONNREFUSED, "nobody behind it: refused");
    CHECK(bind(s, (struct sockaddr *)&a, alen) == -1 && errno == EADDRINUSE, "and in the way of a new bind");
    CHECK(unlink(path) == 0, "until unlinked");
    CHECK(connect(s, (struct sockaddr *)&a, alen) == -1 && errno == ENOENT, "then there is no such name");
    CHECK(bind(s, (struct sockaddr *)&a, alen) == 0 && unlink(path) == 0, "and it can be bound again");
    close(s);

    // An abstract name: no file, gone with the socket.
    unix_exchange("lt_net_abstract", 1);
    unix_addr(&a, &alen, "lt_net_abstract", 1);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(s, (struct sockaddr *)&a, alen) == -1 && errno == ECONNREFUSED, "an abstract name dies with its socket");
    close(s);

    CHECK(socket(AF_INET6, SOCK_STREAM, 0) == -1 && errno == EAFNOSUPPORT, "no IPv6 to offer");
}

static void on_alarm(int sig) { (void)sig; }

#define UP_BYTES (300 * 1024)
#define DOWN_BYTES (100 * 1024)

// The client of check_tcp: sends UP_BYTES, shuts its side, reads DOWN_BYTES.
static int tcp_client(uint16_t port_be) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = port_be};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    static unsigned char buf[4096];
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0 || connect(c, (struct sockaddr *)&a, sizeof a) != 0) return 20;
    for (size_t sent = 0; sent < UP_BYTES;) {
        size_t n = sizeof buf;
        if (n > UP_BYTES - sent) n = UP_BYTES - sent;
        for (size_t i = 0; i < n; i++) buf[i] = pattern(sent + i, 1);
        if (write_all(c, buf, n) != 0) return 21;
        sent += n;
    }
    if (shutdown(c, SHUT_WR) != 0) return 22;
    size_t got = 0;
    for (;;) {
        // Small reads: the window must reopen without one big one.
        ssize_t n = read(c, buf, 1000);
        if (n < 0) return 23;
        if (n == 0) break;
        for (ssize_t i = 0; i < n; i++)
            if (buf[i] != pattern(got + (size_t)i, 2)) return 24;
        got += (size_t)n;
    }
    return got == DOWN_BYTES ? 0 : 25;
}

static void check_tcp(void) {
    struct sockaddr_in a = {.sin_family = AF_INET}, got;
    socklen_t glen = sizeof got;
    static unsigned char buf[4096];
    int one = 1;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int l = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(l >= 0, "socket(AF_INET, SOCK_STREAM)");
    CHECK(setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0, "SO_REUSEADDR");
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0, "bind to any port");
    CHECK(getsockname(l, (struct sockaddr *)&got, &glen) == 0 && got.sin_port != 0 && got.sin_addr.s_addr == htonl(INADDR_LOOPBACK),
          "the port is chosen at bind, and the address is the one bound");
    uint16_t bound_be = got.sin_port;
    CHECK(listen(l, 8) == 0, "listen");
    CHECK(getsockname(l, (struct sockaddr *)&got, &glen) == 0 && glen == sizeof got && got.sin_port == bound_be, "listen keeps that port");
    uint16_t port_be = got.sin_port;

    // accept is cut short by a signal with no SA_RESTART.
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    struct itimerval it = {.it_value = {.tv_usec = 50 * 1000}};
    setitimer(ITIMER_REAL, &it, NULL);
    CHECK(accept(l, NULL, NULL) == -1 && errno == EINTR, "a signal interrupts accept");

    pid_t pid = fork();
    if (pid == 0) _exit(tcp_client(port_be));
    struct sockaddr_in peer;
    socklen_t plen = sizeof peer;
    int c = accept(l, (struct sockaddr *)&peer, &plen);
    CHECK(c >= 0 && peer.sin_family == AF_INET && peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK) && peer.sin_port != 0, "accept names the client");
    glen = sizeof got;
    CHECK(getpeername(c, (struct sockaddr *)&got, &glen) == 0 && got.sin_port == peer.sin_port, "getpeername agrees");
    glen = sizeof got;
    CHECK(getsockname(c, (struct sockaddr *)&got, &glen) == 0 && got.sin_port == port_be, "our end is the listening port");
    CHECK(setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) == 0, "TCP_NODELAY");

    size_t up = 0;
    int bad = 0;
    for (;;) {
        ssize_t n = read(c, buf, sizeof buf);
        if (n <= 0) {
            bad |= n < 0;
            break;
        }
        for (ssize_t i = 0; i < n; i++) bad |= buf[i] != pattern(up + (size_t)i, 1);
        up += (size_t)n;
    }
    CHECK(!bad && up == UP_BYTES, "300 KiB arrive in order, then the end");
    for (size_t sent = 0; sent < DOWN_BYTES;) {
        size_t n = sizeof buf;
        if (n > DOWN_BYTES - sent) n = DOWN_BYTES - sent;
        for (size_t i = 0; i < n; i++) buf[i] = pattern(sent + i, 2);
        if (write_all(c, buf, n) != 0) bad = 1;
        sent += n;
    }
    CHECK(!bad, "100 KiB go back over the half-closed connection");
    close(c);
    CHECK(reap(pid) == 0, "and the client read them all");

    // A read with a timeout gives up.
    int s = socket(AF_INET, SOCK_STREAM, 0);
    a.sin_port = port_be;
    CHECK(connect(s, (struct sockaddr *)&a, sizeof a) == 0, "a second connection");
    c = accept(l, NULL, NULL);
    struct timeval tv = {.tv_usec = 100 * 1000};
    CHECK(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0, "SO_RCVTIMEO");
    long t0 = now_ms();
    CHECK(read(s, buf, 1) == -1 && errno == EAGAIN && now_ms() - t0 >= 80, "a read times out");
    // The peer closes with data unread behind it: the reader still gets it.
    CHECK(write(c, "bye", 3) == 3 && close(c) == 0, "data, then close");
    CHECK(read(s, buf, sizeof buf) == 3 && read(s, buf, sizeof buf) == 0, "arrive in that order");
    close(s);

    // Nobody listens: refused, at once.
    close(l);
    s = socket(AF_INET, SOCK_STREAM, 0);
    t0 = now_ms();
    CHECK(connect(s, (struct sockaddr *)&a, sizeof a) == -1 && errno == ECONNREFUSED && now_ms() - t0 < 2000, "a closed port refuses");
    close(s);

    // connect without waiting: writable when done, the outcome in SO_ERROR.
    l = socket(AF_INET, SOCK_STREAM, 0);
    a.sin_port = 0;
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 1) == 0, "a new listener");
    glen = sizeof got;
    getsockname(l, (struct sockaddr *)&got, &glen);
    s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int r = connect(s, (struct sockaddr *)&got, sizeof got);
    CHECK(r == 0 || errno == EINPROGRESS, "a non-blocking connect");
    struct pollfd p = {.fd = s, .events = POLLOUT};
    int err = -1;
    socklen_t elen = sizeof err;
    CHECK(poll(&p, 1, 2000) == 1 && (p.revents & POLLOUT), "turns writable");
    CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0, "with no error");
    CHECK(read(s, buf, 1) == -1 && errno == EAGAIN, "and nothing to read yet");
    close(s);
    close(l);
}

// The pending error of `fd` (SO_ERROR), -1 if it can't be read.
static int so_error(int fd) {
    int e = -1;
    socklen_t len = sizeof e;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &len) != 0) return -1;
    return e;
}

static int has_error(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    return poll(&p, 1, 0) < 0 || (p.revents & POLLERR);
}

// "ping" then the end of the stream, as `fd` reads them.
static int read_ping_end(int fd) {
    char b[8];
    return read(fd, b, sizeof b) == 4 && memcmp(b, "ping", 4) == 0 && read(fd, b, sizeof b) == 0;
}

// A side that shut its sending half stays usable as long as the other side
// wants: well past the time a FIN left unacknowledged would make the
// retransmission give up (a few round trips once one was timed).
static void check_tcp_linger(void) {
    struct sockaddr_in a = {.sin_family = AF_INET};
    socklen_t alen = sizeof a;
    char b[8];
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int l = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 4) == 0 && getsockname(l, (struct sockaddr *)&a, &alen) == 0, "a listener");
    int c1 = socket(AF_INET, SOCK_STREAM, 0), c2 = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(c1, (struct sockaddr *)&a, sizeof a) == 0 && connect(c2, (struct sockaddr *)&a, sizeof a) == 0, "two connections");
    int s1 = accept(l, NULL, NULL), s2 = accept(l, NULL, NULL);
    CHECK(s1 >= 0 && s2 >= 0, "both accepted");
    // One: the client is done, the server answers late.
    CHECK(write(c1, "ping", 4) == 4 && shutdown(c1, SHUT_WR) == 0 && read_ping_end(s1), "a client done sending");
    // Two: both are done; the server's side is then closed and still held.
    CHECK(write(c2, "ping", 4) == 4 && shutdown(c2, SHUT_WR) == 0 && read_ping_end(s2), "a second one");
    CHECK(write(s2, "pong", 4) == 4 && shutdown(s2, SHUT_WR) == 0, "the server done too");
    CHECK(read(c2, b, sizeof b) == 4 && read(c2, b, sizeof b) == 0, "the client reads it all");
    struct timespec ts = {.tv_sec = 4};
    nanosleep(&ts, NULL);
    CHECK(so_error(c1) == 0 && !has_error(c1), "a half-closed client is still connected");
    CHECK(write(s1, "late", 4) == 4 && close(s1) == 0, "the late answer");
    CHECK(read(c1, b, sizeof b) == 4 && memcmp(b, "late", 4) == 0 && read(c1, b, sizeof b) == 0, "reaches it");
    CHECK(so_error(s2) == 0 && !has_error(s2) && read(s2, b, sizeof b) == 0, "a closed side held open reads the end, no error");
    close(c1);
    close(c2);
    close(s2);
    close(l);
}

// A reader that stops: the writer fills the window and its own buffer and
// waits. The connection outlives a few timeouts that way (the window is
// probed, nothing is given up), and the stream goes on whole.
static void check_tcp_stall(void) {
    struct sockaddr_in a = {.sin_family = AF_INET};
    socklen_t alen = sizeof a;
    static unsigned char buf[4096];
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int l = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 1) == 0 && getsockname(l, (struct sockaddr *)&a, &alen) == 0, "a listener");
    int w = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(connect(w, (struct sockaddr *)&a, sizeof a) == 0, "a connection");
    int r = accept(l, NULL, NULL);
    CHECK(r >= 0 && fcntl(w, F_SETFL, O_NONBLOCK) == 0, "accepted; the writer does not wait");

    size_t sent = 0;
    while (sent < (8u << 20)) {
        for (size_t i = 0; i < sizeof buf; i++) buf[i] = pattern(sent + i, 3);
        ssize_t n = write(w, buf, sizeof buf);
        if (n <= 0) break;
        sent += (size_t)n;
    }
    CHECK(errno == EAGAIN && sent >= 64 * 1024 && sent < (8u << 20), "the writer fills up against a reader that stopped");
    struct timespec ts = {.tv_sec = 3};
    nanosleep(&ts, NULL);
    struct pollfd p = {.fd = w, .events = POLLOUT};
    CHECK(poll(&p, 1, 0) == 0 && so_error(w) == 0 && !has_error(w), "and stays so, connected, while it sleeps");

    size_t got = 0;
    int bad = 0;
    while (got < sent) {
        ssize_t n = read(r, buf, sizeof buf);
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) bad |= buf[i] != pattern(got + (size_t)i, 3);
        got += (size_t)n;
    }
    CHECK(!bad && got == sent, "the reader wakes and gets all of it in order");
    CHECK(poll(&p, 1, 2000) == 1 && (p.revents & POLLOUT), "the writer may go on");
    CHECK(write(w, "tail", 4) == 4 && shutdown(w, SHUT_WR) == 0, "a last write, the end");
    CHECK(read(r, buf, sizeof buf) == 4 && memcmp(buf, "tail", 4) == 0 && read(r, buf, sizeof buf) == 0, "arrive");
    close(w);
    close(r);
    close(l);
}

// Many connections at once, then many in a row: what a closed connection
// leaves behind does not stand in the way of the next ones.
static void check_tcp_many(void) {
    enum { PAIRS = 26, ROUNDS = 400 };
    struct sockaddr_in a = {.sin_family = AF_INET};
    socklen_t alen = sizeof a;
    char b;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int l = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0 && listen(l, 64) == 0 && getsockname(l, (struct sockaddr *)&a, &alen) == 0, "a listener");
    int c[PAIRS], s[PAIRS];
    int made = 0;
    for (; made < PAIRS; made++) {
        c[made] = socket(AF_INET, SOCK_STREAM, 0);
        if (c[made] < 0 || connect(c[made], (struct sockaddr *)&a, sizeof a) != 0) break;
        s[made] = accept(l, NULL, NULL);
        if (s[made] < 0) break;
    }
    if (made != PAIRS) printf("lt_net: connection %d of %d failed\n", made + 1, PAIRS);
    CHECK(made == PAIRS, "26 connections held at once");
    int ok = 1;
    for (int i = 0; i < PAIRS; i++) {
        char x = (char)('a' + i);
        ok &= write(c[i], &x, 1) == 1 && read(s[i], &b, 1) == 1 && b == x;
    }
    CHECK(ok, "each carries its own byte");
    // Half are closed from the client's end first, half from the server's.
    for (int i = 0; i < PAIRS; i++) {
        close(i % 2 ? c[i] : s[i]);
        close(i % 2 ? s[i] : c[i]);
    }

    long t0 = now_ms();
    int done = 0;
    for (; done < ROUNDS; done++) {
        int cc = socket(AF_INET, SOCK_STREAM, 0);
        if (cc < 0 || connect(cc, (struct sockaddr *)&a, sizeof a) != 0) break;
        int ss = accept(l, NULL, NULL);
        if (ss < 0 || write(cc, "q", 1) != 1 || read(ss, &b, 1) != 1) break;
        close(cc);
        close(ss);
    }
    long took = now_ms() - t0;
    if (done != ROUNDS || took >= 10000) printf("lt_net: %d of %d connections in a row, %ld ms\n", done, ROUNDS, took);
    CHECK(done == ROUNDS, "400 connections one after another");
    CHECK(took < 10000, "none of them waits for a closed one to be forgotten");
    close(l);
}

static void check_udp(void) {
    struct sockaddr_in a = {.sin_family = AF_INET}, from, got;
    socklen_t flen = sizeof from, glen = sizeof got;
    char buf[64];
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int srv = socket(AF_INET, SOCK_DGRAM, 0), cli = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(srv >= 0 && cli >= 0, "socket(AF_INET, SOCK_DGRAM)");
    CHECK(bind(srv, (struct sockaddr *)&a, sizeof a) == 0, "bind to any port");
    CHECK(getsockname(srv, (struct sockaddr *)&got, &glen) == 0 && got.sin_port != 0, "which getsockname names");
    a.sin_port = got.sin_port;
    CHECK(recv(srv, buf, sizeof buf, MSG_DONTWAIT) == -1 && errno == EAGAIN, "nothing yet");
    CHECK(sendto(cli, "first", 5, 0, (struct sockaddr *)&a, sizeof a) == 5, "sendto");
    CHECK(sendto(cli, "second!", 7, 0, (struct sockaddr *)&a, sizeof a) == 7, "and again");
    struct pollfd p = {.fd = srv, .events = POLLIN};
    CHECK(poll(&p, 1, 1000) == 1 && (p.revents & POLLIN), "poll sees a datagram");
    CHECK(recvfrom(srv, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen) == 5 && memcmp(buf, "first", 5) == 0, "the first");
    CHECK(flen == sizeof from && from.sin_family == AF_INET && from.sin_port != 0, "with its sender");
    CHECK(recv(srv, buf, sizeof buf, 0) == 7 && memcmp(buf, "second!", 7) == 0, "the second, whole");
    // The answer goes to the address the question came from.
    CHECK(sendto(srv, "answer", 6, 0, (struct sockaddr *)&from, flen) == 6, "a reply to the sender");
    CHECK(recv(cli, buf, sizeof buf, 0) == 6 && memcmp(buf, "answer", 6) == 0, "arrives");
    // A connected datagram socket sends without an address.
    CHECK(connect(cli, (struct sockaddr *)&a, sizeof a) == 0 && send(cli, "conn", 4, 0) == 4, "connect, send");
    CHECK(recv(srv, buf, sizeof buf, 0) == 4, "arrives too");
    char big[2000];
    memset(big, 0, sizeof big);
    CHECK(send(cli, big, sizeof big, 0) == -1 && errno == EMSGSIZE, "more than a frame is refused");
    close(srv);
    close(cli);

    // Many at once: as many as the descriptor table has room for.
    int many[40], n = 0;
    while (n < 40 && (many[n] = socket(AF_INET, SOCK_DGRAM, 0)) >= 0) n++;
    CHECK(n == 40, "forty datagram sockets at once");
    while (n > 0) close(many[--n]);
}

static void check_epoll(void) {
    int sv[2], ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev, out[8];
    char buf[16];
    CHECK(ep >= 0, "epoll_create1");
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv) == 0, "a pair to watch");
    ev.events = EPOLLIN;
    ev.data.u64 = 0x1122334455667788ull;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &ev) == 0, "EPOLL_CTL_ADD");
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &ev) == -1 && errno == EEXIST, "twice is EEXIST");
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, sv[1], NULL) == -1 && errno == ENOENT, "an unknown one ENOENT");
    CHECK(epoll_wait(ep, out, 8, 0) == 0, "nothing ready");
    long t0 = now_ms();
    CHECK(epoll_wait(ep, out, 8, 60) == 0 && now_ms() - t0 >= 50, "a timeout is waited out");
    CHECK(write(sv[1], "a", 1) == 1, "a byte");
    CHECK(epoll_wait(ep, out, 8, 1000) == 1 && out[0].events == EPOLLIN && out[0].data.u64 == 0x1122334455667788ull, "is reported with its data");
    CHECK(epoll_wait(ep, out, 8, 0) == 1, "and again while unread: level-triggered");

    // Edge-triggered: once per arrival.
    ev.events = EPOLLIN | EPOLLET;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, sv[0], &ev) == 0, "EPOLL_CTL_MOD to EPOLLET");
    CHECK(epoll_wait(ep, out, 8, 0) == 1, "what is there is reported once");
    CHECK(epoll_wait(ep, out, 8, 0) == 0, "and not again");
    CHECK(write(sv[1], "b", 1) == 1 && epoll_wait(ep, out, 8, 0) == 1, "a new byte is a new edge");
    CHECK(read(sv[0], buf, sizeof buf) == 2 && epoll_wait(ep, out, 8, 0) == 0, "drained: quiet");

    // One shot: silent after a report until rearmed.
    ev.events = EPOLLIN | EPOLLONESHOT;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, sv[0], &ev) == 0 && write(sv[1], "c", 1) == 1, "EPOLLONESHOT");
    CHECK(epoll_wait(ep, out, 8, 0) == 1 && epoll_wait(ep, out, 8, 0) == 0, "fires once");
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, sv[0], &ev) == 0 && epoll_wait(ep, out, 8, 0) == 1, "and again after a MOD");
    CHECK(read(sv[0], buf, sizeof buf) == 1, "the byte");

    // An eventfd beside it; a waiter woken by a child.
    int efd = eventfd(0, EFD_NONBLOCK);
    ev.events = EPOLLIN;
    ev.data.u64 = 2;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev) == 0, "an eventfd in the set");
    pid_t pid = fork();
    if (pid == 0) {
        uint64_t v = 1;
        usleep(50 * 1000);
        _exit(write(efd, &v, 8) == 8 ? 0 : 1);
    }
    CHECK(epoll_wait(ep, out, 8, 5000) == 1 && out[0].data.u64 == 2, "a blocked epoll_wait wakes on it");
    CHECK(reap(pid) == 0, "the child exited cleanly");
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, efd, NULL) == 0 && epoll_wait(ep, out, 8, 0) == 0, "EPOLL_CTL_DEL");

    // The peer goes: readable, hung up.
    ev.events = EPOLLIN | EPOLLRDHUP;
    ev.data.u64 = 1;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, sv[0], &ev) == 0 && close(sv[1]) == 0, "the peer closes");
    CHECK(epoll_wait(ep, out, 8, 0) == 1 && (out[0].events & EPOLLIN) && (out[0].events & EPOLLRDHUP) && (out[0].events & EPOLLHUP), "EPOLLRDHUP and EPOLLHUP");
    // A closed file leaves the set by itself.
    CHECK(close(sv[0]) == 0 && epoll_wait(ep, out, 8, 0) == 0, "a closed file is forgotten");

    // A regular file can't be waited on; a set can watch a set.
    int reg = open("/etc", O_RDONLY);
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, reg, &ev) == -1 && errno == EPERM, "a directory is EPERM");
    close(reg);
    int outer = epoll_create1(0);
    ev.events = EPOLLIN;
    CHECK(epoll_ctl(outer, EPOLL_CTL_ADD, ep, &ev) == 0 && epoll_wait(outer, out, 8, 0) == 0, "a set in a set");
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev) == 0, "the eventfd back in the inner one");
    uint64_t v = 1;
    CHECK(write(efd, &v, 8) == 8 && epoll_wait(outer, out, 8, 0) == 1, "the outer sees the inner ready");
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, ep, &ev) == -1 && errno == EINVAL, "not itself");
    close(outer);
    close(efd);
    close(ep);
}

static void check_select(void) {
    int p[2], sv[2];
    fd_set r, w;
    char c;
    CHECK(pipe(p) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "a pipe and a pair");
    int top = (p[0] > sv[0] ? p[0] : sv[0]) + 1;
    if (sv[1] >= top) top = sv[1] + 1;
    struct timeval tv = {.tv_usec = 60 * 1000};
    FD_ZERO(&r);
    FD_SET(p[0], &r);
    FD_SET(sv[0], &r);
    long t0 = now_ms();
    CHECK(select(top, &r, NULL, NULL, &tv) == 0 && now_ms() - t0 >= 50, "select times out on nothing");
    CHECK(!FD_ISSET(p[0], &r) && !FD_ISSET(sv[0], &r), "with the sets cleared");
    CHECK(write(p[1], "x", 1) == 1, "a byte in the pipe");
    FD_ZERO(&r);
    FD_ZERO(&w);
    FD_SET(p[0], &r);
    FD_SET(sv[0], &r);
    FD_SET(sv[1], &w);
    CHECK(select(top, &r, &w, NULL, NULL) == 2, "two are ready");
    CHECK(FD_ISSET(p[0], &r) && !FD_ISSET(sv[0], &r) && FD_ISSET(sv[1], &w), "the pipe to read, the socket to write");
    CHECK(read(p[0], &c, 1) == 1, "the byte");
    FD_ZERO(&r);
    FD_SET(60, &r);
    tv.tv_usec = 0;
    CHECK(select(61, &r, NULL, NULL, &tv) == -1 && errno == EBADF, "a closed descriptor is EBADF");
    close(p[0]);
    close(p[1]);
    close(sv[0]);
    close(sv[1]);
}

static const struct {
    const char *name;
    void (*run)(void);
} groups[] = {
    {"eventfd", check_eventfd}, {"pipe", check_pipe_nonblock}, {"pair", check_socketpair},
    {"unix", check_unix_named}, {"tcp", check_tcp},            {"linger", check_tcp_linger},
    {"stall", check_tcp_stall}, {"many", check_tcp_many},      {"udp", check_udp},
    {"epoll", check_epoll},     {"select", check_select},
};

// With arguments, only the groups they name.
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    for (size_t g = 0; g < sizeof groups / sizeof groups[0]; g++) {
        int wanted = argc < 2;
        for (int i = 1; i < argc; i++)
            if (strcmp(argv[i], groups[g].name) == 0) wanted = 1;
        if (wanted) groups[g].run();
    }
    printf("lt_net: all %d checks passed\n", check_no);
    return 0;
}
