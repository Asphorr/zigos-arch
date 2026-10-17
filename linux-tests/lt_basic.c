// lt_basic — what every static musl program needs before main does any
// work: the SysV initial stack (argc/argv/envp/auxv), TLS, stdio through
// writev, and the ext2 root through open/read/getdents64/stat. Boot mode 19
// runs it as `lt_basic one two three`; exit 0 = every check passed, else
// the number of the first failed check.

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

    printf("lt_basic: PASS (%d checks)\n", check_no);
    return 0;
}
