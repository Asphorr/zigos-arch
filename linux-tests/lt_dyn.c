// lt_dyn — a dynamically linked, position-independent program. The kernel
// maps it and its interpreter, musl's dynamic linker, which loads
// /lib/libltdyn.so before main and /lib/libltplug.so on dlopen. Checks the
// auxiliary vector the kernel built, the libraries' data, constructors and
// thread-local storage, dlopen, and an execve into a dynamic program.
// Needs /lib/ld-musl-x86_64.so.1 (tools/add_musl_to_image.sh).
// Exit 0 = every check passed, else the number of the first failed check.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/wait.h>
#include <unistd.h>

extern int lib_ready;
extern int lib_counter;
extern __thread int lib_tls;
int lib_add(int a, int b);
int lib_tls_bump(void);
int *lib_counter_addr(void);

int main(int argc, char **argv);

static int check_no;

#define CHECK(cond, what)                                                     \
    do {                                                                      \
        check_no++;                                                           \
        if (!(cond)) {                                                        \
            printf("lt_dyn: FAIL %d %s (errno %d)\n", check_no, what, errno); \
            exit(check_no);                                                   \
        }                                                                     \
    } while (0)

// What dl_iterate_phdr lists.
static int objects;
static int saw_lib;
static uintptr_t prog_bias;
static int found_prog;

static int each_object(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    objects++;
    if ((uintptr_t)info->dlpi_phdr == getauxval(AT_PHDR)) {
        prog_bias = info->dlpi_addr;
        found_prog = 1;
    }
    if (info->dlpi_name && strstr(info->dlpi_name, "libltdyn.so")) saw_lib = 1;
    return 0;
}

// The segment of the program's headers `ph` (with `n` entries) that holds
// `addr`, as moved by `bias`; its flags, or -1 for none.
static int segment_flags(const Elf64_Phdr *ph, unsigned long n, uintptr_t bias, uintptr_t addr) {
    for (unsigned long i = 0; i < n; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        uintptr_t lo = bias + ph[i].p_vaddr;
        if (addr >= lo && addr < lo + ph[i].p_memsz) return (int)ph[i].p_flags;
    }
    return -1;
}

static int count_type(const Elf64_Phdr *ph, unsigned long n, uint32_t type) {
    int c = 0;
    for (unsigned long i = 0; i < n; i++)
        if (ph[i].p_type == type) c++;
    return c;
}

// A new thread starts from the library's initial value and moves only its
// own copy.
static void *tls_thread(void *arg) {
    (void)arg;
    int first = lib_tls;
    lib_tls_bump();
    lib_tls_bump();
    return (void *)(intptr_t)(first * 100 + lib_tls);
}

static void check_auxv(void) {
    const Elf64_Phdr *ph = (const Elf64_Phdr *)getauxval(AT_PHDR);
    unsigned long n = getauxval(AT_PHNUM);
    CHECK(getauxval(AT_BASE) != 0, "AT_BASE names the interpreter");
    CHECK(ph != NULL && n > 0 && getauxval(AT_PHENT) == sizeof(Elf64_Phdr), "AT_PHDR, AT_PHNUM, AT_PHENT");
    CHECK(count_type(ph, n, PT_INTERP) == 1 && count_type(ph, n, PT_DYNAMIC) == 1, "AT_PHDR points at this program's headers");
    dl_iterate_phdr(each_object, NULL);
    CHECK(found_prog, "the dynamic linker found the program by AT_PHDR");
    CHECK(prog_bias > 0x100000000ul, "a position-independent program is moved high");
    CHECK((uintptr_t)&main > prog_bias, "and runs where it was moved");
    int entry_flags = segment_flags(ph, n, prog_bias, getauxval(AT_ENTRY));
    CHECK(entry_flags >= 0 && (entry_flags & PF_X), "AT_ENTRY lies in the program's code");
    CHECK(segment_flags(ph, n, prog_bias, (uintptr_t)&main) == entry_flags, "beside main");
    const char *fn = (const char *)getauxval(AT_EXECFN);
    CHECK(fn != NULL && strcmp(fn, "/bin/lt_dyn.elf") == 0, "AT_EXECFN");
    const char *plat = (const char *)getauxval(AT_PLATFORM);
    CHECK(plat != NULL && strcmp(plat, "x86_64") == 0, "AT_PLATFORM");
}

static void check_library(void) {
    CHECK(lib_ready == 42, "the library's constructor ran before main");
    CHECK(lib_add(40, 2) == 42, "a call into the library");
    CHECK(lib_counter == 100 && lib_counter_addr() == &lib_counter, "the library's data, one copy");
    lib_counter = 7;
    CHECK(*lib_counter_addr() == 7, "written by the program, seen by the library");
    CHECK(objects >= 3 && saw_lib, "program, library and libc listed");

    CHECK(lib_tls == 7, "the library's thread-local starts at its initial value");
    CHECK(lib_tls_bump() == 8 && lib_tls == 8, "one variable for program and library");
    pthread_t t;
    void *res = NULL;
    CHECK(pthread_create(&t, NULL, tls_thread, NULL) == 0 && pthread_join(t, &res) == 0, "a thread");
    CHECK((intptr_t)res == 7 * 100 + 9, "with a copy of its own");
    CHECK(lib_tls == 8, "ours untouched by it");
}

static void check_dlopen(void) {
    void *h = dlopen("libltplug.so", RTLD_NOW);
    if (!h) printf("lt_dyn: dlopen: %s\n", dlerror());
    CHECK(h != NULL, "dlopen from the default path");
    int *ready = dlsym(h, "plug_ready");
    int (*twice)(int, int) = (int (*)(int, int))dlsym(h, "plug_twice_sum");
    CHECK(ready != NULL && *ready == 1, "the plugin's constructor ran");
    CHECK(twice != NULL && twice(20, 1) == 42, "the plugin calls the library already loaded");
    CHECK(dlsym(RTLD_DEFAULT, "lib_add") == (void *)lib_add, "one lib_add for everybody");
    CHECK(dlclose(h) == 0, "dlclose");
    CHECK(dlopen("libltabsent.so", RTLD_NOW) == NULL && dlerror() != NULL, "a missing library is an error");
}

static void check_exec(void) {
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/lt_dyn.elf", "lt_dyn", "child", (char *)0);
        _exit(99);
    }
    int st = 0;
    CHECK(pid > 0 && waitpid(pid, &st, 0) == pid && WIFEXITED(st), "a child");
    CHECK(WEXITSTATUS(st) == 0, "execve into a dynamic program");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    // Started by check_exec: a dynamic program again, its library loaded.
    if (argc > 1 && strcmp(argv[1], "child") == 0) return lib_add(2, 3) == 5 && lib_ready == 42 ? 0 : 1;
    check_auxv();
    check_library();
    check_dlopen();
    check_exec();
    printf("lt_dyn: all %d checks passed\n", check_no);
    return 0;
}
