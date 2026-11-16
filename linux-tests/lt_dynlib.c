// lt_dynlib — the library lt_dyn is linked against (/lib/libltdyn.so):
// data, thread-local storage and a constructor, in a shared object the
// dynamic linker loads before the program starts.

int lib_ready;
int lib_counter = 100;
__thread int lib_tls = 7;

__attribute__((constructor)) static void lib_init(void) { lib_ready = 42; }

int lib_add(int a, int b) { return a + b; }

int lib_tls_bump(void) { return ++lib_tls; }

int *lib_counter_addr(void) { return &lib_counter; }
