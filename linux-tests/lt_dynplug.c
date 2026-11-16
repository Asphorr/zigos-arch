// lt_dynplug — a plugin lt_dyn opens with dlopen while it runs
// (/lib/libltplug.so). It calls into libltdyn.so, which the dynamic linker
// binds to the copy the program already has.

int lib_add(int a, int b);

int plug_ready;

__attribute__((constructor)) static void plug_init(void) { plug_ready = 1; }

int plug_twice_sum(int a, int b) { return 2 * lib_add(a, b); }
