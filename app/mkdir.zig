// mkdir — create directories.
//
// Usage:  mkdir <path> [<path>...]
//
// One libc.mkdir call per arg. Errors are reported per-path and don't stop
// processing the remaining args (matches BSD/coreutils behavior).

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    const argc = libc.getArgc();
    if (argc < 2) {
        libc.print("\x1b[31mmkdir: usage: mkdir <path>...\x1b[0m\n");
        libc.exit();
    }

    var i: u32 = 1;
    while (i < argc) : (i += 1) {
        var name_buf: [128]u8 = undefined;
        const n = libc.getArgv(i, &name_buf);
        if (n == 0 or n == 0xFFFFFFFF) continue;
        if (!libc.mkdir(name_buf[0..n])) {
            libc.print("\x1b[31mmkdir: cannot create: ");
            libc.print(name_buf[0..n]);
            libc.print("\x1b[0m\n");
        }
    }
    libc.exit();
}
