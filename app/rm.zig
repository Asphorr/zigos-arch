// rm — remove files.
//
// Usage:  rm <path> [<path>...]
//
// Files only — directories must be removed with rmdir. Errors are
// reported per-path; processing continues for the rest.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    const argc = libc.getArgc();
    if (argc < 2) {
        libc.print("\x1b[31mrm: usage: rm <path>...\x1b[0m\n");
        libc.exit();
    }

    var i: u32 = 1;
    while (i < argc) : (i += 1) {
        var name_buf: [128]u8 = undefined;
        const n = libc.getArgv(i, &name_buf);
        if (n == 0 or n == 0xFFFFFFFF) continue;
        if (!libc.unlink(name_buf[0..n])) {
            libc.print("\x1b[31mrm: cannot remove: ");
            libc.print(name_buf[0..n]);
            libc.print("\x1b[0m\n");
        }
    }
    libc.exit();
}
