// touch — create empty files (and update timestamps when re-touched).
//
// Usage:  touch <path> [<path>...]
//
// Opens each path with O_CREATE; if the file doesn't exist ext2 creates
// it (mtime/ctime stamped at creation). Errors are reported per-path
// and don't stop processing the remaining args.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    const argc = libc.getArgc();
    if (argc < 2) {
        libc.print("\x1b[31mtouch: usage: touch <path>...\x1b[0m\n");
        libc.exit();
    }

    var i: u32 = 1;
    while (i < argc) : (i += 1) {
        var name_buf: [128]u8 = undefined;
        const n = libc.getArgv(i, &name_buf);
        if (n == 0 or n == 0xFFFFFFFF) continue;
        const fd_opt = libc.openFlags(name_buf[0..n], libc.O_CREATE);
        if (fd_opt) |fd| {
            libc.close(fd);
        } else {
            libc.print("\x1b[31mtouch: cannot create: ");
            libc.print(name_buf[0..n]);
            libc.print("\x1b[0m\n");
        }
    }
    libc.exit();
}
