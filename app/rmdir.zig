// rmdir — remove empty directories.
//
// Usage:  rmdir <path> [<path>...]
//
// Calls libc.rmdir for each arg. Non-empty directories or missing entries
// produce a red error; processing continues with the remaining args.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    const argc = libc.getArgc();
    if (argc < 2) {
        libc.print("\x1b[31mrmdir: usage: rmdir <path>...\x1b[0m\n");
        libc.exit();
    }

    var i: u32 = 1;
    while (i < argc) : (i += 1) {
        var name_buf: [128]u8 = undefined;
        const n = libc.getArgv(i, &name_buf);
        if (n == 0 or n == 0xFFFFFFFF) continue;
        if (!libc.rmdir(name_buf[0..n])) {
            libc.print("\x1b[31mrmdir: cannot remove (not empty?): ");
            libc.print(name_buf[0..n]);
            libc.print("\x1b[0m\n");
        }
    }
    libc.exit();
}
