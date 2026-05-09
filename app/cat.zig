// cat — print one or more files (or stdin if no args) to stdout.
//   cat foo.txt        prints the contents of foo.txt
//   cat foo bar baz    concatenates foo, bar, baz in order
//   cat                reads stdin to EOF, copies to stdout (works in pipelines)
//
// Reads in 4 KB chunks. fread returns 0 on EOF. Errors (file not found,
// short reads) print a red message and continue with the next file —
// partial output is acceptable since we can't undo what's already been
// written.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    const argc = libc.getArgc();

    var buf: [4096]u8 = undefined;

    // No user args (argv[0] is always the program name) → read stdin.
    if (argc <= 1) {
        while (true) {
            const n = libc.fread(0, &buf);
            if (n == 0 or n == 0xFFFFFFFF) break;
            _ = libc.fwrite(1, buf[0..n]);
        }
        libc.exit();
    }

    var i: u32 = 1;
    while (i < argc) : (i += 1) {
        var name_buf: [32]u8 = undefined;
        const name_len = libc.getArgv(i, &name_buf);
        if (name_len == 0xFFFFFFFF or name_len == 0) continue;
        const name = name_buf[0..name_len];

        const fd = libc.open(name) orelse {
            libc.print("\x1b[31mcat: cannot open: ");
            libc.print(name);
            libc.print("\x1b[0m\n");
            continue;
        };
        while (true) {
            const n = libc.fread(fd, &buf);
            if (n == 0 or n == 0xFFFFFFFF) break;
            _ = libc.fwrite(1, buf[0..n]);
        }
        libc.close(fd);
    }
    libc.exit();
}
