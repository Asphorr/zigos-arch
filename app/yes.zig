// yes — write `y` (or argv[1]) followed by a newline, repeatedly, until
// killed. Useful as a SIGINT-forwarding test target for the shell:
// `yes | head 5` should print 5 y's and exit cleanly; `yes` then Ctrl+C
// should kill it via the shell's SIGINT handler.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    var argbuf: [32]u8 = undefined;
    var word: []const u8 = "y";
    if (libc.getArgc() >= 2) {
        const n = libc.getArgv(1, &argbuf);
        if (n != 0xFFFFFFFF and n != 0) word = argbuf[0..n];
    }
    while (true) {
        libc.print(word);
        libc.printChar('\n');
    }
}
