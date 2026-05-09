// echo — print each user arg separated by single spaces, then a newline.
// Trivial stdout writer for scripting / pipeline experiments
// (`echo hello | wc`, `echo foo | grep f`, `echo a b c`). No flag parsing
// (no `-n` to suppress newline) — keep it simple.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    const argc = libc.getArgc();
    var i: u32 = 1;
    while (i < argc) : (i += 1) {
        if (i > 1) libc.printChar(' ');
        var argbuf: [32]u8 = undefined;
        const n = libc.getArgv(i, &argbuf);
        if (n == 0xFFFFFFFF or n == 0) continue;
        libc.print(argbuf[0..n]);
    }
    libc.printChar('\n');
    libc.exit();
}
