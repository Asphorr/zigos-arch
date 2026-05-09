// head — print the first N lines from stdin (default 10).
//   head 5             prints first 5 lines
//   ls | head 3        first 3 file names
//
// Only stdin is supported (no `head <file>` form yet — `cat foo | head`
// covers the same case). `N` is parsed as a positive integer; non-digit
// characters terminate the parse (so `head -5` would get 0 → fall back).

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    var argbuf: [64]u8 = undefined;
    const arg_len = libc.getExecArg(&argbuf);
    var n_lines: u32 = 10;
    if (arg_len > 0) {
        var v: u32 = 0;
        for (argbuf[0..arg_len]) |c| {
            if (c < '0' or c > '9') break;
            v = v * 10 + (c - '0');
        }
        if (v > 0) n_lines = v;
    }

    var buf: [256]u8 = undefined;
    var emitted: u32 = 0;

    outer: while (emitted < n_lines) {
        const n = libc.fread(0, &buf);
        if (n == 0 or n == 0xFFFFFFFF) break;
        var start: usize = 0;
        for (buf[0..n], 0..) |b, i| {
            if (b == '\n') {
                _ = libc.fwrite(1, buf[start .. i + 1]);
                emitted += 1;
                start = i + 1;
                if (emitted >= n_lines) break :outer;
            }
        }
        // Tail of the chunk without a newline yet — emit it; the next chunk
        // will continue this same line.
        if (start < n) _ = libc.fwrite(1, buf[start..n]);
    }
    libc.exit();
}
