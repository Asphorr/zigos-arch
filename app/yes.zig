// yes — write `y` (or argv[1]) followed by a newline, repeatedly, until
// killed OR until stdout's reader goes away. The write result is CHECKED:
// when the downstream pipe stage exits (head, wc...), pipe.write returns
// 0xFFFFFFFF (the kernel's EPIPE) and we exit — that's what lets
// `yes | head 5` terminate by itself instead of spinning on dead-pipe
// writes forever (2026-06-12 fix; the old version ignored the result and
// once racked up 3.5M failed write syscalls under a long-finished head).
// Still useful as a SIGINT-forwarding test target for the shell: bare
// `yes` then Ctrl+C kills it via the shell's SIGINT handler.

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    var argbuf: [128]u8 = undefined; // was 32 — silently truncated longer words
    var word: []const u8 = "y";
    if (libc.getArgc() >= 2) {
        const n = libc.getArgv(1, &argbuf);
        if (n != 0xFFFFFFFF and n != 0) word = argbuf[0..n];
    }
    // Emit word+newline as ONE write per line so a failing write can't
    // half-emit a line, and so the EPIPE check runs exactly once per line.
    var line_buf: [129]u8 = undefined;
    @memcpy(line_buf[0..word.len], word);
    line_buf[word.len] = '\n';
    const line = line_buf[0 .. word.len + 1];
    while (true) {
        const r = libc.fwrite(1, line);
        if (r == 0xFFFFFFFF or r == 0) break; // EPIPE (reader gone) / dead fd
    }
    libc.exit();
}
