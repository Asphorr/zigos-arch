// sleep — block for N seconds (default 1) then exit. SIGINT-interruptible:
// the kernel's signal-on-syscall-return path delivers SIGINT to its default
// action while we're parked in libc.sleep, so a shell `Ctrl+C` while the
// child is running tears it down without us having to install a handler.
//
// Usage: `sleep` (1s) or `sleep N` (N seconds, decimal).

const libc = @import("libc");

fn parseU32(s: []const u8) u32 {
    if (s.len == 0) return 0;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return 0;
        v = v *% 10 +% @as(u32, c - '0');
    }
    return v;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var seconds: u32 = 1;
    if (libc.getArgc() >= 2) {
        var argbuf: [16]u8 = undefined;
        const n = libc.getArgv(1, &argbuf);
        if (n != 0xFFFFFFFF and n != 0) {
            const parsed = parseU32(argbuf[0..n]);
            if (parsed != 0) seconds = parsed;
        }
    }
    // Sleep one second at a time so a SIGINT lands on a syscall boundary
    // (every iteration). One big libc.sleep(seconds * 1000) would also work
    // — the kernel wakes on signal — but breaking it up means we never sit
    // on a billion-ms wake_tick if the user passes something silly.
    var remaining: u32 = seconds;
    while (remaining > 0) : (remaining -= 1) libc.sleep(1000);
    libc.exit();
}
