// grep — read stdin a line at a time, print lines containing the pattern.
//   grep elf            (used as `ls | grep elf`)
//
// Substring match only (no regex, no `-i`, no `-v`). Lines are accumulated
// in a 512-byte buffer; if a line is longer it gets truncated to that
// length for matching purposes (the printed text is the full accumulated
// portion, the rest is dropped on the floor — fine for the kinds of input
// our tooling produces).

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    var argbuf: [64]u8 = undefined;
    const arg_len = libc.getExecArg(&argbuf);
    if (arg_len == 0) {
        libc.print("\x1b[31mgrep: missing pattern\x1b[0m\n");
        libc.exit();
    }
    const pat = argbuf[0..arg_len];

    var inbuf: [256]u8 = undefined;
    var line: [512]u8 = undefined;
    var line_len: usize = 0;

    while (true) {
        const n = libc.fread(0, &inbuf);
        if (n == 0 or n == 0xFFFFFFFF) break;
        for (inbuf[0..n]) |b| {
            if (b == '\n') {
                if (containsSubstring(line[0..line_len], pat)) {
                    _ = libc.fwrite(1, line[0..line_len]);
                    libc.printChar('\n');
                }
                line_len = 0;
            } else if (line_len < line.len) {
                line[line_len] = b;
                line_len += 1;
            }
            // else: drop overflow silently — we'd rather truncate than crash.
        }
    }
    // Trailing line without a final \n — emit if it matches.
    if (line_len > 0 and containsSubstring(line[0..line_len], pat)) {
        _ = libc.fwrite(1, line[0..line_len]);
        libc.printChar('\n');
    }
    libc.exit();
}

fn containsSubstring(hay: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |c, j| {
            if (hay[i + j] != c) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}
