// dmesg — print the kernel log buffer.
//
// Usage:
//   dmesg              dump the entire visible /dev/kmsg ring
//   dmesg -n 20        last 20 lines
//   dmesg -f           tail-follow: keep printing new lines as they arrive
//
// Implementation: open /dev/kmsg, read in 4 KiB chunks, copy to stdout.
// `-n` keeps a circular line buffer in memory; we slurp the full ring,
// count lines, then emit only the trailing N. `-f` re-opens the device
// after the initial dump and polls for new content (sleep 200ms between
// reads, exit on Ctrl-C — SIGINT is the default action).

const libc = @import("libc");

const RING_BYTES: usize = 32 * 1024;
const MAX_LINES: usize = 1024;

fn parseU32(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

/// Print the last `n` newline-delimited lines from `data`. If the buffer
/// has fewer lines, prints all of them.
fn printLastN(data: []const u8, n: u32) void {
    if (n == 0) return;
    // Build a circular table of line start offsets so we can rewind.
    var line_starts: [MAX_LINES]u32 = undefined;
    var head: usize = 0;
    var len: usize = 0;
    var cur_start: u32 = 0;
    var i: u32 = 0;
    while (i < data.len) : (i += 1) {
        if (data[i] == '\n') {
            line_starts[head] = cur_start;
            head = (head + 1) % MAX_LINES;
            if (len < MAX_LINES) len += 1;
            cur_start = i + 1;
        }
    }
    // Trailing partial line (no newline) — track it too.
    if (cur_start < data.len) {
        line_starts[head] = cur_start;
        head = (head + 1) % MAX_LINES;
        if (len < MAX_LINES) len += 1;
    }

    const want = if (n > len) len else @as(usize, n);
    if (want == 0) return;
    // First wanted line is `want` slots back from head.
    const first_idx = (head + MAX_LINES - want) % MAX_LINES;
    const first_off = line_starts[first_idx];
    libc.print(data[first_off..]);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var follow = false;
    var n_lines: u32 = 0;
    var n_lines_set = false;

    const argc = libc.getArgc();
    var ai: u32 = 1;
    while (ai < argc) : (ai += 1) {
        var arg: [16]u8 = undefined;
        const al = libc.getArgv(ai, &arg);
        if (al == 0 or al == 0xFFFFFFFF) continue;
        const s = arg[0..@min(@as(usize, @intCast(al)), arg.len)];
        if (s.len == 2 and s[0] == '-' and s[1] == 'f') {
            follow = true;
        } else if (s.len == 2 and s[0] == '-' and s[1] == 'n') {
            ai += 1;
            if (ai >= argc) {
                libc.print("\x1b[31mdmesg: -n needs a count\x1b[0m\n");
                libc.exit();
            }
            var nb: [16]u8 = undefined;
            const nl = libc.getArgv(ai, &nb);
            if (nl == 0 or nl == 0xFFFFFFFF) {
                libc.print("\x1b[31mdmesg: -n needs a count\x1b[0m\n");
                libc.exit();
            }
            const num = parseU32(nb[0..@min(@as(usize, @intCast(nl)), nb.len)]) orelse {
                libc.print("\x1b[31mdmesg: -n: not a number\x1b[0m\n");
                libc.exit();
            };
            n_lines = num;
            n_lines_set = true;
        } else {
            libc.print("\x1b[31mdmesg: unknown arg: ");
            libc.print(s);
            libc.print("\x1b[0m\n");
            libc.exit();
        }
    }

    var ring_buf: [RING_BYTES]u8 = undefined;
    const fd = libc.open("/dev/kmsg") orelse {
        libc.print("\x1b[31mdmesg: cannot open /dev/kmsg\x1b[0m\n");
        libc.exit();
    };

    // Initial dump: drain everything currently in the ring (kernel
    // tracks per-fd stream position, so subsequent reads return only
    // *new* bytes — exactly what follow mode wants).
    var total: usize = 0;
    while (total < ring_buf.len) {
        const n = libc.fread(fd, ring_buf[total..]);
        if (n == 0 or n == 0xFFFFFFFF) break;
        total += n;
    }
    if (n_lines_set) {
        printLastN(ring_buf[0..total], n_lines);
    } else {
        libc.print(ring_buf[0..total]);
    }

    if (!follow) {
        libc.close(fd);
        libc.exit();
    }

    // Follow: keep reading from the same fd. The kernel's stream cursor
    // advances even past bytes that age out of the ring, so we never
    // double-print and never miss content unless the kernel writes faster
    // than we can drain (in which case ringRead skips ahead automatically).
    while (true) {
        libc.sleep(200);
        const n = libc.fread(fd, &ring_buf);
        if (n == 0 or n == 0xFFFFFFFF) continue;
        libc.print(ring_buf[0..n]);
    }
}
