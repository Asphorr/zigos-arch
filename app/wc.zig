// Minimal wc — read all of stdin (fd 0), then print "<bytes> <lines>\n".
// Used to validate shell pipelines (`ls | wc`) end-to-end. Reads in 256-byte
// chunks until fread returns 0 (EOF — pipe writer fully closed).

const libc = @import("libc");

export fn _start() linksection(".text.entry") callconv(.c) void {
    var buf: [256]u8 = undefined;
    var bytes: u32 = 0;
    var lines: u32 = 0;

    while (true) {
        const n = libc.fread(0, &buf);
        if (n == 0) break;
        bytes += n;
        for (buf[0..n]) |b| {
            if (b == '\n') lines += 1;
        }
    }

    libc.printNum(bytes);
    libc.print(" bytes ");
    libc.printNum(lines);
    libc.print(" lines\n");
    libc.exit();
}
