// nslookup — resolve a hostname to its IPv4 address via the kernel DNS path.
//
// Usage:
//   nslookup example.com
//
// Output:
//   example.com = 93.184.216.34

const libc = @import("libc");

fn printOctet(n: u8) void {
    if (n == 0) {
        libc.printChar('0');
        return;
    }
    var dig: [3]u8 = undefined;
    var dlen: usize = 0;
    var v: u8 = n;
    while (v > 0) : (dlen += 1) {
        dig[dlen] = '0' + (v % 10);
        v /= 10;
    }
    var rev: [3]u8 = undefined;
    for (0..dlen) |i| rev[i] = dig[dlen - 1 - i];
    libc.print(rev[0..dlen]);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    if (libc.getArgc() < 2) {
        libc.print("\x1b[31mnslookup: missing hostname\x1b[0m\n");
        libc.print("usage: nslookup <hostname>\n");
        libc.exit();
    }

    var host_buf: [256]u8 = undefined;
    const host_len = libc.getArgv(1, &host_buf);
    if (host_len == 0 or host_len == 0xFFFFFFFF) {
        libc.print("\x1b[31mnslookup: empty hostname\x1b[0m\n");
        libc.exit();
    }
    const host = host_buf[0..host_len];

    const ip = libc.resolve(host) orelse {
        libc.print("\x1b[31mnslookup: no answer for ");
        libc.print(host);
        libc.print("\x1b[0m\n");
        libc.exit();
    };

    libc.print(host);
    libc.print(" = ");
    for (0..4) |i| {
        if (i > 0) libc.printChar('.');
        printOctet(ip[i]);
    }
    libc.printChar('\n');
    libc.exit();
}
