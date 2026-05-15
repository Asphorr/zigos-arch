// netstat — show interface, sockets, and ARP cache. Thin reader over the
// three /proc/net* files; all the actual rendering happens in the kernel
// (src/net/net.zig:renderProcInfo / renderProcSock / renderProcArp) so
// every netcat / wget / httpd state change shows up here on the next run.

const libc = @import("libc");

fn dumpFile(label: []const u8, path: []const u8) void {
    libc.print("\x1b[1;36m== ");
    libc.print(label);
    libc.print(" ==\x1b[0m\n");
    const fd = libc.open(path) orelse {
        libc.print("\x1b[31m(unavailable)\x1b[0m\n\n");
        return;
    };
    defer libc.close(fd);
    var buf: [2048]u8 = undefined;
    while (true) {
        const n = libc.fread(fd, &buf);
        if (n == 0) break;
        libc.print(buf[0..n]);
    }
    libc.printChar('\n');
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    dumpFile("interface", "/proc/netinfo");
    dumpFile("sockets",   "/proc/netsock");
    dumpFile("arp cache", "/proc/netarp");
    libc.exit();
}
