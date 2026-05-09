// nc — minimal netcat-style TCP client.
//
// Usage:
//   nc <host> <port>
//
// Examples:
//   nc 10.0.2.2 8080            connect to host port 8080 over QEMU NAT
//   nc example.com 80           DNS-resolve and connect
//   nc towel.blinkenlights.nl 23  watch ASCII Star Wars (telnet)
//
// The app forwards keystrokes from the shell to the peer and prints anything
// the peer sends back. Ctrl+C closes the connection cleanly. There's no line
// editing or escape sequences — every byte you type goes on the wire as-is.

const libc = @import("libc");

const RX_CHUNK: usize = 1024;
const TX_CHUNK: usize = 128;
const IDLE_SLEEP_MS: u32 = 30;

var should_quit: bool = false;

export fn handleSigint(signo: u32, info: *anyopaque, uc: *anyopaque) void {
    _ = signo;
    _ = info;
    _ = uc;
    const flag: *volatile bool = &should_quit;
    flag.* = true;
}

fn parseU16(s: []const u8) ?u16 {
    if (s.len == 0) return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
        if (v > 65535) return null;
    }
    return @intCast(v);
}

fn printIp(ip: [4]u8) void {
    for (0..4) |i| {
        if (i > 0) libc.printChar('.');
        libc.printNum(ip[i]);
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    if (libc.getArgc() < 3) {
        libc.print("\x1b[31mnc: missing arguments\x1b[0m\n");
        libc.print("usage: nc <host> <port>\n");
        libc.exit();
    }

    var host_buf: [256]u8 = undefined;
    const host_len = libc.getArgv(1, &host_buf);
    if (host_len == 0 or host_len == 0xFFFFFFFF) {
        libc.print("\x1b[31mnc: bad host\x1b[0m\n");
        libc.exit();
    }
    const host = host_buf[0..host_len];

    var port_buf: [16]u8 = undefined;
    const port_len = libc.getArgv(2, &port_buf);
    if (port_len == 0 or port_len == 0xFFFFFFFF) {
        libc.print("\x1b[31mnc: bad port\x1b[0m\n");
        libc.exit();
    }
    const port = parseU16(port_buf[0..port_len]) orelse {
        libc.print("\x1b[31mnc: bad port number\x1b[0m\n");
        libc.exit();
    };

    // Try raw IP first (skips DNS for "10.0.2.2"-style targets), then
    // fall back to DNS resolve for hostnames.
    const ip = libc.parseIp(host) orelse libc.resolve(host) orelse {
        libc.print("\x1b[31mnc: cannot resolve ");
        libc.print(host);
        libc.print("\x1b[0m\n");
        libc.exit();
    };

    libc.print("Connecting to ");
    printIp(ip);
    libc.printChar(':');
    libc.printNum(port);
    libc.print("...\n");

    var act: libc.SigAction = .{ .handler = @intFromPtr(&handleSigint) };
    _ = libc.sigaction(libc.SIGINT, &act, null);

    const slot = libc.tcpConnect(ip, port) orelse {
        libc.print("\x1b[31mnc: connection failed\x1b[0m\n");
        libc.exit();
    };
    libc.print("\x1b[32mConnected.\x1b[0m Press Ctrl+C to close.\n");

    var rx_buf: [RX_CHUNK]u8 = undefined;
    var tx_buf: [TX_CHUNK]u8 = undefined;

    while (true) {
        const quit: *volatile bool = &should_quit;
        if (quit.*) break;

        // Drain stdin into a small TX buffer. Send what we got in one
        // tcpSend so we don't fragment into single-byte segments. readChar
        // is non-blocking; it returns 0 when nothing is queued.
        var tx_len: usize = 0;
        while (tx_len < tx_buf.len) {
            const c = libc.readChar();
            if (c == 0) break;
            // Only forward typeable bytes — readChar can also yield kernel
            // navigation codes (0x80+) that the peer can't make sense of.
            if (c >= 0x20 and c <= 0x7E) {
                tx_buf[tx_len] = c;
                tx_len += 1;
            } else if (c == '\n' or c == '\r' or c == '\x08' or c == '\t') {
                tx_buf[tx_len] = c;
                tx_len += 1;
            }
        }
        if (tx_len > 0) {
            if (!libc.tcpSend(slot, tx_buf[0..tx_len])) {
                libc.print("\n\x1b[31mnc: send failed\x1b[0m\n");
                break;
            }
        }

        // Drain whatever the peer has sent. tcpRecv is non-blocking so
        // returning 0 just means "nothing queued yet".
        const n = libc.tcpRecv(slot, &rx_buf);
        if (n > 0) _ = libc.fwrite(1, rx_buf[0..n]);

        // EOF: peer FIN'd AND we've drained everything they wrote.
        const st = libc.tcpStatus(slot);
        if ((st & libc.TCP_STATUS_PEER_CLOSED) != 0 and n == 0) break;

        // Idle sleep when both ends are quiet so we don't burn CPU.
        if (tx_len == 0 and n == 0) libc.sleep(IDLE_SLEEP_MS);
    }

    libc.tcpClose(slot);
    libc.print("\n\x1b[2mConnection closed.\x1b[0m\n");
    libc.exit();
}
