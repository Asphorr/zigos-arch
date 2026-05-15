// httpsget — minimal TLS 1.3 + HTTP/1.1 GET demo.
//
// Usage:
//   httpsget <ip> <port> <sni> <path>
//
// Example:
//   httpsget 10.0.2.2 4433 zigvm /
//
// Drives the full handshake through the kernel's TlsConn API
// (syscalls 107-110): X25519 ECDH, ChaCha20-Poly1305 AEAD, RSA-PSS or
// ECDSA CertificateVerify, chain walking + Mozilla NSS trust anchor
// lookup, then HTTP/1.1 GET over the encrypted channel. No URL parser,
// no redirects, no chunked decoding — the point is to prove that
// userspace can hand the kernel an SNI and a path and get bytes back.

const libc = @import("libc");

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

fn copyArg(idx: u32, buf: []u8) ?[]u8 {
    const n = libc.getArgv(idx, buf);
    if (n == 0 or n == 0xFFFFFFFF) return null;
    return buf[0..n];
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    if (libc.getArgc() < 2) {
        libc.print("\x1b[31mhttpsget: missing arguments\x1b[0m\n");
        libc.print("usage: httpsget <host> [port] [path]\n");
        libc.print("  host: hostname (DNS-resolved) OR IPv4 literal\n");
        libc.print("  port: default 443\n");
        libc.print("  path: default /\n");
        libc.print("examples:\n");
        libc.print("  httpsget example.com\n");
        libc.print("  httpsget 10.0.2.2 4433\n");
        libc.exit();
    }

    var host_buf: [256]u8 = undefined;
    const host = copyArg(1, &host_buf) orelse libc.exit();

    // Try IP literal first; if that fails, treat as hostname and DNS-resolve.
    // The SNI is always the textual host argument — that's the identity the
    // cert's SubjectAltName needs to cover.
    const ip = libc.parseIp(host) orelse libc.resolve(host) orelse {
        libc.print("\x1b[31mhttpsget: cannot resolve ");
        libc.print(host);
        libc.print("\x1b[0m\n");
        libc.exit();
    };

    var port: u16 = 443;
    if (libc.getArgc() >= 3) {
        var port_buf: [16]u8 = undefined;
        const port_arg = copyArg(2, &port_buf) orelse libc.exit();
        port = parseU16(port_arg) orelse {
            libc.print("\x1b[31mhttpsget: bad port\x1b[0m\n");
            libc.exit();
        };
    }

    const sni = host;

    var path_buf: [512]u8 = undefined;
    const path: []u8 = if (libc.getArgc() >= 4)
        copyArg(3, &path_buf) orelse libc.exit()
    else blk: {
        path_buf[0] = '/';
        break :blk path_buf[0..1];
    };

    libc.print("Resolved ");
    libc.print(host);
    libc.print(" -> ");
    for (0..4) |i| {
        if (i > 0) libc.printChar('.');
        libc.printNum(ip[i]);
    }
    libc.printChar(':');
    libc.printNum(port);
    libc.printChar('\n');

    libc.print("Connecting + handshaking...\n");
    const slot = libc.tlsConnect(ip, port, sni) orelse {
        libc.print("\x1b[31mhttpsget: TLS connect failed\x1b[0m\n");
        libc.exit();
    };
    libc.print("\x1b[32mTLS established (slot ");
    libc.printNum(slot);
    libc.print(")\x1b[0m\n");

    // Build a one-line GET. Host header uses the SNI (same identity
    // the server's cert was issued for).
    var req_buf: [1024]u8 = undefined;
    var req_len: usize = 0;
    const prefix = "GET ";
    @memcpy(req_buf[req_len..][0..prefix.len], prefix);
    req_len += prefix.len;
    @memcpy(req_buf[req_len..][0..path.len], path);
    req_len += path.len;
    const middle = " HTTP/1.1\r\nHost: ";
    @memcpy(req_buf[req_len..][0..middle.len], middle);
    req_len += middle.len;
    @memcpy(req_buf[req_len..][0..sni.len], sni);
    req_len += sni.len;
    const suffix = "\r\nConnection: close\r\nUser-Agent: httpsget/0.1\r\n\r\n";
    @memcpy(req_buf[req_len..][0..suffix.len], suffix);
    req_len += suffix.len;

    if (libc.tlsSend(slot, req_buf[0..req_len]) == null) {
        libc.print("\x1b[31mtls_send failed\x1b[0m\n");
        libc.tlsClose(slot);
        libc.exit();
    }

    var rx_buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const n_opt = libc.tlsRecv(slot, &rx_buf);
        if (n_opt) |n| {
            if (n == 0) break; // EOF
            _ = libc.fwrite(1, rx_buf[0..n]);
            total += n;
        } else {
            libc.print("\n\x1b[31mtls_recv error\x1b[0m\n");
            break;
        }
    }

    libc.print("\n\x1b[2m--- ");
    libc.printNum(@intCast(total));
    libc.print(" bytes ---\x1b[0m\n");
    libc.tlsClose(slot);
    libc.exit();
}
