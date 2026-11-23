// TLS smoke test against the dev server: `openssl s_server -www` on the
// QEMU host (SLIRP 10.0.2.2:4433, self-signed CN=zigvm cert). Runs the
// same conn.tlsConnect path apps use, from its own task so boot never
// waits on it. With nothing listening it costs one log line after the
// TCP connect deadline.

const std = @import("std");
const debug = @import("../../debug/debug.zig");
const conn = @import("conn.zig");

const TARGET_IP = [4]u8{ 10, 0, 2, 2 };
const TARGET_PORT: u16 = 4433;
const TARGET_SNI = "zigvm";

pub fn run() void {
    const slot = conn.tlsConnect(TARGET_IP, TARGET_PORT, TARGET_SNI, .{ .insecure_self_signed = true }) orelse {
        debug.klog("[tls] probe: no handshake with 10.0.2.2:4433 (dev server down?)\n", .{});
        return;
    };
    defer conn.tlsClose(slot);

    const req = "GET / HTTP/1.0\r\nHost: " ++ TARGET_SNI ++ "\r\n\r\n";
    if (conn.tlsSend(slot, req) < 0) {
        debug.klog("[tls] probe: handshake OK, send failed\n", .{});
        return;
    }
    var reply: [512]u8 = undefined;
    const n = conn.tlsRecv(slot, &reply);
    if (n <= 0) {
        debug.klog("[tls] probe: handshake OK, no reply (s_server without -www?)\n", .{});
        return;
    }
    const got = reply[0..@intCast(n)];
    const line_end = std.mem.indexOfScalar(u8, got, '\r') orelse got.len;
    debug.klog("[tls] probe PASS: {d} B back, \"{s}\"\n", .{ n, got[0..@min(line_end, 80)] });
}
