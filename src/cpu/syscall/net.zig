//! Syscall handlers (net) — split out of syscall.zig (#797).
//! Dispatched from cpu/syscall.zig doSyscallInner; named in SYSCALLS.

const std = @import("std");
const vga = @import("../../ui/vga.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const keyboard = @import("../../driver/keyboard.zig");
const process = @import("../../proc/process.zig");
const vmm = @import("../../mm/vmm.zig");
const pmm = @import("../../mm/pmm.zig");
const paging = @import("../../mm/paging.zig");
const bga = @import("../../ui/bga.zig");
const vfs = @import("../../fs/vfs.zig");
const desktop = @import("../../ui/desktop.zig");
const xhci = @import("../../driver/xhci.zig");
const debug = @import("../../debug/debug.zig");
const perf = @import("../../debug/perf.zig");
const pipe = @import("../../proc/pipe.zig");
const memmap = @import("../../mm/memmap.zig");
const config = @import("../../config.zig");
const smp = @import("../smp.zig");
const signals = @import("../../proc/signals.zig");
const errno = @import("../../proc/errno.zig");
const sched_asm = @import("../../proc/sched_asm.zig");
const apic = @import("../../time/apic.zig");

const common = @import("common.zig");
const validateUserPtr = common.validateUserPtr;
const validateUserPtrAligned = common.validateUserPtrAligned;
const validateUserPtrWrite = common.validateUserPtrWrite;
const validateUserPtrWriteAligned = common.validateUserPtrWriteAligned;
const USER_SPACE_START = common.USER_SPACE_START;
const USER_SPACE_END = common.USER_SPACE_END;
const E_INVAL = common.E_INVAL;
const E_NOENT = common.E_NOENT;
const E_FAULT = common.E_FAULT;
const E_BADF = common.E_BADF;
const E_NOMEM = common.E_NOMEM;
const E_AGAIN = common.E_AGAIN;
const E_BUSY = common.E_BUSY;
const E_NAMETOOLONG = common.E_NAMETOOLONG;
const E_PIPE = common.E_PIPE;
const E_SRCH = common.E_SRCH;
const E_NOSYS = common.E_NOSYS;
const E_PERM = common.E_PERM;
const E_CHILD = common.E_CHILD;
const E_INTR = common.E_INTR;

/// Snapshot of the active L3 configuration, copied out in one shot so
/// userspace doesn't need to syscall once per field. `dhcp_configured`
/// distinguishes a real DHCP lease from the static SLIRP fallback.
const NetInfo = extern struct {
    local_ip: [4]u8,
    gateway_ip: [4]u8,
    dns_ip: [4]u8,
    subnet_mask: [4]u8,
    mac: [6]u8,
    /// Padding so `dhcp_configured` lands on a natural alignment boundary
    /// — extern structs don't auto-pad and we want a stable wire layout.
    _pad: [2]u8 = .{ 0, 0 },
    dhcp_configured: u32,
    dhcp_lease_secs: u32,
    nic_present: u32,
};

pub fn sysNetInfo(buf_ptr: u32) u32 {
    if (!validateUserPtrWriteAligned(buf_ptr, @sizeOf(NetInfo), @alignOf(NetInfo))) return E_FAULT;
    const net = @import("../../net/net.zig");
    const nic = @import("../../driver/nic.zig");
    const info: *NetInfo = @ptrFromInt(@as(usize, buf_ptr));
    info.* = .{
        .local_ip = net.local_ip,
        .gateway_ip = net.gateway_ip,
        .dns_ip = net.dns_ip,
        .subnet_mask = net.subnet_mask,
        .mac = nic.getMac(),
        .dhcp_configured = if (net.dhcp_configured) 1 else 0,
        .dhcp_lease_secs = net.dhcp_lease_secs,
        .nic_present = if (nic.isReady()) 1 else 0,
    };
    return 0;
}

// --- Directory listing syscall ---

/// resolve(hostname) — kernel-side DNS lookup. host_ptr/host_len describe a
/// user-space hostname (max 255 bytes); ip_out_ptr is a 4-byte user buffer
/// the resolved IPv4 address gets copied into. Returns 0 on success and
/// 0xFFFFFFFF on any failure (network down, lookup timeout, bad input).
pub fn sysNetResolve(host_ptr: u32, host_len: u32, ip_out_ptr: u32) u32 {
    if (host_len == 0 or host_len > 255) return E_NAMETOOLONG;
    if (!validateUserPtr(host_ptr, host_len)) return E_FAULT;
    if (!validateUserPtrWrite(ip_out_ptr, 4)) return E_FAULT;

    var hbuf: [256]u8 = undefined;
    const src: [*]const u8 = @ptrFromInt(@as(usize, host_ptr));
    @memcpy(hbuf[0..host_len], src[0..host_len]);

    const net = @import("../../net/net.zig");
    const ip = net.resolve(hbuf[0..host_len]) orelse return E_INVAL;

    const dst: [*]u8 = @ptrFromInt(@as(usize, ip_out_ptr));
    @memcpy(dst[0..4], &ip);
    return 0;
}

/// http_get(url, response_buf) — synchronous HTTP/1.0 GET. Returns the full
/// response (status line + headers + body) into the user's response buffer
/// and returns the byte count, or 0xFFFFFFFF on failure. Internally caps
/// at 10s wall-clock via tick deadlines, so the caller will return either
/// with data or with a failure rather than blocking indefinitely.
///
/// The 4 logical parameters don't fit in 3 syscall arg slots, so the caller
/// packs `{u32 buf_ptr, u32 buf_len}` into a small struct passed as `req_ptr`.
pub fn sysNetHttpGet(url_ptr: u32, url_len: u32, req_ptr: u32) u32 {
    if (url_len == 0 or url_len > 1024) return E_NAMETOOLONG;
    if (!validateUserPtr(url_ptr, url_len)) return E_FAULT;

    const HttpReq = extern struct { buf_ptr: u32, buf_len: u32 };
    if (!validateUserPtrAligned(req_ptr, @sizeOf(HttpReq), @alignOf(HttpReq))) return E_FAULT;
    const req: *const HttpReq = @ptrFromInt(@as(usize, req_ptr));
    if (req.buf_len == 0 or req.buf_len > 1024 * 1024) return E_INVAL;
    if (!validateUserPtrWrite(req.buf_ptr, req.buf_len)) return E_FAULT;

    var url_buf: [1024]u8 = undefined;
    const url_src: [*]const u8 = @ptrFromInt(@as(usize, url_ptr));
    @memcpy(url_buf[0..url_len], url_src[0..url_len]);

    const buf: [*]u8 = @ptrFromInt(@as(usize, req.buf_ptr));
    const buf_slice = buf[0..req.buf_len];

    const net = @import("../../net/net.zig");
    const n = net.httpGet(url_buf[0..url_len], buf_slice) orelse return E_INVAL;
    return @intCast(n);
}

/// tcp_connect(ip[4], port) — perform the TCP three-way handshake to
/// `ip:port`. Blocks for up to 5s (kernel-side, with sleep yields). Returns
/// a per-process fd (.tcp_sock kind) on success, or 0xFFFFFFFF on failure.
/// close(fd) releases the connection.
pub fn sysNetTcpConnect(ip_ptr: u32, port: u32) u32 {
    if (port == 0 or port > 65535) return E_INVAL;
    if (!validateUserPtr(ip_ptr, 4)) return E_FAULT;

    var ip: [4]u8 = undefined;
    const src: [*]const u8 = @ptrFromInt(@as(usize, ip_ptr));
    @memcpy(ip[0..4], src[0..4]);

    const net = @import("../../net/net.zig");
    const slot = net.tcpConnect(ip, @intCast(port)) orelse return E_INVAL;
    const cur = smp.myCpu().current_pid orelse {
        net.tcpClose(slot);
        return E_INVAL;
    };
    const pcb = &process.procs[cur];
    return common.allocSocketFd(pcb, .tcp_sock, slot) orelse {
        net.tcpClose(slot);
        return E_NOMEM;
    };
}

/// tcp_send(fd, buf, len) — send `len` bytes synchronously over the TCP
/// connection. Splits into MSS-sized segments internally. Returns 0 on
/// success, errno on failure (EBADF if fd isn't a tcp_sock; EINVAL on
/// send failure / peer-closed mid-send).
pub fn sysNetTcpSend(fd: u32, buf_ptr: u32, buf_len: u32) u32 {
    if (buf_len == 0) return 0;
    if (buf_len > 64 * 1024) return E_INVAL;
    if (!validateUserPtr(buf_ptr, buf_len)) return E_FAULT;

    const cur = smp.myCpu().current_pid orelse return E_INVAL;
    const pcb = &process.procs[cur];
    const slot = common.resolveSocketFd(pcb, fd, .tcp_sock) orelse return E_BADF;

    const buf: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    const net = @import("../../net/net.zig");
    if (!net.tcpSend(slot, buf[0..buf_len])) return E_INVAL;
    return 0;
}

/// tcp_recv(fd, buf, len) — copy up to `len` bytes from the connection's
/// RX ring into the user's buffer. Non-blocking: returns 0 if no data is
/// ready yet (callers poll). Closed peer with empty RX returns 0 too —
/// distinguish by checking tcp_status's peer_closed bit.
pub fn sysNetTcpRecv(fd: u32, buf_ptr: u32, buf_len: u32) u32 {
    if (buf_len == 0) return 0;
    if (buf_len > 64 * 1024) return 0;
    if (!validateUserPtrWrite(buf_ptr, buf_len)) return 0;

    const cur = smp.myCpu().current_pid orelse return 0;
    const pcb = &process.procs[cur];
    const slot = common.resolveSocketFd(pcb, fd, .tcp_sock) orelse return 0;

    const buf: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    const net = @import("../../net/net.zig");
    net.poll();
    return @intCast(net.tcpRecv(slot, buf[0..buf_len]));
}

/// tcp_status(fd) — non-blocking status check. Returns a bitmask:
///   bit 0 (1)  : connection is established and active
///   bit 1 (2)  : peer has sent FIN (we may still have data to drain)
///
/// poll() runs first so the FIN bit reflects the freshest state.
pub fn sysNetTcpStatus(fd: u32) u32 {
    const cur = smp.myCpu().current_pid orelse return 0;
    const pcb = &process.procs[cur];
    const slot = common.resolveSocketFd(pcb, fd, .tcp_sock) orelse return 0;
    const net = @import("../../net/net.zig");
    net.poll();
    var status: u32 = 0;
    if (net.tcpIsConnected(slot)) status |= 1;
    if (net.tcpPeerClosed(slot)) status |= 2;
    return status;
}

/// tcp_listen(port) — bind a server-side TCP socket to `port`. Returns a
/// per-process fd (.tcp_listener kind) on success, or 0xFFFFFFFF on
/// failure (port already bound, slot pool full, port == 0). close(fd)
/// releases the listener; already-accepted conns keep working.
pub fn sysNetTcpListen(port: u32) u32 {
    if (port == 0 or port > 65535) return E_INVAL;
    const net = @import("../../net/net.zig");
    const slot = net.tcpListen(@intCast(port)) orelse return E_INVAL;
    const cur = smp.myCpu().current_pid orelse {
        net.tcpUnlisten(slot);
        return E_INVAL;
    };
    const pcb = &process.procs[cur];
    return common.allocSocketFd(pcb, .tcp_listener, slot) orelse {
        net.tcpUnlisten(slot);
        return E_NOMEM;
    };
}

/// tcp_accept(listener_fd) — pop one ESTABLISHED conn from the listener's
/// accept queue. Returns a fresh per-process fd (.tcp_sock kind) for the
/// accepted conn, or 0xFFFFFFFF if nothing is queued yet. poll() runs
/// first to land any pending handshakes.
pub fn sysNetTcpAccept(listener_fd: u32) u32 {
    const cur = smp.myCpu().current_pid orelse return E_INVAL;
    const pcb = &process.procs[cur];
    const lst_slot = common.resolveSocketFd(pcb, listener_fd, .tcp_listener) orelse return E_BADF;
    const net = @import("../../net/net.zig");
    net.poll();
    const conn_slot = net.tcpAccept(lst_slot) orelse return E_INVAL;
    return common.allocSocketFd(pcb, .tcp_sock, conn_slot) orelse {
        net.tcpClose(conn_slot);
        return E_NOMEM;
    };
}

const tls_conn = @import("../../crypto/tls/conn.zig");

/// On-wire layout of the tls_connect args struct (kernel & userspace
/// agree). Packed into a single user pointer because syscalls have a
/// 3-arg limit and we need ip + port + variable-length SNI.
const TlsConnectArgs = extern struct {
    ip: [4]u8,
    port: u16,
    _pad: u16,
    sni_ptr: u32,
    sni_len: u32,
};

/// tls_connect(args_ptr) — open a TLS 1.3 connection. Performs the
/// TCP handshake, full TLS 1.3 handshake (X25519/ChaCha20-Poly1305),
/// certificate validation against Mozilla NSS, and CertificateVerify
/// check. Returns the kernel-side TLS slot id on success, or
/// 0xFFFFFFFF on any failure. Blocks for the duration of the
/// handshake (typically <2s on local network, longer on real
/// internet).
pub fn sysTlsConnect(args_ptr: u32) u32 {
    if (!validateUserPtrAligned(args_ptr, @sizeOf(TlsConnectArgs), @alignOf(TlsConnectArgs))) return E_FAULT;
    var args: TlsConnectArgs = undefined;
    const args_src: [*]const u8 = @ptrFromInt(@as(usize, args_ptr));
    @memcpy(@as([*]u8, @ptrCast(&args))[0..@sizeOf(TlsConnectArgs)], args_src[0..@sizeOf(TlsConnectArgs)]);

    if (args.port == 0 or args.sni_len > 255) return E_INVAL;
    if (!validateUserPtr(args.sni_ptr, args.sni_len)) return E_FAULT;

    var sni_buf: [256]u8 = undefined;
    const sni_src: [*]const u8 = @ptrFromInt(@as(usize, args.sni_ptr));
    @memcpy(sni_buf[0..args.sni_len], sni_src[0..args.sni_len]);

    const slot = tls_conn.tlsConnect(args.ip, args.port, sni_buf[0..args.sni_len]) orelse return E_INVAL;
    return @as(u32, slot);
}

/// tls_send(slot, buf, len) — encrypt `len` bytes as one TLS 1.3
/// application_data record and send it. Returns bytes sent (= len on
/// success), or 0xFFFFFFFF on failure.
pub fn sysTlsSend(slot: u32, buf_ptr: u32, buf_len: u32) u32 {
    if (slot > 255) return E_INVAL;
    if (buf_len == 0) return 0;
    if (buf_len > 16 * 1024) return E_INVAL;
    if (!validateUserPtr(buf_ptr, buf_len)) return E_FAULT;
    const buf: [*]const u8 = @ptrFromInt(@as(usize, buf_ptr));
    const sent = tls_conn.tlsSend(@intCast(slot), buf[0..buf_len]);
    if (sent < 0) return E_INVAL;
    return @intCast(sent);
}

/// tls_recv(slot, buf, len) — drain up to `len` bytes of plaintext
/// from the conn. Blocks until at least one record arrives or the
/// peer closes. Returns bytes read (>0), 0 on graceful close, or
/// 0xFFFFFFFF on error. Use tls_status (TODO) to disambiguate.
pub fn sysTlsRecv(slot: u32, buf_ptr: u32, buf_len: u32) u32 {
    if (slot > 255) return E_INVAL;
    if (buf_len == 0) return 0;
    if (!validateUserPtrWrite(buf_ptr, buf_len)) return E_FAULT;
    const buf: [*]u8 = @ptrFromInt(@as(usize, buf_ptr));
    const got = tls_conn.tlsRecv(@intCast(slot), buf[0..buf_len]);
    if (got < 0) return E_INVAL;
    return @intCast(got);
}

/// tls_close(slot) — send TLS close_notify alert, tear down TCP,
/// release the slot. Idempotent.
pub fn sysTlsClose(slot: u32) u32 {
    if (slot > 255) return 0;
    tls_conn.tlsClose(@intCast(slot));
    return 0;
}
