// Test stub for cpu/ipc/fdpoll.zig. net.zig calls wakePollers(kind, id) inline
// to wake any task blocked in poll()/epoll on a socket fd. There are no tasks in
// the harness, so this is a no-op — it only needs the right shape to compile.
pub const WakeKind = enum { tcp_sock, tcp_listener };

pub fn wakePollers(kind: WakeKind, id: u16) void {
    _ = kind;
    _ = id;
}
