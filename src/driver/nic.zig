// nic — single dispatch point for the TCP/IP stack to talk to whatever
// network card the kernel found. Probe order:
//   1. virtio-net  — preferred when present (QEMU's default, fastest path)
//   2. I225 / I226 — modern Intel 2.5 GbE on most 2020+ motherboards
//   3. e1000       — legacy Intel 8254x (QEMU `-device e1000`, old hardware)
// First driver whose init() returns true wins. Backends added here just
// need init/isReady/send/recv/rxRelease/getMac.

const virtio_net = @import("virtio_net.zig");
const igc = @import("i225.zig");
const e1000 = @import("e1000.zig");
const debug = @import("../debug/debug.zig");

const Backend = enum { none, virtio, igc, e1000 };
var backend: Backend = .none;

pub fn init() bool {
    if (virtio_net.init()) {
        backend = .virtio;
        debug.klog("[nic] using virtio-net\n", .{});
        return true;
    }
    if (igc.init()) {
        backend = .igc;
        debug.klog("[nic] using Intel I225/I226\n", .{});
        return true;
    }
    if (e1000.init()) {
        backend = .e1000;
        debug.klog("[nic] using e1000\n", .{});
        return true;
    }
    debug.klog("[nic] no NIC found — networking disabled\n", .{});
    return false;
}

pub fn isReady() bool {
    return switch (backend) {
        .none => false,
        .virtio => virtio_net.isReady(),
        .igc => igc.isReady(),
        .e1000 => e1000.isReady(),
    };
}

pub fn getMac() [6]u8 {
    return switch (backend) {
        .none => [_]u8{ 0, 0, 0, 0, 0, 0 },
        .virtio => virtio_net.getMac(),
        .igc => igc.getMac(),
        .e1000 => e1000.getMac(),
    };
}

pub fn send(data: []const u8) bool {
    return switch (backend) {
        .none => false,
        .virtio => virtio_net.send(data),
        .igc => igc.send(data),
        .e1000 => e1000.send(data),
    };
}

pub fn recv() ?[]volatile u8 {
    return switch (backend) {
        .none => null,
        .virtio => virtio_net.recv(),
        .igc => igc.recv(),
        .e1000 => e1000.recv(),
    };
}

pub fn rxRelease() void {
    switch (backend) {
        .none => {},
        .virtio => virtio_net.rxRelease(),
        .igc => igc.rxRelease(),
        .e1000 => e1000.rxRelease(),
    }
}
