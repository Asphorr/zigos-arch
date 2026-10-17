//! virtio-console as the kernel log's way out. The klog drain hands it whole
//! chunks, a doorbell each; the UART costs a VM exit per byte (~30 µs under
//! nested virtualization), and QEMU emulates every one of those under the
//! same lock as the disk's doorbells.
//!
//! Port 0 only (MULTIPORT is not negotiated), transmit queue only, polled:
//! the device hands buffers back through the used ring, and nothing here
//! waits for an interrupt. QEMU's virtio-serial writes a buffer out during
//! the doorbell's exit, so they come back at once.
//!
//! QEMU: `-device virtio-serial-pci -device virtconsole,chardev=X`; sharing
//! the UART's log file takes a mux chardev (`-chardev file,...,mux=on` with
//! `-serial chardev:X`).

const std = @import("std");
const pci = @import("pci.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const iommu = @import("../cpu/mmu/iommu.zig");
const virtio = @import("virtio.zig");
const debug = @import("../debug/debug.zig");
const Deadline = @import("../util/deadline.zig").Deadline;

const VIRTIO_VENDOR: u16 = 0x1AF4;
/// virtio device type 3: 0x1040 + 3 modern, 0x1003 transitional.
const DEVICE_IDS = [_]u16{ 0x1043, 0x1003 };
/// transmitq of port 0.
const TX_QUEUE: u16 = 1;
/// Buffers in flight at most; each is one frame.
const SLOTS: u16 = 16;
pub const SLOT_BYTES: u32 = 4096;
/// VIRTIO_F_VERSION_1, bit 32: bit 0 of feature word 1.
const F_VERSION_1_HI: u32 = 1;
/// How long write() waits for the device to free a buffer before giving
/// the chunk back to the caller.
const FULL_WAIT_MS: u32 = 5;

var ready: bool = false;
var vq: virtio.Queue = .{};
var common_base: usize = 0;
var notify_base: usize = 0;
var notify_mult: u32 = 0;
var slot_phys: [SLOTS]usize = undefined;
/// Slots the device has given back (slot i is descriptor i), a stack.
var free_slots: [SLOTS]u16 = undefined;
var n_free: u16 = 0;
var avail_idx: u16 = 0;

/// True once the console takes writes.
pub fn isReady() bool {
    return @atomicLoad(bool, &ready, .acquire);
}

/// Probe and start the console. Boot, single-threaded; false when there is
/// no such device or it would not start (the UART stays the log's path).
pub fn init() bool {
    const dev = for (DEVICE_IDS) |id| {
        if (pci.findByVendorDevice(VIRTIO_VENDOR, id)) |d| break d;
    } else return false;
    var bind = pci.bindDevice(dev);
    defer bind.deinit();
    _ = iommu.enableIsolation(dev.bus, dev.dev, dev.func);

    const common_cap = pci.findVirtioCap(dev, virtio.CAP_COMMON_CFG) orelse return fail("no common config cap");
    const notify_cap = pci.findVirtioCap(dev, virtio.CAP_NOTIFY_CFG) orelse return fail("no notify cap");
    const common_bar = pci.mapBar(dev, common_cap.bar, 0x4000) orelse return fail("common BAR unmapped");
    const notify_bar = pci.mapBar(dev, notify_cap.bar, 0x4000) orelse return fail("notify BAR unmapped");
    common_base = common_bar + common_cap.offset;
    notify_base = notify_bar + notify_cap.offset;
    notify_mult = notify_cap.notify_off_mult;

    // Reset, then ACKNOWLEDGE + DRIVER (virtio 1.1 §3.1.1).
    virtio.ccWrite8(common_base, virtio.CC_DEVICE_STATUS, 0);
    var d = Deadline.ms(100, "virtio-console reset");
    while (virtio.ccRead8(common_base, virtio.CC_DEVICE_STATUS) != 0 and d.live()) std.atomic.spinLoopHint();
    virtio.ccWrite8(common_base, virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE);
    virtio.ccWrite8(common_base, virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER);

    // Features: VERSION_1 when offered, nothing else (no MULTIPORT, no SIZE).
    virtio.ccWrite32(common_base, virtio.CC_DEVICE_FEATURE_SELECT, 1);
    const offered_hi = virtio.ccRead32(common_base, virtio.CC_DEVICE_FEATURE);
    virtio.ccWrite32(common_base, virtio.CC_DRIVER_FEATURE_SELECT, 0);
    virtio.ccWrite32(common_base, virtio.CC_DRIVER_FEATURE, 0);
    virtio.ccWrite32(common_base, virtio.CC_DRIVER_FEATURE_SELECT, 1);
    virtio.ccWrite32(common_base, virtio.CC_DRIVER_FEATURE, offered_hi & F_VERSION_1_HI);
    const features_ok = virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER | virtio.STATUS_FEATURES_OK;
    virtio.ccWrite8(common_base, virtio.CC_DEVICE_STATUS, features_ok);
    if (virtio.ccRead8(common_base, virtio.CC_DEVICE_STATUS) & virtio.STATUS_FEATURES_OK == 0) return fail("FEATURES_OK refused");

    if (!vq.init(common_base, TX_QUEUE, SLOTS)) return fail("transmitq setup failed");
    if (vq.queue_size != SLOTS) return fail("transmitq shorter than the slots");
    _ = iommu.dmaMap(dev.bus, dev.dev, dev.func, vq.desc_phys, 4096, .{});
    _ = iommu.dmaMap(dev.bus, dev.dev, dev.func, vq.used_phys, 4096, .{});
    var i: u16 = 0;
    while (i < SLOTS) : (i += 1) {
        const f = pmm.allocFrame() orelse return fail("no frame for a buffer");
        slot_phys[i] = f.raw();
        _ = iommu.dmaMap(dev.bus, dev.dev, dev.func, f.raw(), SLOT_BYTES, .{});
        const desc = vq.descPtr(i);
        desc.addr = f.raw();
        desc.len = 0;
        desc.flags = 0; // device-readable, no chain
        desc.next = 0;
        free_slots[i] = i;
    }
    n_free = SLOTS;

    virtio.ccWrite8(common_base, virtio.CC_DEVICE_STATUS, features_ok | virtio.STATUS_DRIVER_OK);
    bind.commit();
    @atomicStore(bool, &ready, true, .release);
    debug.klog("[virtio-console] log output on {d}:{d}.{d}\n", .{ dev.bus, dev.dev, dev.func });
    return true;
}

fn fail(why: []const u8) bool {
    debug.klog("[virtio-console] not used: {s}\n", .{why});
    return false;
}

/// Take back the buffers the device is done with, in whatever order it
/// returned them.
fn reclaim() void {
    const used = @atomicLoad(u16, @as(*const u16, @volatileCast(vq.usedIdx())), .acquire);
    while (vq.last_used_idx != used) : (vq.last_used_idx +%= 1) {
        const id = vq.usedRingId(vq.last_used_idx % SLOTS).*;
        if (id < SLOTS and n_free < SLOTS) {
            free_slots[n_free] = @intCast(id);
            n_free += 1;
        }
    }
}

/// Send `bytes` (at most SLOT_BYTES). One caller at a time: the klog
/// drainer. False when the console isn't up or stays full for
/// FULL_WAIT_MS; the caller then has the bytes to put elsewhere.
pub fn write(bytes: []const u8) bool {
    if (!isReady() or bytes.len == 0 or bytes.len > SLOT_BYTES) return false;
    reclaim();
    if (n_free == 0) {
        var d = Deadline.ms(FULL_WAIT_MS, "virtio-console full");
        while (n_free == 0 and d.live()) {
            std.atomic.spinLoopHint();
            reclaim();
        }
        if (n_free == 0) return false;
    }
    n_free -= 1;
    const s = free_slots[n_free];
    const dst: [*]u8 = @ptrFromInt(paging.physToVirt(slot_phys[s]));
    @memcpy(dst[0..bytes.len], bytes);
    vq.descPtr(s).len = @intCast(bytes.len);
    vq.availRing(avail_idx % SLOTS).* = s;
    avail_idx +%= 1;
    // The ring entry and the buffer before the index the device reads.
    @atomicStore(u16, @as(*u16, @volatileCast(vq.availIdx())), avail_idx, .release);
    virtio.notifyQueue(notify_base, vq.notify_off, notify_mult, TX_QUEUE);
    return true;
}
