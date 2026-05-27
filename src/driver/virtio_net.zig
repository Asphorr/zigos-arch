// virtio-net — modern (virtio 1.0+) PCI transport.
//
// Probes a virtio-net PCI device, parses its modern PCI capabilities to
// find common-config / notify / device-config MMIO regions, sets up RX
// (queue 0) + TX (queue 1) virtqueues via the shared virtio.Queue
// infrastructure, and runs RX in IRQ-driven mode via MSI-X. Same shape
// as virtio_gpu and virtio_sound — all three share virtio.zig.
//
// What we negotiate: VIRTIO_NET_F_MAC, VIRTIO_NET_F_STATUS, VIRTIO_F_VERSION_1.
// What we explicitly DON'T negotiate: VIRTIO_NET_F_MRG_RXBUF — would change
// the per-packet header from 10 bytes to 12, complicating both RX and TX
// for no benefit at our packet rates.
//
// Probe order: 0x1041 (modern non-transitional) first, 0x1000 (transitional)
// second. Both expose the modern PCI caps so the same code path drives both;
// the transitional path adds a subsystem-id sanity check (legacy devices
// share device-id 0x1000 with all virtio types — only subsystem distinguishes).
// A purely-legacy-only device (no modern caps) is no longer supported — every
// real-world virtio-net (QEMU, KVM, Hyper-V) has been transitional since 2014.

const pci = @import("pci.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const msix = @import("../time/msix.zig");
const debug = @import("../debug/debug.zig");
const net = @import("../net/net.zig");
const virtio = @import("virtio.zig");
const iommu = @import("../cpu/mmu/iommu.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

const VirtqDesc = virtio.VirtqDesc;
const Virtqueue = virtio.Queue;

// PCI IDs
const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_NET_DEVICE_MODERN: u16 = 0x1041; // 0x1040 + virtio_device_id 1
const VIRTIO_NET_DEVICE_LEGACY: u16 = 0x1000; // transitional

// Feature bits (per virtio §5.1.3 / §6).
const VIRTIO_NET_F_MAC: u6 = 5;
const VIRTIO_NET_F_STATUS: u6 = 16;
const VIRTIO_NET_F_MRG_RXBUF: u6 = 15;
// VIRTIO_F_VERSION_1 lives at bit 32 — i.e. bit 0 of feature word 1.

// Packet header in front of every TX/RX buffer (10 bytes when MRG_RXBUF=0).
const VIRTIO_NET_HDR_SIZE: u32 = 10;
const MTU: u32 = 1514;
const BUF_SIZE: u32 = VIRTIO_NET_HDR_SIZE + MTU;
const MAX_QUEUE_SIZE: u16 = 64;
const NUM_RX_BUFS: u16 = 32;

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;

// Per-queue locks. TCP/UDP send and recv often run on different CPUs (sender
// via syscall, receiver via IRQ on BSP); two locks let them advance
// concurrently while still serialising each ring's "fill descriptor + bump
// availIdx + ring doorbell" sequence.
var tx_lock: SpinLock = .{};
var rx_lock: SpinLock = .{};
// PCI BDF captured at init so per-send TX-buf dmaMap calls don't need to
// re-walk the PCI cache. Zero before init.
var pci_bus: u8 = 0;
var pci_dev: u8 = 0;
var pci_func: u8 = 0;

// MMIO bases (modern transport).
var common_cfg: usize = 0;
var notify_base: usize = 0;
var notify_off_multiplier: u32 = 0;
var device_cfg: usize = 0;

pub var mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
var initialized: bool = false;
var rx_vq: Virtqueue = .{};
var tx_vq: Virtqueue = .{};
var rx_bufs: [MAX_QUEUE_SIZE]usize = .{0} ** MAX_QUEUE_SIZE;
var tx_bufs: [MAX_QUEUE_SIZE]usize = .{0} ** MAX_QUEUE_SIZE;

// Last received descriptor for release (polled-mode single-slot stash).
var rx_last_desc: u16 = 0;

pub var irq_count: u64 = 0;

/// True once an MSI-X vector is bound. recv()/rxRelease() become no-ops in
/// this mode — the IRQ handler exclusively owns the RX ring and drains+
/// refills inline. Mirrors e1000.zig.
var irq_driven: bool = false;

// --- MMIO helpers (use module-global common_cfg) ---

fn ccRead8(off: u32) u8 {
    return @as(*volatile u8, @ptrFromInt(common_cfg + off)).*;
}
fn ccWrite8(off: u32, v: u8) void {
    @as(*volatile u8, @ptrFromInt(common_cfg + off)).* = v;
}
fn ccRead16(off: u32) u16 {
    return @as(*volatile u16, @ptrFromInt(common_cfg + off)).*;
}
fn ccWrite16(off: u32, v: u16) void {
    @as(*volatile u16, @ptrFromInt(common_cfg + off)).* = v;
}
fn ccRead32(off: u32) u32 {
    return @as(*volatile u32, @ptrFromInt(common_cfg + off)).*;
}
fn ccWrite32(off: u32, v: u32) void {
    @as(*volatile u32, @ptrFromInt(common_cfg + off)).* = v;
}

fn devRead8(off: u32) u8 {
    return @as(*volatile u8, @ptrFromInt(device_cfg + off)).*;
}

fn notifyVq(qi: u16, vq: *const Virtqueue) void {
    virtio.notifyQueue(notify_base, vq.notify_off, notify_off_multiplier, qi);
}

/// MSI-X handler for the RX virtqueue. Drain everything pending, hand each
/// frame to net.handleRxFrame, refill the descriptor, ring the doorbell once
/// at the end. Runs with IRQs disabled (interrupt gate); same-CPU syscall
/// paths use IrqSave on rx_lock/tx_lock so they can't be holding either when
/// we fire. MSI-X mode auto-acks at the LAPIC; legacy ISR_STATUS is unneeded.
fn virtioNetIrqHandler() callconv(.c) void {
    irq_count +%= 1;

    var produced: bool = false;
    while (true) {
        if (rx_vq.last_used_idx == rx_vq.usedIdx().*) break;
        const ui = rx_vq.last_used_idx % rx_vq.queue_size;
        const desc_id: u16 = @intCast(rx_vq.usedRingId(ui).*);
        const total_len = rx_vq.usedRingLen(ui).*;

        if (total_len > VIRTIO_NET_HDR_SIZE) {
            const buf: [*]volatile u8 = @ptrFromInt(paging.physToVirt(rx_bufs[desc_id]));
            const data_len = total_len - VIRTIO_NET_HDR_SIZE;
            net.handleRxFrame(buf[VIRTIO_NET_HDR_SIZE .. VIRTIO_NET_HDR_SIZE + data_len]);
        }

        // Refill: descriptor goes straight back to the device.
        const d = rx_vq.descPtr(desc_id);
        d.addr = rx_bufs[desc_id];
        d.len = BUF_SIZE;
        d.flags = virtio.VRING_DESC_F_WRITE;
        d.next = 0;
        const ai = rx_vq.availIdx().*;
        rx_vq.availRing(ai % rx_vq.queue_size).* = desc_id;
        asm volatile ("" ::: .{ .memory = true });
        rx_vq.availIdx().* = ai +% 1;
        rx_vq.last_used_idx +%= 1;
        produced = true;
    }
    if (produced) notifyVq(RX_QUEUE, &rx_vq);
}

pub fn init() bool {
    // Probe modern first, fall back to transitional. Both use the same
    // modern-cap code path below; transitional gets an extra subsys check.
    var dev = pci.findByVendorDevice(VIRTIO_VENDOR, VIRTIO_NET_DEVICE_MODERN);
    if (dev == null) dev = pci.findByVendorDevice(VIRTIO_VENDOR, VIRTIO_NET_DEVICE_LEGACY);
    const dev_found = dev orelse {
        debug.klog("[virtio-net] No device found\n", .{});
        return false;
    };

    // Transitional devices share device-id 0x1000 across all virtio types;
    // subsystem-id distinguishes. Modern (0x1041) doesn't need this since
    // the device-id itself encodes the type.
    if (dev_found.device_id == VIRTIO_NET_DEVICE_LEGACY) {
        const ss = pci.subsystemIds(dev_found);
        if (ss.sid != 1) {
            debug.klog("[virtio-net] Transitional subsystem {d} != 1, not net\n", .{ss.sid});
            return false;
        }
    }

    var bind = pci.bindDevice(dev_found);
    defer bind.deinit();
    pci_bus = dev_found.bus;
    pci_dev = dev_found.dev;
    pci_func = dev_found.func;

    // IOMMU Phase 3: flip onto own SL page table before any virtqueue
    // is set up. Every buffer hardware touches must be explicitly
    // dmaMap'd below. No-op when IOMMU isn't running.
    _ = iommu.enableIsolation(pci_bus, pci_dev, pci_func);

    // Find modern PCI caps.
    const common_cap = pci.findVirtioCap(dev_found, virtio.CAP_COMMON_CFG) orelse {
        debug.klog("[virtio-net] No modern common-config cap (legacy-only device unsupported)\n", .{});
        return false;
    };
    const notify_cap = pci.findVirtioCap(dev_found, virtio.CAP_NOTIFY_CFG) orelse {
        debug.klog("[virtio-net] No notify cap\n", .{});
        return false;
    };
    const device_cap = pci.findVirtioCap(dev_found, virtio.CAP_DEVICE_CFG) orelse {
        debug.klog("[virtio-net] No device-config cap\n", .{});
        return false;
    };

    debug.klog("[virtio-net] Found at {d}:{d} (id=0x{X:0>4}), modern caps OK\n", .{
        dev_found.bus, dev_found.dev, dev_found.device_id,
    });

    // Map the BARs the caps point into. notify and device caps may share
    // the common BAR; check + reuse to avoid duplicate physToVirt.
    const common_bar = pci.mapBar(dev_found, common_cap.bar, 0x4000) orelse {
        debug.klog("[virtio-net] map common BAR failed\n", .{});
        return false;
    };
    common_cfg = common_bar + common_cap.offset;

    if (notify_cap.bar == common_cap.bar) {
        notify_base = common_bar + notify_cap.offset;
    } else {
        const nb = pci.mapBar(dev_found, notify_cap.bar, 0x4000) orelse {
            debug.klog("[virtio-net] map notify BAR failed\n", .{});
            return false;
        };
        notify_base = nb + notify_cap.offset;
    }
    notify_off_multiplier = notify_cap.notify_off_mult;

    if (device_cap.bar == common_cap.bar) {
        device_cfg = common_bar + device_cap.offset;
    } else if (device_cap.bar == notify_cap.bar) {
        // Notify BAR was just mapped above; reuse its physToVirt.
        device_cfg = (notify_base - notify_cap.offset) + device_cap.offset;
    } else {
        const db = pci.mapBar(dev_found, device_cap.bar, 0x4000) orelse {
            debug.klog("[virtio-net] map device BAR failed\n", .{});
            return false;
        };
        device_cfg = db + device_cap.offset;
    }

    // Reset → ACK → DRIVER (per virtio §3.1.1).
    ccWrite8(virtio.CC_DEVICE_STATUS, 0);
    var spin: u32 = 0;
    while (ccRead8(virtio.CC_DEVICE_STATUS) != 0 and spin < 1000) : (spin += 1) {
        asm volatile ("pause");
    }
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE);
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER);

    // Read device features (both 32-bit halves).
    ccWrite32(virtio.CC_DEVICE_FEATURE_SELECT, 0);
    const dev_features_0 = ccRead32(virtio.CC_DEVICE_FEATURE);
    ccWrite32(virtio.CC_DEVICE_FEATURE_SELECT, 1);
    const dev_features_1 = ccRead32(virtio.CC_DEVICE_FEATURE);
    debug.klog("[virtio-net] Device features: 0x{X:0>8} 0x{X:0>8}\n", .{ dev_features_0, dev_features_1 });

    // Negotiate: MAC, STATUS, VERSION_1. Reject MRG_RXBUF.
    var driver_features_0: u32 = 0;
    if (dev_features_0 & (@as(u32, 1) << VIRTIO_NET_F_MAC) != 0) {
        driver_features_0 |= @as(u32, 1) << VIRTIO_NET_F_MAC;
    }
    if (dev_features_0 & (@as(u32, 1) << VIRTIO_NET_F_STATUS) != 0) {
        driver_features_0 |= @as(u32, 1) << VIRTIO_NET_F_STATUS;
    }

    var driver_features_1: u32 = 0;
    // VIRTIO_F_VERSION_1 = bit 32 = bit 0 of word 1. Mandatory for modern.
    if (dev_features_1 & 1 != 0) driver_features_1 |= 1;

    ccWrite32(virtio.CC_DRIVER_FEATURE_SELECT, 0);
    ccWrite32(virtio.CC_DRIVER_FEATURE, driver_features_0);
    ccWrite32(virtio.CC_DRIVER_FEATURE_SELECT, 1);
    ccWrite32(virtio.CC_DRIVER_FEATURE, driver_features_1);
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER | virtio.STATUS_FEATURES_OK);

    if ((ccRead8(virtio.CC_DEVICE_STATUS) & virtio.STATUS_FEATURES_OK) == 0) {
        debug.klog("[virtio-net] FEATURES_OK rejected\n", .{});
        return false;
    }

    // Disable global config-change MSI-X vector (we only care about per-queue).
    ccWrite16(virtio.CC_MSIX_CONFIG, 0xFFFF);

    // Set up RX (queue 0) and TX (queue 1).
    if (!rx_vq.init(common_cfg, RX_QUEUE, MAX_QUEUE_SIZE)) {
        debug.klog("[virtio-net] RX queue init failed\n", .{});
        ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_FAILED);
        return false;
    }
    if (!tx_vq.init(common_cfg, TX_QUEUE, MAX_QUEUE_SIZE)) {
        debug.klog("[virtio-net] TX queue init failed\n", .{});
        ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_FAILED);
        return false;
    }

    // Map the per-virtqueue ring pages — desc/avail share one frame
    // (desc_phys), used ring lives on its own frame (used_phys). The
    // device DMA-reads/writes both during normal queue operation.
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, rx_vq.desc_phys, 4096, .{});
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, rx_vq.used_phys, 4096, .{});
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, tx_vq.desc_phys, 4096, .{});
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, tx_vq.used_phys, 4096, .{});

    // DRIVER_OK — device may now begin queue activity.
    ccWrite8(virtio.CC_DEVICE_STATUS, virtio.STATUS_ACKNOWLEDGE | virtio.STATUS_DRIVER | virtio.STATUS_FEATURES_OK | virtio.STATUS_DRIVER_OK);

    // MAC lives at device_cfg+0..+5 (per virtio §5.1.4 net_config layout).
    if (driver_features_0 & (@as(u32, 1) << VIRTIO_NET_F_MAC) != 0) {
        for (0..6) |i| mac[i] = devRead8(@intCast(i));
    }
    debug.klog("[virtio-net] MAC: {X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}\n", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    });

    // Pre-populate RX queue with buffers. rx_vq.init left every descriptor
    // chained on the free-list; we now move NUM_RX_BUFS of them into the
    // avail ring as device-writable buffers, leaving the remainder free.
    var rx_count: u16 = 0;
    while (rx_count < NUM_RX_BUFS and rx_count < rx_vq.queue_size) : (rx_count += 1) {
        const buf_phys = pmm.allocFrame() orelse break;
        rx_bufs[rx_count] = buf_phys;
        // Map the RX buf into the device's IOVA space so it can DMA the
        // received packet into it. Device-writable only would suffice
        // but we default to RW for simplicity (no harm — the buffer is
        // ours).
        _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, buf_phys, 4096, .{});
        const d = rx_vq.descPtr(rx_count);
        d.addr = buf_phys;
        d.len = BUF_SIZE;
        d.flags = virtio.VRING_DESC_F_WRITE;
        d.next = 0;
        rx_vq.availRing(rx_count).* = rx_count;
    }
    rx_vq.availIdx().* = rx_count;
    rx_vq.num_free = rx_vq.queue_size - rx_count;
    rx_vq.free_head = rx_count;
    notifyVq(RX_QUEUE, &rx_vq);

    // Try MSI-X for IRQ-driven RX. Bind queue 0 → MSI-X table entry 0.
    // Read-back of the queue MSI-X vector confirms the device accepted
    // (NO_VECTOR / 0xFFFF means the device couldn't bind it).
    if (msix.armOne(dev_found, 0, virtioNetIrqHandler)) |armed| {
        ccWrite16(virtio.CC_QUEUE_SELECT, RX_QUEUE);
        ccWrite16(virtio.CC_QUEUE_MSIX_VECTOR, 0);
        const rb = ccRead16(virtio.CC_QUEUE_MSIX_VECTOR);
        if (rb == 0) {
            irq_driven = true;
            debug.klog("[virtio-net] MSI-X armed: IDT vec=0x{x}\n", .{armed.vector.irq_vector});
        } else {
            debug.klog("[virtio-net] MSI-X bind rejected (rb=0x{x}), polled\n", .{rb});
        }
    }

    initialized = true;
    debug.klog("[virtio-net] Ready ({d} RX buffers)\n", .{rx_count});
    bind.commit();
    return true;
}

pub fn isReady() bool {
    return initialized;
}

/// Send a raw ethernet frame (without virtio header — we prepend it).
pub fn send(data: []const u8) bool {
    if (!initialized or data.len > MTU) return false;

    // IrqSave: the IRQ handler may also call into send (ARP reply, TCP ACK
    // synthesised from net.handleRxFrame). Without disabling IF here, the
    // same-CPU IRQ would deadlock on tx_lock. Mirrors e1000.send().
    const flags = tx_lock.acquireIrqSave();
    defer tx_lock.releaseIrqRestore(flags);

    reclaimTx();
    if (tx_vq.num_free == 0) return false;

    const di = tx_vq.free_head;
    const d = tx_vq.descPtr(di);
    tx_vq.free_head = @intCast(d.next);
    tx_vq.num_free -= 1;

    if (tx_bufs[di] == 0) {
        tx_bufs[di] = pmm.allocFrame() orelse {
            d.next = tx_vq.free_head;
            tx_vq.free_head = di;
            tx_vq.num_free += 1;
            return false;
        };
        // Map the freshly-allocated TX buf into the device's IOVA space
        // before the device sees its address. tx_bufs[di] persists for
        // the lifetime of the descriptor slot, so we map once and reuse.
        _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, tx_bufs[di], 4096, .{});
    }

    // virtio-net header (10 bytes, all zeros = no offload) + packet data.
    const buf: [*]u8 = @ptrFromInt(paging.physToVirt(tx_bufs[di]));
    @memset(buf[0..VIRTIO_NET_HDR_SIZE], 0);
    @memcpy(buf[VIRTIO_NET_HDR_SIZE..][0..data.len], data);

    d.addr = tx_bufs[di];
    d.len = @intCast(VIRTIO_NET_HDR_SIZE + data.len);
    d.flags = 0;
    d.next = 0;

    const ai = tx_vq.availIdx().*;
    tx_vq.availRing(ai % tx_vq.queue_size).* = di;
    asm volatile ("" ::: .{ .memory = true });
    tx_vq.availIdx().* = ai +% 1;
    notifyVq(TX_QUEUE, &tx_vq);
    return true;
}

fn reclaimTx() void {
    while (tx_vq.last_used_idx != tx_vq.usedIdx().*) {
        const ui = tx_vq.last_used_idx % tx_vq.queue_size;
        const desc_id: u16 = @intCast(tx_vq.usedRingId(ui).*);
        const d = tx_vq.descPtr(desc_id);
        d.next = tx_vq.free_head;
        tx_vq.free_head = desc_id;
        tx_vq.num_free += 1;
        tx_vq.last_used_idx +%= 1;
    }
}

/// Poll for a received packet. Returns ethernet frame data (after virtio hdr) or null.
/// NOTE: caller MUST call rxRelease() before calling recv() again on the
/// same flow — `rx_last_desc` is single-slot.
pub fn recv() ?[]volatile u8 {
    if (!initialized) return null;
    // IRQ-driven mode: handler exclusively owns the RX ring. net.poll()
    // still calls in here from syscall context but should always see
    // "nothing pending" — return null and let the polling loop exit.
    if (irq_driven) return null;
    const flags = rx_lock.acquireIrqSave();
    defer rx_lock.releaseIrqRestore(flags);
    if (rx_vq.last_used_idx == rx_vq.usedIdx().*) return null;

    const ui = rx_vq.last_used_idx % rx_vq.queue_size;
    const desc_id: u16 = @intCast(rx_vq.usedRingId(ui).*);
    const total_len = rx_vq.usedRingLen(ui).*;

    if (total_len <= VIRTIO_NET_HDR_SIZE) {
        // Empty frame — refill inline since we already hold rx_lock.
        const d_inline = rx_vq.descPtr(desc_id);
        d_inline.addr = rx_bufs[desc_id];
        d_inline.len = BUF_SIZE;
        d_inline.flags = virtio.VRING_DESC_F_WRITE;
        d_inline.next = 0;
        const ai_in = rx_vq.availIdx().*;
        rx_vq.availRing(ai_in % rx_vq.queue_size).* = desc_id;
        asm volatile ("" ::: .{ .memory = true });
        rx_vq.availIdx().* = ai_in +% 1;
        rx_vq.last_used_idx +%= 1;
        notifyVq(RX_QUEUE, &rx_vq);
        return null;
    }

    rx_last_desc = desc_id;
    const buf: [*]volatile u8 = @ptrFromInt(paging.physToVirt(rx_bufs[desc_id]));
    const data_len = total_len - VIRTIO_NET_HDR_SIZE;
    return buf[VIRTIO_NET_HDR_SIZE .. VIRTIO_NET_HDR_SIZE + data_len];
}

/// Release the last received buffer back to the device.
pub fn rxRelease() void {
    if (irq_driven) return;
    const flags = rx_lock.acquireIrqSave();
    defer rx_lock.releaseIrqRestore(flags);
    const di = rx_last_desc;
    const d = rx_vq.descPtr(di);
    d.addr = rx_bufs[di];
    d.len = BUF_SIZE;
    d.flags = virtio.VRING_DESC_F_WRITE;
    d.next = 0;

    const ai = rx_vq.availIdx().*;
    rx_vq.availRing(ai % rx_vq.queue_size).* = di;
    asm volatile ("" ::: .{ .memory = true });
    rx_vq.availIdx().* = ai +% 1;
    rx_vq.last_used_idx +%= 1;
    notifyVq(RX_QUEUE, &rx_vq);
}

pub fn getMac() [6]u8 {
    return mac;
}
