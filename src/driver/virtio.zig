// virtio — shared infrastructure for virtio-PCI 1.0 (modern) drivers.
//
// virtio_gpu and virtio_sound used to carry near-identical 60-LOC
// `Virtqueue` structs + `setupQueue` functions because the queue model
// is spec-fixed: descriptor ring + available ring + used ring, all
// allocated as physically-contiguous memory and described to the device
// via a fixed set of MMIO offsets in the device's "common config" cap.
//
// This module owns:
//   - the spec-fixed common-config register offsets (CC_*)
//   - the descriptor ring entry layout (VirtqDesc)
//   - the descriptor flag constants (VRING_DESC_F_*)
//   - the `Queue` struct + `init`/accessor methods
//   - a small `notifyQueue` helper for the per-queue doorbell
//
// virtio_net is legacy (port-IO) and uses a different register layout —
// it stays separate.

const std = @import("std");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");

// --- Common-config register offsets ---
//
// Spec-fixed (virtio 1.0 §4.1.4.3). Both gpu and sound currently have
// their own private copies of these constants; `virtio.CC_*` is the
// canonical home so a future virtio driver doesn't need to look them
// up from scratch.

pub const CC_DEVICE_FEATURE_SELECT: u32 = 0x00;
pub const CC_DEVICE_FEATURE: u32 = 0x04;
pub const CC_DRIVER_FEATURE_SELECT: u32 = 0x08;
pub const CC_DRIVER_FEATURE: u32 = 0x0C;
pub const CC_MSIX_CONFIG: u32 = 0x10;
pub const CC_NUM_QUEUES: u32 = 0x12;
pub const CC_DEVICE_STATUS: u32 = 0x14;
pub const CC_CONFIG_GENERATION: u32 = 0x15;
pub const CC_QUEUE_SELECT: u32 = 0x16;
pub const CC_QUEUE_SIZE: u32 = 0x18;
pub const CC_QUEUE_MSIX_VECTOR: u32 = 0x1A;
pub const CC_QUEUE_ENABLE: u32 = 0x1C;
pub const CC_QUEUE_NOTIFY_OFF: u32 = 0x1E;
pub const CC_QUEUE_DESC_LO: u32 = 0x20;
pub const CC_QUEUE_DESC_HI: u32 = 0x24;
pub const CC_QUEUE_AVAIL_LO: u32 = 0x28;
pub const CC_QUEUE_AVAIL_HI: u32 = 0x2C;
pub const CC_QUEUE_USED_LO: u32 = 0x30;
pub const CC_QUEUE_USED_HI: u32 = 0x34;

// Cap type values for `pci.findVirtioCap(dev, cfg_type)`.
pub const CAP_COMMON_CFG: u8 = 1;
pub const CAP_NOTIFY_CFG: u8 = 2;
pub const CAP_ISR_CFG: u8 = 3;
pub const CAP_DEVICE_CFG: u8 = 4;
pub const CAP_PCI_CFG: u8 = 5;
pub const CAP_SHARED_MEMORY_CFG: u8 = 8;

// Device-status bits (spec §2.1).
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub const STATUS_FAILED: u8 = 128;

// --- Descriptor ring ---

pub const VirtqDesc = extern struct {
    addr: u64 align(1),
    len: u32 align(1),
    flags: u16 align(1),
    next: u16 align(1),
};

pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

// --- Queue ---

/// One virtqueue: descriptor ring + available ring + used ring, plus the
/// driver-side bookkeeping (free-list head, count, last-used index).
///
/// Memory layout: `desc_phys` and `avail_phys` share one PMM frame
/// (descriptor ring at offset 0, avail ring immediately after); the used
/// ring lives in its own frame so the device can write to it without
/// dirtying the avail-ring cache line on coherent platforms.
pub const Queue = struct {
    desc_phys: usize = 0,
    avail_phys: usize = 0,
    used_phys: usize = 0,
    queue_size: u16 = 0,
    free_head: u16 = 0,
    num_free: u16 = 0,
    last_used_idx: u16 = 0,
    /// Cached value of CC_QUEUE_NOTIFY_OFF read once at init. Without
    /// this, every doorbell ring would do CC_QUEUE_SELECT-write +
    /// CC_QUEUE_NOTIFY_OFF-read first — two MMIO transactions on the
    /// hot per-frame path. The value is constant per queue per spec.
    notify_off: u16 = 0,

    pub fn descPtr(self: *Queue, i: u16) *volatile VirtqDesc {
        return @ptrFromInt(paging.physToVirt(self.desc_phys + @as(usize, i) * @sizeOf(VirtqDesc)));
    }
    pub fn availFlags(self: *Queue) *volatile u16 {
        return @ptrFromInt(paging.physToVirt(self.avail_phys));
    }
    pub fn availIdx(self: *Queue) *volatile u16 {
        return @ptrFromInt(paging.physToVirt(self.avail_phys + 2));
    }
    pub fn availRing(self: *Queue, i: u16) *volatile u16 {
        return @ptrFromInt(paging.physToVirt(self.avail_phys + 4 + @as(usize, i) * 2));
    }
    pub fn usedFlags(self: *Queue) *volatile u16 {
        return @ptrFromInt(paging.physToVirt(self.used_phys));
    }
    pub fn usedIdx(self: *Queue) *volatile u16 {
        return @ptrFromInt(paging.physToVirt(self.used_phys + 2));
    }
    /// Used-ring entry (id, len) at index `i`. Each used-ring entry is 8
    /// bytes: u32 id followed by u32 len.
    pub fn usedRingId(self: *Queue, i: u16) *volatile u32 {
        return @ptrFromInt(paging.physToVirt(self.used_phys + 4 + @as(usize, i) * 8));
    }
    pub fn usedRingLen(self: *Queue, i: u16) *volatile u32 {
        return @ptrFromInt(paging.physToVirt(self.used_phys + 4 + @as(usize, i) * 8 + 4));
    }

    /// Tail u16 in the avail-ring buffer, used only when VIRTIO_F_EVENT_IDX
    /// is negotiated. Driver writes the usedIdx value AT WHICH it wants the
    /// next interrupt; the device suppresses earlier notifications. Per
    /// spec the field lives at `avail_phys + 4 + queue_size * 2`.
    pub fn usedEvent(self: *Queue) *volatile u16 {
        return @ptrFromInt(paging.physToVirt(self.avail_phys + 4 + @as(usize, self.queue_size) * 2));
    }

    /// Allocate ring memory, chain the descriptor free-list, and program
    /// the device with the ring addresses via the common-config registers.
    /// `cc_base` is the kernel VA of the device's common-config region;
    /// `qi` is the virtqueue index; `max_size` is the driver's clamp on
    /// the queue size (devices may report up to 32K which we don't need).
    ///
    /// Returns false if PMM is exhausted, the device reports queue size 0
    /// for `qi`, or the ring won't fit in the two allocated frames. On
    /// success, the queue is left with `queue_size` valid descriptors,
    /// all zeroed, free-list initialised, MSI-X vector unbound (0xFFFF),
    /// and queue_enable=1.
    pub fn init(self: *Queue, cc_base: usize, qi: u16, max_size: u16) bool {
        ccWrite16(cc_base, CC_QUEUE_SELECT, qi);
        const qsz = ccRead16(cc_base, CC_QUEUE_SIZE);
        if (qsz == 0) return false;
        const qs: u16 = if (qsz > max_size) max_size else qsz;
        ccWrite16(cc_base, CC_QUEUE_SIZE, qs);
        self.queue_size = qs;

        // desc ring + avail ring share one frame: desc starts at 0, avail
        // starts at qs * 16 (descriptor stride). Available-ring header is
        // 4 bytes (flags+idx) + qs * 2 (ring entries) + 2 (used_event) =
        // 6 + qs*2 bytes. With qs ≤ 256, total < 4 KB.
        const p_desc_avail = pmm.allocFrame() orelse return false;
        const p_used = pmm.allocFrame() orelse {
            pmm.freeFrame(p_desc_avail);
            return false;
        };
        @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(p_desc_avail)))[0..4096], 0);
        @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(p_used)))[0..4096], 0);

        self.desc_phys = p_desc_avail;
        self.avail_phys = p_desc_avail + @as(usize, qs) * @sizeOf(VirtqDesc);
        self.used_phys = p_used;
        self.free_head = 0;
        self.num_free = qs;
        self.last_used_idx = 0;
        // Free-list: each descriptor's `next` points to the following one.
        // The last entry's `next` is left at `qs`, which is out-of-range —
        // callers track `num_free` so they never follow it.
        for (0..qs) |i| {
            self.descPtr(@intCast(i)).next = @as(u16, @intCast(i)) + 1;
        }

        // Program the device. Must re-select queue first (spec requires
        // QUEUE_SELECT precede the per-queue address writes).
        ccWrite16(cc_base, CC_QUEUE_SELECT, qi);
        // Cache notify_off while we have QUEUE_SELECT pointing at us;
        // it's constant per queue, so subsequent doorbell rings can skip
        // the select+read dance.
        self.notify_off = ccRead16(cc_base, CC_QUEUE_NOTIFY_OFF);
        ccWrite32(cc_base, CC_QUEUE_DESC_LO, @truncate(self.desc_phys));
        ccWrite32(cc_base, CC_QUEUE_DESC_HI, @truncate(self.desc_phys >> 32));
        ccWrite32(cc_base, CC_QUEUE_AVAIL_LO, @truncate(self.avail_phys));
        ccWrite32(cc_base, CC_QUEUE_AVAIL_HI, @truncate(self.avail_phys >> 32));
        ccWrite32(cc_base, CC_QUEUE_USED_LO, @truncate(self.used_phys));
        ccWrite32(cc_base, CC_QUEUE_USED_HI, @truncate(self.used_phys >> 32));
        ccWrite16(cc_base, CC_QUEUE_MSIX_VECTOR, 0xFFFF);
        ccWrite16(cc_base, CC_QUEUE_ENABLE, 1);
        return true;
    }
};

// --- Common-config MMIO accessors ---
//
// These take a `cc_base` so they can serve all virtio drivers from one
// place; private per-driver `ccWrite16`/`ccRead32` helpers are now
// redundant.

pub fn ccRead8(cc_base: usize, off: u32) u8 {
    return @as(*volatile u8, @ptrFromInt(cc_base + off)).*;
}
pub fn ccWrite8(cc_base: usize, off: u32, v: u8) void {
    @as(*volatile u8, @ptrFromInt(cc_base + off)).* = v;
}
pub fn ccRead16(cc_base: usize, off: u32) u16 {
    return @as(*volatile u16, @ptrFromInt(cc_base + off)).*;
}
pub fn ccWrite16(cc_base: usize, off: u32, v: u16) void {
    @as(*volatile u16, @ptrFromInt(cc_base + off)).* = v;
}
pub fn ccRead32(cc_base: usize, off: u32) u32 {
    return @as(*volatile u32, @ptrFromInt(cc_base + off)).*;
}
pub fn ccWrite32(cc_base: usize, off: u32, v: u32) void {
    @as(*volatile u32, @ptrFromInt(cc_base + off)).* = v;
}

/// Ring the per-queue notify doorbell. Address = notify_base +
/// notify_off * notify_off_multiplier, where `notify_off` is the value
/// the device returned from CC_QUEUE_NOTIFY_OFF for this queue index.
/// The write payload is the queue index.
pub fn notifyQueue(notify_base: usize, notify_off: u16, notify_off_mult: u32, qi: u16) void {
    const addr = notify_base + @as(usize, notify_off) * notify_off_mult;
    @as(*volatile u16, @ptrFromInt(addr)).* = qi;
}
