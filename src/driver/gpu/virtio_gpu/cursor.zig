//! The hardware cursor on the cursor queue.

const pmm = @import("../../../mm/pmm.zig");
const paging = @import("../../../mm/paging.zig");
const debug = @import("../../../debug/debug.zig");
const iommu = @import("../../iommu.zig");
const SpinLock = @import("../../../proc/spinlock.zig").SpinLock;
const vg = @import("../virtio_gpu.zig");
const proto = @import("protocol.zig");
const ctrlq = @import("ctrlq.zig");
const scanout = @import("scanout.zig");

/// Serializes cursor_vq + cursor_cmd page mutations. Cursor updates fire
/// from desktop main loop (mouse motion) and from focus changes (which
/// can run from syscall context), so cross-CPU access is real. IrqSave
/// because timer IRQ on BSP can drive a cursor move via virtio_gpu.flush
/// callbacks if we ever wire them to the cursor path.
pub var cursor_lock: SpinLock = .{};
pub var cursor_vq: vg.Virtqueue = .{};

// Cursor command ring. Single-page (4 KB) carved into CURSOR_RING_SIZE
// UpdateCursor slots. Each sendCursorCmd writes into a fresh slot and
// hands its physical address to the device; the previous in-flight slot
// is left untouched while the host DMA-reads it. Sized to MAX_QUEUE_SIZE
// so the cursor virtqueue's own free-descriptor accounting (num_free)
// guarantees we never wrap a slot whose previous use is still pending.
pub var cursor_cmd_phys: usize = 0;
pub const CURSOR_RING_SIZE: u32 = vg.MAX_QUEUE_SIZE;
comptime {
    if (CURSOR_RING_SIZE * @sizeOf(proto.UpdateCursor) > 4096) {
        @compileError("cursor ring exceeds one PMM frame");
    }
}
pub var cursor_ring_idx: u32 = 0;
pub const CURSOR_RESOURCE_ID: u32 = 100;

// --- Hardware cursor ---

// The 12x16 arrow sprite (same as desktop.zig, converted to RGBA at init)
pub const SPRITE_W = 12;
pub const SPRITE_H = 16;
pub const cursor_sprite = [SPRITE_H][SPRITE_W]u8{
    .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0 },
    .{ 1, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 0 },
    .{ 1, 2, 2, 1, 2, 2, 1, 0, 0, 0, 0, 0 },
    .{ 1, 2, 1, 0, 1, 2, 2, 1, 0, 0, 0, 0 },
    .{ 1, 1, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0 },
    .{ 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0 },
};

/// Initialize hardware cursor: create 64x64 resource, upload image, enable.
pub fn initCursor() bool {
    if (!vg.active) return false;

    // Setup cursor queue (queue 1)
    if (!vg.setupQueueInto(1, &cursor_vq)) {
        debug.klog("[virtio-gpu] Failed to setup cursor queue\n", .{});
        return false;
    }
    _ = iommu.dmaMap(vg.pci_bus, vg.pci_dev, vg.pci_func, cursor_vq.desc_phys, 4096, .{});
    _ = iommu.dmaMap(vg.pci_bus, vg.pci_dev, vg.pci_func, cursor_vq.used_phys, 4096, .{});

    // Allocate cursor command page
    cursor_cmd_phys = (pmm.allocFrame() orelse return false).raw();
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(cursor_cmd_phys)))[0..4096], 0);
    _ = iommu.dmaMap(vg.pci_bus, vg.pci_dev, vg.pci_func, cursor_cmd_phys, 4096, .{});

    // Allocate cursor image: 64x64 RGBA = 16384 bytes = 4 contiguous pages
    const cursor_img_phys = (pmm.allocContiguous(4) orelse return false).raw();
    _ = iommu.dmaMap(vg.pci_bus, vg.pci_dev, vg.pci_func, cursor_img_phys, 4 * 4096, .{});

    // Zero and draw cursor into the 64x64 RGBA buffer
    const pixels: [*]volatile u32 = @ptrFromInt(paging.physToVirt(cursor_img_phys));
    for (0..64 * 64) |i| pixels[i] = 0; // Fully transparent

    // Draw the sprite (0=transparent, 1=black, 2=white)
    for (0..SPRITE_H) |row| {
        for (0..SPRITE_W) |col| {
            const p = cursor_sprite[row][col];
            if (p != 0) {
                const color: u32 = if (p == 1) 0xFF000000 else 0xFFFFFFFF; // ARGB
                pixels[row * 64 + col] = color;
            }
        }
    }

    // Create 2D resource for cursor
    if (!scanout.resourceCreate2D(CURSOR_RESOURCE_ID, 64, 64)) {
        debug.klog("[virtio-gpu] Cursor resource create failed\n", .{});
        return false;
    }

    // Attach backing: the single contiguous 4-page image.
    if (!scanout.attachBackingContiguous(CURSOR_RESOURCE_ID, cursor_img_phys, 4)) {
        debug.klog("[virtio-gpu] Cursor backing attach failed\n", .{});
        return false;
    }

    // Transfer cursor image to host
    _ = scanout.transferToHost(CURSOR_RESOURCE_ID, 0, 0, 64, 64);

    // Send UPDATE_CURSOR via cursor queue
    sendCursorCmd(proto.CMD_UPDATE_CURSOR, 0, 0, CURSOR_RESOURCE_ID);

    vg.hw_cursor_active = true;
    debug.klog("[virtio-gpu] Hardware cursor enabled\n", .{});
    return true;
}

pub fn moveCursor(x: i32, y: i32) void {
    if (!vg.hw_cursor_active) return;
    if (vg.cursor_hidden) return; // don't move when hidden
    const ux: u32 = if (x < 0) 0 else @intCast(x);
    const uy: u32 = if (y < 0) 0 else @intCast(y);
    sendCursorCmd(proto.CMD_MOVE_CURSOR, ux, uy, CURSOR_RESOURCE_ID);
}

pub fn hideCursor() void {
    if (!vg.hw_cursor_active) return;
    vg.cursor_hidden = true;
    // Detach cursor resource from scanout (resource_id=0 removes cursor)
    sendCursorCmd(proto.CMD_UPDATE_CURSOR, 0, 0, 0);
}

pub fn showCursor() void {
    if (!vg.hw_cursor_active) return;
    vg.cursor_hidden = false;
    // Re-attach cursor resource to scanout
    sendCursorCmd(proto.CMD_UPDATE_CURSOR, 0, 0, CURSOR_RESOURCE_ID);
}

/// Send a cursor command (fire-and-forget, no response).
pub fn sendCursorCmd(cmd_type: u32, x: u32, y: u32, resource_id: u32) void {
    const flags = cursor_lock.acquireIrqSave();
    defer cursor_lock.releaseIrqRestore(flags);
    if (cursor_vq.num_free == 0) return;

    // Pick the next ring slot and compute its phys addr. Each in-flight
    // descriptor owns its slot until the host completes; the next call
    // writes into a different slot, so the host never sees a torn struct
    // even when sendCursorCmd is invoked back-to-back faster than the
    // host can drain.
    const slot = cursor_ring_idx % CURSOR_RING_SIZE;
    cursor_ring_idx +%= 1;
    const slot_offset = slot * @sizeOf(proto.UpdateCursor);
    const slot_phys = cursor_cmd_phys + slot_offset;
    const cmd: *volatile proto.UpdateCursor = @ptrFromInt(paging.physToVirt(slot_phys));
    cmd.hdr.cmd_type = cmd_type;
    cmd.hdr.flags = 0;
    cmd.hdr.fence_id = 0;
    cmd.hdr.ctx_id = 0;
    cmd.hdr.ring_idx = 0;
    cmd.hdr.padding = .{ 0, 0, 0 };
    cmd.pos.scanout_id = 0;
    cmd.pos.x = x;
    cmd.pos.y = y;
    cmd.pos.padding = 0;
    cmd.resource_id = resource_id;
    cmd.hot_x = 0;
    cmd.hot_y = 0;
    cmd.padding = 0;

    // Add to cursor queue (single descriptor, no response needed)
    const d_idx = cursor_vq.free_head;
    const d = cursor_vq.descPtr(d_idx);
    cursor_vq.free_head = @intCast(d.next);
    cursor_vq.num_free -= 1;

    d.addr = slot_phys;
    d.len = @sizeOf(proto.UpdateCursor);
    d.flags = 0; // No WRITE flag, no NEXT — fire and forget
    d.next = 0;

    const ai = cursor_vq.availIdx().*;
    cursor_vq.availRing(ai % cursor_vq.queue_size).* = d_idx;
    asm volatile ("" ::: .{ .memory = true }); // compiler barrier; x86 TSO handles CPU ordering
    cursor_vq.availIdx().* = ai +% 1;

    // Notify cursor queue (uses cached notify_off — see notifyQueue helper).
    vg.notifyQueue(1, &cursor_vq);

    // Reclaim used descriptors. The host's used-ring entry tells us
    // WHICH descriptor completed via usedRingId(ui).* — we must NOT
    // re-push the local `d_idx` we just submitted (that is the same
    // slot N times across N completions, corrupting the free list
    // into a self-loop and over-incrementing num_free). Prior bug:
    // after enough cursor moves num_free underflows / free_head
    // points at itself, and sendCursorCmd silently drops at the
    // num_free==0 guard above. Mouse cursor "stops updating" after
    // ~queue_size moves. Read each completed id from the used ring
    // and return THAT desc to the free list.
    while (cursor_vq.last_used_idx != ctrlq.usedIdxCoherent(&cursor_vq)) {
        const ui = cursor_vq.last_used_idx % cursor_vq.queue_size;
        const used_id: u16 = @intCast(cursor_vq.usedRingId(ui).*);
        cursor_vq.last_used_idx +%= 1;
        if (used_id >= cursor_vq.queue_size) continue;
        const used_d = cursor_vq.descPtr(used_id);
        used_d.next = cursor_vq.free_head;
        cursor_vq.free_head = used_id;
        cursor_vq.num_free += 1;
    }
}
