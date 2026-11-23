//! Getting frames to the host: flush paths, the fire-and-forget present
//! engine, the staging snapshot and the wedge detector.

const std = @import("std");
const pmm = @import("../../../mm/pmm.zig");
const Phys = @import("../../../util/addr.zig").Phys;
const paging = @import("../../../mm/paging.zig");
const debug = @import("../../../debug/debug.zig");
const iommu = @import("../../iommu.zig");
const apic = @import("../../../irq/apic.zig");
const perf = @import("../../../debug/perf.zig");
const Mutex = @import("../../../proc/spinlock.zig").Mutex;
const vg = @import("../virtio_gpu.zig");
const proto = @import("protocol.zig");
const ctrlq = @import("ctrlq.zig");
const scanout = @import("scanout.zig");

// =============================================================================
// Async (fire-and-forget) present engine
// =============================================================================
//
// The compositor's present pair (TransferToHost2D/SetScanoutBlob +
// ResourceFlush) used to block until the host's MSI-X — and on QEMU's
// GTK/SDL backends the ResourceFlush response is gated on the host actually
// presenting, so every flush charged a full host round-trip (12 ms mean,
// 100+ ms under host pressure) to the CALLER. perf showed flush_rect at 42M
// cyc mean, and the block/wake churn behind it drove schedule() to ~36
// calls/tick (the gpu_io yield storm).
//
// Now a flush posts its batch as one group of control-queue slots and
// returns. At most one batch is in flight; flushes arriving meanwhile
// coalesce into pending damage submitted on completion (the IRQ at the
// batch's last command raises .virtio_gpu, ksoftirqd collects and
// resubmits; irq0's 10 Hz sweep is the lost-IRQ backstop). Other commands
// go out beside it in their own slots.
//
// Consistency (the v2 "staging snapshot" rework): the first cut let the
// host DMA read the LIVE framebuffer while the compositor kept drawing the
// next frame into it — under a fast print burst (`help` scrolling a
// terminal) QEMU captured half-drawn frames and presented shredded text.
// The resource's attached BACKING is a driver-private staging buffer the
// compositor never sees; at submit time the dirty rects are memcpy'd live
// FB → staging (complete frames only — the copy runs after the compositor
// finished drawing and called flush), and the device only ever DMAs from
// staging. Presents are complete-frame snapshots.
//
// Batch shape: pending damage is a LIST of up to 16 rects (mirroring
// ui/desktop/dirty.zig MAX_RECTS) — one batch = N precise TransferToHost2D
// + ONE ResourceFlush of the bbox, one used-ring interrupt at the end.
// Precise transfers keep DMA bytes proportional to true damage; the single
// flush keeps it to one host present per batch. The 2-blob flip path has
// its own pair shape (a flip presents the whole frame anyway).

pub const ABATCH_MAX_RECTS: u32 = 16; // mirrors ui/desktop/dirty.zig MAX_RECTS
pub const ABATCH_MAX_CMDS: u32 = ABATCH_MAX_RECTS + 1; // + trailing ResourceFlush
comptime {
    if (ABATCH_MAX_CMDS > ctrlq.MAX_GROUP) @compileError("a present batch exceeds a queue group");
}

/// What became of the async presents since the last takePresentStats: how
/// many went to the host, how many flush calls found one still in flight
/// and were folded into the next, and how long the host held each one
/// (submit to reap; buckets <2, <4, <8, <16, <33 ms and above).
pub const PresentStats = struct {
    submits: u32 = 0,
    folded: u32 = 0,
    max_us: u32 = 0,
    total_us: u64 = 0,
    hist: [6]u32 = .{0} ** 6,
};
pub var present_stats: PresentStats = .{};

/// The engine's state: pending damage, the batch in flight, the staging
/// buffer, flip_carry, present_stats. ksoftirqd only ever tries it.
pub var present_lock: Mutex = .{};

/// The batch in flight; posted again only once reaped.
var batch: ctrlq.Group = .{};
/// A batch is out. Written under present_lock, read by lock-free gates.
pub var batch_in_flight: bool = false;
var batch_cmds: u32 = 0;
var batch_submit_tsc: u64 = 0;

/// Lock-free mirror of `apend_count != 0` for the softirq gates.
pub var damage_pending: bool = false;

// Pending damage list (exclusive max corners). present_lock.
pub var apend_rects: [ABATCH_MAX_RECTS][4]u32 = undefined;
pub var apend_count: u32 = 0;

// A flip's flush names what differs from the frame shown before it, so the
// host display can repaint that much. Damage of a flip that failed to
// submit rides the next one. x0, y0, x1, y1; present_lock.
pub var flip_carry: ?[4]u32 = null;

pub fn takePresentStats() PresentStats {
    present_lock.acquire();
    defer present_lock.release();
    const s = present_stats;
    present_stats = .{};
    return s;
}

/// Block until the host has taken the present sent last. From then on it
/// shows the new front and reads the old one no more.
pub fn waitPresentIdle() void {
    if (!@atomicLoad(bool, &batch_in_flight, .acquire)) return;
    {
        present_lock.acquire();
        defer present_lock.release();
        waitIdleLocked();
    }
    kickPendingFromTask();
}

fn notePresentDone() void {
    const us = apic.tscToUs(perf.rdtsc() -% batch_submit_tsc);
    @import("../../../debug/ftrace.zig").mark(.present_done, us);
    const s = &present_stats;
    s.total_us += us;
    s.max_us = @max(s.max_us, @as(u32, @intCast(@min(us, 0xFFFF_FFFF))));
    const b: usize = if (us < 2000) 0 else if (us < 4000) 1 else if (us < 8000) 2 else if (us < 16000) 3 else if (us < 33000) 4 else 5;
    s.hist[b] += 1;
}

pub fn boxUnion(a: [4]u32, b: [4]u32) [4]u32 {
    return .{ @min(a[0], b[0]), @min(a[1], b[1]), @max(a[2], b[2]), @max(a[3], b[3]) };
}

pub fn flipDamage(box: [4]u32) [4]u32 {
    const c = flip_carry orelse return box;
    return boxUnion(box, c);
}

// --- Staging snapshot buffer (the resource's attached backing) ---
// Contiguous PMM allocation, IOMMU-mapped, fb_num_pages long. When
// staging_active the device NEVER reads the live framebuffer; every
// transfer site copies its rect live → staging first (async batch path:
// submitRectsLocked; sync fallbacks: copyRectToStaging at the call sites).
// Allocation failure falls back to attaching the live FB (pre-v2
// behavior: correct content, transient tear) and disables the 2D async
// path so sync blocking keeps presents consistent.
pub var staging_phys: usize = 0;
pub var staging_pages: u32 = 0;
pub var staging_virt: [*]u8 = undefined;
pub var staging_active: bool = false;

/// Async needs a working MSI-X → softirq completion path. Early boot and
/// the S3-resume forced-poll window fall back to the synchronous pair.
/// So does a panic (emergency_mode): the panic screen's flush must reach
/// the host NOW — fire-and-forget would coalesce it behind an in-flight
/// batch that ksoftirqd (dead by then) never reaps.
pub fn asyncFlushEligible() bool {
    if (!(ctrlq.use_msix and vg.msix_safe_to_use and !ctrlq.force_polled)) return false;
    if (@atomicLoad(bool, &@import("../../../debug/serial.zig").emergency_mode, .acquire)) return false;
    return @import("../../../cpu/smp.zig").myCpu().ksoftirqd_pid != null;
}

/// Append a damage rect to the pending list. Overlapping/touching rects
/// merge in place (successive frames usually dirty the same tiles, so the
/// list stays short); a full list collapses to its bbox first — bounded
/// state, worst case = a single union. Caller holds present_lock.
pub fn addPendingRectLocked(x0: u32, y0: u32, x1: u32, y1: u32) void {
    var i: u32 = 0;
    while (i < apend_count) : (i += 1) {
        const r = &apend_rects[i];
        if (x0 <= r[2] and r[0] <= x1 and y0 <= r[3] and r[1] <= y1) {
            r[0] = @min(r[0], x0);
            r[1] = @min(r[1], y0);
            r[2] = @max(r[2], x1);
            r[3] = @max(r[3], y1);
            return;
        }
    }
    if (apend_count == ABATCH_MAX_RECTS) {
        var b = apend_rects[0];
        for (apend_rects[1..apend_count]) |r| b = boxUnion(b, r);
        apend_rects[0] = b;
        apend_count = 1;
    }
    apend_rects[apend_count] = .{ x0, y0, x1, y1 };
    apend_count += 1;
    @atomicStore(bool, &damage_pending, true, .release);
}

fn clearPendingLocked() void {
    apend_count = 0;
    @atomicStore(bool, &damage_pending, false, .release);
}

/// Snapshot a rect of the live framebuffer into the staging backing. The
/// device only DMAs from staging, so what the host presents is whatever
/// the compositor had finished drawing when the submit path ran — never a
/// mid-draw frame. No-op when staging is unattached (fallback config).
pub fn copyRectToStaging(x0: u32, y0: u32, x1: u32, y1: u32) void {
    if (!staging_active) return;
    const fb_bytes: [*]const u8 = @ptrCast(@volatileCast(vg.framebuffer));
    const row_bytes: usize = @as(usize, x1 - x0) * 4;
    const stride: usize = @as(usize, vg.width) * 4;
    var off: usize = @as(usize, y0) * stride + @as(usize, x0) * 4;
    var y: u32 = y0;
    while (y < y1) : (y += 1) {
        @memcpy(staging_virt[off .. off + row_bytes], fb_bytes[off .. off + row_bytes]);
        off += stride;
    }
}

/// Post `cmds` as the batch. Caller holds present_lock with nothing out.
fn postBatchLocked(cmds: []const []const u8) bool {
    if (!ctrlq.postGroup(&batch, cmds)) return false;
    batch_cmds = @intCast(cmds.len);
    batch_submit_tsc = perf.rdtsc();
    present_stats.submits += 1;
    @atomicStore(bool, &batch_in_flight, true, .release);
    return true;
}

/// Reap the batch in flight if it came back: stats, the wedge detector.
/// Non-blocking; true when nothing is out any more (the caller may submit).
/// Caller holds present_lock.
fn reapLocked() bool {
    if (!batch_in_flight) return true;
    ctrlq.collect();
    if (ctrlq.groupResult(&batch)) |ok| {
        @atomicStore(bool, &batch_in_flight, false, .release);
        notePresentDone();
        _ = noteFlushResult(ok);
        return true;
    }
    // A host that never answers would pin the batch forever, every flush
    // folding into it: after ~2 s give it up like a sync timeout. Its slots
    // stay the device's until it returns them.
    const tpq = apic.tscPerQuantum();
    if (tpq != 0 and (perf.rdtsc() -% batch_submit_tsc) > tpq *% 200) {
        ctrlq.abandonGroup(&batch);
        @atomicStore(bool, &batch_in_flight, false, .release);
        _ = noteFlushResult(false);
        debug.klog("[virtio-gpu] present batch given up after ~2 s (host unresponsive)\n", .{});
        return true;
    }
    return false;
}

/// Until the batch in flight is reaped; bounded by reapLocked's ~2 s
/// give-up. Caller holds present_lock.
fn waitIdleLocked() void {
    while (!reapLocked()) ctrlq.waitGroup(&batch);
}

/// Double-buffered blob present — fire-and-forget flip. Caller holds
/// present_lock with nothing out. The whole back buffer is shown; `box`
/// (x0, y0, x1, y1) is what changed in it since the last flip.
fn submitBlobFlipLocked(box: [4]u32) bool {
    const new_front = vg.blob_back;
    const dmg = flipDamage(box);
    const sb = proto.SetScanoutBlob{
        .hdr = .{ .cmd_type = proto.CMD_SET_SCANOUT_BLOB },
        .r = .{ .x = 0, .y = 0, .width = vg.width, .height = vg.height },
        .scanout_id = 0,
        .resource_id = scanout.blob_resource_ids[new_front],
        .width = vg.width,
        .height = vg.height,
        .format = proto.FORMAT_B8G8R8X8_UNORM,
        .strides = .{ vg.width * 4, 0, 0, 0 },
    };
    const rf = proto.ResourceFlush{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_FLUSH },
        .r = .{ .x = dmg[0], .y = dmg[1], .width = dmg[2] - dmg[0], .height = dmg[3] - dmg[1] },
        .resource_id = scanout.blob_resource_ids[new_front],
        .padding = 0,
    };
    if (!postBatchLocked(&[_][]const u8{ std.mem.asBytes(&sb), std.mem.asBytes(&rf) })) {
        flip_carry = dmg;
        _ = noteFlushResult(false);
        return false;
    }
    flip_carry = null;
    // Flip immediately. Until the host processes SetScanoutBlob it still
    // scans out the old front: a caller that draws into blob_back while
    // only two blobs exist waits for this present first (waitPresentIdle).
    scanout.blobsFlipped();
    return true;
}

/// Snapshot + post a damage batch: each rect copied live FB → staging, then
/// N TransferToHost2D + one ResourceFlush of the bbox as one group. Short
/// of slots, the bounding box alone. Caller holds present_lock with nothing
/// out; 2D scanout + staging_active only.
fn submitBatchLocked(rects: []const [4]u32) bool {
    if (rects.len == 0) return true;
    if (submitRectsLocked(rects)) return true;
    if (rects.len == 1) return false;
    var b = rects[0];
    for (rects[1..]) |r| b = boxUnion(b, r);
    return submitRectsLocked(&[_][4]u32{b});
}

fn submitRectsLocked(rects: []const [4]u32) bool {
    var th: [ABATCH_MAX_RECTS]proto.TransferToHost2D = undefined;
    var cmds: [ABATCH_MAX_CMDS][]const u8 = undefined;
    var bbox = rects[0];
    for (rects, 0..) |r, i| {
        // Here, not earlier: the batch presents exactly what the compositor
        // had finished drawing at this moment.
        copyRectToStaging(r[0], r[1], r[2], r[3]);
        bbox = boxUnion(bbox, r);
        th[i] = .{
            .hdr = .{ .cmd_type = proto.CMD_TRANSFER_TO_HOST_2D },
            .r = .{ .x = r[0], .y = r[1], .width = r[2] - r[0], .height = r[3] - r[1] },
            .offset = @as(u64, r[1]) * @as(u64, vg.width) * 4 + @as(u64, r[0]) * 4,
            .resource_id = vg.current_resource_id,
            .padding = 0,
        };
        cmds[i] = std.mem.asBytes(&th[i]);
    }
    const rf = proto.ResourceFlush{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_FLUSH },
        .r = .{ .x = bbox[0], .y = bbox[1], .width = bbox[2] - bbox[0], .height = bbox[3] - bbox[1] },
        .resource_id = vg.current_resource_id,
        .padding = 0,
    };
    cmds[rects.len] = std.mem.asBytes(&rf);
    return postBatchLocked(cmds[0 .. rects.len + 1]);
}

/// Submit the pending damage once nothing is out. Caller holds
/// present_lock. On failure the rects go back to pending (retried by the
/// next flush call / softirq / tick).
fn kickPendingFlushLocked() void {
    if (batch_in_flight or apend_count == 0) return;
    if (!asyncFlushEligible()) return;
    if (vg.scanout_is_blob) {
        var box = apend_rects[0];
        for (apend_rects[1..apend_count]) |r| box = boxUnion(box, r);
        clearPendingLocked();
        // A flip presents the whole back buffer; the pending damage tells
        // the host how much of it is new. Single-blob: the sync path owns
        // presentation; dropped (the next flush repaints through it).
        if (vg.blob_count >= 2) _ = submitBlobFlipLocked(box);
        return;
    }
    if (!staging_active) {
        // Staging lost under us: dropped; the sync fallback paths repaint
        // consistently by blocking.
        clearPendingLocked();
        return;
    }
    const local: [ABATCH_MAX_RECTS][4]u32 = apend_rects;
    const cnt = apend_count;
    clearPendingLocked();
    if (!submitBatchLocked(local[0..cnt])) {
        for (local[0..cnt]) |r| addPendingRectLocked(r[0], r[1], r[2], r[3]);
    }
}

/// Async entry for the flush paths. Returns true if the rect was handled
/// (submitted or queued) — the caller is done. False = not eligible; the
/// caller runs the synchronous body.
pub fn flushRectAsyncSubmit(x0: u32, y0: u32, x1: u32, y1: u32) bool {
    if (!asyncFlushEligible()) return false;
    if (vg.scanout_is_blob and vg.blob_count < 2) return false; // single-cmd shape — sync path
    if (!vg.scanout_is_blob and !staging_active) return false; // no snapshot buffer — sync path stays consistent by blocking
    defer kickPendingFromTask(); // after the release below
    present_lock.acquire();
    defer present_lock.release();
    if (!reapLocked()) present_stats.folded += 1;
    // Queue the damage; the kick no-ops while a batch is still out (the
    // rects ride the next one, merged with whatever else lands meanwhile).
    addPendingRectLocked(x0, y0, x1, y1);
    kickPendingFlushLocked();
    return true;
}

/// Whether the softirq has work here: a batch out or damage pending.
pub fn wantsService() bool {
    return @atomicLoad(bool, &batch_in_flight, .acquire) or @atomicLoad(bool, &damage_pending, .acquire);
}

/// ksoftirqd, after ctrlq collected: reap the batch, submit pending damage.
/// Only tries the lock: its holder does the same once it lets go
/// (kickPendingFromTask). The atomic gate keeps early boot, with no tasks
/// and nothing async, away from the Mutex.
pub fn serviceFromSoftirq() void {
    if (!wantsService()) return;
    if (!present_lock.tryAcquire()) return;
    defer present_lock.release();
    _ = reapLocked();
    kickPendingFlushLocked();
}

/// After present_lock is let go: a completion whose softirq found it taken
/// would otherwise wait for the next flush or irq0's 10 Hz sweep. Raised
/// from task context, never from the softirq itself (no self-wake spin).
fn kickPendingFromTask() void {
    const out = @atomicLoad(bool, &batch_in_flight, .acquire);
    const reapable = out and ctrlq.groupDone(&batch);
    const submittable = !out and @atomicLoad(bool, &damage_pending, .acquire);
    if (reapable or submittable) _ = @import("../../../irq/softirq.zig").raise(.virtio_gpu);
}

/// The device was reset (S3 resume): the batch in flight died with it.
pub fn resetAfterDeviceReset() void {
    @atomicStore(bool, &batch_in_flight, false, .release);
    batch = .{};
    clearPendingLocked();
}

/// For ctrlq.dumpWaiterForTarget; racy reads.
pub fn dumpState() void {
    debug.klog("    present: in_flight={any} cmds={d} pending_rects={d} staging={any} wedged={any} lock_held={any}\n", .{
        @atomicLoad(bool, &batch_in_flight, .acquire), batch_cmds, apend_count, staging_active, wedged, present_lock.isHeld(),
    });
}

/// (Re)allocate the staging snapshot buffer to match fb_num_pages. Reuse
/// across S3 resume (same size, RAM + IOMMU domain survive); realloc on
/// mode change. Failure is non-fatal: staging_active stays false, the
/// resource gets the live FB as backing (pre-v2 behavior) and the 2D
/// async path disables itself.
pub fn ensureStaging() void {
    if (staging_active and staging_pages == scanout.fb_num_pages) return;
    // The old buffer may be a live DMA target: free it only once the batch
    // in flight is back. Pending damage describes the buffer being freed:
    // dropped. Boot/S3 callers are uncontended; the S3 path is
    // force_polled, so the idle wait pause-spins.
    defer kickPendingFromTask();
    present_lock.acquire();
    defer present_lock.release();
    waitIdleLocked();
    clearPendingLocked();
    if (staging_phys != 0) {
        staging_active = false;
        iommu.dmaUnmap(vg.pci_bus, vg.pci_dev, vg.pci_func, staging_phys, @as(usize, staging_pages) * 4096);
        pmm.freeContiguous(Phys.of(staging_phys), staging_pages);
        staging_phys = 0;
        staging_pages = 0;
    }
    const phys = (pmm.allocContiguous(scanout.fb_num_pages) orelse {
        debug.klog("[virtio-gpu] staging alloc failed ({d} pages) — live-FB backing, 2D async flush disabled\n", .{scanout.fb_num_pages});
        return;
    }).raw();
    staging_phys = phys;
    staging_pages = scanout.fb_num_pages;
    staging_virt = @ptrFromInt(paging.physToVirt(phys));
    _ = iommu.dmaMap(vg.pci_bus, vg.pci_dev, vg.pci_func, phys, @as(usize, scanout.fb_num_pages) * 4096, .{});
    @memset(staging_virt[0 .. @as(usize, scanout.fb_num_pages) * 4096], 0);
    staging_active = true;
}

// =============================================================================
// Compositor wedge tracking (gaps #7 + #16).
//
// Without this, a host-side stall (CVE-2024-3446 reentrancy drop, virgl
// thread stuck, host hypervisor descheduling for SMI) made the compositor
// time out a flush after a second, then immediately retry next frame.
// 60 retries/sec × 1 sec wait/retry = the desktop completely frozen for
// minutes while it grinds through identical failing submits.
//
// Now: after WEDGE_THRESHOLD consecutive flush failures we mark the GPU
// wedged and short-circuit subsequent flush*() calls (early-return at
// function entry). The desktop keeps running — input, syscalls, scheduling
// all unchanged — but the screen stops updating. Every
// WEDGE_PROBE_INTERVAL_TICKS we allow one probe through; if it succeeds,
// clear wedged and resume normal flushing.
//
// Threshold is small (4) because each failure already costs ~1 sec, so
// the user-visible latency budget is "blow 4 sec then surrender" — not
// the multi-minute hang the old code produced.
// =============================================================================
pub const WEDGE_THRESHOLD: u32 = 4;
pub const WEDGE_PROBE_INTERVAL_TICKS: u64 = 500; // ~5 sec at 100 Hz

pub var consecutive_flush_failures: u32 = 0;
pub var wedged: bool = false;
pub var wedge_first_tick: u64 = 0;
pub var last_probe_tick: u64 = 0;

/// Update wedge state from a flush result. Returns the input `ok`
/// unchanged so the caller can keep its existing flow.
pub fn noteFlushResult(ok: bool) bool {
    if (ok) {
        if (wedged) {
            const span = @import("../../../proc/process.zig").tick_count -% wedge_first_tick;
            debug.klog("[gpu] CONTROLLER RECOVERED after {d} ticks wedged\n", .{span});
        }
        consecutive_flush_failures = 0;
        wedged = false;
    } else {
        consecutive_flush_failures +%= 1;
        if (!wedged and consecutive_flush_failures >= WEDGE_THRESHOLD) {
            wedged = true;
            wedge_first_tick = @import("../../../proc/process.zig").tick_count;
            last_probe_tick = wedge_first_tick;
            debug.klog(
                "[gpu] CONTROLLER WEDGE after {d} consecutive flush timeouts — suppressing flushes (probe every {d} ticks)\n",
                .{ consecutive_flush_failures, WEDGE_PROBE_INTERVAL_TICKS },
            );
        }
    }
    return ok;
}

/// Wedge gate for flush callers. Returns true → caller should early-return
/// (skip this frame's flush). Returns false → caller proceeds normally.
/// When wedged AND the probe interval has elapsed, returns false so ONE
/// flush attempt goes through; result feeds noteFlushResult and either
/// clears the wedge or re-arms the probe timer.
pub fn shouldSkipFlush() bool {
    if (!wedged) return false;
    const now = @import("../../../proc/process.zig").tick_count;
    if ((now -% last_probe_tick) >= WEDGE_PROBE_INTERVAL_TICKS) {
        last_probe_tick = now;
        return false; // let one probe through
    }
    return true;
}

pub fn flush() void {
    if (vg.skip_external_flush) return;
    flushUnconditional();
}

/// The blob page flip, synchronously: SetScanoutBlob + ResourceFlush of
/// the whole back buffer in one queue round trip.
fn flipSync() void {
    const new_front = vg.blob_back;
    const sb = proto.SetScanoutBlob{
        .hdr = .{ .cmd_type = proto.CMD_SET_SCANOUT_BLOB },
        .r = .{ .x = 0, .y = 0, .width = vg.width, .height = vg.height },
        .scanout_id = 0,
        .resource_id = scanout.blob_resource_ids[new_front],
        .width = vg.width,
        .height = vg.height,
        .format = proto.FORMAT_B8G8R8X8_UNORM,
        .strides = .{ vg.width * 4, 0, 0, 0 },
    };
    const rf = proto.ResourceFlush{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_FLUSH },
        .r = .{ .x = 0, .y = 0, .width = vg.width, .height = vg.height },
        .resource_id = scanout.blob_resource_ids[new_front],
        .padding = 0,
    };
    _ = noteFlushResult(ctrlq.sendPair(std.mem.asBytes(&sb), std.mem.asBytes(&rf)));
    scanout.blobsFlipped();
}

/// The 2D present, synchronously: snapshot, transfer + flush of the rect
/// in one queue round trip. (A batch still out — a panic mid-flight — may
/// read a torn staging once; this transfer comes after it on the queue,
/// so the final present is consistent.)
fn transferFlushSync(x0: u32, y0: u32, x1: u32, y1: u32) void {
    copyRectToStaging(x0, y0, x1, y1);
    const th = proto.TransferToHost2D{
        .hdr = .{ .cmd_type = proto.CMD_TRANSFER_TO_HOST_2D },
        .r = .{ .x = x0, .y = y0, .width = x1 - x0, .height = y1 - y0 },
        .offset = @as(u64, y0) * @as(u64, vg.width) * 4 + @as(u64, x0) * 4,
        .resource_id = vg.current_resource_id,
        .padding = 0,
    };
    const rf = proto.ResourceFlush{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_FLUSH },
        .r = .{ .x = x0, .y = y0, .width = x1 - x0, .height = y1 - y0 },
        .resource_id = vg.current_resource_id,
        .padding = 0,
    };
    _ = noteFlushResult(ctrlq.sendPair(std.mem.asBytes(&th), std.mem.asBytes(&rf)));
}

pub fn flushUnconditional() void {
    if (!vg.active) return;
    if (shouldSkipFlush()) return;
    const t = perf.enter();
    defer perf.leave(.flush_rect, t);
    // Fire-and-forget when the MSI-X→softirq completion path is up: submit
    // (or coalesce) and return. Below: the early-boot / forced-poll /
    // single-blob fallback.
    if (flushRectAsyncSubmit(0, 0, vg.width, vg.height)) return;
    if (vg.scanout_is_blob and vg.blob_count >= 2) {
        // The compositor just wrote into blob_back (framebuffer points at
        // it): show it, then point framebuffer at the next back blob.
        flipSync();
    } else if (vg.scanout_is_blob) {
        // Single-buffer blob: host udmabuf-imports our pages, no transfer.
        _ = noteFlushResult(scanout.resourceFlushCmd(vg.current_resource_id, 0, 0, vg.width, vg.height));
    } else {
        transferFlushSync(0, 0, vg.width, vg.height);
    }
}

/// Flush a dirty rectangle. Only transfers the specified region.
pub fn flushRect(x: u32, y: u32, w: u32, h: u32) void {
    if (vg.skip_external_flush) return;
    flushRectUnconditional(x, y, w, h);
}

/// Compositor-only flushRect that bypasses skip_external_flush. The
/// mode-9 GPU compositor uses this to flush its own dirty regions.
pub fn flushRectUnconditional(x: u32, y: u32, w: u32, h: u32) void {
    if (!vg.active) return;
    if (shouldSkipFlush()) return;
    const x0 = @min(x, vg.width);
    const y0 = @min(y, vg.height);
    const x1 = @min(x + w, vg.width);
    const y1 = @min(y + h, vg.height);
    if (x0 >= x1 or y0 >= y1) return;
    const t = perf.enter();
    defer perf.leave(.flush_rect, t);
    // Fire-and-forget when eligible — see flushUnconditional.
    if (flushRectAsyncSubmit(x0, y0, x1, y1)) return;
    if (vg.scanout_is_blob and vg.blob_count >= 2) {
        // A partial rect can't be flipped: the whole back is presented.
        flipSync();
    } else if (vg.scanout_is_blob) {
        _ = noteFlushResult(scanout.resourceFlushCmd(vg.current_resource_id, x0, y0, x1 - x0, y1 - y0));
    } else {
        transferFlushSync(x0, y0, x1, y1);
    }
}
