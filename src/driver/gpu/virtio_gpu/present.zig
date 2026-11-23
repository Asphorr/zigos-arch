//! Getting frames to the host: flush paths, the fire-and-forget present
//! engine, the staging snapshot and the wedge detector.

const pmm = @import("../../../mm/pmm.zig");
const Phys = @import("../../../util/addr.zig").Phys;
const paging = @import("../../../mm/paging.zig");
const debug = @import("../../../debug/debug.zig");
const iommu = @import("../../iommu.zig");
const apic = @import("../../../irq/apic.zig");
const perf = @import("../../../debug/perf.zig");
const Deadline = @import("../../../util/deadline.zig").Deadline;
const vg = @import("../virtio_gpu.zig");
const virtio = @import("../../bus/virtio.zig");
const proto = @import("protocol.zig");
const ctrlq = @import("ctrlq.zig");
const scanout = @import("scanout.zig");

// =============================================================================
// Async (fire-and-forget) flush engine
// =============================================================================
//
// The compositor's present pair (TransferToHost2D/SetScanoutBlob +
// ResourceFlush) used to block in sendSimpleCmdPair until the host's MSI-X —
// and on QEMU's GTK/SDL backends the ResourceFlush response is gated on the
// host actually presenting, so every flush charged a full host round-trip
// (12 ms mean, 100+ ms under host pressure) to the CALLER, holding ctrl_lock
// the whole time. perf showed flush_rect at 42M cyc mean, and the block/wake
// churn behind it drove schedule() to ~36 calls/tick (the gpu_io yield storm).
//
// Now a flush SUBMITS the pair and returns. At most one pair is in flight;
// flushes arriving meanwhile coalesce into one pending dirty rect submitted
// on completion (event-driven: the MSI-X handler raises .virtio_gpu so
// ksoftirqd reaps + resubmits; the 10 Hz tickSweep is the lost-IRQ backstop).
// Sync control commands (resource ops, 3D, capsets) first wait for + reap
// the in-flight pair under ctrl_lock — preserving the "at most one
// outstanding ctrl op" invariant that sendCmdViaPhys/sendSimpleCmdPair's
// last_used_idx accounting relies on, and reusing cmd/resp slots 0+1 safely.
//
// Consistency (the v2 "staging snapshot" rework): the first cut let the
// host DMA read the LIVE framebuffer while the compositor kept drawing the
// next frame into it — under a fast print burst (`help` scrolling a
// terminal) QEMU captured half-drawn frames and presented shredded text.
// The old sync path never showed this because the blocking wait serialized
// draw → transfer → present. v2 restores that consistency without the
// blocking: the resource's attached BACKING is a driver-private staging
// buffer the compositor never sees; at submit time the dirty rects are
// memcpy'd live FB → staging (complete frames only — the copy runs after
// the compositor finished drawing and called flush), and the device only
// ever DMAs from staging. Presents are complete-frame snapshots again.
//
// Batch shape (also v2): pending damage is a LIST of up to 16 rects
// (mirroring ui/desktop/dirty.zig MAX_RECTS) instead of one union bbox —
// one submission = N precise TransferToHost2D + ONE ResourceFlush of the
// bbox, one used-ring interrupt at the end. Precise transfers keep DMA
// bytes proportional to true damage (clock + dock dirty no longer
// transfers the whole screen); the single flush keeps it to one host
// present per batch. Single-blob configs never get here; the 2-blob flip
// path keeps its own pair shape (flip presents the whole frame anyway).

pub const ABATCH_MAX_RECTS: u32 = 16; // mirrors ui/desktop/dirty.zig MAX_RECTS
pub const ABATCH_MAX_CMDS: u32 = ABATCH_MAX_RECTS + 1; // + trailing ResourceFlush

/// Response-slot stride within resp_phys for the async batch (CtrlHdr is
/// 24 B; cache-line spacing keeps the device writes from false-sharing).
/// The sync pair path keeps its historical PAIR_CMD_SLOT_BYTES layout.
pub const ABATCH_RESP_STRIDE: u32 = 64;
comptime {
    if (ABATCH_MAX_CMDS * ctrlq.PAIR_CMD_SLOT_BYTES > ctrlq.CMD_PAGES * 4096) @compileError("async batch overflows cmd_phys");
    if (ABATCH_MAX_CMDS * ABATCH_RESP_STRIDE > 4096) @compileError("async batch overflows resp_phys");
    if (@sizeOf(proto.CtrlHdr) > ABATCH_RESP_STRIDE) @compileError("CtrlHdr exceeds resp stride");
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

pub fn takePresentStats() PresentStats {
    ctrlq.ctrl_lock.acquire();
    defer ctrlq.ctrl_lock.release();
    const s = present_stats;
    present_stats = .{};
    return s;
}

/// Block until the host has taken the present sent last. From then on it
/// shows the new front and reads the old one no more.
pub fn waitPresentIdle() void {
    if (!@atomicLoad(bool, &aflush_in_flight, .acquire)) return;
    {
        ctrlq.ctrl_lock.acquire();
        defer ctrlq.ctrl_lock.release();
        waitAsyncFlushIdleLocked();
    }
    kickPendingFromTask();
}

/// Caller holds ctrl_lock.
pub fn notePresentDone() void {
    const us = apic.tscToUs(perf.rdtsc() -% aflush_submit_tsc);
    @import("../../../debug/ftrace.zig").mark(.present_done, us);
    const s = &present_stats;
    s.total_us += us;
    s.max_us = @max(s.max_us, @as(u32, @intCast(@min(us, 0xFFFF_FFFF))));
    const b: usize = if (us < 2000) 0 else if (us < 4000) 1 else if (us < 8000) 2 else if (us < 16000) 3 else if (us < 33000) 4 else 5;
    s.hist[b] += 1;
}

pub var aflush_in_flight: bool = false;
pub var aflush_target_idx: u16 = 0;
pub var aflush_ncmds: u32 = 0; // cmds in the in-flight batch (2 for a blob pair)
pub var aflush_descs: [2 * ABATCH_MAX_CMDS]u16 = [_]u16{0} ** (2 * ABATCH_MAX_CMDS);
pub var aflush_submit_tsc: u64 = 0;

/// Lock-free mirror of `apend_count != 0` for the IRQ/tickSweep gates.
pub var aflush_pending: bool = false;

// Pending damage list (exclusive max corners). All mutation under ctrl_lock.
pub var apend_rects: [ABATCH_MAX_RECTS][4]u32 = undefined;
pub var apend_count: u32 = 0;

// A flip's flush names what differs from the frame shown before it, so the
// host display can repaint that much. Damage of a flip that failed to
// submit rides the next one. x0, y0, x1, y1; ctrl_lock.
pub var flip_carry: ?[4]u32 = null;

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
// submitBatchLocked; sync fallbacks: copyRectToStaging at the call sites).
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
/// pair that ksoftirqd (dead by then) never reaps.
pub fn asyncFlushEligible() bool {
    if (!(ctrlq.use_msix and vg.msix_safe_to_use and !ctrlq.force_polled)) return false;
    if (@atomicLoad(bool, &@import("../../../debug/serial.zig").emergency_mode, .acquire)) return false;
    return @import("../../../cpu/smp.zig").myCpu().ksoftirqd_pid != null;
}

/// Append a damage rect to the pending list. Overlapping/touching rects
/// merge in place (successive frames usually dirty the same tiles, so the
/// list stays short); a full list collapses to its bbox first — bounded
/// state, worst case = the old single-union behavior. Caller holds
/// ctrl_lock.
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
        i = 1;
        while (i < apend_count) : (i += 1) {
            b[0] = @min(b[0], apend_rects[i][0]);
            b[1] = @min(b[1], apend_rects[i][1]);
            b[2] = @max(b[2], apend_rects[i][2]);
            b[3] = @max(b[3], apend_rects[i][3]);
        }
        apend_rects[0] = b;
        apend_count = 1;
    }
    apend_rects[apend_count] = .{ x0, y0, x1, y1 };
    apend_count += 1;
    @atomicStore(bool, &aflush_pending, true, .release);
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

/// Stage + submit a cmd pair WITHOUT waiting. Caller holds ctrl_lock and
/// has ensured nothing is outstanding (reapAsyncFlushLocked returned true).
/// Same staging/descriptor dance as sendSimpleCmdPair minus the wait; no
/// MSI-X retarget (the reap runs wherever ksoftirqd picks it up, so
/// steering the completion IRQ buys nothing here).
pub fn submitPairAsyncLocked(
    cmd0_buf: [*]const u8,
    cmd0_len: u32,
    cmd1_buf: [*]const u8,
    cmd1_len: u32,
) bool {
    if (ctrlq.ctrl_vq.num_free < 4) return false;
    if (cmd0_len > ctrlq.PAIR_CMD_SLOT_BYTES or cmd1_len > ctrlq.PAIR_CMD_SLOT_BYTES) return false;

    const cmd_base: usize = paging.physToVirt(ctrlq.cmd_phys);
    const resp_base: usize = paging.physToVirt(ctrlq.resp_phys);
    @memcpy(@as([*]volatile u8, @ptrFromInt(cmd_base))[0..cmd0_len], cmd0_buf[0..cmd0_len]);
    @memcpy(@as([*]volatile u8, @ptrFromInt(cmd_base + ctrlq.PAIR_CMD_SLOT_BYTES))[0..cmd1_len], cmd1_buf[0..cmd1_len]);
    @memset(@as([*]volatile u8, @ptrFromInt(resp_base))[0..@sizeOf(proto.CtrlHdr)], 0);
    @memset(@as([*]volatile u8, @ptrFromInt(resp_base + ABATCH_RESP_STRIDE))[0..@sizeOf(proto.CtrlHdr)], 0);

    const c0d0_idx = ctrlq.ctrl_vq.free_head;
    const c0d0 = ctrlq.ctrl_vq.descPtr(c0d0_idx);
    const c0d1_idx: u16 = @intCast(c0d0.next);
    const c0d1 = ctrlq.ctrl_vq.descPtr(c0d1_idx);
    const c1d0_idx: u16 = @intCast(c0d1.next);
    const c1d0 = ctrlq.ctrl_vq.descPtr(c1d0_idx);
    const c1d1_idx: u16 = @intCast(c1d0.next);
    const c1d1 = ctrlq.ctrl_vq.descPtr(c1d1_idx);
    ctrlq.ctrl_vq.free_head = @intCast(c1d1.next);
    ctrlq.ctrl_vq.num_free -= 4;

    c0d0.addr = ctrlq.cmd_phys;
    c0d0.len = cmd0_len;
    c0d0.flags = virtio.VRING_DESC_F_NEXT;
    c0d0.next = c0d1_idx;
    c0d1.addr = ctrlq.resp_phys;
    c0d1.len = @sizeOf(proto.CtrlHdr);
    c0d1.flags = virtio.VRING_DESC_F_WRITE;
    c0d1.next = 0;

    c1d0.addr = ctrlq.cmd_phys + ctrlq.PAIR_CMD_SLOT_BYTES;
    c1d0.len = cmd1_len;
    c1d0.flags = virtio.VRING_DESC_F_NEXT;
    c1d0.next = c1d1_idx;
    c1d1.addr = ctrlq.resp_phys + ABATCH_RESP_STRIDE;
    c1d1.len = @sizeOf(proto.CtrlHdr);
    c1d1.flags = virtio.VRING_DESC_F_WRITE;
    c1d1.next = 0;

    var ai = ctrlq.ctrl_vq.availIdx().*;
    ctrlq.ctrl_vq.availRing(ai % ctrlq.ctrl_vq.queue_size).* = c0d0_idx;
    ai +%= 1;
    ctrlq.ctrl_vq.availRing(ai % ctrlq.ctrl_vq.queue_size).* = c1d0_idx;
    asm volatile ("" ::: .{ .memory = true });
    ctrlq.ctrl_vq.availIdx().* = ai +% 1;

    if (ctrlq.use_event_idx) {
        ctrlq.ctrl_vq.usedEvent().* = ctrlq.ctrl_vq.last_used_idx +% 1;
        asm volatile ("" ::: .{ .memory = true });
    }

    vg.notifyQueue(0, &ctrlq.ctrl_vq);

    aflush_target_idx = ctrlq.ctrl_vq.last_used_idx +% 2;
    aflush_ncmds = 2;
    aflush_descs[0] = c0d0_idx;
    aflush_descs[1] = c0d1_idx;
    aflush_descs[2] = c1d0_idx;
    aflush_descs[3] = c1d1_idx;
    aflush_submit_tsc = perf.rdtsc();
    present_stats.submits += 1;
    @atomicStore(bool, &aflush_in_flight, true, .release);
    return true;
}

pub fn freeAflushDescsLocked() void {
    const n: u32 = aflush_ncmds * 2;
    if (n == 0) return;
    var next: u16 = ctrlq.ctrl_vq.free_head;
    var i: u32 = n;
    while (i > 0) {
        i -= 1;
        ctrlq.ctrl_vq.descPtr(aflush_descs[i]).next = next;
        next = aflush_descs[i];
    }
    ctrlq.ctrl_vq.free_head = next;
    ctrlq.ctrl_vq.num_free += @intCast(n);
}

/// Reap the in-flight async pair if complete — free its descriptors,
/// advance last_used_idx, validate responses, feed the wedge detector.
/// Non-blocking. Returns true when nothing is outstanding anymore (the
/// caller may submit). Caller holds ctrl_lock.
pub fn reapAsyncFlushLocked() bool {
    if (!aflush_in_flight) return true;
    const used = ctrlq.usedIdxCoherent(&ctrlq.ctrl_vq);
    if (@as(i16, @bitCast(used -% aflush_target_idx)) < 0) {
        // Not complete. Wedge guard: a host that never answers would pin
        // in_flight forever (every flush coalescing into a black hole) —
        // after ~2 s abandon the pair exactly like the sync path's
        // timeout: resync, free, count a failure.
        const tpq = apic.tscPerQuantum();
        if (tpq != 0 and (perf.rdtsc() -% aflush_submit_tsc) > tpq *% 200) {
            // KNOWN LIMITATION (same as sendSimpleCmdPair's sync timeout
            // resync): the device still owns these descriptor indices; a
            // LATE completion after they're reused can alias onto the next
            // batch's accounting. Accepted for a host that's already dead
            // for 2s+; a generation stamp would close it properly.
            ctrlq.ctrl_vq.last_used_idx = ctrlq.usedIdxCoherent(&ctrlq.ctrl_vq);
            freeAflushDescsLocked();
            @atomicStore(bool, &aflush_in_flight, false, .release);
            _ = noteFlushResult(false);
            debug.klog("[virtio-gpu] async batch ABANDONED after ~2s (host unresponsive)\n", .{});
            return true;
        }
        return false;
    }
    ctrlq.ctrl_vq.last_used_idx = aflush_target_idx;
    freeAflushDescsLocked();
    @atomicStore(bool, &aflush_in_flight, false, .release);
    notePresentDone();

    const resp_base: usize = paging.physToVirt(ctrlq.resp_phys);
    var ok = true;
    var ci: u32 = 0;
    while (ci < aflush_ncmds) : (ci += 1) {
        const slot = resp_base + ci * ABATCH_RESP_STRIDE;
        ctrlq.clflushRange(slot, @sizeOf(proto.CtrlHdr));
        const resp: *const proto.CtrlHdr = @ptrFromInt(slot);
        if (resp.cmd_type != proto.RESP_OK_NODATA) {
            ok = false;
            debug.klog("[virtio-gpu] async batch error: cmd {d}/{d} resp=0x{X}\n", .{ ci, aflush_ncmds, resp.cmd_type });
        }
    }
    _ = noteFlushResult(ok);
    return true;
}

/// Block (holding ctrl_lock — the historical posture of every sync ctrl op)
/// until no async pair is outstanding. Bounded: reapAsyncFlushLocked's ~2 s
/// abandon guarantees forward progress even against a dead host. Same
/// blockOn(.gpu_io) + wake_tick net as the sync pair's wait.
pub fn waitAsyncFlushIdleLocked() void {
    while (!reapAsyncFlushLocked()) {
        // Polled / panic context must never park — pause-spin; the reap's
        // ~2 s abandon bounds the loop even against a dead host.
        if (ctrlq.force_polled or
            @atomicLoad(bool, &@import("../../../debug/serial.zig").emergency_mode, .acquire))
        {
            asm volatile ("pause");
            continue;
        }
        const process = @import("../../../proc/process.zig");
        const cur = @import("../../../cpu/smp.zig").currentPid() orelse {
            // No task context — asyncFlushEligible() should make this
            // unreachable; bounded wait as a belt.
            var d = Deadline.ms(ctrlq.CTRL_POLL_BUDGET_MS, "virtio-gpu flush reap (no task)");
            while (d.live() and !reapAsyncFlushLocked()) {
                asm volatile ("pause");
            }
            return;
        };
        @atomicStore(u8, &ctrlq.current_gpu_waiter, @intCast(cur), .release);
        defer @atomicStore(u8, &ctrlq.current_gpu_waiter, 0xFF, .release);
        @atomicStore(u64, &process.procs[cur].wake_tick, process.tick_count +% 1, .release);
        @import("../../../proc/sched.zig").registerWakeDeadline(process.tick_count +% 1);
        process.blockOn(.gpu_io, proto.CMD_RESOURCE_FLUSH);
    }
}

/// Double-buffered blob present — fire-and-forget flip. Caller holds
/// ctrl_lock with nothing outstanding. The whole back buffer is shown;
/// `box` (x0, y0, x1, y1) is what changed in it since the last flip.
pub fn submitBlobFlipAsyncLocked(box: [4]u32) bool {
    const new_front = vg.blob_back;
    const dmg = flipDamage(box);
    var sb = proto.SetScanoutBlob{
        .hdr = .{ .cmd_type = proto.CMD_SET_SCANOUT_BLOB },
        .r = .{ .x = 0, .y = 0, .width = vg.width, .height = vg.height },
        .scanout_id = 0,
        .resource_id = scanout.blob_resource_ids[new_front],
        .width = vg.width,
        .height = vg.height,
        .format = proto.FORMAT_B8G8R8X8_UNORM,
        .strides = .{ vg.width * 4, 0, 0, 0 },
    };
    var rf = proto.ResourceFlush{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_FLUSH },
        .r = .{ .x = dmg[0], .y = dmg[1], .width = dmg[2] - dmg[0], .height = dmg[3] - dmg[1] },
        .resource_id = scanout.blob_resource_ids[new_front],
        .padding = 0,
    };
    if (!submitPairAsyncLocked(
        @as([*]const u8, @ptrCast(&sb)),
        @sizeOf(proto.SetScanoutBlob),
        @as([*]const u8, @ptrCast(&rf)),
        @sizeOf(proto.ResourceFlush),
    )) {
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

/// Snapshot + submit a damage batch: each rect is copied live FB →
/// staging, then N TransferToHost2D + one ResourceFlush of the bbox go
/// out as a single virtqueue submission with ONE completion interrupt
/// (usedEvent armed at the last command). Caller holds ctrl_lock with
/// nothing outstanding; 2D-scanout + staging_active only.
pub fn submitBatchLocked(rects: []const [4]u32) bool {
    var n: u32 = @intCast(rects.len);
    if (n == 0) return true;
    var local: [ABATCH_MAX_RECTS][4]u32 = undefined;
    @memcpy(local[0..n], rects);

    // Descriptor pressure (sync ops sharing the queue): degrade to the
    // bbox — 2 cmds, 4 descs — before giving up entirely.
    if (ctrlq.ctrl_vq.num_free < 2 * (n + 1) and n > 1) {
        var b = local[0];
        var i: u32 = 1;
        while (i < n) : (i += 1) {
            b[0] = @min(b[0], local[i][0]);
            b[1] = @min(b[1], local[i][1]);
            b[2] = @max(b[2], local[i][2]);
            b[3] = @max(b[3], local[i][3]);
        }
        local[0] = b;
        n = 1;
    }
    const ncmds: u32 = n + 1;
    if (ctrlq.ctrl_vq.num_free < 2 * ncmds) return false;

    const cmd_base: usize = paging.physToVirt(ctrlq.cmd_phys);
    const resp_base: usize = paging.physToVirt(ctrlq.resp_phys);

    // Stage commands: one transfer per rect, tracking the bbox for the
    // trailing flush. The staging copy happens HERE — the device reads
    // only staging, so this batch presents exactly what the compositor
    // had finished drawing at this moment.
    var bx0: u32 = 0xFFFF_FFFF;
    var by0: u32 = 0xFFFF_FFFF;
    var bx1: u32 = 0;
    var by1: u32 = 0;
    var ci: u32 = 0;
    while (ci < n) : (ci += 1) {
        const r = local[ci];
        copyRectToStaging(r[0], r[1], r[2], r[3]);
        bx0 = @min(bx0, r[0]);
        by0 = @min(by0, r[1]);
        bx1 = @max(bx1, r[2]);
        by1 = @max(by1, r[3]);
        var th = proto.TransferToHost2D{
            .hdr = .{ .cmd_type = proto.CMD_TRANSFER_TO_HOST_2D },
            .r = .{ .x = r[0], .y = r[1], .width = r[2] - r[0], .height = r[3] - r[1] },
            .offset = @as(u64, r[1]) * @as(u64, vg.width) * 4 + @as(u64, r[0]) * 4,
            .resource_id = vg.current_resource_id,
            .padding = 0,
        };
        const dst: [*]volatile u8 = @ptrFromInt(cmd_base + ci * ctrlq.PAIR_CMD_SLOT_BYTES);
        @memcpy(dst[0..@sizeOf(proto.TransferToHost2D)], @as([*]const u8, @ptrCast(&th))[0..@sizeOf(proto.TransferToHost2D)]);
    }
    var rf = proto.ResourceFlush{
        .hdr = .{ .cmd_type = proto.CMD_RESOURCE_FLUSH },
        .r = .{ .x = bx0, .y = by0, .width = bx1 - bx0, .height = by1 - by0 },
        .resource_id = vg.current_resource_id,
        .padding = 0,
    };
    const rf_dst: [*]volatile u8 = @ptrFromInt(cmd_base + n * ctrlq.PAIR_CMD_SLOT_BYTES);
    @memcpy(rf_dst[0..@sizeOf(proto.ResourceFlush)], @as([*]const u8, @ptrCast(&rf))[0..@sizeOf(proto.ResourceFlush)]);

    ci = 0;
    while (ci < ncmds) : (ci += 1) {
        @memset(@as([*]volatile u8, @ptrFromInt(resp_base + ci * ABATCH_RESP_STRIDE))[0..@sizeOf(proto.CtrlHdr)], 0);
    }

    // Descriptor chains + avail entries (same dance as the pair path,
    // generalized to ncmds 2-desc chains).
    const ai = ctrlq.ctrl_vq.availIdx().*;
    ci = 0;
    while (ci < ncmds) : (ci += 1) {
        const d0_idx = ctrlq.ctrl_vq.free_head;
        const d0 = ctrlq.ctrl_vq.descPtr(d0_idx);
        const d1_idx: u16 = @intCast(d0.next);
        const d1 = ctrlq.ctrl_vq.descPtr(d1_idx);
        ctrlq.ctrl_vq.free_head = @intCast(d1.next);
        d0.addr = ctrlq.cmd_phys + ci * ctrlq.PAIR_CMD_SLOT_BYTES;
        d0.len = if (ci < n) @sizeOf(proto.TransferToHost2D) else @sizeOf(proto.ResourceFlush);
        d0.flags = virtio.VRING_DESC_F_NEXT;
        d0.next = d1_idx;
        d1.addr = ctrlq.resp_phys + ci * ABATCH_RESP_STRIDE;
        d1.len = @sizeOf(proto.CtrlHdr);
        d1.flags = virtio.VRING_DESC_F_WRITE;
        d1.next = 0;
        aflush_descs[ci * 2] = d0_idx;
        aflush_descs[ci * 2 + 1] = d1_idx;
        ctrlq.ctrl_vq.availRing((ai +% @as(u16, @intCast(ci))) % ctrlq.ctrl_vq.queue_size).* = d0_idx;
    }
    ctrlq.ctrl_vq.num_free -= @intCast(2 * ncmds);
    asm volatile ("" ::: .{ .memory = true });
    ctrlq.ctrl_vq.availIdx().* = ai +% @as(u16, @intCast(ncmds));

    if (ctrlq.use_event_idx) {
        // Interrupt once, at the LAST completion (same math as the pair's
        // +1-for-2: device signals when used_idx crosses usedEvent).
        ctrlq.ctrl_vq.usedEvent().* = ctrlq.ctrl_vq.last_used_idx +% @as(u16, @intCast(ncmds - 1));
        asm volatile ("" ::: .{ .memory = true });
    }

    vg.notifyQueue(0, &ctrlq.ctrl_vq);

    aflush_target_idx = ctrlq.ctrl_vq.last_used_idx +% @as(u16, @intCast(ncmds));
    aflush_ncmds = ncmds;
    aflush_submit_tsc = perf.rdtsc();
    present_stats.submits += 1;
    @atomicStore(bool, &aflush_in_flight, true, .release);
    return true;
}

/// Submit the pending damage list once the queue is free. Caller holds
/// ctrl_lock. On submit failure the rects go back to pending (retried by
/// the next flush call / softirq / tick).
pub fn kickPendingFlushLocked() void {
    if (aflush_in_flight or apend_count == 0) return;
    if (!asyncFlushEligible()) return;
    if (vg.scanout_is_blob) {
        var box = apend_rects[0];
        for (apend_rects[1..apend_count]) |r| box = boxUnion(box, r);
        apend_count = 0;
        @atomicStore(bool, &aflush_pending, false, .release);
        if (vg.blob_count >= 2) {
            // A flip presents the whole back buffer; the pending damage
            // tells the host how much of it is new.
            _ = submitBlobFlipAsyncLocked(box);
        }
        // Single-blob: sync path owns presentation; drop (next flush
        // repaints through it).
        return;
    }
    if (!staging_active) {
        // Shape changed under us (staging lost) — drop; the sync fallback
        // paths repaint consistently by blocking.
        apend_count = 0;
        @atomicStore(bool, &aflush_pending, false, .release);
        return;
    }
    const local: [ABATCH_MAX_RECTS][4]u32 = apend_rects;
    const cnt = apend_count;
    apend_count = 0;
    @atomicStore(bool, &aflush_pending, false, .release);
    if (!submitBatchLocked(local[0..cnt])) {
        var i: u32 = 0;
        while (i < cnt) : (i += 1) {
            addPendingRectLocked(local[i][0], local[i][1], local[i][2], local[i][3]);
        }
    }
}

/// Async entry for the flush paths. Returns true if the rect was handled
/// (submitted or queued) — the caller is done. False = not eligible; the
/// caller runs the original synchronous body.
pub fn flushRectAsyncSubmit(x0: u32, y0: u32, x1: u32, y1: u32) bool {
    if (!asyncFlushEligible()) return false;
    if (vg.scanout_is_blob and vg.blob_count < 2) return false; // single-cmd shape — sync path
    if (!vg.scanout_is_blob and !staging_active) return false; // no snapshot buffer — sync path stays consistent by blocking
    ctrlq.ctrl_lock.acquire();
    defer ctrlq.ctrl_lock.release();
    if (!reapAsyncFlushLocked()) present_stats.folded += 1;
    // Queue the damage; kick no-ops while a batch is still in flight (the
    // rects ride the next kick, merged with whatever else lands meanwhile).
    addPendingRectLocked(x0, y0, x1, y1);
    kickPendingFlushLocked();
    return true;
}

/// Post-release hook for the sync ctrl-op paths: a completion interrupt
/// that fired while WE held ctrl_lock made ksoftirqd's tryAcquire miss —
/// without this, a pending damage batch would sit until the 10 Hz backstop
/// (~100 ms of stale screen). Raised from task context, never from the
/// drain itself, so ksoftirqd can't self-wake-spin (the Inc1 lesson).
pub fn kickPendingFromTask() void {
    if (@atomicLoad(bool, &aflush_pending, .acquire) and
        !@atomicLoad(bool, &aflush_in_flight, .acquire))
    {
        _ = @import("../../../irq/softirq.zig").raise(.virtio_gpu);
    }
}

/// (Re)allocate the staging snapshot buffer to match fb_num_pages. Reuse
/// across S3 resume (same size, RAM + IOMMU domain survive); realloc on
/// mode change. Failure is non-fatal: staging_active stays false, the
/// resource gets the live FB as backing (pre-v2 behavior) and the 2D
/// async path disables itself.
pub fn ensureStaging() void {
    if (staging_active and staging_pages == scanout.fb_num_pages) return;
    // Serialize against the flush path: ksoftirqd's pending-kick memcpys
    // into staging under ctrl_lock — freeing the old buffer outside it
    // would be a use-after-free of a live DMA target (mode change racing
    // a leftover-damage kick). Also drop pending damage here: those rects
    // describe the buffer being freed. Boot/S3 callers are uncontended;
    // the S3 path is force_polled so the idle-wait pause-spins, no park.
    ctrlq.ctrl_lock.acquire();
    defer ctrlq.ctrl_lock.release();
    waitAsyncFlushIdleLocked();
    apend_count = 0;
    @atomicStore(bool, &aflush_pending, false, .release);
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
// call sendCmdViaPhys → 1-sec timeout, then immediately retry next frame.
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

/// Update wedge state from a sendSimpleCmdPair result. Returns the input
/// `ok` unchanged so the caller can keep its existing flow.
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

pub fn flushUnconditional() void {
    if (!vg.active) return;
    if (shouldSkipFlush()) return;
    const t = @import("../../../debug/perf.zig").enter();
    defer @import("../../../debug/perf.zig").leave(.flush_rect, t);
    // Fire-and-forget when the MSI-X→softirq completion path is up: submit
    // (or coalesce) and return. The sync body below is the early-boot /
    // forced-poll / single-blob fallback.
    if (flushRectAsyncSubmit(0, 0, vg.width, vg.height)) return;
    if (vg.scanout_is_blob and vg.blob_count >= 2) {
        // Page flip: the compositor just wrote into blob_back (which
        // framebuffer points at). Display it, then point framebuffer at
        // the next back blob. The two cmds
        // (SetScanoutBlob + ResourceFlush) are batched into one virtqueue
        // submit so the host pipelines them and we pay one round-trip
        // instead of two — the dominant per-frame cost on QEMU's GTK
        // backend (~21 ms saved/frame).
        const new_front = vg.blob_back;
        var sb = proto.SetScanoutBlob{
            .hdr = .{ .cmd_type = proto.CMD_SET_SCANOUT_BLOB },
            .r = .{ .x = 0, .y = 0, .width = vg.width, .height = vg.height },
            .scanout_id = 0,
            .resource_id = scanout.blob_resource_ids[new_front],
            .width = vg.width,
            .height = vg.height,
            .format = proto.FORMAT_B8G8R8X8_UNORM,
            .strides = .{ vg.width * 4, 0, 0, 0 },
        };
        var rf = proto.ResourceFlush{
            .hdr = .{ .cmd_type = proto.CMD_RESOURCE_FLUSH },
            .r = .{ .x = 0, .y = 0, .width = vg.width, .height = vg.height },
            .resource_id = scanout.blob_resource_ids[new_front],
            .padding = 0,
        };
        _ = noteFlushResult(ctrlq.sendSimpleCmdPair(
            @as([*]const u8, @ptrCast(&sb)),
            @sizeOf(proto.SetScanoutBlob),
            @as([*]const u8, @ptrCast(&rf)),
            @sizeOf(proto.ResourceFlush),
        ));
        scanout.blobsFlipped();
    } else if (vg.scanout_is_blob) {
        // Single-buffer blob: host udmabuf-imports our pages, no transfer.
        _ = noteFlushResult(scanout.resourceFlushCmd(vg.current_resource_id, 0, 0, vg.width, vg.height));
    } else {
        // 2D fallback: full transfer + flush — also batched into one
        // virtqueue submit + single MSI-X round-trip. Snapshot first: the
        // attached backing is the staging buffer, not the live FB. (If an
        // async batch is somehow still in flight — panic mid-flight — the
        // device may read a torn staging once; sendSimpleCmdPair drains it
        // before this transfer, so the FINAL present is consistent.)
        copyRectToStaging(0, 0, vg.width, vg.height);
        var th = proto.TransferToHost2D{
            .hdr = .{ .cmd_type = proto.CMD_TRANSFER_TO_HOST_2D },
            .r = .{ .x = 0, .y = 0, .width = vg.width, .height = vg.height },
            .offset = 0,
            .resource_id = vg.current_resource_id,
            .padding = 0,
        };
        var rf = proto.ResourceFlush{
            .hdr = .{ .cmd_type = proto.CMD_RESOURCE_FLUSH },
            .r = .{ .x = 0, .y = 0, .width = vg.width, .height = vg.height },
            .resource_id = vg.current_resource_id,
            .padding = 0,
        };
        _ = noteFlushResult(ctrlq.sendSimpleCmdPair(
            @as([*]const u8, @ptrCast(&th)),
            @sizeOf(proto.TransferToHost2D),
            @as([*]const u8, @ptrCast(&rf)),
            @sizeOf(proto.ResourceFlush),
        ));
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
    const t = @import("../../../debug/perf.zig").enter();
    defer @import("../../../debug/perf.zig").leave(.flush_rect, t);
    // Fire-and-forget when eligible — see flushUnconditional.
    if (flushRectAsyncSubmit(x0, y0, x1, y1)) return;
    if (vg.scanout_is_blob and vg.blob_count >= 2) {
        // Page flip: SetScanoutBlob + ResourceFlush batched (see
        // flushUnconditional for rationale). Partial rects can't be
        // flipped — always present the whole back.
        const new_front = vg.blob_back;
        var sb = proto.SetScanoutBlob{
            .hdr = .{ .cmd_type = proto.CMD_SET_SCANOUT_BLOB },
            .r = .{ .x = 0, .y = 0, .width = vg.width, .height = vg.height },
            .scanout_id = 0,
            .resource_id = scanout.blob_resource_ids[new_front],
            .width = vg.width,
            .height = vg.height,
            .format = proto.FORMAT_B8G8R8X8_UNORM,
            .strides = .{ vg.width * 4, 0, 0, 0 },
        };
        var rf = proto.ResourceFlush{
            .hdr = .{ .cmd_type = proto.CMD_RESOURCE_FLUSH },
            .r = .{ .x = 0, .y = 0, .width = vg.width, .height = vg.height },
            .resource_id = scanout.blob_resource_ids[new_front],
            .padding = 0,
        };
        _ = noteFlushResult(ctrlq.sendSimpleCmdPair(
            @as([*]const u8, @ptrCast(&sb)),
            @sizeOf(proto.SetScanoutBlob),
            @as([*]const u8, @ptrCast(&rf)),
            @sizeOf(proto.ResourceFlush),
        ));
        scanout.blobsFlipped();
    } else if (vg.scanout_is_blob) {
        _ = noteFlushResult(scanout.resourceFlushCmd(vg.current_resource_id, x0, y0, x1 - x0, y1 - y0));
    } else {
        // 2D fallback dirty-rect path — transfer + flush batched. Snapshot
        // first (see flushUnconditional).
        copyRectToStaging(x0, y0, x1, y1);
        const xferw = x1 - x0;
        const xferh = y1 - y0;
        const offset: u64 = @as(u64, y0) * @as(u64, vg.width) * 4 + @as(u64, x0) * 4;
        var th = proto.TransferToHost2D{
            .hdr = .{ .cmd_type = proto.CMD_TRANSFER_TO_HOST_2D },
            .r = .{ .x = x0, .y = y0, .width = xferw, .height = xferh },
            .offset = offset,
            .resource_id = vg.current_resource_id,
            .padding = 0,
        };
        var rf = proto.ResourceFlush{
            .hdr = .{ .cmd_type = proto.CMD_RESOURCE_FLUSH },
            .r = .{ .x = x0, .y = y0, .width = xferw, .height = xferh },
            .resource_id = vg.current_resource_id,
            .padding = 0,
        };
        _ = noteFlushResult(ctrlq.sendSimpleCmdPair(
            @as([*]const u8, @ptrCast(&th)),
            @sizeOf(proto.TransferToHost2D),
            @as([*]const u8, @ptrCast(&rf)),
            @sizeOf(proto.ResourceFlush),
        ));
    }
}
