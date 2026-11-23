//! The control queue. A command in flight holds a slot: two descriptors
//! that never change hands and the memory for the command and its
//! response. Slot 0 is the large buffer (16 KB of command, a page of
//! response), one user at a time under large_lock; the others take commands
//! up to 192 bytes with responses up to 64.
//!
//! q_lock covers the ring and the slot table, and only briefly: nobody
//! waits for the device under it, and the doorbell is rung after it. A
//! waiter watches the used index with no lock held, then sleeps; the IRQ
//! wakes the waiter of each slot that came back. Posted commands (the
//! present engine's batches) are collected by ksoftirqd.
//!
//! A command that gets no answer keeps its slot until the device returns
//! it, so a late completion never passes for another command's.

const std = @import("std");
const pmm = @import("../../../mm/pmm.zig");
const paging = @import("../../../mm/paging.zig");
const debug = @import("../../../debug/debug.zig");
const iommu = @import("../../iommu.zig");
const msix = @import("../../../irq/msix.zig");
const spinlock = @import("../../../proc/spinlock.zig");
const SpinLock = spinlock.SpinLock;
const Mutex = spinlock.Mutex;
const apic = @import("../../../irq/apic.zig");
const perf = @import("../../../debug/perf.zig");
const Deadline = @import("../../../util/deadline.zig").Deadline;
const smp = @import("../../../cpu/smp.zig");
const vg = @import("../virtio_gpu.zig");
const virtio = @import("../../bus/virtio.zig");
const proto = @import("protocol.zig");
const present = @import("present.zig");

/// A wait at least this long is logged with its command type.
pub const SLOW_GPU_SUBMIT_THRESHOLD_MS: u64 = 50;
/// How long a command may take before its slot is given up.
pub const SYNC_TIMEOUT_MS: u64 = 1000;

pub const SLOT_BYTES: usize = 256;
pub const SLOT_RESP_OFF: usize = 192;
pub const SLOT_CMD_MAX: usize = SLOT_RESP_OFF;
pub const SLOT_RESP_MAX: usize = SLOT_BYTES - SLOT_RESP_OFF;
pub const CMD_PAGES: u32 = 4;
pub const LARGE_CMD_MAX: usize = CMD_PAGES * 4096;
pub const LARGE_RESP_MAX: usize = 4096;
/// Commands one group may post.
pub const MAX_GROUP: usize = 17;

const LARGE: u8 = 0;
const MAX_SLOTS: usize = vg.MAX_QUEUE_SIZE / 2;
const SLOT_PAGES: u32 = ((MAX_SLOTS - 1) * SLOT_BYTES + 4095) / 4096;
const NO_PID: u8 = 0xFF;

comptime {
    // The device writes responses: a cache line of their own.
    if (SLOT_RESP_OFF % 64 != 0 or SLOT_BYTES % 64 != 0) @compileError("slot response not line-aligned");
    if (@sizeOf(proto.CtrlHdr) > SLOT_RESP_MAX) @compileError("CtrlHdr exceeds a slot response");
    if (@sizeOf(proto.SetScanoutBlob) > SLOT_CMD_MAX) @compileError("SetScanoutBlob exceeds a slot");
    if (MAX_GROUP + 2 > MAX_SLOTS - 1) @compileError("a group would starve sync commands");
}

// MSI-X armed for the queue (after init): waits may sleep for the IRQ.
pub var use_msix: bool = false;

/// Diagnostic and S3-resume switch: every wait pause-spins on the used
/// index instead of sleeping. Read at the start of each wait.
pub var force_polled: bool = false;

/// VIRTIO_F_RING_EVENT_IDX negotiated: used_event says which completion
/// interrupts (armLocked).
pub var use_event_idx: bool = false;

/// The queue's MSI-X table entry (kernel VA); 0 = not armed. A task about
/// to sleep steers it to its own CPU: under Hyper-V a halted vCPU's LAPIC
/// stops, and only the completion IRQ itself wakes it.
pub var msix_entry_addr: usize = 0;

pub var ctrl_vq: vg.Virtqueue = .{};

/// The large buffer: slot 0's command and response.
pub var cmd_phys: usize = 0;
pub var resp_phys: usize = 0;
var slot_phys: usize = 0;

const State = enum(u8) { free, queued, returned, abandoned };

const Slot = struct {
    state: State = .free,
    posted: bool = false,
    /// Sync: the task that sent it, so that its end gives the slot up.
    owner: u8 = NO_PID,
    /// Asleep on it; read by the IRQ without q_lock.
    waiter: u8 = NO_PID,
    cmd_type: u32 = 0,
    group: ?*Group = null,
    /// Bumped each time the slot is freed: a ticket of an older use no
    /// longer matches, so nobody acts on a slot that has moved on.
    gen: u16 = 0,
};

/// One use of a slot: what its sender waits on and frees.
const Ticket = struct {
    idx: u8,
    gen: u16,
};

/// Posted commands that come back together: the present engine's batch.
/// Owned by its poster, which posts it again only once it is done.
pub const Group = struct {
    idx: [MAX_GROUP]u8 = undefined,
    count: u8 = 0,
    outstanding: u8 = 0,
    failed: bool = false,
    /// Every command came back, or the group was given up. Atomic.
    done: bool = true,
    /// Avail index past its last command: where its IRQ is armed.
    end: u16 = 0,
};

var slots: [MAX_SLOTS]Slot = [_]Slot{.{}} ** MAX_SLOTS;
var slot_count: u8 = 0;

var q_lock: SpinLock = .{};
var large_lock: Mutex = .{};
var kick_pending: bool = false;
/// Tasks asleep on a slot or for a free one, and how many (q_lock).
var asleep: [4]u64 = .{ 0, 0, 0, 0 };
var sleepers: u8 = 0;
/// Tasks waiting for a free slot (q_lock).
var slot_wanted: [4]u64 = .{ 0, 0, 0, 0 };
/// Posted commands the device holds. Written under q_lock, read by the IRQ.
var posted_out: u8 = 0;
/// The group the IRQ is armed for, if any (q_lock).
var group_out: ?*Group = null;
/// The task waiting for posted commands (waitGroup). Atomic.
var posted_waiter: u8 = NO_PID;
/// APIC id the MSI-X entry points at (q_lock); 0xFFFFFFFF = unknown.
var steered_apic: u32 = 0xFFFF_FFFF;

pub const Stats = struct {
    sync: u64 = 0,
    large: u64 = 0,
    posted: u64 = 0,
    sleeps: u64 = 0,
    slot_waits: u64 = 0,
    abandoned: u64 = 0,
    late: u64 = 0,
    stray: u64 = 0,
};
/// Under q_lock; diagnostics read it racily.
pub var stats: Stats = .{};

/// Once the control queue is set up: the large buffer and the slots.
pub fn init() bool {
    slot_count = @intCast(@min(ctrl_vq.queue_size / 2, MAX_SLOTS));
    if (slot_count < 4) return false; // the large buffer and a pair, at least
    cmd_phys = (pmm.allocContiguous(CMD_PAGES) orelse return false).raw();
    resp_phys = (pmm.allocFrame() orelse return false).raw();
    slot_phys = (pmm.allocContiguous(SLOT_PAGES) orelse return false).raw();
    @memset(virt(slot_phys)[0 .. @as(usize, SLOT_PAGES) * 4096], 0);
    _ = iommu.dmaMap(vg.pci_bus, vg.pci_dev, vg.pci_func, cmd_phys, CMD_PAGES * 4096, .{});
    _ = iommu.dmaMap(vg.pci_bus, vg.pci_dev, vg.pci_func, resp_phys, 4096, .{});
    _ = iommu.dmaMap(vg.pci_bus, vg.pci_dev, vg.pci_func, slot_phys, @as(usize, SLOT_PAGES) * 4096, .{});
    spinlock.registerLock("virtio_gpu.queue", &q_lock);
    spinlock.registerMutex("virtio_gpu.large", &large_lock);
    debug.klog("[virtio-gpu] control queue: {d} slots + the large buffer\n", .{slot_count - 1});
    if (slot_count - 1 < MAX_GROUP + 2) {
        debug.klog("[virtio-gpu] a full present batch won't fit beside a pair: batches fall back to their bounding box\n", .{});
    }
    return true;
}

/// The device was reset (S3 resume): point the queue back at its rings and
/// forget everything in flight, under q_lock so that no drain sees the
/// rings half done. A task still waiting finds its slot gone and fails.
pub fn reprogramAfterDeviceReset(cc_base: usize) bool {
    q_lock.acquire();
    defer q_lock.release();
    if (!ctrl_vq.reprogram(cc_base, 0)) return false;
    for (slots[0..slot_count], 0..) |*s, i| {
        const w = s.waiter;
        if (s.group) |g| {
            g.outstanding = 0;
            g.failed = true;
            @atomicStore(bool, &g.done, true, .release);
        }
        freeLocked(@intCast(i));
        if (w != NO_PID) wakeTask(w);
    }
    group_out = null;
    @atomicStore(u8, &posted_out, 0, .release);
    @atomicStore(bool, &kick_pending, false, .release);
    steered_apic = 0xFFFF_FFFF;
    wakeSlotWantersLocked();
    return true;
}

// --- Cache coherence ---
//
// Responses and the used ring are read after a clflush + mfence, a
// workaround from 2026-05-20 for a stale-read freeze. QEMU's DMA is
// coherent on x86, so it may well be unneeded; measure before removing.
// usedIdxCoherent's mfence is also what orders a used_event store before
// the used-index load in armLocked and the waits.

pub inline fn clflushLine(addr: usize) void {
    asm volatile ("clflush (%[a])"
        :
        : [a] "r" (addr),
        : .{ .memory = true });
    asm volatile ("mfence" ::: .{ .memory = true });
}

pub inline fn clflushRange(addr: usize, len: usize) void {
    var p = addr & ~@as(usize, 63);
    const end = addr + len;
    while (p < end) : (p += 64) {
        asm volatile ("clflush (%[a])"
            :
            : [a] "r" (p),
            : .{ .memory = true });
    }
    asm volatile ("mfence" ::: .{ .memory = true });
}

pub inline fn usedIdxCoherent(vq: *vg.Virtqueue) u16 {
    clflushLine(@intFromPtr(vq.usedIdx()));
    return vq.usedIdx().*;
}

/// The descriptor id of used-ring entry `i`.
fn usedId(i: u16) u32 {
    const p = ctrl_vq.usedRingId(i % ctrl_vq.queue_size);
    clflushLine(@intFromPtr(p));
    return p.*;
}

inline fn consumed() u16 {
    return @atomicLoad(u16, &ctrl_vq.last_used_idx, .acquire);
}

// --- Slots ---

inline fn virt(p: usize) [*]volatile u8 {
    return @ptrFromInt(paging.physToVirt(p));
}

fn cmdPhysOf(i: u8) usize {
    return if (i == LARGE) cmd_phys else slot_phys + @as(usize, i - 1) * SLOT_BYTES;
}

fn respPhysOf(i: u8) usize {
    return if (i == LARGE) resp_phys else cmdPhysOf(i) + SLOT_RESP_OFF;
}

inline fn headOf(i: u8) u16 {
    return @as(u16, i) * 2;
}

fn cmdType(cmd: []const u8) u32 {
    return std.mem.readInt(u32, cmd[0..4], .little);
}

/// Point slot `i`'s descriptors at its buffers and make it available. The
/// doorbell is left to kick().
fn queueLocked(i: u8, cmd_len: usize, resp_len: usize) Ticket {
    const h = headOf(i);
    const d0 = ctrl_vq.descPtr(h);
    d0.addr = cmdPhysOf(i);
    d0.len = @intCast(cmd_len);
    d0.flags = virtio.VRING_DESC_F_NEXT;
    d0.next = h + 1;
    const d1 = ctrl_vq.descPtr(h + 1);
    d1.addr = respPhysOf(i);
    d1.len = @intCast(resp_len);
    d1.flags = virtio.VRING_DESC_F_WRITE;
    d1.next = 0;
    const ai = ctrl_vq.availIdx().*;
    ctrl_vq.availRing(ai % ctrl_vq.queue_size).* = h;
    asm volatile ("" ::: .{ .memory = true }); // entry before index; x86 keeps store order
    ctrl_vq.availIdx().* = ai +% 1;
    slots[i].state = .queued;
    @atomicStore(bool, &kick_pending, true, .release);
    return .{ .idx = i, .gen = slots[i].gen };
}

/// Ring the doorbell for what was made available since the last ring. It
/// traps to the host: never under q_lock. Whoever takes the flag covers
/// every entry published before.
fn kick() void {
    if (@atomicRmw(bool, &kick_pending, .Xchg, false, .acq_rel)) vg.notifyQueue(0, &ctrl_vq);
}

/// Fill `out` with free small slots; all or none.
fn findFreeLocked(out: []u8) bool {
    var n: usize = 0;
    var i: u8 = 1;
    while (i < slot_count and n < out.len) : (i += 1) {
        if (slots[i].state == .free) {
            out[n] = i;
            n += 1;
        }
    }
    return n == out.len;
}

fn freeLocked(i: u8) void {
    slots[i] = .{ .gen = slots[i].gen +% 1 };
}

inline fn ours(t: Ticket) bool {
    return slots[t.idx].gen == t.gen;
}

/// Collect what the device returned since the last drain: sync slots are
/// marked for their waiters, posted ones checked and freed, given-up ones
/// freed at last. Wakes whoever waits for what came back. Whether a posted
/// group finished: the present engine reaps it (see drainForeignLocked).
fn drainLocked() bool {
    const used = usedIdxCoherent(&ctrl_vq);
    var freed = false;
    var group_done = false;
    while (ctrl_vq.last_used_idx != used) {
        const id = usedId(ctrl_vq.last_used_idx);
        @atomicStore(u16, &ctrl_vq.last_used_idx, ctrl_vq.last_used_idx +% 1, .release);
        if (id & 1 != 0 or id / 2 >= slot_count) {
            stray(id);
            continue;
        }
        const i: u8 = @intCast(id / 2);
        const s = &slots[i];
        switch (s.state) {
            .queued => if (s.posted) {
                if (postedReturnedLocked(i)) group_done = true;
                freed = true;
            } else {
                s.state = .returned;
                const w = @atomicLoad(u8, &s.waiter, .acquire);
                if (w != NO_PID) wakeTask(w);
            },
            .abandoned => {
                stats.late += 1;
                debug.klog("[virtio-gpu] cmd 0x{X} came back after it was given up (slot {d})\n", .{ s.cmd_type, i });
                freeLocked(i);
                freed = true;
            },
            .free, .returned => stray(id),
        }
    }
    if (freed) wakeSlotWantersLocked();
    return group_done;
}

/// drainLocked by anyone but the present engine and its softirq: a batch
/// that came back is left for ksoftirqd to reap.
fn drainForeignLocked() void {
    if (drainLocked()) raiseSoftirq();
}

fn emergency() bool {
    return @atomicLoad(bool, &@import("../../../debug/serial.zig").emergency_mode, .acquire);
}

/// Not in a panic: the scheduler may be held by a CPU that never runs again.
fn raiseSoftirq() void {
    if (!emergency()) _ = @import("../../../irq/softirq.zig").raise(.virtio_gpu);
}

fn stray(id: u32) void {
    stats.stray += 1;
    debug.klog("[virtio-gpu] stray completion of descriptor {d}\n", .{id});
}

/// Whether its group finished with it.
fn postedReturnedLocked(i: u8) bool {
    const s = &slots[i];
    var group_done = false;
    const rv = paging.physToVirt(respPhysOf(i));
    clflushRange(rv, @sizeOf(proto.CtrlHdr));
    const resp: *const volatile proto.CtrlHdr = @ptrFromInt(rv);
    const ok = resp.cmd_type == proto.RESP_OK_NODATA;
    if (!ok) debug.klog("[virtio-gpu] posted cmd 0x{X} failed: resp=0x{X}\n", .{ s.cmd_type, resp.cmd_type });
    if (s.group) |g| {
        if (!ok) g.failed = true;
        g.outstanding -= 1;
        if (g.outstanding == 0) {
            if (group_out == g) group_out = null;
            @atomicStore(bool, &g.done, true, .release);
            group_done = true;
            const pw = @atomicLoad(u8, &posted_waiter, .acquire);
            if (pw != NO_PID and pw != currentPid8()) wakeTask(pw);
        }
    }
    freeLocked(i);
    @atomicStore(u8, &posted_out, posted_out - 1, .release);
    return group_done;
}

/// Ask for an interrupt at the next completion someone sleeps for: any
/// completion while a task is asleep, else the end of the posted group.
/// With nobody to tell, none is asked for. Without EVENT_IDX the device
/// signals every completion anyway.
fn armLocked() void {
    if (!use_event_idx) return;
    while (true) {
        const at = ctrl_vq.last_used_idx;
        const in_group: u8 = if (group_out) |g| g.outstanding else 0;
        const ev: u16 = if (sleepers != 0 or posted_out != in_group)
            at
        else if (group_out) |g|
            g.end -% 1
        else
            return;
        ctrl_vq.usedEvent().* = ev;
        // A completion that landed before the store went unsignaled:
        // collect it and arm again. usedIdxCoherent fences the store.
        if (usedIdxCoherent(&ctrl_vq) == at) return;
        drainForeignLocked();
    }
}

// --- Sleeping ---

fn bitSet(m: *[4]u64, pid: u8) void {
    m[pid >> 6] |= @as(u64, 1) << @intCast(pid & 63);
}

/// Clear `pid`'s bit; whether it was set.
fn bitClear(m: *[4]u64, pid: u8) bool {
    const b = @as(u64, 1) << @intCast(pid & 63);
    const was = m[pid >> 6] & b != 0;
    m[pid >> 6] &= ~b;
    return was;
}

fn enrollLocked(me: u8) void {
    if (asleep[me >> 6] & (@as(u64, 1) << @intCast(me & 63)) != 0) return;
    bitSet(&asleep, me);
    sleepers += 1;
}

fn unenrollLocked(me: u8) void {
    if (bitClear(&asleep, me)) sleepers -= 1;
}

fn wakeSlotWantersLocked() void {
    for (&slot_wanted, 0..) |*w, word| {
        var m = w.*;
        w.* = 0;
        while (m != 0) : (m &= m - 1) {
            wakeTask(@intCast(word * 64 + @ctz(m)));
        }
    }
}

/// Wake a task waiting here. One that moved on to another wait is left to
/// that wait's waker; one about to sleep (wait_kind still .none) gets
/// wake_pending, which blockOn's handshake honours.
fn wakeTask(pid: u8) void {
    if (emergency()) return; // the scheduler may be held by a stopped CPU
    const process = @import("../../../proc/process.zig");
    const kind = @atomicLoad(process.WaitKind, &process.procs[pid].wait_kind, .acquire);
    if (kind != .gpu_io and kind != .none) return;
    @import("../../../debug/wakelat.zig").hintWake(pid, .gpu_io);
    @import("../../../proc/sched.zig").wake(pid);
    vg.virtio_gpu_waiter_wakes +%= 1;
}

fn steerIrqLocked() void {
    if (msix_entry_addr == 0) return;
    const apic_id: u32 = smp.myCpu().lapic_id;
    if (apic_id == steered_apic) return;
    msix.retargetEntry(msix_entry_addr, apic_id);
    steered_apic = apic_id;
}

/// Whether this wait may sleep for the IRQ. Not before MSI-X, during the
/// S3 resume, in a panic, or without a task.
fn irqWaitOk() bool {
    if (!(use_msix and vg.msix_safe_to_use and !force_polled)) return false;
    if (@atomicLoad(bool, &@import("../../../debug/serial.zig").emergency_mode, .acquire)) return false;
    return smp.currentPid() != null;
}

fn currentPid8() u8 {
    return if (smp.currentPid()) |p| @intCast(p) else NO_PID;
}

/// Sleep until woken, with a backstop one tick on should the IRQ go missing
/// (CVE-2024-3446's reentrancy guard drops notifications). blockOnDeadline:
/// it re-checks the deadline once asleep, so a tick between arming it and
/// sleeping cannot drop it.
fn sleepOn(cmd_type: u32) void {
    const process = @import("../../../proc/process.zig");
    @import("../../../proc/sched.zig").blockOnDeadline(.gpu_io, cmd_type, process.tick_count +% 1);
}

/// Pause-spin until the used index moves past `seen`, or `d` runs out.
fn pollPast(seen: u16, d: *Deadline) void {
    while (usedIdxCoherent(&ctrl_vq) == seen and d.live()) asm volatile ("pause");
}

/// pollPast for half a millisecond at most: a slot can come free without
/// the used index moving (its owner frees it).
fn pollBriefly(seen: u16) void {
    var d = Deadline.us(500, "virtio-gpu slot (polled)");
    pollPast(seen, &d);
}

/// Most commands are back within ~200 µs: watch for that with no lock and
/// no IRQ before sleeping. Whether the used index moved.
fn spinBriefly() bool {
    const tpq = apic.tscPerQuantum();
    if (tpq == 0) return false;
    const seen = consumed();
    const end = perf.rdtsc() +% tpq / 50; // 200 µs at a 10 ms quantum
    while (perf.rdtsc() < end) {
        if (usedIdxCoherent(&ctrl_vq) != seen) return true;
        asm volatile ("pause");
    }
    return false;
}

const WaitEnd = enum { ok, timeout, reset };

/// Wait until the slots of `tickets`, queued by this task, come back. On a
/// timeout the ones still out are given up: they stay the device's until it
/// returns them. `.reset`: they were taken from us meanwhile (S3 reset).
fn waitSlots(tickets: []const Ticket, cmd_type: u32) WaitEnd {
    const sp = @import("../../../debug/syscall_perf.zig").scope(.gpu_wait);
    defer sp.end();
    const t0 = perf.rdtsc();
    var d = Deadline.ms(SYNC_TIMEOUT_MS, "virtio-gpu command");
    const irq_wait = irqWaitOk();
    const me = currentPid8();
    const spun_back = irq_wait and spinBriefly();
    var sleeps: u32 = 0;
    var enrolled = false;
    const end: WaitEnd = wait: while (true) {
        // Each pass: collect, look at our slots, then poll or sleep.
        q_lock.acquire();
        if (enrolled) {
            for (tickets) |t| {
                if (ours(t)) @atomicStore(u8, &slots[t.idx].waiter, NO_PID, .release);
            }
            unenrollLocked(me);
            enrolled = false;
        }
        drainForeignLocked();
        var all = true;
        var gone = false;
        for (tickets) |t| {
            if (!ours(t)) {
                gone = true;
                continue;
            }
            switch (slots[t.idx].state) {
                .returned => {},
                .queued => all = false,
                .free, .abandoned => gone = true,
            }
        }
        if (gone) {
            q_lock.release();
            break :wait .reset;
        }
        if (all) {
            armLocked();
            q_lock.release();
            break :wait .ok;
        }
        if (!d.live()) {
            giveUpLocked(tickets);
            armLocked();
            q_lock.release();
            break :wait .timeout;
        }
        if (!irq_wait) {
            const seen = ctrl_vq.last_used_idx;
            q_lock.release();
            pollPast(seen, &d);
            continue;
        }
        for (tickets) |t| {
            if (slots[t.idx].state == .queued) @atomicStore(u8, &slots[t.idx].waiter, me, .release);
        }
        enrollLocked(me);
        enrolled = true;
        steerIrqLocked();
        armLocked();
        // Collect what came back since the drain above (armLocked does so
        // with EVENT_IDX; without it, nothing did): a slot of ours among it
        // woke us, and blockOnDeadline returns at once. The fence in
        // usedIdxCoherent orders the waiter stores before the load.
        if (usedIdxCoherent(&ctrl_vq) != ctrl_vq.last_used_idx) drainForeignLocked();
        stats.sleeps += 1;
        q_lock.release();
        sleepOn(cmd_type);
        sleeps += 1;
    } else unreachable;

    const wait_ms = apic.tscToMs(perf.rdtsc() -% t0);
    if (wait_ms >= SLOW_GPU_SUBMIT_THRESHOLD_MS or end != .ok) {
        debug.klog("[slow-gpu] cmd_type=0x{X} slots={d} wait={d}ms sleeps={d} spun_back={any} end={s}\n", .{
            cmd_type, tickets.len, wait_ms, sleeps, spun_back, @tagName(end),
        });
    }
    if (end == .timeout) {
        debug.klog("[virtio-gpu] cmd 0x{X} got no answer in {d} ms; its slot stays with the device\n", .{ cmd_type, SYNC_TIMEOUT_MS });
    }
    return end;
}

/// The slots of a wait that timed out: what came back is freed, what is
/// still out stays given up until the device returns it.
fn giveUpLocked(tickets: []const Ticket) void {
    var freed = false;
    for (tickets) |t| {
        if (!ours(t)) continue;
        switch (slots[t.idx].state) {
            .returned => {
                freeLocked(t.idx);
                freed = true;
            },
            .queued => {
                slots[t.idx].state = .abandoned;
                slots[t.idx].owner = NO_PID;
                @atomicStore(u8, &slots[t.idx].waiter, NO_PID, .release);
                stats.abandoned += 1;
            },
            .free, .abandoned => {},
        }
    }
    if (freed) wakeSlotWantersLocked();
}

/// After a wait that ended .ok: copy the responses out and free the slots,
/// if they are still ours (an S3 reset may have taken them since). Under
/// q_lock, so that nobody reuses a slot halfway through the copy.
fn takeResponses(tickets: []const Ticket, resps: []const []u8) bool {
    q_lock.acquire();
    defer q_lock.release();
    for (tickets) |t| {
        if (!ours(t) or slots[t.idx].state != .returned) return false;
    }
    for (tickets, resps) |t, r| {
        const rv = paging.physToVirt(respPhysOf(t.idx));
        clflushRange(rv, r.len);
        @memcpy(r, @as([*]const volatile u8, @ptrFromInt(rv))[0..r.len]);
        freeLocked(t.idx);
    }
    wakeSlotWantersLocked();
    return true;
}

/// Take `idx.len` free small slots, waiting while the device holds them all.
/// On true q_lock is held and the caller queues them.
fn takeSlotsLocked(idx: []u8, cmd_type: u32) bool {
    var d = Deadline.ms(SYNC_TIMEOUT_MS, "virtio-gpu slot");
    const me = currentPid8();
    q_lock.acquire();
    while (true) {
        drainForeignLocked();
        if (findFreeLocked(idx)) return true;
        if (!d.live()) {
            q_lock.release();
            debug.klog("[virtio-gpu] no free slot for cmd 0x{X} in {d} ms\n", .{ cmd_type, SYNC_TIMEOUT_MS });
            return false;
        }
        stats.slot_waits += 1;
        if (!irqWaitOk()) {
            const seen = ctrl_vq.last_used_idx;
            q_lock.release();
            pollBriefly(seen);
            q_lock.acquire();
            continue;
        }
        bitSet(&slot_wanted, me);
        enrollLocked(me);
        armLocked();
        q_lock.release();
        sleepOn(cmd_type);
        q_lock.acquire();
        _ = bitClear(&slot_wanted, me);
        unenrollLocked(me);
    }
}

fn sendSmall(cmds: []const []const u8, resps: []const []u8) bool {
    var idx_buf: [2]u8 = undefined;
    var ticket_buf: [2]Ticket = undefined;
    std.debug.assert(cmds.len <= idx_buf.len and cmds.len == resps.len);
    const idx = idx_buf[0..cmds.len];
    const tickets = ticket_buf[0..cmds.len];
    const ct = cmdType(cmds[0]);
    if (!takeSlotsLocked(idx, ct)) return false;
    const me = currentPid8();
    for (cmds, resps, idx, tickets) |c, r, i, *t| {
        @memcpy(virt(cmdPhysOf(i))[0..c.len], c);
        @memset(virt(respPhysOf(i))[0..r.len], 0);
        slots[i].owner = me;
        slots[i].cmd_type = cmdType(c);
        t.* = queueLocked(i, c.len, r.len);
    }
    stats.sync += 1;
    q_lock.release();
    kick();
    // Not ok: the slots were given up or taken by a reset, not ours to free.
    if (waitSlots(tickets, ct) != .ok) return false;
    return takeResponses(tickets, resps);
}

// --- Commands ---

/// Send a command and wait for its response: in a slot when both fit, else
/// through the large buffer. False when it could not be sent, got no answer
/// in time, or the device was reset meanwhile.
pub fn send(cmd: []const u8, resp: []u8) bool {
    if (cmd.len < @sizeOf(proto.CtrlHdr) or resp.len < @sizeOf(proto.CtrlHdr)) return false;
    if (cmd.len <= SLOT_CMD_MAX and resp.len <= SLOT_RESP_MAX) {
        return sendSmall(&[_][]const u8{cmd}, &[_][]u8{resp});
    }
    if (cmd.len > LARGE_CMD_MAX or resp.len > LARGE_RESP_MAX) {
        debug.klog("[virtio-gpu] cmd 0x{X} too large: {d} B, response {d} B\n", .{ cmdType(cmd), cmd.len, resp.len });
        return false;
    }
    const big = largeAcquire() orelse return false;
    defer big.release();
    @memcpy(big.cmd()[0..cmd.len], cmd);
    if (!big.run(cmd.len, resp.len)) return false;
    // Ours until release(): nobody else queues slot 0 without large_lock.
    @memcpy(resp, big.resp()[0..resp.len]);
    return true;
}

pub fn sendCmd(cmd_buf: [*]const u8, cmd_len: u32, resp_buf: [*]u8, resp_len: u32) bool {
    return send(cmd_buf[0..cmd_len], resp_buf[0..resp_len]);
}

/// send() of a command answered by OK_NODATA.
pub fn sendSimpleCmd(cmd_buf: [*]const u8, cmd_len: u32) bool {
    var resp: proto.CtrlHdr = .{};
    if (!send(cmd_buf[0..cmd_len], std.mem.asBytes(&resp))) return false;
    if (resp.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] cmd 0x{X}: error response 0x{X}\n", .{ cmdType(cmd_buf[0..4]), resp.cmd_type });
        return false;
    }
    return true;
}

/// Two commands made available together, one doorbell, one wait. True when
/// both answer OK_NODATA.
pub fn sendPair(cmd0: []const u8, cmd1: []const u8) bool {
    if (cmd0.len > SLOT_CMD_MAX or cmd1.len > SLOT_CMD_MAX) return false;
    var r0: proto.CtrlHdr = .{};
    var r1: proto.CtrlHdr = .{};
    if (!sendSmall(&[_][]const u8{ cmd0, cmd1 }, &[_][]u8{ std.mem.asBytes(&r0), std.mem.asBytes(&r1) })) return false;
    if (r0.cmd_type != proto.RESP_OK_NODATA or r1.cmd_type != proto.RESP_OK_NODATA) {
        debug.klog("[virtio-gpu] pair 0x{X}+0x{X} failed: resp0=0x{X} resp1=0x{X}\n", .{ cmdType(cmd0), cmdType(cmd1), r0.cmd_type, r1.cmd_type });
        return false;
    }
    return true;
}

/// The large buffer for one command, built in place.
pub const Large = struct {
    pub fn cmd(_: Large) [*]volatile u8 {
        return virt(cmd_phys);
    }
    pub fn resp(_: Large) [*]volatile u8 {
        return virt(resp_phys);
    }
    pub fn respHdr(_: Large) *const volatile proto.CtrlHdr {
        return @ptrFromInt(paging.physToVirt(resp_phys));
    }

    /// Send what was built in cmd() and wait for the response in resp().
    pub fn run(_: Large, cmd_len: usize, resp_len: usize) bool {
        std.debug.assert(cmd_len >= @sizeOf(proto.CtrlHdr) and cmd_len <= LARGE_CMD_MAX);
        std.debug.assert(resp_len >= @sizeOf(proto.CtrlHdr) and resp_len <= LARGE_RESP_MAX);
        @memset(virt(resp_phys)[0..resp_len], 0);
        const ct = @as(*const volatile u32, @ptrFromInt(paging.physToVirt(cmd_phys))).*;
        q_lock.acquire();
        slots[LARGE].owner = currentPid8();
        slots[LARGE].cmd_type = ct;
        large_ticket = queueLocked(LARGE, cmd_len, resp_len);
        stats.large += 1;
        q_lock.release();
        kick();
        if (waitSlots(&[_]Ticket{large_ticket.?}, ct) != .ok) return false;
        clflushRange(paging.physToVirt(resp_phys), resp_len);
        return true;
    }

    pub fn release(_: Large) void {
        if (large_ticket) |t| {
            q_lock.acquire();
            // Not ours any more: given up (the device holds it) or reset.
            if (ours(t) and slots[LARGE].state == .returned) {
                freeLocked(LARGE);
            }
            q_lock.release();
            large_ticket = null;
        }
        large_lock.release();
    }
};

/// The use of slot 0 by the large_lock holder (large_lock).
var large_ticket: ?Ticket = null;

/// The large buffer, for one command: build it in cmd(), run(), release().
/// Null while the device still holds the last one, which got no answer.
pub fn largeAcquire() ?Large {
    large_lock.acquire();
    // One a killed holder left behind (releaseMutexesOwnedBy let it go).
    large_ticket = null;
    q_lock.acquire();
    drainForeignLocked();
    const free = slots[LARGE].state == .free;
    q_lock.release();
    if (!free) {
        large_lock.release();
        debug.klog("[virtio-gpu] the large buffer is still with the device\n", .{});
        return null;
    }
    return .{};
}

// --- Posted groups ---

/// Post `cmds` as group `g` and return at once: all of them, or none when
/// that many slots are not free. One doorbell; one IRQ, at the last.
pub fn postGroup(g: *Group, cmds: []const []const u8) bool {
    std.debug.assert(cmds.len > 0 and cmds.len <= MAX_GROUP);
    std.debug.assert(@atomicLoad(bool, &g.done, .acquire));
    q_lock.acquire();
    _ = drainLocked(); // no batch of ours to finish: g was done
    const idx = g.idx[0..cmds.len];
    if (!findFreeLocked(idx)) {
        q_lock.release();
        return false;
    }
    for (cmds, idx) |c, i| {
        @memcpy(virt(cmdPhysOf(i))[0..c.len], c);
        @memset(virt(respPhysOf(i))[0..@sizeOf(proto.CtrlHdr)], 0);
        slots[i].posted = true;
        slots[i].group = g;
        slots[i].cmd_type = cmdType(c);
        _ = queueLocked(i, c.len, @sizeOf(proto.CtrlHdr));
    }
    g.count = @intCast(cmds.len);
    g.outstanding = g.count;
    g.failed = false;
    g.end = ctrl_vq.availIdx().*;
    @atomicStore(bool, &g.done, false, .release);
    @atomicStore(u8, &posted_out, posted_out + g.count, .release);
    stats.posted += g.count;
    // A second group out at once is armed for at its first completion
    // (armLocked counts it as loose posted commands).
    if (group_out == null) group_out = g;
    armLocked();
    q_lock.release();
    kick();
    return true;
}

pub fn groupDone(g: *const Group) bool {
    return @atomicLoad(bool, &g.done, .acquire);
}

/// How group `g` went: true if every command answered OK_NODATA, null
/// while some are still out (as of the last collect).
pub fn groupResult(g: *const Group) ?bool {
    if (!groupDone(g)) return null;
    return !g.failed;
}

/// Give group `g` up: its commands still out stay the device's until it
/// returns them.
pub fn abandonGroup(g: *Group) void {
    q_lock.acquire();
    defer q_lock.release();
    _ = drainLocked(); // the caller reaps g itself
    if (groupDone(g)) return;
    var dropped: u8 = 0;
    for (g.idx[0..g.count]) |i| {
        const s = &slots[i];
        // A slot of the group that came back may carry another command now.
        if (s.state != .queued or s.group != g) continue;
        s.state = .abandoned;
        s.group = null;
        s.posted = false;
        dropped += 1;
        stats.abandoned += 1;
    }
    @atomicStore(u8, &posted_out, posted_out - dropped, .release);
    g.outstanding = 0;
    g.failed = true;
    if (group_out == g) group_out = null;
    @atomicStore(bool, &g.done, true, .release);
    armLocked();
}

/// Wait a while for group `g`: until it comes back, a tick passes, or
/// (polled) the used index moves. The caller collects and re-checks.
pub fn waitGroup(g: *Group) void {
    if (!irqWaitOk()) {
        collect();
        if (groupDone(g)) return;
        var d = Deadline.ms(1, "virtio-gpu group (polled)");
        pollPast(consumed(), &d);
        return;
    }
    const me = currentPid8();
    @atomicStore(u8, &posted_waiter, me, .release);
    defer @atomicStore(u8, &posted_waiter, NO_PID, .release);
    collect();
    if (groupDone(g)) return;
    sleepOn(proto.CMD_RESOURCE_FLUSH);
}

/// Collect completions and re-arm the IRQ, waking whoever they were for.
/// For the present engine and its softirq, which reap a finished batch
/// themselves.
pub fn collect() void {
    q_lock.acquire();
    _ = drainLocked();
    armLocked();
    q_lock.release();
}

/// Task `pid` ended, perhaps asleep here: its slots go. One the device still
/// holds stays given up until it comes back.
pub fn releaseTask(pid: u8) void {
    if (slot_count == 0) return;
    q_lock.acquire();
    defer q_lock.release();
    var freed = false;
    for (slots[0..slot_count], 0..) |*s, i| {
        if (s.waiter == pid) @atomicStore(u8, &s.waiter, NO_PID, .release);
        if (s.owner != pid) continue;
        switch (s.state) {
            .returned => {
                freeLocked(@intCast(i));
                freed = true;
            },
            .queued => {
                s.state = .abandoned;
                s.owner = NO_PID;
                stats.abandoned += 1;
            },
            .free, .abandoned => {},
        }
    }
    _ = bitClear(&slot_wanted, pid);
    unenrollLocked(pid);
    if (@atomicLoad(u8, &posted_waiter, .acquire) == pid) @atomicStore(u8, &posted_waiter, NO_PID, .release);
    if (freed) wakeSlotWantersLocked();
    armLocked();
}

/// Whether a panic-time flush could block here: the queue lock held, maybe
/// by a CPU that will never run again. Snapshot.
pub fn busy() bool {
    return @atomicLoad(u32, &q_lock.next_ticket, .acquire) != @atomicLoad(u32, &q_lock.now_serving, .acquire);
}

// --- IRQ and the lost-IRQ backstop ---

/// Wakes the waiters of what came back; they collect it themselves.
/// Posted commands are collected by ksoftirqd (.virtio_gpu softirq), and so
/// is a completion nobody waits on while others sleep (a given-up command,
/// say): it spent the IRQ armed for them, and the collect re-arms it.
pub fn virtioGpuIrqHandler() callconv(.c) void {
    vg.virtio_gpu_irq_count +%= 1;
    const cpu = smp.myCpu();
    if (cpu.cpu_id < vg.virtio_gpu_irq_per_cpu.len) vg.virtio_gpu_irq_per_cpu[cpu.cpu_id] +%= 1;
    if (emergency()) return;

    const used = usedIdxCoherent(&ctrl_vq);
    var i = consumed();
    var n: u16 = 0;
    var unclaimed = false;
    while (i != used and n < ctrl_vq.queue_size) : ({
        i +%= 1;
        n += 1;
    }) {
        const id = usedId(i);
        if (id & 1 != 0 or id / 2 >= slot_count) continue;
        const w = @atomicLoad(u8, &slots[id / 2].waiter, .acquire);
        if (w != NO_PID) irqWake(w, cpu) else unclaimed = true;
    }
    const posted = @atomicLoad(u8, &posted_out, .acquire) != 0;
    if (unclaimed and !posted and @atomicLoad(u8, &sleepers, .monotonic) != 0) {
        _ = @import("../../../irq/softirq.zig").raise(.virtio_gpu);
    }
    if (posted) {
        _ = @import("../../../irq/softirq.zig").raise(.virtio_gpu);
        cpu.dynirq_preempt_pending = true;
        const pw = @atomicLoad(u8, &posted_waiter, .acquire);
        if (pw != NO_PID) irqWake(pw, cpu);
    }
}

fn irqWake(pid: u8, cpu: anytype) void {
    const process = @import("../../../proc/process.zig");
    const kind = @atomicLoad(process.WaitKind, &process.procs[pid].wait_kind, .acquire);
    if (kind != .gpu_io and kind != .none) return;
    const wakelat = @import("../../../debug/wakelat.zig");
    const sched = @import("../../../proc/sched.zig");
    wakelat.noteGpuIrq(pid);
    wakelat.hintWake(pid, .gpu_io);
    sched.wake(pid);
    vg.virtio_gpu_waiter_wakes +%= 1;
    // Queued on this CPU: the dynirq epilogue runs it if it outranks the
    // current task. On another CPU, wake() sent the reschedule IPI.
    if (sched.wakeupPreemptsLocal(pid)) cpu.dynirq_preempt_pending = true;
}

/// Whether irq0's backstop has anything for tickSweep: posted commands out,
/// present damage pending, or completions nobody collected (a lost IRQ).
pub fn sweepWanted() bool {
    if (!vg.active or !use_msix or slot_count == 0) return false;
    if (@atomicLoad(u8, &posted_out, .acquire) != 0 or present.wantsService()) return true;
    return usedIdxCoherent(&ctrl_vq) != consumed();
}

/// ksoftirqd: after the IRQ for posted commands, or irq0's backstop for a
/// lost one. Collects, then lets the present engine reap and resubmit.
pub fn tickSweep() void {
    if (!vg.active or !use_msix or slot_count == 0) return;
    collect();
    present.serviceFromSoftirq();
}

/// For the yield-loop / stuck-waiter detectors: the queue as it stands,
/// read without its lock. `target` is the waiter's command type.
pub fn dumpWaiterForTarget(target: u32) void {
    debug.klog("  virtio-gpu queue (waiting on cmd 0x{X}):\n", .{target});
    debug.klog("    active={any} use_msix={any} msix_safe={any} event_idx={any} polled={any}\n", .{
        vg.active, use_msix, vg.msix_safe_to_use, use_event_idx, force_polled,
    });
    if (!vg.active or slot_count == 0) return;
    const hw_used = usedIdxCoherent(&ctrl_vq);
    const avail = ctrl_vq.availIdx().*;
    const done = consumed();
    debug.klog("    collected={d} used={d} avail={d} sleepers={d} posted_out={d} irqs={d} wakes={d}\n", .{
        done, hw_used, avail, sleepers, @atomicLoad(u8, &posted_out, .acquire), vg.virtio_gpu_irq_count, vg.virtio_gpu_waiter_wakes,
    });
    for (slots[0..slot_count], 0..) |s, i| {
        if (s.state == .free) continue;
        debug.klog("    slot {d}: {s}{s} cmd=0x{X} owner={d} waiter={d}\n", .{
            i, @tagName(s.state), if (s.posted) " posted" else "", s.cmd_type, s.owner, s.waiter,
        });
    }
    const st = stats;
    debug.klog("    sync={d} large={d} posted={d} sleeps={d} slot_waits={d} abandoned={d} late={d} stray={d}\n", .{
        st.sync, st.large, st.posted, st.sleeps, st.slot_waits, st.abandoned, st.late, st.stray,
    });
    present.dumpState();
    if (hw_used != done) {
        debug.klog("    ===> device returned commands nobody collected yet (lost IRQ? the backstop collects them)\n", .{});
    } else if (avail != done) {
        debug.klog("    ===> the device holds commands it has not answered: a host-side wait\n", .{});
    } else {
        debug.klog("    (queue idle)\n", .{});
    }
}
