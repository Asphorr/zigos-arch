//! io_uring Phase 3 — per-IRQ async NVMe (A1).
//!
//! Phase 2 (worker model) parks the worker on `.nvme_io` inside vfs.read →
//! nvme.ioCommandAsync per op, so N submits complete serially (worker can
//! only block on one CID at a time). Phase 3 adds opcodes
//! `OP_NVME_READ` / `OP_NVME_WRITE` that bypass the FS stack and submit
//! directly via `nvme.submitAsyncCallback`. Each in-flight op stores its
//! context in a per-instance `pending[]` slot; NVMe's IRQ-side reapCq
//! invokes our callback from IRQ context, which sets `done=true` and wakes
//! the worker. The worker scans pending on every wake, copies bounce →
//! user for completed reads, posts CQEs, and resumes submitting.
//!
//! Result: a user that submits N NVMe reads sees them complete with a
//! wall-time close to 1×latency instead of N×latency. The NVMe queue
//! (Q_DEPTH=16) is the in-flight cap.
//!
//! Phase 3 scope:
//!   - OP_NVME_READ (raw LBA, bypasses VFS).
//!   - OP_NVME_WRITE returns invalid (.invalid). Needs the nvme API split
//!     into alloc-CID + submit-prepared so the bounce buffer can be
//!     populated BEFORE the device DMAs it. Wired in the next iteration.
//!   - OP_NOP, OP_READ, OP_WRITE (worker model from Phase 2) unchanged.
//!
//! NVMe-op SQE encoding:
//!   sqe.opcode = OP_NVME_READ
//!   sqe.fd     = ctrl_idx (0 = primary, 1 = secondary)
//!   sqe.off    = LBA (32-bit; truncated)
//!   sqe.addr   = user buffer VA
//!   sqe.len    = SECTORS (NOT bytes) — bytes = sectors * block_size
//!
//! Skipped (Phase 4+): SQPOLL, fixed buffers/files, ext2-async wiring,
//! ops beyond NVMe + R/W/NOP.

const std = @import("std");
const process = @import("../proc/process.zig");
const shm = @import("../mm/shm.zig");
const paging = @import("../mm/paging.zig");
const vfs = @import("../fs/vfs.zig");
const debug = @import("../debug/debug.zig");
const smp = @import("smp.zig");
const pcid_mod = @import("pcid.zig");
const fault = @import("../proc/fault.zig");
const protect = @import("protect.zig");
const lifecycle = @import("../proc/lifecycle.zig");
const config = @import("../config.zig");
const memmap = @import("../mm/memmap.zig");
const nvme = @import("../driver/nvme.zig");

const common = @import("syscall/common.zig");
const E_INVAL = common.E_INVAL;
const E_NOMEM = common.E_NOMEM;
const E_FAULT = common.E_FAULT;
const E_BADF = common.E_BADF;

const fdpoll = @import("fdpoll.zig");

pub const OP_NOP: u8 = 0;
pub const OP_READ: u8 = 1;
pub const OP_WRITE: u8 = 2;
pub const OP_NVME_READ: u8 = 3;
pub const OP_NVME_WRITE: u8 = 4;
/// Wait until `fd` is ready for the events specified in `sqe.len`
/// (POLLIN|POLLOUT|... — see fdpoll.zig). Returns the ready mask in
/// CQE.res, or a negative errno on bad fd / out-of-waiters. Submitted
/// like any other SQE; completion happens when the underlying fd's
/// subsystem (pipe/console/etc) calls fdpoll.wakePollers.
pub const OP_POLL: u8 = 5;

pub const MAX_ENTRIES: u32 = 256;
pub const MIN_ENTRIES: u32 = 1;
pub const MAX_INSTANCES_PER_PROC: u8 = 4;
pub const MAX_INSTANCES_TOTAL: u8 = 16;

/// In-flight cap per instance. Sized to match NVMe Q_DEPTH so the worker
/// can keep the device's queue saturated without the pending table
/// becoming the bottleneck before NVMe does.
const MAX_PENDING_PER_INSTANCE: u8 = 16;

// Small Linux-canonical errno values that fit in i32 (the kernel's wider
// 0xFFFFFFxx range doesn't). Mirrored from Phase 2 — used as CQE.res when
// the SQE failed validation.
const ERES_BADF: i32 = -9;
const ERES_FAULT: i32 = -14;
const ERES_INVAL: i32 = -22;
const ERES_IO: i32 = -5;
const ERES_NOMEM: i32 = -12;

pub const Sqe = extern struct {
    opcode: u8,
    flags: u8,
    _pad1: u16,
    fd: u32,
    off: u64,
    addr: u64,
    len: u32,
    user_data: u64,
    _pad2: [28]u8,
};

pub const Cqe = extern struct {
    user_data: u64,
    res: i32,
    flags: u32,
};

/// Shared kernel↔userspace ring header — mmap'd into the owning process
/// at `Instance.user_va`. Access-tag legend (see docs/STYLE.md): the
/// SQ/CQ counters are `(u)` user-mmap-shared (kernel uses @atomicLoad
/// .acquire on counters the producer-side owns and @atomicStore .release
/// on the ones we produce). Counters tagged with their *kernel* role —
/// "kernel-consumer" reads with .acquire, "kernel-producer" writes with
/// .release. Reference implementation for the (u) discipline.
pub const RingHeader = extern struct {
    sq_head: u32, // (u) kernel-producer — kernel writes .release as SQEs are consumed
    sq_tail: u32, // (u) kernel-consumer — userspace writes .release after filling an SQE
    sq_mask: u32, // (c) set at setup
    sq_entries: u32, // (c)
    cq_head: u32, // (u) kernel-consumer — userspace writes .release after reading a CQE
    cq_tail: u32, // (u) kernel-producer — kernel writes .release after posting a CQE
    cq_mask: u32, // (c)
    cq_entries: u32, // (c)
    sqes_offset: u32, // (c)
    cqes_offset: u32, // (c)
    _pad: [24]u8,
};
comptime {
    // ABI contract — userspace libc maps this struct directly; size +
    // offsets must stay stable. 32-byte trailer + 10×u32 = 72 → padded to 96.
    const a = std.debug.assert;
    a(@sizeOf(RingHeader) == 64);
    a(@offsetOf(RingHeader, "sq_head") == 0);
    a(@offsetOf(RingHeader, "sq_tail") == 4);
    a(@offsetOf(RingHeader, "sq_mask") == 8);
    a(@offsetOf(RingHeader, "cq_head") == 16);
    a(@offsetOf(RingHeader, "cq_tail") == 20);
    a(@offsetOf(RingHeader, "sqes_offset") == 32);
    a(@offsetOf(RingHeader, "cqes_offset") == 36);
}

/// One async NVMe op in flight. Allocated by the worker before submit,
/// populated with the SQE-derived parameters + the CQE-side `user_data`,
/// then handed to `nvme.submitAsyncCallback` with `ctx = @intFromPtr(self)`.
/// The IRQ callback writes `success` + `done`; the worker drains on wake.
const PendingOp = struct {
    // Access-tag legend (see docs/STYLE.md). `in_use` and `done` are the
    // synchronization points: `in_use` flips false→true under the
    // submitter (allocPendingSlot) and back via worker drain; `done`
    // flips false→true under the IRQ-callback / fdpoll-callback. Other
    // fields are written by the submitter BEFORE in_use=true (or BEFORE
    // ringing the NVMe doorbell), then read by the worker AFTER it
    // observes done=true — the release/acquire pair on done carries
    // them. Fields tagged "(done-fenced)" mean "covered by done's
    // release/acquire ordering, no explicit atomic needed."
    in_use: bool = false, // (a) submitter sets, worker clears
    instance_id: u8 = 0xFF, // (done-fenced) read by IRQ callback (line ~258) via @ptrFromInt(ctx)
    op: u8 = 0, // (done-fenced)
    ctrl_idx: u32 = 0, // (done-fenced)
    packed_cid: u16 = 0, // (done-fenced)
    user_addr: usize = 0, // (done-fenced)
    sectors: u32 = 0, // (done-fenced)
    bytes: u32 = 0, // (done-fenced)
    cqe_user_data: u64 = 0, // (done-fenced)
    /// IRQ-callback writes with Release; worker reads with Acquire. All
    /// other fields are written by the worker before submit; the worker
    /// re-reads them after observing done=true, but they were never
    /// re-written by any other context, so no atomic needed.
    done: bool = false, // (a) IRQ / fdpoll callback writes .release; worker reads .acquire
    success: bool = false, // (done-fenced) IRQ callback writes plain before done=true
    /// OP_POLL only — set by fdpoll's completion callback to the ready
    /// mask that triggered the wake. Worker reads after observing
    /// `done` with Acquire, then posts CQE.res = poll_mask.
    poll_mask: u16 = 0, // (done-fenced) fdpoll callback writes plain before done=true
    /// OP_POLL only — index into fdpoll.waiters[] for the registered
    /// waiter, so on instance shutdown we can drop the registration
    /// before recycling the pending slot. 0xFF = no waiter registered.
    fdpoll_waiter_idx: u8 = 0xFF, // owner: worker-only after allocPendingSlot
    /// Slot generation. Bumped on every allocPendingSlot. Captured by
    /// fdpoll.register and fired back through pollCompletionCallback so a
    /// deferred wake firing on a since-recycled slot is a no-op instead
    /// of clobbering the new op's poll_mask/done. Pre-fix, the race was:
    /// wakePollers snapshots the waiter, drops the lock, slot drains +
    /// allocPendingSlot reassigns it, deferred cb lands on the wrong op.
    /// 16 bits gives 65 535 generations before wrap — far more than the
    /// 64-deep pending array could chew through between a register and
    /// its matching wake.
    gen: u16 = 0, // (a) bumped by allocPendingSlot; read by pollCompletionCallback
};

const Instance = struct {
    // Access-tag legend (see docs/STYLE.md). The Instance's lifecycle is
    // setup() (under global iouring `lock`) → worker_pid wake → worker
    // drains until exit_requested → self-recycle. `in_use` is the
    // single source of truth for "this slot is alive."
    in_use: bool = false, // (a) setup writes .release; worker self-clears at recycle
    exit_requested: bool = false, // (a) releaseAllForPid sets; worker reads
    owner_pid: u32 = 0xFFFFFFFF, // (c) set under iouring lock in setup; self-cleared at recycle
    user_va: usize = 0, // (c)
    region_pages: u32 = 0, // (c)
    entries: u32 = 0, // (c)
    shm_id: u32 = 0xFFFFFFFF, // (c)
    header_kvirt: usize = 0, // (c)
    worker_pid: u32 = 0xFFFFFFFF, // (c) — final field set by setup, signals "fully constructed"
    pending: [MAX_PENDING_PER_INSTANCE]PendingOp = [_]PendingOp{.{}} ** MAX_PENDING_PER_INSTANCE,
    /// Suppress spurious wakes to .iouring_cq parkers. Set by enter() to its
    /// min_complete before parking; cleared on exit. Worker checks before
    /// calling wakeIoUringCqWaiters — only wakes when ready ≥ cq_min_complete.
    /// Without this, a 16-deep concurrent submit triggered 16 separate IRQs →
    /// 16 wake-and-re-park cycles for the app (each adds a ~4 ms schedule
    /// round-trip), turning a single wait into N × round-trip latency.
    /// 0 means "no one is parked / no waiter cares" — worker skips the wake.
    cq_min_complete: u32 = 0, // (a) enter() writes before park, worker reads
};

var instances: [MAX_INSTANCES_TOTAL]Instance = [_]Instance{.{}} ** MAX_INSTANCES_TOTAL;
var lock: @import("../proc/spinlock.zig").SpinLock = .{};

inline fn nextPow2(v: u32) u32 {
    if (v <= 1) return 1;
    var r: u32 = 1;
    while (r < v) r <<= 1;
    return r;
}

fn regionSize(entries: u32) usize {
    const sz: usize = @sizeOf(RingHeader) + entries * @sizeOf(Sqe) + entries * @sizeOf(Cqe);
    return (sz + 0xFFF) & ~@as(usize, 0xFFF);
}

inline fn kvirtAt(inst: *const Instance, off: usize) usize {
    const page = off / 0x1000;
    const in_page = off % 0x1000;
    const phys = shm.frameAt(inst.shm_id, @intCast(page)) orelse @panic("iouring kvirtAt: shm frame gone");
    return paging.physToVirt(phys) + in_page;
}

fn readSqe(inst: *Instance, idx_masked: u32) Sqe {
    const off: usize = @sizeOf(RingHeader) + idx_masked * @sizeOf(Sqe);
    const p: *const Sqe = @ptrFromInt(kvirtAt(inst, off));
    return p.*;
}

fn writeCqe(inst: *Instance, idx_masked: u32, cqe: Cqe) void {
    const off: usize = @sizeOf(RingHeader) + inst.entries * @sizeOf(Sqe) + idx_masked * @sizeOf(Cqe);
    const p: *Cqe = @ptrFromInt(kvirtAt(inst, off));
    p.* = cqe;
}

fn countOwnedLocked(pid: u32) u8 {
    var n: u8 = 0;
    // By-pointer iter: per-Instance memcpy onto kstack is ~12 KB (pending
    // array × 16). By-value loop overflows kstack at this size.
    for (&instances) |*it| if (@atomicLoad(bool, &it.in_use, .acquire) and it.owner_pid == pid) {
        n += 1;
    };
    return n;
}

fn findByVa(pid: u32, va: usize) ?*Instance {
    for (&instances) |*it| if (@atomicLoad(bool, &it.in_use, .acquire) and it.owner_pid == pid and it.user_va == va) {
        return it;
    };
    return null;
}

/// Allocate a free pending slot. Single-writer (the worker) so no CAS
/// loop needed — but mark `in_use` with Release so the IRQ callback's
/// Acquire-load on `done` synchronizes-with all the field writes that
/// follow this allocation.
fn allocPendingSlot(inst: *Instance) ?u8 {
    for (&inst.pending, 0..) |*p, i| {
        if (@atomicLoad(bool, &p.in_use, .acquire)) continue;
        // Preserve+bump gen across the field reset so the new slot has a
        // unique generation. Deferred wakes from the previous incarnation
        // compare against `expected_gen` and short-circuit.
        const next_gen = p.gen +% 1;
        p.* = .{};
        p.gen = next_gen;
        @atomicStore(bool, &p.in_use, true, .release);
        return @intCast(i);
    }
    return null;
}

fn pendingInFlightCount(inst: *Instance) u32 {
    var n: u32 = 0;
    for (&inst.pending) |*p| {
        if (@atomicLoad(bool, &p.in_use, .acquire)) n += 1;
    }
    return n;
}

/// Called from NVMe IRQ context (reapCq) when the CQE for an op submitted
/// via `submitAsyncCallback` arrives. MUST stay brief: just record the
/// outcome and wake the worker.
///
/// IRQ-context guarantee chain: NVMe's reapCq runs with `cq_lock` held
/// and IRQs disabled. The wake here calls into the scheduler's run-queue
/// lock — already established as IRQ-safe by `proc.wake` from the
/// non-callback NVMe path (line `proc.wake(pid)` in nvme.reapCq).
fn nvmeCompletionCallback(ctx: usize, success: bool, sc: u16) callconv(.c) void {
    _ = sc;
    const p: *PendingOp = @ptrFromInt(ctx);
    // Order: write success first (plain), then done with Release. Worker
    // observes done with Acquire, then reads success — release-acquire on
    // done synchronizes the success read with this write.
    p.success = success;
    @atomicStore(bool, &p.done, true, .release);
    if (p.instance_id < MAX_INSTANCES_TOTAL) {
        process.wakeIoUringWorker(@intCast(p.instance_id));
    }
}

/// fdpoll's completion callback for OP_POLL. Called from whatever
/// subsystem flipped the fd's readiness (pipe.write, desktop.pushEvent,
/// etc.) — may be on any CPU, not necessarily the instance's worker
/// CPU. Mirrors `nvmeCompletionCallback`'s shape: store the result,
/// flip `done` with Release, wake the worker so it posts the CQE via
/// the normal drainCompletions path.
fn pollCompletionCallback(inst_id: u8, slot_idx: u8, expected_gen: u16, ready_mask: u16) void {
    if (inst_id >= MAX_INSTANCES_TOTAL) return;
    const inst = &instances[inst_id];
    if (!@atomicLoad(bool, &inst.in_use, .acquire)) return;
    if (slot_idx >= inst.pending.len) return;
    const p = &inst.pending[slot_idx];
    // Defend against stale wakes after the slot was recycled — the
    // worker clears in_use after posting the CQE; fdpoll.unregister
    // should have dropped the waiter before that, but a wake racing
    // with shutdown can still arrive.
    if (!@atomicLoad(bool, &p.in_use, .acquire)) return;
    // Recycled-slot guard: if allocPendingSlot bumped gen since the
    // waiter was registered, the slot now belongs to a different op
    // and we'd clobber its poll_mask/done. Closes the lifecycle race.
    if (p.gen != expected_gen) return;
    if (p.op != OP_POLL) return;
    p.poll_mask = ready_mask;
    @atomicStore(bool, &p.done, true, .release);
    process.wakeIoUringWorker(inst_id);
}

/// Called from `setup` the first time it runs. Registers the OP_POLL
/// completion path with fdpoll; idempotent because we compare-and-swap
/// against null. fdpoll has no other consumer right now, so storing
/// our pointer here is safe.
fn ensurePollCallbackRegistered() void {
    @atomicStore(
        ?*const fn (inst_id: u8, slot_idx: u8, expected_gen: u16, ready_mask: u16) void,
        &fdpoll.completion_callback,
        pollCompletionCallback,
        .release,
    );
}

/// Execute one non-NVMe Sqe synchronously. For OP_READ/WRITE the worker
/// swaps to the owner's CR3 so user-buffer dereferences resolve. vfs.read/
/// write take the owner's PCB so fd_table lookups use the right table.
///
/// Acquires owner_leader.as_lock around the validation + CR3 swap + vfs
/// call to serialize against concurrent sysMunmap/sysMprotect on the
/// owner's own thread (would otherwise unmap pages mid-vfs, causing a
/// kernel-mode #PF that the ring-3-only handler can't service → panic).
/// Plus ensureUserRangeWritableFor breaks COW so the kernel WRITE on the
/// user VA doesn't trap on a fork-shared page. Closes HIGH classes 3+3b
/// reviewer flagged 2026-05-24.
fn executeSyncAsWorker(inst: *Instance, sqe: Sqe) i32 {
    if (inst.owner_pid >= process.MAX_PROCS) return ERES_FAULT;
    const owner_pcb = &process.procs[inst.owner_pid];

    switch (sqe.opcode) {
        OP_NOP => return 0,
        OP_READ, OP_WRITE => {
            if (sqe.fd >= config.MAX_FDS) return ERES_BADF;
            if (!owner_pcb.fd_table[sqe.fd].in_use) return ERES_BADF;
            if (sqe.len == 0) return 0;

            const addr: usize = @intCast(sqe.addr);
            // Subtract-form bound check: avoids ReleaseSafe overflow panic.
            if (addr < memmap.USER_SPACE_START or
                addr > memmap.USER_SPACE_END or
                sqe.len > memmap.USER_SPACE_END - addr)
            {
                return ERES_FAULT;
            }
            const owner_pd_phys: u64 = owner_pcb.page_dir_phys;
            const owner_pcid: u16 = owner_pcb.pcid;
            if (owner_pd_phys == 0) return ERES_FAULT;

            // AS-stability lock. Acquired BEFORE CR3 swap (the swap itself
            // must not span a yield, but Mutex.acquire may yield via
            // blockOnMutex on contention — fine here since CR3 hasn't been
            // touched yet). Released on return via defer.
            const owner_leader = process.leader(owner_pcb);
            owner_leader.as_lock.acquire();
            defer owner_leader.as_lock.release();

            const my_cpu_id = smp.myCpu().cpu_id;
            const kernel_pd_phys = paging.getKernelPageDirPhys();
            pcid_mod.loadCr3(owner_pd_phys, owner_pcid, my_cpu_id);
            defer pcid_mod.loadCr3(kernel_pd_phys, 0, my_cpu_id);

            // Break COW + lazy-fault any missing pages in the range BEFORE
            // vfs touches user memory. For OP_WRITE (vfs reads user buf to
            // write to fd) we only need PRESENT; for OP_READ (vfs writes
            // user buf) we need writable. We always ensure writable — extra
            // strictness is fine for reads (the buffer is meant to receive
            // data; the caller wouldn't pass a R/O page).
            if (!fault.ensureUserRangeWritableFor(owner_pcb, addr, sqe.len)) {
                return ERES_FAULT;
            }

            protect.allowUserAccess();
            defer protect.disallowUserAccess();

            if (sqe.opcode == OP_READ) {
                const buf: [*]u8 = @ptrFromInt(addr);
                const n = vfs.read(owner_pcb, sqe.fd, buf, sqe.len);
                return if (n == 0xFFFFFFFF) ERES_INVAL else @intCast(n);
            } else {
                const buf: [*]const u8 = @ptrFromInt(addr);
                const n = vfs.write(owner_pcb, sqe.fd, buf, sqe.len);
                return if (n == 0xFFFFFFFF) ERES_INVAL else @intCast(n);
            }
        },
        else => return ERES_INVAL,
    }
}

/// Result of attempting to submit an NVMe (or OP_POLL) op.
const SubmitResult = enum {
    /// Successfully submitted; sq_head must be advanced. For NVMe this
    /// means the pending slot is now active and will complete via the
    /// IRQ callback; for OP_POLL it means a waiter was registered with
    /// fdpoll and will complete via pollCompletionCallback.
    ok,
    /// Backend queue is full (NVMe controller's queue OR our pending
    /// table); leave sq_head + pending slot alone so the next loop
    /// iteration retries after some completions free space.
    queue_full,
    /// SQE handled inline — error or already-ready. The CQE has been
    /// posted by the submit fn; sq_head must be advanced. The variant
    /// is named `invalid` for historical NVMe reasons but the OP_POLL
    /// path uses it for both error AND immediate-success completions.
    invalid,
};

/// Submit one OP_POLL SQE. Three outcomes:
///   * fd already ready: post success CQE inline, return .invalid (caller
///     advances sq_head).
///   * fd not ready, pending slot + fdpoll waiter both allocated: return
///     .ok (caller advances sq_head; completion comes via the callback).
///   * fd not ready, pending table full: return .queue_full (do NOT
///     advance sq_head; the next loop iteration retries after a slot
///     frees). fdpoll-registry-full collapses into an inline error CQE
///     instead — it's rare and not worth re-blocking the SQE for.
///   * fd invalid / events == 0 / etc: post error CQE inline, return .invalid.
///
/// sqe.fd  — fd index into the caller's fd_table.
/// sqe.len — events mask (POLLIN/POLLOUT/POLLERR/POLLHUP). Low 16 bits used.
fn submitPollOp(inst: *Instance, inst_id: u8, sqe: Sqe) SubmitResult {
    if (inst.owner_pid >= process.MAX_PROCS) {
        return postInlineCqe(inst, sqe.user_data, ERES_FAULT);
    }
    if (sqe.fd >= config.MAX_FDS) {
        return postInlineCqe(inst, sqe.user_data, ERES_BADF);
    }
    const pid: u8 = @intCast(inst.owner_pid);
    const fd: u8 = @intCast(sqe.fd);
    const events: u16 = @intCast(sqe.len & 0xFFFF);
    if (events == 0) {
        return postInlineCqe(inst, sqe.user_data, ERES_INVAL);
    }

    const handle = fdpoll.resolveFd(pid, fd) orelse {
        return postInlineCqe(inst, sqe.user_data, ERES_BADF);
    };

    // Fast path: already ready. Post CQE immediately, no registration.
    const ready_now = fdpoll.pollMaskHandle(pid, handle);
    const matched_now = ready_now & events;
    if (matched_now != 0) {
        return postInlineCqe(inst, sqe.user_data, @intCast(matched_now));
    }

    // Slow path: register + wait.
    const slot_idx = allocPendingSlot(inst) orelse return .queue_full;
    const p = &inst.pending[slot_idx];
    p.op = OP_POLL;
    p.cqe_user_data = sqe.user_data;
    p.done = false;
    p.poll_mask = 0;
    p.instance_id = inst_id;
    p.fdpoll_waiter_idx = 0xFF;

    const widx = fdpoll.register(inst_id, slot_idx, pid, handle, events, p.gen) orelse {
        // Registry full — free the slot we just took and surface ENOMEM.
        @atomicStore(bool, &p.in_use, false, .release);
        return postInlineCqe(inst, sqe.user_data, ERES_NOMEM);
    };
    p.fdpoll_waiter_idx = widx;

    // Race-close: fd may have flipped to ready BETWEEN our pollMaskHandle
    // check and fdpoll.register. Re-check now that the waiter is enrolled;
    // if it's actually ready, manually fire the completion path so we
    // don't depend on a future wakePollers (which may have already run
    // and missed us). Mirrors the futex enroll-then-recheck handshake.
    const ready_post = fdpoll.pollMaskHandle(pid, handle);
    const matched_post = ready_post & events;
    if (matched_post != 0) {
        // fdpoll might already have cleared the waiter slot if it raced;
        // unregister is idempotent so this is safe either way.
        fdpoll.unregister(widx);
        p.poll_mask = matched_post;
        @atomicStore(bool, &p.done, true, .release);
        // Worker drains in the same loop pass — no wake needed since we
        // ARE the worker.
    }

    return .ok;
}

/// Post a single CQE with `(user_data, res)` and signal CQ waiters.
/// Always returns `.invalid` so OP_POLL callers can `switch` cleanly.
fn postInlineCqe(inst: *Instance, user_data: u64, res: i32) SubmitResult {
    const hdr: *RingHeader = @ptrFromInt(inst.header_kvirt);
    const cq_tail = @atomicLoad(u32, &hdr.cq_tail, .acquire);
    writeCqe(inst, cq_tail & hdr.cq_mask, .{
        .user_data = user_data,
        .res = res,
        .flags = 0,
    });
    @atomicStore(u32, &hdr.cq_tail, cq_tail +% 1, .release);
    const inst_id: u32 = @intCast((@intFromPtr(inst) - @intFromPtr(&instances[0])) / @sizeOf(Instance));
    process.wakeIoUringCqWaiters(inst_id);
    return .invalid;
}

/// Submit one NVMe SQE asynchronously. On `.ok`, the pending slot is now
/// active; the worker will drain it after the IRQ callback fires.
/// On `.queue_full` or `.invalid`, the pending slot has been freed.
fn submitNvmeOp(inst: *Instance, inst_id: u8, slot_idx: u8, sqe: Sqe) SubmitResult {
    const p = &inst.pending[slot_idx];

    const ctrl_idx: u32 = sqe.fd;
    const lba: u32 = @truncate(sqe.off);
    const sectors: u32 = sqe.len;

    if (ctrl_idx >= nvme.controllerCount()) {
        @atomicStore(bool, &p.in_use, false, .release);
        return .invalid;
    }
    const block_size = nvme.controllerBlockSize(ctrl_idx);
    if (block_size == 0) {
        @atomicStore(bool, &p.in_use, false, .release);
        return .invalid;
    }
    if (sectors == 0 or sectors > nvme.maxSectorsPerCmd()) {
        @atomicStore(bool, &p.in_use, false, .release);
        return .invalid;
    }
    const bytes: u32 = sectors * block_size;

    const user_addr: usize = @intCast(sqe.addr);
    // Subtract-form bound check: avoids the `user_addr + bytes` overflow
    // panic ReleaseSafe would trip on a maliciously-large addr.
    if (user_addr < memmap.USER_SPACE_START or
        user_addr > memmap.USER_SPACE_END or
        bytes > memmap.USER_SPACE_END - user_addr)
    {
        @atomicStore(bool, &p.in_use, false, .release);
        return .invalid;
    }

    if (inst.owner_pid >= process.MAX_PROCS) {
        @atomicStore(bool, &p.in_use, false, .release);
        return .invalid;
    }
    if (process.procs[inst.owner_pid].page_dir_phys == 0) {
        @atomicStore(bool, &p.in_use, false, .release);
        return .invalid;
    }

    if (sqe.opcode != OP_NVME_READ) {
        // OP_NVME_WRITE deferred — needs nvme alloc/submit API split so
        // the bounce buffer can be populated before the doorbell.
        debug.klog("[iouring] OP_NVME_WRITE not yet implemented (sqe.user_data=0x{X})\n", .{sqe.user_data});
        @atomicStore(bool, &p.in_use, false, .release);
        return .invalid;
    }

    // Fill the pending slot. These writes are observed by the IRQ callback
    // ONLY after it does an Acquire-load on `done`; submitAsyncCallback's
    // io_lock release is the happens-before edge between these writes and
    // the device-side SQE pickup, so the callback (which cannot fire until
    // the device processes our SQE) will always see them.
    p.instance_id = inst_id;
    p.op = sqe.opcode;
    p.ctrl_idx = ctrl_idx;
    p.user_addr = user_addr;
    p.sectors = sectors;
    p.bytes = bytes;
    p.cqe_user_data = sqe.user_data;
    p.done = false;
    p.success = false;

    const IO_READ: u8 = 0x02;
    var packed_cid: u16 = 0;
    const ok = nvme.submitAsyncCallback(
        ctrl_idx,
        IO_READ,
        lba,
        sectors,
        &nvmeCompletionCallback,
        @intFromPtr(p),
        &packed_cid,
    );
    if (!ok) {
        @atomicStore(bool, &p.in_use, false, .release);
        return .queue_full;
    }
    p.packed_cid = packed_cid;
    return .ok;
}

/// Drain one completed pending slot. Copies bounce → user (for reads),
/// posts the CQE, releases the NVMe CID, frees the slot.
///
/// Acquires owner_leader.as_lock around the CR3 swap + ensureUserRangeWritableFor
/// + memcpy. Lock-then-swap order is correct (Mutex may yield on
/// contention; CR3 must not span a yield). ensureUserRangeWritableFor
/// breaks any COW page in the range so the kernel WRITE doesn't trap as
/// kernel-mode #PF. Closes HIGH classes 3+3b reviewer flagged 2026-05-24.
fn handleCompletion(inst: *Instance, p: *PendingOp) void {
    // OP_POLL completes via fdpoll.wakePollers (not NVMe IRQ), no CID
    // to release, no bounce copy. Just post the ready mask and free
    // the slot. Branch sits ahead of the NVMe-shaped path because the
    // shared epilogue calls nvme.releaseAsyncCid unconditionally.
    if (p.op == OP_POLL) {
        const hdr: *RingHeader = @ptrFromInt(inst.header_kvirt);
        const cq_tail = @atomicLoad(u32, &hdr.cq_tail, .acquire);
        writeCqe(inst, cq_tail & hdr.cq_mask, .{
            .user_data = p.cqe_user_data,
            .res = @intCast(p.poll_mask),
            .flags = 0,
        });
        @atomicStore(u32, &hdr.cq_tail, cq_tail +% 1, .release);
        // fdpoll already cleared its waiter slot before invoking our
        // callback (in wakePollers), so no fdpoll.unregister needed.
        p.fdpoll_waiter_idx = 0xFF;
        @atomicStore(bool, &p.in_use, false, .release);
        return;
    }

    const success = p.success; // Already synchronized via Acquire on done.
    var res: i32 = if (success) @intCast(p.bytes) else ERES_IO;

    if (success and p.op == OP_NVME_READ) {
        if (inst.owner_pid >= process.MAX_PROCS) {
            res = ERES_FAULT;
        } else copy: {
            const owner_pcb = &process.procs[inst.owner_pid];
            if (owner_pcb.page_dir_phys == 0) {
                res = ERES_FAULT;
                break :copy;
            }

            const owner_leader = process.leader(owner_pcb);
            owner_leader.as_lock.acquire();
            defer owner_leader.as_lock.release();

            const my_cpu_id = smp.myCpu().cpu_id;
            const kernel_pd_phys = paging.getKernelPageDirPhys();
            pcid_mod.loadCr3(owner_pcb.page_dir_phys, owner_pcb.pcid, my_cpu_id);
            defer pcid_mod.loadCr3(kernel_pd_phys, 0, my_cpu_id);

            if (!fault.ensureUserRangeWritableFor(owner_pcb, p.user_addr, p.bytes)) {
                res = ERES_FAULT;
                break :copy;
            }

            const bounce_phys = nvme.bounceBufPhys(p.ctrl_idx, p.packed_cid) orelse {
                res = ERES_FAULT;
                break :copy;
            };

            protect.allowUserAccess();
            defer protect.disallowUserAccess();

            const dst: [*]u8 = @ptrFromInt(p.user_addr);
            const src: [*]const u8 = @ptrFromInt(paging.physToVirt(bounce_phys));
            @memcpy(dst[0..p.bytes], src[0..p.bytes]);
        }
    }

    nvme.releaseAsyncCid(p.ctrl_idx, p.packed_cid);

    const hdr: *RingHeader = @ptrFromInt(inst.header_kvirt);
    const cq_tail = @atomicLoad(u32, &hdr.cq_tail, .acquire);
    writeCqe(inst, cq_tail & hdr.cq_mask, .{
        .user_data = p.cqe_user_data,
        .res = res,
        .flags = 0,
    });
    @atomicStore(u32, &hdr.cq_tail, cq_tail +% 1, .release);

    @atomicStore(bool, &p.in_use, false, .release);
}

/// Drain every completed pending slot. Returns the count drained — the
/// worker uses this to decide whether to wake CQ waiters.
fn drainCompletions(inst: *Instance) u32 {
    var n: u32 = 0;
    for (&inst.pending) |*p| {
        if (!@atomicLoad(bool, &p.in_use, .acquire)) continue;
        if (!@atomicLoad(bool, &p.done, .acquire)) continue;
        handleCompletion(inst, p);
        n += 1;
    }
    return n;
}

/// Per-instance worker entry point. Spawned by `setup` via createKernelTask.
/// Self-discovers its instance id by scanning the table for the entry whose
/// `worker_pid` matches its own pid — set by setup before the worker is
/// awakened.
///
/// Main loop on each pass:
///   1. Drain completed pending NVMe ops (post CQEs, free slots).
///   2. Pull SQEs and either submit them async (NVMe ops) or execute
///      synchronously (NOP/READ/WRITE).
///   3. Park on .iouring_work until either enter() (new submission) or
///      the NVMe IRQ callback (completion) wakes us.
fn workerLoop() callconv(.c) noreturn {
    const my_pid = process.getCurrentPid();
    var inst_id: u8 = 0xFF;
    while (inst_id == 0xFF) {
        for (&instances, 0..) |*it, i| if (@atomicLoad(bool, &it.in_use, .acquire) and it.worker_pid == my_pid) {
            inst_id = @intCast(i);
            break;
        };
        if (inst_id == 0xFF) {
            process.blockOn(.iouring_work, 0xFFFFFFFE);
        }
    }

    debug.klog("[iouring-worker] pid={d} bound to instance {d}\n", .{ my_pid, inst_id });

    while (true) {
        const inst = &instances[inst_id];
        if (!@atomicLoad(bool, &inst.in_use, .acquire)) break;

        // Phase 1: drain completed in-flight ops. ALWAYS runs first so
        // we observe completions whether woken by enter() (new submission)
        // or by the NVMe IRQ callback (op completed).
        const drained = drainCompletions(inst);
        if (drained > 0) {
            // Only wake CQ waiters when the parked caller's min_complete is
            // satisfied — otherwise they'd wake, re-check, see ready < min,
            // and re-park, paying a full schedule round-trip per spurious
            // wake. With this gate, a 16-deep enter(min=16) wakes the app
            // exactly once when the 16th completion lands, instead of 16×.
            const cq_hdr: *RingHeader = @ptrFromInt(inst.header_kvirt);
            const cq_tail = @atomicLoad(u32, &cq_hdr.cq_tail, .acquire);
            const cq_head = @atomicLoad(u32, &cq_hdr.cq_head, .acquire);
            const ready = cq_tail -% cq_head;
            const min_c = @atomicLoad(u32, &inst.cq_min_complete, .acquire);
            if (min_c == 0 or ready >= min_c) {
                process.wakeIoUringCqWaiters(inst_id);
            }
        }

        // Phase 1b: shutdown coordination. If the owner requested exit,
        // STOP submitting new SQEs but keep draining until every in-flight
        // op completes. Then self-recycle the Instance slot and exit.
        // This closes two HIGH bugs caught by reviewer (2026-05-24):
        //   - HIGH "PD freed under live CR3": tearDownTask frees the owner's
        //     page-dir AFTER releaseAllForPid returns, so the worker must
        //     not still be inside a CR3-swap when teardown advances.
        //   - HIGH "stale IRQ to recycled slot": if we exit with NVMe ops
        //     still in flight, their IRQ callbacks will fire AFTER setup()
        //     has handed this Instance to a new owner, corrupting state.
        // Draining synchronously here means: by the time the owner's
        // tearDownTask returns from releaseAllForPid (which spin-waits on
        // worker_pid going to .zombie), every NVMe op has been reaped via
        // releaseAsyncCid and no stale callbacks can fire.
        if (@atomicLoad(bool, &inst.exit_requested, .acquire)) {
            // OP_POLL slots don't complete on their own — fdpoll wake is
            // the only signal, and a dying process won't generate one.
            // Drop them now so pendingInFlightCount can reach zero.
            // Idempotent: subsequent iterations see in_use=false and skip.
            for (&inst.pending) |*p| {
                if (!@atomicLoad(bool, &p.in_use, .acquire)) continue;
                if (p.op != OP_POLL) continue;
                if (p.fdpoll_waiter_idx != 0xFF) {
                    fdpoll.unregister(p.fdpoll_waiter_idx);
                    p.fdpoll_waiter_idx = 0xFF;
                }
                @atomicStore(bool, &p.in_use, false, .release);
            }
            if (pendingInFlightCount(inst) == 0) {
                // All in-flight cleared. Self-recycle the Instance slot,
                // THEN destroyCurrent. setup() can immediately reuse this
                // slot once we've cleared it.
                @atomicStore(bool, &inst.exit_requested, false, .release);
                inst.owner_pid = 0xFFFFFFFF;
                inst.user_va = 0;
                inst.region_pages = 0;
                inst.entries = 0;
                inst.shm_id = 0xFFFFFFFF;
                inst.header_kvirt = 0;
                inst.worker_pid = 0xFFFFFFFF;
                @atomicStore(bool, &inst.in_use, false, .release);
                break;
            }
            // In-flight still outstanding — wait for IRQ callbacks. The
            // callbacks wake us on .iouring_work; the next loop iteration
            // drains, decrements pendingInFlightCount, and re-checks.
            process.blockOn(.iouring_work, inst_id);
            continue;
        }

        // Phase 2: submit SQEs until SQ empty, pending table full, or
        // NVMe queue full. Sync ops always submit (no pending slot needed).
        const hdr: *RingHeader = @ptrFromInt(inst.header_kvirt);
        var blocked_by_full = false;
        submit_loop: while (!@atomicLoad(bool, &inst.exit_requested, .acquire)) {
            const sq_head = @atomicLoad(u32, &hdr.sq_head, .acquire);
            const sq_tail = @atomicLoad(u32, &hdr.sq_tail, .acquire);
            if (sq_head == sq_tail) break :submit_loop;

            const sqe = readSqe(inst, sq_head & hdr.sq_mask);

            switch (sqe.opcode) {
                OP_POLL => {
                    // OP_POLL flow:
                    //   1. Resolve fd → FdHandle (current pcb's fd_table)
                    //   2. Check pollMask NOW. If matches requested events
                    //      → post CQE inline + advance sq_head, no slot.
                    //   3. Else allocate pending slot + register with fdpoll.
                    //      Slot completes via pollCompletionCallback → drain.
                    // sqe.fd holds the fd index; sqe.len holds the events
                    // mask (POLLIN/POLLOUT/...). Re-purposing sqe.len keeps
                    // the SQE shape unchanged.
                    switch (submitPollOp(inst, inst_id, sqe)) {
                        .ok, .invalid => {
                            @atomicStore(u32, &hdr.sq_head, sq_head +% 1, .release);
                        },
                        .queue_full => {
                            blocked_by_full = true;
                            break :submit_loop;
                        },
                    }
                },
                OP_NVME_READ, OP_NVME_WRITE => {
                    const slot_idx = allocPendingSlot(inst) orelse {
                        // Pending table full — break and park; completions
                        // will free slots. Don't post anything yet.
                        blocked_by_full = true;
                        break :submit_loop;
                    };
                    switch (submitNvmeOp(inst, inst_id, slot_idx, sqe)) {
                        .ok => {
                            @atomicStore(u32, &hdr.sq_head, sq_head +% 1, .release);
                        },
                        .queue_full => {
                            // NVMe device queue is full; pending slot already
                            // freed by submitNvmeOp. Park; completions free
                            // a CID, then retry.
                            blocked_by_full = true;
                            break :submit_loop;
                        },
                        .invalid => {
                            // Pending slot freed. Post error CQE inline.
                            const cq_tail = @atomicLoad(u32, &hdr.cq_tail, .acquire);
                            writeCqe(inst, cq_tail & hdr.cq_mask, .{
                                .user_data = sqe.user_data,
                                .res = ERES_INVAL,
                                .flags = 0,
                            });
                            @atomicStore(u32, &hdr.sq_head, sq_head +% 1, .release);
                            @atomicStore(u32, &hdr.cq_tail, cq_tail +% 1, .release);
                            process.wakeIoUringCqWaiters(inst_id);
                        },
                    }
                },
                else => {
                    const res = executeSyncAsWorker(inst, sqe);
                    const cq_tail = @atomicLoad(u32, &hdr.cq_tail, .acquire);
                    writeCqe(inst, cq_tail & hdr.cq_mask, .{
                        .user_data = sqe.user_data,
                        .res = res,
                        .flags = 0,
                    });
                    @atomicStore(u32, &hdr.sq_head, sq_head +% 1, .release);
                    @atomicStore(u32, &hdr.cq_tail, cq_tail +% 1, .release);
                    process.wakeIoUringCqWaiters(inst_id);
                },
            }
        }

        if (@atomicLoad(bool, &inst.exit_requested, .acquire)) break;

        // Phase 3: park if there's nothing to do right now.
        const sq_head_post = @atomicLoad(u32, &hdr.sq_head, .acquire);
        const sq_tail_post = @atomicLoad(u32, &hdr.sq_tail, .acquire);
        const sq_empty = sq_head_post == sq_tail_post;
        const in_flight = pendingInFlightCount(inst);

        if (sq_empty and in_flight == 0) {
            // Truly idle — only enter() can wake us.
            process.blockOn(.iouring_work, inst_id);
        } else if (blocked_by_full) {
            // Waiting on NVMe-side queue or pending-table room — only an
            // IRQ-callback wake can free that, and that wakes .iouring_work.
            process.blockOn(.iouring_work, inst_id);
        } else if (sq_empty) {
            // Pending in-flight; SQ drained. Wait for IRQ callbacks.
            process.blockOn(.iouring_work, inst_id);
        } else {
            // SQ still has work and we have free slots — keep looping.
        }
    }

    debug.klog("[iouring-worker] pid={d} exiting (instance {d})\n", .{ my_pid, inst_id });
    lifecycle.destroyCurrent();
    unreachable;
}

/// Create a new io_uring instance. Allocates the shared ring region,
/// installs the user-side LazyRegion mapping, spawns a worker task,
/// and returns the user VA.
pub fn setup(entries_req: u32) u32 {
    if (entries_req == 0 or entries_req > MAX_ENTRIES) return 0;
    const entries = nextPow2(entries_req);
    if (entries > MAX_ENTRIES) return 0;

    ensurePollCallbackRegistered();

    const pcb = process.currentPCB() orelse return 0;
    _ = pcb.page_directory orelse return 0;
    const lead = process.leader(pcb);

    // AS-stability lock — setup adds a lazy region + bumps mmap_top. Even
    // for the first instance, the caller's other threads or a sibling
    // worker (other instance, same pid) could be mutating concurrently.
    lead.as_lock.acquire();
    defer lead.as_lock.release();

    if (lead.lazy_count >= process.MAX_LAZY_REGIONS) return 0;

    const region_bytes = regionSize(entries);
    const region_pages: u32 = @intCast(region_bytes / 0x1000);

    const flags = lock.acquireIrqSave();
    var slot_opt: ?usize = null;
    if (countOwnedLocked(lead.tgid) >= MAX_INSTANCES_PER_PROC) {
        lock.releaseIrqRestore(flags);
        return 0;
    }
    for (&instances, 0..) |*it, i| if (!@atomicLoad(bool, &it.in_use, .acquire)) {
        slot_opt = i;
        break;
    };
    const slot = slot_opt orelse {
        lock.releaseIrqRestore(flags);
        return 0;
    };
    @atomicStore(bool, &instances[slot].in_use, true, .release);
    @atomicStore(bool, &instances[slot].exit_requested, false, .release);
    instances[slot].worker_pid = 0xFFFFFFFF;
    // Reset all pending slots — last owner may have left stale state.
    for (&instances[slot].pending) |*p| {
        p.* = .{};
    }
    lock.releaseIrqRestore(flags);

    const shm_id = shm.create(region_pages) orelse {
        instances[slot].in_use = false;
        return 0;
    };

    if (region_bytes > lead.mmap_top) {
        shm.release(shm_id);
        instances[slot].in_use = false;
        return 0;
    }
    const new_top = lead.mmap_top - region_bytes;
    if (new_top < lead.user_brk) {
        shm.release(shm_id);
        instances[slot].in_use = false;
        return 0;
    }
    if (!process.addLazyRegion(lead.tgid, new_top, lead.mmap_top, 0)) {
        shm.release(shm_id);
        instances[slot].in_use = false;
        return 0;
    }
    const ridx = lead.lazy_count - 1;
    lead.lazy_regions[ridx].prot = process.PROT_RW;
    lead.lazy_regions[ridx].shm_id = shm_id;
    lead.mmap_top = new_top;

    const phys0 = shm.frameAt(shm_id, 0) orelse {
        shm.release(shm_id);
        instances[slot].in_use = false;
        return 0;
    };
    const header_kvirt = paging.physToVirt(phys0);
    const hdr: *RingHeader = @ptrFromInt(header_kvirt);
    hdr.* = .{
        .sq_head = 0,
        .sq_tail = 0,
        .sq_mask = entries - 1,
        .sq_entries = entries,
        .cq_head = 0,
        .cq_tail = 0,
        .cq_mask = entries - 1,
        .cq_entries = entries,
        .sqes_offset = @sizeOf(RingHeader),
        .cqes_offset = @sizeOf(RingHeader) + entries * @sizeOf(Sqe),
        ._pad = [_]u8{0} ** 24,
    };

    instances[slot].owner_pid = lead.tgid;
    instances[slot].user_va = new_top;
    instances[slot].region_pages = region_pages;
    instances[slot].entries = entries;
    instances[slot].shm_id = shm_id;
    instances[slot].header_kvirt = header_kvirt;

    const worker_pid_opt = lifecycle.createKernelTask(
        @intFromPtr(&workerLoop),
        "iouring-worker",
        0,
        .normal,
        16 * 1024,
    );
    const worker_pid = worker_pid_opt orelse {
        if (lead.lazy_count > 0) {
            const removed = lead.lazy_regions[lead.lazy_count - 1];
            lead.lazy_regions[lead.lazy_count - 1] = .{};
            lead.lazy_count -= 1;
            if (removed.start == lead.mmap_top) lead.mmap_top = removed.end;
        }
        shm.release(shm_id);
        instances[slot].in_use = false;
        return 0;
    };
    instances[slot].worker_pid = @intCast(worker_pid);
    process.wake(@intCast(worker_pid));

    debug.klog("[iouring] setup pid={d} va=0x{X} entries={d} worker_pid={d}\n", .{
        lead.tgid, new_top, entries, worker_pid,
    });
    return @intCast(new_top);
}

/// User-visible enter: kick the worker if `to_submit > 0`; block until the
/// CQ has at least `min_complete` entries pending consumption (if asked).
/// Returns the number of CQEs currently available for the caller to reap.
///
/// Returns 0xFFFFFFFF on E_INVAL (no such ring for caller).
pub fn enter(user_va: u32, to_submit: u32, min_complete: u32) u32 {
    _ = to_submit;
    const pcb = process.currentPCB() orelse return 0xFFFFFFFF;
    const lead = process.leader(pcb);
    const inst = findByVa(lead.tgid, user_va) orelse return 0xFFFFFFFF;
    const hdr: *RingHeader = @ptrFromInt(inst.header_kvirt);

    const inst_id: u32 = @intCast((@intFromPtr(inst) - @intFromPtr(&instances[0])) / @sizeOf(Instance));

    const sq_head_pre = @atomicLoad(u32, &hdr.sq_head, .acquire);
    const sq_tail_pre = @atomicLoad(u32, &hdr.sq_tail, .acquire);
    if (sq_tail_pre != sq_head_pre) {
        process.wakeIoUringWorker(inst_id);
    }

    if (min_complete > 0) {
        // Tell the worker what min_complete we're waiting for, so it can
        // suppress per-CQE wakes and only wake us when the count is hit.
        @atomicStore(u32, &inst.cq_min_complete, min_complete, .release);
        defer @atomicStore(u32, &inst.cq_min_complete, 0, .release);

        while (true) {
            const cq_tail = @atomicLoad(u32, &hdr.cq_tail, .acquire);
            const cq_head = @atomicLoad(u32, &hdr.cq_head, .acquire);
            const ready = cq_tail -% cq_head;
            if (ready >= min_complete) break;
            if (!@atomicLoad(bool, &inst.in_use, .acquire) or @atomicLoad(bool, &inst.exit_requested, .acquire)) break;
            process.blockOn(.iouring_cq, inst_id);
        }
    }

    const cq_tail_final = @atomicLoad(u32, &hdr.cq_tail, .acquire);
    const cq_head_final = @atomicLoad(u32, &hdr.cq_head, .acquire);
    return cq_tail_final -% cq_head_final;
}

/// Release all instances owned by `pid`. Called from tearDownTask. Sets
/// exit_requested on each owned instance and wakes the worker; the worker
/// itself drains any in-flight NVMe ops, releases their CIDs, recycles
/// the Instance slot, and self-destroys.
///
/// We then SPIN-WAIT until each worker has actually finished its self-
/// cleanup (Instance.in_use went false). This is required because
/// tearDownTask's NEXT step frees the owner's page directory, and the
/// worker may still be inside a CR3-swap (handleCompletion's bounce→user
/// memcpy) referencing it. Closes the HIGH "PD freed under live CR3"
/// race reviewer flagged 2026-05-24.
pub fn releaseAllForPid(pid: u32) void {
    // Phase 1: signal exit + wake everyone, without holding `lock` (the
    // worker may need to take it during cleanup, and we'll spin-wait
    // below — must not hold it while blocked).
    var owned_slots: [MAX_INSTANCES_TOTAL]bool = [_]bool{false} ** MAX_INSTANCES_TOTAL;
    {
        const flags = lock.acquireIrqSave();
        defer lock.releaseIrqRestore(flags);
        for (&instances, 0..) |*it, idx| {
            if (!@atomicLoad(bool, &it.in_use, .acquire)) continue;
            if (it.owner_pid != pid) continue;
            owned_slots[idx] = true;
            @atomicStore(bool, &it.exit_requested, true, .release);
            if (it.worker_pid < process.MAX_PROCS) {
                process.wake(@intCast(it.worker_pid));
            }
            // Wake CQ waiters so they bail (their loop checks exit_requested).
            process.wakeIoUringCqWaiters(@intCast(idx));
        }
    }

    // Phase 2: wait for each worker to self-recycle the Instance. The
    // worker checks exit_requested at the top of its loop and only exits
    // after pendingInFlightCount == 0 — meaning every NVMe op has been
    // reaped via releaseAsyncCid by handleCompletion. Once Instance.in_use
    // flips to false, the worker is at most one instruction away from
    // destroyCurrent and is no longer inside any CR3-swap.
    var spins: u64 = 0;
    for (owned_slots, 0..) |is_owned, idx| {
        if (!is_owned) continue;
        while (@atomicLoad(bool, &instances[idx].in_use, .acquire)) {
            spins += 1;
            // Yield to give the worker a chance to run. softYield() here
            // mirrors nvme.ioCommandAsync's queue-full-retry pattern.
            smp.myCpu().pending_soft_yield = true;
            @import("../proc/sched_asm.zig").softYield();
            // Diagnostic: if we spin >100k times the worker is wedged.
            // 100k * softYield latency = many seconds at minimum.
            if (spins > 100_000 and spins & 0xFFFF == 0) {
                debug.klog("[iouring] releaseAllForPid: still waiting on instance {d} (spins={d})\n", .{ idx, spins });
            }
        }
    }
}
