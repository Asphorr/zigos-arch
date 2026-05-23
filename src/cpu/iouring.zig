//! io_uring Phase 1 — Linux-style submission/completion ring for syscall
//! batching. Userspace submits Sqes (ops), kernel processes them, writes
//! Cqes (results), userspace polls for completions. The ring memory is a
//! single shared-anon region (via mm/shm) mapped into both user and
//! kernel addressing — no per-op syscall validation, no copying.
//!
//! Phase 1 scope:
//!   - OP_NOP, OP_READ, OP_WRITE only (vfs-routed, synchronous dispatch).
//!   - Single contiguous ring region (header + sqes + cqes in one mmap).
//!   - Capacity up to 256 entries / 4 instances per process / 16 total.
//!   - io_uring_enter blocks on first SQE -> waits to_submit ops, returns
//!     completions_processed.
//!
//! Skipped (Phase 2+): SQPOLL kthread (zero-syscall), fixed buffers /
//! fixed files, linked SQEs, real async dispatch (NVMe ioCommandAsync
//! integration), every op beyond R/W/NOP.
//!
//! Layout (single shared region):
//!   [0 .. 64)           RingHeader
//!   [64 .. 64 + e*64)   Sqe array
//!   [64 + e*64 .. ..)   Cqe array
//! where e = entries (caller-requested, rounded up to power of two).

const std = @import("std");
const process = @import("../proc/process.zig");
const shm = @import("../mm/shm.zig");
const paging = @import("../mm/paging.zig");
const vfs = @import("../fs/vfs.zig");
const debug = @import("../debug/debug.zig");
const smp = @import("smp.zig");

const common = @import("syscall/common.zig");
const E_INVAL = common.E_INVAL;
const E_NOMEM = common.E_NOMEM;
const E_FAULT = common.E_FAULT;
const E_BADF = common.E_BADF;

pub const OP_NOP: u8 = 0;
pub const OP_READ: u8 = 1;
pub const OP_WRITE: u8 = 2;

pub const MAX_ENTRIES: u32 = 256;
pub const MIN_ENTRIES: u32 = 1;
pub const MAX_INSTANCES_PER_PROC: u8 = 4;
pub const MAX_INSTANCES_TOTAL: u8 = 16;

/// Userspace fills these; layout is fixed (Linux-ish but trimmed). Total 64 B
/// so a power-of-two count fits page boundaries cleanly. `_pad` reserves
/// space for future fields (msg_flags, buf_index, splice_fd_in) without ABI
/// break — keep as zero for now.
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

/// Kernel writes these; userspace consumes. `res` is the syscall result
/// (positive bytes for READ/WRITE success; negated errno on failure;
/// 0 for NOP). `user_data` echoes the SQE's tag so the caller can pair
/// completions to submissions.
pub const Cqe = extern struct {
    user_data: u64,
    res: i32,
    flags: u32,
};

/// At offset 0 of the ring region. Heads / tails are u32 monotonic
/// counters; the index in the array is `value & mask`. Userspace
/// touches sq_tail (advancing on submit) and cq_head (advancing on
/// reap); kernel touches sq_head (consuming) and cq_tail (producing).
pub const RingHeader = extern struct {
    sq_head: u32,
    sq_tail: u32,
    sq_mask: u32,
    sq_entries: u32,
    cq_head: u32,
    cq_tail: u32,
    cq_mask: u32,
    cq_entries: u32,
    sqes_offset: u32,
    cqes_offset: u32,
    _pad: [24]u8,
};

const Instance = struct {
    in_use: bool = false,
    owner_pid: u32 = 0xFFFFFFFF,
    user_va: usize = 0,
    region_pages: u32 = 0,
    entries: u32 = 0,
    shm_id: u32 = 0xFFFFFFFF,
    // Kernel-side view of the same frames the user mmapped. Computed once
    // at setup and stable as long as shm holds the region (refcount > 0).
    // Cross-page within the region resolves via shm.frameAt(shm_id, idx).
    header_kvirt: usize = 0,
};

var instances: [MAX_INSTANCES_TOTAL]Instance = [_]Instance{.{}} ** MAX_INSTANCES_TOTAL;
var lock: @import("../proc/spinlock.zig").SpinLock = .{};

inline fn nextPow2(v: u32) u32 {
    if (v <= 1) return 1;
    var r: u32 = 1;
    while (r < v) r <<= 1;
    return r;
}

/// Page-aligned total region size given `entries` (already pow2).
fn regionSize(entries: u32) usize {
    const sz: usize = @sizeOf(RingHeader) + entries * @sizeOf(Sqe) + entries * @sizeOf(Cqe);
    return (sz + 0xFFF) & ~@as(usize, 0xFFF);
}

/// Read u32 from the ring at a byte offset, going through kernel mapping.
/// Caller guarantees offset is within region.
inline fn rdU32(inst: *const Instance, off: usize) u32 {
    const p: *u32 = @ptrFromInt(kvirtAt(inst, off));
    return @atomicLoad(u32, p, .acquire);
}
inline fn wrU32(inst: *const Instance, off: usize, val: u32) void {
    const p: *u32 = @ptrFromInt(kvirtAt(inst, off));
    @atomicStore(u32, p, val, .release);
}
inline fn kvirtAt(inst: *const Instance, off: usize) usize {
    const page = off / 0x1000;
    const in_page = off % 0x1000;
    const phys = shm.frameAt(inst.shm_id, @intCast(page)) orelse @panic("iouring kvirtAt: shm frame gone");
    return paging.physToVirt(phys) + in_page;
}

/// Total instances owned by `pid`. Caller holds the lock.
fn countOwnedLocked(pid: u32) u8 {
    var n: u8 = 0;
    for (instances) |it| if (it.in_use and it.owner_pid == pid) {
        n += 1;
    };
    return n;
}

/// Look up the instance owned by `pid` whose user_va matches. Returns null
/// if not found. No lock — read-only and only used in syscall paths where
/// the owner is the current pid (lifecycle teardown holds the lock).
fn findByVa(pid: u32, va: usize) ?*Instance {
    for (&instances) |*it| if (it.in_use and it.owner_pid == pid and it.user_va == va) {
        return it;
    };
    return null;
}

/// Create a new io_uring instance. `entries_req` is rounded up to a power
/// of two (capped at MAX_ENTRIES). Allocates a shared region, initializes
/// the header, registers a LazyRegion in the caller's AS, returns the user
/// VA. Returns 0 on any failure (E_INVAL / E_NOMEM / out-of-table).
pub fn setup(entries_req: u32) u32 {
    if (entries_req == 0 or entries_req > MAX_ENTRIES) return 0;
    const entries = nextPow2(entries_req);
    if (entries > MAX_ENTRIES) return 0;

    const pcb = process.currentPCB() orelse return 0;
    _ = pcb.page_directory orelse return 0;
    const lead = process.leader(pcb);
    if (lead.lazy_count >= process.MAX_LAZY_REGIONS) return 0;

    const region_bytes = regionSize(entries);
    const region_pages: u32 = @intCast(region_bytes / 0x1000);

    const flags = lock.acquireIrqSave();
    var slot_opt: ?usize = null;
    if (countOwnedLocked(lead.tgid) >= MAX_INSTANCES_PER_PROC) {
        lock.releaseIrqRestore(flags);
        return 0;
    }
    for (instances, 0..) |it, i| if (!it.in_use) {
        slot_opt = i;
        break;
    };
    const slot = slot_opt orelse {
        lock.releaseIrqRestore(flags);
        return 0;
    };
    instances[slot].in_use = true; // reserve so a peer doesn't grab it
    lock.releaseIrqRestore(flags);

    const shm_id = shm.create(region_pages) orelse {
        instances[slot].in_use = false;
        return 0;
    };

    // VA — same downward growth as sysMmap.
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

    // Initialize the header. Resolve kvirt of the first frame for direct
    // access; the header always lives in page 0 of the region.
    const phys0 = shm.frameAt(shm_id, 0) orelse {
        // shouldn't happen — we just allocated it
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

    debug.klog("[iouring] setup pid={d} va=0x{X} entries={d} pages={d}\n", .{
        lead.tgid, new_top, entries, region_pages,
    });
    return @intCast(new_top);
}

/// Read a single Sqe from the ring at logical index `idx_masked`. Returns
/// the Sqe by value so the caller can drop the kernel pointer before any
/// reentrant call.
fn readSqe(inst: *Instance, idx_masked: u32) Sqe {
    const off: usize = @sizeOf(RingHeader) + idx_masked * @sizeOf(Sqe);
    const p: *const Sqe = @ptrFromInt(kvirtAt(inst, off));
    return p.*;
}

/// Write a Cqe at logical index `idx_masked`.
fn writeCqe(inst: *Instance, idx_masked: u32, cqe: Cqe) void {
    const off: usize = @sizeOf(RingHeader) + inst.entries * @sizeOf(Sqe) + idx_masked * @sizeOf(Cqe);
    const p: *Cqe = @ptrFromInt(kvirtAt(inst, off));
    p.* = cqe;
}

/// Execute one Sqe synchronously and return the result for the Cqe.
/// Convention (Phase 1, Linux io_uring-ish): res >= 0 = byte count
/// or 0 for NOP; res < 0 = small negated errno. ZigOS's full
/// 0xFFFFFFxx errno values don't fit in i32, so we map to Linux's small
/// canonical numbers at this boundary — userspace tools that already
/// know io_uring conventions stay portable.
const ERES_BADF: i32 = -9;   // EBADF
const ERES_FAULT: i32 = -14; // EFAULT
const ERES_INVAL: i32 = -22; // EINVAL

fn execute(inst: *Instance, sqe: Sqe) i32 {
    const pcb = process.currentPCB() orelse return ERES_FAULT;
    _ = inst;

    switch (sqe.opcode) {
        OP_NOP => return 0,
        OP_READ => {
            if (sqe.fd >= @import("../config.zig").MAX_FDS) return ERES_BADF;
            if (!pcb.fd_table[sqe.fd].in_use) return ERES_BADF;
            if (sqe.len == 0) return 0;
            // validateUserPtr does range check + ensures every page is
            // mapped + STACs SMAP for the rest of the enclosing syscall.
            // Without this, vfs.read's internal memcpy into the user buf
            // would #PF with err.smap (kernel touched user page, AC=0).
            const addr_lo: u32 = @truncate(sqe.addr);
            if (!common.validateUserPtr(addr_lo, sqe.len)) return ERES_FAULT;
            const buf: [*]u8 = @ptrFromInt(@as(usize, addr_lo));
            const n = vfs.read(pcb, sqe.fd, buf, sqe.len);
            if (n == 0xFFFFFFFF) return ERES_INVAL;
            return @intCast(n);
        },
        OP_WRITE => {
            if (sqe.fd >= @import("../config.zig").MAX_FDS) return ERES_BADF;
            if (!pcb.fd_table[sqe.fd].in_use) return ERES_BADF;
            if (sqe.len == 0) return 0;
            const addr_lo: u32 = @truncate(sqe.addr);
            if (!common.validateUserPtr(addr_lo, sqe.len)) return ERES_FAULT;
            const buf: [*]const u8 = @ptrFromInt(@as(usize, addr_lo));
            const n = vfs.write(pcb, sqe.fd, buf, sqe.len);
            if (n == 0xFFFFFFFF) return ERES_INVAL;
            return @intCast(n);
        },
        else => return ERES_INVAL,
    }
}

/// Process up to `to_submit` SQEs from the ring at `user_va`. Returns the
/// number of completions written (== number of SQEs processed for Phase 1's
/// synchronous dispatch). `min_complete` is currently a hint — synchronous
/// dispatch always writes one CQE per processed SQE, so the caller's wait
/// is naturally satisfied.
///
/// Returns 0xFFFFFFFF on E_INVAL (no such ring for caller).
pub fn enter(user_va: u32, to_submit: u32, min_complete: u32) u32 {
    _ = min_complete;
    const pcb = process.currentPCB() orelse return 0xFFFFFFFF;
    const lead = process.leader(pcb);
    const inst = findByVa(lead.tgid, user_va) orelse return 0xFFFFFFFF;

    const hdr: *RingHeader = @ptrFromInt(inst.header_kvirt);
    var sq_head = @atomicLoad(u32, &hdr.sq_head, .acquire);
    const sq_tail = @atomicLoad(u32, &hdr.sq_tail, .acquire);
    var cq_tail = @atomicLoad(u32, &hdr.cq_tail, .acquire);

    var n_submit: u32 = 0;
    const available = sq_tail -% sq_head; // wrap-safe
    const cap = if (to_submit < available) to_submit else available;

    while (n_submit < cap) : (n_submit += 1) {
        const sqe = readSqe(inst, sq_head & hdr.sq_mask);
        const res = execute(inst, sqe);
        writeCqe(inst, cq_tail & hdr.cq_mask, .{
            .user_data = sqe.user_data,
            .res = res,
            .flags = 0,
        });
        sq_head +%= 1;
        cq_tail +%= 1;
    }

    @atomicStore(u32, &hdr.sq_head, sq_head, .release);
    @atomicStore(u32, &hdr.cq_tail, cq_tail, .release);
    return n_submit;
}

/// Release all instances owned by `pid`. Called from tearDownTask so the
/// slot table entries are recycled on process exit. Does NOT call
/// shm.release — the LazyRegion cleanup in tearDownTask already drops the
/// shm ref (the io_uring instance is bookkeeping; the user-visible memory
/// is owned by the LazyRegion, which holds the only ref count).
pub fn releaseAllForPid(pid: u32) void {
    const flags = lock.acquireIrqSave();
    defer lock.releaseIrqRestore(flags);
    for (&instances) |*it| {
        if (!it.in_use) continue;
        if (it.owner_pid != pid) continue;
        it.in_use = false;
        it.owner_pid = 0xFFFFFFFF;
        it.user_va = 0;
        it.region_pages = 0;
        it.entries = 0;
        it.shm_id = 0xFFFFFFFF;
        it.header_kvirt = 0;
    }
}
