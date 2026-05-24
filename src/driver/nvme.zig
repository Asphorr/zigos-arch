// NVMe (Non-Volatile Memory Express) — modern PCIe SSD driver.
//
// Most desktop/laptop boot drives shipped after ~2018 are NVMe (M.2
// PCIe form factor) rather than SATA. This driver gives ZigOS access
// to those — same code path on real hardware as in QEMU's `-device
// nvme`. Combined with the AHCI driver, storage coverage spans the
// last ~20 years of consumer PCs.
//
// Reference: NVMe Base Specification 1.4. We use only:
//   - Admin queue (CREATE_CQ, CREATE_SQ, IDENTIFY)
//   - One I/O queue pair per controller (qid=1)
//   - Read / Write commands with single-PRP transfers (one sector at a
//     time, bounce-buffered through a 4 KiB-aligned per-controller
//     scratch page so user buffers can be any alignment).
// No interrupts (we poll). No NCQ, no fused commands, no SGL, no
// metadata, no fabrics. Just enough to read and write a disk.
//
// Surface mirrors ahci.zig — readSector/readSectors/writeSector split
// into "primary" / "secondary". `block.zig` dispatches between NVMe,
// AHCI, and legacy ATA in that order. To exercise the NVMe path in
// QEMU, swap your `-drive` lines to `-device nvme,drive=...`.

const std = @import("std");
const io = @import("../io.zig");
const pci = @import("pci.zig");
const iommu = @import("../cpu/iommu.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const msix = @import("../time/msix.zig");
const debug = @import("../debug/debug.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

// PCI class for "Mass Storage Controller / NVM Subsystem / NVMe I/O".
const PCI_CLASS_STORAGE: u8 = 0x01;
const PCI_SUBCLASS_NVM: u8 = 0x08;
const PCI_PROGIF_NVME: u8 = 0x02;

// --- Controller registers (BAR0-relative) ---
const REG_CAP_LO: u32 = 0x00;
const REG_CAP_HI: u32 = 0x04;
const REG_VS: u32 = 0x08;
const REG_INTMS: u32 = 0x0C;
const REG_INTMC: u32 = 0x10;
const REG_CC: u32 = 0x14;
const REG_CSTS: u32 = 0x1C;
const REG_AQA: u32 = 0x24;
const REG_ASQ_LO: u32 = 0x28;
const REG_ASQ_HI: u32 = 0x2C;
const REG_ACQ_LO: u32 = 0x30;
const REG_ACQ_HI: u32 = 0x34;

// --- Controller Configuration (CC) bits ---
const CC_EN: u32 = 1 << 0;
// CC_CSS=0 (NVM command set), AMS=0 (round-robin), MPS=0 (4 KiB pages)
const CC_IOSQES_64: u32 = 6 << 16; // log2(64) = 6 — submission entry size
const CC_IOCQES_16: u32 = 4 << 20; // log2(16) = 4 — completion entry size

const CSTS_RDY: u32 = 1 << 0;
// Controller Fatal Status. Set when the device has hit an unrecoverable
// internal error and is refusing all subsequent commands. Without checking
// this we just time out on every I/O while the controller silently sits in
// a dead state. Gap #4 (2026-05-20).
const CSTS_CFS: u32 = 1 << 1;

// --- Admin command opcodes ---
const ADMIN_CREATE_SQ: u8 = 0x01;
const ADMIN_CREATE_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;

// --- I/O command opcodes ---
const IO_FLUSH: u8 = 0x00;
const IO_WRITE: u8 = 0x01;
const IO_READ: u8 = 0x02;
// Gap #8 (2026-05-20): Write Zeroes — no data transfer, device zero-fills
// the specified LBA range internally. Massively cheaper than write(zeros)
// because no bus traffic. cdw10/11 = starting LBA, cdw12 = num_lbas-1 + flags.
const IO_WRITE_ZEROES: u8 = 0x08;
// Gap #7 (2026-05-20): Dataset Management. With AD (Deallocate) bit set
// in cdw11, this is the NVMe equivalent of SATA TRIM — tells the SSD's
// flash translation layer the named LBA ranges are no longer in use, so
// it can avoid preserving them through garbage collection. Big perf +
// lifespan win on real hardware once the disk has been filled once.
const IO_DSM: u8 = 0x09;
const DSM_ATTR_AD: u32 = 1 << 2; // Deallocate (cdw11 bit 2)

/// One range descriptor in the DSM Range structure block pointed to by
/// PRP1. The block is up to NR+1 of these (NR encoded in cdw10[7:0]).
/// We currently emit exactly one range per call — block.zig's munmap /
/// file-delete hooks can batch multiple LBAs into one call by extending
/// `trim*` to accept a slice.
const DsmRange = extern struct {
    context_attributes: u32 = 0,
    length: u32 = 0, // in LBAs
    starting_lba: u64 = 0,
};

// --- Identify CNS values ---
const CNS_NAMESPACE: u32 = 0x00;
const CNS_CONTROLLER: u32 = 0x01;
const CNS_ACTIVE_NS_LIST: u32 = 0x02;

// --- Submission queue entry (64 bytes) ---
const SqEntry = extern struct {
    opcode: u8,
    flags: u8,
    cid: u16 align(1),
    nsid: u32 align(1),
    _rsv0: u64 align(1),
    mptr: u64 align(1),
    prp1: u64 align(1),
    prp2: u64 align(1),
    cdw10: u32 align(1),
    cdw11: u32 align(1),
    cdw12: u32 align(1),
    cdw13: u32 align(1),
    cdw14: u32 align(1),
    cdw15: u32 align(1),
};

// --- Completion queue entry (16 bytes) ---
const CqEntry = extern struct {
    result: u32 align(1),
    _rsv: u32 align(1),
    sq_head: u16 align(1),
    sq_id: u16 align(1),
    cid: u16 align(1),
    status: u16 align(1), // bit 0 = phase, bits 15:1 = status code
};

const Q_DEPTH: u16 = 16;
const MAX_CONTROLLERS: usize = 3; // 0 = tarfs, 1 = ext2, 2 = swap
const SECTOR_SIZE: u32 = 512;

/// Compile-time toggle for the async I/O path. When **true** (default
/// since 2026-05-19's Q_DEPTH=16 maturation), every read/write submits
/// + yields, the IRQ handler reaps + wakes blocked processes, and we
/// get Q_DEPTH=16-way parallelism. When false, `ioCommand` and the IRQ
/// handler take the polled / sync path that was the original driver
/// shape. Gap #16 (2026-05-20) corrected the prior comment that
/// claimed `false` was the default — it never was post-mat.
///
/// SAFETY: async requires `process.blockOn` to work, which requires a
/// current_pid on this CPU. Early-boot reads (ext2.init reading the
/// superblock from main.zig:407 before enterFirstTask at line 565) run
/// before any scheduled task exists — async path would dead-lock. The
/// per-controller flag stays false until the FIRST scheduled task
/// runs, then flips on. See `enableAsync` below.
const ASYNC_BUILD_ENABLED: bool = true;

/// One async I/O in flight. The externally-visible CID we write into the
/// SQE is NOT just the slot index — it's `(gen << 4) | slot_idx` (gap #2,
/// 2026-05-20). The generation counter lets `reapCq` detect completions
/// for already-abandoned slots: a CID with `expected_gen != waiters[slot].gen`
/// is an orphan from a previous timed-out command and gets dropped with
/// an explicit klog instead of falsely waking the slot's current owner.
/// Q_DEPTH=16 → 4 bits of slot, 12 bits of generation = 4096 generations
/// before wrap. At realistic ZigOS I/O rates (~100 ops/sec total = ~6
/// per slot per sec), the 30s timeout window covers <200 generations,
/// well under wrap. `gen` is bumped on every alloc; we never use gen=0,
/// so pre-async-flip sync CIDs (which never set the high 12 bits) can't
/// false-match a freshly-allocated slot.
/// Per-CID completion notification. Two flavors:
///   .pid   — IRQ reaper calls process.wake(pid). Used by sync-style
///            blockOn(.nvme_io) waiters: ioCommandAsync, submitDatalessAsync.
///   .cb    — IRQ reaper invokes the callback in IRQ context with
///            (ctx, success, status_code). Used by io_uring's per-IRQ
///            async path: callback marks the io_uring PendingOp done and
///            wakes the worker. Callback MUST be brief — runs at IRQ
///            context (still cli/iretq window), but cq_lock has already
///            been released by the time dispatch runs. Deferred work
///            (user-buffer copy, posting CQE) happens in the woken task.
const WakeMode = union(enum) {
    pid: u8,
    cb: struct {
        callback: *const fn (ctx: usize, success: bool, sc: u16) callconv(.c) void,
        ctx: usize,
    },
};

const NvmeWaiter = struct {
    active: bool = false,
    completed: bool = false,
    success: bool = false,
    status_code: u16 = 0,
    wake: WakeMode = .{ .pid = 0xFF },
    gen: u16 = 0,
    /// Gap #11 (2026-05-20): SQ ring slot index (in [0, Q_DEPTH)) where
    /// the SQE for this command was written. Lets `dumpWaiterForTarget`
    /// dump the actual SQE the device should be processing, so the
    /// autopsy can confirm "yes, our cmd is sitting at io_sq[N] waiting"
    /// vs "the SQ has someone else's cmd in our slot." Set in
    /// `ioCommandAsync` between alloc and doorbell; 0xFFFF = never set.
    sq_slot: u16 = 0xFFFF,
};

/// Pack a slot index + generation counter into the 16-bit CID we write
/// into the SQE. The device echoes this back unchanged in the CQE.
inline fn packCid(slot_idx: u16, gen: u16) u16 {
    // gen must stay within 12 bits — the cid is u16 with 4 bits of slot
    // and 12 bits of gen. Without the mask, a stray gen=4096 (= 0x1000)
    // would shift to 0x10000 and silently truncate to 0, making packCid
    // collide with packCid(slot, 0). nextGen wraps to keep us in 12-bit
    // range; the mask here is belt-and-suspenders for callers and for
    // any future code path that might compute gen out-of-band.
    return ((gen & 0xFFF) << 4) | (slot_idx & 0xF);
}

inline fn cidSlot(cid: u16) u16 {
    return cid & 0xF;
}

inline fn cidGen(cid: u16) u16 {
    return cid >> 4;
}

/// Bump the generation counter, skipping 0 on wrap so any future CQE
/// with gen=0 (which can only happen from a never-issued or sync-era
/// CID) is always an orphan rather than a false match.
inline fn nextGen(g: u16) u16 {
    // Wrap at 12 bits — that's the gen field width inside the packed
    // cid (4 bits slot + 12 bits gen = u16). Pre-fix this used u16
    // wraparound, letting gen drift up to 65535 even though packCid
    // could only echo 12 bits. After 4096 commands per slot, the
    // 13th bit set in `g` would shift out of the cid, packCid
    // produced cid=`slot` (gen-bits all zero), and the matching
    // reaper saw expected_gen=0 vs w.gen=4096 → "orphan" + never
    // wake the waiter. Reproduced 2026-05-20 after ~65k NVMe
    // commands during a boot+launch session.
    const g1 = (g + 1) & 0xFFF;
    return if (g1 == 0) 1 else g1;
}

const Controller = struct {
    mmio_base: usize = 0,
    doorbell_stride_log: u8 = 0,

    admin_sq: usize = 0, // phys addr of the admin SQ ring
    admin_cq: usize = 0,
    admin_sq_tail: u16 = 0,
    admin_cq_head: u16 = 0,
    admin_cq_phase: bool = true,

    io_sq: usize = 0,
    io_cq: usize = 0,
    io_sq_tail: u16 = 0,
    io_cq_head: u16 = 0,
    io_cq_phase: bool = true,

    // Per-CID bounce buffers (BOUNCE_PAGES_PER_SLOT * 4 KiB each, contiguous).
    // Async submitters claim a CID via `allocCid`, use bounce_bufs[cid] for
    // the PRP1 (and PRP2 / prp_list_phys for larger transfers). Each entry
    // is the PHYSICAL base address; pages are contiguous in physical memory.
    // 16 * 32 KiB = 512 KiB per controller after the bump.
    bounce_bufs: [Q_DEPTH]usize = [_]usize{0} ** Q_DEPTH,
    // Per-CID PRP list pages. NVMe requires a PRP list when a transfer
    // spans more than 2 pages: PRP1 = page0, PRP2 = phys of a list page
    // containing u64 entries for page1, page2, ... For ≤ 2 pages PRP2 is
    // the page1 phys directly and this list page is unused. One page each,
    // 16 * 4 KiB = 64 KiB per controller.
    prp_list_phys: [Q_DEPTH]usize = [_]usize{0} ** Q_DEPTH,
    waiters: [Q_DEPTH]NvmeWaiter = [_]NvmeWaiter{.{}} ** Q_DEPTH,

    nsid: u32 = 0, // first active namespace ID
    block_size: u32 = SECTOR_SIZE,

    next_cid: u16 = 1,
    initialized: bool = false,

    // MSI-X: when present, I/O completions wake the kernel via `hlt`
    // instead of busy-spinning the polled clflush loop. The admin queue
    // stays polled because it's only used during init.
    use_msix: bool = false,
    msix_cap: msix.Cap = undefined,
    // Absolute virtual address of the I/O CQ's MSI-X table entry — saved
    // at init so the per-call retarget in ioCommandOneSector doesn't have
    // to re-walk the cap structure. data is the vector word writeEntry
    // needs; addr is recomputed each call from the current CPU's APIC ID.
    // msix_current_addr caches the most recently written addr so we can
    // skip the mask/write/unmask cycle when the calling CPU hasn't changed.
    msix_io_entry: usize = 0,
    msix_data: u32 = 0,
    msix_current_addr: u64 = 0,

    // Serializes ioCommandOneSector across CPUs. The bounce_buf, SQ tail,
    // and CQ head/phase are all single-element state — concurrent access
    // from BSP and an AP would clobber any of them. Acquired only inside
    // ioCommandOneSector so admin-path callers (which run BSP-only at
    // boot) stay lock-free.
    io_lock: SpinLock = .{},

    // Async-path CQ reaper lock. Held by `reapCq` (called from
    // `nvmeIrqHandler` when async mode is active) and by the submit
    // path while it advances cq_head reading completions during fallback
    // polling. Distinct from io_lock so submit can release after ringing
    // the doorbell without blocking IRQ reapers on other CPUs.
    cq_lock: SpinLock = .{},
    // When true, IRQs scan the I/O CQ + wake waiters. When false, IRQs
    // only bump irq_count and ioCommand polls the CQ inline. Phase C
    // flips this to true after migrating all readers/writers off the
    // synchronous path. Read by `nvmeIrqHandler` on every IRQ.
    async_mode: bool = false,

    /// Gap #12 (2026-05-20): per-controller count of CQEs that
    /// `reapCq` actually processed. Bumped each time a completion was
    /// found and routed to a waiter (or dropped as an orphan). Pair
    /// with the global `irq_count` to discriminate "IRQs arrived but
    /// CQ was empty" from "IRQs arrived AND drained completions" per
    /// controller. The shared global handler can't attribute IRQs to a
    /// specific device, but each controller's own reapCq knows what it
    /// saw on its CQ.
    cqe_drained_count: u64 = 0,
    /// Counter for `if (cid_opt == null)` retries inside the async
    /// queue-full retry loop (gap #6). Bumped each time allocCid
    /// returned null and we yielded. Diagnostic only.
    queue_full_retries: u64 = 0,
};

var controllers: [MAX_CONTROLLERS]Controller = .{ .{}, .{}, .{} };
var num_controllers: usize = 0;
pub var irq_count: u64 = 0;

/// MSI-X handler. In sync mode (async_mode=false), just bumps a counter
/// so the next waitCompletion iteration finds a flipped phase bit. In
/// async mode, scans every async-enabled controller's CQ, wakes the
/// blocked process whose CID matched, then calls schedule() so the
/// woken task gets dispatched IMMEDIATELY instead of waiting up to a
/// timer tick (~10 ms). Without the schedule() call, every async I/O
/// pays a full slice penalty — measured at ~18 ms/call vs the expected
/// ~50 µs NVMe completion latency. Matches killKickHandler's pattern.
fn nvmeIrqHandler() callconv(.c) void {
    irq_count +%= 1;
    if (!ASYNC_BUILD_ENABLED) return;
    var any_woken = false;
    var i: usize = 0;
    while (i < num_controllers) : (i += 1) {
        if (controllers[i].async_mode) {
            if (reapCq(&controllers[i])) any_woken = true;
        }
    }
    // Shape C: do NOT call schedule() from the IRQ handler. Calling schedule
    // here runs with RSP on whatever kstack the IRQ inherited — which may
    // not be current_pid's, opening the cross-stack-aliasing window the
    // mirror-flip detector caught 2026-05-19. Instead, set a flag the
    // DynIrqStub epilogue checks just before iretq; if set, it calls
    // schedule() from the stub's own frame where RSP discipline is sound.
    if (any_woken) {
        const smp = @import("../cpu/smp.zig");
        smp.myCpu().dynirq_preempt_pending = true;
    }
}

fn r32(c: *const Controller, off: u32) u32 {
    return @as(*volatile u32, @ptrFromInt(c.mmio_base + off)).*;
}

fn w32(c: *const Controller, off: u32, val: u32) void {
    @as(*volatile u32, @ptrFromInt(c.mmio_base + off)).* = val;
}

fn w64(c: *const Controller, off: u32, val: u64) void {
    @as(*volatile u64, @ptrFromInt(c.mmio_base + off)).* = val;
}

/// Submission-queue tail doorbell for queue `qid`.
fn sqDoorbell(c: *const Controller, qid: u16) *volatile u32 {
    const stride: u32 = @as(u32, 4) << @intCast(c.doorbell_stride_log);
    return @ptrFromInt(c.mmio_base + 0x1000 + (2 * @as(u32, qid)) * stride);
}

/// Completion-queue head doorbell for queue `qid`.
fn cqDoorbell(c: *const Controller, qid: u16) *volatile u32 {
    const stride: u32 = @as(u32, 4) << @intCast(c.doorbell_stride_log);
    return @ptrFromInt(c.mmio_base + 0x1000 + (2 * @as(u32, qid) + 1) * stride);
}

/// Find every NVMe controller via the PCI cache and try to init each.
/// Stops at MAX_CONTROLLERS.
fn scanAndInit() void {
    var found: [MAX_CONTROLLERS]pci.PciDevice = undefined;
    const n = pci.findAllByClass(PCI_CLASS_STORAGE, PCI_SUBCLASS_NVM, PCI_PROGIF_NVME, &found);
    for (found[0..n]) |dev| {
        if (num_controllers >= MAX_CONTROLLERS) break;
        debug.klog("[nvme] found ctrl#{d} at {x}:{x}.{d} vendor=0x{x} dev=0x{x}\n", .{
            num_controllers, dev.bus, dev.dev, dev.func, dev.vendor_id, dev.device_id,
        });
        if (initController(&controllers[num_controllers], dev, num_controllers)) {
            num_controllers += 1;
        }
    }
}

/// Gap #5 (2026-05-20): track every PMM page initController allocates so
/// any failure on the path frees them all. Pre-fix, a `create IO CQ`
/// failure on line ~435 leaked ~20 pages (admin SQ/CQ, scratch bounce,
/// 16 per-CID bounces, ns_list, IO SQ/CQ) — ~80 KB per failed init,
/// which on the 256 MB QEMU build was enough to cascade subsequent
/// allocations into pressure within seconds. `commit()` flips the
/// committed flag once the controller is fully ready; if `commit()`
/// is never reached, `deinit()` frees everything tracked. Mirrors the
/// pci.BoundHandle pattern (gap pci#3) used by every other DMA driver.
const InitState = struct {
    // Each tracked allocation is (base, page_count). page_count > 1 means
    // an `allocContiguous(count)` block that has to be freed via
    // freeContiguous(base, count), not freeFrame.
    pages: [48]usize = [_]usize{0} ** 48,
    counts: [48]u32 = [_]u32{0} ** 48,
    n: usize = 0,
    committed: bool = false,

    /// Allocate one PMM page and track it. Returns null on alloc
    /// failure; caller propagates that up via the usual `orelse return
    /// false` pattern.
    fn trackAlloc(self: *@This()) ?usize {
        return self.trackAllocN(1);
    }

    /// Allocate `count` contiguous PMM pages and track them as one
    /// block. deinit frees the whole block via freeContiguous on the
    /// abort path. Returns the physical base address of page 0.
    fn trackAllocN(self: *@This(), count: u32) ?usize {
        const p = pmm.allocContiguous(count) orelse return null;
        if (self.n < self.pages.len) {
            self.pages[self.n] = p;
            self.counts[self.n] = count;
            self.n += 1;
        }
        return p;
    }

    fn commit(self: *@This()) void {
        self.committed = true;
    }

    fn deinit(self: *@This()) void {
        if (self.committed) return;
        var i: usize = 0;
        while (i < self.n) : (i += 1) {
            if (self.pages[i] == 0) continue;
            if (self.counts[i] <= 1) {
                pmm.freeFrame(self.pages[i]);
            } else {
                pmm.freeContiguous(self.pages[i], self.counts[i]);
            }
        }
    }
};

fn initController(c: *Controller, dev: pci.PciDevice, idx: usize) bool {
    if (dev.bars[0] == 0) {
        debug.klog("[nvme] ctrl#{d} BAR0 unassigned\n", .{idx});
        return false;
    }
    var bind = pci.bindDevice(dev);
    defer bind.deinit();
    var init_state = InitState{};
    defer init_state.deinit();
    // Store the kernel-side VA (physmap). Hardware never sees mmio_base; only
    // CPU-side register reads/writes through it.
    c.mmio_base = paging.physToVirt(@intCast(dev.bars[0]));

    // Probe MSI-X up front (before CC.EN). If the cap is missing or
    // there's no free dynamic IRQ vector, `use_msix` stays false and we
    // fall back to the original busy-spin polled completion path.
    // Admin queue at entry 0 stays polled; arm entry 1 for the I/O CQ.
    if (msix.armOne(dev, 1, nvmeIrqHandler)) |armed| {
        c.msix_cap = armed.cap;
        c.use_msix = true;
        c.msix_io_entry = armed.entry_addr;
        c.msix_data = armed.vector.data;
        c.msix_current_addr = armed.vector.addr;
        debug.klog("[nvme] ctrl#{d} MSI-X armed: tbl_sz={d} IDT vec=0x{x} dest=0x{x}\n", .{
            idx, armed.cap.table_size, armed.vector.irq_vector, armed.vector.addr,
        });
    } else {
        debug.klog("[nvme] ctrl#{d} MSI-X unavailable, polled mode\n", .{idx});
    }

    const cap_hi = r32(c, REG_CAP_HI);
    c.doorbell_stride_log = @truncate(cap_hi & 0xF); // CAP[35:32]
    debug.klog("[nvme] ctrl#{d} mmio=0x{x} dstrd_log={d}\n", .{ idx, c.mmio_base, c.doorbell_stride_log });

    // Disable the controller before reprogramming AQ pointers.
    const cc = r32(c, REG_CC);
    if (cc & CC_EN != 0) {
        w32(c, REG_CC, cc & ~CC_EN);
        var spin: u32 = 0;
        while ((r32(c, REG_CSTS) & CSTS_RDY) != 0 and spin < 5_000_000) : (spin += 1) {}
    }

    // Allocate one page each for admin SQ (1 KiB used) + admin CQ (256 B).
    const a_sq = init_state.trackAlloc() orelse return false;
    const a_cq = init_state.trackAlloc() orelse return false;
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(a_sq)))[0..4096], 0);
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(a_cq)))[0..4096], 0);
    c.admin_sq = a_sq;
    c.admin_cq = a_cq;

    // AQA[27:16] = ACQS-1, AQA[11:0] = ASQS-1.
    const aqa: u32 = (@as(u32, Q_DEPTH - 1) << 16) | @as(u32, Q_DEPTH - 1);
    w32(c, REG_AQA, aqa);
    // Split 64-bit ASQ/ACQ writes into separate 32-bit MMIO ops — some
    // PCIe controllers fault on a quad-word access; pairs always work.
    w32(c, REG_ASQ_LO, @truncate(a_sq));
    w32(c, REG_ASQ_HI, @truncate(a_sq >> 32));
    w32(c, REG_ACQ_LO, @truncate(a_cq));
    w32(c, REG_ACQ_HI, @truncate(a_cq >> 32));

    // IOMMU Phase 3: switch this device onto its own isolated SL page
    // table and explicitly map the admin queues BEFORE CC.EN flips. From
    // CC.EN onward the controller can DMA to anything we've mapped (and
    // ONLY that) — an OOB write hits the fault recording register.
    // Order matters: enableIsolation MUST precede the dmaMap calls (a
    // no-op when IOMMU isn't running; safe to call unconditionally).
    _ = iommu.enableIsolation(dev.bus, dev.dev, dev.func);
    _ = iommu.dmaMap(dev.bus, dev.dev, dev.func, a_sq, 4096, .{});
    _ = iommu.dmaMap(dev.bus, dev.dev, dev.func, a_cq, 4096, .{});

    // Set SQ/CQ entry sizes, leave CSS=NVM, MPS=0 (4 KiB), then enable.
    w32(c, REG_CC, CC_IOSQES_64 | CC_IOCQES_16);
    w32(c, REG_CC, CC_IOSQES_64 | CC_IOCQES_16 | CC_EN);

    var spin: u32 = 0;
    while ((r32(c, REG_CSTS) & CSTS_RDY) == 0 and spin < 10_000_000) : (spin += 1) {}
    if ((r32(c, REG_CSTS) & CSTS_RDY) == 0) {
        debug.klog("[nvme] ctrl#{d} not RDY (csts=0x{x})\n", .{ idx, r32(c, REG_CSTS) });
        return false;
    }

    c.next_cid = 1;
    // The legacy single-page `c.bounce_buf` was dropped 2026-05-20 with
    // the PRP-list bump — `ioCommandSync` now reuses `bounce_bufs[0]`,
    // and the field on Controller is gone. No allocation needed here.

    // Per-CID bounce buffers + PRP list pages for the async path.
    // BOUNCE_PAGES_PER_SLOT contiguous pages per slot (32 KiB at the
    // default 8) so a single command can transfer up to 64 sectors;
    // one extra page per slot for the PRP list when the transfer
    // spans > 2 pages. IOMMU-map both ranges so the device can DMA.
    var ci: usize = 0;
    while (ci < Q_DEPTH) : (ci += 1) {
        const bb = init_state.trackAllocN(BOUNCE_PAGES_PER_SLOT) orelse return false;
        c.bounce_bufs[ci] = bb;
        _ = iommu.dmaMap(dev.bus, dev.dev, dev.func, bb, BOUNCE_BYTES_PER_SLOT, .{});
        const list_pg = init_state.trackAlloc() orelse return false;
        c.prp_list_phys[ci] = list_pg;
        _ = iommu.dmaMap(dev.bus, dev.dev, dev.func, list_pg, 4096, .{});
    }

    // Step 1: list active namespaces. NSID 0 is "no specific NS" for the
    // CNS=2 query. Result is a u32[1024] table of NSIDs (zero-terminated).
    const ns_list_phys = init_state.trackAlloc() orelse return false;
    _ = iommu.dmaMap(dev.bus, dev.dev, dev.func, ns_list_phys, 4096, .{});
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(ns_list_phys)))[0..4096], 0);
    if (!adminCommand(c, .{
        .opcode = ADMIN_IDENTIFY,
        .nsid = 0,
        .prp1 = ns_list_phys,
        .cdw10 = CNS_ACTIVE_NS_LIST,
    })) {
        debug.klog("[nvme] ctrl#{d} identify nslist failed\n", .{idx});
        return false;
    }
    const ns_list: *const [1024]u32 = @ptrFromInt(paging.physToVirt(ns_list_phys));
    if (ns_list[0] == 0) {
        debug.klog("[nvme] ctrl#{d} no active namespaces\n", .{idx});
        return false;
    }
    c.nsid = ns_list[0];

    // Step 2: identify the namespace to learn its block size. The Identify
    // Namespace structure has FLBAS at byte 26 (low 4 bits = LBA Format
    // index), and an array of 16 LBAFx entries starting at byte 128 — each
    // 4 bytes, with byte 2 carrying LBADS (block size = 2^LBADS).
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(ns_list_phys)))[0..4096], 0);
    if (!adminCommand(c, .{
        .opcode = ADMIN_IDENTIFY,
        .nsid = c.nsid,
        .prp1 = ns_list_phys,
        .cdw10 = CNS_NAMESPACE,
    })) {
        debug.klog("[nvme] ctrl#{d} identify ns failed\n", .{idx});
        return false;
    }
    const id_ns: [*]const u8 = @ptrFromInt(paging.physToVirt(ns_list_phys));
    const flbas = id_ns[26];
    const lbaf_idx: usize = flbas & 0x0F;
    const lbads = id_ns[128 + lbaf_idx * 4 + 2];
    c.block_size = @as(u32, 1) << @intCast(lbads);
    debug.klog("[nvme] ctrl#{d} nsid={d} block_size={d}\n", .{ idx, c.nsid, c.block_size });

    if (c.block_size != SECTOR_SIZE) {
        debug.klog("[nvme] ctrl#{d} block_size {d} != 512, refusing\n", .{ idx, c.block_size });
        return false;
    }

    // Step 3: allocate I/O queue pair (qid=1). One page each.
    const io_sq = init_state.trackAlloc() orelse return false;
    const io_cq = init_state.trackAlloc() orelse return false;
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(io_sq)))[0..4096], 0);
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(io_cq)))[0..4096], 0);
    c.io_sq = io_sq;
    c.io_cq = io_cq;
    _ = iommu.dmaMap(dev.bus, dev.dev, dev.func, io_sq, 4096, .{});
    _ = iommu.dmaMap(dev.bus, dev.dev, dev.func, io_cq, 4096, .{});

    // Create I/O completion queue first — the SQ creation command needs
    // to reference an existing CQ. cdw11 layout: IV[31:16] | IEN[1] | PC[0].
    // With MSI-X armed, IV=1 (matches the table entry we wrote in
    // initController) and IEN=1; otherwise IEN=0 and the device never
    // asserts an interrupt.
    const cq_cdw11: u32 = if (c.use_msix) (@as(u32, 1) << 16) | (@as(u32, 1) << 1) | 1 else 1;
    if (!adminCommand(c, .{
        .opcode = ADMIN_CREATE_CQ,
        .prp1 = io_cq,
        .cdw10 = (@as(u32, Q_DEPTH - 1) << 16) | 1, // qsize-1 << 16 | qid
        .cdw11 = cq_cdw11,
    })) {
        debug.klog("[nvme] ctrl#{d} create IO CQ failed\n", .{idx});
        return false;
    }

    if (!adminCommand(c, .{
        .opcode = ADMIN_CREATE_SQ,
        .prp1 = io_sq,
        .cdw10 = (@as(u32, Q_DEPTH - 1) << 16) | 1,
        .cdw11 = (1 << 16) | 1, // CQID=1 << 16 | PC=1
    })) {
        debug.klog("[nvme] ctrl#{d} create IO SQ failed\n", .{idx});
        return false;
    }

    c.initialized = true;
    debug.klog("[nvme] ctrl#{d} ready\n", .{idx});
    init_state.commit();
    bind.commit();
    return true;
}

/// Issue an admin command. Caller fills opcode + the relevant fields;
/// we set cid and post the command. Polls to completion.
const AdminArgs = struct {
    opcode: u8,
    nsid: u32 = 0,
    prp1: u64 = 0,
    prp2: u64 = 0,
    cdw10: u32 = 0,
    cdw11: u32 = 0,
    cdw12: u32 = 0,
    // Gap #17 (2026-05-20): the original struct stopped at cdw12, leaving
    // no way to issue admin commands that need the upper command-data
    // words (Get Log Page's LOL/LOU dword pair, certain Get Features
    // selectors). Adding them as zero-defaulted keeps every existing
    // caller untouched.
    cdw13: u32 = 0,
    cdw14: u32 = 0,
    cdw15: u32 = 0,
};

fn adminCommand(c: *Controller, args: AdminArgs) bool {
    const cid = c.next_cid;
    c.next_cid +%= 1;
    const slot_addr = c.admin_sq + @as(usize, c.admin_sq_tail) * 64;
    const slot32: [*]volatile u32 = @ptrFromInt(paging.physToVirt(slot_addr));
    writeSqe(slot32, args.opcode, cid, args.nsid, args.prp1, args.prp2, args.cdw10, args.cdw11, args.cdw12);
    // Gap #17: overlay cdw13/14/15 on top of writeSqe's zero-fill so
    // callers that set the new AdminArgs fields actually transmit them.
    // Skipping the writes when zero keeps the common path unchanged.
    if (args.cdw13 != 0) slot32[13] = args.cdw13;
    if (args.cdw14 != 0) slot32[14] = args.cdw14;
    if (args.cdw15 != 0) slot32[15] = args.cdw15;
    storeBarrier();
    c.admin_sq_tail = (c.admin_sq_tail + 1) % Q_DEPTH;
    sqDoorbell(c, 0).* = @as(u32, c.admin_sq_tail);
    // Admin queue stays polled (init-only path; no MSI-X entry is armed
    // for it).
    return waitCompletion(c, c.admin_cq, &c.admin_cq_head, &c.admin_cq_phase, 0, false);
}

/// Drain prior WB stores (the SQE bytes) before any subsequent operation.
/// Empirically, `mfence` alone wasn't enough on this QEMU/KVM setup —
/// the controller's read of the SQ would see the zero-initialized memory
/// instead of our just-written command. Adding a single OUT to port 0x80
/// (a harmless BIOS POST-diagnostic register) fixes it: UC writes are
/// serializing on x86 and flush the store buffer in a way that the
/// emulated NVMe device's guest-memory read can definitely observe. The
/// mfence is kept to be belt-and-suspenders.
inline fn storeBarrier() void {
    asm volatile ("mfence" ::: .{ .memory = true });
    io.outb(0x80, 0);
}

/// Lay an SQ entry as 16 explicit volatile u32 writes. Volatile keeps
/// the compiler from reordering the SQE writes past the volatile
/// doorbell write (without it Zig was free to hoist the doorbell up,
/// since the SQ memory and the MMIO doorbell don't alias). The format
/// is the NVMe 64-byte command structure (NVMe spec §4.2):
///   dword 0  : cid<<16 | flags<<8 | opcode
///   dword 1  : nsid
///   dword 2-3: reserved
///   dword 4-5: mptr (metadata pointer)
///   dword 6-7: prp1
///   dword 8-9: prp2
///   dword 10 : cdw10
///   dword 11 : cdw11
///   dword 12-15: cdw12..15 (zeroed for the commands we issue today)
/// Compute PRP1/PRP2 for a transfer of `n_bytes` starting at the named
/// slot's bounce buffer. Used by both sync and async I/O paths.
///
/// NVMe's PRP rules:
///   * `n_bytes <= 4096`: PRP1 = bounce, PRP2 = 0.
///   * `n_bytes <= 8192`: PRP1 = bounce (page0), PRP2 = bounce + 4096
///     (page1). No PRP list needed for exactly 2 pages.
///   * `n_bytes >  8192`: PRP1 = bounce (page0), PRP2 = `prp_list_phys`
///     (phys addr of a 4 KiB page whose first (n_pages - 1) u64 entries
///     point to page1, page2, ..., page(N-1)). One PRP list page covers
///     up to 512 entries × 4 KiB = 2 MiB — far past our 32 KiB ceiling.
///
/// `bounce_bufs[slot_idx]` is contiguous in physical memory across
/// `BOUNCE_PAGES_PER_SLOT` pages (allocated via `pmm.allocContiguous`),
/// so the PRP list is just a flat `bounce + i*4096` sequence — no
/// scatter/gather complexity.
const Prp = struct { prp1: u64, prp2: u64 };
fn buildPrp(c: *Controller, slot_idx: u16, n_bytes: u32) Prp {
    const bounce = c.bounce_bufs[slot_idx];
    if (n_bytes <= 4096) return .{ .prp1 = bounce, .prp2 = 0 };
    if (n_bytes <= 8192) return .{ .prp1 = bounce, .prp2 = bounce + 4096 };
    const list_va: [*]volatile u64 = @ptrFromInt(paging.physToVirt(c.prp_list_phys[slot_idx]));
    const n_pages: u32 = (n_bytes + 4095) / 4096;
    var i: u32 = 0;
    while (i + 1 < n_pages) : (i += 1) {
        list_va[i] = bounce + @as(u64, i + 1) * 4096;
    }
    return .{ .prp1 = bounce, .prp2 = c.prp_list_phys[slot_idx] };
}

fn writeSqe(s: [*]volatile u32, opcode: u8, cid: u16, nsid: u32, prp1: u64, prp2: u64, cdw10: u32, cdw11: u32, cdw12: u32) void {
    s[0] = @as(u32, opcode) | (@as(u32, cid) << 16);
    s[1] = nsid;
    s[2] = 0;
    s[3] = 0;
    s[4] = 0;
    s[5] = 0;
    s[6] = @truncate(prp1);
    s[7] = @truncate(prp1 >> 32);
    s[8] = @truncate(prp2);
    s[9] = @truncate(prp2 >> 32);
    s[10] = cdw10;
    s[11] = cdw11;
    s[12] = cdw12;
    s[13] = 0;
    s[14] = 0;
    s[15] = 0;
}

fn waitCompletion(c: *const Controller, cq_phys: usize, head_ptr: *u16, phase_ptr: *bool, qid: u16, use_irq: bool) bool {
    _ = use_irq;
    const cq: [*]volatile CqEntry = @ptrFromInt(paging.physToVirt(cq_phys));
    // rdtsc-based deadline. The old sti+hlt path relied on the LAPIC timer
    // to wake hlt every 10ms — if LAPIC IRQ delivery to this CPU stops
    // working (which redteam tripped on the secondary controller), hlt
    // parks forever and no post-hlt counter helps. Pause-spin with an
    // rdtsc deadline is bounded regardless of interrupt state.
    //
    // NVMe normal completion latency is <100µs; pause-spinning for that
    // long is essentially free (~hundreds of µs of CPU). The MSI-X retarget
    // logic above is now a no-op for waking us but still ensures the IRQ
    // handler runs on the right CPU when the device completes.
    const t_start = @import("../debug/perf.zig").rdtsc();
    // ~2s at 1 GHz min TSC freq — generous on any modern CPU.
    const TIMEOUT_CYC: u64 = 2_000_000_000;
    while (true) {
        if (@import("../debug/perf.zig").rdtsc() -% t_start > TIMEOUT_CYC) {
            const csts = r32(c, REG_CSTS);
            debug.klog("[nvme] waitCompletion timeout (qid={d} head={d} csts=0x{x})\n", .{ qid, head_ptr.*, csts });
            // Gap #4 (2026-05-20): CSTS.CFS = controller fatal status.
            // If set, the device has irrecoverably failed and is dropping
            // every command. Call it out explicitly — otherwise the
            // recurring timeouts look like SW bugs.
            if (csts & CSTS_CFS != 0) {
                debug.klog("[nvme] ===> CSTS.CFS set: CONTROLLER IN FATAL STATE — all subsequent commands will fail\n", .{});
            }
            return false;
        }

        // QEMU's NVMe iothread writes completions on a different host
        // CPU; the guest's L1 keeps a stale (zero) copy of the cache line
        // unless we explicitly invalidate it. clflush + mfence guarantees
        // each load goes to actual memory.
        //
        // clflush takes a *virtual* address — the CPU walks paging to find
        // the cache line. Passing cq_phys directly used to work back when
        // PML4[0] held the 1:1 low-identity map, but that was dropped in
        // Phase 3 (see project_phase3_pml4_drop). Use the already-translated
        // virtual cq pointer instead.
        const slot_vaddr = @intFromPtr(&cq[head_ptr.*]);
        asm volatile ("clflush (%[ptr])"
            :
            : [ptr] "r" (slot_vaddr),
            : .{ .memory = true });
        asm volatile ("mfence" ::: .{ .memory = true });
        const status_word = cq[head_ptr.*].status;
        const phase_bit = (status_word & 1) != 0;
        if (phase_bit == phase_ptr.*) {
            const sc = status_word >> 1;
            head_ptr.* = (head_ptr.* + 1) % Q_DEPTH;
            // Phase flips each time the head wraps the queue.
            if (head_ptr.* == 0) phase_ptr.* = !phase_ptr.*;
            cqDoorbell(c, qid).* = head_ptr.*;
            if (sc != 0) {
                debug.klog("[nvme] cmd error sc=0x{x}\n", .{sc});
                return false;
            }
            return true;
        }
        asm volatile ("pause");
    }
}

// Aggregate counters for read-path investigation. Diff'd by callers to
// attribute spend to a specific load (vfs.loadFileFresh).
pub var io_call_count: u64 = 0;
pub var io_total_cycles: u64 = 0;
pub var io_wait_cycles: u64 = 0;
pub var io_msix_retargets: u64 = 0;
pub var io_max_wait_cycles: u64 = 0;

/// Bounce buffer size per CID slot, in 4 KiB pages. Contiguous in
/// physical memory so the SQE can describe it with one PRP page list.
/// 8 pages × 4 KiB = 32 KiB per slot → MAX_SECTORS_PER_CMD = 64.
/// 16 slots × 32 KiB = 512 KiB per controller (was 64 KiB at 1 page/slot).
const BOUNCE_PAGES_PER_SLOT: u32 = 8;
const BOUNCE_BYTES_PER_SLOT: u32 = BOUNCE_PAGES_PER_SLOT * 4096;

/// Max sectors per NVMe command. Bounded by the bounce buffer (each cmd
/// must fit in BOUNCE_PAGES_PER_SLOT pages = 32 KiB = 64 sectors at the
/// hardware-mandated 512 B sector size). Larger transfers split at the
/// caller via readSectorsSecondary's loop. Pre-2026-05-20 this was 8
/// (single-PRP, no list) and an 963 KB app load took ~241 commands; with
/// 64 it's ~30 commands — 8× fewer iothread round-trips, which is the
/// actual bottleneck on QEMU NVMe.
const MAX_SECTORS_PER_CMD: u32 = 64;

/// Issue an N-sector I/O (1..MAX_SECTORS_PER_CMD). Bounce-buffers the
/// data through the per-controller scratch page so the user buffer can
/// be any alignment.
fn ioCommand(c: *Controller, opcode: u8, lba: u32, user_buf: usize, sectors: u32) bool {
    if (!c.initialized) return false;
    if (sectors == 0 or sectors > MAX_SECTORS_PER_CMD) return false;
    // Route to async path if this controller has been switched over.
    // ctrl_idx = pointer arithmetic into the global controllers[] array
    // so blockOn's wait_target is unambiguous.
    if (ASYNC_BUILD_ENABLED and c.async_mode) {
        const idx_offset = (@intFromPtr(c) - @intFromPtr(&controllers[0])) / @sizeOf(Controller);
        return ioCommandAsync(c, @intCast(idx_offset), opcode, lba, user_buf, sectors);
    }
    const t_call_start = @import("../debug/perf.zig").rdtsc();

    // Serialize across CPUs — bounce_buf, SQ tail, CQ head/phase, and the
    // MSI-X table entry retarget below all assume single-issuer state.
    //
    // IRQ-disabled acquire: if a timer/NVMe IRQ fires on this CPU while
    // we hold io_lock, its handler can set `dynirq_preempt_pending` which
    // makes the IRQ stub's epilogue call `schedule()`, parking us .ready
    // with the lock STILL HELD. The newly-dispatched task on this CPU
    // then spins forever in io_lock.acquire — classic
    // SpinLock-held-across-schedule deadlock, reproduced 2026-05-20
    // (single-CPU lock-spin dump, holder and spinner both at this site).
    // acquireIrqSave keeps timer/NVMe IRQs queued at the LAPIC until we
    // release; the critical section is short (SQE write + doorbell), so
    // queue depth is bounded by one tick.
    //
    // Stale comment removed: the pre-2026-05-20 path used `sti; hlt` in
    // waitCompletion and needed IRQs on — that path is gone (see
    // waitCompletion's `_ = use_irq;` at line ~667), and pause-spin
    // works regardless of IF state.
    const _lock_flags = c.io_lock.acquireIrqSave();
    defer c.io_lock.releaseIrqRestore(_lock_flags);

    const xfer_bytes: u32 = sectors * c.block_size;
    // Sync path reuses bounce_bufs[0] (legacy single-page bounce_buf was
    // dropped — the per-slot array is now BOUNCE_BYTES_PER_SLOT-sized and
    // sync is serialized by io_lock, so picking a fixed slot is safe and
    // gives us the same 64-sector ceiling as async without parallel
    // submitter concerns).
    const sync_slot: u16 = 0;
    const sync_bounce_phys = c.bounce_bufs[sync_slot];
    if (opcode == IO_WRITE) {
        const dst: [*]u8 = @ptrFromInt(paging.physToVirt(sync_bounce_phys));
        const src: [*]const u8 = @ptrFromInt(user_buf);
        @memcpy(dst[0..xfer_bytes], src[0..xfer_bytes]);
    }

    const cid = c.next_cid;
    c.next_cid +%= 1;
    const slot_addr = c.io_sq + @as(usize, c.io_sq_tail) * 64;
    const slot32: [*]volatile u32 = @ptrFromInt(paging.physToVirt(slot_addr));
    const prp = buildPrp(c, sync_slot, xfer_bytes);
    writeSqe(slot32, opcode, cid, c.nsid, prp.prp1, prp.prp2, lba, 0, sectors - 1);
    // cdw10=LBA[31:0], cdw11=LBA[63:32]=0, cdw12 num_lbas-1.

    storeBarrier();

    // Gap #15 (2026-05-20): the original MSI-X retarget here aimed to
    // steer the IRQ to the CPU doing `sti; hlt`. waitCompletion has
    // since moved to pause-spin (the `use_irq` param is discarded;
    // line ~530), so retargeting MSI-X does nothing useful in this
    // sync path — pause-spin doesn't sleep on IRQ. Async retarget in
    // ioCommandAsync below still matters because that path genuinely
    // waits via MWAIT / blockOn. Deleted the dead retarget block here.

    c.io_sq_tail = (c.io_sq_tail + 1) % Q_DEPTH;
    sqDoorbell(c, 1).* = @as(u32, c.io_sq_tail);

    const t_wait_start = @import("../debug/perf.zig").rdtsc();
    if (!waitCompletion(c, c.io_cq, &c.io_cq_head, &c.io_cq_phase, 1, c.use_msix)) return false;
    const t_wait_end = @import("../debug/perf.zig").rdtsc();
    const wait_dt = t_wait_end -% t_wait_start;
    io_wait_cycles +%= wait_dt;
    if (wait_dt > io_max_wait_cycles) io_max_wait_cycles = wait_dt;

    if (opcode == IO_READ) {
        const dst: [*]u8 = @ptrFromInt(user_buf);
        const src: [*]const u8 = @ptrFromInt(paging.physToVirt(sync_bounce_phys));
        @memcpy(dst[0..xfer_bytes], src[0..xfer_bytes]);
    }
    const t_call_end = @import("../debug/perf.zig").rdtsc();
    io_call_count += 1;
    io_total_cycles +%= t_call_end -% t_call_start;
    return true;
}

// ============================================================
// Async I/O path (Phase B — dead code until `async_mode` flipped)
// ============================================================
//
// Submit-and-yield model. `ioCommandAsync` allocates a free CID via
// allocCid, writes the SQE using bounce_bufs[cid] as PRP1, rings the
// doorbell, then `blockOn(.nvme_io, packed_target)`. The NVMe IRQ
// handler (`nvmeIrqHandler`) calls `reapCq` for each controller,
// which advances io_cq_head, finds the matching waiter by CID, sets
// completed/status_code, and `process.wake(waiter.pid)`. The woken
// process reads its waiter slot, copies bounce → user for IO_READ,
// frees the CID, and returns.
//
// Concurrency:
//   - Multiple submitters race on cid allocation + SQ tail bump. Both
//     happen inside io_lock (short critical section, no waitCompletion).
//   - Reaper holds cq_lock while advancing io_cq_head; submitters never
//     touch io_cq_head in async mode, so cq_lock and io_lock are
//     non-overlapping.
//   - Waiter slot transition active→completed is atomic-release; reader
//     in waiter's wake-up path uses atomic-acquire.

/// Allocate a free waiter slot, bump its generation counter, and return
/// the packed CID `(new_gen << 4) | slot_idx`. Caller must already hold
/// `c.io_lock`. Returns null if Q_DEPTH commands are already in flight.
///
/// The packed CID is what gets written into the SQE and echoed by the
/// device in the CQE. `reapCq` decodes both halves to detect orphan
/// completions (gen mismatch == slot was abandoned + reused since this
/// command was issued).
fn allocCid(c: *Controller) ?u16 {
    // Lockless slot claim via per-slot CAS on `active`. Pre-rework this
    // was a linear scan under `io_lock`; the lock was the dominant cost
    // in ioCommand's cli-hold (8-28 ms). Multiple submitters can claim
    // different free slots in parallel here without ANY locking.
    //
    // Ordering: gen MUST be bumped AFTER winning the CAS (so we know we
    // own the slot exclusively) and BEFORE returning the cid (so the
    // submitter writes the new gen into the SQE, and any late CQE from
    // the previous occupant orphan-misses on gen mismatch in reapCq).
    // A late CQE arriving in the (CAS-win, gen-bump) window would match
    // the OLD gen — reapCq would set `completed=true` on us spuriously.
    // We reset `completed` after the gen bump so the submitter never
    // sees that stale write when it starts polling.
    var i: u16 = 0;
    while (i < Q_DEPTH) : (i += 1) {
        if (@atomicLoad(bool, &c.waiters[i].active, .acquire)) continue;
        if (@cmpxchgStrong(bool, &c.waiters[i].active, false, true, .acq_rel, .acquire)) |_| {
            // CAS lost — another CPU just claimed this slot.
            continue;
        }
        // Own the slot. Bump gen atomically, then reset state.
        const new_gen = nextGen(@atomicLoad(u16, &c.waiters[i].gen, .acquire));
        @atomicStore(u16, &c.waiters[i].gen, new_gen, .release);
        @atomicStore(bool, &c.waiters[i].completed, false, .release);
        c.waiters[i].success = false;
        c.waiters[i].status_code = 0;
        c.waiters[i].wake = .{ .pid = 0xFF };
        c.waiters[i].sq_slot = 0xFFFF;
        return packCid(i, new_gen);
    }
    return null;
}

/// CQ scanner. Advances io_cq_head over every CQE whose phase bit
/// matches our expected value, finds the matching waiter by CID, sets
/// completion fields, and wakes the blocked process. Returns true iff
/// at least one waiter was woken.
///
/// Callable from both IRQ context (primary path, via nvmeIrqHandler)
/// and task context (defensive safety-net call from ioCommandAsync's
/// wait loop, to recover from lost MSI-X messages caused by mask races
/// during mid-flight retargeting or PCIe posted-write ordering hiding
/// the CQE from the IRQ-side read). `acquireIrqSave` ensures the lock
/// is safe to take from either side without recursive-deadlock if an
/// IRQ arrives mid-section in task context.
fn reapCq(c: *Controller) bool {
    if (!c.initialized) return false;

    // Wakes are STAGED inside the cq_lock window and DISPATCHED outside.
    // Each proc.wake takes sched_lock; inlining 16 of them under cq_lock
    // gave us [cli-hold] reapCq+0x34 holds of 5-39 ms under mtswap
    // (2026-05-24). Pulling dispatch out shortens cq_lock to "drain CQEs
    // + advance head + ring doorbell" — pure device-state work. Waiter
    // slot is pinned by `gen`, so a TIMEOUT path racing to free between
    // release and dispatch is safe: the wake still goes to the right pid
    // (and that pid's blockOn returns whether or not we woke it).
    const PendingWake = struct {
        wake: WakeMode,
        success: bool,
        sc: u16,
    };
    var pending: [Q_DEPTH]PendingWake = undefined;
    var pending_count: usize = 0;
    var any_woken = false;

    {
        const irq_flags = c.cq_lock.acquireIrqSave();
        defer c.cq_lock.releaseIrqRestore(irq_flags);
        const cq: [*]volatile CqEntry = @ptrFromInt(paging.physToVirt(c.io_cq));
        var any = false;
        while (true) {
            const slot_vaddr = @intFromPtr(&cq[c.io_cq_head]);
            asm volatile ("clflush (%[ptr])"
                :
                : [ptr] "r" (slot_vaddr),
                : .{ .memory = true });
            asm volatile ("mfence" ::: .{ .memory = true });
            const status_word = cq[c.io_cq_head].status;
            const phase_bit = (status_word & 1) != 0;
            if (phase_bit != c.io_cq_phase) break;
            const cid = cq[c.io_cq_head].cid;
            const sc = status_word >> 1;
            // Gap #2+#3 (2026-05-20): decode the slot + generation. The slot
            // tells us which waiter to wake; the generation tells us this
            // completion is for the CURRENT occupant of that slot. A gen
            // mismatch means the original submitter timed out and abandoned;
            // the slot may now hold a different waiter that we MUST NOT
            // mistakenly wake with this stale completion.
            const slot_idx = cidSlot(cid);
            const expected_gen = cidGen(cid);
            const w = &c.waiters[slot_idx];
            if (w.active and w.gen == expected_gen) {
                w.status_code = sc;
                w.success = (sc == 0);
                @atomicStore(bool, &w.completed, true, .release);
                // Stage — dispatch below, outside cq_lock.
                pending[pending_count] = .{
                    .wake = w.wake,
                    .success = w.success,
                    .sc = sc,
                };
                pending_count += 1;
                any_woken = true;
            } else {
                // Orphan: either the slot was already freed (a TIMEOUT path
                // abandoned it), or the slot was reused under a new gen
                // (active=true but gen has moved on). Either way the
                // completion is not for any current waiter — log it and
                // drop. Without this branch the orphan would be silently
                // swallowed; the previous code path even risked falsely
                // waking the slot's CURRENT owner with stale status data.
                debug.klog(
                    "[nvme] orphan CQE: cid=0x{X:0>4} (slot={d} gen={d}) sc=0x{X} — current slot active={any} gen={d}\n",
                    .{ cid, slot_idx, expected_gen, sc, w.active, w.gen },
                );
            }
            c.io_cq_head = (c.io_cq_head + 1) % Q_DEPTH;
            if (c.io_cq_head == 0) c.io_cq_phase = !c.io_cq_phase;
            c.cqe_drained_count +%= 1; // gap #12
            any = true;
        }
        if (any) cqDoorbell(c, 1).* = c.io_cq_head;
    }

    // Dispatch — cq_lock released, still in IRQ context. proc.wake
    // takes sched_lock; the staging above keeps that out of our cli
    // window. .cb path is io_uring's IRQ callback (same constraints as
    // before minus the cq_lock-held claim).
    if (pending_count > 0) {
        const proc = @import("../proc/process.zig");
        var i: usize = 0;
        while (i < pending_count) : (i += 1) {
            const p = pending[i];
            switch (p.wake) {
                .pid => |pid| proc.wake(pid),
                .cb => |hook| hook.callback(hook.ctx, p.success, p.sc),
            }
        }
    }

    return any_woken;
}

/// Introspection helper used by the yield-loop detector. `wait_target`
/// is the same encoding as `PCB.wait_target` for `WaitKind.nvme_io`:
/// (ctrl_idx << 16) | cid. Dumps the waiter slot, the SW-side CQ state,
/// and peeks the CQE at `io_cq_head` — if its phase bit matches the
/// SW-expected phase, the hardware has already written a completion
/// there and the IRQ-reaper has failed to pick it up. That single line
/// is the root-cause discriminator between "HW stuck" and "SW missed
/// the wake".
pub fn dumpWaiterForTarget(wait_target: u32) void {
    const ctrl_idx: usize = @intCast((wait_target >> 16) & 0xFFFF);
    const packed_cid: u16 = @intCast(wait_target & 0xFFFF);
    if (ctrl_idx >= num_controllers) {
        debug.klog("  nvme: ctrl_idx={d} out of range (num_controllers={d})\n", .{ ctrl_idx, num_controllers });
        return;
    }
    // Gap #1 follow-up (2026-05-20): the wait_target embeds the
    // *packed* cid (gen<<4 | slot), not the bare slot index. Pre-fix
    // this function rejected every async cid with the "out of range"
    // message because slot+gen always exceeded Q_DEPTH=16. Decode both
    // halves so the dump actually fires.
    const slot_idx: u16 = cidSlot(packed_cid);
    const expected_gen: u16 = cidGen(packed_cid);
    const c = &controllers[ctrl_idx];
    const w = &c.waiters[slot_idx];
    debug.klog("  nvme{d}.waiters[slot={d} expected_gen={d} packed_cid=0x{X:0>4}]:\n", .{ ctrl_idx, slot_idx, expected_gen, packed_cid });
    debug.klog("    active     = {any}\n", .{w.active});
    debug.klog("    completed  = {any}\n", .{w.completed});
    debug.klog("    success    = {any}\n", .{w.success});
    debug.klog("    status     = 0x{X:0>4}\n", .{w.status_code});
    switch (w.wake) {
        .pid => |p| debug.klog("    wake       = pid({d})\n", .{p}),
        .cb => |hook| debug.klog("    wake       = cb(fn=0x{X:0>16} ctx=0x{X:0>16})\n", .{ @intFromPtr(hook.callback), hook.ctx }),
    }
    debug.klog("    current_gen= {d}{s}\n", .{
        w.gen,
        if (w.gen == expected_gen) "" else " (MISMATCH — slot was reused since this command issued)",
    });
    // Gap #11 (2026-05-20): dump the SQE for this waiter so the autopsy
    // can confirm "our cmd really is queued at sq_slot N with the right
    // opcode/nsid/lba". Skips when sq_slot is 0xFFFF (never set —
    // shouldn't happen for an active waiter).
    if (w.sq_slot < Q_DEPTH) {
        const sqe_addr = c.io_sq + @as(usize, w.sq_slot) * 64;
        const sqe: [*]const volatile u32 = @ptrFromInt(paging.physToVirt(sqe_addr));
        debug.klog("  nvme{d}.io_sq[{d}] (the SQE for this waiter):\n", .{ ctrl_idx, w.sq_slot });
        debug.klog("    dword0=0x{X:0>8} (opcode=0x{X} cid=0x{X:0>4})\n", .{ sqe[0], sqe[0] & 0xFF, sqe[0] >> 16 });
        debug.klog("    nsid={d} prp1=0x{X:0>8}_{X:0>8} cdw10/lba=0x{X}\n", .{ sqe[1], sqe[7], sqe[6], sqe[10] });
        debug.klog("    cdw12=0x{X} (num_lbas-1 + flags)\n", .{sqe[12]});
        const cid_in_sqe: u16 = @intCast(sqe[0] >> 16);
        if (cid_in_sqe != packed_cid) {
            debug.klog("    ===> SQE.cid 0x{X} != waiter packed_cid 0x{X} — slot was REUSED\n", .{ cid_in_sqe, packed_cid });
        }
    }
    debug.klog("  nvme{d}.cq:\n", .{ctrl_idx});
    debug.klog("    sw_head     = {d}\n", .{c.io_cq_head});
    debug.klog("    sw_phase    = {any}\n", .{c.io_cq_phase});
    debug.klog("    sw_sq_tail  = {d}\n", .{c.io_sq_tail});
    debug.klog("    async_mode  = {any}\n", .{c.async_mode});
    debug.klog("    cqe_drained = {d} (per-ctrl, gap #12)\n", .{c.cqe_drained_count});
    debug.klog("    queue_full_retries = {d}\n", .{c.queue_full_retries});

    const cq: [*]volatile CqEntry = @ptrFromInt(paging.physToVirt(c.io_cq));
    // clflush head slot so we read whatever HW DMA'd most recently, not
    // a stale cache line. Same pattern reapCq uses on its scan.
    const slot_vaddr = @intFromPtr(&cq[c.io_cq_head]);
    asm volatile ("clflush (%[ptr])"
        :
        : [ptr] "r" (slot_vaddr),
        : .{ .memory = true });
    const head_cqe = cq[c.io_cq_head];
    const hw_phase = (head_cqe.status & 1) != 0;
    debug.klog("    cq[head].cid    = {d}\n", .{head_cqe.cid});
    debug.klog("    cq[head].status = 0x{X:0>4}\n", .{head_cqe.status});
    debug.klog("    cq[head].phase  = {any}\n", .{hw_phase});
    if (hw_phase == c.io_cq_phase) {
        debug.klog("    ===> HW completion present at head; SW reaper missed it\n", .{});
    } else {
        debug.klog("    (HW phase != SW expected; no pending completion at head)\n", .{});
    }
    debug.klog("  nvme{d}.irq_count = {d}\n", .{ ctrl_idx, irq_count });
}

/// Async I/O command — submit and block until IRQ wakes us. Caller
/// passes the user-side virtual buffer; we bounce through bounce_bufs
/// for alignment + IOMMU containment. Returns true on success.
fn ioCommandAsync(c: *Controller, ctrl_idx: u32, opcode: u8, lba: u32, user_buf: usize, sectors: u32) bool {
    if (!c.initialized) return false;
    if (sectors == 0 or sectors > MAX_SECTORS_PER_CMD) return false;
    const t_call_start = @import("../debug/perf.zig").rdtsc();

    // ---- Submit phase: lockless prep + narrow lock for SQ tail+doorbell ----
    // Step 2 (2026-05-24): allocCid is now lockless (per-slot CAS on
    // .active). Step 3 narrows io_lock to just the SQE write + tail bump
    // + doorbell — the writes that MUST be ordered across submitters
    // because they all target io_sq[io_sq_tail] and the single doorbell
    // register. Everything else (waiter setup, bounce copy, MSI-X
    // retarget, build PRP) is per-slot or per-controller-but-already-
    // synchronized state and runs lock-free in parallel across CPUs.
    const MAX_QUEUE_FULL_RETRIES: u32 = 8;
    const proc = @import("../proc/process.zig");
    const smp = @import("../cpu/smp.zig");
    const cid: u16 = blk_alloc: {
        var attempts: u32 = 0;
        while (true) : (attempts += 1) {
            if (allocCid(c)) |c_packed| break :blk_alloc c_packed;
            if (attempts >= MAX_QUEUE_FULL_RETRIES) {
                debug.klog("[nvme] queue full after {d} retries on ctrl#{d} (pid={d}, opcode=0x{X}, lba={d})\n", .{
                    attempts, ctrl_idx, smp.myCpu().current_pid orelse 0xFF, opcode, lba,
                });
                return false;
            }
            c.queue_full_retries +%= 1;
            // Yield so the IRQ reaper (or tickSweep) gets a chance to
            // drain in-flight completions. Must set pending_soft_yield
            // first — without it handleIRQ0 mis-attributes the int $0x20
            // as a kernel-mode hardware timer (sendEOI+rearm+return) and
            // never calls schedule(), making the "yield" a no-op spin.
            smp.myCpu().pending_soft_yield = true;
            @import("../proc/sched_asm.zig").softYield();
        }
    };
    // Gap #2: `cid` is now a packed (gen << 4) | slot value. The slot
    // index — which we use to index `bounce_bufs`, `waiters`, etc. — is
    // the low 4 bits; the gen is upper bits and goes into the SQE as-is.
    const slot_idx: u16 = cidSlot(cid);
    const bounce_phys = c.bounce_bufs[slot_idx];
    const xfer_bytes: u32 = sectors * c.block_size;

    // Mark the waiter as belonging to the current process so the IRQ
    // handler knows whom to wake. allocCid already CAS-claimed the slot
    // exclusively to us — no lock needed for these per-slot writes.
    const cur_pid: u8 = if (smp.myCpu().current_pid) |p| @intCast(p) else 0xFF;
    c.waiters[slot_idx].wake = .{ .pid = cur_pid };

    // For IO_WRITE, copy user → bounce. Slot is ours via CAS until we
    // free it; the bounce buffer at bounce_bufs[slot_idx] is per-slot
    // so no other submitter touches it. Lock-free.
    if (opcode == IO_WRITE) {
        const dst: [*]u8 = @ptrFromInt(paging.physToVirt(bounce_phys));
        const src: [*]const u8 = @ptrFromInt(user_buf);
        @memcpy(dst[0..xfer_bytes], src[0..xfer_bytes]);
    }

    // MSI-X retarget: msix_current_addr is shared per-controller, but
    // updates are idempotent (any LAPIC that the IRQ delivers to can
    // handle the wake — pid lookup is global). Two CPUs racing to write
    // distinct dest_ids would just oscillate; pick one with a brief
    // io_lock window OR move this OUT entirely. For now keep inside the
    // narrow lock below — costs one MMIO write on the rare retarget.
    const new_msix_addr: u64 = if (c.use_msix) blk: {
        const apic = @import("../time/apic.zig");
        const dest_id: u64 = apic.getLapicId() & 0xFF;
        break :blk 0xFEE00000 | (dest_id << 12);
    } else 0;

    // ---- Narrow critical section: SQE write at our slot + doorbell ----
    // What it protects:
    //   - io_sq_tail bump must atomically pair with the SQE write to
    //     io_sq[tail] — otherwise two submitters could write the same
    //     slot or skip a slot.
    //   - sqDoorbell writes must be in tail order (device reads SQEs
    //     up to the doorbell value).
    //   - MSI-X retarget piggy-backs here (idempotent; cheap).
    // What it does NOT protect:
    //   - allocCid / waiter setup / bounce copy (lockless above).
    //   - bounce_bufs[slot_idx] (per-slot ownership).
    const saved_io_flags = c.io_lock.acquireIrqSave();
    if (c.use_msix and c.msix_current_addr != new_msix_addr) {
        msix.writeEntry(c.msix_io_entry, new_msix_addr, c.msix_data, false);
        c.msix_current_addr = new_msix_addr;
        io_msix_retargets += 1;
    }
    const sq_tail_at_submit = c.io_sq_tail;
    c.waiters[slot_idx].sq_slot = sq_tail_at_submit;
    const slot_addr = c.io_sq + @as(usize, sq_tail_at_submit) * 64;
    const slot32: [*]volatile u32 = @ptrFromInt(paging.physToVirt(slot_addr));
    const prp = buildPrp(c, slot_idx, xfer_bytes);
    writeSqe(slot32, opcode, cid, c.nsid, prp.prp1, prp.prp2, lba, 0, sectors - 1);
    storeBarrier();
    c.io_sq_tail = (sq_tail_at_submit + 1) % Q_DEPTH;
    sqDoorbell(c, 1).* = @as(u32, c.io_sq_tail);
    c.io_lock.releaseIrqRestore(saved_io_flags);

    // ---- Wait phase: yield until IRQ reaper wakes us ----
    const t_wait_start = @import("../debug/perf.zig").rdtsc();
    const wait_target: u32 = (ctrl_idx << 16) | @as(u32, cid);
    // Gap #2 (2026-05-20): wall-clock timeout. The pre-2026-05-20 loop
    // spun until `completed` flipped — under a full IRQ-loss event
    // (device sent the CQE but MSI-X delivery failed AND the per-tick
    // sweeper of gap #1 also couldn't see the CQE, e.g. controller fatal
    // state) we'd park forever. 30s is generous for any legitimate I/O;
    // exceeding it means the device is misbehaving badly enough that
    // we'd rather surface the error than hide it. Slot is abandoned via
    // the gen counter (allocCid bumps on next reuse), so even if the
    // CQE arrives much later it lands in the orphan-log branch of
    // reapCq rather than spuriously waking the slot's next occupant.
    const TIMEOUT_CYC_ASYNC: u64 = 30_000_000_000; // ~30 s at 1 GHz
    // Block until completion. The IRQ reaper sets w.completed and calls
    // proc.wake(w.pid). blockOn handles the wake-pending handshake.
    //
    // Idle-task fast path: when an AP idle is doing the wait (typical
    // for `apProcessLoadQueue` app-load reads), there's nothing else to
    // schedule on this CPU — going through blockOn → softYield →
    // schedule → self-dispatch just busy-spins. Instead, MONITOR the
    // completion byte and MWAIT until the IRQ reaper writes it (or any
    // interrupt arrives). Same latency as blockOn for true completion
    // but zero schedule churn while we wait. Measured 2026-05-19:
    // calc.elf load on AP avg_wait was 42 ms/call from the spin; with
    // MWAIT, drops to the IRQ-latency floor.
    const cur_is_idle = blk: {
        if (smp.myCpu().current_pid) |p| break :blk proc.procs[p].is_idle;
        break :blk false;
    };
    const mwait_mod = @import("../cpu/mwait.zig");
    var timed_out = false;
    while (!@atomicLoad(bool, &c.waiters[slot_idx].completed, .acquire)) {
        if (@import("../debug/perf.zig").rdtsc() -% t_wait_start > TIMEOUT_CYC_ASYNC) {
            timed_out = true;
            break;
        }
        if (cur_is_idle and mwait_mod.mwait_supported) {
            const a = @intFromPtr(&c.waiters[slot_idx].completed);
            asm volatile (
                \\sti
                \\monitor
                :
                : [a] "{rax}" (a),
                  [cx] "{rcx}" (@as(u64, 0)),
                  [d] "{rdx}" (@as(u64, 0)),
            );
            asm volatile (
                \\mwait
                :
                : [a] "{rax}" (mwait_mod.default_hint),
                  [cx] "{rcx}" (@as(u64, 1)),
            );
        } else {
            proc.blockOn(.nvme_io, wait_target);
        }
        // Safety net: opportunistically drain the CQ in case the
        // IRQ-driven reapCq missed our completion. Two known race
        // classes converge here — (1) MSI-X message lost during a
        // mid-flight mask/unmask retarget (PBA replay isn't always
        // reliable under QEMU contention), and (2) PCIe posted-write
        // ordering letting the MSI-X land at the CPU before the CQE
        // DMA is globally visible, so the IRQ-context read saw a
        // stale phase bit and broke. In both cases HW thinks the IRQ
        // was delivered and won't refire; without this drain the
        // waiter would park forever. No-op when the CQ is empty;
        // single MMIO + cq_lock acquire when it isn't.
        _ = reapCq(c);
    }
    const t_wait_end = @import("../debug/perf.zig").rdtsc();
    const wait_dt = t_wait_end -% t_wait_start;
    io_wait_cycles +%= wait_dt;
    if (wait_dt > io_max_wait_cycles) io_max_wait_cycles = wait_dt;

    if (timed_out) {
        debug.klog(
            "[nvme] ASYNC TIMEOUT cid=0x{X:0>4} (slot={d} gen={d}) ctrl#{d} pid={d} opcode=0x{X} lba={d} sectors={d}\n",
            .{ cid, slot_idx, cidGen(cid), ctrl_idx, cur_pid, opcode, lba, sectors },
        );
        // Dump the waiter + CQ state so the autopsy can tell "device
        // never completed" vs "device completed but reapCq missed."
        dumpWaiterForTarget(wait_target);
        // Check CSTS for the controller-fatal bit. If set, the device is
        // permanently dead — log it once so the user sees something
        // other than "everything froze."
        const csts = r32(c, REG_CSTS);
        if (csts & CSTS_CFS != 0) {
            debug.klog("[nvme] ctrl#{d} CONTROLLER FATAL STATUS (csts=0x{X})\n", .{ ctrl_idx, csts });
        }
        // Abandon the slot. The gen counter (which allocCid bumped on
        // entry) is what makes this safe — if the CQE arrives after we
        // free, reapCq's gen check will catch it as an orphan and the
        // slot's NEXT occupant (different gen) won't be falsely woken.
        @atomicStore(bool, &c.waiters[slot_idx].active, false, .release);
        return false;
    }

    const success = c.waiters[slot_idx].success;

    // Copy bounce → user for reads BEFORE freeing the CID, otherwise a
    // racing submitter could reuse the bounce buffer.
    if (opcode == IO_READ and success) {
        const dst: [*]u8 = @ptrFromInt(user_buf);
        const src: [*]const u8 = @ptrFromInt(paging.physToVirt(bounce_phys));
        @memcpy(dst[0..xfer_bytes], src[0..xfer_bytes]);
    }

    // Free the CID slot. Release-ordered so a subsequent allocCid sees
    // the prior fields cleared.
    @atomicStore(bool, &c.waiters[slot_idx].active, false, .release);

    const t_call_end = @import("../debug/perf.zig").rdtsc();
    io_call_count += 1;
    io_total_cycles +%= t_call_end -% t_call_start;
    return success;
}

/// Gap #7+#8 (2026-05-20): async submit/wait helper for commands that
/// don't transfer user data. Used by TRIM (DSM Deallocate) and Write
/// Zeroes — both need the same submit + wait + free-slot machinery as
/// `ioCommandAsync` but without the user-buffer copies. `payload` is
/// optional bytes copied into the slot's bounce buffer (used as PRP1) —
/// DSM uses this for the range structure block; Write Zeroes passes an
/// empty slice and we send prp1=0.
///
/// Why async-only: post-`enableAsync`, sync `next_cid` values can decode
/// to the same packed (gen << 4) | slot as a current async waiter,
/// causing `reapCq` to either falsely wake the wrong pid or steal the
/// CQE from the sync poller's view of `io_cq_head`. Routing these
/// through the async path uses real `allocCid`/`waiters[]` bookkeeping
/// and avoids the collision entirely.
fn submitDatalessAsync(
    c: *Controller,
    ctrl_idx: u32,
    opcode: u8,
    payload: []const u8,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
) bool {
    if (!c.initialized) return false;
    if (!c.async_mode) {
        // Pre-async-enable callers would need a sync variant; not
        // exercised in current code (TRIM and WZ are called from user
        // paths long after enableAsync). Surface the impossibility.
        debug.klog("[nvme] dataless opcode 0x{X} attempted pre-async-enable\n", .{opcode});
        return false;
    }
    if (payload.len > 4096) return false;

    const proc = @import("../proc/process.zig");
    const smp = @import("../cpu/smp.zig");

    // Same queue-full retry pattern as ioCommandAsync (gap #6) — allocCid
    // is lockless since step 2 so the retry loop no longer hangs onto
    // io_lock across the soft-yield.
    const MAX_QUEUE_FULL_RETRIES: u32 = 8;
    const cid: u16 = blk_alloc: {
        var attempts: u32 = 0;
        while (true) : (attempts += 1) {
            if (allocCid(c)) |c_packed| break :blk_alloc c_packed;
            if (attempts >= MAX_QUEUE_FULL_RETRIES) {
                debug.klog("[nvme] dataless 0x{X}: queue full after {d} retries ctrl#{d}\n", .{ opcode, attempts, ctrl_idx });
                return false;
            }
            c.queue_full_retries +%= 1;
            @import("../proc/sched_asm.zig").softYield();
        }
    };
    const slot_idx: u16 = cidSlot(cid);

    // Copy payload into bounce. Per-slot ownership via the allocCid CAS
    // means no other submitter touches bounce_bufs[slot_idx]; no lock.
    var prp1: u64 = 0;
    if (payload.len > 0) {
        prp1 = c.bounce_bufs[slot_idx];
        const bounce: [*]volatile u8 = @ptrFromInt(paging.physToVirt(prp1));
        @memcpy(bounce[0..payload.len], payload);
    }

    const cur_pid: u8 = if (smp.myCpu().current_pid) |p| @intCast(p) else 0xFF;
    c.waiters[slot_idx].wake = .{ .pid = cur_pid };

    const new_msix_addr: u64 = if (c.use_msix) blk: {
        const apic_mod = @import("../time/apic.zig");
        const dest_id: u64 = apic_mod.getLapicId() & 0xFF;
        break :blk 0xFEE00000 | (dest_id << 12);
    } else 0;

    // Narrow critical section: SQE write at our slot + tail bump + doorbell.
    // See ioCommandAsync above for the rationale.
    const saved_io_flags = c.io_lock.acquireIrqSave();
    if (c.use_msix and c.msix_current_addr != new_msix_addr) {
        msix.writeEntry(c.msix_io_entry, new_msix_addr, c.msix_data, false);
        c.msix_current_addr = new_msix_addr;
        io_msix_retargets += 1;
    }
    const sq_tail_at_submit = c.io_sq_tail;
    c.waiters[slot_idx].sq_slot = sq_tail_at_submit;
    const slot_addr = c.io_sq + @as(usize, sq_tail_at_submit) * 64;
    const slot32: [*]volatile u32 = @ptrFromInt(paging.physToVirt(slot_addr));
    writeSqe(slot32, opcode, cid, c.nsid, prp1, 0, cdw10, cdw11, cdw12);
    storeBarrier();
    c.io_sq_tail = (sq_tail_at_submit + 1) % Q_DEPTH;
    sqDoorbell(c, 1).* = @as(u32, c.io_sq_tail);
    c.io_lock.releaseIrqRestore(saved_io_flags);

    // Wait phase — same shape as ioCommandAsync.
    const t_wait_start = @import("../debug/perf.zig").rdtsc();
    const wait_target: u32 = (ctrl_idx << 16) | @as(u32, cid);
    const TIMEOUT_CYC_ASYNC: u64 = 30_000_000_000;

    const cur_is_idle = blk: {
        if (smp.myCpu().current_pid) |p| break :blk proc.procs[p].is_idle;
        break :blk false;
    };
    const mwait_mod = @import("../cpu/mwait.zig");
    var timed_out = false;
    while (!@atomicLoad(bool, &c.waiters[slot_idx].completed, .acquire)) {
        if (@import("../debug/perf.zig").rdtsc() -% t_wait_start > TIMEOUT_CYC_ASYNC) {
            timed_out = true;
            break;
        }
        if (cur_is_idle and mwait_mod.mwait_supported) {
            const a = @intFromPtr(&c.waiters[slot_idx].completed);
            asm volatile (
                \\sti
                \\monitor
                :
                : [a] "{rax}" (a),
                  [cx] "{rcx}" (@as(u64, 0)),
                  [d] "{rdx}" (@as(u64, 0)),
            );
            asm volatile (
                \\mwait
                :
                : [a] "{rax}" (mwait_mod.default_hint),
                  [cx] "{rcx}" (@as(u64, 1)),
            );
        } else {
            proc.blockOn(.nvme_io, wait_target);
        }
        _ = reapCq(c);
    }

    if (timed_out) {
        debug.klog("[nvme] dataless ASYNC TIMEOUT cid=0x{X:0>4} (slot={d}) ctrl#{d} opcode=0x{X}\n", .{ cid, slot_idx, ctrl_idx, opcode });
        dumpWaiterForTarget(wait_target);
        @atomicStore(bool, &c.waiters[slot_idx].active, false, .release);
        return false;
    }

    const success = c.waiters[slot_idx].success;
    @atomicStore(bool, &c.waiters[slot_idx].active, false, .release);
    return success;
}

/// NVMe Flush (opcode 0x00). Tells the controller to commit all writes
/// for `nsid` to non-volatile storage. Without this, writes can sit in
/// the device write cache and be lost on power loss / hard reset.
///
/// Routes through `submitDatalessAsync` (same machinery as TRIM/WZ) so the
/// async CQ reaper sees a proper packed-CID waiter rather than a raw
/// `next_cid` value. Pre-fix this used the sync path with raw next_cid:
/// post-enableAsync, the MSI-X for the flush could land on a peer CPU, get
/// reaped by `reapCq`, fail the CID→waiter lookup (because raw next_cid
/// rarely decodes to a live `(gen<<4)|slot`), advance `io_cq_head` past
/// the flush CQE, and leave the sync poller spinning for the 2s timeout
/// while shutdown silently misses the actual flush. Closes a race the
/// reviewer caught on 2026-05-23 surfaced by the swap-async flip.
fn flushController(c: *Controller) bool {
    if (!c.initialized) return false;
    const idx_offset = (@intFromPtr(c) - @intFromPtr(&controllers[0])) / @sizeOf(Controller);
    return submitDatalessAsync(c, @intCast(idx_offset), IO_FLUSH, &[_]u8{}, 0, 0, 0);
}

// === Public surface ===

pub fn init() bool {
    scanAndInit();
    if (num_controllers == 0) return false;
    const spinlock = @import("../proc/spinlock.zig");
    if (num_controllers >= 1) spinlock.registerLock("nvme0.io_lock", &controllers[0].io_lock);
    if (num_controllers >= 2) spinlock.registerLock("nvme1.io_lock", &controllers[1].io_lock);
    debug.klog("[nvme] {d} controller(s) ready (primary={s}, secondary={s})\n", .{
        num_controllers,
        if (num_controllers >= 1) "yes" else "no",
        if (num_controllers >= 2) "yes" else "no",
    });
    return true;
}

pub fn isReady() bool {
    return num_controllers > 0;
}

/// Gap #1 (2026-05-20): per-tick CQ sweeper. Wired into `handleIRQ0`
/// (BSP only) so the entire system gets at least one `reapCq` call per
/// LAPIC timer tick (~10 ms), regardless of MSI-X delivery.
///
/// Why this is necessary: the async path's `reapCq` is normally driven
/// by the device's MSI-X message. Two races silently lose that message:
///   1. MSI-X mask/unmask retarget mid-flight — PBA replay isn't reliable
///      under QEMU contention, so a message can be discarded.
///   2. PCIe posted-write ordering — the MSI-X can land at the CPU
///      BEFORE the CQE DMA is globally visible, so the IRQ handler's
///      clflush'd read sees a stale phase bit and breaks, and the device
///      never re-fires (it thinks the IRQ was delivered).
/// In both cases the blocked task's `blockOn` never returns, the
/// safety-net `reapCq` inside `ioCommandAsync` never runs, and the task
/// parks forever — the recurring wedge the yield-loop detector caught
/// on 2026-05-19 and again 2026-05-20.
///
/// Cost: one clflush + ~one MMIO read per controller per tick when the
/// CQ is empty; one full drain per tick if completions are pending.
/// Negligible for ZigOS's I/O rates.
pub fn tickSweep() void {
    if (!ASYNC_BUILD_ENABLED) return;
    var i: usize = 0;
    while (i < num_controllers) : (i += 1) {
        if (controllers[i].async_mode) _ = reapCq(&controllers[i]);
    }
}

pub fn hasSecondary() bool {
    return num_controllers >= 2;
}

pub fn readSectorPrimary(lba: u32, dest: [*]u8) void {
    if (num_controllers < 1) return;
    _ = ioCommand(&controllers[0], IO_READ, lba, @intFromPtr(dest), 1);
}

pub fn readSectorsPrimary(lba: u32, count: u8, dest: [*]u8) void {
    if (num_controllers < 1) return;
    var done: u32 = 0;
    const total: u32 = if (count == 0) 256 else @as(u32, count);
    while (done < total) {
        const chunk: u32 = @min(total - done, MAX_SECTORS_PER_CMD);
        _ = ioCommand(&controllers[0], IO_READ, lba + done, @intFromPtr(dest) + done * controllers[0].block_size, chunk);
        done += chunk;
    }
}

pub fn readSectorSecondary(lba: u32, dest: [*]u8) void {
    if (num_controllers < 2) return;
    _ = ioCommand(&controllers[1], IO_READ, lba, @intFromPtr(dest), 1);
}

pub fn readSectorsSecondary(lba: u32, count: u8, dest: [*]u8) void {
    if (num_controllers < 2) return;
    var done: u32 = 0;
    const total: u32 = if (count == 0) 256 else @as(u32, count);
    while (done < total) {
        const chunk: u32 = @min(total - done, MAX_SECTORS_PER_CMD);
        _ = ioCommand(&controllers[1], IO_READ, lba + done, @intFromPtr(dest) + done * controllers[1].block_size, chunk);
        done += chunk;
    }
}

/// Generic indexed sector I/O for callers that aren't the FS primary/secondary
/// — currently the swap subsystem on controller #2. Chunks by
/// MAX_SECTORS_PER_CMD. Returns false if `idx` isn't an initialized controller.
/// `dest`/`src` is a kernel VA; a physmap VA is fine (ioCommand does the DMA
/// translation), which is how swap passes physToVirt(frame).
pub fn readSectorsOn(idx: usize, lba: u32, count: u32, dest: [*]u8) bool {
    if (idx >= num_controllers) return false;
    const c = &controllers[idx];
    var done: u32 = 0;
    while (done < count) {
        const chunk: u32 = @min(count - done, MAX_SECTORS_PER_CMD);
        if (!ioCommand(c, IO_READ, lba + done, @intFromPtr(dest) + done * c.block_size, chunk)) return false;
        done += chunk;
    }
    return true;
}

pub fn writeSectorsOn(idx: usize, lba: u32, count: u32, src: [*]const u8) bool {
    if (idx >= num_controllers) return false;
    const c = &controllers[idx];
    var done: u32 = 0;
    while (done < count) {
        const chunk: u32 = @min(count - done, MAX_SECTORS_PER_CMD);
        if (!ioCommand(c, IO_WRITE, lba + done, @intFromPtr(src) + done * c.block_size, chunk)) return false;
        done += chunk;
    }
    return true;
}

// === Per-IRQ async path (io_uring A1) ===
//
// `ioCommandAsync` blocks the caller until the IRQ reaper calls
// `proc.wake(w.pid)` and the caller observes `completed=true`. That model
// serializes ops within a single caller — a 4-op io_uring submit
// dispatches one at a time because the worker can only park on one CID.
//
// `submitAsyncCallback` is the same submit half WITHOUT the wait. The
// caller registers a completion callback; the IRQ reaper invokes it from
// IRQ context when the CQE arrives. This lets io_uring's worker submit
// N ops, return immediately, park on a single .iouring_complete wait,
// and have every callback wake it when any op finishes — true per-IRQ
// concurrency.
//
// Bounce buffer ownership: the per-CID `bounce_bufs[slot_idx]` is used
// as the DMA target, same as the sync path. Caller copies user→bounce
// before submit (for WRITE) and bounce→user after callback (for READ),
// via `bounceBufPhys(ctrl_idx, packed_cid)`. The CID stays allocated
// (waiter.active=true) from submit until the caller invokes
// `releaseAsyncCid` — this prevents the slot's bounce buffer from being
// reused mid-flight.

pub const AsyncCompletionFn = *const fn (ctx: usize, success: bool, sc: u16) callconv(.c) void;

/// Submit an async I/O with a completion callback. Returns true on submit;
/// false on controller-not-ready / bad args / queue-full (caller decides
/// whether to retry). On success, `out_packed_cid` receives the CID the
/// caller passes back to `bounceBufPhys` and `releaseAsyncCid`.
///
/// IRQ-context contract: the callback runs from `reapCq` in IRQ
/// context (cli/iretq window) but with `cq_lock` ALREADY RELEASED as
/// of step-1 of the lockless-rework (2026-05-24 — see reapCq). Keep
/// it brief — atomic stores and a single `proc.wake` are fine;
/// anything that might yield is not.
pub fn submitAsyncCallback(
    ctrl_idx: u32,
    opcode: u8,
    lba: u32,
    sectors: u32,
    callback: AsyncCompletionFn,
    ctx: usize,
    out_packed_cid: *u16,
) bool {
    if (ctrl_idx >= num_controllers) return false;
    const c = &controllers[ctrl_idx];
    if (!c.initialized or !c.async_mode) return false;
    if (sectors == 0 or sectors > MAX_SECTORS_PER_CMD) return false;
    if (opcode != IO_READ and opcode != IO_WRITE) return false;

    // allocCid is lockless (step 2). One-shot here — no queue-full retry
    // because submitAsyncCallback callers (io_uring) handle EAGAIN.
    const cid = allocCid(c) orelse return false;
    const slot_idx: u16 = cidSlot(cid);
    const xfer_bytes: u32 = sectors * c.block_size;

    // Wake mode = callback (per-slot, owned by us via the CAS in allocCid).
    c.waiters[slot_idx].wake = .{ .cb = .{ .callback = callback, .ctx = ctx } };

    const new_msix_addr: u64 = if (c.use_msix) blk: {
        const apic_mod = @import("../time/apic.zig");
        const dest_id: u64 = apic_mod.getLapicId() & 0xFF;
        break :blk 0xFEE00000 | (dest_id << 12);
    } else 0;

    // Narrow critical section: SQE write + tail bump + doorbell.
    const saved_flags = c.io_lock.acquireIrqSave();
    if (c.use_msix and c.msix_current_addr != new_msix_addr) {
        msix.writeEntry(c.msix_io_entry, new_msix_addr, c.msix_data, false);
        c.msix_current_addr = new_msix_addr;
        io_msix_retargets += 1;
    }
    const sq_tail_at_submit = c.io_sq_tail;
    c.waiters[slot_idx].sq_slot = sq_tail_at_submit;
    const slot_addr = c.io_sq + @as(usize, sq_tail_at_submit) * 64;
    const slot32: [*]volatile u32 = @ptrFromInt(paging.physToVirt(slot_addr));
    const prp = buildPrp(c, slot_idx, xfer_bytes);
    writeSqe(slot32, opcode, cid, c.nsid, prp.prp1, prp.prp2, lba, 0, sectors - 1);
    storeBarrier();
    c.io_sq_tail = (sq_tail_at_submit + 1) % Q_DEPTH;
    sqDoorbell(c, 1).* = @as(u32, c.io_sq_tail);
    c.io_lock.releaseIrqRestore(saved_flags);

    out_packed_cid.* = cid;
    return true;
}

/// Physical base of the per-CID bounce buffer. Caller converts to a
/// kernel VA via `paging.physToVirt` to copy data in/out. Only valid
/// between a successful `submitAsyncCallback` and the matching
/// `releaseAsyncCid` call.
pub fn bounceBufPhys(ctrl_idx: u32, packed_cid: u16) ?usize {
    if (ctrl_idx >= num_controllers) return null;
    const slot_idx: u16 = cidSlot(packed_cid);
    if (slot_idx >= Q_DEPTH) return null;
    return controllers[ctrl_idx].bounce_bufs[slot_idx];
}

/// Release the CID after the caller is done with the bounce buffer
/// (typically: after a READ has been copied to user). MUST be called
/// exactly once per successful `submitAsyncCallback`.
pub fn releaseAsyncCid(ctrl_idx: u32, packed_cid: u16) void {
    if (ctrl_idx >= num_controllers) return;
    const slot_idx: u16 = cidSlot(packed_cid);
    if (slot_idx >= Q_DEPTH) return;
    @atomicStore(bool, &controllers[ctrl_idx].waiters[slot_idx].active, false, .release);
}

/// Block size for `ctrl_idx`. Used by io_uring to compute the byte-len
/// CQE result from the SQE's sector count.
pub fn controllerBlockSize(ctrl_idx: u32) u32 {
    if (ctrl_idx >= num_controllers) return 0;
    return controllers[ctrl_idx].block_size;
}

/// Max sectors per single submit, exposed so io_uring can validate the
/// SQE's `len` field client-side without recompiling on Q_DEPTH changes.
pub fn maxSectorsPerCmd() u32 {
    return MAX_SECTORS_PER_CMD;
}

/// Number of initialized NVMe controllers (swap.zig checks this to see if its
/// dedicated device is present).
pub fn controllerCount() usize {
    return num_controllers;
}

/// Commit any in-flight writes to non-volatile storage on the primary
/// controller. Returns true on success. Callers concerned about
/// crash-consistency (file commits, shutdown) should call this after
/// the last write.
pub fn flushPrimary() bool {
    if (num_controllers < 1) return false;
    return flushController(&controllers[0]);
}

pub fn flushSecondary() bool {
    if (num_controllers < 2) return false;
    return flushController(&controllers[1]);
}

/// Convenience: flush every initialized controller. Use from shutdown
/// paths where you don't care about which controller.
pub fn flushAll() void {
    var i: usize = 0;
    while (i < num_controllers) : (i += 1) {
        _ = flushController(&controllers[i]);
    }
}

/// Switch every initialized controller into async I/O mode. After this
/// call, ioCommand routes through ioCommandAsync (submit-and-yield +
/// IRQ reaper). Caller MUST already be a scheduled task — early-boot
/// callers without a current_pid will dead-lock in blockOn. Suggested
/// call site: top of the first user-mode task entry (desktop.taskEntry)
/// after the scheduler is fully active.
pub fn enableAsync() void {
    if (!ASYNC_BUILD_ENABLED) return;
    var i: usize = 0;
    while (i < num_controllers) : (i += 1) {
        controllers[i].async_mode = true;
        // 2026-05-20 cleanup: the legacy single-page `bounce_buf` field
        // is gone. Sync path now uses `bounce_bufs[0]`, which stays
        // valid post-flip (async submitters won't pick slot 0 specifically;
        // they just race for the first free slot via allocCid, and after
        // the flip nobody calls sync anyway).
    }
    debug.klog("[nvme] async I/O enabled on {d} controller(s)\n", .{num_controllers});
}

pub fn writeSectorSecondary(lba: u32, src: [*]const u8) void {
    if (num_controllers < 2) return;
    _ = ioCommand(&controllers[1], IO_WRITE, lba, @intFromPtr(src), 1);
}

// =========================================================================
// Gap #7: TRIM (DSM Deallocate) — tell the SSD's flash translation layer
// the named LBA range is no longer in use. Big SSD-lifespan and write-
// performance win once the disk has been filled once. Single-range API
// today; block.zig batch-delete paths can extend to multi-range later.
// =========================================================================

fn trimController(c: *Controller, ctrl_idx: u32, lba: u64, num_blocks: u32) bool {
    if (num_blocks == 0) return true; // no-op trim is fine
    if (num_blocks > 0xFFFF_FFFF) return false; // single u32 length field
    const range = DsmRange{
        .context_attributes = 0,
        .length = num_blocks,
        .starting_lba = lba,
    };
    const payload = std.mem.asBytes(&range);
    // cdw10: number of ranges - 1. We send exactly one.
    // cdw11: DSM attributes — Deallocate (AD = bit 2).
    return submitDatalessAsync(c, ctrl_idx, IO_DSM, payload, 0, DSM_ATTR_AD, 0);
}

pub fn trimPrimary(lba: u64, num_blocks: u32) bool {
    if (num_controllers < 1) return false;
    return trimController(&controllers[0], 0, lba, num_blocks);
}

pub fn trimSecondary(lba: u64, num_blocks: u32) bool {
    if (num_controllers < 2) return false;
    return trimController(&controllers[1], 1, lba, num_blocks);
}

// =========================================================================
// Gap #8: Write Zeroes — device zero-fills the specified LBA range
// internally without any PCIe data transfer. ~100× cheaper than
// write(zeros) for sparse-file holes or shred-style zero passes.
// =========================================================================

fn writeZeroesControllerImpl(c: *Controller, ctrl_idx: u32, lba: u64, num_blocks: u32) bool {
    if (num_blocks == 0) return true;
    if (num_blocks > 0x10000) return false; // NVMe spec caps at u16+1 LBAs per cmd
    // cdw10/11: starting LBA. cdw12: num_lbas - 1 (low 16 bits) + DEAC/PRINFO/etc
    // (all left zero). Empty payload → prp1=0.
    const lba_lo: u32 = @truncate(lba);
    const lba_hi: u32 = @truncate(lba >> 32);
    const nlb_m1: u32 = num_blocks - 1;
    return submitDatalessAsync(c, ctrl_idx, IO_WRITE_ZEROES, &[_]u8{}, lba_lo, lba_hi, nlb_m1);
}

pub fn writeZeroesPrimary(lba: u64, num_blocks: u32) bool {
    if (num_controllers < 1) return false;
    return writeZeroesControllerImpl(&controllers[0], 0, lba, num_blocks);
}

pub fn writeZeroesSecondary(lba: u64, num_blocks: u32) bool {
    if (num_controllers < 2) return false;
    return writeZeroesControllerImpl(&controllers[1], 1, lba, num_blocks);
}

/// Zero a range, preferring the primary controller. Caller specifies
/// which device via a separate selector — same shape as the existing
/// `flushPrimary`/`flushSecondary` split.
pub fn writeZeroesAll(lba: u64, num_blocks: u32) void {
    _ = writeZeroesPrimary(lba, num_blocks);
    _ = writeZeroesSecondary(lba, num_blocks);
}
