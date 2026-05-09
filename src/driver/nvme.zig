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

// --- Admin command opcodes ---
const ADMIN_CREATE_SQ: u8 = 0x01;
const ADMIN_CREATE_CQ: u8 = 0x05;
const ADMIN_IDENTIFY: u8 = 0x06;

// --- I/O command opcodes ---
const IO_WRITE: u8 = 0x01;
const IO_READ: u8 = 0x02;

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
const MAX_CONTROLLERS: usize = 2;
const SECTOR_SIZE: u32 = 512;

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

    // 4 KiB-aligned scratch page used as a bounce buffer for read/write
    // PRPs — lets the caller pass non-page-aligned destinations.
    bounce_buf: usize = 0,

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
};

var controllers: [MAX_CONTROLLERS]Controller = .{ .{}, .{} };
var num_controllers: usize = 0;
pub var irq_count: u64 = 0;

/// Catch-all MSI-X handler: just bumps a counter and returns. The real
/// work — re-reading the CQ — happens in the next iteration of the
/// `waitCompletion` hlt loop. The handler exists only so the LAPIC can
/// EOI and the kernel can be woken from `hlt`.
fn nvmeIrqHandler() callconv(.c) void {
    irq_count +%= 1;
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

fn initController(c: *Controller, dev: pci.PciDevice, idx: usize) bool {
    if (dev.bar0 == 0) {
        debug.klog("[nvme] ctrl#{d} BAR0 unassigned\n", .{idx});
        return false;
    }
    pci.bindDevice(dev);
    // Store the kernel-side VA (physmap). Hardware never sees mmio_base; only
    // CPU-side register reads/writes through it.
    c.mmio_base = paging.physToVirt(@intCast(dev.bar0));

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
    const a_sq = pmm.allocContiguous(1) orelse return false;
    const a_cq = pmm.allocContiguous(1) orelse return false;
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
    c.bounce_buf = pmm.allocContiguous(1) orelse return false;

    // Step 1: list active namespaces. NSID 0 is "no specific NS" for the
    // CNS=2 query. Result is a u32[1024] table of NSIDs (zero-terminated).
    const ns_list_phys = pmm.allocContiguous(1) orelse return false;
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
    const io_sq = pmm.allocContiguous(1) orelse return false;
    const io_cq = pmm.allocContiguous(1) orelse return false;
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(io_sq)))[0..4096], 0);
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(io_cq)))[0..4096], 0);
    c.io_sq = io_sq;
    c.io_cq = io_cq;

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
};

fn adminCommand(c: *Controller, args: AdminArgs) bool {
    const cid = c.next_cid;
    c.next_cid +%= 1;
    const slot_addr = c.admin_sq + @as(usize, c.admin_sq_tail) * 64;
    const slot32: [*]volatile u32 = @ptrFromInt(paging.physToVirt(slot_addr));
    writeSqe(slot32, args.opcode, cid, args.nsid, args.prp1, args.prp2, args.cdw10, args.cdw11, args.cdw12);
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
    const cq: [*]volatile CqEntry = @ptrFromInt(paging.physToVirt(cq_phys));
    var spin: u32 = 0;
    while (true) {
        // For the MSI-X path, mask IRQs across the phase check so the
        // sti+hlt shadow guarantees atomicity. Without the cli below, the
        // window between the phase check and `sti; hlt` is interrupt-
        // observable: an MSI-X arriving in that window is consumed by the
        // dummy handler, hlt then reaches with nothing pending, and AP
        // sleeps until the next 100 Hz timer (~10 ms). A 0.x % miss rate
        // there inflates avg_wait per sector by 10-30x — exactly the
        // pattern we measured on app loads (paint 226 µs, files 1700 µs).
        if (use_irq) asm volatile ("cli" ::: .{ .memory = true });

        // QEMU's NVMe iothread writes completions on a different host
        // CPU; the guest's L1 keeps a stale (zero) copy of the cache line
        // unless we explicitly invalidate it. clflush + mfence guarantees
        // each load goes to actual memory. Still required even with
        // MSI-X — the LAPIC interrupt delivery is a separate memory write
        // and doesn't snoop the CQ's cache line for us.
        const slot_addr = cq_phys + @as(usize, head_ptr.*) * @sizeOf(CqEntry);
        asm volatile ("clflush (%[ptr])"
            :
            : [ptr] "r" (slot_addr),
            : .{ .memory = true });
        asm volatile ("mfence" ::: .{ .memory = true });
        const status_word = cq[head_ptr.*].status;
        const phase_bit = (status_word & 1) != 0;
        if (phase_bit == phase_ptr.*) {
            if (use_irq) asm volatile ("sti" ::: .{ .memory = true });
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
        if (use_irq) {
            // sti + hlt is atomic (sti shadow); we won't miss an IRQ
            // delivered between the two. With cli above guarding the
            // phase check, the entire check-then-sleep is atomic w.r.t.
            // IRQ delivery — no missed wake.
            asm volatile ("sti; hlt" ::: .{ .memory = true });
        } else {
            asm volatile ("pause");
            spin += 1;
            if (spin > 50_000_000) {
                debug.klog("[nvme] command timeout (qid={d} head={d} csts=0x{x})\n", .{ qid, head_ptr.*, r32(c, REG_CSTS) });
                return false;
            }
        }
    }
}

// Aggregate counters for read-path investigation. Diff'd by callers to
// attribute spend to a specific load (vfs.loadFileFresh).
pub var io_call_count: u64 = 0;
pub var io_total_cycles: u64 = 0;
pub var io_wait_cycles: u64 = 0;
pub var io_msix_retargets: u64 = 0;
pub var io_max_wait_cycles: u64 = 0;

/// Max sectors per NVMe command, bounded by the 4 KiB bounce buffer (8
/// sectors fit). Larger transfers would need a second PRP page or a PRP
/// list — we punt on that complexity and batch in 8-sector chunks at the
/// caller. Going from 1→8 sectors per command alone cuts ~88% of QEMU
/// NVMe iothread round-trips, which is the actual bottleneck on
/// concurrent app launches (NVMe completion latency on the host
/// dominates per-sector cost).
const MAX_SECTORS_PER_CMD: u32 = 8;

/// Issue an N-sector I/O (1..MAX_SECTORS_PER_CMD). Bounce-buffers the
/// data through the per-controller scratch page so the user buffer can
/// be any alignment.
fn ioCommand(c: *Controller, opcode: u8, lba: u32, user_buf: usize, sectors: u32) bool {
    if (!c.initialized) return false;
    if (sectors == 0 or sectors > MAX_SECTORS_PER_CMD) return false;
    const t_call_start = @import("../debug/perf.zig").rdtsc();

    // Serialize across CPUs — bounce_buf, SQ tail, CQ head/phase, and the
    // MSI-X table entry retarget below all assume single-issuer state.
    // Plain acquire (not acquireIrqSave): the NVMe IRQ handler (just bumps
    // irq_count) doesn't take this lock, so re-entry can't deadlock; and
    // we WANT interrupts on so waitCompletion's sti+hlt actually wakes.
    c.io_lock.acquire();
    defer c.io_lock.release();

    const xfer_bytes: u32 = sectors * SECTOR_SIZE;
    if (opcode == IO_WRITE) {
        const dst: [*]u8 = @ptrFromInt(paging.physToVirt(c.bounce_buf));
        const src: [*]const u8 = @ptrFromInt(user_buf);
        @memcpy(dst[0..xfer_bytes], src[0..xfer_bytes]);
    }

    const cid = c.next_cid;
    c.next_cid +%= 1;
    const slot_addr = c.io_sq + @as(usize, c.io_sq_tail) * 64;
    const slot32: [*]volatile u32 = @ptrFromInt(paging.physToVirt(slot_addr));
    writeSqe(slot32, opcode, cid, c.nsid, c.bounce_buf, 0, lba, 0, sectors - 1);
    // cdw10=LBA[31:0], cdw11=LBA[63:32]=0, cdw12 num_lbas-1.

    storeBarrier();

    // Retarget the MSI-X I/O CQ entry to the calling CPU so its sti+hlt
    // is woken by the actual NVMe completion (~50µs) instead of the local
    // 100Hz LAPIC timer (~10ms). Skip if already targeted at the calling
    // CPU — BSP-side reads (the sysExec/sysExecAs path) hit this every
    // sector and the mask/unmask cycle was stalling MSI-X delivery enough
    // to drop us into the timer fallback, which made shell `files` take
    // ~6 s instead of ~100 ms.
    if (c.use_msix) {
        const apic = @import("../time/apic.zig");
        const dest_id: u64 = apic.getLapicId() & 0xFF;
        const new_addr: u64 = 0xFEE00000 | (dest_id << 12);
        if (c.msix_current_addr != new_addr) {
            msix.writeEntry(c.msix_io_entry, new_addr, c.msix_data, false);
            c.msix_current_addr = new_addr;
            io_msix_retargets += 1;
        }
    }

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
        const src: [*]const u8 = @ptrFromInt(paging.physToVirt(c.bounce_buf));
        @memcpy(dst[0..xfer_bytes], src[0..xfer_bytes]);
    }
    const t_call_end = @import("../debug/perf.zig").rdtsc();
    io_call_count += 1;
    io_total_cycles +%= t_call_end -% t_call_start;
    return true;
}

// === Public surface ===

pub fn init() bool {
    scanAndInit();
    if (num_controllers == 0) return false;
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
        _ = ioCommand(&controllers[0], IO_READ, lba + done, @intFromPtr(dest) + done * SECTOR_SIZE, chunk);
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
        _ = ioCommand(&controllers[1], IO_READ, lba + done, @intFromPtr(dest) + done * SECTOR_SIZE, chunk);
        done += chunk;
    }
}

pub fn writeSectorSecondary(lba: u32, src: [*]const u8) void {
    if (num_controllers < 2) return;
    _ = ioCommand(&controllers[1], IO_WRITE, lba, @intFromPtr(src), 1);
}
