// Intel VT-d / IOMMU.
//
// Three modes a device can run in:
//
//   Shared identity (default): the device's context entry points at
//   `identity_pml4_phys`, a 1 GiB identity-mapped SL page table shared
//   across all devices. IOMMU is on, translation runs, but every DMA
//   gets the same address back. Catches "DMA above 1 GiB" mistakes but
//   not bugs within the identity-mapped range. This is the default
//   because it doesn't require driver changes.
//
//   Isolated (per-device): driver calls `enableIsolation(b,d,f)`. The
//   device gets its own empty PML4. Any DMA to an address NOT
//   explicitly mapped via `dmaMap` faults. This is where the headline
//   "catch DMA bugs as exact faults" benefit lives — bugs hit the
//   fault path immediately instead of corrupting memory.
//
//   Pass-through (T=10b): IOMMU is on but skips translation entirely
//   for this device. Not used by default in this kernel (we prefer
//   identity-mapped translation, which exercises the full machinery
//   and lets us trip faults for OOB DMA). Helpers retained for
//   completeness.
//
// Spec refs: Intel VT-d Specification:
//   §8  — DMAR ACPI table format
//   §9  — Register layout (CAP, ECAP, GCMD, GSTS, RTADDR, CCMD, IOTLB)
//   §10 — Root + context table format
//   §11 — Second-level page table format

const std = @import("std");
const acpi = @import("../../acpi/acpi.zig");
const pmm = @import("../../mm/pmm.zig");
const paging = @import("../../mm/paging.zig");
const debug = @import("../../debug/debug.zig");
const pci = @import("../../driver/pci.zig");
const msix = @import("../../time/msix.zig");
const process = @import("../../proc/process.zig");

// --- VT-d register offsets (relative to each DRHD's `register_base`) ------

const VER: u32 = 0x000;
const CAP: u32 = 0x008;
const ECAP: u32 = 0x010;
const GCMD: u32 = 0x018;
const GSTS: u32 = 0x01C;
const RTADDR: u32 = 0x020;
const CCMD: u32 = 0x028;
const FSTS: u32 = 0x034;
const FECTL: u32 = 0x038;
const FEDATA: u32 = 0x03C;
const FEADDR: u32 = 0x040;
const FEUADDR: u32 = 0x044;

// --- FECTL bit positions (Intel VT-d §11.4.7) -----------------------------
//
// FECTL is the fault-event control register. Setting IM=1 masks the MSI
// (faults pile up in FSTS/FRR but don't deliver). IP is a hardware-set
// pending bit — when an MSI was suppressed by IM, hardware sets IP, and
// clearing IM at any later point re-delivers. We start the firmware
// hand-off masked, write FEDATA/FEADDR/FEUADDR, then clear IM to arm.

const FECTL_IM: u32 = 1 << 31;
const FECTL_IP: u32 = 1 << 30;

// --- GCMD / GSTS bit positions --------------------------------------------

const GCMD_TE: u32 = 1 << 31; // Translation Enable    (level-sensitive)
const GCMD_SRTP: u32 = 1 << 30; // Set Root Table Pointer (one-shot)
const GCMD_WBF: u32 = 1 << 27; // Write Buffer Flush    (one-shot)
const GCMD_QIE: u32 = 1 << 26; // Queued Invalidation   (level-sensitive)
const GCMD_IRE: u32 = 1 << 25; // Interrupt Remap       (level-sensitive)

const GSTS_TES: u32 = 1 << 31;
const GSTS_RTPS: u32 = 1 << 30;
const GSTS_WBFS: u32 = 1 << 27;
const GSTS_QIES: u32 = 1 << 26;
const GSTS_IRES: u32 = 1 << 25;

// --- CAP register bit fields (Intel VT-d §9.1) ----------------------------

inline fn capSagaw(cap: u64) u8 {
    return @intCast((cap >> 8) & 0x1F);
}
inline fn capMgawMinus1(cap: u64) u8 {
    return @intCast((cap >> 16) & 0x3F);
}
inline fn capRwbf(cap: u64) bool {
    return (cap & (1 << 4)) != 0;
}
/// FRO — first Fault Recording Register offset, in bytes. Bits[33:24] of
/// CAP are the offset in 16-byte units.
inline fn capFroOffset(cap: u64) u32 {
    return @intCast(((cap >> 24) & 0x3FF) * 16);
}
/// NFR — Number of Fault-recording Registers minus 1.
inline fn capNfr(cap: u64) u32 {
    return @intCast((cap >> 40) & 0xFF);
}
/// CM — Caching Mode. When set, hardware may cache NOT-present and
/// erroneous entries too, so installing a fresh mapping REQUIRES an
/// invalidation before the device can use it. Real hardware reports 0;
/// emulated IOMMUs (QEMU with caching-mode=on, as vfio needs) report 1.
inline fn capCachingMode(cap: u64) bool {
    return (cap & (1 << 7)) != 0;
}
/// PSI — page-selective-within-domain IOTLB invalidation supported.
inline fn capPsi(cap: u64) bool {
    return (cap & (@as(u64, 1) << 39)) != 0;
}
/// SLLPS bit 0 (CAP[34]) — 2 MiB second-level large pages supported.
inline fn capSllps2M(cap: u64) bool {
    return (cap & (@as(u64, 1) << 34)) != 0;
}

// --- ECAP register bit fields (Intel VT-d §9.3) ---------------------------

inline fn ecapPassThrough(ecap: u64) bool {
    return (ecap & (1 << 6)) != 0;
}
/// C — page-walk coherency: hardware snoops the CPU caches when reading
/// root/context/second-level tables. When CLEAR (common on real Intel
/// client parts; QEMU reports 1), every CPU write to those tables must be
/// CLFLUSHed before hardware is relied on to observe it.
inline fn ecapCoherent(ecap: u64) bool {
    return (ecap & 1) != 0;
}
/// IRO — IOTLB Register Offset, in bytes. ECAP[17:8] in 16-byte units.
inline fn ecapIotlbOffset(ecap: u64) u32 {
    return @intCast(((ecap >> 8) & 0x3FF) * 16);
}

// --- Context-entry translation types --------------------------------------

const T_LEGACY: u64 = 0b00 << 2;
const T_PASS_THROUGH: u64 = 0b10 << 2;

// --- Second-level page-table flags (Intel VT-d §10) ----------------------
//
// Each entry: bit 0 = R, bit 1 = W, bit 7 = PS (large page), bits[12:51]
// = next-level table phys / 4KB-page phys. Bits[3:6] are TM/SNP/ignored
// in the leaf-PT case; we leave them zero. For identity mapping we only
// need R | W.

const SL_R: u64 = 1 << 0;
const SL_W: u64 = 1 << 1;
const SL_RW: u64 = SL_R | SL_W;
const SL_PS: u64 = 1 << 7; // large-page leaf (2 MiB at the PD level)

// --- Identity-map sizing ----------------------------------------------------
//
// The span is computed at init() from the highest usable RAM address PMM
// manages — PMM itself is hard-capped at 4 GiB (see pmm.init), so every
// DMA-able frame a driver can ever hand a device lies below that. A fixed
// 1 GiB (the old constant) silently uncovered frames on any >1 GiB machine:
// the first driver DMA buffer allocated above the span would fault at the
// IOMMU with no kernel-side warning. 1 GiB floor keeps the QEMU 128 MB
// layout building the exact table set it always has.
const IDENTITY_SPAN_FLOOR: u64 = 1 << 30; // 1 GiB
const IDENTITY_SPAN_CEIL: u64 = 1 << 32; // 4 GiB — PMM's own allocation cap
var identity_span: u64 = IDENTITY_SPAN_FLOOR;

/// Leaf size for the shared identity tree: 2 MiB pages when EVERY DRHD
/// supports them (the tree is shared, so the least capable unit decides).
/// QEMU's intel-iommu reports SLLPS=0 (4 KiB only); real hardware
/// virtually always has 2 MiB, collapsing the 4 GiB tree from ~2054
/// frames (~8 MiB) to 7 frames.
var identity_use_2m: bool = false;

/// Number of second-level page-table levels — MUST match the AGAW
/// advertised in every context entry (agaw_common below). 4 levels for
/// 48-bit AGAW, 3 for 39-bit. The old code hardcoded a 4-level tree but
/// fell back to advertising AGAW=39-bit when SAGAW lacked 48-bit support
/// — which is QEMU's intel-iommu DEFAULT (x-aw-bits=39). A 3-level
/// hardware walk over a 4-level tree reads the PML4 as a PDPT and
/// resolves leaf PTEs one level early: DMA "translates" into the page-
/// table frames themselves and corrupts the tree on first write.
var sl_levels: u8 = 4;
var agaw_common: u3 = 2;

/// False when any DRHD reports ECAP.C=0 (page-walk accesses don't snoop
/// the CPU caches): every table write is then CLFLUSHed. QEMU is
/// coherent; real Intel client platforms are commonly NOT.
var tables_coherent: bool = true;

// --- Root + Context entry layout ------------------------------------------
//
// Root table: 4 KB, 256 entries × 16 bytes. Indexed by PCI bus.
//   qword0: bit 0 = Present, bits[63:12] = ctx-table phys >> 12
//   qword1: 0
//
// Context table: 4 KB per bus, 256 entries × 16 bytes. Indexed by
// (dev << 3 | func).
//   qword0: bit 0 = Present, bits[3:2] = T (translation type),
//           bits[63:12] = SLPTPTR phys >> 12 (irrelevant in pass-through)
//   qword1: bits[2:0] = AGAW (address-width selector),
//           bits[23:8] = Domain ID

const Drhd = struct {
    base_phys: u64,
    base_va: usize,
    cap: u64,
    ecap: u64,
    root_phys: u64,
    /// Shadow of the level-sensitive bits we've written to GCMD. Necessary
    /// because GCMD is write-only (reads return undefined per spec) and
    /// each new GCMD write must include the existing level state OR'd
    /// with the new action.
    gcmd_shadow: u32,
    ctx_phys: [256]u64,
};

const MAX_DRHDS: usize = 8;
var drhd_count: usize = 0;
var drhds: [MAX_DRHDS]Drhd = undefined;

/// Root of the second-level page table tree that identity-maps the first
/// `IDENTITY_MAP_SPAN` bytes of physical address space. Shared across all
/// DRHDs and all non-isolated PCI devices. Built once on first bringUp,
/// lives for the kernel's lifetime.
var identity_pml4_phys: u64 = 0;

// --- Per-device tracking --------------------------------------------------
//
// One slot per cached PCI device. The default (shared identity-map) is
// installed in `bringUp` for every device. `enableIsolation` flips a
// specific device to use its own private SL page table, after which
// `dmaMap` calls install explicit mappings.

const Device = struct {
    bus: u8,
    dev: u8,
    func: u8,
    /// Index into `drhds[]` that owns this device's context entry. Today
    /// we assume one DRHD covers everything (typical for QEMU/single-
    /// socket Intel hardware), so this is always 0.
    drhd_idx: u8 = 0,
    /// True after `enableIsolation` has switched this device to its own
    /// private page table.
    isolated: bool = false,
    /// Root of the device's SL page table. Equals `identity_pml4_phys`
    /// when `isolated=false`, points at a private empty PML4 otherwise.
    slptptr_phys: u64 = 0,
    /// VT-d Domain ID. Shared identity uses DID=1; isolated devices get
    /// a unique DID from `next_isolated_did` so per-domain IOTLB and
    /// context-cache invalidations target exactly this device.
    did: u16 = 1,
};

const MAX_DEVICES: usize = 64;
var devices: [MAX_DEVICES]Device = undefined;
var device_count: usize = 0;
var next_isolated_did: u16 = 2; // DID 1 reserved for the shared identity domain

pub const Prot = packed struct(u8) {
    read: bool = true,
    write: bool = true,
    _pad: u6 = 0,
};

pub var iommu_present: bool = false;
pub var translation_active: bool = false;

// --- MMIO helpers ---------------------------------------------------------

inline fn readReg32(base: usize, off: u32) u32 {
    const p: *volatile u32 = @ptrFromInt(base + off);
    return p.*;
}

inline fn writeReg32(base: usize, off: u32, val: u32) void {
    const p: *volatile u32 = @ptrFromInt(base + off);
    p.* = val;
}

inline fn readReg64(base: usize, off: u32) u64 {
    const p: *volatile u64 = @ptrFromInt(base + off);
    return p.*;
}

inline fn writeReg64(base: usize, off: u32, val: u64) void {
    const p: *volatile u64 = @ptrFromInt(base + off);
    p.* = val;
}

inline fn pause() void {
    asm volatile ("pause");
}

/// Issue a GCMD operation. `action` is the bit to set this time. For
/// one-shot bits (SRTP/WBF/SIRTP), the write is `shadow | action` and
/// the shadow stays unchanged. For level-sensitive bits (TE/QIE/IRE),
/// pass `persist=true` and the shadow picks the bit up so future writes
/// keep it set.
fn gcmdWrite(drhd: *Drhd, action: u32, persist: bool) void {
    const value = drhd.gcmd_shadow | action;
    writeReg32(drhd.base_va, GCMD, value);
    if (persist) drhd.gcmd_shadow |= action;
}

fn waitGsts(drhd: *Drhd, mask: u32) bool {
    var spins: u32 = 0;
    while ((readReg32(drhd.base_va, GSTS) & mask) != mask) {
        pause();
        spins +%= 1;
        if (spins > 100_000_000) {
            debug.klog("[iommu] timeout waiting for GSTS mask=0x{x}\n", .{mask});
            return false;
        }
    }
    return true;
}

/// Wait for a GSTS bit to CLEAR. WBFS is the odd one out among the
/// status bits: hardware sets it while the write-buffer flush is in
/// flight and clears it on completion (§10.4.4) — the SET-polarity wait
/// used for RTPS/TES would ride a 100M-spin timeout on every RWBF=1
/// chipset (the flush often completes before the first poll).
fn waitGstsClear(drhd: *Drhd, mask: u32) bool {
    var spins: u32 = 0;
    while ((readReg32(drhd.base_va, GSTS) & mask) != 0) {
        pause();
        spins +%= 1;
        if (spins > 100_000_000) {
            debug.klog("[iommu] timeout waiting for GSTS clear mask=0x{x}\n", .{mask});
            return false;
        }
    }
    return true;
}

/// Poll a 64-bit register until bit 63 (ICC/IVT — "invalidation in
/// flight") clears. Shared spin discipline for CCMD and IOTLB_REG.
fn waitInvalDone(base: usize, off: u32, what: []const u8) void {
    var spins: u32 = 0;
    while ((readReg64(base, off) & (@as(u64, 1) << 63)) != 0) {
        pause();
        spins +%= 1;
        if (spins > 100_000_000) {
            debug.klog("[iommu] {s} invalidation timeout\n", .{what});
            return;
        }
    }
}

// --- Table-write visibility (non-coherent IOMMUs) ---------------------------
//
// With ECAP.C=0 the hardware page walker reads root/context/SL tables
// straight from memory, NOT through the CPU caches — every entry we write
// must be CLFLUSHed out, and the flushes fenced before the MMIO write that
// makes hardware consume them (CLFLUSH is weakly ordered; MFENCE is its
// documented fence). Linux does exactly this via iommu_flush_cache. On
// coherent parts (QEMU) all three helpers are no-ops — plain WB stores are
// already ordered before subsequent UC MMIO writes on x86.

inline fn flushTableWrite(ptr: anytype) void {
    if (tables_coherent) return;
    asm volatile ("clflush (%[p])"
        :
        : [p] "r" (@intFromPtr(ptr)),
        : .{ .memory = true });
}

fn flushTableRange(va: usize, len: usize) void {
    if (tables_coherent) return;
    var off: usize = 0;
    while (off < len) : (off += 64) {
        asm volatile ("clflush (%[p])"
            :
            : [p] "r" (va + off),
            : .{ .memory = true });
    }
}

inline fn tableSyncBarrier() void {
    if (!tables_coherent) asm volatile ("mfence" ::: .{ .memory = true });
}

// --- DMAR walk ------------------------------------------------------------

const WalkCtx = struct {
    found: usize = 0,
};

fn dmarCb(ctx: *WalkCtx, h: *align(1) const acpi.DmarRemappingHeader) void {
    if (h.entry_type != @intFromEnum(acpi.DmarType.drhd)) return;
    if (drhd_count >= MAX_DRHDS) return;
    const drhd_hdr: *align(1) const acpi.DmarDrhd = @ptrCast(h);
    drhds[drhd_count] = .{
        .base_phys = drhd_hdr.register_base,
        .base_va = paging.physToVirt(drhd_hdr.register_base),
        .cap = 0,
        .ecap = 0,
        .root_phys = 0,
        .gcmd_shadow = 0,
        .ctx_phys = [_]u64{0} ** 256,
    };
    drhd_count += 1;
    ctx.found += 1;
    debug.klog("[iommu] DRHD #{d} base=0x{x} seg={d} flags=0x{x}\n", .{
        drhd_count - 1, drhd_hdr.register_base, drhd_hdr.segment, drhd_hdr.flags,
    });
}

// --- Per-DRHD bring-up ----------------------------------------------------

// --- Identity-mapped second-level page tables ----------------------------
//
// Walk an `sl_levels`-deep table tree (root → … → leaf), allocating
// intermediate tables on demand, and install identity leaves for every
// page in [0, identity_span). Returns the root phys, cached after first
// call. Depth and leaf size are decided in init()'s capability pre-pass.
//
// Memory cost: 4 GiB span at 4 KiB leaves ≈ 2054 frames (~8 MiB); at
// 2 MiB leaves it's 7 frames. The old 1 GiB / 4 KiB layout (QEMU's
// floor) stays 515 frames ≈ 2 MiB.

fn allocZeroFrame() ?u64 {
    const phys = pmm.allocFrame() orelse return null;
    const va = paging.physToVirt(phys);
    const ptr: [*]u8 = @ptrFromInt(va);
    @memset(ptr[0..4096], 0);
    // Non-coherent walker must not read stale (pre-zero) lines.
    flushTableRange(va, 4096);
    return phys;
}

/// Ensure `parent[idx]` points at a next-level table; allocate if needed.
/// Returns the kernel-VA pointer to the next-level table for further
/// walking. R/W flags propagate down — a leaf access requires R/W at
/// every parent entry.
fn ensureSlTable(parent: [*]u64, idx: usize) ?[*]u64 {
    if (parent[idx] != 0) {
        const next_phys = parent[idx] & ~@as(u64, 0xFFF);
        return @ptrFromInt(paging.physToVirt(next_phys));
    }
    const next_phys = allocZeroFrame() orelse return null;
    parent[idx] = next_phys | SL_RW;
    flushTableWrite(&parent[idx]);
    return @ptrFromInt(paging.physToVirt(next_phys));
}

// 9-bit index groups, top level first. A 4-level (48-bit AGAW) walk uses
// all four; a 3-level (39-bit) walk starts at the 30-bit group — the
// root table is then what a CPU walk would call the PDPT.
const SL_SHIFTS = [_]u6{ 39, 30, 21, 12 };

const SlLeaf = struct { table: [*]u64, idx: usize };

/// Walk from `root_phys` down to the table whose entries cover
/// `leaf_shift` bits (12 = 4 KiB PTE, 21 = 2 MiB PDE), allocating
/// intermediate tables. Depth-aware via `sl_levels`.
fn slWalkAlloc(root_phys: u64, iova: u64, leaf_shift: u6) ?SlLeaf {
    var table: [*]u64 = @ptrFromInt(paging.physToVirt(root_phys));
    var li: usize = 4 - @as(usize, sl_levels);
    while (SL_SHIFTS[li] != leaf_shift) : (li += 1) {
        const idx: usize = @intCast((iova >> SL_SHIFTS[li]) & 0x1FF);
        table = ensureSlTable(table, idx) orelse return null;
    }
    return .{ .table = table, .idx = @intCast((iova >> leaf_shift) & 0x1FF) };
}

/// Non-allocating variant: null when any level on the way is absent.
fn slWalkLookup(root_phys: u64, iova: u64, leaf_shift: u6) ?SlLeaf {
    var table: [*]u64 = @ptrFromInt(paging.physToVirt(root_phys));
    var li: usize = 4 - @as(usize, sl_levels);
    while (SL_SHIFTS[li] != leaf_shift) : (li += 1) {
        const idx: usize = @intCast((iova >> SL_SHIFTS[li]) & 0x1FF);
        if (table[idx] == 0) return null;
        table = @ptrFromInt(paging.physToVirt(table[idx] & ~@as(u64, 0xFFF)));
    }
    return .{ .table = table, .idx = @intCast((iova >> leaf_shift) & 0x1FF) };
}

fn buildIdentityMap() ?u64 {
    if (identity_pml4_phys != 0) return identity_pml4_phys;
    const root_phys = allocZeroFrame() orelse {
        debug.klog("[iommu] OOM allocating identity-map root\n", .{});
        return null;
    };

    const leaf_shift: u6 = if (identity_use_2m) 21 else 12;
    const leaf_flags: u64 = if (identity_use_2m) SL_RW | SL_PS else SL_RW;
    const step: u64 = @as(u64, 1) << leaf_shift;

    var addr: u64 = 0;
    while (addr < identity_span) : (addr += step) {
        const leaf = slWalkAlloc(root_phys, addr, leaf_shift) orelse return null;
        leaf.table[leaf.idx] = addr | leaf_flags;
        flushTableWrite(&leaf.table[leaf.idx]);
    }

    identity_pml4_phys = root_phys;
    debug.klog("[iommu] identity-map built: {d} MiB ({d}-level, {s} leaves) at root=0x{x}\n", .{
        identity_span / (1024 * 1024),
        sl_levels,
        if (identity_use_2m) "2M" else "4K",
        root_phys,
    });
    return root_phys;
}

fn ensureContextTable(drhd: *Drhd, bus: u8) u64 {
    if (drhd.ctx_phys[bus] != 0) return drhd.ctx_phys[bus];
    const phys = pmm.allocFrame() orelse {
        debug.klog("[iommu] OOM allocating context table for bus {d}\n", .{bus});
        return 0;
    };
    const ptr: [*]u8 = @ptrFromInt(paging.physToVirt(phys));
    @memset(ptr[0..4096], 0);
    drhd.ctx_phys[bus] = phys;

    // Wire the root entry for this bus to point at the new context table.
    const root_va = paging.physToVirt(drhd.root_phys);
    const root_entry: *volatile u64 = @ptrFromInt(root_va + @as(usize, bus) * 16);
    root_entry.* = phys | 1; // Present + ctx-table pointer
    flushTableWrite(root_entry);

    return phys;
}

/// Program one device's context entry to legacy second-level translation
/// pointing at the shared identity-map PML4. Translation is "real" — the
/// IOMMU walks our SL page tables on every DMA — but the result is 1:1
/// for any address within IDENTITY_MAP_SPAN, so drivers see no behavior
/// change. A DMA to any address ABOVE the mapped span faults (logged to
/// the fault recording registers), which is the headline diagnostic
/// benefit of running real translation instead of pass-through.
fn setLegacyTranslationEntry(drhd: *Drhd, bus: u8, dev: u8, func: u8, slptptr_phys: u64, agaw: u3, did: u16) void {
    const ctx_phys = ensureContextTable(drhd, bus);
    if (ctx_phys == 0) return;
    const devfn: usize = (@as(usize, dev) << 3) | @as(usize, func);
    const ctx_va = paging.physToVirt(ctx_phys);
    const ctx_entry: [*]volatile u64 = @ptrFromInt(ctx_va + devfn * 16);
    // qword 1 FIRST, qword 0 (which carries Present) LAST — the same
    // discipline as CPU PTEs (and Linux's context_set_* order). Hardware
    // walking the entry between the two stores must never see Present=1
    // beside a half-updated second qword. Matters for the live rewrite in
    // enableIsolation; free at initial bring-up (root pointer not set yet).
    // qword 1: AGAW in [2:0], DID in [23:8].
    ctx_entry[1] = (@as(u64, did) << 8) | @as(u64, agaw);
    // qword 0: Present + T=legacy + SLPTPTR. SLPTPTR is bits[63:12] of
    // the second-level page-table-tree root phys; low 12 bits must be 0.
    ctx_entry[0] = 1 | T_LEGACY | (slptptr_phys & ~@as(u64, 0xFFF));
    // Both qwords share one 16-byte-aligned line region; one flush covers.
    flushTableWrite(&ctx_entry[0]);
}

/// Bring one DRHD online: allocate its root table, install identity-
/// translation context entries for every cached PCI device, enable TE.
/// CAP/ECAP were already read (and cross-DRHD decisions made) in init()'s
/// capability pre-pass.
fn bringUp(idx: usize) bool {
    const drhd = &drhds[idx];
    const ver = readReg32(drhd.base_va, VER);

    debug.klog("[iommu] DRHD #{d} VER=0x{x} CAP=0x{x} ECAP=0x{x} MGAW={d} SAGAW=0x{x}\n", .{
        idx,             ver,                drhd.cap,             drhd.ecap,
        capMgawMinus1(drhd.cap) + 1,         capSagaw(drhd.cap),
    });

    // Seed the GCMD shadow from live status. GSTS mirrors the level-
    // sensitive bits at the SAME positions (TES/QIES/IRES); starting from
    // a blank shadow would make our first one-shot write silently DISABLE
    // anything firmware left enabled — e.g. interrupt remapping armed by
    // a BIOS for x2APIC — the instant we issue SRTP.
    drhd.gcmd_shadow = readReg32(drhd.base_va, GSTS) & (GSTS_TES | GSTS_QIES | GSTS_IRES);
    if (drhd.gcmd_shadow != 0) {
        debug.klog("[iommu] DRHD #{d} firmware left GSTS=0x{x} enabled; preserving\n", .{
            idx, drhd.gcmd_shadow,
        });
    }

    // Build (or reuse) the shared identity-map second-level page table.
    // Done lazily on first DRHD bringUp so we don't spend the frames if
    // no DMAR is present.
    const slptptr = buildIdentityMap() orelse {
        debug.klog("[iommu] DRHD #{d} failed to build identity-map; skipping\n", .{idx});
        return false;
    };

    const root_phys = allocZeroFrame() orelse {
        debug.klog("[iommu] OOM allocating root table\n", .{});
        return false;
    };
    drhd.root_phys = root_phys;

    const did: u16 = 1;

    var dev_count: usize = 0;
    for (pci.allDevices()) |d| {
        setLegacyTranslationEntry(drhd, d.bus, d.dev, d.func, slptptr, agaw_common, did);
        // Cache a Device record so enableIsolation/dmaMap have somewhere
        // to look up the (bus, dev, func) → (drhd, slptptr, did) triple
        // without re-walking pci.allDevices each call. First DRHD wins:
        // with multiple DRHDs the same (b,d,f) is programmed into every
        // unit's tables (harmless — a unit ignores traffic outside its
        // scope), but the record must not be duplicated or a 2-DRHD
        // machine would overflow MAX_DEVICES with clones.
        if (device_count < MAX_DEVICES and findDevice(d.bus, d.dev, d.func) == null) {
            devices[device_count] = .{
                .bus = d.bus,
                .dev = d.dev,
                .func = d.func,
                .drhd_idx = @intCast(idx),
                .isolated = false,
                .slptptr_phys = slptptr,
                .did = did,
            };
            device_count += 1;
        }
        dev_count += 1;
    }
    debug.klog("[iommu] DRHD #{d} programmed {d} devices (T=legacy, AGAW={d}, DID={d})\n", .{
        idx, dev_count, agaw_common, did,
    });

    // Everything hardware is about to read must be visible in memory
    // before the root pointer is set (no-op on coherent parts).
    tableSyncBarrier();

    // Set Root Table Pointer.
    writeReg64(drhd.base_va, RTADDR, root_phys);
    gcmdWrite(drhd, GCMD_SRTP, false); // one-shot
    if (!waitGsts(drhd, GSTS_RTPS)) return false;

    // Context-cache invalidation: CCMD with ICC=1, CIRG=01 (global).
    // ICC is bit 63, CIRG is bits 62:61.
    const ccmd_invl: u64 = (@as(u64, 1) << 63) | (@as(u64, 0b01) << 61);
    writeReg64(drhd.base_va, CCMD, ccmd_invl);
    waitInvalDone(drhd.base_va, CCMD, "global CCMD");

    // IOTLB invalidation: IOTLB_REG with IVT=1, IIRG=01 (global). The
    // IOTLB block lives at ECAP.IRO; the IOTLB_REG itself is at IRO + 8
    // (IRO + 0 is the IVA_REG for page-granular invalidation).
    const iotlb_reg_off = ecapIotlbOffset(drhd.ecap) + 8;
    const iotlb_invl: u64 = (@as(u64, 1) << 63) | (@as(u64, 0b01) << 60);
    writeReg64(drhd.base_va, iotlb_reg_off, iotlb_invl);
    waitInvalDone(drhd.base_va, iotlb_reg_off, "global IOTLB");

    // Write-buffer flush if hardware demands it (CAP.RWBF=1). One-shot;
    // completion = WBFS returning to 0 (see waitGstsClear).
    if (capRwbf(drhd.cap)) {
        gcmdWrite(drhd, GCMD_WBF, false);
        _ = waitGstsClear(drhd, GSTS_WBFS);
    }

    // Enable translation (level-sensitive — picks up in the shadow).
    gcmdWrite(drhd, GCMD_TE, true);
    if (!waitGsts(drhd, GSTS_TES)) return false;

    const fsts = readReg32(drhd.base_va, FSTS);
    debug.klog("[iommu] DRHD #{d} TE enabled, FSTS=0x{x}\n", .{ idx, fsts });

    return true;
}

// --- Public API -----------------------------------------------------------

var init_ran: bool = false;

/// Top-level bring-up. Runs once (the old header claimed idempotence the
/// code didn't have — a second call would re-append every DRHD and re-run
/// bring-up). Must run after `acpi.init()` + `pci.enumerate()` and BEFORE
/// any driver issues DMA — otherwise the device's DMA hits an empty
/// IOMMU context (Present=0) and faults.
pub fn init() void {
    if (init_ran) return;
    init_ran = true;
    if (acpi.getDmar() == null) {
        debug.klog("[iommu] no DMAR table — IOMMU not configured\n", .{});
        return;
    }
    var wctx = WalkCtx{};
    var it = acpi.dmarEntries();
    while (it.next()) |h| dmarCb(&wctx, h);
    if (wctx.found == 0) {
        debug.klog("[iommu] DMAR present but no DRHDs found\n", .{});
        return;
    }
    iommu_present = true;

    // Capability pre-pass: the identity tree is SHARED across DRHDs, so
    // its depth (AGAW), leaf size (SLLPS) and cache-flush discipline
    // (ECAP.C) are all least-common-denominator decisions that must be
    // made before the first table is built.
    var sagaw_all: u8 = 0x1F;
    identity_use_2m = true;
    for (drhds[0..drhd_count]) |*drhd| {
        drhd.cap = readReg64(drhd.base_va, CAP);
        drhd.ecap = readReg64(drhd.base_va, ECAP);
        sagaw_all &= capSagaw(drhd.cap);
        if (!capSllps2M(drhd.cap)) identity_use_2m = false;
        if (!ecapCoherent(drhd.ecap)) tables_coherent = false;
    }
    if ((sagaw_all & (1 << 2)) != 0) {
        agaw_common = 2; // 48-bit, 4-level
        sl_levels = 4;
    } else if ((sagaw_all & (1 << 1)) != 0) {
        agaw_common = 1; // 39-bit, 3-level — QEMU's default x-aw-bits
        sl_levels = 3;
    } else {
        // No width we can build a matching tree for. Refuse loudly rather
        // than guess: a mismatched AGAW makes hardware walk the tree at
        // the wrong depth and DMA into the table frames themselves.
        debug.klog("[iommu] no common 39/48-bit SAGAW (0x{x}) — leaving translation off\n", .{sagaw_all});
        return;
    }

    // Identity span: cover everything PMM can ever hand a driver (PMM is
    // hard-capped at 4 GiB), rounded up to a 1 GiB multiple with a 1 GiB
    // floor (keeps QEMU's 128 MB layout byte-identical to the old fixed
    // span). A fixed 1 GiB on a bigger machine meant the first DMA buffer
    // allocated above it faulted at the IOMMU with no kernel-side hint.
    const top = @max(@as(u64, pmm.highestUsablePhys()), IDENTITY_SPAN_FLOOR);
    const rounded = (top + IDENTITY_SPAN_FLOOR - 1) & ~(IDENTITY_SPAN_FLOOR - 1);
    identity_span = @min(rounded, IDENTITY_SPAN_CEIL);

    if (!tables_coherent)
        debug.klog("[iommu] non-coherent page walks (ECAP.C=0) — CLFLUSHing table writes\n", .{});

    var enabled: usize = 0;
    var i: usize = 0;
    while (i < drhd_count) : (i += 1) {
        if (bringUp(i)) enabled += 1;
    }
    if (enabled == drhd_count) translation_active = true;
    debug.klog("[iommu] init done: {d}/{d} DRHDs enabled (legacy translation, identity-mapped)\n", .{ enabled, drhd_count });
}

/// Drain fault status. Acknowledges by writing back the same FSTS bits
/// that were set (write-1-to-clear). Logs a one-liner per fault.
pub fn dumpFaults() void {
    if (!iommu_present) return;
    var i: usize = 0;
    while (i < drhd_count) : (i += 1) {
        const drhd = &drhds[i];
        const fsts = readReg32(drhd.base_va, FSTS);
        if (fsts == 0) continue;
        debug.klog("[iommu] DRHD #{d} FSTS=0x{x} (PFO={s} PPF={s})\n", .{
            i, fsts,
            if ((fsts & 1) != 0) "y" else "n",
            if ((fsts & 2) != 0) "y" else "n",
        });
        // Drain fault recording regs. Each FRR is 16 bytes; the upper
        // qword's bit 63 = Fault (F). Writing F=1 clears that record.
        const fro = capFroOffset(drhd.cap);
        const nfr = capNfr(drhd.cap) + 1;
        var k: u32 = 0;
        while (k < nfr) : (k += 1) {
            const upper_off = fro + k * 16 + 8;
            const upper = readReg64(drhd.base_va, upper_off);
            if ((upper & (@as(u64, 1) << 63)) == 0) continue;
            const lower = readReg64(drhd.base_va, fro + k * 16);
            const fault_reason: u8 = @intCast((upper >> 32) & 0xFF);
            const source_id: u16 = @intCast(upper & 0xFFFF);
            debug.klog(
                "[iommu]   FRR#{d}: dev={x:0>2}:{x:0>2}.{x} reason=0x{x} addr=0x{x}\n",
                .{ k, source_id >> 8, (source_id >> 3) & 0x1F, source_id & 0x7, fault_reason, lower },
            );
            writeReg64(drhd.base_va, upper_off, upper); // clear F bit
        }
        // Clear FSTS (write-1-to-clear bits).
        writeReg32(drhd.base_va, FSTS, fsts);
    }
}

// --- Phase 3: per-device isolation + DMA-map API -------------------------

fn findDevice(bus: u8, dev: u8, func: u8) ?*Device {
    var i: usize = 0;
    while (i < device_count) : (i += 1) {
        const d = &devices[i];
        if (d.bus == bus and d.dev == dev and d.func == func) return d;
    }
    return null;
}

/// Invalidate one device's context-cache entry. Issued whenever we mutate
/// its context entry (e.g. switching from shared identity to isolated).
/// CCMD with ICC=1, CIRG=11b (device-granular), source_id = bus<<8|devfn.
fn invalidateContextCacheDevice(drhd: *Drhd, bus: u8, devfn: u8) void {
    const source_id: u64 = (@as(u64, bus) << 8) | @as(u64, devfn);
    const ccmd_invl: u64 =
        (@as(u64, 1) << 63) | // ICC
        (@as(u64, 0b11) << 61) | // CIRG = device
        (source_id << 16); // SID at bits[31:16]
    writeReg64(drhd.base_va, CCMD, ccmd_invl);
    waitInvalDone(drhd.base_va, CCMD, "device CCMD");
}

/// Invalidate IOTLB entries for one domain (all addresses). Issued after
/// installing a brand-new SLPTPTR for a device — any stale entries
/// previously tagged with that DID must be flushed before the device
/// starts using the new page table.
fn invalidateIotlbDomain(drhd: *Drhd, did: u16) void {
    const iotlb_off = ecapIotlbOffset(drhd.ecap) + 8;
    const cmd: u64 =
        (@as(u64, 1) << 63) | // IVT
        (@as(u64, 0b10) << 60) | // IIRG = domain
        (@as(u64, did) << 32); // DID at bits[49:32]
    writeReg64(drhd.base_va, iotlb_off, cmd);
    waitInvalDone(drhd.base_va, iotlb_off, "domain IOTLB");
}

/// Invalidate one (DID, address) IOTLB entry. Used after `dmaUnmap` so
/// the device doesn't keep DMA-ing through a stale mapping. Falls back
/// to a domain-wide flush when the unit doesn't support page-selective
/// invalidation (CAP.PSI=0) — issuing IIRG=page there is undefined.
fn invalidateIotlbPage(drhd: *Drhd, did: u16, iova: u64) void {
    if (!capPsi(drhd.cap)) {
        invalidateIotlbDomain(drhd, did);
        return;
    }
    const iotlb_off = ecapIotlbOffset(drhd.ecap);
    // IVA_REG at offset 0: address | AM (0 = single 4KB page).
    writeReg64(drhd.base_va, iotlb_off, iova & ~@as(u64, 0xFFF));
    // IOTLB_REG at offset 8: IVT | IIRG=page | DID.
    const cmd: u64 =
        (@as(u64, 1) << 63) |
        (@as(u64, 0b11) << 60) |
        (@as(u64, did) << 32);
    writeReg64(drhd.base_va, iotlb_off + 8, cmd);
    waitInvalDone(drhd.base_va, iotlb_off + 8, "page IOTLB");
}

/// Install one 4 KB mapping in a device's SL page-table tree. Returns
/// false on OOM. Caller is responsible for IOTLB invalidation if the
/// mapping replaces a previously-present entry.
fn installSlPage(root_phys: u64, iova: u64, phys: u64, prot: Prot) bool {
    var flags: u64 = 0;
    if (prot.read) flags |= SL_R;
    if (prot.write) flags |= SL_W;

    const leaf = slWalkAlloc(root_phys, iova, 12) orelse return false;
    leaf.table[leaf.idx] = (phys & ~@as(u64, 0xFFF)) | flags;
    flushTableWrite(&leaf.table[leaf.idx]);
    return true;
}

/// Remove one 4 KB mapping from a device's SL page-table tree. Tables
/// stay allocated (no reclaim) — drivers rarely unmap, and a cleared PT
/// entry is sufficient to fault subsequent DMAs.
fn clearSlPage(root_phys: u64, iova: u64) void {
    const leaf = slWalkLookup(root_phys, iova, 12) orelse return;
    leaf.table[leaf.idx] = 0;
    flushTableWrite(&leaf.table[leaf.idx]);
}

/// Flip a device from the shared identity-map onto its own empty page
/// table. After this, every DMA from the device faults unless an
/// explicit `dmaMap` covers the target address. No-op when the IOMMU
/// isn't running or the device is already isolated.
pub fn enableIsolation(bus: u8, dev: u8, func: u8) bool {
    if (!translation_active) return false;
    const d = findDevice(bus, dev, func) orelse return false;
    if (d.isolated) return true;

    const new_pml4 = allocZeroFrame() orelse {
        debug.klog("[iommu] enableIsolation({d}:{d}.{d}) OOM\n", .{ bus, dev, func });
        return false;
    };
    const did = next_isolated_did;
    next_isolated_did += 1;

    // Rewrite the context entry to point at the new (empty) root table
    // with the new DID. AGAW unchanged (agaw_common everywhere).
    const drhd = &drhds[d.drhd_idx];
    const old_did = d.did;
    setLegacyTranslationEntry(drhd, d.bus, d.dev, d.func, new_pml4, agaw_common, did);

    d.isolated = true;
    d.slptptr_phys = new_pml4;
    d.did = did;

    // Flush cached state per the spec's context-entry-change sequence
    // (§6.2.2.1): device context-cache invalidation, then IOTLB flush of
    // the OLD domain — in-flight walks were tagged with old_did, and the
    // new DID has nothing cached by definition. (The old code flushed the
    // NEW did here: a no-op that left the mandated old-domain flush out.)
    const devfn: u8 = (d.dev << 3) | d.func;
    tableSyncBarrier();
    invalidateContextCacheDevice(drhd, d.bus, devfn);
    invalidateIotlbDomain(drhd, old_did);

    debug.klog("[iommu] {d:0>2}:{d:0>2}.{d} isolated (DID={d}, PML4=0x{x})\n", .{
        bus, dev, func, did, new_pml4,
    });
    return true;
}

/// Install a `[phys, phys+len)` mapping in a device's IOVA space. Returns
/// the IOVA (always == `phys` in this kernel — we use identity-style 1:1
/// IOVAs so drivers can keep passing physical addresses to hardware).
/// For non-isolated devices this is a no-op (the shared identity-map
/// already covers `[0, IDENTITY_MAP_SPAN)`). `len` rounds up to 4 KB.
pub fn dmaMap(bus: u8, dev: u8, func: u8, phys: u64, len: u64, prot: Prot) bool {
    // Tripwire (netstat-desktop kstack-corruption hunt 2026-05-17): if a
    // driver hands us a phys that lies inside the kernel kstack pool,
    // mapping it for DMA would let the device clobber another task's
    // saved context — exactly the wild-RIP=0 symptom. IOMMU isolation
    // can't catch this on its own because the kernel is explicitly
    // authorizing the mapping. Caller's RIP in the panic backtrace
    // identifies the buggy driver call site.
    {
        // kstack_pool is PMM-backed in the physmap now (not at KERNEL_VIRT_BASE);
        // use its recorded phys base + region size for the DMA tripwire range.
        const ks_phys_start = process.kstack_pool_phys_base;
        const ks_phys_end = ks_phys_start + process.KSTACK_POOL_BYTES;
        const req_end = phys + len;
        if (phys < ks_phys_end and req_end > ks_phys_start) {
            debug.klog("\n[iommu-tripwire] !!! dmaMap into kstack range !!!\n", .{});
            debug.klog("[iommu-tripwire]   device={X:0>2}:{X:0>2}.{X}\n", .{ bus, dev, func });
            debug.klog("[iommu-tripwire]   phys=0x{X} len=0x{X} prot={any}\n", .{ phys, len, prot });
            debug.klog("[iommu-tripwire]   kstack_pool phys=[0x{X}..0x{X})\n", .{ ks_phys_start, ks_phys_end });
            debug.klog("[iommu-tripwire]   caller RA=0x{X}\n", .{@returnAddress()});
            @panic("dmaMap target hits kstack_pool — driver is mapping a kstack frame for DMA");
        }
    }
    if (!translation_active) return true; // IOMMU off — driver can DMA freely
    const d = findDevice(bus, dev, func) orelse return false;
    if (!d.isolated) {
        // Shared identity-map covers it — but ONLY within the span. Catch
        // the out-of-range case here, loudly, instead of letting the
        // device fault later with no kernel-side hint. Unreachable while
        // the span tracks PMM's ceiling; kept as a tripwire for MMIO-phys
        // targets (peer-to-peer style) that never came from PMM.
        if (phys + len > identity_span) {
            debug.klog("[iommu] dmaMap {x:0>2}:{x:0>2}.{x} phys=0x{x}+0x{x} beyond identity span 0x{x}\n", .{
                bus, dev, func, phys, len, identity_span,
            });
            return false;
        }
        return true;
    }

    const drhd = &drhds[d.drhd_idx];
    const start = phys & ~@as(u64, 0xFFF);
    const end = (phys + len + 0xFFF) & ~@as(u64, 0xFFF);
    var addr: u64 = start;
    while (addr < end) : (addr += 0x1000) {
        if (!installSlPage(d.slptptr_phys, addr, addr, prot)) return false;
    }
    tableSyncBarrier();
    // With CAP.CM=0 (all real hardware; QEMU's default) not-present
    // entries are never cached, so freshly-installed mappings need no
    // invalidation. Caching-mode units (QEMU with caching-mode=on) DO
    // cache the misses — flush the domain or the device keeps faulting
    // on addresses that are now mapped.
    if (capCachingMode(drhd.cap)) invalidateIotlbDomain(drhd, d.did);
    return true;
}

/// Remove a `[phys, phys+len)` mapping and flush IOTLB. No-op for
/// non-isolated devices.
pub fn dmaUnmap(bus: u8, dev: u8, func: u8, phys: u64, len: u64) void {
    if (!translation_active) return;
    const d = findDevice(bus, dev, func) orelse return;
    if (!d.isolated) return;

    const drhd = &drhds[d.drhd_idx];
    const start = phys & ~@as(u64, 0xFFF);
    const end = (phys + len + 0xFFF) & ~@as(u64, 0xFFF);
    var addr: u64 = start;
    while (addr < end) : (addr += 0x1000) {
        clearSlPage(d.slptptr_phys, addr);
        tableSyncBarrier();
        invalidateIotlbPage(drhd, d.did, addr);
    }
}

// --- Fault MSI delivery ---------------------------------------------------
//
// Without this, the only way to learn about an isolated-DMA fault is to
// poll `dumpFaults` (kdbg menu, watchdog tick, etc). With MSI armed,
// hardware fires an IDT vector the instant a faulting DMA hits the page-
// table walk — handler decodes (bus, dev, func, reason, addr) and logs
// inline, so DMA bugs surface within microseconds instead of minutes.
//
// Must run AFTER `apic.init()` (LAPIC has to be active to receive MSI)
// so it isn't folded into `init()` above.

fn faultIrqHandler() callconv(.c) void {
    dumpFaults();
}

/// Arm fault-event MSI on every DRHD. `init()` already left FECTL masked
/// (IM=1 is the firmware default), so the dance is: allocate one shared
/// IDT vector → write FEDATA/FEADDR/FEUADDR on each DRHD → clear IM.
/// All DRHDs share one vector; the handler scans every DRHD's FSTS so
/// the dispatch source is irrelevant.
pub fn armFaultMsi() void {
    if (!iommu_present) return;
    if (drhd_count == 0) return;

    const v = msix.allocVector(faultIrqHandler) orelse {
        debug.klog("[iommu] fault MSI: no free dynamic vector\n", .{});
        return;
    };

    var i: usize = 0;
    while (i < drhd_count) : (i += 1) {
        const drhd = &drhds[i];
        // Hold the mask while changing the MSI message, per spec.
        writeReg32(drhd.base_va, FECTL, FECTL_IM);
        writeReg32(drhd.base_va, FEDATA, v.data);
        writeReg32(drhd.base_va, FEADDR, @truncate(v.addr));
        writeReg32(drhd.base_va, FEUADDR, @truncate(v.addr >> 32));
        // Unmask. Any IP latched while masked delivers immediately.
        writeReg32(drhd.base_va, FECTL, 0);
        debug.klog("[iommu] DRHD #{d} fault MSI armed (vec=0x{x})\n", .{ i, v.irq_vector });
    }
}
