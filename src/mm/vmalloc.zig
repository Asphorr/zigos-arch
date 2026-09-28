// vmalloc — kernel allocator for non-DMA, non-contig-required buffers.
//
// A physically-contiguous run from PMM is fine for small allocations but
// breaks once memory fragments: requesting 6 MB needs 1537 contiguous
// frames, which can't be served after a few apps have churned the bitmap.
// The wallpaper bitmap was the first thing big enough to feel the pinch;
// heap.kvmalloc (kalloc's large path) now lands here too.
//
// This module returns a virtually-contiguous range backed by N individually
// allocated PMM frames. Each frame can come from anywhere in physical
// memory; we map them into consecutive VAs in a dedicated kernel-VA arena
// at VMALLOC_BASE. The caller sees a single contiguous pointer; the
// fragmentation problem disappears.
//
// Use cases (now): wallpaper bitmap. Use cases (future): screenshots,
// file caches, large compositor scratch buffers, anything kernel-read,
// no-DMA, multi-MB.
//
// NOT for DMA. Drivers that hand a pointer to hardware (NVMe PRPs,
// virtio queues, etc.) still need pmm.allocContiguous.
//
// Modernization (2026-05-24): plugged into the rest of the kernel —
//   - free() does a kernel-PCID TLB shootdown so other CPUs drop stale
//     entries before the freed PMM frames are recycled (was: local invlpg
//     only; latent SMP UAF noted in the source for ages, fixed now)
//   - shootdown is gated by boot_phase — pre-scheduler boot has 1 CPU,
//     local invlpg suffices and the IPI fan-out machinery isn't up yet
//   - PTEs carry NX by default; vmalloc is data-only, anyone executing
//     from a vmalloc buffer is an attacker
//   - alloc/free wrap kasan unpoison/poison so UAF on vmalloc'd memory
//     surfaces the same way it does on the heap
//   - atomic stats (pages_in_use, live_regions, peak_pages) exposed for
//     /proc/meminfo + sysmon

const pmm = @import("pmm.zig");
const paging = @import("paging.zig");
const debug = @import("../debug/debug.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const std = @import("std");
const tlb = @import("../cpu/mmu/tlb.zig");
const boot_phase = @import("../boot/boot_phase.zig");
const kasan = @import("../debug/kasan.zig");
const Phys = @import("../util/addr.zig").Phys;
const irqsEnabled = @import("../time/pause.zig").irqsEnabled;

/// Kernel VA arena. Sits in an otherwise-unused PML4 slot above the
/// physmap (which owns slot 256 entirely). Slot 258 = 0xFFFF810000000000.
/// Two PML4 slots of headroom past physmap end keeps space for future
/// kernel mappings.
pub const VMALLOC_BASE: usize = 0xFFFF810000000000;
pub const VMALLOC_SIZE: usize = 64 * 1024 * 1024; // 64 MB
const NUM_PAGES: usize = VMALLOC_SIZE / 4096; // 16384
const BITMAP_WORDS: usize = NUM_PAGES / 64;

var bitmap: [BITMAP_WORDS]u64 = [_]u64{0} ** BITMAP_WORDS;
var lock: SpinLock = .{};
var initialized: bool = false;

const MAGIC: u64 = 0x564D414C4C4F4321; // "VMALLOC!"
const HEADER_PAD: usize = 16;

const Header = extern struct {
    magic: u64,
    pages: u32,
    _pad: u32 = 0,
};

const PRESENT: u64 = 1;
const RW: u64 = 2;
const NX: u64 = 1 << 63;
// x86-64 PTE phys mask: bits [51:12]. Bits [11:0] are flags, [62:52] are
// PKE/ignored, [63] is NX. `~0xFFF` only clears flag bits — it leaks NX
// (and any PKE bits) into the extracted phys, which then looks like a
// frame number > 2^52 to PMM and gets rejected as a bad address.
const PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PAGE_MASK: u64 = PHYS_MASK;

/// PTE flags for vmalloc data pages: P + RW + NX. Setting NX (bit 63) means
/// instruction fetch from a vmalloc page #GPs — vmalloc returns DATA buffers,
/// no legitimate caller jumps into one. Cheap defense against the "use a
/// data-page write to land shellcode" pattern.
const VMALLOC_PTE_FLAGS: u64 = PRESENT | RW | NX;

// === Stats — read by sysmon / /proc/meminfo (atomic; lock-free readers) ===
var pages_in_use: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
var live_regions: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);
var peak_pages_in_use: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

pub fn pagesInUse() u32 {
    return pages_in_use.load(.monotonic);
}
pub fn liveRegions() u32 {
    return live_regions.load(.monotonic);
}
pub fn peakPagesInUse() u32 {
    return peak_pages_in_use.load(.monotonic);
}
pub fn totalPages() u32 {
    return @intCast(NUM_PAGES);
}

/// `addr` is inside the arena (live or not).
pub fn contains(addr: usize) bool {
    return addr >= VMALLOC_BASE and addr < VMALLOC_BASE + VMALLOC_SIZE;
}

inline fn isFree(idx: usize) bool {
    return (bitmap[idx / 64] & (@as(u64, 1) << @intCast(idx % 64))) == 0;
}

inline fn setUsed(idx: usize) void {
    bitmap[idx / 64] |= @as(u64, 1) << @intCast(idx % 64);
}

inline fn setFree(idx: usize) void {
    bitmap[idx / 64] &= ~(@as(u64, 1) << @intCast(idx % 64));
}

fn findContigFree(n: usize) ?usize {
    var i: usize = 0;
    while (i + n <= NUM_PAGES) {
        if (!isFree(i)) {
            i += 1;
            continue;
        }
        var count: usize = 1;
        while (count < n and isFree(i + count)) : (count += 1) {}
        if (count == n) return i;
        i += count;
    }
    return null;
}

/// Walk the kernel page tables to set a single PTE in the arena.
/// PML4 + PDPT + PD are pre-installed by init(); only PT is lazy.
fn mapPage(va: usize, phys: Phys) bool {
    const pml4_phys = paging.getKernelPML4Phys();
    const pml4: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pml4_phys));
    const pml4_idx = (va >> 39) & 0x1FF;
    if (pml4[pml4_idx] & PRESENT == 0) return false;

    const pdpt_phys = pml4[pml4_idx] & PAGE_MASK;
    const pdpt: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pdpt_phys));
    const pdpt_idx = (va >> 30) & 0x1FF;
    if (pdpt[pdpt_idx] & PRESENT == 0) return false;

    const pd_phys = pdpt[pdpt_idx] & PAGE_MASK;
    const pd: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pd_phys));
    const pd_idx = (va >> 21) & 0x1FF;
    if (pd[pd_idx] & PRESENT == 0) {
        const pt_phys = pmm.allocFrame() orelse return false;
        const pt_kv = pt_phys.toVirt().ptr([*]u8);
        @memset(pt_kv[0..4096], 0);
        pd[pd_idx] = pt_phys.raw() | PRESENT | RW;
    }

    const pt_phys = pd[pd_idx] & PAGE_MASK;
    const pt: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pt_phys));
    const pt_idx = (va >> 12) & 0x1FF;
    pt[pt_idx] = phys.raw() | VMALLOC_PTE_FLAGS;
    // Fresh PTE on a previously-not-present slot — local invlpg flushes any
    // negative cache entry. No TLB shootdown needed: peers also have no
    // cached entry (because there was nothing to cache) and their next walk
    // will pull the new PTE through the kernel-shared page-table tree.
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (va),
        : .{ .memory = true });
    return true;
}

/// The arena PTE for `va`, or null if a table above it isn't there.
fn ptePtr(va: usize) ?*volatile u64 {
    const pml4_phys = paging.getKernelPML4Phys();
    const pml4: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pml4_phys));
    const pml4_idx = (va >> 39) & 0x1FF;
    if (pml4[pml4_idx] & PRESENT == 0) return null;

    const pdpt_phys = pml4[pml4_idx] & PAGE_MASK;
    const pdpt: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pdpt_phys));
    const pdpt_idx = (va >> 30) & 0x1FF;
    if (pdpt[pdpt_idx] & PRESENT == 0) return null;

    const pd_phys = pdpt[pdpt_idx] & PAGE_MASK;
    const pd: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pd_phys));
    const pd_idx = (va >> 21) & 0x1FF;
    if (pd[pd_idx] & PRESENT == 0) return null;

    const pt_phys = pd[pd_idx] & PAGE_MASK;
    const pt: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pt_phys));
    return &pt[(va >> 12) & 0x1FF];
}

inline fn invlpg(va: usize) void {
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (va),
        : .{ .memory = true });
}

/// Inverse of mapPage with a local flush only. Returns the physical frame
/// that was mapped, or null if nothing was there. Used on alloc's rollback,
/// where no other CPU has had the address.
fn unmapPage(va: usize) ?Phys {
    const pte = ptePtr(va) orelse return null;
    const old = pte.*;
    if (old & PRESENT == 0) return null;
    pte.* = 0;
    invlpg(va);
    return Phys.of(old & PAGE_MASK);
}

/// One-time setup: install the PML4 entry, PDPT, and PD covering our
/// arena. PTs are still allocated on demand at the first alloc that
/// touches each 2 MB slice (32 PTs total for 64 MB).
pub fn init() void {
    const pml4_phys = paging.getKernelPML4Phys();
    const pml4: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pml4_phys));
    const pml4_idx = (VMALLOC_BASE >> 39) & 0x1FF;

    if (pml4[pml4_idx] & PRESENT == 0) {
        const pdpt_phys = pmm.allocFrame() orelse {
            debug.klog("[vmalloc] init: pmm.allocFrame for PDPT failed\n", .{});
            return;
        };
        const pdpt_kv = pdpt_phys.toVirt().ptr([*]u8);
        @memset(pdpt_kv[0..4096], 0);
        pml4[pml4_idx] = pdpt_phys.raw() | PRESENT | RW;
    }

    const pdpt_phys = pml4[pml4_idx] & PAGE_MASK;
    const pdpt: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pdpt_phys));
    const pdpt_idx = (VMALLOC_BASE >> 30) & 0x1FF;
    if (pdpt[pdpt_idx] & PRESENT == 0) {
        const pd_phys = pmm.allocFrame() orelse {
            debug.klog("[vmalloc] init: pmm.allocFrame for PD failed\n", .{});
            return;
        };
        const pd_kv = pd_phys.toVirt().ptr([*]u8);
        @memset(pd_kv[0..4096], 0);
        pdpt[pdpt_idx] = pd_phys.raw() | PRESENT | RW;
    }

    initialized = true;
    debug.klog("[vmalloc] init: arena @ 0x{X:0>16}, {d} MB ({d} pages)\n", .{
        VMALLOC_BASE, VMALLOC_SIZE / (1024 * 1024), NUM_PAGES,
    });
    // WITNESS: track the arena lock's order vs other subsystem locks. Reached
    // only on successful init (the allocFrame failures above return early).
    @import("../proc/spinlock.zig").registerLock("vmalloc.lock", &lock);
}

/// Allocate `size` bytes from the vmalloc arena. Returns a kernel-VA
/// pointer to a virtually-contiguous region. Backed by N scattered PMM
/// frames; no physical contiguity, so this succeeds whenever PMM has
/// `ceil(size/4096)` total free frames anywhere.
pub fn alloc(size: usize) ?[*]u8 {
    if (!initialized or size == 0) return null;
    const total = HEADER_PAD + size;
    const pages = (total + 4095) / 4096;
    if (pages > NUM_PAGES) return null;

    lock.acquire();
    defer lock.release();

    const start = findContigFree(pages) orelse {
        debug.klog("[vmalloc] alloc: no contig VA run of {d} pages\n", .{pages});
        return null;
    };

    var i: usize = 0;
    while (i < pages) : (i += 1) {
        const phys = pmm.allocFrame() orelse {
            // Roll back frames we've already mapped.
            var j: usize = 0;
            while (j < i) : (j += 1) {
                const va_j = VMALLOC_BASE + (start + j) * 4096;
                if (unmapPage(va_j)) |p| pmm.freeFrame(p);
                setFree(start + j);
            }
            debug.klog("[vmalloc] alloc: pmm.allocFrame failed at page {d}/{d}\n", .{ i, pages });
            return null;
        };
        const va = VMALLOC_BASE + (start + i) * 4096;
        if (!mapPage(va, phys)) {
            pmm.freeFrame(phys);
            var j: usize = 0;
            while (j < i) : (j += 1) {
                const va_j = VMALLOC_BASE + (start + j) * 4096;
                if (unmapPage(va_j)) |p| pmm.freeFrame(p);
                setFree(start + j);
            }
            return null;
        }
        setUsed(start + i);
    }

    const base_va = VMALLOC_BASE + start * 4096;
    const hdr: *Header = @ptrFromInt(base_va);
    hdr.* = .{ .magic = MAGIC, .pages = @intCast(pages) };

    // KASAN: unpoison only the user-visible bytes (skip header pad). Header
    // itself stays implicitly unpoisoned via vmalloc-arena exclusion in
    // kasan.zig REGION_LO/HI check (shadow only covers low 256 MB; vmalloc
    // arena is at 0xFFFF810000000000, so kasan.poison/unpoison is a no-op
    // here today — but we call it anyway so the moment the kasan shadow
    // extends to cover kernel VAs, vmalloc gets free UAF detection without
    // a code change.)
    kasan.unpoison(base_va + HEADER_PAD, size);

    const new_pages = pages_in_use.fetchAdd(@intCast(pages), .monotonic) + @as(u32, @intCast(pages));
    _ = live_regions.fetchAdd(1, .monotonic);
    // Update peak via CAS — tiny race ok, peak is diagnostic.
    var peak = peak_pages_in_use.load(.monotonic);
    while (new_pages > peak) {
        if (peak_pages_in_use.cmpxchgWeak(peak, new_pages, .monotonic, .monotonic) == null) break;
        peak = peak_pages_in_use.load(.monotonic);
    }

    return @ptrFromInt(base_va + HEADER_PAD);
}

/// Free a region previously returned by `alloc`. Validates the header
/// magic so a stray pointer doesn't silently corrupt the bitmap.
///
/// Waits for every CPU to flush its TLB, so never call it with interrupts
/// off or under a spinlock another CPU may spin on with interrupts off: a
/// CPU spinning there can't take the flush IPI.
pub fn free(ptr: [*]u8) void {
    const addr = @intFromPtr(ptr);
    if (addr < VMALLOC_BASE + HEADER_PAD or addr >= VMALLOC_BASE + VMALLOC_SIZE) {
        debug.klog("[vmalloc] free: ptr 0x{X} outside arena\n", .{addr});
        return;
    }
    const base_va = addr - HEADER_PAD;
    const hdr: *Header = @ptrFromInt(base_va);
    // One winner per region: the unmap below runs without the arena lock.
    if (@cmpxchgStrong(u64, &hdr.magic, MAGIC, 0xDEADDEADDEADDEAD, .acq_rel, .monotonic)) |seen| {
        debug.klog("[vmalloc] free: bad magic 0x{X:0>16} at 0x{X}\n", .{ seen, base_va });
        return;
    }
    const pages: usize = @intCast(hdr.pages);
    const start = (base_va - VMALLOC_BASE) / 4096;

    // Poison the user-visible bytes BEFORE we drop the lock so any racing
    // reader hits a kasan red-zone instead of the soon-to-be-recycled data.
    // Size derived from header.pages × frame - header pad.
    kasan.poison(base_va + HEADER_PAD, pages * 4096 - HEADER_PAD, kasan.SHADOW_FREED);

    const smp_up = boot_phase.isComplete();
    if (smp_up and !irqsEnabled()) {
        debug.kwarn(@src(), "vmalloc.free(0x{X}) with interrupts off: a CPU spinning with IF=0 on a lock we hold can't ack the TLB flush", .{addr});
    }

    // No arena lock from here to the bitmap update: the range stays marked
    // used, so nothing else touches its PTEs, and the flush wait below
    // must not hold a lock alloc spins on. PRESENT goes first; the frame
    // address stays in the PTE until every CPU has flushed.
    var i: usize = 0;
    while (i < pages) : (i += 1) {
        const va = VMALLOC_BASE + (start + i) * 4096;
        const pte = ptePtr(va) orelse continue;
        pte.* &= ~PRESENT;
        invlpg(va);
    }

    // Kernel-PCID shootdown: every alive CPU drops the range (CR4.PGE
    // toggle, since these PTEs are global) before PMM can hand a frame
    // out again, say as a page table. One batch for the whole range.
    // Before the scheduler only cpu0 runs and the local invlpg suffices.
    if (smp_up) tlb.shootdownAll(0);

    i = 0;
    while (i < pages) : (i += 1) {
        const va = VMALLOC_BASE + (start + i) * 4096;
        const pte = ptePtr(va) orelse continue;
        const old = pte.*;
        pte.* = 0;
        if (old & PAGE_MASK != 0) pmm.freeFrame(Phys.of(old & PAGE_MASK));
    }

    {
        lock.acquire();
        defer lock.release();
        i = 0;
        while (i < pages) : (i += 1) setFree(start + i);
    }

    if (pages_in_use.load(.monotonic) >= pages) {
        _ = pages_in_use.fetchSub(@intCast(pages), .monotonic);
    } else {
        pages_in_use.store(0, .monotonic);
    }
    if (live_regions.load(.monotonic) > 0) {
        _ = live_regions.fetchSub(1, .monotonic);
    }
}
