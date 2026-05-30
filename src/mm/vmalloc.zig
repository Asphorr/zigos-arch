// vmalloc — kernel allocator for non-DMA, non-contig-required buffers.
//
// kvmalloc (heap.zig) backs every allocation with one physically-contiguous
// run from PMM. That's fine for small allocations but breaks once the heap
// fragments: requesting 6 MB needs 1537 contiguous frames, which can't be
// served after a few apps have churned the bitmap. The wallpaper bitmap
// was the first thing big enough to feel the pinch.
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
// virtio queues, etc.) still need pmm.allocContiguous via kvmalloc.
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
//     surfaces the same way it does on kvmalloc
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
fn mapPage(va: usize, phys: usize) bool {
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
        const pt_kv: [*]u8 = @ptrFromInt(paging.physToVirt(pt_phys));
        @memset(pt_kv[0..4096], 0);
        pd[pd_idx] = pt_phys | PRESENT | RW;
    }

    const pt_phys = pd[pd_idx] & PAGE_MASK;
    const pt: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pt_phys));
    const pt_idx = (va >> 12) & 0x1FF;
    pt[pt_idx] = phys | VMALLOC_PTE_FLAGS;
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

/// Inverse of mapPage. Returns the physical frame that was mapped, or
/// null if nothing was there. Caller must perform a TLB shootdown for the
/// VA AFTER the PMM frame has been freed (or batch the shootdown across
/// many unmaps via `tlb.shootdownAll(0)`).
fn unmapPage(va: usize) ?usize {
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
    const pt_idx = (va >> 12) & 0x1FF;
    const old = pt[pt_idx];
    if (old & PRESENT == 0) return null;
    pt[pt_idx] = 0;
    // Local invlpg only. Caller is responsible for the cross-CPU shootdown
    // (typically batched as one `tlb.shootdownAll(0)` covering all unmapped
    // pages, instead of one IPI per page). See `free()` for the batching.
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (va),
        : .{ .memory = true });
    return old & PAGE_MASK;
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
        const pdpt_kv: [*]u8 = @ptrFromInt(paging.physToVirt(pdpt_phys));
        @memset(pdpt_kv[0..4096], 0);
        pml4[pml4_idx] = pdpt_phys | PRESENT | RW;
    }

    const pdpt_phys = pml4[pml4_idx] & PAGE_MASK;
    const pdpt: [*]volatile u64 = @ptrFromInt(paging.physToVirt(pdpt_phys));
    const pdpt_idx = (VMALLOC_BASE >> 30) & 0x1FF;
    if (pdpt[pdpt_idx] & PRESENT == 0) {
        const pd_phys = pmm.allocFrame() orelse {
            debug.klog("[vmalloc] init: pmm.allocFrame for PD failed\n", .{});
            return;
        };
        const pd_kv: [*]u8 = @ptrFromInt(paging.physToVirt(pd_phys));
        @memset(pd_kv[0..4096], 0);
        pdpt[pdpt_idx] = pd_phys | PRESENT | RW;
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
pub fn free(ptr: [*]u8) void {
    const addr = @intFromPtr(ptr);
    if (addr < VMALLOC_BASE + HEADER_PAD or addr >= VMALLOC_BASE + VMALLOC_SIZE) {
        debug.klog("[vmalloc] free: ptr 0x{X} outside arena\n", .{addr});
        return;
    }
    const base_va = addr - HEADER_PAD;
    const hdr: *Header = @ptrFromInt(base_va);
    if (hdr.magic != MAGIC) {
        debug.klog("[vmalloc] free: bad magic 0x{X:0>16} at 0x{X}\n", .{ hdr.magic, base_va });
        return;
    }
    const pages: usize = @intCast(hdr.pages);
    hdr.magic = 0xDEADDEADDEADDEAD;
    const start = (base_va - VMALLOC_BASE) / 4096;

    // Poison the user-visible bytes BEFORE we drop the lock so any racing
    // reader hits a kasan red-zone instead of the soon-to-be-recycled data.
    // Size derived from header.pages × frame - header pad.
    kasan.poison(base_va + HEADER_PAD, pages * 4096 - HEADER_PAD, kasan.SHADOW_FREED);

    lock.acquire();
    defer lock.release();

    var i: usize = 0;
    while (i < pages) : (i += 1) {
        const va = VMALLOC_BASE + (start + i) * 4096;
        if (unmapPage(va)) |phys| pmm.freeFrame(phys);
        setFree(start + i);
    }

    // Cross-CPU TLB shootdown. Kernel-PCID (pcid 0) shootdown broadcasts
    // to every alive CPU + toggles CR4.PGE on each (kernel mappings carry
    // PGE so a CR3 reload alone won't evict them). One IPI batch covers
    // the whole range — cheaper than per-page shootdownPage(0, va) when
    // pages > 1. Gated on boot_phase: pre-scheduler boot only has cpu0 alive
    // and the local invlpg inside unmapPage already sufficed; the shootdown
    // IPI fan-out machinery may not even be armed yet.
    //
    // Without this, freed PMM frames could be observed live on another CPU
    // via a stale kernel TLB entry — catastrophic if PMM has handed the
    // frame back out for, say, a page table. Latent SMP UAF bug pre-2026-05-24.
    if (boot_phase.isComplete()) {
        tlb.shootdownAll(0);
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
