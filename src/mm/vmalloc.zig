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

const pmm = @import("pmm.zig");
const paging = @import("paging.zig");
const debug = @import("../debug/debug.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

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
const PAGE_MASK: u64 = ~@as(u64, 0xFFF);

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
    pt[pt_idx] = phys | PRESENT | RW;
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (va),
        : .{ .memory = true });
    return true;
}

/// Inverse of mapPage. Returns the physical frame that was mapped, or
/// null if nothing was there.
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
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (va),
        : .{ .memory = true });
    // NOTE: local-CPU TLB invalidation only. Other CPUs that previously
    // touched this VA could still have a stale entry; for kernel mappings
    // shared across all CPUs the proper fix is a TLB shootdown IPI.
    // Acceptable for vmalloc free today because frees are rare (wallpaper
    // change, app exit) and the freed frame is unlikely to be reused
    // quickly. Revisit if this allocator gets used for hot frees.
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

    lock.acquire();
    defer lock.release();

    var i: usize = 0;
    while (i < pages) : (i += 1) {
        const va = VMALLOC_BASE + (start + i) * 4096;
        if (unmapPage(va)) |phys| pmm.freeFrame(phys);
        setFree(start + i);
    }
}
