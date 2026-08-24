//! dma — device-visible memory as one typed value.
//!
//! Every DMA allocation in the tree repeats the same four-step dance:
//! allocate contiguous frames, derive the CPU view via the physmap,
//! IOMMU-map the range, zero it. The physical and virtual halves then
//! travel as two loose u64s that nothing stops a driver from swapping —
//! the exact bug class that reads as "DMA writes garbage" and costs
//! days. `Dma(T)` fuses the halves: `.device()` yields only a `Phys`
//! (ring base registers, descriptor fields), `.cpu()` yields only a
//! volatile pointer (CPU-side access), and neither can be mistaken for
//! the other at compile time.
//!
//! IOMMU mapping stays at the call site (`iommu.dmaMap` needs the PCI
//! identity, which the allocation doesn't have) — see the e1000 ring
//! setup for the canonical sequence.
//!
//! Rings live forever in practice; `free()` exists for error-path
//! unwinding during init.

const std = @import("std");

const pmm = @import("../mm/pmm.zig");
const addr = @import("addr.zig");

const PAGE_BYTES: usize = 4096;

/// `count` items of `T`, physically contiguous, zeroed, device-visible.
pub fn Dma(comptime T: type) type {
    return struct {
        // Stored raw, typed only at the API surface: a non-exhaustive
        // enum field inside a generic struct is on the suspect list of
        // the LLVM Invalid-type emission bug
        // (reference-llvm-anon-struct-bitcode-bug).
        base_raw: u64,
        count: usize,

        const Self = @This();

        /// Device-side view: the physical base. Feed `.raw()`, `.lo32()`,
        /// `.hi32()`, or `.add(off)` to registers and descriptors.
        pub inline fn device(self: Self) addr.Phys {
            return addr.Phys.of(self.base_raw);
        }

        /// CPU-side view through the physmap. Volatile: the device writes
        /// these bytes behind the compiler's back.
        pub inline fn cpu(self: Self) [*]volatile T {
            return self.device().toVirt().ptr([*]volatile T);
        }

        /// Payload bytes (`count * @sizeOf(T)`).
        pub inline fn bytes(self: Self) usize {
            return self.count * @sizeOf(T);
        }

        /// Whole-page footprint — what was actually allocated and what an
        /// IOMMU mapping must cover (page granularity).
        pub inline fn byteCapacity(self: Self) usize {
            return pagesFor(self.bytes()) * PAGE_BYTES;
        }

        /// Error-path unwinding during init only — a live device still
        /// DMA-ing into a freed ring is a use-after-free with a bus master
        /// on the other end.
        pub fn free(self: Self) void {
            pmm.freeContiguous(@intCast(self.base_raw), @intCast(pagesFor(self.bytes())));
        }

        /// Allocate `count` items of `T`: physically contiguous whole
        /// pages, zeroed through the physmap before return. Null = out of
        /// contiguous frames (caller logs its own context — rule 12).
        /// A static method returning ?Self, NOT a free fn returning
        /// `?Dma(T)` — the generic-call type expression in a free fn's
        /// return position was one of tonight's LLVM Invalid-type rolls.
        pub fn alloc(count: usize) ?Self {
            const pages = pagesFor(count * @sizeOf(T));
            const phys = pmm.allocContiguous(@intCast(pages)) orelse return null;
            const d = Self{ .base_raw = phys, .count = count };
            @memset(d.device().toVirt().ptr([*]u8)[0 .. pages * PAGE_BYTES], 0);
            return d;
        }
    };
}

fn pagesFor(nbytes: usize) usize {
    return (nbytes + PAGE_BYTES - 1) / PAGE_BYTES;
}
