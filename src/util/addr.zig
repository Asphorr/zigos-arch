//! addr — physical and virtual addresses as distinct types.
//!
//! A `u64` cannot say which address space it lives in, and the kernel
//! mixes three: physical (DMA targets, page-table entries, BAR values),
//! kernel-virtual (everything the CPU dereferences), and user-virtual
//! (already fenced off by `UserPtr(T)`). `Phys` and `Virt` fence the
//! first two the same way: a `Phys` cannot be dereferenced at all, a
//! `Virt` cannot be handed to a device, and the one legal crossing —
//! the physmap — is spelled `phys.toVirt()`.
//!
//! `Phys.of(x)` is an unchecked assertion, not a conversion: writing it
//! marks the audited spot where a raw integer (a wire field, a PTE, a
//! BAR read) enters the typed world. The types are non-exhaustive
//! enums, so they are exactly u64-sized, carry no methods a stray
//! arithmetic op could invoke implicitly, and cost nothing at runtime.
//!
//! Adoption is incremental (UserPtr precedent): `util/dma.zig` births
//! typed driver memory; mm internals keep raw usize until touched.

const paging = @import("../mm/paging.zig");

/// A physical address. No deref — reach the bytes via `toVirt()`.
pub const Phys = enum(u64) {
    _,

    /// Wrap a raw integer asserting it IS physical. Grep-able audit point.
    pub inline fn of(v: u64) Phys {
        return @enumFromInt(v);
    }

    /// Unwrap for a wire field, PTE, or device register. The consumer's
    /// name documents the space; nothing is lost typing-wise at a sink.
    pub inline fn raw(self: Phys) u64 {
        return @intFromEnum(self);
    }

    /// Byte offset within the same region (page math, ring strides).
    pub inline fn add(self: Phys, bytes: u64) Phys {
        return @enumFromInt(@intFromEnum(self) + bytes);
    }

    /// Low/high halves for BASE_LO/BASE_HI register pairs.
    pub inline fn lo32(self: Phys) u32 {
        return @truncate(@intFromEnum(self));
    }
    pub inline fn hi32(self: Phys) u32 {
        return @truncate(@intFromEnum(self) >> 32);
    }

    /// The one legal phys→virt crossing: through the physmap.
    pub inline fn toVirt(self: Phys) Virt {
        return Virt.of(paging.physToVirt(@intFromEnum(self)));
    }
};

/// A kernel-virtual address. Dereference via `ptr()`; never DMA-visible.
pub const Virt = enum(u64) {
    _,

    /// Wrap a raw integer asserting it IS kernel-virtual.
    pub inline fn of(v: u64) Virt {
        return @enumFromInt(v);
    }

    pub inline fn raw(self: Virt) u64 {
        return @intFromEnum(self);
    }

    pub inline fn add(self: Virt, bytes: u64) Virt {
        return @enumFromInt(@intFromEnum(self) + bytes);
    }

    /// Materialize as a pointer type of the caller's choosing:
    /// `v.ptr([*]u8)`, `v.ptr(*volatile u32)`.
    pub inline fn ptr(self: Virt, comptime T: type) T {
        return @ptrFromInt(@intFromEnum(self));
    }
};
