//! Endian-typed wrappers for wire-format fields.
//!
//! Direct `u32` / `u16` fields on extern structs that cross a wire
//! (DMA descriptor, on-disk inode, network header, MMIO register) carry
//! an implicit endianness assumption that's invisible at access sites:
//! `sqe.cid = 5` looks identical whether `cid` is little-endian (NVMe),
//! big-endian (network), or native. Wrapping the field in `LE(T)` /
//! `BE(T)` lifts that assumption into the type system — direct
//! `sqe.cid = 5` becomes a compile error, forcing callers through
//! `sqe.cid.set(5)` which does the byte-swap correctly regardless of
//! host endianness.
//!
//! Zero runtime cost on a same-endian host: `nativeToLittle(u32, x)`
//! on x86_64 is a no-op the compiler folds out. The cost is in API
//! verbosity, paid once at the access site.
//!
//! Layout invariant: `LE(T)` and `BE(T)` are `extern struct { raw: T
//! align(1) }` — same size + alignment as the bare `T`, so they're
//! drop-in replacements in `extern struct` wire definitions without
//! disturbing `@sizeOf` / `@offsetOf` comptime asserts.
//!
//! See docs/STYLE.md "Endian-typed wire fields" for the convention.

const std = @import("std");

/// Little-endian field of type T. Use on every LE wire field (NVMe,
/// virtio, ext2/fat32 on-disk, all of x86 PCI/MSR/MMIO layouts).
pub fn LE(comptime T: type) type {
    return extern struct {
        raw: T align(1),

        const Self = @This();

        pub inline fn get(self: *const Self) T {
            return std.mem.littleToNative(T, self.raw);
        }

        pub inline fn set(self: *Self, val: T) void {
            self.raw = std.mem.nativeToLittle(T, val);
        }

        /// Initializer for struct literals: `.field = LE(u32).init(5)`.
        pub inline fn init(val: T) Self {
            return .{ .raw = std.mem.nativeToLittle(T, val) };
        }
    };
}

/// Big-endian field of type T. Use on every BE wire field (IPv4, TCP,
/// UDP, DNS, BGP, ICMP, ARP — every network protocol header).
pub fn BE(comptime T: type) type {
    return extern struct {
        raw: T align(1),

        const Self = @This();

        pub inline fn get(self: *const Self) T {
            return std.mem.bigToNative(T, self.raw);
        }

        pub inline fn set(self: *Self, val: T) void {
            self.raw = std.mem.nativeToBig(T, val);
        }

        pub inline fn init(val: T) Self {
            return .{ .raw = std.mem.nativeToBig(T, val) };
        }
    };
}

comptime {
    // Layout contract: wrappers preserve size + alignment of T so they're
    // safe to drop into extern struct wire definitions.
    std.debug.assert(@sizeOf(LE(u16)) == 2);
    std.debug.assert(@sizeOf(LE(u32)) == 4);
    std.debug.assert(@sizeOf(LE(u64)) == 8);
    std.debug.assert(@sizeOf(BE(u16)) == 2);
    std.debug.assert(@sizeOf(BE(u32)) == 4);
    std.debug.assert(@sizeOf(BE(u64)) == 8);
}
