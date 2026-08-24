//! mmio — register blocks as typed windows instead of offset arithmetic.
//!
//! Eight drivers hand-roll `fn mmioRead(off) u32` over `base + off`, and
//! 400+ sites shift-and-mask bits out of the results. The house
//! replacement: describe the register file once as an `extern struct` of
//! `Ro(T)`/`Rw(T)` cells (T = the register's `packed struct(uN)` when its
//! bits have names, or a bare uN), assert the offsets below it per the
//! layout-assert rule, and open a `window()` over the BAR:
//!
//! ```zig
//! const Regs = extern struct { cap: Ro(u64), cc: Rw(Cc), csts: Ro(Csts), ... };
//! const r = mmio.window(Regs, Virt.of(bar_virt));
//! if (r.csts.read().rdy) ...
//! r.cc.write(.{ .en = true, ... });
//! ```
//!
//! A write to an `Ro` cell or a read of a `Wo` cell is a compile error;
//! bit access is by field name; every access is volatile through the
//! window pointer. The one-cell-per-register model means offsets come
//! from the struct layout, checked once, instead of being re-derived at
//! every access.

const std = @import("std");

const addr = @import("addr.zig");

fn Backing(comptime T: type) type {
    const bits = @bitSizeOf(T);
    if (bits != 8 and bits != 16 and bits != 32 and bits != 64) {
        @compileError("mmio cell must be 8/16/32/64 bits, got " ++ @typeName(T));
    }
    if (@sizeOf(T) * 8 != bits) {
        @compileError("mmio cell type has padding: " ++ @typeName(T));
    }
    return std.meta.Int(.unsigned, bits);
}

/// Read-write register cell.
pub fn Rw(comptime T: type) type {
    return extern struct {
        raw: Backing(T),

        pub inline fn read(self: *volatile @This()) T {
            return @bitCast(self.raw);
        }

        pub inline fn write(self: *volatile @This(), val: T) void {
            self.raw = @bitCast(val);
        }
    };
}

/// Read-only register cell — no write method exists to call.
pub fn Ro(comptime T: type) type {
    return extern struct {
        raw: Backing(T),

        pub inline fn read(self: *volatile @This()) T {
            return @bitCast(self.raw);
        }
    };
}

/// Write-only register cell (doorbells, command triggers) — reading one
/// is often side-effecting or undefined, so no read method exists.
pub fn Wo(comptime T: type) type {
    return extern struct {
        raw: Backing(T),

        pub inline fn write(self: *volatile @This(), val: T) void {
            self.raw = @bitCast(val);
        }
    };
}

/// A 64-bit register that must be programmed as two 32-bit accesses —
/// some PCIe controllers fault on quad-word MMIO (the NVMe ASQ/ACQ
/// lesson). The constraint becomes the type: there IS no 64-bit write.
pub const Split64 = extern struct {
    lo: Rw(u32),
    hi: Rw(u32),

    pub inline fn writeSplit(self: *volatile Split64, val: u64) void {
        self.lo.write(@truncate(val));
        self.hi.write(@truncate(val >> 32));
    }
};

comptime {
    std.debug.assert(@sizeOf(Split64) == 8);
    std.debug.assert(@offsetOf(Split64, "hi") == 4);
}

/// Open a typed window over an MMIO range already mapped at `base`.
/// The pointee is volatile, so every cell access through it is too.
pub fn window(comptime Regs: type, base: addr.Virt) *volatile Regs {
    comptime {
        if (@typeInfo(Regs) != .@"struct" or @typeInfo(Regs).@"struct".layout != .@"extern") {
            @compileError("mmio.window wants an extern struct of register cells");
        }
    }
    return base.ptr(*volatile Regs);
}
