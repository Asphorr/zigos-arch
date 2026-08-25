//! geom — disk quantities as distinct types.
//!
//! The Phys/Virt move (util/addr.zig), applied to the OTHER numbers systems
//! code juggles: a sector POSITION (`Lba`), a sector COUNT (`Sectors`), and
//! a byte count (`Bytes`) are three different quantities that all live in a
//! u64, and every `* 512`, `<< 9`, `+ count - 1` written by hand is one
//! chance to mix them. The GPT/mkfs/installer work is wall-to-wall sector
//! math, and its worst trap is dimensionless: an INCLUSIVE end LBA and an
//! exclusive one read identically in code and differ by one partition
//! overlap.
//!
//! So the vocabulary here is:
//!   - `Lba`      a position. Moves only by `Sectors` (`at.add(n)`); two
//!                positions never add.
//!   - `Sectors`  a count. Converts to `Bytes` and back; the byte→sector
//!                direction states its rounding (`exact` asserts, `ceil`
//!                rounds up) instead of hiding it in a `/`.
//!   - `Span`     a contiguous run, stored FIRST..LAST INCLUSIVE — the GPT
//!                on-disk convention — with count/overlap/contains derived
//!                inside, so the `+1`/`-1` lives in exactly one file.
//!
//! Like Phys, these are non-exhaustive enum(u64)s: u64-sized, no implicit
//! arithmetic, `.raw()` only at a genuine sink (a wire field, a driver call
//! that takes u32 LBA, a log line), `.of()` only where a raw integer enters
//! (a parsed on-disk field, a device's reported size).

const std = @import("std");

/// One logical sector, in bytes. Every block-layer entry point in this
/// kernel speaks 512-byte sectors (NVMe namespaces are formatted LBAf=512;
/// fs/gpt.zig asserts its own constant against this one).
pub const SECTOR_SIZE: u64 = 512;

/// A sector POSITION on a specific device.
pub const Lba = enum(u64) {
    _,

    pub inline fn of(v: u64) Lba {
        return @enumFromInt(v);
    }
    pub inline fn raw(self: Lba) u64 {
        return @intFromEnum(self);
    }
    /// Position + count. The only way an Lba moves.
    pub inline fn add(self: Lba, n: Sectors) Lba {
        return @enumFromInt(@intFromEnum(self) + @intFromEnum(n));
    }
    /// Position - count (asserts no underflow in safe builds).
    pub inline fn back(self: Lba, n: Sectors) Lba {
        return @enumFromInt(@intFromEnum(self) - @intFromEnum(n));
    }
    /// Round up to the next multiple of `align_sectors`.
    pub inline fn alignUpTo(self: Lba, align_sectors: u64) Lba {
        const v = @intFromEnum(self);
        return @enumFromInt((v + align_sectors - 1) / align_sectors * align_sectors);
    }
    /// For an INCLUSIVE end position: round down so the NEXT position
    /// (`self + 1`) lands on a multiple of `align_sectors` — i.e. whatever
    /// follows this span starts aligned. The transform that is wrong to
    /// hand-write twice.
    pub inline fn alignEndDownTo(self: Lba, align_sectors: u64) Lba {
        return @enumFromInt((@intFromEnum(self) + 1) / align_sectors * align_sectors - 1);
    }
};

/// A COUNT of sectors.
pub const Sectors = enum(u64) {
    _,

    pub inline fn of(v: u64) Sectors {
        return @enumFromInt(v);
    }
    pub inline fn raw(self: Sectors) u64 {
        return @intFromEnum(self);
    }
    pub inline fn add(self: Sectors, other: Sectors) Sectors {
        return @enumFromInt(@intFromEnum(self) + @intFromEnum(other));
    }
    pub inline fn toBytes(self: Sectors) Bytes {
        return @enumFromInt(@intFromEnum(self) * SECTOR_SIZE);
    }
};

/// A COUNT of bytes.
pub const Bytes = enum(u64) {
    _,

    pub inline fn of(v: u64) Bytes {
        return @enumFromInt(v);
    }
    pub inline fn raw(self: Bytes) u64 {
        return @intFromEnum(self);
    }
    /// Byte count that IS a whole number of sectors — asserts divisibility
    /// (ReleaseSafe: a stray `+ header_bytes` that breaks alignment panics
    /// here, at the conversion, instead of truncating a sector away).
    pub inline fn toSectorsExact(self: Bytes) Sectors {
        const v = @intFromEnum(self);
        std.debug.assert(v % SECTOR_SIZE == 0);
        return @enumFromInt(v / SECTOR_SIZE);
    }
    /// Byte count rounded UP to whole sectors (the "how many sectors do I
    /// read to cover this struct" direction).
    pub inline fn toSectorsCeil(self: Bytes) Sectors {
        return @enumFromInt((@intFromEnum(self) + SECTOR_SIZE - 1) / SECTOR_SIZE);
    }
};

/// A contiguous run of sectors, first..last INCLUSIVE — the GPT convention,
/// adopted kernel-wide at this boundary because converting inclusive ⇄
/// exclusive at API seams is where off-by-one partition overlaps come from
/// (gpt.zig's own words). A one-sector span has first == last; an empty
/// span is unrepresentable, which matches what a partition table can hold.
pub const Span = struct {
    first: Lba,
    /// Inclusive.
    last: Lba,

    pub inline fn fromFirstLast(first: Lba, last: Lba) Span {
        std.debug.assert(first.raw() <= last.raw());
        return .{ .first = first, .last = last };
    }
    pub inline fn fromFirstCount(first: Lba, n: Sectors) Span {
        std.debug.assert(n.raw() != 0);
        return .{ .first = first, .last = @enumFromInt(first.raw() + n.raw() - 1) };
    }
    pub inline fn count(self: Span) Sectors {
        return @enumFromInt(self.last.raw() - self.first.raw() + 1);
    }
    pub inline fn contains(self: Span, at: Lba) bool {
        return at.raw() >= self.first.raw() and at.raw() <= self.last.raw();
    }
    /// True when the runs share at least one sector. Inclusive bounds make
    /// this the two-comparison classic with no `-1` anywhere.
    pub inline fn overlaps(self: Span, other: Span) bool {
        return self.first.raw() <= other.last.raw() and other.first.raw() <= self.last.raw();
    }
};

// ------------------------------ self-proof ----------------------------------
comptime {
    const a = std.debug.assert;
    // Position/count arithmetic.
    a(Lba.of(10).add(Sectors.of(5)).raw() == 15);
    a(Lba.of(15).back(Sectors.of(5)).raw() == 10);
    a(Sectors.of(8).toBytes().raw() == 4096);
    a(Bytes.of(4096).toSectorsExact().raw() == 8);
    a(Bytes.of(4097).toSectorsCeil().raw() == 9);
    a(Bytes.of(4096).toSectorsCeil().raw() == 8);
    // Alignment: result is aligned, never moves backward, fixpoint on aligned.
    a(Lba.of(34).alignUpTo(2048).raw() == 2048);
    a(Lba.of(2048).alignUpTo(2048).raw() == 2048);
    a(Lba.of(2049).alignUpTo(2048).raw() == 4096);
    // Inclusive-end alignment: (last+1) becomes a boundary; a last whose
    // successor already IS one stays put (fixpoint).
    a(Lba.of(4095).alignEndDownTo(2048).raw() == 4095);
    a(Lba.of(4094).alignEndDownTo(2048).raw() == 2047);
    a(Lba.of(4096).alignEndDownTo(2048).raw() == 4095);
    a((Lba.of(999_999).alignEndDownTo(2048).raw() + 1) % 2048 == 0);
    // Span identities.
    a(Span.fromFirstCount(Lba.of(2048), Sectors.of(131072)).last.raw() == 133119);
    a(Span.fromFirstLast(Lba.of(2048), Lba.of(133119)).count().raw() == 131072);
    a(Span.fromFirstCount(Lba.of(7), Sectors.of(1)).count().raw() == 1); // one-sector span
    const p1 = Span.fromFirstLast(Lba.of(100), Lba.of(199));
    const p2 = Span.fromFirstLast(Lba.of(200), Lba.of(299));
    a(!p1.overlaps(p2) and !p2.overlaps(p1)); // adjacent is NOT overlap
    a(p1.overlaps(Span.fromFirstLast(Lba.of(199), Lba.of(250)))); // one shared sector is
    a(p1.contains(Lba.of(199)) and !p1.contains(Lba.of(200)));
}
