//! CRC-32 (ISO-HDLC / zlib / PNG: reflected polynomial 0xEDB88320, init
//! 0xFFFFFFFF, final complement).
//!
//! One implementation for every in-kernel user of this polynomial. Two
//! subsystems need exactly this variant and would otherwise each grow their
//! own copy: `mm/pmem_log.zig` checksums log records, and `fs/gpt.zig`
//! checksums the GPT header and partition-entry array (UEFI 2.10 §5.3
//! specifies this same CRC-32).
//!
//! Table-free Sarwate — one shift-and-xor per bit. Deliberately not a
//! 1 KiB lookup table: every caller here checksums at most a few KiB at
//! human-initiated moments (a log append, a partition table write), so the
//! table's memory and cache footprint would buy nothing measurable. If a
//! hot-path user ever appears, add a table variant beside this one rather
//! than changing this function's cost profile underneath the existing
//! callers.
//!
//! The rolling `start`/`feed`/`end` shape exists because a record's checksum
//! usually spans a header slice and a payload slice that are not contiguous
//! in memory; `oneShot` wraps the common single-slice case.

const std = @import("std");

/// Reflected CRC-32 polynomial. Named because a bare 0xEDB88320 in the
/// shift loop is invisible to anyone grepping for which variant this is.
const POLY_REFLECTED: u32 = 0xEDB88320;

/// Initial register value before the first `feed`.
const INIT: u32 = 0xFFFFFFFF;

/// Opens a rolling computation. Pair with `feed` (any number of times,
/// including zero) then exactly one `end`.
pub inline fn start() u32 {
    return INIT;
}

/// Folds one slice into an in-progress checksum and returns the new
/// register value. Order matters: feeding A then B is not the same
/// checksum as feeding B then A, so callers must feed in wire order.
pub fn feed(crc_in: u32, bytes: []const u8) u32 {
    var crc = crc_in;
    for (bytes) |b| {
        crc ^= b;
        var k: u8 = 0;
        while (k < 8) : (k += 1) {
            // Branch-free conditional xor: mask is all-ones when the low
            // bit is set, all-zeros otherwise.
            const mask: u32 = @bitCast(-@as(i32, @intCast(crc & 1)));
            crc = (crc >> 1) ^ (POLY_REFLECTED & mask);
        }
    }
    return crc;
}

/// Closes a rolling computation. The final complement is part of the
/// standard — a value that skips it will not match any other
/// implementation's output.
pub inline fn end(crc: u32) u32 {
    return ~crc;
}

/// Checksum of a single contiguous slice. Equivalent to
/// `end(feed(start(), bytes))`.
pub fn oneShot(bytes: []const u8) u32 {
    return end(feed(start(), bytes));
}

comptime {
    // The standard check value: CRC-32 of the ASCII string "123456789" is
    // 0xCBF43926 for this variant. Asserting it at comptime means a future
    // edit that silently changes the polynomial, the init value, or the
    // final complement fails the build instead of quietly producing
    // checksums that no host tool (e2fsck, sgdisk, zlib) agrees with.
    std.debug.assert(oneShot("123456789") == 0xCBF43926);

    // An empty input must still complement the init value — the degenerate
    // case a hand-rolled reimplementation usually gets wrong.
    std.debug.assert(oneShot("") == 0x00000000);
}
