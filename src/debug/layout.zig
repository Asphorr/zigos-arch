//! Comptime layout validators for hand-overlaid block storage.
//!
//! When a module overlays multiple fields onto a single memory region at
//! manually-computed offsets (TLSF free block, pipe ring, pmm Run pool,
//! save_trace entry, IretqSnap GPR base, etc.), there is no compiler check
//! that the fields' actual `@sizeOf` widths don't overlap. The 2026-05-28
//! heap bug — `?usize` is 16 bytes wide, but it was stored at +8 and the
//! next field at +16, silently overlapping by 8 bytes — is the canonical
//! failure mode. The fix in heap.zig changed `?usize` to plain `usize`,
//! but nothing prevents the same regression in another file.
//!
//! Usage: at the bottom of a struct/block definition, add a comptime block:
//!
//!   comptime {
//!       layout.assertFieldsNonOverlap(&.{
//!           .{ .name = "header",    .offset = 0,                .size = @sizeOf(usize) },
//!           .{ .name = "next_free", .offset = 8,                .size = @sizeOf(@TypeOf(nextFreePtr(0).*)) },
//!           .{ .name = "prev_free", .offset = 16,               .size = @sizeOf(@TypeOf(prevFreePtr(0).*)) },
//!           .{ .name = "footer",    .offset = MIN_BLOCK_SIZE-8, .size = @sizeOf(usize) },
//!       }, MIN_BLOCK_SIZE);
//!   }
//!
//! The .size MUST come from `@sizeOf(@TypeOf(<the actual deref>))`, never
//! hand-counted — that's the whole point. If a future refactor widens the
//! deref'd type (e.g., usize → ?usize), the assertion trips at compile.

const std = @import("std");

pub const Field = struct {
    name: []const u8,
    offset: usize,
    size: usize,
};

/// Each field must fit in [0, container_size) and no two fields' byte ranges
/// may intersect. Pass null for container_size to skip the bounds check (use
/// when the container size is unbounded or context-dependent, e.g., a free
/// block whose total size is variable).
pub fn assertFieldsNonOverlap(comptime fields: []const Field, comptime container_size: ?usize) void {
    comptime {
        // Zero-size rejection runs UNCONDITIONALLY — including the
        // null-container path. A zero .size means the caller's
        // @sizeOf(@TypeOf(deref)) collapsed (field type refactored to a
        // zero-bit type): the empty interval [x, x) overlaps nothing, so
        // the field's protection would silently vanish while the checker
        // keeps reporting green — the exact vacuous-pass failure mode this
        // library exists to prevent.
        for (fields) |f| {
            if (f.size == 0) {
                @compileError(std.fmt.comptimePrint(
                    "layout: field '{s}' has zero size",
                    .{f.name},
                ));
            }
        }
        if (container_size) |cs| {
            for (fields) |f| {
                const f_end = f.offset + f.size;
                if (f_end > cs) {
                    @compileError(std.fmt.comptimePrint(
                        "layout: field '{s}' [{}, {}) overflows container size {} by {} bytes",
                        .{ f.name, f.offset, f_end, cs, f_end - cs },
                    ));
                }
            }
        }
        var i: usize = 0;
        while (i < fields.len) : (i += 1) {
            const a = fields[i];
            var j: usize = i + 1;
            while (j < fields.len) : (j += 1) {
                const b = fields[j];
                const a_end = a.offset + a.size;
                const b_end = b.offset + b.size;
                // Half-open intervals [start, end). Overlap iff
                // a.offset < b_end AND b.offset < a_end.
                if (a.offset < b_end and b.offset < a_end) {
                    const ov_start = if (a.offset > b.offset) a.offset else b.offset;
                    const ov_end = if (a_end < b_end) a_end else b_end;
                    @compileError(std.fmt.comptimePrint(
                        "layout: '{s}' [{}, {}) overlaps '{s}' [{}, {}) on bytes [{}, {})",
                        .{ a.name, a.offset, a_end, b.name, b.offset, b_end, ov_start, ov_end },
                    ));
                }
            }
        }
    }
}

/// Stricter: fields must non-overlap AND together cover exactly container_size.
/// Useful when there is no "unused" region in the block (e.g., a packed extern
/// struct's expected on-wire layout).
pub fn assertFieldsExactFill(comptime fields: []const Field, comptime container_size: usize) void {
    comptime {
        assertFieldsNonOverlap(fields, container_size);
        var covered: usize = 0;
        for (fields) |f| covered += f.size;
        if (covered != container_size) {
            @compileError(std.fmt.comptimePrint(
                "layout: fields cover {} bytes, container is {} ({} bytes uncovered)",
                .{ covered, container_size, container_size - covered },
            ));
        }
    }
}

// === Self-tests at comptime ===

comptime {
    // Two adjacent 8-byte fields — must not overlap.
    assertFieldsNonOverlap(&.{
        .{ .name = "a", .offset = 0, .size = 8 },
        .{ .name = "b", .offset = 8, .size = 8 },
    }, 16);

    // Exact fill.
    assertFieldsExactFill(&.{
        .{ .name = "hdr", .offset = 0, .size = 8 },
        .{ .name = "body", .offset = 8, .size = 16 },
        .{ .name = "ftr", .offset = 24, .size = 8 },
    }, 32);

    // Sparse layout with hole — non-overlap passes, exact-fill would fail.
    assertFieldsNonOverlap(&.{
        .{ .name = "a", .offset = 0, .size = 8 },
        .{ .name = "b", .offset = 24, .size = 8 },
    }, 32);

    // Null container (variable-size block): overlap check still applies,
    // bounds check skipped. Previously this path had no self-test coverage.
    assertFieldsNonOverlap(&.{
        .{ .name = "hdr", .offset = 0, .size = 8 },
        .{ .name = "link", .offset = 8, .size = 8 },
    }, null);
}
