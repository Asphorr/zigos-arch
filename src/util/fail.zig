//! fail — errors that carry their birthplace.
//!
//! A Zig error value names the CLASS of failure; what it cannot carry is
//! the detail (which LBA, what status word, which cid) or where it was
//! born. The house pattern: the failure site returns through `fail()`,
//! which records the detail into a fixed ring and hands the error back —
//! `return fail(error.BadCrc, "lba={d} crc 0x{X}!=0x{X}", .{...})`. The
//! ring is RECORD-only (rule 6): nothing prints on the hot path, and a
//! probe loop that legitimately fails a hundred times (mounting every
//! partition of every disk) stays quiet. `errtrace.dump()` drains the
//! tail when an error actually surfaces at an ABI boundary or a panic.
//!
//! ReleaseSafe builds compile with error-return tracing forced ON
//! (build.zig), so the propagation path — every `try` between birth and
//! catch — is reconstructable via @errorReturnTrace(); this ring holds
//! the half a StackTrace can't: the formatted detail.

const std = @import("std");

// Core deps.
const perf = @import("../debug/perf.zig");
const Guarded = @import("guarded.zig").Guarded;

// Diagnostics-only deps (dumpRecent).
const serial = @import("../debug/serial.zig");
const apic = @import("../time/apic.zig");

/// Generic kernel failure vocabulary, for plumbing that doesn't want its
/// own set. Subsystems with richer taxonomies keep declaring their own
/// (bpf.VerifyError, tls.RecordError, gpt.ParseError) — errno.fromError
/// translates both by NAME at the ABI boundary.
pub const KError = error{
    NoMem,
    NoSlot,
    NoEnt,
    Busy,
    Timeout,
    BadArg,
    BadState,
    Fault,
    Io,
    Corrupt,
    Unsupported,
};

/// Ring depth. 32 entries survive a burst (one failing probe loop) while
/// keeping the whole ring under 4 KB of BSS.
const RING_ENTRIES: usize = 32;
/// Formatted-detail budget per entry. Overlong messages truncate — the
/// prefix carries the identifiers, which is what an autopsy needs.
const MSG_BYTES: usize = 96;

const Entry = struct {
    seq: u64 = 0, // 1-based global sequence, 0 = never used
    tsc: u64 = 0, // perf.rdtsc() at record time
    name: []const u8 = "", // @errorName — static storage
    msg: [MSG_BYTES]u8 = undefined,
    msg_len: u8 = 0,
};

/// Everything the ring lock protects, behind the lock (util/guarded.zig).
/// The lock is a leaf: held only across one slot's fields + the seq bump,
/// never acquires anything else, safe from IRQ context via the IrqSave
/// token.
const RingState = struct {
    entries: [RING_ENTRIES]Entry = [_]Entry{.{}} ** RING_ENTRIES,
    /// Total records ever; next slot = seq % RING_ENTRIES.
    seq: u64 = 0,
};

var ring: Guarded(RingState) = .init(.{});

/// Record the detail, return the error unchanged — so failure sites stay
/// one-liners: `return fail(error.Timeout, "cid={d}", .{cid});`. The
/// returned type is the argument's own error-set type, so it coerces
/// exactly like a bare `return error.X` would.
pub fn fail(e: anytype, comptime fmt: []const u8, args: anytype) @TypeOf(e) {
    record(e, fmt, args);
    return e;
}

/// Contract: task/IRQ context only — NEVER from an NMI handler
/// (ring.lock is a plain ticket lock; acquireIrqSave does not mask NMI,
/// so an NMI-context fail() self-deadlocks against an interrupted
/// holder on the same CPU). Format only kernel-owned data: a `{s}` on a
/// user-space slice would take a kernel #PF with IRQs off and the ring
/// lock held.
fn record(e: anyerror, comptime fmt: []const u8, args: anytype) void {
    const h = ring.acquireIrqSave();
    defer h.release();
    const slot = &h.ptr.entries[h.ptr.seq % RING_ENTRIES];
    h.ptr.seq += 1;
    slot.seq = h.ptr.seq;
    slot.tsc = perf.rdtsc();
    slot.name = @errorName(e);
    // Zero first: on NoSpaceLeft, bufPrint leaves only the prefix it
    // managed — without the wipe, dumpRecent would splice that prefix
    // onto stale bytes from the record 32 entries ago and print a
    // confident, WRONG reading.
    @memset(&slot.msg, 0);
    if (std.fmt.bufPrint(&slot.msg, fmt, args)) |written| {
        slot.msg_len = @intCast(written.len);
    } else |_| {
        slot.msg_len = @intCast(std.mem.indexOfScalar(u8, &slot.msg, 0) orelse MSG_BYTES);
    }
}

/// Print the newest `max` ring entries, oldest first. Diagnostic path
/// (errtrace.dump, cli `errlog`): serial only, bounded, takes the ring
/// lock briefly per entry snapshot — safe anywhere serial.print is.
pub fn dumpRecent(max: usize) void {
    const h0 = ring.acquireIrqSave();
    const total = h0.ptr.seq;
    h0.release();
    if (total == 0) {
        serial.print("[fail-ring] empty\n", .{});
        return;
    }
    const n = @min(@min(max, RING_ENTRIES), total);
    serial.print("[fail-ring] last {d} of {d} recorded failures:\n", .{ n, total });
    var i: u64 = total - n;
    while (i < total) : (i += 1) {
        // Snapshot under the lock; a racing writer can recycle the slot
        // between iterations, in which case the seq check names the skip.
        const h = ring.acquireIrqSave();
        const slot = h.ptr.entries[i % RING_ENTRIES];
        h.release();
        if (slot.seq != i + 1) {
            serial.print("  #{d}: (recycled mid-dump)\n", .{i + 1});
            continue;
        }
        // Guard the subtraction: cross-CPU TSC skew could read `now`
        // below the record's stamp, and the wrapped value would
        // overflow-panic in the `* 10` (same class as
        // Deadline.elapsedMs).
        const per_quantum = apic.tscPerQuantum();
        const now = perf.rdtsc();
        const age_ms: u64 = if (per_quantum == 0 or now <= slot.tsc) 0 else (now - slot.tsc) * 10 / per_quantum;
        serial.print("  #{d}: {s} \"{s}\" ({d} ms ago)\n", .{
            slot.seq, slot.name, slot.msg[0..slot.msg_len], age_ms,
        });
    }
}
