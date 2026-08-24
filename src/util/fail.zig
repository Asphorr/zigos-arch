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
const spinlock = @import("../proc/spinlock.zig");

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
    seq: u64 = 0, // (p:ring_lock) 1-based global sequence, 0 = never used
    tsc: u64 = 0, // (p:ring_lock) perf.rdtsc() at record time
    name: []const u8 = "", // (p:ring_lock) @errorName — static storage
    msg: [MSG_BYTES]u8 = undefined, // (p:ring_lock)
    msg_len: u8 = 0, // (p:ring_lock)
};

var ring: [RING_ENTRIES]Entry = [_]Entry{.{}} ** RING_ENTRIES;
/// (p:ring_lock) total records ever; next slot = ring_seq % RING_ENTRIES.
var ring_seq: u64 = 0;
/// Leaf lock: held only across one slot's fields + the seq bump; never
/// acquires anything else, safe from IRQ context via IrqSave.
var ring_lock: spinlock.SpinLock = .{};

/// Record the detail, return the error unchanged — so failure sites stay
/// one-liners: `return fail(error.Timeout, "cid={d}", .{cid});`. The
/// returned type is the argument's own error-set type, so it coerces
/// exactly like a bare `return error.X` would.
pub fn fail(e: anytype, comptime fmt: []const u8, args: anytype) @TypeOf(e) {
    record(e, fmt, args);
    return e;
}

fn record(e: anyerror, comptime fmt: []const u8, args: anytype) void {
    const flags = ring_lock.acquireIrqSave();
    defer ring_lock.releaseIrqRestore(flags);
    const slot = &ring[ring_seq % RING_ENTRIES];
    ring_seq += 1;
    slot.seq = ring_seq;
    slot.tsc = perf.rdtsc();
    slot.name = @errorName(e);
    if (std.fmt.bufPrint(&slot.msg, fmt, args)) |written| {
        slot.msg_len = @intCast(written.len);
    } else |_| {
        slot.msg_len = MSG_BYTES; // truncated: buffer holds the prefix
    }
}

/// Print the newest `max` ring entries, oldest first. Diagnostic path
/// (errtrace.dump, cli `errlog`): serial only, bounded, takes the ring
/// lock briefly per entry snapshot — safe anywhere serial.print is.
pub fn dumpRecent(max: usize) void {
    const flags = ring_lock.acquireIrqSave();
    const total = ring_seq;
    ring_lock.releaseIrqRestore(flags);
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
        const f2 = ring_lock.acquireIrqSave();
        const slot = ring[i % RING_ENTRIES];
        ring_lock.releaseIrqRestore(f2);
        if (slot.seq != i + 1) {
            serial.print("  #{d}: (recycled mid-dump)\n", .{i + 1});
            continue;
        }
        const per_quantum = apic.tscPerQuantum();
        const age_ms: u64 = if (per_quantum == 0) 0 else (perf.rdtsc() -% slot.tsc) * 10 / per_quantum;
        serial.print("  #{d}: {s} \"{s}\" ({d} ms ago)\n", .{
            slot.seq, slot.name, slot.msg[0..slot.msg_len], age_ms,
        });
    }
}
