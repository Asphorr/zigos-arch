//! slot_table — the fixed-pool claim protocol, written once.
//!
//! 26 subsystems keep an `in_use`-flagged fixed array (pipes, shm, tls
//! conns, pcid, fdpoll, …) and each re-derives the same four-invariant
//! claim dance from memory:
//!
//!   1. unlocked fast FILTER on in_use (skip busy slots cheaply);
//!   2. take the slot lock and RE-CHECK in_use — without this, two CPUs
//!      pass the filter together and initialise the same slot (the
//!      pipe.alloc double-claim, 2026-06);
//!   3. reset the payload fields WITHOUT touching `lock` (a whole-struct
//!      `.{}` assign would zero the ticket counters the claimant is
//!      HOLDING and a cross-CPU spinner is mid-acquire on) and without
//!      touching `in_use` yet;
//!   4. publish with a `.release` store of in_use=true LAST, so readers
//!      that check it unlocked can never observe a half-reset slot
//!      (x86-TSO keeps the plain field writes ahead of it).
//!
//! `claim()` is that dance over a borrowed slice — the table keeps
//! owning its array, its indices, and its free/refcount policy; only
//! the claim protocol is shared. The reset is comptime reflection over
//! the struct's own field defaults, so a new field added with a default
//! is reset correctly with zero extra code — and a field added WITHOUT
//! a default fails the build instead of joining half-reset.
//!
//! Requirements on T, checked at comptime: a `lock: SpinLock` field, an
//! `in_use: bool = false` field, defaults on everything else. A payload
//! buffer defaulted `= undefined` (contract-undefined while unclaimed)
//! is named in an optional `pub const claim_skip_reset = .{"buf"};`
//! decl on the struct so the reset skips it explicitly.

const std = @import("std");

const spinlock = @import("../proc/spinlock.zig");

/// The result of a successful claim: the slot, locked, payload reset,
/// NOT yet published. Fill the caller-specific fields (refcounts), then
/// `publish()`. `abort()` backs out (slot stays free).
pub fn Claim(comptime T: type) type {
    return struct {
        slot: *T,
        idx: u32,
        irq_flags: u64,

        const Self = @This();

        /// in_use=true with .release, then drop the slot lock. After
        /// this the slot is live for every unlocked-filter reader.
        pub fn publish(self: Self) void {
            @atomicStore(bool, &self.slot.in_use, true, .release);
            self.slot.lock.releaseIrqRestore(self.irq_flags);
        }

        /// Back out: drop the lock, slot stays unclaimed (in_use was
        /// never set). The payload reset it received is harmless.
        pub fn abort(self: Self) void {
            self.slot.lock.releaseIrqRestore(self.irq_flags);
        }
    };
}

/// Scan `slots` for a free entry and claim it per the protocol above.
/// Null = pool exhausted. O(n) linear scan — fine for the tens-of-slots
/// tables this serves; a table hot enough to need a freelist has
/// outgrown this helper.
pub fn claim(comptime T: type, slots: []T) ?Claim(T) {
    comptime verifyTable(T);
    for (slots, 0..) |*s, i| {
        // Unlocked fast filter — the claim itself re-checks under the
        // slot lock below. Monotonic: no ordering needed for a hint.
        if (@atomicLoad(bool, &s.in_use, .monotonic)) continue;
        const flags = s.lock.acquireIrqSave();
        if (s.in_use) { // lost the claim race to another CPU
            s.lock.releaseIrqRestore(flags);
            continue;
        }
        resetPayload(T, s);
        return .{ .slot = s, .idx = @intCast(i), .irq_flags = flags };
    }
    return null;
}

/// Release a slot back to the pool. Caller decides WHEN (refcounts hit
/// zero, teardown) and must hold the slot lock, matching the claim
/// side's discipline — asserted, not assumed.
pub fn recycle(comptime T: type, slot: *T) void {
    comptime verifyTable(T);
    slot.lock.assertHeld();
    @atomicStore(bool, &slot.in_use, false, .release);
}

/// Field-by-field reset to declared defaults, skipping `lock` (held by
/// the claimant RIGHT NOW), `in_use` (published last, separately), and
/// anything the struct names in `claim_skip_reset` (undefined-defaulted
/// payload buffers — contract-undefined while unclaimed, and a runtime
/// store of a big undefined constant is a wasted memcpy at best).
fn resetPayload(comptime T: type, slot: *T) void {
    inline for (@typeInfo(T).@"struct".fields) |f| {
        if (comptime !shouldReset(T, f.name)) continue;
        if (comptime f.defaultValue()) |dv| {
            @field(slot, f.name) = dv;
        } else {
            @compileError("slot_table: field '" ++ f.name ++ "' of " ++ @typeName(T) ++ " has no default and is not in claim_skip_reset — a claimed slot would carry stale state");
        }
    }
}

fn shouldReset(comptime T: type, comptime name: []const u8) bool {
    if (std.mem.eql(u8, name, "lock") or std.mem.eql(u8, name, "in_use")) return false;
    if (@hasDecl(T, "claim_skip_reset")) {
        inline for (T.claim_skip_reset) |skip| {
            if (std.mem.eql(u8, name, skip)) return false;
        }
    }
    return true;
}

fn verifyTable(comptime T: type) void {
    if (!@hasField(T, "lock") or @FieldType(T, "lock") != spinlock.SpinLock) {
        @compileError("slot_table: " ++ @typeName(T) ++ " needs a `lock: SpinLock` field");
    }
    if (!@hasField(T, "in_use") or @FieldType(T, "in_use") != bool) {
        @compileError("slot_table: " ++ @typeName(T) ++ " needs an `in_use: bool` field");
    }
}
