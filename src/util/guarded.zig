//! guarded — data that lives behind its lock.
//!
//! The completion of the Lock-Guard pattern (docs/STYLE.md): the hand-rolled
//! `pmm.Region.Guard` proved that a *witness of lock-held state* can make
//! "requires the lock" a compile error instead of a `(p:lockname)` comment.
//! `Guarded(T)` generalizes it and adds the missing half — the DATA moves
//! behind the witness too. The only route to a `*T` is a token that an
//! acquire returned, so "touched the state, forgot the lock" stops being a
//! once-a-month race and becomes code of a visibly different shape.
//!
//! What the type gives beyond the raw `lock + fields + comments` layout:
//!   - lock and data are declared as ONE thing; the pairing is structure,
//!     not adjacency;
//!   - lock-requiring helpers become methods on `T` — reachable only
//!     through `held.ptr`, which is the compile-time assertHeld;
//!   - the IrqSave flags ride INSIDE the token, so the acquire flavor and
//!     the release flavor can never be mismatched (the stale-acquire_tsc /
//!     phantom-[smi-cause] class dies at the type level);
//!   - `@returnAddress()`-based autopsy attribution is preserved: the
//!     acquire wrappers are `inline`, so a plain `acquire()` records the
//!     REAL call site, not this file. (`acquireIrqSave` has ALWAYS
//!     attributed to SpinLock's own internals — it takes @returnAddress
//!     inside the `self.acquire()` it re-enters — kernel-wide, wrapper
//!     or no wrapper. Nothing lost here, but nothing gained either.)
//!
//! What it deliberately does NOT give (Zig has no private fields and no
//! borrow checker):
//!   - `g.data__` still compiles. The trailing `__` is the tripwire: it is
//!     ugly in review and greppable by the planned context lint. Convention
//!     holds the door; the type merely makes the honest path the easy one.
//!   - a token outliving its release is not caught. Keep the house shape:
//!     `const h = g.acquire(); defer h.release();` in one scope.
//!
//! When NOT to reach for this (STYLE.md's own criterion, unchanged): state
//! whose lock lives on ANOTHER object (PCB fields under their runqueue's
//! lock) or fields with per-field split protection (nvme waiters: alloc
//! side under io_lock, completion side under cq_lock; pmm's shared bitmap).
//! Those keep `(p:lockname)` prose — or wait for the keyed-guard variant.
//! Mutex-flavored state has no customer yet; add `GuardedMutex` when one
//! appears, don't pre-build it.

const std = @import("std");
const spinlock = @import("../proc/spinlock.zig");

pub fn Guarded(comptime T: type) type {
    return struct {
        /// Public for exactly two customers: `spinlock.registerLock(&g.lock)`
        /// (autopsy naming) and lock-choreography sites that hold it through
        /// other means and re-enter via `refHeld()`. Never acquire it
        /// directly to touch the data — that's what the tokens are for.
        lock: spinlock.SpinLock = .{},
        /// The protected state. The `__` suffix marks the ONLY field the
        /// convention forbids touching outside this file's tokens.
        data__: T,

        const Self = @This();

        pub fn init(value: T) Self {
            return .{ .data__ = value };
        }

        /// Witness of a plain `acquire()`. Thin: a pointer pair, no hidden
        /// state — see the comptime proof below.
        pub const Held = struct {
            ptr: *T,
            lock: *spinlock.SpinLock,

            pub inline fn release(self: Held) void {
                self.lock.release();
            }
        };

        /// Witness of `acquireIrqSave()`. Carries the saved RFLAGS, so the
        /// paired restore cannot be forgotten or fed someone else's flags.
        pub const IrqHeld = struct {
            ptr: *T,
            lock: *spinlock.SpinLock,
            flags: u64,

            pub inline fn release(self: IrqHeld) void {
                self.lock.releaseIrqRestore(self.flags);
            }
        };

        /// Task-context acquire (SpinLock.acquire semantics: preempt-pinned
        /// for the hold, IRQs stay on). inline so SpinLock's holder_ra
        /// names the caller, not this wrapper.
        pub inline fn acquire(self: *Self) Held {
            self.lock.acquire();
            return .{ .ptr = &self.data__, .lock = &self.lock };
        }

        /// IRQ-safe acquire (SpinLock.acquireIrqSave semantics). inline
        /// for symmetry and zero cost; holder_ra for THIS flavor has
        /// always named SpinLock.acquireIrqSave internals (it re-enters
        /// via self.acquire()), so attribution is unchanged either way.
        pub inline fn acquireIrqSave(self: *Self) IrqHeld {
            const flags = self.lock.acquireIrqSave();
            return .{ .ptr = &self.data__, .lock = &self.lock, .flags = flags };
        }

        /// Escape for choreographies that provably hold `lock` through other
        /// means — the pmm lock-ALL-regions walk, where materializing N
        /// tokens would burn kernel stack for nothing. Runtime-checked
        /// (assertHeld: this CPU is the holder) in safe builds, free in
        /// ReleaseFast. Prefer the tokens everywhere a token fits.
        pub inline fn refHeld(self: *Self) *T {
            self.lock.assertHeld();
            return &self.data__;
        }

        /// Lock-free view for autopsy/wedge-dump paths that must not
        /// acquire (the holder may be the thing being autopsied). Values
        /// may be torn or stale; print them, never act on them.
        pub inline fn racyPeek(self: *const Self) *const T {
            return &self.data__;
        }
    };
}

// ------------------------------ self-proof ----------------------------------
comptime {
    const G = Guarded(u64);
    // Tokens are thin plain pairs/triples — no hidden state rode in. A held
    // token costing more than its words would show up here, at build time.
    std.debug.assert(@sizeOf(G.Held) == 2 * @sizeOf(usize));
    std.debug.assert(@sizeOf(G.IrqHeld) == 3 * @sizeOf(usize));
    // The wrapper adds a SpinLock and nothing else (alignment permitting):
    // data is stored inline, not boxed.
    std.debug.assert(@sizeOf(G) <= @sizeOf(spinlock.SpinLock) + @sizeOf(u64) + @alignOf(spinlock.SpinLock));
}
