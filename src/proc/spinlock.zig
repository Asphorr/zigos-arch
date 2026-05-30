const std = @import("std");
const witness = @import("../debug/witness.zig");

/// Ticket-based spinlock for SMP synchronization.
/// Uses @atomicRmw for lock-free ticket acquisition.
pub const SpinLock = struct {
    next_ticket: u32 = 0,
    now_serving: u32 = 0,
    /// WITNESS lock-order class, set by registerLock. 0xFF = unregistered
    /// (the common case) → the lock-order hooks below are skipped entirely.
    witness_class: u8 = 0xFF,
    /// Holder diagnostics — populated after acquire wins, cleared on
    /// release. Read by the spin-warn diagnostic so a deadlock dump
    /// names not just the spinner but the CPU + RIP that's still
    /// sitting on the lock. 0xFF cpu = unheld.
    holder_cpu: u8 = 0xFF,
    holder_ra: u64 = 0,
    /// TSC at the moment `acquireIrqSave` returned. Read by
    /// `releaseIrqRestore` to compute the cli-held duration and emit
    /// a `[cli-hold]` warning past CLI_HOLD_THRESHOLD_MS. 0 = not
    /// currently held by an IrqSave path (plain acquire/release pairs
    /// don't bracket and don't fire the warning).
    acquire_tsc: u64 = 0,

    /// Acquire the lock. Spins until this ticket is served.
    ///
    /// Backoff strategy: proportional-to-ticket-distance. A waiter that's
    /// `D` tickets behind issues `min(D, 32)` `pause` instructions before
    /// re-checking — far-behind waiters re-poll less aggressively, which
    /// cuts the cache-line ping the releaser would otherwise eat (every
    /// `now_serving` write invalidates every waiter's cached copy). The
    /// next-in-line waiter (D==1) still polls at ~max rate so handoff
    /// latency is unchanged from the unbacked-off case.
    ///
    /// After ~200M poll iterations (≈seconds on KVM, longer on real HW
    /// once distance>1 stretches each iteration) we log a one-shot
    /// warning naming both the caller (return address) and the current
    /// holder (cpu + ra). Long spin = almost always a missing release
    /// or a cross-CPU deadlock; the log line is enough for symbols.zig
    /// to resolve both ends.
    pub fn acquire(self: *SpinLock) void {
        const ra = @returnAddress();
        const ticket = @atomicRmw(u32, &self.next_ticket, .Add, 1, .seq_cst);
        var spins: u64 = 0;
        var warned = false;
        while (true) {
            const serving = @atomicLoad(u32, &self.now_serving, .acquire);
            if (serving == ticket) {
                const cpu = currentCpuId();
                self.holder_cpu = cpu;
                self.holder_ra = ra;
                if (comptime witness.enabled) {
                    if (self.witness_class != 0xFF) {
                        const smp = @import("../cpu/smp.zig");
                        witness.spinAcquire(self.witness_class, cpu, smp.myCpu().current_pid, ra);
                    }
                }
                return;
            }
            // u32 wrapping subtract: handles next_ticket overflow correctly
            // since both values are mod 2^32 of the same monotonic counter.
            const distance: u32 = ticket -% serving;
            const cap: u32 = if (distance > 32) 32 else distance;
            var i: u32 = 0;
            while (i < cap) : (i += 1) asm volatile ("pause");
            spins +%= 1;
            if (!warned and spins > 200_000_000) {
                warned = true;
                printSpinDiag(self, ticket, serving, ra);
            }
        }
    }

    /// Runtime check that THIS CPU holds the lock. Inline call at the
    /// entry of every `_locked` function (and any function documented
    /// as requiring the lock). Linux's `lockdep_assert_held` analogue —
    /// catches "caller forgot the lock" the first time the path runs,
    /// instead of waiting for a timing-dependent race. Compiled out in
    /// non-Debug/non-ReleaseSafe.
    pub inline fn assertHeld(self: *const SpinLock) void {
        if (std.debug.runtime_safety) {
            const cpu = currentCpuId();
            std.debug.assert(@atomicLoad(u8, &self.holder_cpu, .acquire) == cpu);
        }
    }

    /// Release the lock. Advances to the next ticket.
    pub fn release(self: *SpinLock) void {
        if (comptime witness.enabled) {
            if (self.witness_class != 0xFF) witness.spinRelease(self.witness_class, currentCpuId());
        }
        self.holder_cpu = 0xFF;
        // Leave holder_ra in place as a "last holder" hint — useful when a
        // deadlock fires immediately after a release/re-acquire cycle.
        _ = @atomicRmw(u32, &self.now_serving, .Add, 1, .release);
    }

    /// Acquire with interrupts disabled. Returns previous RFLAGS for restore.
    pub fn acquireIrqSave(self: *SpinLock) u64 {
        const flags = saveAndDisableIrq();
        self.acquire();
        self.acquire_tsc = @import("../debug/perf.zig").rdtsc();
        return flags;
    }

    /// Release and restore interrupt state. Emits `[cli-hold]` with the
    /// acquire site + held duration if we sat with cli for longer than
    /// CLI_HOLD_THRESHOLD_MS — ground-truth replacement for the SMI
    /// classifier's IRQ0-gap sampling, which can't tell our cli-hold
    /// apart from host SMI or cross-CPU spin contention.
    pub fn releaseIrqRestore(self: *SpinLock, flags: u64) void {
        const start_tsc = self.acquire_tsc;
        const holder_ra = self.holder_ra;
        const cpu_id = self.holder_cpu;
        self.acquire_tsc = 0;
        self.release();
        if (start_tsc != 0) cliHoldCheck(self, start_tsc, holder_ra, cpu_id);
        restoreIrq(flags);
    }
};

/// Warn threshold for cli-bracketed critical sections. 5 ms is the same
/// floor the SMI classifier uses; anything above that is provably too
/// long regardless of why.
const CLI_HOLD_THRESHOLD_MS: u64 = 5;

/// One-shot rate-limit per process tick to avoid log floods when a
/// genuinely-slow path runs in a loop (e.g. paging code-walk during
/// swap pressure). Bumps to >0 only inside cliHoldCheck.
var cli_hold_logged_this_tick: u32 = 0;
var cli_hold_last_tick: u64 = 0;

fn cliHoldCheck(self: *SpinLock, start_tsc: u64, ra: u64, cpu_id: u8) void {
    const apic = @import("../time/apic.zig");
    const per_q = apic.tscPerQuantum();
    if (per_q == 0) return; // pre-calibration; no useful conversion
    const perf = @import("../debug/perf.zig");
    const delta = perf.rdtsc() -% start_tsc;
    // tsc_per_quantum covers 10 ms; threshold in TSC = per_q * (ms/10)
    const threshold_tsc = per_q * CLI_HOLD_THRESHOLD_MS / 10;
    if (delta < threshold_tsc) return;
    // Soft rate-limit: at most ~16 lines per second-of-tick window.
    const process = @import("process.zig");
    const tick: u64 = @atomicLoad(u64, &process.tick_count, .monotonic);
    if (tick != cli_hold_last_tick) {
        cli_hold_last_tick = tick;
        cli_hold_logged_this_tick = 0;
    }
    if (cli_hold_logged_this_tick >= 16) return;
    cli_hold_logged_this_tick += 1;
    const symbols = @import("../debug/symbols.zig");
    const serial = @import("../debug/serial.zig");
    const ms = delta * 10 / per_q;
    if (symbols.resolveKernel(ra)) |r| {
        serial.print(
            "[cli-hold] cpu{d} lock@0x{X} {d} ms at {s}+0x{X}\n",
            .{ cpu_id, @intFromPtr(self), ms, r.name, r.offset },
        );
    } else {
        serial.print(
            "[cli-hold] cpu{d} lock@0x{X} {d} ms ra=0x{X}\n",
            .{ cpu_id, @intFromPtr(self), ms, ra },
        );
    }
}

fn currentCpuId() u8 {
    const apic = @import("../time/apic.zig");
    if (!apic.apic_active) return 0;
    return @as(u8, @truncate(apic.getLapicId()));
}

/// Print the [lock-spin] diagnostic with symbol-resolved caller and
/// holder addresses, then broadcast an NMI to capture every other
/// CPU's current RIP. Falls back to raw hex when the kernel symbol
/// table hasn't been loaded yet (early boot) or when the address
/// falls in a gap between known symbols.
///
/// The NMI broadcast is the key signal: holder_ra is just where the
/// holder ACQUIRED the lock — it doesn't tell us where the holder
/// currently IS (could be in the wait loop, past it but stuck on a
/// nested call, etc.). NMI snapshots dump live RIP from every CPU.
fn printSpinDiag(self: *SpinLock, ticket: u32, serving: u32, ra: usize) void {
    const symbols = @import("../debug/symbols.zig");
    const serial = @import("../debug/serial.zig");
    const kdbg = @import("../debug/kdbg.zig");
    const caller = symbols.resolveKernel(ra);
    const holder = symbols.resolveKernel(self.holder_ra);
    serial.print("[lock-spin] cpu{d} waiting on lock@0x{X} ticket={d} now_serving={d} caller=", .{
        currentCpuId(), @intFromPtr(self), ticket, serving,
    });
    if (caller) |c| {
        serial.print("{s}+0x{X}", .{ c.name, c.offset });
    } else {
        serial.print("0x{X}", .{ra});
    }
    serial.print(" | holder cpu{d} ra=", .{self.holder_cpu});
    if (holder) |h| {
        serial.print("{s}+0x{X}\n", .{ h.name, h.offset });
    } else {
        serial.print("0x{X}\n", .{self.holder_ra});
    }
    // NMI broadcast → every other CPU prints `[nmi-snap cpuN] rip=...
    // fn=symbol+0xN` from inside its NMI handler. Tells us where the
    // holder is RIGHT NOW, not just where it acquired.
    kdbg.broadcastNMI();
}

fn saveAndDisableIrq() u64 {
    var flags: u64 = undefined;
    asm volatile ("pushfq; pop %[f]; cli"
        : [f] "=r" (flags),
    );
    return flags;
}

fn restoreIrq(flags: u64) void {
    if (flags & 0x200 != 0) asm volatile ("sti");
}

// =============================================================================
// Mutex — sleep-aware lock. Unlike SpinLock, holder is identified by PCB
// (owner_pid, not CPU), and contention causes the caller to blockOn(.mutex)
// instead of busy-spinning. Safe to hold ACROSS blockOn() calls — the
// scheduler will never pick another task and have it grab the same mutex,
// because the wait queue gates them via process.blockOnMutex.
//
// When to use Mutex (not SpinLock):
//   - locks held across kernel paths that may yield: virtio-gpu submit
//     (blockOn(.gpu_io) while holding ctrl_lock), long-running disk I/O
//     serialization, anything that may legally sleep while held.
//
// When to KEEP SpinLock:
//   - IRQ-context locks (an IRQ handler cannot sleep).
//   - tiny critical sections where one cache miss > context-switch cost.
//   - boot-time / pre-scheduler paths (no current_pid yet).
//
// Pre-scheduler safety: if smp.myCpu().current_pid is null (early init
// before the first task is dispatched), acquire/release degrade to a
// no-op stamp. The system is single-threaded at that point so no actual
// serialization is needed.
//
// Wake policy: thundering herd. release() wakes ALL .mutex waiters on
// this mutex's id; they re-CAS in parallel, one wins, losers re-sleep
// via blockOnMutex's compare-and-sleep. Acceptable because Mutex is
// reserved for low-contention long-wait locks; the spurious wake cost
// is negligible vs the wait time we're already paying.
// =============================================================================

pub const Mutex = struct {
    /// 0xFFFF = unowned. Otherwise = PID of holder.
    owner_pid: u16 = 0xFFFF,
    /// Diagnostic: where the current/last holder acquired the lock.
    /// Held across release as a "last holder" hint for post-mortems.
    holder_ra: u64 = 0,
    /// WITNESS lock-order class, set by registerMutex. 0xFF = unregistered.
    witness_class: u8 = 0xFF,

    /// Non-blocking, non-trapping observe: is this mutex currently held by
    /// SOMEBODY (any pid)? Snapshot only — value may be stale by the time
    /// the caller acts. Used by panic_screen to decide whether to skip a
    /// GPU flush that would recursively acquire ctrl_lock and self-deadlock.
    pub fn isHeld(self: *const Mutex) bool {
        return @atomicLoad(u16, &self.owner_pid, .acquire) != 0xFFFF;
    }

    /// Runtime check that THIS PID holds the lock. Inline call at the
    /// entry of every Mutex-requiring method. See SpinLock.assertHeld
    /// for the rationale.
    pub inline fn assertHeld(self: *const Mutex) void {
        if (std.debug.runtime_safety) {
            const smp = @import("../cpu/smp.zig");
            const cur = smp.myCpu().current_pid orelse return;
            std.debug.assert(@atomicLoad(u16, &self.owner_pid, .acquire) == @as(u16, @intCast(cur)));
        }
    }

    pub fn acquire(self: *Mutex) void {
        const ra = @returnAddress();
        const smp = @import("../cpu/smp.zig");
        const cur_opt = smp.myCpu().current_pid;
        if (cur_opt == null) {
            // Pre-scheduler / no-task context. Single-threaded — just
            // stamp and return. We deliberately DON'T write owner_pid
            // here: leaving it at 0xFFFF means once the scheduler is up,
            // the first real acquirer sees a free lock (the alternative
            // would require a release-from-no-task path).
            self.holder_ra = ra;
            return;
        }
        const my_pid: u16 = @intCast(cur_opt.?);
        // Recursive-acquire detector. If we're already the holder, sleeping
        // on the contended path would be a permanent self-deadlock — only
        // we can release, and we're about to sleep waiting for ourselves.
        // Panic HERE with the original acquire site + the recursive caller
        // so the bug is debuggable. (Reproduced 2026-05-17: desktop's
        // GPU flush path nested ctrl_lock.acquire while already holding;
        // root-caused via [lock-dump] + [wake-skip] cross-reference.)
        if (@atomicLoad(u16, &self.owner_pid, .acquire) == my_pid) {
            const serial = @import("../debug/serial.zig");
            const symbols = @import("../debug/symbols.zig");
            serial.print("\n!!! Mutex RECURSIVE ACQUIRE by pid={d} !!!\n", .{my_pid});
            serial.print("  mutex @ 0x{X:0>16}\n", .{@intFromPtr(self)});
            if (symbols.resolveKernel(self.holder_ra)) |h| {
                serial.print("  original acquire at: {s}+0x{X}\n", .{ h.name, h.offset });
            } else {
                serial.print("  original acquire at: 0x{X:0>16}\n", .{self.holder_ra});
            }
            if (symbols.resolveKernel(ra)) |c| {
                serial.print("  recursive acquire at: {s}+0x{X}\n", .{ c.name, c.offset });
            } else {
                serial.print("  recursive acquire at: 0x{X:0>16}\n", .{ra});
            }
            @panic("Mutex recursive acquire — self-deadlock prevented");
        }
        if (comptime witness.enabled) {
            // Before the (possibly blocking) CAS loop, so a "sleeping with a
            // spinlock held" violation is caught before we actually park.
            // Use currentCpuId() (LAPIC id) to match the spin hooks — both
            // index witness's spin_held[] and must agree on the numbering, or
            // the sleep-with-spinlock check reads the wrong CPU's held-set.
            if (self.witness_class != 0xFF) witness.mutexAcquire(self.witness_class, currentCpuId(), my_pid, ra);
        }
        const process = @import("process.zig");
        while (true) {
            // Fast path: claim the lock atomically.
            if (@cmpxchgStrong(u16, &self.owner_pid, 0xFFFF, my_pid, .acquire, .monotonic) == null) {
                self.holder_ra = ra;
                return;
            }
            // Contended. Compare-and-sleep until released, then retry.
            // blockOnMutex re-reads owner_pid inside its critical section,
            // so a release that races our enrollment doesn't lose the wake.
            process.blockOnMutex(@truncate(@intFromPtr(self)), &self.owner_pid);
        }
    }

    pub fn release(self: *Mutex) void {
        const smp = @import("../cpu/smp.zig");
        if (smp.myCpu().current_pid == null) {
            // Pre-scheduler: nothing to wake; clear diag.
            return;
        }
        if (comptime witness.enabled) {
            if (self.witness_class != 0xFF) witness.mutexRelease(self.witness_class, smp.myCpu().current_pid.?);
        }
        // Clear ownership BEFORE waking waiters: they retry CAS on wake
        // and need to observe the free state.
        @atomicStore(u16, &self.owner_pid, 0xFFFF, .release);
        const process = @import("process.zig");
        process.wakeMutexWaiters(@truncate(@intFromPtr(self)));
    }

    /// Death-while-holding cleanup. Called from tearDownTask on each
    /// registered mutex when a pid dies. Without this, a SIGKILL of a
    /// pid mid-blockOn() while it holds (say) virtio_gpu.ctrl_lock leaves
    /// the lock permanently owned by a dead pid — every subsequent
    /// submitter then deadlocks in `acquire`, looking like a hardware
    /// hang. Same idea as Linux's `__exit_robust_list` for futexes.
    ///
    /// Returns true if the mutex was force-released (caller can log).
    /// CAS is used so a racing legitimate `release` from the live holder
    /// (if the pid check were stale across teardown stages) doesn't
    /// double-wake. Wake waiters AFTER the CAS so they observe the free
    /// state and re-CAS for acquire.
    pub fn forceReleaseIfOwnedBy(self: *Mutex, pid: u16) bool {
        if (@cmpxchgStrong(u16, &self.owner_pid, pid, 0xFFFF, .release, .monotonic) != null) {
            return false; // not held by `pid` (or not held at all)
        }
        const process = @import("process.zig");
        process.wakeMutexWaiters(@truncate(@intFromPtr(self)));
        return true;
    }
};

/// Walk every registered Mutex and force-release any owned by `pid`.
/// Called from `tearDownTask` so a dying pid never strands a named lock.
/// O(named_lock_count) — small fixed bound, runs once per teardown.
/// Spin locks are skipped (no per-pid ownership; they're held by CPU).
pub fn releaseMutexesOwnedBy(pid: u16) void {
    const serial = @import("../debug/serial.zig");
    // Drop WITNESS's per-pid mutex-held bits so a force-release doesn't
    // strand a stale bit into the next task that reuses this pid slot.
    if (comptime witness.enabled) witness.threadExit(pid);
    var i: u8 = 0;
    while (i < named_lock_count) : (i += 1) {
        const ent = &named_locks[i];
        if (ent.kind != .mutex or ent.ptr == 0) continue;
        const lock: *Mutex = @ptrFromInt(ent.ptr);
        if (lock.forceReleaseIfOwnedBy(pid)) {
            serial.print("[lock-dump] force-released {s} from dying pid={d}\n", .{ ent.name, pid });
        }
    }
}

// =============================================================================
// Lock registry — opt-in naming for SpinLocks and Mutexes so panic/wedge
// dumps can identify the holder of any contended lock by name. Each
// module that wants its lock named at autopsy calls registerLock or
// registerMutex once at boot. Unregistered locks are still functional;
// they just don't appear in autopsy dumps. Registry is fixed-size to
// avoid allocations and to make the dump itself lock-free.
// =============================================================================

const MAX_NAMED_LOCKS: usize = 32;

comptime {
    // Each registered lock's registry index doubles as its WITNESS class, so
    // the registry must not be able to hand out an index WITNESS can't track
    // (registerClass silently drops index >= MAX_CLASSES). Asserted here —
    // spinlock already imports witness, so this direction avoids a cycle.
    if (MAX_NAMED_LOCKS > @as(usize, witness.MAX_CLASSES)) {
        @compileError("MAX_NAMED_LOCKS exceeds witness.MAX_CLASSES — registered locks would be silently untracked");
    }
}

const LockKind = enum(u8) { spin, mutex };

const NamedLock = struct {
    name: []const u8 = "",
    kind: LockKind = .spin,
    ptr: usize = 0, // *SpinLock or *Mutex, discriminated by kind
};

var named_locks: [MAX_NAMED_LOCKS]NamedLock = [_]NamedLock{.{}} ** MAX_NAMED_LOCKS;
var named_lock_count: u8 = 0;

/// Register a SpinLock under `name`. Called once per lock at boot. Also
/// assigns the lock its WITNESS lock-order class (= the registry index).
pub fn registerLock(name: []const u8, lock: *SpinLock) void {
    if (named_lock_count >= MAX_NAMED_LOCKS) return;
    lock.witness_class = named_lock_count;
    named_locks[named_lock_count] = .{ .name = name, .kind = .spin, .ptr = @intFromPtr(lock) };
    witness.registerClass(named_lock_count, name, .spin);
    named_lock_count += 1;
}

/// Register a Mutex under `name`. Same idea as registerLock but the
/// dump path reads owner_pid (not cpu).
pub fn registerMutex(name: []const u8, lock: *Mutex) void {
    if (named_lock_count >= MAX_NAMED_LOCKS) return;
    lock.witness_class = named_lock_count;
    named_locks[named_lock_count] = .{ .name = name, .kind = .mutex, .ptr = @intFromPtr(lock) };
    witness.registerClass(named_lock_count, name, .mutex);
    named_lock_count += 1;
}

/// Register a per-CPU (or otherwise multi-instance) SpinLock FAMILY under a
/// single WITNESS lock-order class. Returns the class so the caller can tag
/// every instance (`lock.witness_class = class`); `representative` is tagged
/// here and is the instance the [lock-dump] autopsy will name (one class can't
/// name N distinct holders anyway). Returns 0xFF if the registry is full, in
/// which case the caller must skip tagging.
///
/// SOUND ONLY when no single CPU ever holds two instances of the family at
/// once: the held-set carries one bit per CPU, so a second same-class acquire
/// on the same CPU is indistinguishable and its release would clear the bit
/// early (a benign false-negative, never a false alarm). ZigOS's per-CPU
/// sched_lock satisfies this — schedule() only ever takes the running CPU's
/// own (see sched.zig); cross-CPU wakeups go through the reschedule IPI, which
/// makes the *remote* CPU take its own lock.
pub fn registerLockClass(name: []const u8, representative: *SpinLock) u8 {
    if (named_lock_count >= MAX_NAMED_LOCKS) return 0xFF;
    const class = named_lock_count;
    representative.witness_class = class;
    named_locks[class] = .{ .name = name, .kind = .spin, .ptr = @intFromPtr(representative) };
    witness.registerClass(class, name, .spin);
    named_lock_count += 1;
    return class;
}

/// Walk registered SpinLocks; emit one [smi-cause] line per currently-held
/// lock whose acquire_tsc indicates it has been held for at least
/// `threshold_ticks` TSC ticks (now − acquire_tsc ≥ threshold_ticks).
/// Mutexes are intentionally skipped — they sleep, so a long-held mutex
/// does not hold cli and cannot cause an SMI-style stall. Cheap O(N) over
/// MAX_NAMED_LOCKS (=32) — safe to call from smi.tick().
pub fn dumpHeldLocksOlderThan(now_tsc: u64, threshold_ticks: u64) void {
    const serial = @import("../debug/serial.zig");
    const symbols = @import("../debug/symbols.zig");
    var i: u8 = 0;
    while (i < named_lock_count) : (i += 1) {
        const ent = &named_locks[i];
        if (ent.ptr == 0 or ent.kind != .spin) continue;
        const lock: *SpinLock = @ptrFromInt(ent.ptr);
        const cpu = @atomicLoad(u8, &lock.holder_cpu, .acquire);
        if (cpu == 0xFF) continue;
        const ts = @atomicLoad(u64, &lock.acquire_tsc, .acquire);
        if (ts == 0 or now_tsc <= ts) continue;
        const held = now_tsc - ts;
        if (held < threshold_ticks) continue;
        serial.print("[smi-cause]   {s}: HELD by cpu{d} for {d} tsc ra=", .{ ent.name, cpu, held });
        if (symbols.resolveKernel(lock.holder_ra)) |r| {
            serial.print("{s}+0x{X}\n", .{ r.name, r.offset });
        } else {
            serial.print("0x{X}\n", .{lock.holder_ra});
        }
    }
}

/// Dump every registered lock's state: SpinLocks print holder cpu +
/// ticket distance, Mutexes print holder pid. Both symbol-resolve the
/// last acquire site. Called from the panic / watchdog autopsy AFTER
/// peer CPUs are halted via broadcastNMI.
pub fn dumpAllLocks() void {
    const serial = @import("../debug/serial.zig");
    const symbols = @import("../debug/symbols.zig");
    serial.print("[lock-dump] ({d} registered locks)\n", .{named_lock_count});
    var i: u8 = 0;
    while (i < named_lock_count) : (i += 1) {
        const ent = &named_locks[i];
        if (ent.ptr == 0) continue;
        switch (ent.kind) {
            .spin => {
                const lock: *SpinLock = @ptrFromInt(ent.ptr);
                const serving = @atomicLoad(u32, &lock.now_serving, .acquire);
                const ticket = @atomicLoad(u32, &lock.next_ticket, .acquire);
                const waiters = ticket -% serving;
                const held = lock.holder_cpu != 0xFF;
                if (held) {
                    serial.print("[lock-dump]   {s}: HELD by cpu{d} (waiters={d}) ra=", .{
                        ent.name, lock.holder_cpu, if (waiters > 0) waiters - 1 else 0,
                    });
                    if (symbols.resolveKernel(lock.holder_ra)) |r| {
                        serial.print("{s}+0x{X}\n", .{ r.name, r.offset });
                    } else {
                        serial.print("0x{X}\n", .{lock.holder_ra});
                    }
                } else if (waiters != 0) {
                    serial.print("[lock-dump]   {s}: free but {d} stale waiters (lock-state inconsistency)\n", .{
                        ent.name, waiters,
                    });
                } else {
                    serial.print("[lock-dump]   {s}: free\n", .{ent.name});
                }
            },
            .mutex => {
                const lock: *Mutex = @ptrFromInt(ent.ptr);
                const owner = @atomicLoad(u16, &lock.owner_pid, .acquire);
                if (owner != 0xFFFF) {
                    serial.print("[lock-dump]   {s}: HELD by pid={d} ra=", .{ ent.name, owner });
                    if (symbols.resolveKernel(lock.holder_ra)) |r| {
                        serial.print("{s}+0x{X}\n", .{ r.name, r.offset });
                    } else {
                        serial.print("0x{X}\n", .{lock.holder_ra});
                    }
                } else {
                    serial.print("[lock-dump]   {s}: free\n", .{ent.name});
                }
            },
        }
    }
}
