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
    /// `releaseIrqRestore` to compute the cli-held duration and record
    /// a cli-hold past CLI_HOLD_THRESHOLD_MS (see cliHoldCheck). 0 = not
    /// currently held by an IrqSave path (plain acquire/release pairs
    /// don't bracket and don't record).
    acquire_tsc: u64 = 0,
    /// vm_alive_pulse sampled at the same moment as acquire_tsc. Diffed at
    /// release to tell "the whole VM was frozen by the host during this
    /// window" (pulse unchanged) from "the VM kept executing" — the only
    /// signal that discriminates a host pause INSIDE a cli window from a
    /// genuine long hold, since the TSC keeps counting through both.
    acquire_pulse: u64 = 0,

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
    ///
    /// Involuntary-preemption pin: the whole acquire+hold window bumps
    /// this CPU's `preempt_pin`, dropped by release() — see the
    /// preempt_pin block comment for why every plain acquire needs it
    /// (the SpinLock-held-across-schedule deadlock class).
    pub fn acquire(self: *SpinLock) void {
        const ra = @returnAddress();
        // Pin BEFORE taking the ticket so there is no instant at which we
        // own (or are committed to owning) the lock while still parkable.
        // The id-read + increment pair must be IRQ-atomic: an IRQ between
        // them could preempt-and-migrate us, landing the pin on the wrong
        // CPU's counter (stuck pin there, underflow here). Two instructions
        // under cli; acquireIrqSave callers arrive with IF already 0 and
        // pay nothing extra.
        const pin_flags = saveAndDisableIrq();
        const cpu = currentCpuId();
        if (cpu < MAX_HOLD_CPUS) preempt_pin[cpu] += 1;
        restoreIrq(pin_flags);
        const ticket = @atomicRmw(u32, &self.next_ticket, .Add, 1, .seq_cst);
        var spins: u64 = 0;
        var warned = false;
        while (true) {
            const serving = @atomicLoad(u32, &self.now_serving, .acquire);
            if (serving == ticket) {
                // Atomic store: every diagnostic reader (assertHeld, the
                // same-CPU spin diag, dumpHeldLocksOlderThan, cpuHoldsAnyLock)
                // atomic-loads holder_cpu — keep writer and readers paired.
                @atomicStore(u8, &self.holder_cpu, cpu, .release);
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
            // Spin-waiters are still EXECUTING even with IRQs masked
            // (acquireIrqSave spins cli'd) — pulse the VM-liveness witness
            // so a peer's long hold that we're queued on isn't mistaken
            // for a whole-VM host freeze (see cliHoldCheck's verdict).
            if (spins & 0xFFF == 0) {
                noteAlivePulse();
                // Same-CPU holder while we spin can never resolve on its
                // own: the preempt pin means a holder is never parked
                // mid-hold, so a holder_cpu equal to OURS is either our own
                // caller (recursion) or this CPU's interrupted context (an
                // IRQ path acquiring what its interruptee holds) — both
                // spin forever. Diagnose at ~4M rounds (order 100ms)
                // instead of waiting out the generic 200M warn. (A task
                // that slept holding the lock and resumed on another CPU
                // can clear this — recoverable, hence diag, not panic.)
                if (!warned and spins >= (1 << 22) and
                    @atomicLoad(u8, &self.holder_cpu, .acquire) == cpu)
                {
                    warned = true;
                    printSpinDiag(self, ticket, serving, ra);
                }
            }
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
        // holder_cpu is ours and stable — the preempt pin forbids migration
        // for the whole hold — so reuse it instead of re-reading the LAPIC
        // id (an uncached MMIO load) for witness + the unpin below.
        const cpu = self.holder_cpu;
        if (comptime witness.enabled) {
            if (self.witness_class != 0xFF) witness.spinRelease(self.witness_class, cpu);
        }
        @atomicStore(u8, &self.holder_cpu, 0xFF, .release);
        // Clear the IrqSave bracket stamp here too: a lock acquired via
        // acquireIrqSave but released via plain release() would otherwise
        // keep a stale acquire_tsc, and the NEXT plain acquire/release
        // cycle would expose holder_cpu set + ancient tsc to
        // dumpHeldLocksOlderThan — a phantom multi-second [smi-cause].
        self.acquire_tsc = 0;
        // Leave holder_ra in place as a "last holder" hint — useful when a
        // deadlock fires immediately after a release/re-acquire cycle.
        _ = @atomicRmw(u32, &self.now_serving, .Add, 1, .release);
        // Unpin AFTER the lock is publicly free. An IRQ landing in between
        // sees pin>0 and defers (flag stays set) — never a parked holder.
        // The read-modify-write is safe without cli because any interrupting
        // handler nets ZERO on the pin (its own acquire/release pair), so an
        // in-flight decrement can't be lost to interleaving — and preemption
        // from here is impossible while the count is still raised.
        // The 0xFF guard makes a double-release skip the decrement instead
        // of underflowing the pin into a permanently-unpreemptible CPU.
        if (cpu < MAX_HOLD_CPUS and preempt_pin[cpu] != 0) preempt_pin[cpu] -= 1;
    }

    /// Acquire with interrupts disabled. Returns previous RFLAGS for restore.
    pub fn acquireIrqSave(self: *SpinLock) u64 {
        const flags = saveAndDisableIrq();
        self.acquire();
        self.acquire_pulse = @atomicLoad(u64, &vm_alive_pulse, .monotonic);
        self.acquire_tsc = @import("../debug/perf.zig").rdtsc();
        return flags;
    }

    /// Release and restore interrupt state. RECORDS a cli-hold (per-CPU
    /// slot, drained + printed by smi.tick under a rate budget) when we
    /// sat with cli for longer than CLI_HOLD_THRESHOLD_MS — ground truth
    /// the SMI classifier corroborates its IRQ0-gap sampling against. For
    /// ≥250ms windows the record carries a freeze-vs-hold verdict (see
    /// vm_alive_pulse). Record-only by design: inline printing here used
    /// to flood thousands of misattributed lines per host-pause storm.
    pub fn releaseIrqRestore(self: *SpinLock, flags: u64) void {
        const start_tsc = self.acquire_tsc;
        const start_pulse = self.acquire_pulse;
        const holder_ra = self.holder_ra;
        const cpu_id = self.holder_cpu;
        self.release(); // also clears acquire_tsc
        if (start_tsc != 0) cliHoldCheck(self, start_tsc, start_pulse, holder_ra, cpu_id);
        restoreIrq(flags);
    }
};

/// Warn threshold for cli-bracketed critical sections. 5 ms is the same
/// floor the SMI classifier uses; anything above that is provably too
/// long regardless of why.
const CLI_HOLD_THRESHOLD_MS: u64 = 5;

// =============================================================================
// cli-hold recording — record-only at release; smi.tick prints.
//
// History: cliHoldCheck used to print [cli-hold] lines inline at release
// time. Under a Hyper-V host-pause storm that produced thousands of lines
// per boot — every vCPU freeze landing inside schedule()'s cli window read
// as an 8-525ms "lock hold" with stale stack frames, and the flood misled
// a whole perf session (2026-06-09). The guest TSC keeps counting through
// a host pause, so DURATION ALONE cannot distinguish a host-frozen window
// from a genuine long hold.
//
// What can: progress elsewhere in the VM. vm_alive_pulse is bumped by every
// handleIRQ0 entry on every CPU (hardware tick or soft yield) and by
// spin-waiters every 4096 backoff rounds. The holder itself can never
// advance it: cli is masked for its whole window and it isn't spinning.
// So across a ≥250ms hold window:
//   pulse advanced ≥2 → something in the VM executed → genuine hold (or a
//                       single-vCPU host steal — indistinguishable inside);
//   pulse unchanged   → NOTHING in the VM ran → whole-VM host freeze,
//                       provably not a kernel hold.
// 250ms = 2.5× the AP idle one-shot cap (10 quanta, rearmTimerForCurrent),
// so an alive-but-idle AP is guaranteed ≥2 pulses inside the window. Below
// 250ms the witness has no resolution → verdict stays .unverified. Same
// when cpu_count==1 (e.g. S3 AP-offline window): no peer, no witness.
// Caveat: a raw cli/sti poll loop (rare, audited) on the only other CPU
// would also silence pulses and could fake .vm_frozen — acceptable for a
// log-only verdict.
//
// Records land in a per-CPU seqlock slot (single writer: the releasing CPU,
// which still holds cli — not even an IRQ can start a nested write). The
// BSP's smi.tick drains all slots every tick and prints under a budget with
// a suppressed-counter, so an AP-side hold or a sub-gap BSP hold still
// surfaces while a storm collapses to a few honest lines + a count.
// =============================================================================

/// Whole-VM execution witness. See block comment above.
var vm_alive_pulse: u64 = 0;

/// Bump the VM-liveness witness. Called from handleIRQ0 (any CPU, any
/// entry kind) and from SpinLock.acquire's contended spin loop.
pub inline fn noteAlivePulse() void {
    _ = @atomicRmw(u64, &vm_alive_pulse, .Add, 1, .monotonic);
}

/// == smp.MAX_CPUS (LAPIC ids are bounded below it at MADT collection).
/// Kept as a local constant so this file stays a top-level leaf; the
/// comptime check below keeps the two from drifting apart.
pub const MAX_HOLD_CPUS: usize = 32;

comptime {
    if (MAX_HOLD_CPUS != @import("../cpu/smp.zig").MAX_CPUS) {
        @compileError("MAX_HOLD_CPUS must equal smp.MAX_CPUS — per-CPU slots below are indexed by LAPIC id");
    }
}

// =============================================================================
// Involuntary-preemption pin — the systematic fix for the SpinLock-held-
// across-schedule deadlock class.
//
// History: a device IRQ landing while a task holds a PLAIN-acquired SpinLock
// (IF=1) can set dynirq_preempt_pending; the DynIrqStub epilogue then ran
// schedule() unconditionally, parking the holder .ready WITH THE LOCK HELD.
// The next task on that CPU to touch the lock spins it dead. Reproduced
// 2026-05-20 at nvme.ioCommand (io_lock) and fixed THERE with acquireIrqSave
// — but every other plain acquire in task context (pmm, page_cache, as_lock,
// vmalloc, swap, …) stayed exposed. Note the timer never had this hole:
// handleIRQ0 deliberately refuses to preempt !from_user contexts.
//
// Fix (Linux preempt_count, scoped to what this kernel needs): each plain
// acquire bumps its CPU's pin before the ticket is taken; release drops it
// after now_serving advances. check_and_preempt_dynirq defers (leaves the
// pending flag SET) while the interrupted context's pin is non-zero — the
// pin drops within the critical section's own µs scale, and the still-set
// flag is consumed at the next boundary. Consequences, all deliberate:
//   * A holder can never be parked mid-hold ⇒ spin waits are bounded by
//     real critical-section lengths, and holder_cpu/witness per-CPU state
//     can never be invalidated by migration-while-holding.
//   * Spinners are pinned too (the pin covers the wait). Safe BECAUSE
//     holders are never parked: the wait is µs-bounded. The one way to
//     break that is sleeping while holding a spinlock — already a bug,
//     already WITNESS-checked, now also surfaced by the same-CPU early
//     spin diagnostic in acquire().
//   * User-mode interrupts always see pin==0 (ring 3 cannot hold kernel
//     locks), so wake-from-IRQ dispatch latency for user contexts — the
//     input path — is byte-identical.
//   * The pin is per-CPU, not per-task: every context switch happens at
//     pin==0 (schedule() releases sched_lock before switchTo; voluntary
//     yields holding a spinlock are the WITNESS bug above), so no
//     save/restore across switches is needed.
// =============================================================================
var preempt_pin: [MAX_HOLD_CPUS]u32 = [_]u32{0} ** MAX_HOLD_CPUS;

/// True when the calling CPU currently holds (or is acquiring) at least one
/// plain-acquired SpinLock and must not be involuntarily preempted. Called
/// by check_and_preempt_dynirq at IF=0; own-CPU counter, plain read.
pub fn preemptionPinned() bool {
    const cpu = currentCpuId();
    if (cpu >= MAX_HOLD_CPUS) return false;
    return preempt_pin[cpu] != 0;
}

pub const HoldVerdict = enum(u8) { unverified, vm_alive, vm_frozen };

/// One recorded cli-hold. Written by the owning CPU under the seqlock
/// protocol below; read by smi.tick via sampleHold.
pub const CliHoldRecord = struct {
    /// Seqlock: bumped to odd before the fields are written, back to even
    /// after. Even and != the reader's last-seen ⇒ a new stable record.
    /// Advances by 2 per record, so (seq_now − seq_seen)/2 − 1 = records
    /// overwritten before the reader drained them.
    seq: u32 = 0,
    end_tsc: u64 = 0,
    dur_tsc: u64 = 0,
    /// Acquire-site return address.
    ra: u64 = 0,
    lock_addr: u64 = 0,
    /// vm_alive_pulse advance across the window (meaningful only when the
    /// verdict logic ran: dur ≥ 250ms and >1 CPU online).
    pulse_delta: u64 = 0,
    verdict: HoldVerdict = .unverified,
    /// Release-time stack-scan return addresses (.text-filtered), captured
    /// raw and symbol-resolved only if printed. 0 = unused entry.
    path: [3]u64 = .{ 0, 0, 0 },
};

var clihold_slots: [MAX_HOLD_CPUS]CliHoldRecord = [_]CliHoldRecord{.{}} ** MAX_HOLD_CPUS;

/// Seqlock read of `cpu`'s slot into `out`. Returns the (even) seq on a
/// stable read — 0 means "never written" — or null on a torn read (writer
/// mid-update; caller retries next tick). All reader loads are .acquire and
/// all writer stores .release: an acquire load forbids later ops from
/// moving above it, so s1 → fields → s2 executes in program order, which is
/// exactly what a seqlock reader needs.
pub fn sampleHold(cpu: usize, out: *CliHoldRecord) ?u32 {
    if (cpu >= MAX_HOLD_CPUS) return null;
    const slot = &clihold_slots[cpu];
    const s1 = @atomicLoad(u32, &slot.seq, .acquire);
    if (s1 & 1 != 0) return null;
    out.end_tsc = @atomicLoad(u64, &slot.end_tsc, .acquire);
    out.dur_tsc = @atomicLoad(u64, &slot.dur_tsc, .acquire);
    out.ra = @atomicLoad(u64, &slot.ra, .acquire);
    out.lock_addr = @atomicLoad(u64, &slot.lock_addr, .acquire);
    out.pulse_delta = @atomicLoad(u64, &slot.pulse_delta, .acquire);
    out.verdict = @atomicLoad(HoldVerdict, &slot.verdict, .acquire);
    for (&out.path, 0..) |*p, i| p.* = @atomicLoad(u64, &slot.path[i], .acquire);
    const s2 = @atomicLoad(u32, &slot.seq, .acquire);
    if (s2 != s1) return null;
    out.seq = s1;
    return s1;
}

/// Linker-provided bounds of the kernel `.text` section (see linker.ld).
/// The P5 held-path stack-scan uses these to keep only words that point
/// INTO executable code. The kernel symbol table also carries data
/// symbols (`kstack_pool` in .bss, the `__bss_phys_*` aliases, …), so an
/// unfiltered `resolveKernel` on raw stack words happily labels random
/// pointers/locals with a data-symbol name — pure noise. A real return
/// address always lands in `.text`; that's the only filter we need.
extern var __text_start: u8;
extern var __text_end: u8;

inline fn isKernelTextAddr(v: u64) bool {
    return v >= @intFromPtr(&__text_start) and v < @intFromPtr(&__text_end);
}

fn cliHoldCheck(self: *SpinLock, start_tsc: u64, start_pulse: u64, ra: u64, cpu_id: u8) void {
    const apic = @import("../time/apic.zig");
    const per_q = apic.tscPerQuantum();
    if (per_q == 0) return; // pre-calibration; no useful conversion
    const perf = @import("../debug/perf.zig");
    const delta = perf.rdtsc() -% start_tsc;
    // tsc_per_quantum covers 10 ms; threshold in TSC = per_q * (ms/10)
    const threshold_tsc = per_q * CLI_HOLD_THRESHOLD_MS / 10;
    if (delta < threshold_tsc) return;
    if (cpu_id >= MAX_HOLD_CPUS) return;

    // Freeze-vs-hold verdict — see the vm_alive_pulse block comment.
    var verdict: HoldVerdict = .unverified;
    var pulse_delta: u64 = 0;
    const verdict_min_tsc = per_q * 25; // 250 ms = 2.5× the AP idle one-shot cap
    if (delta >= verdict_min_tsc) {
        pulse_delta = @atomicLoad(u64, &vm_alive_pulse, .monotonic) -% start_pulse;
        const smp = @import("../cpu/smp.zig");
        if (smp.cpu_count > 1) {
            verdict = if (pulse_delta == 0) .vm_frozen else if (pulse_delta >= 2) .vm_alive else .unverified;
        }
    }

    // P5: mini stack-scan backtrace of the holder AT RELEASE. The acquire
    // `ra` is only WHERE the lock was taken; this captures the call path
    // the critical section was on when it finally let go. The RBP walk is
    // unreliable here (higher-half kernel + omit-frame-pointer), so we scan
    // THIS cpu's own (mapped) kstack for words that point into kernel
    // `.text` — the range pre-filter is what keeps the output trustworthy
    // (raw stack words alias data symbols otherwise). Raw addresses only;
    // symbol resolution is deferred to smi's print path. Skipped for
    // vm_frozen: those frames are host-storm noise we'll never print —
    // exactly the stale-frame misattribution this redesign exists to kill.
    var path = [3]u64{ 0, 0, 0 };
    if (verdict != .vm_frozen) {
        var fp = @frameAddress();
        const page_top = (fp & ~@as(usize, 0xFFF)) + 0x1000;
        var scanned: usize = 0;
        var shown: usize = 0;
        while (fp + 8 <= page_top and scanned < 96 and shown < 3) : (fp += 8) {
            scanned += 1;
            const v = @as(*const u64, @ptrFromInt(fp)).*;
            if (!isKernelTextAddr(v)) continue;
            path[shown] = v;
            shown += 1;
        }
    }

    // Publish into this CPU's seqlock slot. Single writer guaranteed: we
    // still hold cli, so not even an IRQ can start a second write here.
    const slot = &clihold_slots[cpu_id];
    const s = @atomicLoad(u32, &slot.seq, .monotonic);
    @atomicStore(u32, &slot.seq, s +% 1, .release); // odd: write in progress
    @atomicStore(u64, &slot.end_tsc, start_tsc +% delta, .release);
    @atomicStore(u64, &slot.dur_tsc, delta, .release);
    @atomicStore(u64, &slot.ra, ra, .release);
    @atomicStore(u64, &slot.lock_addr, @intFromPtr(self), .release);
    @atomicStore(u64, &slot.pulse_delta, pulse_delta, .release);
    @atomicStore(HoldVerdict, &slot.verdict, verdict, .release);
    for (path, 0..) |v, i| @atomicStore(u64, &slot.path[i], v, .release);
    @atomicStore(u32, &slot.seq, s +% 2, .release); // even: stable

    // No PM_TMR on this board → smi.tick never drains the slots. Rare
    // config (q35 always has one); print directly, hard-capped per boot.
    if (!@import("../time/smi.zig").isActive()) {
        const S = struct {
            var printed: u32 = 0;
        };
        if (S.printed < 32) {
            S.printed += 1;
            const symbols = @import("../debug/symbols.zig");
            const serial = @import("../debug/serial.zig");
            const ms = delta * 10 / per_q;
            if (symbols.resolveKernel(ra)) |r| {
                serial.print("[cli-hold] cpu{d} lock@0x{X} {d} ms at {s}+0x{X} (no-smi fallback)\n", .{ cpu_id, @intFromPtr(self), ms, r.name, r.offset });
            } else {
                serial.print("[cli-hold] cpu{d} lock@0x{X} {d} ms ra=0x{X} (no-smi fallback)\n", .{ cpu_id, @intFromPtr(self), ms, ra });
            }
        }
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

/// Mutex.owner_pid sentinel for holds taken from a context with no
/// current_pid. Outside the valid pid range (MAX_PROCS=64) and distinct
/// from the 0xFFFF "unowned" sentinel, so forceReleaseIfOwnedBy(real pid)
/// can never match it.
pub const NO_TASK_OWNER: u16 = 0xFFFE;

pub const Mutex = struct {
    /// 0xFFFF = unowned. 0xFFFE (NO_TASK_OWNER) = held from a no-task
    /// context (pre-scheduler boot thread, or an IRQ that landed before the
    /// first dispatch). Otherwise = PID of holder.
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
            // No-task context — pre-scheduler boot. The old stamp-only
            // no-op assumed strict single-threadedness, but IRQ-context
            // callers exist (virtio_gpu's IF=0 inline-fallback tryAcquire
            // can fire mid-boot): an unclaimed hold let tryAcquire
            // "succeed" straight into this live critical section. CLAIM a
            // sentinel owner so exclusion is real; release()'s no-task
            // path clears it. On CAS failure proceed anyway like the old
            // code (a no-task acquire of a held mutex can only be the
            // boot thread self-nesting — excluding would self-wedge the
            // boot) but say so: it means the inner release will free the
            // outer hold early, which is worth a breadcrumb.
            if (@cmpxchgStrong(u16, &self.owner_pid, 0xFFFF, NO_TASK_OWNER, .acquire, .monotonic) != null) {
                const serial = @import("../debug/serial.zig");
                serial.print("[mutex] no-task acquire of held mutex@0x{X} (boot self-nest?)\n", .{@intFromPtr(self)});
            }
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

    /// Non-blocking acquire attempt. Returns true on success (caller owns
    /// the mutex and must release()). A lock already held — including by
    /// the calling pid itself — just returns false: the caller chose not
    /// to wait, so unlike acquire() there is no self-deadlock to panic
    /// about. No-task context mirrors acquire(): stamp and succeed.
    pub fn tryAcquire(self: *Mutex) bool {
        const ra = @returnAddress();
        const smp = @import("../cpu/smp.zig");
        const cur_opt = smp.myCpu().current_pid;
        if (cur_opt == null) {
            // Honest even with no task: claim the sentinel or report
            // failure. (The old unconditional `return true` let an
            // IRQ-context tryAcquire during a boot-thread hold walk
            // straight into the live critical section.)
            if (@cmpxchgStrong(u16, &self.owner_pid, 0xFFFF, NO_TASK_OWNER, .acquire, .monotonic) != null) {
                return false;
            }
            self.holder_ra = ra;
            return true;
        }
        const my_pid: u16 = @intCast(cur_opt.?);
        if (@cmpxchgStrong(u16, &self.owner_pid, 0xFFFF, my_pid, .acquire, .monotonic) != null) {
            return false;
        }
        if (comptime witness.enabled) {
            // After the CAS (we never sleep here, so the pre-park ordering
            // concern in acquire() doesn't apply) — but still recorded, so
            // release()'s witness.mutexRelease stays balanced.
            if (self.witness_class != 0xFF) witness.mutexAcquire(self.witness_class, currentCpuId(), my_pid, ra);
        }
        self.holder_ra = ra;
        return true;
    }

    pub fn release(self: *Mutex) void {
        const smp = @import("../cpu/smp.zig");
        if (smp.myCpu().current_pid == null) {
            // No-task context: clear the sentinel claim (no-op if a boot
            // self-nest's inner release already freed it). Wake on success
            // is cheap pre-scheduler (procs[] all .unused → no-op) and
            // closes the lost-wake hole if a task ever DOES contend a
            // sentinel-held mutex.
            if (@cmpxchgStrong(u16, &self.owner_pid, NO_TASK_OWNER, 0xFFFF, .release, .monotonic) == null) {
                const process = @import("process.zig");
                process.wakeMutexWaiters(@truncate(@intFromPtr(self)));
            }
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

/// True if `cpu_id` currently holds any registered SpinLock. The watchdog
/// uses this to tell a peer that's frozen but holding NOTHING (host vCPU
/// pause — safe to wait for it to resume) from one frozen INSIDE a cli
/// critical section (a real wedge there can deadlock-propagate to us, so
/// halt sooner). Best-effort: only registered locks are visible —
/// an unregistered-lock wedge reads as "free" and just gets the longer
/// grace, still caught by the resume probe. Cheap O(N) over the registry.
pub fn cpuHoldsAnyLock(cpu_id: u8) bool {
    var i: u8 = 0;
    while (i < named_lock_count) : (i += 1) {
        const ent = &named_locks[i];
        if (ent.ptr == 0 or ent.kind != .spin) continue;
        const lock: *SpinLock = @ptrFromInt(ent.ptr);
        if (@atomicLoad(u8, &lock.holder_cpu, .acquire) == cpu_id) return true;
    }
    return false;
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
                if (owner == NO_TASK_OWNER) {
                    serial.print("[lock-dump]   {s}: HELD by no-task ctx ra=", .{ent.name});
                    if (symbols.resolveKernel(lock.holder_ra)) |r| {
                        serial.print("{s}+0x{X}\n", .{ r.name, r.offset });
                    } else {
                        serial.print("0x{X}\n", .{lock.holder_ra});
                    }
                } else if (owner != 0xFFFF) {
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
