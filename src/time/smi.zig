// SMI / scheduler stall detector.
//
// Real-HW BIOSes fire System Management Interrupts (SMIs) for things like
// USB legacy emulation, fan control, thermal throttling, and ACPI events.
// SMM runs at a higher privilege than the OS and can hold all CPUs for
// 5-80 ms with no notification. Symptom: the desktop hitches every few
// seconds even though "nothing" is happening.
//
// Detection works because:
//   - BSP IRQ0 (timer) fires deterministically every 10 ms when IRQs are
//     unmasked.
//   - ACPI PM_TMR is a 24- or 32-bit free-running counter at 3.579545 MHz,
//     accessed via I/O port from FADT.pm_tmr_blk.
//   - Between two consecutive BSP IRQ0 entries, PM_TMR should advance by
//     ~35795 ticks (= 10 ms × 3.579545 MHz). If we see significantly more,
//     the OS lost time — either to SMM or to a long-disabled IRQ window.
//
// This module is also the sole PRINTER for spinlock's cli-hold records:
// cliHoldCheck records into per-CPU seqlock slots and tick() drains them
// under a rate budget (flushCliHolds). Printing used to happen inline at
// release time — under a Hyper-V host-pause storm that flooded thousands
// of misattributed [cli-hold] lines per boot (see spinlock.zig's
// vm_alive_pulse block comment for the full story).
//
// The wall ruler (2026-09-16): PM_TMR was the only ruler until the tick
// was measured — the PIIX4 timer port is emulated in QEMU USERSPACE, so
// one `inl` is a KVM_EXIT_IO round trip through QEMU, and nested under
// Hyper-V that is ~100k+ cycles; the tick paid two (entry sample + exit
// re-baseline) = ~80 % of the BSP tick's 396k mean cycles. Under KVM the
// tick now reads kvmclock instead (kvm.clockNs: the BSP's pvclock record
// in guest RAM, ~100 cycles, no exit) and keeps PM_TMR for bare metal
// and non-KVM hypervisors. Both are absolute-frequency wall clocks that
// count through host pauses, which is exactly what a gap detector needs;
// the TSC alone is not, because tsc_per_quantum is a CALIBRATED figure a
// stall can corrupt (apic.tscPerQuantumSane). The ruler is latched once,
// at the first BSP tick (kvm.initPerCpuPv runs before apic.init starts
// IRQ0), and never switches: tickOverdue() reads the baseline cross-CPU,
// and a ruler that changes under it would pair a baseline from one clock
// with a reading from the other. benchRulers() prints both read costs at
// boot — "[smi] ruler read cost".

const acpi = @import("../acpi/acpi.zig");
const apic = @import("apic.zig");
const debug = @import("../debug/debug.zig");
const io = @import("../io.zig");
const exectrail = @import("../debug/exectrail.zig");
const symbols = @import("../debug/symbols.zig");
const spinlock = @import("../proc/spinlock.zig");
const kvm = @import("../virt/kvm.zig");
const pause = @import("pause.zig");
const smp = @import("../cpu/smp.zig");

const PM_TMR_HZ: u64 = 3_579_545;
const QUANTUM_MS: u64 = 10;
// Threshold: anything above 15 ms between BSP IRQ0 ticks counts as a
// stall. 5 ms slop above the expected 10 ms — KVM scheduling jitter alone
// can hit 1-3 ms; SMM stalls start at 5+ ms.
const STALL_THRESHOLD_PM: u64 = 15 * PM_TMR_HZ / 1000;

/// Largest one-shot interval (in 10ms quanta) armed on the BSP since the
/// last tick() sample. Tickless idle deliberately stretches the BSP
/// one-shot (up to 10 quanta); without this the stretched gap reads as a
/// ~100ms HOST-L0 stall — steal=0, exactly the L0 signature, a fake.
/// rearmTimerForCurrent + the idle-wake shorten hook report every arm;
/// tick() raises its stall threshold by the noted stretch and resets to
/// 1 (the next arm re-notes). BSP-written like everything in this file;
/// (a) because tickOverdue() reads it cross-CPU.
var armed_quanta_max: u32 = 1;

pub fn noteArmed(quanta: u32) void {
    if (quanta > @atomicLoad(u32, &armed_quanta_max, .monotonic)) @atomicStore(u32, &armed_quanta_max, quanta, .monotonic);
}

var pm_tmr_port: u16 = 0;
var pm_tmr_mask: u32 = 0;
var initialized: bool = false;

/// Which wall clock the detector measures IRQ0 gaps on. `pm_tmr` = the
/// ACPI timer port (3.579545 MHz, 24/32-bit, wraps); `kvmclock` = the
/// BSP's pvclock record via kvm.clockNs (ns, u64, no exit). Latched by
/// latchRuler() at the first BSP tick, published before `have_baseline`;
/// never changes afterwards (see the header).
const Ruler = enum(u8) { pm_tmr, kvmclock };
/// (a) BSP-written once at latch, read cross-CPU by tickOverdue() only
/// after it has seen have_baseline (acquire) — hence always the latched
/// value there.
var ruler: Ruler = .pm_tmr;
/// Ruler ticks per second — PM_TMR_HZ or 1e9. (a) as `ruler`.
var ruler_hz: u64 = PM_TMR_HZ;
/// Ruler ticks per 10 ms quantum (= ruler_hz / 100). (a) as `ruler`.
var ruler_per_quantum: u64 = PM_TMR_HZ / 100;
/// 15 ms in ruler ticks — the base stall threshold. (a) as `ruler`.
var stall_threshold_base: u64 = STALL_THRESHOLD_PM;
/// kvmclock reads that came back null (record torn for the whole seqlock
/// bound). That tick keeps its baseline and measures nothing; the next
/// gap then spans two quanta and may log as a 20 ms HOST stall, which is
/// about what a host mid-update preempting us for ~100 µs+ amounts to.
/// BSP-only, dumped nowhere yet — a counter so the shape is visible in a
/// debugger if it ever matters.
var ruler_null_reads: u64 = 0;

/// Most-recent stall window in BSP TSC, published for perf.zig's sample
/// quarantine (a perf sample whose [start,end] overlaps this window was
/// host-pause-contaminated, regardless of its magnitude). start is derived
/// from the PM_TMR gap via tsc_per_quantum — approximate, which is fine:
/// this drives quarantine decisions, not accounting. end published LAST
/// with .release so a reader that observes it sees the matching start.
/// Published unconditionally per detected stall (NOT behind the 1/s log
/// rate-limit) — perf needs every window.
pub var stall_win_start_tsc: u64 = 0;
pub var stall_win_end_tsc: u64 = 0;

/// Ruler reading at the EXIT of the previous BSP tick (see tick()) — a
/// masked PM_TMR value or kvmclock ns, per `ruler`. (a) — BSP-written,
/// read cross-CPU by tickOverdue() after `have_baseline`.
var last_wall: u64 = 0;
/// (a) False until the first tick has stored a baseline; published with
/// .release AFTER last_wall and the latched ruler, so a cross-CPU reader
/// that sees it true sees a consistent (ruler, baseline) pair. Replaces
/// the old "last_pm == 0" sentinel: a kvmclock reading is boottime ns and
/// is never 0 in practice, but "in practice" is not a sentinel.
var have_baseline: bool = false;
var sample_count: u64 = 0;
/// KVM steal-time reading at the previous tick (ns); 0 = not sampled yet.
/// BSP-only like everything here (tick() is BSP IRQ0).
var last_steal_ns: u64 = 0;
pub var stall_events: u64 = 0;
/// Subset of stall_events with duration ≥ BIG_STALL_US — the only stalls
/// that can swallow a key-release long enough to fabricate a phantom
/// 200ms "hold" (keyboard typematic quarantine trigger). The 15-50ms
/// drizzle of nested-virt vCPU-steal slices freezes the tick clock along
/// with the input path (one-shot timer → ~1 late tick per stall), so it
/// can't manufacture phantom holds — quarantining on every drizzle event
/// starved legit auto-repeat ("hold-to-delete is slow", 2026-06-10: 84%
/// of one boot's 991 stalls were <50ms).
pub var big_stall_events: u64 = 0;
const BIG_STALL_US: u64 = 50_000;
pub var max_stall_us: u64 = 0;
var last_log_tick: u64 = 0;

pub fn init() void {
    const f = acpi.getFadt() orelse return;
    if (f.pm_tmr_blk == 0 or f.pm_tmr_len == 0) return;
    pm_tmr_port = @truncate(f.pm_tmr_blk);
    // FADT.flags bit 8 = TMR_VAL_EXT. When set, PM_TMR is 32-bit; otherwise
    // 24-bit (and bits [31:24] read zero). Wraparound is at 1.2 hr in 32-bit
    // mode and 4.6 sec in 24-bit mode — both fine for our 10 ms windows.
    const ext_32 = (f.flags & (1 << 8)) != 0;
    pm_tmr_mask = if (ext_32) 0xFFFFFFFF else 0xFFFFFF;
    initialized = true;
    debug.klog("[smi] PM_TMR detector ready: port=0x{x} {s}-bit\n", .{ pm_tmr_port, if (ext_32) "32" else "24" });
}

/// True once the PM_TMR detector is armed. spinlock.cliHoldCheck uses this
/// to decide whether tick() will drain its hold slots or it must fall back
/// to printing directly (no-FADT boards).
pub fn isActive() bool {
    return initialized;
}

/// Called from BSP IRQ0 (timer). Reads the wall ruler, computes
/// elapsed-since-last in ruler ticks, flags windows that exceeded the
/// stall threshold. Also drains spinlock's cli-hold slots every tick (see
/// flushCliHolds).
///
/// Don't call from APs — their IRQ0 is irregular (idle hlt suppresses it)
/// and would trigger constant false positives. Don't call before APIC
/// timer is calibrated and running, or the baseline is meaningless.
pub fn tick() void {
    if (!initialized) return;
    if (!@atomicLoad(bool, &have_baseline, .monotonic)) latchRuler();
    tickBody();
    // Re-baseline at EXIT, not entry: the next gap is measured from the end
    // of this handler's work, so the handler's own IF=0 body — the cli-hold
    // drain, a [lock-dump] over the serial line at 115200 baud (a 1 KB dump
    // is ~90 ms), classifyAndLog — is guest-run time in neither the stall
    // figure nor the host-pause credit. It carries no cli-hold record of
    // its own, so without this the tick after a chatty one would have read
    // it as a whole-VM pause. One extra ruler read per tick (free on
    // kvmclock; the second QEMU round trip on PM_TMR). Same vCPU
    // expression as the entry sample so the two steal baselines agree.
    // A null kvmclock read keeps the previous baseline (see
    // ruler_null_reads) rather than storing a lie.
    if (rulerNow()) |w| {
        @atomicStore(u64, &last_wall, w, .monotonic);
        @atomicStore(bool, &have_baseline, true, .release);
    } else {
        ruler_null_reads +%= 1;
    }
    last_steal_ns = kvm.stealNs(smp.myCpu().cpu_id);
}

/// First BSP tick only: pick the ruler for the life of the boot. kvmclock
/// when KVM has armed and proven the BSP's record (kvm.initPerCpuPv runs
/// before apic.init starts IRQ0, so by the first tick the answer is
/// final); PM_TMR otherwise. Logged once — the line pairs with
/// "[smi] ruler read cost" from benchRulers().
fn latchRuler() void {
    if (kvm.clockReady()) {
        ruler = .kvmclock;
        ruler_hz = 1_000_000_000;
    } else {
        ruler = .pm_tmr;
        ruler_hz = PM_TMR_HZ;
    }
    ruler_per_quantum = ruler_hz / 100;
    stall_threshold_base = 15 * ruler_hz / 1000;
    debug.klog("[smi] tick ruler: {s} ({s})\n", .{
        @tagName(ruler),
        if (ruler == .kvmclock) "BSP pvclock record in guest RAM, no exit" else "ACPI timer port, one QEMU round trip per read under KVM",
    });
}

/// One ruler reading. null only on the kvmclock ruler when the record
/// stayed torn for the whole seqlock bound (kvm.clockNs).
inline fn rulerNow() ?u64 {
    return switch (ruler) {
        .pm_tmr => @as(u64, io.inl(pm_tmr_port) & pm_tmr_mask),
        .kvmclock => kvm.clockNs(0),
    };
}

/// Ruler ticks from `prev` to `now`: wrap-safe on the masked PM_TMR,
/// saturating on kvmclock ns (a cross-CPU read of slot 0 with a TSC a
/// few cycles behind the BSP's must not wrap into 2^64).
fn rulerDelta(prev: u64, now: u64) u64 {
    return switch (ruler) {
        .pm_tmr => pmDelta(@truncate(prev), @truncate(now)),
        .kvmclock => now -| prev,
    };
}

/// Ruler ticks → microseconds. Split whole-seconds/remainder math so a
/// multi-hour gap on the ns ruler cannot overflow (delta × 1e6 would at
/// 5 h; the PM ruler never came close).
fn rulerToUs(delta: u64) u64 {
    const whole_s = delta / ruler_hz;
    const rem = delta % ruler_hz;
    return (whole_s *| 1_000_000) +| (rem * 1_000_000 / ruler_hz);
}

/// Ruler ticks → TSC cycles at `per_q` TSC per 10 ms quantum. Split
/// whole-quanta/remainder math: rem < ruler_per_quantum (≤ 1e7) times
/// per_q (≤ PER_QUANTUM_MAX 1e11) stays under 2^64; the whole-quanta
/// product saturates instead of overflowing on an absurd gap.
fn rulerToTsc(delta: u64, per_q: u64) u64 {
    const whole_q = delta / ruler_per_quantum;
    const rem = delta % ruler_per_quantum;
    return (whole_q *| per_q) +| (rem * per_q / ruler_per_quantum);
}

/// Boot diagnostic, BSP, IF=1, after kvm.initPerCpuPv: the read cost of
/// both rulers in wall TSC cycles, and which one the tick will latch.
/// Under nested Hyper-V the PM_TMR figure IS the price the tick used to
/// pay twice per 10 ms; on bare metal it is a ~1 µs chipset read and
/// kvmclock reads "absent". 128 port reads ≈ 10 ms once at boot.
pub fn benchRulers() void {
    if (!initialized) return;
    const pm_reads: u32 = 128;
    const kc_reads: u32 = 1024;
    var sink: u64 = 0;
    var i: u32 = 0;
    const kvmclock_ready = kvm.clockReady();
    const t0 = rdtsc();
    while (i < pm_reads) : (i += 1) sink +%= io.inl(pm_tmr_port);
    const t1 = rdtsc();
    if (kvmclock_ready) {
        i = 0;
        while (i < kc_reads) : (i += 1) sink +%= kvm.clockNs(0) orelse 0;
    }
    const t2 = rdtsc();
    asm volatile (""
        :
        : [s] "r" (sink),
    );
    debug.klog("[smi] ruler read cost: pm_tmr {d} cyc, kvmclock {d} cyc ({d}/{d} reads, wall); tick ruler will be {s}\n", .{
        (t1 -| t0) / pm_reads,
        if (kvmclock_ready) (t2 -| t1) / kc_reads else 0,
        pm_reads,
        kc_reads,
        if (kvmclock_ready) "kvmclock" else "pm_tmr",
    });
}

fn tickBody() void {
    sample_count +%= 1;
    if (!@atomicLoad(bool, &have_baseline, .monotonic)) return; // first sample: tick() stores the baseline on exit
    const now: u64 = rulerNow() orelse {
        ruler_null_reads +%= 1;
        return; // measure nothing on a torn kvmclock read; the baseline stands
    };
    const delta = rulerDelta(@atomicLoad(u64, &last_wall, .monotonic), now);

    // KVM steal across this tick window. Sampled EVERY tick so a stall
    // tick's delta spans exactly its gap — the ground truth that splits
    // host pauses into layers: steal covering the gap = L1 (zigvm's
    // scheduler descheduled our vCPU thread); steal ≈ 0 with a big gap =
    // L0 (Hyper-V paused all of zigvm — invisible to KVM's accounting,
    // no L1 runqueue wait ever happens). Cheap: seqlock read of a
    // guest-RAM struct, no exit. 0 on bare metal / pre-arm. Saturating:
    // a bailed-out seqlock read (kvm.stealNs) returns 0 and must read as
    // "no steal", not as a wrapped 2^64.
    const cur_steal_ns = kvm.stealNs(smp.myCpu().cpu_id);
    const steal_delta_ns = if (last_steal_ns == 0) 0 else cur_steal_ns -| last_steal_ns;

    const tsc_per_quantum = apic.tscPerQuantum();
    var now_tsc: u64 = 0;
    if (tsc_per_quantum > 0) {
        now_tsc = rdtsc();
        // Drain recorded cli-holds EVERY tick, not only on stall ticks: a
        // hold on an AP never delays BSP IRQ0, and a 5-15ms BSP hold stays
        // under the stall threshold — both must still surface.
        flushCliHolds(tsc_per_quantum);
    }

    // Threshold scales with the deliberately-armed interval: a tickless
    // BSP sleeping 10 quanta produces a 100ms gap BY DESIGN — only time
    // beyond (armed - one quantum) + slop is an anomaly. Ruler units.
    const stall_threshold = stall_threshold_base + @as(u64, armed_quanta_max - 1) * ruler_per_quantum;
    @atomicStore(u32, &armed_quanta_max, 1, .monotonic);
    if (delta < stall_threshold) return;
    // Atomic store: keyboard.pollRepeat reads this cross-CPU (desktop loop
    // may run on an AP) to quarantine typematic repeat across host pauses.
    // The plain read in the +% is fine — BSP IRQ0 is the ONLY writer, so
    // this is not a racy RMW; don't "fix" it into @atomicRmw or a lock.
    @atomicStore(u64, &stall_events, stall_events +% 1, .monotonic);
    const us = rulerToUs(delta);
    if (us >= BIG_STALL_US) {
        @atomicStore(u64, &big_stall_events, big_stall_events +% 1, .monotonic);
    }
    if (us > max_stall_us) max_stall_us = us;

    // Corroboration for cpu0's gap: did THIS cpu record a cli-hold ending
    // just before this IRQ0? A real cli-hold is recorded µs before the
    // pending IRQ0 re-fires; an unrelated stale record fails the
    // end-within-a-quantum check. Same-cpu so a peer's hold can't
    // masquerade as ours. The record also carries the freeze-vs-hold
    // verdict: a vm_frozen window must NOT be blamed OURS — its TSC delta
    // counted host freeze time, not kernel work. Computed for EVERY stall
    // tick (not only the logged ones): the host-pause credit below hangs
    // on it.
    var cli_us: u64 = 0;
    var cli_ra: u64 = 0;
    var cli_vm_frozen = false;
    if (tsc_per_quantum > 0) {
        const my_cpu: u8 = smp.myCpuId();
        var rec: spinlock.CliHoldRecord = undefined;
        if (spinlock.sampleHold(my_cpu, &rec)) |seq| {
            if (seq != 0 and now_tsc >= rec.end_tsc and (now_tsc - rec.end_tsc) < tsc_per_quantum) {
                cli_us = rec.dur_tsc * 10_000 / tsc_per_quantum; // tsc_per_quantum = TSC/10ms = TSC/10_000µs
                cli_ra = rec.ra;
                cli_vm_frozen = rec.verdict == .vm_frozen;
            }
        }
    }
    // Same rule classifyAndLog applies: a recorded hold covering ≥ half the
    // gap, with the VM alive through it, means THIS CPU was running with
    // IRQs off — the gap is our cli window, not a pause.
    const ours = cli_us != 0 and cli_us * 2 >= us and !cli_vm_frozen;

    if (tsc_per_quantum > 0) {
        // Gap in TSC ≈ delta × tsc_per_quantum / ruler ticks per quantum.
        // Publish for perf's quarantine.
        const delta_tsc = rulerToTsc(delta, tsc_per_quantum);
        @atomicStore(u64, &stall_win_start_tsc, now_tsc -% delta_tsc, .monotonic);
        @atomicStore(u64, &stall_win_end_tsc, now_tsc, .release);
        // Credit the host-pause clock with the UNACCOUNTED part of a HOST
        // gap: beyond the armed interval + slop (the threshold), beyond
        // what KVM's steal already explains (L1 — credited per-vCPU by
        // pause.stealTsc). What remains is whole-VM pause: L0, or a real
        // SMI on bare metal. An OURS gap is not credited at all: the CPU
        // was executing inside a cli window, and any pause that landed
        // INSIDE that window is the window's own waiter's to observe
        // (pause.Epoch, IF=0 jumps) — crediting it here too would count
        // the whole cli window as pause. Under-credits by the slop on
        // purpose (pause.zig, "conservative in one direction").
        //
        // On the SANE calibration only, end to end: the raw figure above
        // is fine for perf's quarantine window, but a stall-corrupted
        // calibration (up to ~200× the real rate) would inflate the gap
        // here while pause.nsToTsc — sane-gated — subtracted no steal at
        // all, and every stall tick would pour ~200× its excess into the
        // account the NVMe waits subtract with no fallback of their own.
        // No sane rate ⇒ no credit (the waits run on wall time, as before).
        const per_q_sane = apic.tscPerQuantumSane();
        if (!ours and per_q_sane != 0) {
            const gap_tsc = rulerToTsc(delta, per_q_sane);
            const threshold_tsc = rulerToTsc(stall_threshold, per_q_sane);
            const l0_tsc = gap_tsc -| threshold_tsc -| pause.nsToTsc(steal_delta_ns);
            if (l0_tsc != 0) pause.creditL0(l0_tsc);
        }
    }
    // Rate limit: log at most once per second (every 100 BSP IRQ0s).
    if (sample_count - last_log_tick < 100) return;
    last_log_tick = sample_count;

    if (tsc_per_quantum > 0) {
        // Lock-attribution: any lock CURRENTLY held >5ms (half the 10ms
        // LAPIC quantum) — catches a PEER cpu still sitting on one
        // (orthogonal to cpu0's own gap, corroborated above). One
        // [smi-cause] line per lock, ABOVE the classifier verdict.
        spinlock.dumpHeldLocksOlderThan(now_tsc, tsc_per_quantum / 2);
    }

    // prev_rip (in classifyAndLog) = what cpu0 was doing at the PREVIOUS
    // IRQ0 boundary (exectrail head-1; handleIRQ0 calls smi.tick() BEFORE
    // exectrail.recordIrq()). The verdict is decided by cli_us — an ACTUAL
    // recorded cli-hold — not guessed from prev_rip; prev_rip is only
    // context for where a host pause happened to sample us.
    classifyAndLog(us, cli_us, cli_ra, cli_vm_frozen, steal_delta_ns / 1000);
}

/// Is the BSP's tick itself overdue — an IRQ0 gap in progress (or just
/// ended) that tick() has not yet measured and credited to the host-pause
/// clock? The second look for a budget that expired on an AP in the
/// microseconds between the VM resuming and the BSP's pending IRQ0
/// landing (pause.zig, "granularity"). Same threshold as tick(),
/// including the tickless stretch, so a BSP legitimately asleep for 10
/// quanta doesn't read as overdue. One ruler read per call (kvmclock: the
/// BSP's record in guest RAM with this CPU's TSC; PM_TMR: the port round
/// trip) — only on the expiry path, and Deadline bounds how long it keeps
/// asking (a grant window of at most two quanta: a credit that is coming
/// comes within microseconds of the resume).
///
/// True also while the BSP merely sits in a long IF=0 window of its own
/// (the mkfs pour holds the NVMe CQ lock for seconds) — the caller cannot
/// tell the two apart, which is why its grants are bounded. Refuses
/// (false) on the BSP with IF=0: that caller is the reason its own tick is
/// late and must not cite it as evidence — a cli'd BSP poll keeps expiring
/// on wall time, the watchdog's peer view stays its backstop. A BSP wedged
/// with IF=0 forever would make every AP wait "overdue" for its grant
/// window; that BSP is exactly what the AP's watchdog halts on.
pub fn tickOverdue() bool {
    if (!initialized) return false;
    // acquire pairs with tick()'s release: a true here means `ruler`, the
    // per-ruler constants and last_wall are the latched, published set.
    if (!@atomicLoad(bool, &have_baseline, .acquire)) return false;
    if (smp.myCpuId() == 0 and !pause.irqsEnabled()) return false;
    const prev = @atomicLoad(u64, &last_wall, .monotonic);
    const now = rulerNow() orelse return false; // torn kvmclock read: no evidence, no grant
    const armed = @atomicLoad(u32, &armed_quanta_max, .monotonic);
    const threshold = stall_threshold_base + @as(u64, armed - 1) * ruler_per_quantum;
    return rulerDelta(prev, now) >= threshold;
}

inline fn rdtsc() u64 {
    return asm volatile (
        \\ rdtsc
        \\ shlq $32, %%rdx
        \\ orq %%rdx, %%rax
        : [r] "={rax}" (-> u64),
        :: .{ .rdx = true });
}

/// Wraparound-safe delta on the masked PM_TMR counter. Returns the number
/// of PM ticks elapsed from `prev` to `now`. Caller already masked both
/// with `pm_tmr_mask`. PM_TMR ruler only — rulerDelta dispatches here.
fn pmDelta(prev: u32, now: u32) u64 {
    if (now >= prev) return now - prev;
    // Wrapped: distance is (mask - prev) + now + 1.
    return (@as(u64, pm_tmr_mask) - prev) + now + 1;
}

// ---------------------------------------------------------------------------
// cli-hold drain — sole printer for spinlock's per-CPU hold records.
// ---------------------------------------------------------------------------

/// Budget: at most this many [cli-hold] lines per ~1s window. A host-pause
/// storm generates one record per freeze-inside-cli; without the budget
/// that's still hundreds of lines/minute. Anything over budget (or
/// overwritten in a slot before we drained it) is counted and reported
/// once per window — the data degrades to a count, never to silence.
const HOLD_LINES_PER_WINDOW: u32 = 4;

var hold_last_seen: [spinlock.MAX_HOLD_CPUS]u32 = [_]u32{0} ** spinlock.MAX_HOLD_CPUS;
var hold_window_start_sample: u64 = 0;
var hold_printed_this_window: u32 = 0;
var hold_suppressed_this_window: u64 = 0;

fn flushCliHolds(tsc_per_quantum: u64) void {
    // ~1s window (100 BSP ticks at 10ms) — same cadence as the [smi] limiter.
    if (sample_count -% hold_window_start_sample >= 100) {
        if (hold_suppressed_this_window > 0) {
            debug.klog("[cli-hold] +{d} hold(s) suppressed ({d}/s print budget)\n", .{ hold_suppressed_this_window, HOLD_LINES_PER_WINDOW });
        }
        hold_window_start_sample = sample_count;
        hold_printed_this_window = 0;
        hold_suppressed_this_window = 0;
    }
    var cpu: usize = 0;
    while (cpu < spinlock.MAX_HOLD_CPUS) : (cpu += 1) {
        var rec: spinlock.CliHoldRecord = undefined;
        const seq = spinlock.sampleHold(cpu, &rec) orelse continue; // torn → retry next tick
        if (seq == hold_last_seen[cpu]) continue; // nothing new (incl. never-written 0)
        const missed: u32 = (seq -% hold_last_seen[cpu]) / 2 -| 1;
        hold_last_seen[cpu] = seq;
        if (hold_printed_this_window >= HOLD_LINES_PER_WINDOW) {
            hold_suppressed_this_window += @as(u64, missed) + 1;
            continue;
        }
        hold_printed_this_window += 1;
        hold_suppressed_this_window += missed;
        const us = rec.dur_tsc * 10_000 / tsc_per_quantum;
        if (symbols.resolveKernel(rec.ra)) |r| {
            debug.klog("[cli-hold] cpu{d} lock@0x{X} {d}us at {s}+0x{X}", .{ cpu, rec.lock_addr, us, r.name, r.offset });
        } else {
            debug.klog("[cli-hold] cpu{d} lock@0x{X} {d}us ra=0x{X}", .{ cpu, rec.lock_addr, us, rec.ra });
        }
        switch (rec.verdict) {
            .vm_frozen => debug.klog(" — VM SILENT thru window: host freeze, NOT a kernel hold", .{}),
            .vm_alive => debug.klog(" — VM alive (pulses={d}): genuine hold or 1-vCPU steal", .{rec.pulse_delta}),
            .unverified => {},
        }
        if (missed > 0) debug.klog(" (+{d} earlier unlogged)", .{missed});
        debug.klog("\n", .{});
        // Held-path backtrace captured at release time. vm_frozen records
        // carry none (skipped at capture — the frames would be stale
        // host-storm noise, the 2026-06-09 misattribution).
        if (rec.verdict != .vm_frozen) {
            for (rec.path, 0..) |p, i| {
                if (p == 0) continue;
                if (symbols.resolveKernel(p)) |r2| {
                    debug.klog("[cli-hold]   held-path #{d}: {s}+0x{X}\n", .{ i, r2.name, r2.offset });
                }
            }
        }
    }
}

const KERNEL_HIGH_HALF: u64 = 0xFFFF800000000000;

// Decide OURS vs HOST from cli_us — the duration of an ACTUAL cpu-local
// cli-hold that ended just before this IRQ0 (0 if none). A gap is OURS only
// when a recorded hold covers at least half of it AND the hold's window
// wasn't itself a whole-VM freeze (cli_vm_frozen). The old code guessed
// "OURS" from prev_rip alone, so every host pause that happened to sample
// schedule() — the hottest kernel code — was mislabeled "OURS at schedule";
// then the corroboration rework still mislabeled host-freezes-inside-cli as
// OURS because the TSC counts through a freeze. cli_ra is the hold's
// acquire site = the authoritative location.
fn classifyAndLog(us: u64, cli_us: u64, cli_ra: u64, cli_vm_frozen: bool, steal_us: u64) void {
    const accounted = cli_us != 0 and cli_us * 2 >= us;

    // Layer split for host verdicts, from KVM's own accounting (ground
    // truth, not a heuristic): steal covering ≥half the gap = the L1
    // zigvm scheduler descheduled our vCPU thread; steal ≈ 0 against a
    // big gap = L0 Hyper-V paused all of zigvm (KVM never sees a runqueue
    // wait, so steal stays flat — the 2026-06-12 52ms-steal-vs-307ms-stall
    // decomposition). "HOST?" when steal isn't armed (bare metal: PM_TMR
    // gaps there are real SMIs, which steal can't speak to either way).
    const steal_armed = last_steal_ns != 0;
    const host_tag: []const u8 = if (!steal_armed)
        "HOST?"
    else if (steal_us * 2 >= us)
        "HOST-L1 (zigvm steal)"
    else
        "HOST-L0 (hypervisor pause)";

    if (accounted) {
        if (cli_vm_frozen) {
            // The recorded hold covers the gap, but the whole VM was silent
            // through it (vm_alive_pulse unchanged): the host froze us
            // INSIDE the cli window. Freeze time, not kernel work.
            if (symbols.resolveKernel(cli_ra)) |r| {
                debug.klog("[smi] stall: {d}us — {s} (froze {d}us inside cli window at {s}+0x{X}; VM silent; steal={d}us) — events={d} max={d}us\n", .{ us, host_tag, cli_us, r.name, r.offset, steal_us, stall_events, max_stall_us });
            } else {
                debug.klog("[smi] stall: {d}us — {s} (froze {d}us inside cli window at ra=0x{X:0>16}; VM silent; steal={d}us) — events={d} max={d}us\n", .{ us, host_tag, cli_us, cli_ra, steal_us, stall_events, max_stall_us });
            }
            return;
        }
        // OURS — but a nonzero steal here means the hold itself was
        // stretched by L1 preemption mid-window; the printed steal lets
        // the reader subtract before blaming the acquire site.
        if (symbols.resolveKernel(cli_ra)) |r| {
            debug.klog("[smi] stall: {d}us — OURS (cli-hold {d}us at {s}+0x{X}; steal={d}us) — events={d} max={d}us\n", .{ us, cli_us, r.name, r.offset, steal_us, stall_events, max_stall_us });
        } else {
            debug.klog("[smi] stall: {d}us — OURS (cli-hold {d}us at ra=0x{X:0>16}; steal={d}us) — events={d} max={d}us\n", .{ us, cli_us, cli_ra, steal_us, stall_events, max_stall_us });
        }
        return;
    }

    // No cli-hold accounts for the gap → host pause; host_tag carries the
    // L0/L1 layer verdict. Report WHERE cpu0 was sampled (prev_rip) as
    // context, plus cli-acct (the largest hold we did see, ~0) to make
    // the "nothing actually held cli" basis explicit.
    const prev_rip_opt = exectrail.peekHeadMinusOne(0);
    if (prev_rip_opt == null) {
        debug.klog("[smi] stall: {d}us — {s} (steal={d}us cli-acct={d}us) — no trail (events={d} max={d}us)\n", .{ us, host_tag, steal_us, cli_us, stall_events, max_stall_us });
        return;
    }
    const prev_rip = prev_rip_opt.?;

    // Syscall marker (low canonical half; a real kernel RIP 0xFFFF8000.. is
    // >= MARKER_BASE but lacks the bit-47/48 pattern, hence the high bound).
    // CPU was mid-syscall when the pause began.
    if (prev_rip >= exectrail.MARKER_BASE and prev_rip < KERNEL_HIGH_HALF) {
        const sys_num = prev_rip & 0xFFFF;
        debug.klog("[smi] stall: {d}us — {s} (was in sc#{d}; steal={d}us cli-acct={d}us) — events={d} max={d}us\n", .{ us, host_tag, sys_num, steal_us, cli_us, stall_events, max_stall_us });
        return;
    }

    // User-space RIP — IRQs were unmasked, so it can't be our cli-hold → host.
    if (prev_rip < KERNEL_HIGH_HALF) {
        debug.klog("[smi] stall: {d}us — {s} (user RIP 0x{X:0>16}; steal={d}us) — events={d} max={d}us\n", .{ us, host_tag, prev_rip, steal_us, stall_events, max_stall_us });
        return;
    }

    // Kernel RIP, no cli-hold corroborated. idle/hlt = expected host wait;
    // anything else = host starvation that sampled us mid-kernel.
    if (symbols.resolveKernel(prev_rip)) |r| {
        const is_idle = std.mem.indexOf(u8, r.name, "idle") != null or
            std.mem.indexOf(u8, r.name, "Idle") != null;
        const why = if (is_idle) "kernel idle/hlt" else "vCPU pause";
        debug.klog("[smi] stall: {d}us — {s} ({s}; was at {s}+0x{X}; steal={d}us cli-acct={d}us) — events={d} max={d}us\n", .{ us, host_tag, why, r.name, r.offset, steal_us, cli_us, stall_events, max_stall_us });
    } else {
        debug.klog("[smi] stall: {d}us — {s} (kernel RIP 0x{X:0>16} unresolved; steal={d}us cli-acct={d}us) — events={d} max={d}us\n", .{ us, host_tag, prev_rip, steal_us, cli_us, stall_events, max_stall_us });
    }
}

const std = @import("std");
