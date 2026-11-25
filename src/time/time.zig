// Kernel time: one monotonic clock, and the wall clock on top of it.
//
// The monotonic clock is the TSC, pinned now and then to the machine's
// reference clock (refclock.zig) — see the block above ANCHOR_MIN_NS. It
// does not count S3.
//
// The wall clock is the monotonic one plus an offset: the RTC, read at boot
// and again after S3, which the RTC counts and the monotonic clock does not.
// Nothing else reads the RTC — a read is port I/O and good to a second.

const std = @import("std");
const acpi = @import("../acpi/acpi.zig");
const debug = @import("../debug/debug.zig");
const perf = @import("../debug/perf.zig");
const serial = @import("../debug/serial.zig");
const rtc = @import("rtc.zig");
const refclock = @import("refclock.zig");
const apic = @import("../irq/apic.zig");

const NS_PER_S: u64 = std.time.ns_per_s;

/// The wall clock at clock 0, Unix nanoseconds. (a) moved by the S3 resume.
var wall_base_ns: u64 = 0;
/// Time spent in S3. (a)
var suspended_ns: u64 = 0;
/// The reference clock's reading at clock 0. (a) set where the TSC clock
/// starts, and by restartClock.
var ref_zero_ns: u64 = 0;
var initialized: bool = false;

/// Days from civil — converts (year, month, day) to days since 1970-01-01
/// using Howard Hinnant's algorithm. Correct for the proleptic Gregorian
/// calendar from year 1 onward; we only ever pass it RTC dates so the input
/// is always > 2000-01-01. Returns negative for pre-1970 dates (won't happen
/// in our use), so we cast to i64 to avoid underflow surprises.
fn daysFromCivil(year: u16, month: u8, day: u8) i64 {
    const y_adj: i64 = if (month <= 2) @as(i64, year) - 1 else @as(i64, year);
    const era: i64 = @divFloor(if (y_adj >= 0) y_adj else y_adj - 399, 400);
    const yoe: u64 = @intCast(y_adj - era * 400); // [0, 399]
    const m: u64 = @intCast(month);
    const d: u64 = @intCast(day);
    const doy: u64 = (153 * (if (m > 2) m - 3 else m + 9) + 2) / 5 + d - 1; // [0, 365]
    const doe: u64 = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    return era * 146097 + @as(i64, @intCast(doe)) - 719468;
}

/// Convert an RTC date+time to Unix epoch seconds.
fn rtcToUnix(dt: rtc.DateTime) u64 {
    const days = daysFromCivil(dt.year, dt.month, dt.day);
    if (days < 0) return 0;
    const secs_in_day: u64 = @as(u64, dt.hour) * 3600 + @as(u64, dt.minute) * 60 + @as(u64, dt.second);
    return @as(u64, @intCast(days)) * 86400 + secs_in_day;
}

/// What the wall clock starts from on a machine whose RTC holds no date.
const NO_RTC: rtc.DateTime = .{ .year = 2000, .month = 1, .day = 1, .hour = 0, .minute = 0, .second = 0 };

/// Start the clocks. After apic.init (the TSC's rate), hpet.init and the
/// BSP's kvmclock record (refclock.init picks among them). The first call
/// wins.
pub fn init() void {
    if (initialized) return;
    refclock.init();
    if (acpi.getFadt()) |f| rtc.setCenturyRegister(f.century);
    const read = rtc.readDateTime();
    const dt = read orelse NO_RTC;
    wall_base_ns = rtcToUnix(dt) * NS_PER_S;
    // Clock 0 is here, at the RTC reading the wall clock is counted from,
    // and the TSC clock starts now rather than at its first reader.
    @atomicStore(u64, &ref_zero_ns, refRaw() orelse 0, .monotonic);
    initialized = true;
    _ = monotonicNanos();

    const note: []const u8 = if (read == null) " — the RTC holds no date" else "";
    debug.klog("[time] Boot epoch: {d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC = {d}s since 1970{s}\n", .{
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, wall_base_ns / NS_PER_S, note,
    });
}

/// From the BSP's timer tick. The clock is read at least this often: the
/// anchoring counts on it (UNREAD_MAX_NS), and a reference counter narrower
/// than 64 bits has to be read before it wraps (refclock.maxGapNs).
pub fn tick() void {
    _ = monotonicNanos();
}

/// Wall-clock split into (sec, usec). sec is Unix epoch; usec is microseconds
/// within the current second [0, 999999].
/// Named rather than an anonymous return type — anonymous struct types in
/// the kernel's call graph trip the Zig 0.15.2 → LLVM 20.1.2 bitcode bug
/// ("Invalid type" / "Only named structs can be forward referenced").
pub const Time = struct { sec: u64, usec: u32 };

pub fn now() Time {
    if (!initialized) return .{ .sec = 0, .usec = 0 };
    const ns = realtimeNanos();
    return .{ .sec = ns / NS_PER_S, .usec = @intCast(ns % NS_PER_S / 1_000) };
}

/// Wall-clock nanoseconds since the Unix epoch (now() at full precision).
pub fn realtimeNanos() u64 {
    return @atomicLoad(u64, &wall_base_ns, .monotonic) + monotonicNanos();
}

/// Monotonic nanoseconds since the clock was started: the reference clock
/// for sleeps and timeouts. Never goes back, on any CPU; stands still
/// across S3.
pub fn monotonicNanos() u64 {
    if (!initialized) return 0;
    const ns = tscNanos() orelse refNanos() orelse 0;
    const prev = @atomicRmw(u64, &clk_last, .Max, ns, .monotonic);
    return @max(prev, ns);
}

/// The monotonic clock plus the time spent in S3.
pub fn boottimeNanos() u64 {
    return monotonicNanos() + @atomicLoad(u64, &suspended_ns, .monotonic);
}

/// When the machine was started, Unix seconds: the same before and after a
/// sleep.
pub fn bootEpochSeconds() u64 {
    return (@atomicLoad(u64, &wall_base_ns, .monotonic) -| @atomicLoad(u64, &suspended_ns, .monotonic)) / NS_PER_S;
}

/// The reference clock, raw. Interrupts off for the read (refclock.nanos).
fn refRaw() ?u64 {
    const flags = saveAndDisableIrq();
    defer restoreIrq(flags);
    return refclock.nanos();
}

/// The reference clock as a reading of this clock: from clock 0.
fn refNanos() ?u64 {
    return fromRefZero(refRaw() orelse return null);
}

inline fn fromRefZero(raw: u64) u64 {
    // Wrapping: a rebase may put the zero above the counter. A reading a
    // hair before the zero (the rebase's own race) is 0, not a wrap.
    const d = raw -% @atomicLoad(u64, &ref_zero_ns, .monotonic);
    return if (d >> 63 != 0) 0 else d;
}

// The clock runs on the TSC. Reading the reference costs: an HPET read is
// an MMIO exit — ~20 µs under nested virtualization, and for as long as the
// host's display thread holds its lock when a frame is being presented
// (tens of ms, this CPU stopped meanwhile). So the reference only re-anchors
// the TSC clock: ANCHOR_MIN_NS after the first anchor, then after as long
// as the rate has been measured over, up to ANCHOR_MAX_NS. The anchor pins
// (tsc, ns), and the rate is reference time over TSC ticks since a baseline
// anchor, ever more exact — over an interval no longer than that stretch
// the clock strays no further than one sample is off. Re-anchoring may step
// the clock a little either way; clk_last keeps what callers see from going
// back (and covers TSCs that differ slightly between CPUs).
//
// The two clocks can part by more than drift. A hypervisor that stops the
// machine — a debugger, a snapshot — stops the reference and not the TSC;
// a CPU without an invariant TSC changes its rate. The reference is right.
// To a reader this shows as the clock having gone unread (UNREAD_MAX_NS),
// and such a reading waits for an anchor: see tscNanos. At the anchor it
// shows as a step (STEP_MAX_NS) or as a rate far from the one in use, and
// the rate is measured again from a new baseline.
//
// On a machine with no reference the first anchor is the only one, and the
// rate stays the one the LAPIC timer calibration measured.
const ANCHOR_MIN_NS: u64 = 100_000_000;
const ANCHOR_MAX_NS: u64 = 10_000_000_000;
/// "Next anchor due": never.
const NEVER: u64 = std.math.maxInt(u64);
/// A sample this many times wider than the narrowest one sat through a
/// stall: the running anchor tells the time better.
const SAMPLE_WIDE: u64 = 8;
/// TSC skew between CPUs this clock rides out.
const TSC_BEHIND_MAX_NS: u64 = 1_000_000;
/// The BSP's tick reads the clock (tick()). A reading further than this
/// past the last one handed out is not passed on before an anchor; until
/// then the clock stands at that last one.
const UNREAD_MAX_NS: u64 = 2 * ANCHOR_MIN_NS;
/// Between two anchors the clocks drift by microseconds. This far apart,
/// one of them was stopped or set.
const STEP_MAX_NS: u64 = ANCHOR_MIN_NS / 4;
/// The shortest window a rate is taken over.
const RATE_WINDOW_MIN_NS: u64 = 1_000_000;

/// Anchor, written under the seqlock clk_seq (odd while being written) by
/// whoever holds clk_busy; read lock-free.
var clk_seq: u32 = 0;
var clk_tsc: u64 = 0;
var clk_ns: u64 = 0;
/// ns per TSC tick, 32.32 fixed point. 0 = the TSC clock hasn't started.
var clk_mult: u64 = 0;
/// When the next anchor is due; part of the anchor.
var clk_due_ns: u64 = 0;
/// Held with interrupts off, for an anchor's length.
var clk_busy: bool = false;
/// The highest value monotonicNanos has handed out.
var clk_last: u64 = 0;

// The holder of clk_busy's own.
/// The anchor the rate is measured from. At the rate in use it leads through
/// the last anchor taken from the reference: either it is that anchor, or
/// the rate in use was measured from it to that anchor.
var clk_base_tsc: u64 = 0;
var clk_base_ns: u64 = 0;
/// No rate has been taken from this baseline yet.
var clk_base_new: bool = false;
/// A rate far from the one in use, as the baseline before this one showed
/// it; 0 = none.
var clk_rate_seen: u64 = 0;
/// The narrowest reference sample of late, in TSC ticks.
var clk_min_width: u64 = 0;

/// Clock reading from the TSC, re-anchoring when due. null while the TSC's
/// rate is unknown (the LAPIC timer never calibrated): the reference alone
/// is the clock then.
fn tscNanos() ?u64 {
    const has_ref = refclock.which() != .none;
    // The anchor read below is one this call's anchor() found good.
    var mine = false;
    while (true) {
        const t = perf.rdtsc();
        var a_tsc: u64 = undefined;
        var a_ns: u64 = undefined;
        var mult: u64 = undefined;
        var due: u64 = undefined;
        while (true) {
            const s = @atomicLoad(u32, &clk_seq, .acquire);
            if (s & 1 != 0) {
                std.atomic.spinLoopHint();
                continue;
            }
            a_tsc = @atomicLoad(u64, &clk_tsc, .acquire);
            a_ns = @atomicLoad(u64, &clk_ns, .acquire);
            mult = @atomicLoad(u64, &clk_mult, .acquire);
            due = @atomicLoad(u64, &clk_due_ns, .acquire);
            if (@atomicLoad(u32, &clk_seq, .acquire) == s) break;
        }
        if (mult == 0) {
            const per_q = apic.tscPerQuantumSane();
            if (per_q == 0) return null;
            // 10 ms per quantum. Not started by this call: the clock stands
            // where it stood.
            if (!anchor((@as(u64, 10_000_000) << 32) / per_q)) return @atomicLoad(u64, &clk_last, .monotonic);
            mine = true;
            continue;
        }
        // A TSC a little behind the anchoring CPU's reads as the anchor
        // itself; one far behind can't run this clock.
        if (t < a_tsc and ticksToNs(a_tsc - t, mult) > TSC_BEHIND_MAX_NS) return refNanos() orelse a_ns;
        const ns = a_ns + ticksToNs(t -| a_tsc, mult);
        if (mine) return ns;
        const last = @atomicLoad(u64, &clk_last, .monotonic);
        const unread = has_ref and ns > last +| UNREAD_MAX_NS;
        if (ns < due and !unread) return ns;
        if (anchor(0)) {
            mine = true;
            continue;
        }
        // Another CPU is at the anchor, or the reference gave nothing: an
        // unread clock stands. (Stepping it here would add up, one step a
        // caller, for as long as that CPU is kept off its anchor.)
        return if (unread) last else ns;
    }
}

inline fn ticksToNs(ticks: u64, mult: u64) u64 {
    return @truncate((@as(u128, ticks) * mult) >> 32);
}

const Anchor = struct { tsc: u64, ns: u64, mult: u64 };

/// Pin the clock to the reference now. `first_mult` starts the clock (rate
/// from the LAPIC calibration); 0 re-anchors a running one. One caller at a
/// time, the others keep reading the anchor there is; interrupts off from
/// end to end, so that clk_busy is never held by a context that can be
/// preempted or parked. True: the anchor there is now was found good under
/// clk_busy, and the caller reads the clock off it.
fn anchor(first_mult: u64) bool {
    const flags = saveAndDisableIrq();
    defer restoreIrq(flags);
    if (@cmpxchgStrong(bool, &clk_busy, false, true, .acquire, .monotonic) != null) return false;
    defer @atomicStore(bool, &clk_busy, false, .release);
    const running = @atomicLoad(u64, &clk_mult, .acquire) != 0;
    // Started by another CPU since this one looked, or not there to re-anchor.
    if (running != (first_mult == 0)) return false;
    return if (running) reanchor() else start(first_mult);
}

/// The start: on from the last value handed out.
fn start(mult: u64) bool {
    const last = @atomicLoad(u64, &clk_last, .monotonic);
    var a: Anchor = .{ .tsc = perf.rdtsc(), .ns = last, .mult = mult };
    var due: u64 = NEVER;
    if (refclock.which() != .none) {
        const s = sampleRefTwice() orelse return false; // unreadable just now: the next reader starts it
        a.tsc = s.tsc;
        a.ns = fromRefZero(s.ref);
        // A reference behind what was handed out has been reset: its zero
        // moves to where the clock stands.
        if (a.ns < last) {
            @atomicStore(u64, &ref_zero_ns, s.ref -% last, .monotonic);
            a.ns = last;
        }
        clk_min_width = s.width;
        due = a.ns + ANCHOR_MIN_NS;
    }
    rebase(a.tsc, a.ns);
    clk_rate_seen = 0;
    // No reader takes a start that came late for the clock gone unread.
    _ = @atomicRmw(u64, &clk_last, .Max, a.ns, .monotonic);
    publish(a, due);
    return true;
}

fn reanchor() bool {
    const a: Anchor = .{ .tsc = clk_tsc, .ns = clk_ns, .mult = clk_mult };
    const t0 = perf.rdtsc();
    // The clock at t0, as the other CPUs read it.
    var at_t0 = a.ns + ticksToNs(t0 -| a.tsc, a.mult);
    const last = @atomicLoad(u64, &clk_last, .monotonic);
    const unread = at_t0 > last +| UNREAD_MAX_NS;
    // Anchored by another CPU since the caller looked. One more anchor
    // here, microseconds on, would have no window to take a rate over and
    // would start the baseline again for nothing.
    if (!unread and at_t0 < clk_due_ns) return true;
    if (unread) {
        // Until the reference has been read the other CPUs go on from the
        // last value handed out, at the TSC's rate.
        at_t0 = last;
        publish(.{ .tsc = t0, .ns = at_t0, .mult = a.mult }, NEVER);
    }
    const s = sampleRefTwice() orelse {
        // Unreadable just now: the anchor stands, look again soon.
        publish(null, at_t0 + ANCHOR_MIN_NS);
        return false;
    };
    if (s.width < clk_min_width) clk_min_width = s.width;
    if (s.width > clk_min_width *| SAMPLE_WIDE) {
        // Both samples sat through a stall: the anchor stands, look again
        // soon. What counts as wide gives a little, so that a reference
        // grown slower for good is believed in the end.
        clk_min_width += clk_min_width / 8 + 1;
        publish(null, at_t0 + ticksToNs(perf.rdtsc() -| t0, a.mult) + ANCHOR_MIN_NS);
        return false;
    }

    const ns = fromRefZero(s.ref);
    // Where the clock would have been at the sample, going by the last
    // anchor the reference gave: the baseline at the rate in use leads
    // through it. The published anchor may be one laid without the
    // reference (above), and the step is not measured from that.
    const was = clk_base_ns + ticksToNs(s.tsc -| clk_base_tsc, a.mult);
    const step = if (ns > was) ns - was else was - ns;
    const steady = clk_base_new or step <= STEP_MAX_NS;
    const rate = rateSince(s.tsc, ns);
    const take = if (rate) |r|
        (steady and near(r, a.mult, 8)) or (clk_base_new and near(r, clk_rate_seen, 64))
    else
        false;
    var mult = a.mult;
    var next = ANCHOR_MIN_NS;
    if (take) {
        mult = rate.?;
        next = std.math.clamp(ns - clk_base_ns, ANCHOR_MIN_NS, @max(ANCHOR_MIN_NS, @min(ANCHOR_MAX_NS, refclock.maxGapNs())));
        clk_base_new = false;
        clk_rate_seen = 0;
    } else {
        // A clock was stopped or set inside the window, or the rate in use
        // is far off. The rate is measured again from here; one far from
        // the rate in use is taken when two baselines running show it — a
        // stop does not come out the same twice.
        clk_rate_seen = if (clk_base_new) rate orelse 0 else 0;
        rebase(s.tsc, ns);
    }
    // No reader takes the step this anchor makes for the clock gone unread.
    _ = @atomicRmw(u64, &clk_last, .Max, ns, .monotonic);
    publish(.{ .tsc = s.tsc, .ns = ns, .mult = mult }, ns + next);
    return true;
}

fn rebase(tsc: u64, ns: u64) void {
    clk_base_tsc = tsc;
    clk_base_ns = ns;
    clk_base_new = true;
}

/// ns per TSC tick (32.32) from the baseline to this sample; null over a
/// window too short to tell.
fn rateSince(tsc: u64, ns: u64) ?u64 {
    if (tsc <= clk_base_tsc or ns < clk_base_ns +| RATE_WINDOW_MIN_NS) return null;
    const r = (@as(u128, ns - clk_base_ns) << 32) / (tsc - clk_base_tsc);
    return if (r == 0) null else std.math.cast(u64, r);
}

/// `a` is within 1/`part` of `b`.
inline fn near(a: u64, b: u64, part: u64) bool {
    return (if (a > b) a - b else b - a) <= b / part;
}

/// Write the anchor and when the next one is due; `a` null leaves the
/// anchor as it is. Holder of clk_busy only.
fn publish(a: ?Anchor, due: u64) void {
    // IF off across the odd window: a reader in an IRQ on this CPU would
    // otherwise spin on a writer it interrupted.
    const flags = saveAndDisableIrq();
    defer restoreIrq(flags);
    _ = @atomicRmw(u32, &clk_seq, .Add, 1, .acq_rel);
    if (a) |v| {
        @atomicStore(u64, &clk_tsc, v.tsc, .release);
        @atomicStore(u64, &clk_ns, v.ns, .release);
        @atomicStore(u64, &clk_mult, v.mult, .release);
    }
    @atomicStore(u64, &clk_due_ns, due, .release);
    _ = @atomicRmw(u32, &clk_seq, .Add, 1, .acq_rel);
}

/// A reference reading and the TSC at it.
const Sample = struct {
    tsc: u64,
    /// The reference, raw.
    ref: u64,
    /// The TSC pair around the read was this far apart.
    width: u64,
};

/// The reference and the TSC at its read (the midpoint of a TSC pair around
/// it, IRQs off).
fn sampleRef() ?Sample {
    const flags = saveAndDisableIrq();
    defer restoreIrq(flags);
    const t0 = perf.rdtsc();
    const ref = refclock.nanos() orelse return null;
    const t1 = perf.rdtsc();
    const width = t1 -% t0;
    return .{ .tsc = t0 +% width / 2, .ref = ref, .width = width };
}

/// The better of two samples: an IRQ or a host stall inside one widens it.
fn sampleRefTwice() ?Sample {
    const a = sampleRef() orelse return sampleRef();
    const b = sampleRef() orelse return a;
    return if (b.width < a.width) b else a;
}

/// After S3, on the BSP alone with IRQs off. The clock starts over from the
/// reference, going on from the last value handed out: S3 reset the TSCs
/// and may have reset the reference. The wall clock takes the sleep from
/// the RTC.
pub fn restartClock() void {
    if (!initialized) return;
    refclock.afterS3();
    const last = @atomicLoad(u64, &clk_last, .monotonic);
    // The reference's zero moves to where the clock stands: a reference
    // that counted the sleep does not carry it into this clock.
    if (refclock.nanos()) |raw| @atomicStore(u64, &ref_zero_ns, raw -% last, .monotonic);
    @atomicStore(u32, &clk_seq, 0, .release);
    @atomicStore(u64, &clk_mult, 0, .release);
    @atomicStore(bool, &clk_busy, false, .release);
    _ = monotonicNanos(); // started here, not at its first reader

    // The RTC counts in whole seconds, the same ones the boot reading was
    // in: a sleep shorter than the clock's sub-second part does not show,
    // and the wall clock never steps back. An RTC that holds no date now
    // says nothing about the sleep.
    const rtc_ns = rtcToUnix(rtc.readDateTime() orelse return) * NS_PER_S;
    const was = wall_base_ns + last;
    if (rtc_ns <= was) return;
    const slept = rtc_ns - was;
    @atomicStore(u64, &wall_base_ns, wall_base_ns + slept, .monotonic);
    @atomicStore(u64, &suspended_ns, suspended_ns + slept, .monotonic);
    serial.print("[time] resumed: {d} s asleep by the RTC, wall clock moved on\n", .{slept / NS_PER_S});
}

inline fn saveAndDisableIrq() u64 {
    var flags: u64 = undefined;
    asm volatile ("pushfq; pop %[f]; cli"
        : [f] "=r" (flags),
        :
        : .{ .memory = true });
    return flags;
}

inline fn restoreIrq(flags: u64) void {
    if (flags & 0x200 != 0) asm volatile ("sti" ::: .{ .memory = true });
}

// --- Local time ---

/// Local time is UTC plus this many minutes, east positive. Set from
/// /etc/zigos.conf and the Settings app; there is no DST.
var utc_offset_min: i32 = 0;

pub const UTC_OFFSET_MIN: i32 = -12 * 60;
pub const UTC_OFFSET_MAX: i32 = 14 * 60;

pub fn utcOffsetMinutes() i32 {
    return @atomicLoad(i32, &utc_offset_min, .monotonic);
}

/// False, with nothing changed, for an offset no zone has.
pub fn setUtcOffsetMinutes(minutes: i32) bool {
    if (minutes < UTC_OFFSET_MIN or minutes > UTC_OFFSET_MAX) return false;
    @atomicStore(i32, &utc_offset_min, minutes, .monotonic);
    return true;
}

/// The wall clock as a calendar date and time of day, in local time.
pub fn localNow() rtc.DateTime {
    const local: i64 = @as(i64, @intCast(now().sec)) + @as(i64, utcOffsetMinutes()) * 60;
    var dt = civilFromDays(@divFloor(local, 86400));
    const tod: u32 = @intCast(@mod(local, 86400));
    dt.hour = @intCast(tod / 3600);
    dt.minute = @intCast(tod % 3600 / 60);
    dt.second = @intCast(tod % 60);
    return dt;
}

/// Inverse of daysFromCivil (same algorithm family); sets the date fields only.
fn civilFromDays(days: i64) rtc.DateTime {
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe: u64 = @intCast(z - era * 146097); // [0, 146096]
    const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    const doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    const mp = (5 * doy + 2) / 153; // [0, 11]
    const day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    const month = if (mp < 10) mp + 3 else mp - 9; // [1, 12]
    const year = @as(i64, @intCast(yoe)) + era * 400 + @intFromBool(month <= 2);
    return .{
        .year = @intCast(year),
        .month = @intCast(month),
        .day = @intCast(day),
        .hour = 0,
        .minute = 0,
        .second = 0,
    };
}

comptime {
    // The two calendar conversions undo each other, leap day included.
    const a = std.debug.assert;
    for ([_][3]u16{ .{ 1970, 1, 1 }, .{ 2000, 2, 29 }, .{ 2026, 11, 25 }, .{ 2100, 3, 1 } }) |d| {
        const back = civilFromDays(daysFromCivil(d[0], @intCast(d[1]), @intCast(d[2])));
        a(back.year == d[0] and back.month == d[1] and back.day == d[2]);
    }
    a(daysFromCivil(1970, 1, 1) == 0);
    a(rtcToUnix(.{ .year = 2026, .month = 11, .day = 25, .hour = 8, .minute = 13, .second = 51 }) == 1795594431);
}
