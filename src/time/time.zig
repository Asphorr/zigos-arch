// Wall-clock time. Captures the RTC date/time once at boot, converts to a
// Unix-epoch second, and freezes the HPET counter at that moment. Subsequent
// queries combine the boot baseline with HPET delta for monotonic, sub-second-
// precise wall-clock readings.
//
// Why not just read RTC every call? Two reasons:
//   1. RTC reads are slow (port I/O + UIP wait — easily 100µs).
//   2. RTC granularity is one second; HPET gives nanoseconds.
//
// Why bother with Unix epoch at all? It makes timestamps directly meaningful
// to user code (e.g. `time` command, file mtimes, scheduling deadlines). The
// alternative — "seconds since boot" — is fine for relative timing but
// ambiguous when an app stores times to disk and later reads them back from
// a different boot.

const std = @import("std");
const debug = @import("../debug/debug.zig");
const perf = @import("../debug/perf.zig");
const rtc = @import("rtc.zig");
const hpet = @import("hpet.zig");
const apic = @import("apic.zig");

var boot_unix_sec: u64 = 0;
var boot_hpet_ns: u64 = 0;
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

/// Latch boot epoch baseline. Must run after hpet.init(). Idempotent — the
/// first call wins; later calls are no-ops so we don't drift.
pub fn init() void {
    if (initialized) return;
    if (!hpet.isInitialized()) {
        debug.klog("[time] HPET not initialized — wall-clock will be coarse\n", .{});
    }

    // Read RTC and HPET as close together as possible. Order: HPET first
    // (nanosecond-cheap), then RTC (slow). The skew is at most one RTC read
    // duration (~100µs) which is well below RTC's 1s granularity.
    const ns = hpet.readNanos();
    const dt = rtc.readDateTime();
    boot_hpet_ns = ns;
    boot_unix_sec = rtcToUnix(dt);
    initialized = true;

    debug.klog("[time] Boot epoch: {d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC = {d}s since 1970\n", .{
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, boot_unix_sec,
    });
}

/// Wall-clock split into (sec, usec). sec is Unix epoch; usec is microseconds
/// within the current second [0, 999999]. Falls back to seconds-since-boot if
/// HPET wasn't available — apps that need absolute time should still get a
/// monotonic answer just with an unknown offset.
/// Named rather than an anonymous return type — anonymous struct types in
/// the kernel's call graph trip the Zig 0.15.2 → LLVM 20.1.2 bitcode bug
/// ("Invalid type" / "Only named structs can be forward referenced").
pub const Time = struct { sec: u64, usec: u32 };

pub fn now() Time {
    if (!initialized) return .{ .sec = 0, .usec = 0 };
    const delta_ns = monotonicNanos();
    const delta_sec = delta_ns / 1_000_000_000;
    const remainder_ns = delta_ns % 1_000_000_000;
    return .{
        .sec = boot_unix_sec + delta_sec,
        .usec = @intCast(remainder_ns / 1_000),
    };
}

/// Monotonic nanoseconds since the boot epoch was latched. Useful for short-
/// duration timing where the absolute epoch doesn't matter (it's also the
/// reference clock for sysUsleep). Never goes back, on any CPU.
pub fn monotonicNanos() u64 {
    if (!initialized) return 0;
    const ns = tscNanos() orelse hpetNanos();
    const prev = @atomicRmw(u64, &clk_last, .Max, ns, .monotonic);
    return @max(prev, ns);
}

fn hpetNanos() u64 {
    const now_ns = hpet.readNanos();
    // HPET counter is monotonic; saturating subtract guards against the
    // unlikely case where init's reading raced and ended up slightly ahead.
    return if (now_ns > boot_hpet_ns) now_ns - boot_hpet_ns else 0;
}

// The clock runs on the TSC. An HPET read is an MMIO exit (~20 µs under
// nested virtualization), so HPET only re-anchors the TSC clock every
// ANCHOR_NS: the anchor pins (tsc, ns), and the rate is HPET time over TSC
// ticks since the first anchor, ever more exact. Re-anchoring may step the
// clock a little either way; clk_last keeps what callers see from going back
// (and covers TSCs that differ slightly between CPUs).
const ANCHOR_NS: u64 = 100_000_000;

/// Anchor, written under the seqlock clk_seq (odd while being written) by
/// whoever holds clk_busy; read lock-free.
var clk_seq: u32 = 0;
var clk_tsc: u64 = 0;
var clk_ns: u64 = 0;
/// ns per TSC tick, 32.32 fixed point. 0 = the TSC clock hasn't started.
var clk_mult: u64 = 0;
var clk_first_tsc: u64 = 0;
var clk_first_ns: u64 = 0;
var clk_busy: bool = false;
/// The highest value monotonicNanos has handed out.
var clk_last: u64 = 0;

/// Clock reading from the TSC, re-anchoring when due; null until the TSC
/// rate is known (before LAPIC timer calibration).
fn tscNanos() ?u64 {
    const t = perf.rdtsc();
    var a_tsc: u64 = undefined;
    var a_ns: u64 = undefined;
    var mult: u64 = undefined;
    while (true) {
        const s = @atomicLoad(u32, &clk_seq, .acquire);
        if (s & 1 != 0) {
            std.atomic.spinLoopHint();
            continue;
        }
        a_tsc = @atomicLoad(u64, &clk_tsc, .acquire);
        a_ns = @atomicLoad(u64, &clk_ns, .acquire);
        mult = @atomicLoad(u64, &clk_mult, .acquire);
        if (@atomicLoad(u32, &clk_seq, .acquire) == s) break;
    }
    if (mult == 0) {
        const per_q = apic.tscPerQuantumSane();
        if (per_q == 0) return null;
        // 10 ms per quantum.
        anchor((@as(u64, 10_000_000) << 32) / per_q);
        return null;
    }
    // A TSC a little behind the anchoring CPU's reads as the anchor itself.
    const dt = if (t > a_tsc) t - a_tsc else 0;
    const ns = a_ns + ticksToNs(dt, mult);
    if (ns - a_ns >= ANCHOR_NS) anchor(0);
    return ns;
}

inline fn ticksToNs(ticks: u64, mult: u64) u64 {
    return @truncate((@as(u128, ticks) * mult) >> 32);
}

/// Pin the clock to HPET now. `first_mult` starts the clock (rate from
/// the LAPIC calibration); 0 re-anchors a running one. One caller at a
/// time; the others keep reading the old anchor.
fn anchor(first_mult: u64) void {
    if (@cmpxchgStrong(bool, &clk_busy, false, true, .acquire, .monotonic) != null) return;
    defer @atomicStore(bool, &clk_busy, false, .release);
    const running = @atomicLoad(u64, &clk_mult, .acquire) != 0;
    if (!running and first_mult == 0) return;
    const ns = hpetNanos();
    const t = perf.rdtsc();
    var mult = first_mult;
    if (running) {
        mult = clk_mult;
        if (t > clk_first_tsc and ns > clk_first_ns) {
            mult = @intCast((@as(u128, ns - clk_first_ns) << 32) / (t - clk_first_tsc));
        }
    } else {
        clk_first_tsc = t;
        clk_first_ns = ns;
    }
    // IF off across the odd window: a reader in an IRQ on this CPU would
    // otherwise spin on a writer it interrupted.
    const flags = saveAndDisableIrq();
    defer restoreIrq(flags);
    _ = @atomicRmw(u32, &clk_seq, .Add, 1, .acq_rel);
    @atomicStore(u64, &clk_tsc, t, .release);
    @atomicStore(u64, &clk_ns, ns, .release);
    @atomicStore(u64, &clk_mult, mult, .release);
    _ = @atomicRmw(u32, &clk_seq, .Add, 1, .acq_rel);
}

inline fn saveAndDisableIrq() u64 {
    var flags: u64 = undefined;
    asm volatile ("pushfq; pop %[f]; cli"
        : [f] "=r" (flags),
    );
    return flags;
}

inline fn restoreIrq(flags: u64) void {
    if (flags & 0x200 != 0) asm volatile ("sti");
}

/// Wall-clock nanoseconds since the Unix epoch (now() at full precision).
pub fn realtimeNanos() u64 {
    return boot_unix_sec * 1_000_000_000 + monotonicNanos();
}
