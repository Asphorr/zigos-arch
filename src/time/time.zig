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

const debug = @import("../debug/debug.zig");
const rtc = @import("rtc.zig");
const hpet = @import("hpet.zig");

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
pub fn now() struct { sec: u64, usec: u32 } {
    if (!initialized) return .{ .sec = 0, .usec = 0 };
    const now_ns = hpet.readNanos();
    // HPET counter is monotonic; saturating subtract guards against the
    // unlikely case where init's reading raced and ended up slightly ahead.
    const delta_ns = if (now_ns > boot_hpet_ns) now_ns - boot_hpet_ns else 0;
    const delta_sec = delta_ns / 1_000_000_000;
    const remainder_ns = delta_ns % 1_000_000_000;
    return .{
        .sec = boot_unix_sec + delta_sec,
        .usec = @intCast(remainder_ns / 1_000),
    };
}

/// Monotonic nanoseconds since the boot epoch was latched. Useful for short-
/// duration timing where the absolute epoch doesn't matter (it's also the
/// reference clock for sysUsleep — one less indirection than going through
/// HPET directly).
pub fn monotonicNanos() u64 {
    if (!initialized) return 0;
    const now_ns = hpet.readNanos();
    return if (now_ns > boot_hpet_ns) now_ns - boot_hpet_ns else 0;
}
