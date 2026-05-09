// Boot-log presentation layer.
//
// Two output channels with different aesthetics:
//   - Serial: a tree-style log (▼ Phase / ├─ step [ ✓ ] / └─ phase total)
//     in full Unicode + ANSI colors. Goes to serial.log for debugging.
//   - VGA: a styled fixed-layout boot screen owned by `src/ui/boot_screen.zig`
//     with a centered logo, one row per phase with a status badge, and a
//     small ring of recent klog lines at the bottom. Driven entirely from
//     this module via boot_screen.startPhase / endPhase / setPhaseDetail.
//
// Each phase here maps to one Phase enum entry on the boot_screen. Steps
// inside a phase only show on serial; the boot_screen aggregates them
// into the phase row's status and last-detail.

const std = @import("std");
const serial = @import("serial.zig");
const boot_screen = @import("../ui/boot_screen.zig");
const apic = @import("../time/apic.zig");

pub const Phase = boot_screen.Phase;

// Timing state: TSC at boot start (set in banner) and TSC at last printed
// step (advanced on every ok/skip/warn/fail). Step-level timing reports
// "time since previous step or phase header"; the boot total in done()
// reports "time since banner". TSC rate comes from apic.tscToMs which
// returns 0 until APIC calibration completes — early steps before
// calibration silently report 0 ms (still useful: most early steps ARE
// near-zero anyway).
var boot_start_tsc: u64 = 0;
var last_step_tsc: u64 = 0;
// Phase counter + per-phase timing baseline. setTotalPhases(N) called once
// after banner() lets phase headers render an "N/total" progress bar plus
// a phase-total-ms summary printed BEFORE the next phase header (i.e. at
// the moment the previous phase logically ends).
var phase_total: u32 = 0;
var phase_idx: u32 = 0;
var phase_start_tsc: u64 = 0;

// Current phase identity + most-severe step status seen inside it. The
// boot_screen row only needs the aggregate; the per-step detail is just
// the latest okNote/warn/fail formatted message.
var current_phase: ?Phase = null;
var current_phase_status: boot_screen.Status = .ok;
var current_phase_detail: [32]u8 = undefined;
var current_phase_detail_len: u8 = 0;

inline fn captureDetail(comptime fmt: []const u8, args: anytype) void {
    if (std.fmt.bufPrint(&current_phase_detail, fmt, args)) |out| {
        current_phase_detail_len = @intCast(out.len);
    } else |_| {
        current_phase_detail_len = 0;
    }
    if (current_phase) |p| {
        boot_screen.setPhaseDetail(p, current_phase_detail[0..current_phase_detail_len]);
    }
}

inline fn promoteStatus(new_st: boot_screen.Status) void {
    // Severity order: fail > warn > skip > ok > pending. Don't downgrade.
    const severity = struct {
        fn rank(st: boot_screen.Status) u8 {
            return switch (st) {
                .pending => 0,
                .in_progress => 0,
                .ok => 1,
                .skip => 2,
                .warn => 3,
                .fail => 4,
            };
        }
    };
    if (severity.rank(new_st) > severity.rank(current_phase_status)) {
        current_phase_status = new_st;
    }
}

const Color = enum {
    none,
    cyan,
    green,
    yellow,
    red,
    gray,
    white,

    inline fn ansi(self: Color) []const u8 {
        return switch (self) {
            .none => "",
            .cyan => "\x1b[1;36m",
            .green => "\x1b[1;32m",
            .yellow => "\x1b[1;33m",
            .red => "\x1b[1;31m",
            .gray => "\x1b[90m",
            .white => "\x1b[1;37m",
        };
    }

};

inline fn s(c: Color, comptime fmt: []const u8, args: anytype) void {
    serial.print("{s}", .{c.ansi()});
    serial.print(fmt, args);
    serial.print("\x1b[0m", .{});
}

/// Identifies WHICH kernel build a given serial.log came from. Format keeps
/// build_id (hex) + human-readable UTC timestamp on a single greppable line.
/// Extracted from banner() so it ends up as its own symbol — easier to
/// verify the call actually fired by inspecting nm output.
pub noinline fn printBootId() void {
    const build_options = @import("build_options");
    const build_id: u64 = build_options.build_id;
    const epoch = std.time.epoch;
    const es = epoch.EpochSeconds{ .secs = build_id };
    const year_day = es.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = es.getDaySeconds();
    s(.gray, "[boot-id] build=0x{X:0>16} utc={d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z\n", .{
        build_id,
        year_day.year,
        @intFromEnum(month_day.month),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    });
}

/// Print the boot banner. First thing kernelMain should call. Initializes
/// the boot_screen panel on VGA (which paints its own logo card) and
/// writes a plain Unicode banner to serial.
pub fn banner() void {
    boot_start_tsc = apic.readTsc();
    last_step_tsc = boot_start_tsc;

    // Serial: Unicode double-line box. Width 51 cols inside (52 with borders).
    const blank_s = "\u{2551}" ++ (" " ** 50) ++ "\u{2551}\n";
    serial.print("\n", .{});
    s(.cyan, "  \u{2554}" ++ ("\u{2550}" ** 50) ++ "\u{2557}\n", .{});
    s(.cyan, "  " ++ blank_s, .{});
    s(.cyan, "  \u{2551}", .{});
    s(.white, "                Z i g O S   x86_64                ", .{});
    s(.cyan, "\u{2551}\n", .{});
    s(.cyan, "  " ++ blank_s, .{});
    s(.cyan, "  \u{2551}", .{});
    s(.gray, "                     booting...                   ", .{});
    s(.cyan, "\u{2551}\n", .{});
    s(.cyan, "  " ++ blank_s, .{});
    s(.cyan, "  \u{255A}" ++ ("\u{2550}" ** 50) ++ "\u{255D}\n", .{});

    // [boot-id] — single line that identifies WHICH kernel build a serial.log
    // came from. Crucial when archived logs accumulate across iterations: a
    // crash in serial-2026-05-04-103045.log might be from build A, the next
    // one from build B; without this line, the log is ambiguous. Format
    // keeps the build_id (hex) AND a human-readable UTC timestamp on the
    // same line so grep+eyeball both work.
    printBootId();

    // VGA: hand off to boot_screen — it paints the styled logo card and
    // empty phase rows. Subsequent stray vga.print calls are captured into
    // the screen's klog tail ring via vga.redirect_fn.
    boot_screen.init();
}

/// Caller declares total expected phases — enables the progress bar in each
/// phase header. Called once after banner(), before the first phase().
pub fn setTotalPhases(n: u32) void {
    phase_total = n;
}

inline fn drawProgressBar(c: u32, total: u32) void {
    if (total == 0) return;
    s(.gray, "  ", .{});
    var i: u32 = 0;
    while (i < total) : (i += 1) {
        if (i < c) {
            s(.green, "\u{25B0}", .{}); // ▰ filled bar
        } else {
            s(.gray, "\u{25B1}", .{}); // ▱ empty bar
        }
    }
    s(.gray, "  {d}/{d}\n", .{ c, total });
}

inline fn closePreviousPhase() void {
    if (current_phase) |p| {
        const ms_total = if (phase_start_tsc != 0)
            apic.tscToMs(apic.readTsc() - phase_start_tsc)
        else
            0;
        boot_screen.endPhase(p, current_phase_status, ms_total);
        current_phase = null;
    }
    if (phase_idx == 0 or phase_start_tsc == 0) return;
    const ms = apic.tscToMs(apic.readTsc() - phase_start_tsc);
    if (ms == 0) return;
    s(.gray, "  \u{2570}\u{2500} phase total: {d} ms\n", .{ms}); // ╰─
}

/// Capture step delta since `last_step_tsc` (in ms), advance the marker.
/// Returns 0 if TSC isn't calibrated yet OR if delta < 1ms — caller can
/// elide the timing tail when 0 is returned, keeping fast steps clean.
fn stepMs() u64 {
    const now = apic.readTsc();
    const delta = now - last_step_tsc;
    last_step_tsc = now;
    return apic.tscToMs(delta);
}

/// Format the trailing " 12 ms" / "  3 ms" tail, right-aligned to width 4
/// for the number. Empty string if ms == 0 (avoids noisy "0 ms" everywhere).
inline fn tail(ms: u64) void {
    if (ms == 0) {
        s(.gray, "\n", .{});
        return;
    }
    s(.gray, "  {d:>4} ms\n", .{ms});
}

/// Open a new boot phase. Closes the previous phase (prints its total ms
/// if non-trivial), advances the phase counter, draws the progress bar,
/// then prints the phase header with the caller-supplied glyph. Resets
/// the step-timing baseline so the FIRST step's "ms" reflects time spent
/// inside the phase itself.
///
/// `serial_glyph` is a Unicode character shown on serial only — VGA
/// always uses CP437 ▼ (\x1F) since most BMP glyphs aren't in CP437.
pub fn phase(p: Phase, comptime serial_glyph: []const u8, comptime name: []const u8) void {
    closePreviousPhase();
    phase_idx += 1;
    phase_start_tsc = apic.readTsc();
    last_step_tsc = phase_start_tsc;

    current_phase = p;
    current_phase_status = .ok;
    current_phase_detail_len = 0;
    boot_screen.startPhase(p);

    serial.print("\n", .{});
    drawProgressBar(phase_idx, phase_total);
    s(.cyan, serial_glyph ++ "  " ++ name ++ "\n", .{});
}

/// Step succeeded. Right-aligned check mark in green.
pub fn ok(comptime name: []const u8) void {
    s(.gray, "  \u{251C}\u{2500} ", .{}); // ├─
    s(.white, "{s:<42}", .{name});
    s(.green, "[ \u{2713} ]", .{}); // ✓
    tail(stepMs());
    promoteStatus(.ok);
}

/// Step succeeded with a short detail string (e.g. "1920x1080", "32 MB free").
/// Detail comes BEFORE the timing tail, so output reads:
///   "Physical memory manager  [ ✓ ] 99 MB free  12 ms"
/// The detail is also captured as the current phase's row detail on the
/// boot_screen panel.
pub fn okNote(comptime name: []const u8, comptime fmt: []const u8, args: anytype) void {
    s(.gray, "  \u{251C}\u{2500} ", .{});
    s(.white, "{s:<42}", .{name});
    s(.green, "[ \u{2713} ] ", .{});
    s(.gray, fmt, args);
    tail(stepMs());
    promoteStatus(.ok);
    captureDetail(fmt, args);
}

/// Step skipped — feature not present, optional. Gray dash.
pub fn skip(comptime name: []const u8, comptime fmt: []const u8, args: anytype) void {
    s(.gray, "  \u{251C}\u{2500} ", .{});
    s(.gray, "{s:<42}", .{name});
    s(.gray, "[ - ] ", .{});
    s(.gray, fmt, args);
    tail(stepMs());
    promoteStatus(.skip);
    captureDetail(fmt, args);
}

/// Step warning — succeeded but with caveat (fallback used, retry, etc.).
pub fn warn(comptime name: []const u8, comptime fmt: []const u8, args: anytype) void {
    s(.gray, "  \u{251C}\u{2500} ", .{});
    s(.white, "{s:<42}", .{name});
    s(.yellow, "[ ~ ] ", .{});
    s(.yellow, fmt, args);
    tail(stepMs());
    promoteStatus(.warn);
    captureDetail(fmt, args);
}

/// Step failed.
pub fn fail(comptime name: []const u8, comptime fmt: []const u8, args: anytype) void {
    s(.gray, "  \u{251C}\u{2500} ", .{});
    s(.white, "{s:<42}", .{name});
    s(.red, "[ \u{2717} ] ", .{}); // ✗
    s(.red, fmt, args);
    tail(stepMs());
    promoteStatus(.fail);
    captureDetail(fmt, args);
}

/// Closing summary card. Last thing kmain calls before launching the desktop.
/// Closes the final phase (prints its total ms), then prints a separator,
/// the user-supplied summary, and total boot time.
pub fn done(comptime fmt: []const u8, args: anytype) void {
    closePreviousPhase();
    const total_ms = apic.tscToMs(apic.readTsc() - boot_start_tsc);

    serial.print("\n", .{});
    s(.cyan, "  " ++ ("\u{2500}" ** 49) ++ "\n", .{}); // ─ x49
    s(.green, "  " ++ fmt ++ "\n", args);
    s(.gray, "  Boot completed in {d} ms\n", .{total_ms});

    // boot_screen's last row is .desktop — paint it as in_progress; the
    // GUI takeover that follows will replace VGA text with the framebuffer
    // before the user sees a stale "in progress" forever.
    boot_screen.startPhase(.desktop);
}
