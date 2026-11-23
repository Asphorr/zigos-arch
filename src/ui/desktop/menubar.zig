// Top menu bar — glassy backdrop with the "ZigOS" wordmark on the left,
// the focused window's title next to it, a CPU/MEM mini-bar pair, and the
// HH:MM clock pinned to the right edge. One frame at the top of every
// desktop scene.

const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const rtc = @import("../../time/rtc.zig");
const time = @import("../../time/time.zig");
const layout = @import("layout.zig");
const dirty_rects = @import("dirty.zig");
const smp = @import("../../cpu/smp.zig");
const apic = @import("../../irq/apic.zig");
const pmm = @import("../../mm/pmm.zig");
const process = @import("../../proc/process.zig");

const MENUBAR_H = layout.MENUBAR_H;

// CPU sampling state. We average activity over a small sliding window so
// the bar doesn't twitch every frame. The sample window is ~50 timer ticks
// (≈0.5s @ 100Hz) — long enough to be readable, short enough to feel live.
var prev_tsc: u64 = 0;
var prev_idle_cyc: u64 = 0;
var prev_cpus: u64 = 0;
var cpu_pct: u8 = 0;
var last_sample_tick: u64 = 0;

fn sampleCpu() void {
    const now = process.tick_count;
    // Refresh at most every 50 ticks. Returning early keeps the displayed
    // value stable between samples rather than dropping to 0 on idle frames.
    if (now -% last_sample_tick < 50) return;
    last_sample_tick = now;

    const tsc = apic.readTsc();
    var idle: u64 = 0;
    var cpus: u64 = 0;
    for (&smp.cpus) |*c| {
        if (!c.alive) continue;
        idle +%= smp.idleCycles(c, tsc);
        cpus += 1;
    }
    // A CPU coming online, or the TSC restarting across S3, voids the window.
    const valid = prev_tsc != 0 and tsc > prev_tsc and cpus == prev_cpus;
    const span = if (valid) (tsc - prev_tsc) * cpus else 0;
    const d_idle = idle -% prev_idle_cyc;
    prev_tsc = tsc;
    prev_idle_cyc = idle;
    prev_cpus = cpus;
    if (span < 100) return;
    const busy: u64 = if (d_idle >= span) 0 else span - d_idle;
    cpu_pct = @intCast(@min(100, busy / (span / 100)));
}

fn memPct() u8 {
    const total = pmm.managedFrameCount();
    if (total == 0) return 0;
    const free = pmm.freeFrameCount();
    const used: u32 = if (free >= total) 0 else total - free;
    return @intCast((@as(u64, used) * 100) / @as(u64, total));
}

/// Color for a load bar at percentage `pct`. Green <60, amber 60..85,
/// red ≥85 — same thresholds as macOS Stats / iStat menus.
fn loadColor(pct: u8) u32 {
    if (pct >= 85) return 0xFFEF4444; // red
    if (pct >= 60) return 0xFFEABA38; // amber
    return 0xFF55C95E; // green
}

const STAT_BAR_W: u32 = 36;

fn statFill(pct: u8) u32 {
    return (@as(u32, pct) * STAT_BAR_W) / 100;
}

// What the last render() showed, and when, for stale().
var shown_minute: u8 = 0xFF;
var shown_cpu_fill: u32 = 0;
var shown_mem_fill: u32 = 0;
var shown_tick: u64 = 0;
var last_stale_check: u64 = 0;

/// Ticks a stat bar may lag its value. A repaint costs the whole bar's
/// blur (hundreds of ms under TCG), so the bars don't chase the CPU load.
const STAT_REFRESH_TICKS: u64 = 500;

/// True when the clock's minute has moved since the last render(), or a
/// stat bar's fill has and the bar is STAT_REFRESH_TICKS old; the desktop
/// then repaints the bar. Checks at most once a second (the clock read is
/// port I/O).
pub fn stale() bool {
    const now = process.tick_count;
    if (now -% last_stale_check < 100) return false;
    last_stale_check = now;
    if (rtc.readTime().minute != shown_minute) return true;
    if (now -% shown_tick < STAT_REFRESH_TICKS) return false;
    sampleCpu();
    return statFill(cpu_pct) != shown_cpu_fill or statFill(memPct()) != shown_mem_fill;
}

const STAT_BAR_H: u32 = 5;
const STAT_LABEL_GAP: u32 = 6;

fn statPairWidth(label: []const u8, atlas: *const aa_font.Atlas) u32 {
    return atlas.measure(label) + STAT_LABEL_GAP + STAT_BAR_W;
}

/// Draw one labelled mini-bar with its left edge at `x`.
fn drawStatBar(x: i32, label: []const u8, pct: u8, atlas: *const aa_font.Atlas) void {
    const text_y: i32 = @divTrunc(@as(i32, MENUBAR_H) - @as(i32, atlas.line_height), 2);
    aa_font.drawText(x, text_y, label, 0xA0A0A8, atlas);

    const bar_x: i32 = x + @as(i32, @intCast(atlas.measure(label) + STAT_LABEL_GAP));
    const bar_y: i32 = @divTrunc(@as(i32, MENUBAR_H) - @as(i32, STAT_BAR_H), 2) + 1;

    gfx.fillRoundedRectAlpha(bar_x, bar_y, STAT_BAR_W, STAT_BAR_H, 2, 0x50000000);
    const fill_w: u32 = statFill(pct);
    if (fill_w > 0) gfx.fillRoundedRectAlpha(bar_x, bar_y, @max(fill_w, 3), STAT_BAR_H, 2, loadColor(pct));
}

const weekdays = [7][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const months = [12][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/// Day of the week, 0 = Sunday (Sakamoto's method; Gregorian dates).
fn weekday(year: u32, month: u32, day: u32) u32 {
    const t = [12]u32{ 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
    const y = if (month < 3) year - 1 else year;
    return (y + y / 4 - y / 100 + y / 400 + t[month - 1] + day) % 7;
}

/// "Sun 15 Nov  11:33" into `buf`; returns the length written.
fn formatClock(buf: *[20]u8, dt: rtc.DateTime) usize {
    var n: usize = 0;
    // A clock that was never set can read month 0 or day 0: show the time alone.
    if (dt.month >= 1 and dt.month <= 12 and dt.day >= 1 and dt.day <= 31 and dt.year >= 1) {
        @memcpy(buf[n..][0..3], weekdays[weekday(dt.year, dt.month, dt.day)]);
        n += 3;
        buf[n] = ' ';
        n += 1;
        if (dt.day >= 10) {
            buf[n] = '0' + dt.day / 10;
            n += 1;
        }
        buf[n] = '0' + dt.day % 10;
        n += 1;
        buf[n] = ' ';
        n += 1;
        @memcpy(buf[n..][0..3], months[dt.month - 1]);
        n += 3;
        buf[n] = ' ';
        buf[n + 1] = ' ';
        n += 2;
    }
    buf[n] = '0' + dt.hour / 10;
    buf[n + 1] = '0' + dt.hour % 10;
    buf[n + 2] = ':';
    buf[n + 3] = '0' + dt.minute / 10;
    buf[n + 4] = '0' + dt.minute % 10;
    return n + 5;
}

/// Render the menubar. `focused_title` is the visible window's title (or
/// null if no window is focused / it isn't visible). The caller decides
/// what counts as focused so this stays free of window-state coupling.
pub fn render(focused_title: ?[]const u8) void {
    dirty_rects.add(0, 0, gfx.screen_w, MENUBAR_H);
    // Glass backdrop (blur + tint) over a dark hairline at the bottom edge.
    gfx.blurRegion(0, 0, gfx.screen_w, MENUBAR_H, 6);
    gfx.saturateRegion(0, 0, gfx.screen_w, MENUBAR_H, 40);
    gfx.fillRectAlpha(0, 0, gfx.screen_w, MENUBAR_H, 0x4A18181C);
    gfx.fillRectAlpha(0, @as(i32, MENUBAR_H) - 1, gfx.screen_w, 1, 0x38000000);

    // SF Pro Text 13 throughout: the wordmark semibold, the rest regular.
    const atlas = aa_font.getDefault13();
    const bold = aa_font.getDefault13Semibold();
    const text_y: i32 = @divTrunc(@as(i32, MENUBAR_H) - @as(i32, atlas.line_height), 2);

    aa_font.drawText(14, text_y, "ZigOS", 0xFFFFFF, bold);
    if (focused_title) |title| {
        const title_x: i32 = 14 + @as(i32, @intCast(bold.measure("ZigOS"))) + 16;
        aa_font.drawText(title_x, text_y, title, 0xE4E4E8, atlas);
    }

    // Right-side widgets, laid out right-to-left: [MEM] [CPU] [date + clock].
    const utc = rtc.readDateTime();
    const dt = time.toLocal(utc);
    var clock_buf: [20]u8 = undefined;
    const clock = clock_buf[0..formatClock(&clock_buf, dt)];
    const clock_x: i32 = @as(i32, @intCast(gfx.screen_w)) - @as(i32, @intCast(atlas.measure(clock))) - 14;
    aa_font.drawText(clock_x, text_y, clock, 0xF2F2F4, atlas);

    sampleCpu();
    const mp = memPct();
    // The RTC's minute, which is what stale() compares against.
    shown_minute = utc.minute;
    shown_cpu_fill = statFill(cpu_pct);
    shown_mem_fill = statFill(mp);
    shown_tick = process.tick_count;

    const cpu_x: i32 = clock_x - 18 - @as(i32, @intCast(statPairWidth("CPU", atlas)));
    drawStatBar(cpu_x, "CPU", cpu_pct, atlas);
    const mem_x: i32 = cpu_x - 14 - @as(i32, @intCast(statPairWidth("MEM", atlas)));
    drawStatBar(mem_x, "MEM", mp, atlas);
}
