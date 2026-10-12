// Top menu bar — glassy backdrop with the "ZigOS" wordmark on the left,
// the focused window's title next to it, a CPU/MEM mini-bar pair, and the
// HH:MM clock pinned to the right edge. One frame at the top of every
// desktop scene.

const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const rtc = @import("../../time/rtc.zig");
const layout = @import("layout.zig");
const dirty_rects = @import("dirty.zig");
const smp = @import("../../cpu/smp.zig");
const apic = @import("../../time/apic.zig");
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

/// Draw one labelled mini-bar at (x, y_top). Returns the right-edge x so
/// the caller can stack the next widget to its left.
fn drawStatBar(x: i32, y_top: i32, label: []const u8, pct: u8, atlas: *const aa_font.Atlas) i32 {
    const text_y: i32 = @divTrunc(@as(i32, MENUBAR_H) - @as(i32, atlas.line_height), 2);
    const label_w: u32 = atlas.measure(label);
    aa_font.drawText(x, text_y, label, 0x8C8C92, atlas);

    const bar_x: i32 = x + @as(i32, @intCast(label_w)) + 6;
    const bar_w: u32 = STAT_BAR_W;
    const bar_h: u32 = 6;
    const bar_y: i32 = y_top + @divTrunc(@as(i32, MENUBAR_H) - @as(i32, bar_h), 2);

    // Trough — soft inset behind the fill.
    gfx.fillRectAlpha(bar_x, bar_y, bar_w, bar_h, 0x44000000);
    gfx.fillRectAlpha(bar_x, bar_y, bar_w, 1, 0x22000000);

    const fill_w: u32 = statFill(pct);
    if (fill_w > 0) {
        const col = loadColor(pct);
        gfx.fillRectAlpha(bar_x, bar_y, fill_w, bar_h, col);
        // 1-px top highlight gives the fill a slight bevel
        gfx.fillRectAlpha(bar_x, bar_y, fill_w, 1, 0x40FFFFFF);
    }

    return bar_x + @as(i32, @intCast(bar_w));
}

/// Render the menubar. `focused_title` is the visible window's title (or
/// null if no window is focused / it isn't visible). The caller decides
/// what counts as focused so this stays free of window-state coupling.
pub fn render(focused_title: ?[]const u8) void {
    dirty_rects.add(0, 0, gfx.screen_w, MENUBAR_H);
    // Glass backdrop (blur + tint)
    gfx.blurRegion(0, 0, gfx.screen_w, MENUBAR_H, 6);
    gfx.saturateRegion(0, 0, gfx.screen_w, MENUBAR_H, 40);
    gfx.fillRectAlpha(0, 0, gfx.screen_w, MENUBAR_H, 0x381A1A1E);
    // Bottom border + top highlight
    gfx.drawHLine(0, @as(i32, MENUBAR_H) - 1, gfx.screen_w, 0x333338);
    gfx.drawHLine(0, 0, gfx.screen_w, 0x18FFFFFF);

    // SF Pro Text 16 for everything in the bar. line_height ~19, MENUBAR_H=28
    // → leave 4-5px above and below.
    const atlas = aa_font.getDefault16();
    const text_y: i32 = @divTrunc(@as(i32, MENUBAR_H) - @as(i32, atlas.line_height), 2);

    aa_font.drawText(12, text_y, "ZigOS", 0xC0C0CC, atlas);

    const zigos_w: i32 = @intCast(atlas.measure("ZigOS"));
    gfx.drawVLine(12 + zigos_w + 8, 6, MENUBAR_H - 12, 0x444448);

    if (focused_title) |title| {
        aa_font.drawText(12 + zigos_w + 18, text_y, title, 0xEEEEEE, atlas);
    }

    // Right-side widgets, laid out right-to-left: [stat bars] [sep] [clock].
    const time = rtc.readTime();
    var clock_buf: [5]u8 = undefined;
    clock_buf[0] = '0' + time.hour / 10;
    clock_buf[1] = '0' + time.hour % 10;
    clock_buf[2] = ':';
    clock_buf[3] = '0' + time.minute / 10;
    clock_buf[4] = '0' + time.minute % 10;
    const clock_w: i32 = @intCast(atlas.measure(&clock_buf));
    const clock_x: i32 = @as(i32, @intCast(gfx.screen_w)) - clock_w - 12;
    aa_font.drawText(clock_x, text_y, &clock_buf, 0xEEEEEE, atlas);

    // Stat bars: CPU on the right, MEM on the left. Refresh CPU sample, then
    // place each pair (label + bar) to the left of the clock. ~58 px wide per
    // pair (10-12 px label + 6 px gap + 36 px bar + 4 px gap to next).
    sampleCpu();
    const mp = memPct();
    shown_minute = time.minute;
    shown_cpu_fill = statFill(cpu_pct);
    shown_mem_fill = statFill(mp);
    shown_tick = process.tick_count;
    const sep_x: i32 = clock_x - 10;
    gfx.drawVLine(sep_x, 6, MENUBAR_H - 12, 0x444448);

    // Per-widget budget: ~26 px label + 6 px gap + 36 px bar = ~68 px.
    const pair_w: i32 = 70;
    const cpu_x: i32 = sep_x - 8 - pair_w;
    _ = drawStatBar(cpu_x, 0, "CPU", cpu_pct, atlas);
    const mem_x: i32 = cpu_x - 8 - pair_w;
    _ = drawStatBar(mem_x, 0, "MEM", mp, atlas);
}
