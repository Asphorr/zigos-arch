// Styled boot screen — graphical (preferred) or VGA text-mode fallback.
//
// Graphical mode uses gfx primitives + a hand-laid pixel-art ZIGOS logo
// composed of axis-aligned rectangles (no font scaling tricks — each
// letter is a deliberate mini-typeface). VGA text mode is the brief
// initial-render path on Multiboot before virtio-gpu comes up at the
// end of Phase 2; serial.log gets the full boot tree from boot_log.zig
// either way.
//
// State machine:
//   1. boot_screen.init()              — first call from blog.banner().
//      If gfx.screen_w != 0 (UEFI's GOP path), goes straight to graphical;
//      otherwise renders the VGA text panel.
//   2. boot_screen.upgradeToGraphical() — Multiboot's mid-Phase-2 transition,
//      called by kernelMain after early_fb.tryVirtioGpu succeeds. Re-renders
//      the same accumulated state (rows[].status / detail / ms) into gfx.
//   3. boot_screen.holdMinimum(ms)     — busy-wait until `ms` have elapsed
//      since init. Lets the user see the finished panel before desktop
//      takes over the framebuffer.
//   4. boot_screen.disable()           — desktop calls this in taskEntry
//      before its own virtio-gpu setup; restores vga.redirect_fn.

const std = @import("std");
const vga = @import("vga.zig");
const gfx = @import("gfx.zig");
const apic = @import("../time/apic.zig");

pub const Phase = enum(u8) {
    cpu = 0,
    memory = 1,
    time_smp = 2,
    storage = 3,
    lockdown = 4,
    hardware = 5,
    desktop = 6,
};

const PHASE_COUNT: u8 = 7;

const phase_names: [PHASE_COUNT][]const u8 = .{
    "CPU bring-up",
    "Memory & paging",
    "Time & SMP",
    "Storage",
    "Lockdown",
    "Hardware probe",
    "Desktop",
};

pub const Status = enum(u8) {
    pending,
    in_progress,
    ok,
    warn,
    fail,
    skip,
};

const PhaseRow = struct {
    label: []const u8,
    detail: [40]u8 = [_]u8{0} ** 40,
    detail_len: u8 = 0,
    status: Status = .pending,
    ms: u64 = 0,
};

var rows: [PHASE_COUNT]PhaseRow = undefined;
var current_phase: ?Phase = null;

const KLOG_LINES: u8 = 4;
const KLOG_WIDTH: u8 = 120;
var klog_ring: [KLOG_LINES][KLOG_WIDTH]u8 = undefined;
var klog_lens: [KLOG_LINES]u8 = .{0} ** KLOG_LINES;
var klog_head: u8 = 0;
var klog_buf: [KLOG_WIDTH]u8 = undefined;
var klog_buf_len: u8 = 0;

var enabled: bool = false;
var graphical: bool = false;
var prev_redirect_fn: ?*const fn (u8) void = null;
var boot_start_tsc: u64 = 0;

// ===========================================================================
// Theme
// ===========================================================================

// Vertical gradient — subtle "lit from below" navy.
const BG_TOP: u32 = 0x080C14;
const BG_BOTTOM: u32 = 0x141A26;

// Logo accents (LOGO_FG itself is defined alongside the letter rects).
const ACCENT: u32 = 0x35C5E5; // teal-cyan
const ACCENT_DIM: u32 = 0x1B5566;

// Text.
const FG_SUBTITLE: u32 = 0x7A8694;
const FG_LABEL_LIVE: u32 = 0xE0E5EC;
const FG_LABEL_DIM: u32 = 0x6E7B8C;
const FG_DETAIL: u32 = 0x9FA9B8;
const FG_TIMING: u32 = 0x4E5A6C;
const FG_RULE: u32 = 0x2A3340;
const FG_KLOG: u32 = 0x6E7B8C;
const FG_ELAPSED: u32 = 0x4E5A6C;

// Status badges.
const BADGE_OK_FG: u32 = 0x7FE08A;
const BADGE_OK_BG: u32 = 0x14281C;
const BADGE_WARN_FG: u32 = 0xFFC56C;
const BADGE_WARN_BG: u32 = 0x2A2410;
const BADGE_FAIL_FG: u32 = 0xFF7070;
const BADGE_FAIL_BG: u32 = 0x2C1414;
const BADGE_SKIP_FG: u32 = 0x6E7B8C;
const BADGE_SKIP_BG: u32 = 0x161B22;
const BADGE_PROG_FG: u32 = 0xFFD080;
const BADGE_PROG_BG: u32 = 0x2A2010;
const BADGE_PEND_FG: u32 = 0x3A4250;
const BADGE_PEND_BG: u32 = 0x10141C;

// ===========================================================================
// Pixel-art ZIGOS logo
// ===========================================================================
//
// Each letter is a list of {dx, dy, w, h} rectangles relative to its own
// top-left. Letter heights are 96 px; widths vary (60 for Z/G/O/S, 38 for I).
// Stroke width is 10 px. Below the logo: a cyan accent bar with a small
// chevron in the centre.
//
// The letters render through fillRectBayer, which uses a 4×4 ordered
// dither matrix to draw a fraction of each rect's pixels. fill_progress
// picks how many — 0 means "no pixels" (invisible), 16 means "every pixel"
// (solid). The boot animation walks fill_progress from 0 to 16 so the
// letters appear to materialise from a halftone print.

const Rect = struct { dx: i32, dy: i32, w: u32, h: u32 };

const LOGO_H: u32 = 96;
const LETTER_GAP: u32 = 16;
const LETTER_W_WIDE: u32 = 60;
const LETTER_W_I: u32 = 38;

const LOGO_FG: u32 = 0xF0F4F8;

const Z_RECTS = [_]Rect{
    .{ .dx = 0, .dy = 0, .w = 60, .h = 10 }, // top bar
    .{ .dx = 45, .dy = 10, .w = 15, .h = 16 }, // diagonal stair (top)
    .{ .dx = 33, .dy = 24, .w = 15, .h = 16 },
    .{ .dx = 21, .dy = 38, .w = 15, .h = 16 },
    .{ .dx = 12, .dy = 52, .w = 15, .h = 16 },
    .{ .dx = 0, .dy = 66, .w = 15, .h = 20 }, // diagonal stair (bottom)
    .{ .dx = 0, .dy = 86, .w = 60, .h = 10 }, // bottom bar
};

const I_RECTS = [_]Rect{
    .{ .dx = 8, .dy = 0, .w = 22, .h = 8 }, // top serif
    .{ .dx = 14, .dy = 8, .w = 10, .h = 80 }, // stem
    .{ .dx = 8, .dy = 88, .w = 22, .h = 8 }, // bottom serif
};

const G_RECTS = [_]Rect{
    .{ .dx = 0, .dy = 0, .w = 60, .h = 10 }, // top
    .{ .dx = 0, .dy = 10, .w = 10, .h = 76 }, // left stem
    .{ .dx = 0, .dy = 86, .w = 60, .h = 10 }, // bottom
    .{ .dx = 50, .dy = 50, .w = 10, .h = 36 }, // right partial
    .{ .dx = 28, .dy = 50, .w = 32, .h = 10 }, // inner horizontal
};

const O_RECTS = [_]Rect{
    .{ .dx = 0, .dy = 0, .w = 60, .h = 10 }, // top
    .{ .dx = 0, .dy = 10, .w = 10, .h = 76 }, // left
    .{ .dx = 50, .dy = 10, .w = 10, .h = 76 }, // right
    .{ .dx = 0, .dy = 86, .w = 60, .h = 10 }, // bottom
};

const S_RECTS = [_]Rect{
    .{ .dx = 0, .dy = 0, .w = 60, .h = 10 }, // top
    .{ .dx = 0, .dy = 10, .w = 10, .h = 33 }, // upper-left vertical
    .{ .dx = 0, .dy = 43, .w = 60, .h = 10 }, // middle bar
    .{ .dx = 50, .dy = 53, .w = 10, .h = 33 }, // lower-right vertical
    .{ .dx = 0, .dy = 86, .w = 60, .h = 10 }, // bottom
};

const LETTERS = [_]struct { rects: []const Rect, w: u32 }{
    .{ .rects = &Z_RECTS, .w = LETTER_W_WIDE },
    .{ .rects = &I_RECTS, .w = LETTER_W_I },
    .{ .rects = &G_RECTS, .w = LETTER_W_WIDE },
    .{ .rects = &O_RECTS, .w = LETTER_W_WIDE },
    .{ .rects = &S_RECTS, .w = LETTER_W_WIDE },
};

fn logoTotalWidth() u32 {
    var w: u32 = 0;
    for (LETTERS, 0..) |l, i| {
        w += l.w;
        if (i < LETTERS.len - 1) w += LETTER_GAP;
    }
    return w;
}

// --- Fill animation -------------------------------------------------------
//
// 4×4 Bayer ordered dither matrix. For each pixel (x, y) in a rect, the
// pixel is drawn iff `BAYER[y%4][x%4] < fill_progress`. fill_progress
// ranges 0..16 — 0 hides everything, 16 fills every pixel. Levels in
// between produce a uniform halftone pattern that grows denser as the
// threshold rises.

const BAYER4: [4][4]u8 = .{
    .{ 0, 8, 2, 10 },
    .{ 12, 4, 14, 6 },
    .{ 3, 11, 1, 9 },
    .{ 15, 7, 13, 5 },
};

const FILL_FULL: u8 = 16;
var fill_progress: u8 = FILL_FULL;

fn fillRectBayer(x: i32, y: i32, w: u32, h: u32, color: u32, threshold: u8) void {
    if (threshold == 0) return;
    if (threshold >= FILL_FULL) {
        gfx.fillRect(x, y, w, h, color);
        return;
    }
    var dy: u32 = 0;
    while (dy < h) : (dy += 1) {
        const py: i32 = y + @as(i32, @intCast(dy));
        if (py < 0) continue;
        const upy: u32 = @intCast(py);
        const by: usize = upy % 4;
        var dx: u32 = 0;
        while (dx < w) : (dx += 1) {
            const px: i32 = x + @as(i32, @intCast(dx));
            if (px < 0) continue;
            const upx: u32 = @intCast(px);
            const bx: usize = upx % 4;
            if (BAYER4[by][bx] < threshold) {
                gfx.putPixel(px, py, color);
            }
        }
    }
}

fn drawLogoGfx(origin_x: i32, origin_y: i32) void {
    var cursor_x: i32 = origin_x;
    for (LETTERS) |letter| {
        for (letter.rects) |r| {
            fillRectBayer(cursor_x + r.dx, origin_y + r.dy, r.w, r.h, LOGO_FG, fill_progress);
        }
        cursor_x += @as(i32, @intCast(letter.w + LETTER_GAP));
    }

    // Accent bar + chevron — animates with the same threshold so the whole
    // mark resolves together.
    const total_w = logoTotalWidth();
    const bar_y: i32 = origin_y + @as(i32, @intCast(LOGO_H)) + 18;
    const bar_w: u32 = total_w;
    const bar_x: i32 = origin_x;
    const chevron_w: u32 = 36;
    const seg_w: u32 = (bar_w -| chevron_w) / 2;
    fillRectBayer(bar_x, bar_y, seg_w, 3, ACCENT, fill_progress);
    fillRectBayer(bar_x + @as(i32, @intCast(seg_w + chevron_w)), bar_y, seg_w, 3, ACCENT, fill_progress);
    const c_x: i32 = bar_x + @as(i32, @intCast(seg_w));
    fillRectBayer(c_x, bar_y - 4, 8, 4, ACCENT, fill_progress);
    fillRectBayer(c_x + 9, bar_y - 8, 8, 4, ACCENT, fill_progress);
    fillRectBayer(c_x + 18, bar_y - 4, 8, 4, ACCENT, fill_progress);
    fillRectBayer(c_x + 27, bar_y, 8, 4, ACCENT, fill_progress);
    fillRectBayer(c_x, bar_y + 6, 8, 4, ACCENT_DIM, fill_progress);
    fillRectBayer(c_x + 9, bar_y + 10, 8, 4, ACCENT_DIM, fill_progress);
    fillRectBayer(c_x + 18, bar_y + 6, 8, 4, ACCENT_DIM, fill_progress);
    fillRectBayer(c_x + 27, bar_y + 2, 8, 4, ACCENT_DIM, fill_progress);
}

/// Walk the fill progress from 0 to FILL_FULL, redrawing the logo (and
/// flushing the framebuffer) at each step. Bayer is monotonic — each
/// step only adds pixels — so we just keep stamping new dots on top of
/// the previous frame; no clear required.
///
/// Timing uses raw TSC delta because apic.tscToMs is not calibrated yet
/// during early boot. ~80M ticks per step ≈ 25–40 ms depending on CPU,
/// 16 steps total ≈ 400–650 ms.
fn runFillAnimation() void {
    if (!enabled or !graphical) return;
    const layout = computeLayout();
    const ticks_per_step: u64 = 80_000_000;
    var step: u8 = 1;
    while (step <= FILL_FULL) : (step += 1) {
        fill_progress = step;
        drawLogoGfx(layout.logo_x, layout.logo_y);
        flushFb();
        const start = apic.readTsc();
        while (apic.readTsc() -% start < ticks_per_step) {
            asm volatile ("pause");
        }
    }
    fill_progress = FILL_FULL;
}

// ===========================================================================
// Graphical render path
// ===========================================================================

const GfxLayout = struct {
    sw: u32,
    sh: u32,
    logo_x: i32,
    logo_y: i32,
    subtitle_y: i32,
    rows_top: i32,
    row_step: i32,
    badge_x: i32,
    label_x: i32,
    detail_x: i32,
    ms_x: i32,
    klog_top: i32,
    klog_x: i32,
    klog_w: u32,
};

fn computeLayout() GfxLayout {
    const sw = gfx.screen_w;
    const sh = gfx.screen_h;
    const logo_w = logoTotalWidth();
    const logo_x: i32 = @intCast((sw -| logo_w) / 2);
    const panel_w: u32 = 980;
    const panel_x: i32 = @intCast((sw -| panel_w) / 2);

    return .{
        .sw = sw,
        .sh = sh,
        .logo_x = logo_x,
        .logo_y = 110,
        .subtitle_y = 110 + @as(i32, @intCast(LOGO_H)) + 50,
        .rows_top = 290,
        .row_step = 38,
        .badge_x = panel_x + 60,
        .label_x = panel_x + 200,
        .detail_x = panel_x + 460,
        .ms_x = panel_x + @as(i32, @intCast(panel_w)) - 80,
        .klog_top = @as(i32, @intCast(sh)) -| 130,
        .klog_x = panel_x + 60,
        .klog_w = panel_w -| 60,
    };
}

inline fn flushFb() void {
    if (gfx.post_blit_fn) |f| f();
}

fn lerpColor(a: u32, b: u32, t_num: u32, t_den: u32) u32 {
    const ar = (a >> 16) & 0xFF;
    const ag = (a >> 8) & 0xFF;
    const ab = a & 0xFF;
    const br = (b >> 16) & 0xFF;
    const bg = (b >> 8) & 0xFF;
    const bb = b & 0xFF;
    const r = ar + ((br -% ar) * t_num) / t_den;
    const g = ag + ((bg -% ag) * t_num) / t_den;
    const bl = ab + ((bb -% ab) * t_num) / t_den;
    return ((r & 0xFF) << 16) | ((g & 0xFF) << 8) | (bl & 0xFF);
}

fn drawGradientBg(layout: GfxLayout) void {
    // Step the gradient in 4-row bands to keep this fast on virtio-gpu —
    // each fillRect issues one transfer; 270 bands at 1080 high is plenty
    // smooth and ~6× cheaper than per-row fills.
    const step: u32 = 4;
    var y: u32 = 0;
    while (y < layout.sh) : (y += step) {
        const color = lerpColor(BG_TOP, BG_BOTTOM, y, layout.sh);
        gfx.fillRect(0, @intCast(y), layout.sw, step, color);
    }
}

const GfxBadge = struct { text: []const u8, fg: u32, bg: u32 };

fn statusBadgeGfx(st: Status) GfxBadge {
    return switch (st) {
        .pending => .{ .text = "        ", .fg = BADGE_PEND_FG, .bg = BADGE_PEND_BG },
        .in_progress => .{ .text = " . . . .", .fg = BADGE_PROG_FG, .bg = BADGE_PROG_BG },
        .ok => .{ .text = "   OK   ", .fg = BADGE_OK_FG, .bg = BADGE_OK_BG },
        .warn => .{ .text = "  WARN  ", .fg = BADGE_WARN_FG, .bg = BADGE_WARN_BG },
        .fail => .{ .text = "  FAIL  ", .fg = BADGE_FAIL_FG, .bg = BADGE_FAIL_BG },
        .skip => .{ .text = "  skip  ", .fg = BADGE_SKIP_FG, .bg = BADGE_SKIP_BG },
    };
}

fn rowBgColor(layout: GfxLayout, y: i32) u32 {
    const yu: u32 = if (y < 0) 0 else @intCast(y);
    return lerpColor(BG_TOP, BG_BOTTOM, yu, layout.sh);
}

fn drawPhaseRowGfx(layout: GfxLayout, idx: usize) void {
    if (idx >= PHASE_COUNT) return;
    const r: i32 = layout.rows_top + @as(i32, @intCast(idx)) * layout.row_step;
    const row = rows[idx];

    // Wipe row strip with the background gradient color at this y so badge
    // colors don't leak when we redraw .ok over .in_progress.
    const strip_x: i32 = layout.badge_x - 12;
    const strip_w: u32 = @intCast(layout.ms_x + 80 - strip_x);
    var sy: i32 = r - 6;
    while (sy < r + 26) : (sy += 4) {
        gfx.fillRect(strip_x, sy, strip_w, 4, rowBgColor(layout, sy));
    }

    const badge = statusBadgeGfx(row.status);

    // Rounded badge: 8 chars × 9 px advance = 72 px text width + 12 px pad.
    const badge_w: u32 = 96;
    const badge_h: u32 = 24;
    gfx.fillRoundedRect(layout.badge_x, r - 2, badge_w, badge_h, 6, badge.bg);
    // Centre text inside the badge: padding (96-72)/2 = 12.
    gfx.drawString(layout.badge_x + 12, r + 3, badge.text, badge.fg, badge.bg);

    const label_fg: u32 = switch (row.status) {
        .pending, .skip => FG_LABEL_DIM,
        else => FG_LABEL_LIVE,
    };
    gfx.drawString(layout.label_x, r + 3, row.label, label_fg, 0);

    if (row.detail_len > 0) {
        gfx.drawString(layout.detail_x, r + 3, row.detail[0..row.detail_len], FG_DETAIL, 0);
    }

    if (row.ms > 0) {
        var buf: [16]u8 = undefined;
        if (std.fmt.bufPrint(&buf, "{d:>5} ms", .{row.ms})) |ms_str| {
            gfx.drawString(layout.ms_x, r + 3, ms_str, FG_TIMING, 0);
        } else |_| {}
    }
}

fn drawKlogRingGfx(layout: GfxLayout) void {
    const line_h: i32 = 18;
    // Wipe the klog area first using the bg gradient.
    var sy: i32 = layout.klog_top - 14;
    const total_h: i32 = @as(i32, @intCast(KLOG_LINES)) * line_h + 8;
    while (sy < layout.klog_top - 14 + total_h) : (sy += 4) {
        gfx.fillRect(layout.klog_x, sy, layout.klog_w, 4, rowBgColor(layout, sy));
    }
    // Hairline rule above the klog block.
    gfx.fillRect(layout.klog_x, layout.klog_top - 12, layout.klog_w, 1, FG_RULE);

    for (0..KLOG_LINES) |i| {
        const y: i32 = layout.klog_top + @as(i32, @intCast(i)) * line_h;
        const idx = (klog_head + i) % KLOG_LINES;
        const len = klog_lens[idx];
        if (len > 0) {
            gfx.drawString(layout.klog_x + 8, y, klog_ring[idx][0..len], FG_KLOG, 0);
        }
    }
}

fn drawElapsedGfx(layout: GfxLayout) void {
    const elapsed_ms = apic.tscToMs(apic.readTsc() -% boot_start_tsc);
    var buf: [32]u8 = undefined;
    if (std.fmt.bufPrint(&buf, "boot {d}.{d:0>3}s", .{ elapsed_ms / 1000, elapsed_ms % 1000 })) |s| {
        // Right-aligned in upper-right corner.
        const x: i32 = @as(i32, @intCast(layout.sw)) - @as(i32, @intCast(s.len)) * 9 - 24;
        // Wipe behind it first.
        gfx.fillRect(x - 6, 22, @intCast(s.len * 9 + 12), 18, rowBgColor(layout, 22));
        gfx.drawString(x, 24, s, FG_ELAPSED, 0);
    } else |_| {}
}

fn drawAllGfx() void {
    const layout = computeLayout();
    drawGradientBg(layout);

    drawLogoGfx(layout.logo_x, layout.logo_y);

    // Subtitle in 8x16 Spleen, centred under the accent bar.
    const sub = "long mode  -  x86_64";
    const sub_x: i32 = @intCast((layout.sw -| @as(u32, @intCast(sub.len)) * 9) / 2);
    gfx.drawString(sub_x, layout.subtitle_y, sub, FG_SUBTITLE, 0);

    for (0..PHASE_COUNT) |i| drawPhaseRowGfx(layout, i);
    drawKlogRingGfx(layout);
    drawElapsedGfx(layout);
    flushFb();
}

// ===========================================================================
// VGA text-mode render path (transitional fallback)
// ===========================================================================

inline fn putAt(r: usize, c: usize, ch: u8, fg: vga.Color, bg: vga.Color) void {
    if (r >= vga.HEIGHT or c >= vga.WIDTH) return;
    vga.MEM[r * vga.WIDTH + c] = .{ .char = ch, .fg = fg, .bg = bg };
}

inline fn writeAt(r: usize, c: usize, s: []const u8, fg: vga.Color, bg: vga.Color) void {
    var col = c;
    for (s) |ch| {
        if (col >= vga.WIDTH) break;
        putAt(r, col, ch, fg, bg);
        col += 1;
    }
}

inline fn fillRow(r: usize, ch: u8, fg: vga.Color, bg: vga.Color) void {
    for (0..vga.WIDTH) |c| putAt(r, c, ch, fg, bg);
}

fn drawLogoVga() void {
    const top: usize = 2;
    const bot: usize = 7;
    const left: usize = 16;
    const right: usize = 63;
    const fg: vga.Color = .LightCyan;
    const bg: vga.Color = .Black;
    putAt(top, left, 0xC9, fg, bg);
    putAt(top, right, 0xBB, fg, bg);
    putAt(bot, left, 0xC8, fg, bg);
    putAt(bot, right, 0xBC, fg, bg);
    var c = left + 1;
    while (c < right) : (c += 1) {
        putAt(top, c, 0xCD, fg, bg);
        putAt(bot, c, 0xCD, fg, bg);
    }
    var r = top + 1;
    while (r < bot) : (r += 1) {
        putAt(r, left, 0xBA, fg, bg);
        putAt(r, right, 0xBA, fg, bg);
        var x = left + 1;
        while (x < right) : (x += 1) putAt(r, x, ' ', .White, bg);
    }
    const title = "Z I G O S    x86_64";
    writeAt(top + 2, (left + right - title.len) / 2, title, .White, bg);
    const sub = "long mode";
    writeAt(top + 3, (left + right - sub.len) / 2, sub, .DarkGray, bg);
}

const VgaBadge = struct { text: []const u8, fg: vga.Color };
fn statusBadgeVga(st: Status) VgaBadge {
    return switch (st) {
        .pending => .{ .text = "[      ]", .fg = .DarkGray },
        .in_progress => .{ .text = "[ .... ]", .fg = .Yellow },
        .ok => .{ .text = "[  OK  ]", .fg = .LightGreen },
        .warn => .{ .text = "[ WARN ]", .fg = .Yellow },
        .fail => .{ .text = "[ FAIL ]", .fg = .LightRed },
        .skip => .{ .text = "[ skip ]", .fg = .DarkGray },
    };
}

fn drawPhaseRowVga(idx: usize) void {
    if (idx >= PHASE_COUNT) return;
    const r: usize = 10 + idx;
    fillRow(r, ' ', .LightGray, .Black);
    const row = rows[idx];
    const badge = statusBadgeVga(row.status);
    writeAt(r, 8, badge.text, badge.fg, .Black);
    const label_fg: vga.Color = switch (row.status) {
        .pending, .skip => .DarkGray,
        else => .White,
    };
    writeAt(r, 19, row.label, label_fg, .Black);
    if (row.detail_len > 0) {
        const n = @min(row.detail_len, 32);
        writeAt(r, 41, row.detail[0..n], .DarkGray, .Black);
    }
    if (row.ms > 0) {
        var buf: [12]u8 = undefined;
        if (std.fmt.bufPrint(&buf, "{d:>4} ms", .{row.ms})) |ms_str| {
            writeAt(r, 80 - ms_str.len - 1, ms_str, .DarkGray, .Black);
        } else |_| {}
    }
}

fn drawKlogRingVga() void {
    for (0..KLOG_LINES) |i| {
        const r: usize = 19 + i;
        fillRow(r, ' ', .DarkGray, .Black);
        const idx = (klog_head + i) % KLOG_LINES;
        const len = klog_lens[idx];
        if (len > 0) {
            const max: usize = @min(@as(usize, len), 72);
            writeAt(r, 4, klog_ring[idx][0..max], .DarkGray, .Black);
        }
    }
}

fn drawAllVga() void {
    if (!vga.available) return;
    for (0..vga.HEIGHT) |r| fillRow(r, ' ', .LightGray, .Black);
    drawLogoVga();
    for (0..PHASE_COUNT) |i| drawPhaseRowVga(i);
    fillRow(18, ' ', .DarkGray, .Black);
    var c: usize = 4;
    while (c < 76) : (c += 1) putAt(18, c, 0xC4, .DarkGray, .Black);
    drawKlogRingVga();
}

// ===========================================================================
// Public API
// ===========================================================================

pub fn init() void {
    boot_start_tsc = apic.readTsc();
    for (0..PHASE_COUNT) |i| {
        rows[i] = .{ .label = phase_names[i] };
    }
    klog_head = 0;
    klog_buf_len = 0;
    for (0..KLOG_LINES) |i| klog_lens[i] = 0;

    enabled = true;
    graphical = gfx.screen_w != 0 and gfx.screen_h != 0;

    if (graphical) {
        // Start with the logo invisible. drawAllGfx paints the gradient bg,
        // panel chrome, badges, etc.; then runFillAnimation walks
        // fill_progress 0→16 over ~500 ms so the letters dither in.
        fill_progress = 0;
        drawAllGfx();
        runFillAnimation();
    } else {
        drawAllVga();
    }

    prev_redirect_fn = vga.redirect_fn;
    vga.redirect_fn = appendByte;
}

/// Multiboot path: called by kernelMain after early_fb.tryVirtioGpu()
/// flips on a graphical FB mid-Phase-2. Re-renders the accumulated state
/// in graphical mode and runs the dither-in animation.
pub fn upgradeToGraphical() void {
    if (!enabled) return;
    if (graphical) return;
    if (gfx.screen_w == 0 or gfx.screen_h == 0) return;
    graphical = true;
    fill_progress = 0;
    drawAllGfx();
    runFillAnimation();
}

pub fn startPhase(p: Phase) void {
    if (!enabled) return;
    current_phase = p;
    rows[@intFromEnum(p)].status = .in_progress;
    if (graphical) {
        const layout = computeLayout();
        drawPhaseRowGfx(layout, @intFromEnum(p));
        drawElapsedGfx(layout);
        flushFb();
    } else {
        drawPhaseRowVga(@intFromEnum(p));
    }
}

pub fn endPhase(p: Phase, st: Status, ms: u64) void {
    if (!enabled) return;
    rows[@intFromEnum(p)].status = st;
    rows[@intFromEnum(p)].ms = ms;
    if (graphical) {
        const layout = computeLayout();
        drawPhaseRowGfx(layout, @intFromEnum(p));
        drawElapsedGfx(layout);
        flushFb();
    } else {
        drawPhaseRowVga(@intFromEnum(p));
    }
    if (current_phase == p) current_phase = null;
}

pub fn setPhaseDetail(p: Phase, detail: []const u8) void {
    if (!enabled) return;
    var row = &rows[@intFromEnum(p)];
    const n = @min(detail.len, row.detail.len);
    @memcpy(row.detail[0..n], detail[0..n]);
    row.detail_len = @intCast(n);
    if (graphical) {
        const layout = computeLayout();
        drawPhaseRowGfx(layout, @intFromEnum(p));
        flushFb();
    } else {
        drawPhaseRowVga(@intFromEnum(p));
    }
}

pub fn currentPhase() ?Phase {
    return current_phase;
}

pub fn appendByte(b: u8) void {
    if (!enabled) return;
    if (b == '\n' or b == '\r') {
        flushLine();
        return;
    }
    if (b < 0x20) return;
    if (klog_buf_len < KLOG_WIDTH) {
        klog_buf[klog_buf_len] = b;
        klog_buf_len += 1;
    }
}

fn flushLine() void {
    if (klog_buf_len == 0) return;
    @memcpy(klog_ring[klog_head][0..klog_buf_len], klog_buf[0..klog_buf_len]);
    klog_lens[klog_head] = klog_buf_len;
    klog_head = (klog_head + 1) % KLOG_LINES;
    klog_buf_len = 0;
    if (graphical) {
        // Update the back of the FB but DON'T flush — flushing on every
        // klog line means a virtio-gpu sendCmd (which does sti;hlt for the
        // MSI-X completion) per line, and during apic.init that briefly
        // re-enables IF mid-IOAPIC-program. Subsequent phase transitions
        // (startPhase / endPhase) flush, which picks up the klog updates
        // too — so the user still sees them, just not at per-line granularity.
        const layout = computeLayout();
        drawKlogRingGfx(layout);
        drawElapsedGfx(layout);
    } else {
        drawKlogRingVga();
    }
}

/// Busy-wait until `ms` have elapsed since boot_screen.init. Lets the user
/// see the finished panel before desktop overwrites the framebuffer.
/// Interrupts stay enabled — the timer + heartbeat fire normally during
/// the hold, and the elapsed-time counter on screen ticks up in real time
/// (we redraw it every ~50 ms while waiting).
pub fn holdMinimum(ms: u64) void {
    if (!enabled or !graphical) return;
    const start = apic.readTsc();
    var last_redraw = start;
    while (true) {
        const now = apic.readTsc();
        const elapsed = apic.tscToMs(now -% start);
        if (elapsed >= ms) break;
        if (apic.tscToMs(now -% last_redraw) >= 50) {
            const layout = computeLayout();
            drawElapsedGfx(layout);
            flushFb();
            last_redraw = now;
        }
        asm volatile ("pause");
    }
}

/// Stop owning the screen. Restores prior redirect_fn (usually null).
pub fn disable() void {
    enabled = false;
    vga.redirect_fn = prev_redirect_fn;
}
