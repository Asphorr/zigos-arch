// Top-right toast notification — slides in from the right edge, holds,
// then slides back out. Brief glass pill with a single line of text.
// One toast at a time; a new `show()` call replaces whatever was there.
//
// Lifecycle: `show()` queues the text. The desktop main loop calls
// `tick(now)` each frame; the pill's place follows from its age in timer
// ticks, so it stays up LIFE_TICKS whatever the frame rate. `render()`
// draws it at the eased position — ease-out on the way in, ease-in on
// the way out.

const gfx = @import("../gfx.zig");
const aa_font = @import("../aa_font.zig");
const layout = @import("layout.zig");
const dirty_rects = @import("dirty.zig");

/// The longest text, and the longest sender name in front of it.
const TEXT_MAX: usize = 64;
const SENDER_MAX: usize = 32;

var text_buf: [SENDER_MAX + 2 + TEXT_MAX]u8 = @splat(0);
var text_len: u8 = 0;

/// Timer ticks (10 ms) on screen, both slides included, and per slide.
const LIFE_TICKS: u32 = 300;
const SLIDE_TICKS: u32 = 15;

var active: bool = false;
/// show() ran and tick() has not yet stamped the start.
var fresh: bool = false;
var start_tick: u64 = 0;
/// Ticks since start_tick as of the last tick().
var age: u32 = 0;

const PILL_H: u32 = 34;
const PAD_X: u32 = 16;
const RADIUS: u32 = 11;
const MARGIN: i32 = 10;

/// Show `text` for LIFE_TICKS. A new call replaces the toast on screen.
pub fn show(text: []const u8) void {
    if (text.len == 0) return;
    put(0, text);
}

/// show() for a program's text: "sender: text".
pub fn showFrom(sender: []const u8, text: []const u8) void {
    if (text.len == 0) return;
    const n = @min(sender.len, SENDER_MAX);
    for (0..n) |i| text_buf[i] = sender[i];
    text_buf[n] = ':';
    text_buf[n + 1] = ' ';
    put(n + 2, text);
}

/// The text, from `at` on, and the pill's start.
fn put(at: usize, text: []const u8) void {
    const copy_len = @min(text.len, TEXT_MAX);
    for (0..copy_len) |i| text_buf[at + i] = text[i];
    text_len = @intCast(at + copy_len);
    active = true;
    fresh = true;
    age = 0;
}

pub fn isActive() bool {
    return active;
}

fn sliding(a: u32) bool {
    return a < SLIDE_TICKS or a > LIFE_TICKS - SLIDE_TICKS;
}

/// Advance to tick `now`. Returns true iff the desktop must repaint the
/// pill's old and new rects: it appeared, moved or left.
pub fn tick(now: u64) bool {
    if (!active) return false;
    if (fresh) {
        fresh = false;
        start_tick = now;
        return true;
    }
    const new_age: u32 = @intCast(@min(now -% start_tick, LIFE_TICKS));
    const moved = new_age != age and (sliding(age) or sliding(new_age));
    age = new_age;
    if (age >= LIFE_TICKS) {
        active = false;
        return true;
    }
    return moved;
}

/// The tick at which tick() next has something to do: every other tick
/// during a slide, the start of the slide-out during the hold.
pub fn nextWake(now: u64) u64 {
    if (fresh or sliding(age)) return now + 2;
    return start_tick + (LIFE_TICKS - SLIDE_TICKS) + 1;
}

/// Screen rect [x0, y0, x1, y1) the last render() painted, null if none.
pub var painted: ?[4]i32 = null;

fn pillWidth() u32 {
    return aa_font.getDefault13().measure(text_buf[0..text_len]) + PAD_X * 2;
}

/// Pill origin at the current age.
fn pillPos() [2]i32 {
    const toast_w = pillWidth();
    const toast_y: i32 = @as(i32, layout.MENUBAR_H) + MARGIN;

    // `full_x` = resting position; `off_x` = distance from rest to fully
    // off-screen past the right edge. The pill eases between the two.
    const full_x: i32 = @as(i32, @intCast(gfx.screen_w)) - @as(i32, @intCast(toast_w)) - MARGIN;
    const off_x: i32 = @as(i32, @intCast(toast_w)) + MARGIN;
    const total: i32 = SLIDE_TICKS;
    var toast_x: i32 = full_x;
    if (age < SLIDE_TICKS) {
        // Slide-in from the right edge with quadratic ease-out.
        const t: i32 = @intCast(age);
        const progress = total - @divTrunc((total - t) * (total - t), total);
        toast_x = full_x + off_x - @divTrunc(off_x * progress, total);
    } else if (age > LIFE_TICKS - SLIDE_TICKS) {
        // Slide-out with quadratic ease-in, the mirror of the slide-in.
        const t: i32 = @intCast(age - (LIFE_TICKS - SLIDE_TICKS));
        const progress = @divTrunc(t * t, total);
        toast_x = full_x + @divTrunc(off_x * progress, total);
    }
    return .{ toast_x, toast_y };
}

/// Screen rect [x0, y0, x1, y1) render() would paint now (pill plus its
/// shadow), null when no toast is up.
pub fn rect() ?[4]i32 {
    if (!active) return null;
    const p = pillPos();
    return .{ p[0] - 1, p[1], p[0] + @as(i32, @intCast(pillWidth())) + 1, p[1] + @as(i32, PILL_H) + 4 };
}

pub fn render() void {
    painted = rect();
    const r = painted orelse return;
    const toast_w = pillWidth();
    const toast_x = r[0] + 1;
    const toast_y = r[1];

    // Track the painted region so partial-blit paths flush this strip.
    const ux: u32 = if (r[0] < 0) 0 else @intCast(r[0]);
    const uy: u32 = if (r[1] < 0) 0 else @intCast(r[1]);
    dirty_rects.add(ux, uy, toast_w + 2, PILL_H + 4);

    // Shadow, glass, hairline ring: all inside rect().
    gfx.fillRoundedRectAlpha(toast_x - 1, toast_y + 1, toast_w + 2, PILL_H + 3, RADIUS + 1, 0x18000000);
    gfx.fillRoundedRectAlpha(toast_x, toast_y + 3, toast_w, PILL_H, RADIUS, 0x28000000);
    gfx.fillGlass(toast_x, toast_y, toast_w, PILL_H, RADIUS, 0xA026262A, 6);
    gfx.strokeRoundedRectAlpha(toast_x, toast_y, toast_w, PILL_H, RADIUS, 0x30FFFFFF);

    const atlas = aa_font.getDefault13();
    const text_y: i32 = toast_y + @as(i32, @intCast((PILL_H -| atlas.line_height) / 2));
    aa_font.drawText(toast_x + @as(i32, PAD_X), text_y, text_buf[0..text_len], 0xF2F2F4, atlas);
}
