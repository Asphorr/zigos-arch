// Top-right toast notification — slide-in from the right edge, brief
// glass pill with a single line of text. One toast at a time; a new
// `show()` call replaces whatever was there.
//
// Lifecycle: `show()` queues text + resets timer/anim. The desktop
// main loop calls `tick()` once per frame, which decrements the
// timer and advances the slide-in. `render()` draws the current
// frame's glass pill at the eased-in position.
//
// Width estimate uses 9 px / char (matches the legacy bitmap font's
// advance) plus 32 px horizontal padding — close enough for SF Pro
// at body size given the surrounding 12 px screen margin.

const gfx = @import("../gfx.zig");
const layout = @import("layout.zig");
const dirty_rects = @import("dirty.zig");

var text_buf: [64]u8 = [_]u8{0} ** 64;
var text_len: u8 = 0;
var timer: u32 = 0;
var anim: u8 = 0;

pub const ANIM_FRAMES: u8 = 8;
const FONT_ADVANCE: u32 = 9; // Approximate glyph width for sizing only
const PILL_H: u32 = 36;
const MARGIN: i32 = 12;

/// Show `text` for ~200 frames (~3 s at 60 Hz, scales with desktop tick
/// rate). A new call interrupts the previous toast immediately.
pub fn show(text: []const u8) void {
    if (text.len == 0) return;
    const copy_len = @min(text.len, text_buf.len);
    for (0..copy_len) |i| text_buf[i] = text[i];
    text_len = @intCast(copy_len);
    timer = 200;
    anim = 0;
}

/// True iff a toast is currently on screen. Desktop's idle-yield logic
/// uses this to keep ticking while the slide-in / fade-out plays.
pub fn isActive() bool {
    return timer > 0;
}

/// Per-frame timer/anim advance. Returns true iff the desktop must
/// schedule a full repaint (slide-in step or final fade-out).
pub fn tick() bool {
    if (timer == 0) return false;
    var dirty = false;
    if (anim < ANIM_FRAMES) {
        anim += 1;
        dirty = true;
    }
    timer -= 1;
    if (timer == 0) dirty = true;
    return dirty;
}

pub fn render() void {
    if (timer == 0) return;
    const toast_w: u32 = @as(u32, text_len) * FONT_ADVANCE + 32;
    const toast_y: i32 = @as(i32, layout.MENUBAR_H) + MARGIN;

    // Slide-in from right edge with quadratic ease-out.
    const full_x: i32 = @as(i32, @intCast(gfx.screen_w)) - @as(i32, @intCast(toast_w)) - MARGIN;
    const off_x: i32 = @as(i32, @intCast(toast_w)) + MARGIN;
    var toast_x: i32 = full_x;
    if (anim < ANIM_FRAMES) {
        const t: i32 = @intCast(anim);
        const total: i32 = ANIM_FRAMES;
        const progress = total - @divTrunc((total - t) * (total - t), total);
        toast_x = full_x + off_x - @divTrunc(off_x * progress, total);
    }

    // Track the painted region so partial-blit paths flush this strip.
    // Add 2 px on each side for the shadow + specular border.
    const ux: u32 = if (toast_x < 1) 0 else @intCast(toast_x - 1);
    const uy: u32 = if (toast_y < 1) 0 else @intCast(toast_y - 1);
    dirty_rects.add(ux, uy, toast_w + 4, PILL_H + 4);

    // Shadow + glass backdrop + 1 px specular border.
    gfx.fillRoundedRectAlpha(toast_x + 2, toast_y + 2, toast_w, PILL_H, 10, 0x40000000);
    gfx.fillGlass(toast_x, toast_y, toast_w, PILL_H, 10, 0x382A2A3A, 6);
    gfx.fillRoundedRectAlpha(toast_x - 1, toast_y - 1, toast_w + 2, PILL_H + 2, 11, 0x18FFFFFF);
    // Body text — opaque bitmap font is fine; glass already painted under it.
    gfx.drawString(toast_x + 16, toast_y + 10, text_buf[0..text_len], 0xFFFFFF, 0);
}
