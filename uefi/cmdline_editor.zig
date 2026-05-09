// Single-line cmdline editor for the boot menu. Pops over the menu when
// the user presses `e`, lets them edit the kernel cmdline string that
// gets persisted in NVRAM and consumed by the kernel on the next boot.
//
// Scope of v1: insert printable ASCII, backspace, left/right caret,
// Home/End, Enter to commit, Esc to cancel. Caret blinks every ~500 ms
// for visibility. Cmdline is capped at 255 bytes (matches kernel's
// `BootInfo.cmdline[256]`).
//
// Why a separate file: keeps the editor's input loop and chrome out of
// the menu's draw block — the menu calls in once and gets back a new
// length (or `null` on Esc) without growing.

const std = @import("std");
const uefi = std.os.uefi;
const SimpleTextInput = uefi.protocol.SimpleTextInput;
const BootServices = uefi.tables.BootServices;
const aa = @import("aa_font");

pub const MAX_CMDLINE: usize = 255;

const COLOR_PANEL: u32 = 0x00121A2C;
const COLOR_BORDER_OUT: u32 = 0x0050A8FF;
const COLOR_BORDER_IN: u32 = 0x001A2238;
const COLOR_TITLE: u32 = 0x008FA8C8;
const COLOR_TEXT: u32 = 0x00D8DEEC;
const COLOR_DIM: u32 = 0x006A788C;
const COLOR_FIELD_BG: u32 = 0x00080A14;
const COLOR_FIELD_BORDER: u32 = 0x00606878;
const COLOR_CARET: u32 = 0x00FFCE60;
const COLOR_SHADOW: u32 = 0x00010204;

fn fillRect(fb: aa.Fb, x: u32, y: u32, w: u32, h: u32, color: u32) void {
    const x_end = @min(x + w, fb.w);
    const y_end = @min(y + h, fb.h);
    var yy: u32 = y;
    while (yy < y_end) : (yy += 1) {
        var xx: u32 = x;
        while (xx < x_end) : (xx += 1) {
            fb.base[yy * fb.stride + xx] = color;
        }
    }
}

fn drawBorder(fb: aa.Fb, x: u32, y: u32, w: u32, h: u32, color: u32) void {
    fillRect(fb, x, y, w, 1, color);
    if (h >= 2) fillRect(fb, x, y + h - 1, w, 1, color);
    fillRect(fb, x, y, 1, h, color);
    if (w >= 2) fillRect(fb, x + w - 1, y, 1, h, color);
}

/// Run the editor. `initial` is the starting text (can be empty); the
/// edited result is written to `out` and the new length returned. On Esc,
/// returns null and `out` is left untouched. Caller is responsible for
/// persisting the result to NVRAM.
pub fn edit(
    fb: aa.Fb,
    stin: *SimpleTextInput,
    bs: *BootServices,
    initial: []const u8,
    out: []u8,
) ?usize {
    aa.ensureLoaded();

    var buf: [MAX_CMDLINE + 1]u8 = [_]u8{0} ** (MAX_CMDLINE + 1);
    var len: usize = @min(initial.len, MAX_CMDLINE);
    if (len > 0) @memcpy(buf[0..len], initial[0..len]);
    var caret: usize = len;

    // Modal coords — centered over the menu, comfortable width for ~80
    // chars of SF Pro Text 16 (~7 px/char average).
    const ow: u32 = 740;
    const oh: u32 = 150;
    const ox = (fb.w -| ow) / 2;
    const oy = (fb.h -| oh) / 2;

    var caret_visible = true;
    var blink_ticks: u32 = 0;
    var redraw = true;

    while (true) {
        if (redraw) {
            // Drop shadow + panel chrome
            fillRect(fb, ox + 6, oy + 6, ow, oh, COLOR_SHADOW);
            fillRect(fb, ox, oy, ow, oh, COLOR_PANEL);
            drawBorder(fb, ox, oy, ow, oh, COLOR_BORDER_OUT);
            drawBorder(fb, ox + 1, oy + 1, ow - 2, oh - 2, COLOR_BORDER_IN);

            // Title bar
            const title = "edit kernel cmdline";
            const tw = aa.default_16.measure(title);
            aa.drawText(fb, @intCast(ox + (ow - tw) / 2), @intCast(oy + 16), title, COLOR_TITLE, &aa.default_16);

            // Input field
            const fx = ox + 30;
            const fy = oy + 56;
            const fw = ow - 60;
            const fh: u32 = 32;
            fillRect(fb, fx, fy, fw, fh, COLOR_FIELD_BG);
            drawBorder(fb, fx, fy, fw, fh, COLOR_FIELD_BORDER);

            // Text + caret. Field text starts 8 px from left edge.
            const text_y = fy + (fh -| aa.default_16.line_height) / 2;
            aa.drawText(fb, @intCast(fx + 8), @intCast(text_y), buf[0..len], COLOR_TEXT, &aa.default_16);
            if (caret_visible) {
                const caret_off = aa.default_16.measure(buf[0..caret]);
                const caret_x = fx + 8 + caret_off;
                fillRect(fb, caret_x, text_y, 2, aa.default_16.line_height, COLOR_CARET);
            }

            // Footer hint
            const hint = "Enter saves to NVRAM, Esc cancels  •  arrows + Home/End move caret  •  Backspace deletes";
            const hw = aa.default_16.measure(hint);
            const hint_x: u32 = if (hw + 32 > ow) ox + 16 else ox + (ow - hw) / 2;
            aa.drawText(fb, @intCast(hint_x), @intCast(oy + oh - 28), hint, COLOR_DIM, &aa.default_16);

            redraw = false;
        }

        // Poll keyboard
        if (stin.readKeyStroke()) |key| {
            // Any keystroke makes caret visible to provide feedback.
            caret_visible = true;
            blink_ticks = 0;
            redraw = true;
            switch (key.scan_code) {
                0x17 => return null, // Esc
                0x03 => { // Right
                    if (caret < len) caret += 1;
                },
                0x04 => { // Left
                    if (caret > 0) caret -= 1;
                },
                0x05 => { // Home
                    caret = 0;
                },
                0x06 => { // End
                    caret = len;
                },
                0x08 => { // Delete
                    if (caret < len) {
                        std.mem.copyForwards(u8, buf[caret .. len - 1], buf[caret + 1 .. len]);
                        len -= 1;
                        buf[len] = 0;
                    }
                },
                else => {
                    // Enter (CR or LF) — commit.
                    if (key.unicode_char == 0x0D or key.unicode_char == 0x0A) {
                        const n = @min(len, out.len);
                        @memcpy(out[0..n], buf[0..n]);
                        return n;
                    }
                    // Backspace — delete char to the left of the caret.
                    if (key.unicode_char == 0x08) {
                        if (caret > 0) {
                            if (caret < len) {
                                std.mem.copyForwards(u8, buf[caret - 1 .. len - 1], buf[caret..len]);
                            }
                            caret -= 1;
                            len -= 1;
                            buf[len] = 0;
                        }
                        continue;
                    }
                    // Printable ASCII insert.
                    const ch: u32 = key.unicode_char;
                    if (ch >= 0x20 and ch < 0x7F and len < MAX_CMDLINE) {
                        if (caret < len) {
                            std.mem.copyBackwards(u8, buf[caret + 1 .. len + 1], buf[caret..len]);
                        }
                        buf[caret] = @intCast(ch);
                        caret += 1;
                        len += 1;
                    }
                },
            }
        } else |_| {}

        // Caret blink — every ~500 ms toggle visibility.
        blink_ticks += 1;
        if (blink_ticks >= 10) {
            blink_ticks = 0;
            caret_visible = !caret_visible;
            redraw = true;
        }
        bs.stall(50_000) catch {};
    }
}
