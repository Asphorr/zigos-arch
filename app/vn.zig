//! ZigOS visual-novel engine — skeleton.
//!
//! Goal of this iteration: prove the render+input pipeline before the
//! script loader, AST interpreter, and asset pipeline come online. Runs
//! a hardcoded 4-line "Hello, VN" script, click-to-advance, ESC quits.
//!
//! Things that exist:
//!   - 1280×720 window (DDLC native res).
//!   - 3 render layers — BG fill, sprite placeholder, dialogue box.
//!   - Textbox: rounded translucent panel, speaker tag, word-wrapped body.
//!   - Click-to-advance with a blinking "▼" indicator.
//!
//! Things deliberately absent (next iterations):
//!   - Asset I/O (no BG / sprite PNGs loaded yet — placeholders are fills).
//!   - Script loading (.rpyc decoding + JSON AST). Test script is inline.
//!   - Audio (mixer + vorbis are wired in build.zig but unused here).
//!   - Choice menus, Jump, If, Python eval — all Week 2 day-2+ work.
//!   - Save/load. Window resize. Per-character typewriter speed.
//!
//! Layered architecture this skeleton bakes in:
//!   bg_layer:    paints behind everything; will be drawPixmap(bg.png).
//!   sprite_layer: 0..N character positions; will be drawPixmapAlpha.
//!   dialogue_layer: textbox + name tag + body text + advance indicator.
//! The render fns are written so each can become a no-op when not needed —
//! e.g., the dialogue layer skips on a Show statement with no text.

const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const image = @import("image");

const WIN_W: u32 = 1280;
const WIN_H: u32 = 720;

/// Loaded once at startup; rendered via drawPixmapAlphaScaled each frame.
/// `null` falls back to the procedural gradient — keeps the engine bootable
/// even if asset I/O fails (e.g. file missing during dev iteration).
var bg_image: ?image.Pixel = null;
var sprite_image: ?image.Pixel = null;

const BG_PATH: []const u8 = "/share/vn_bg.png";
const SPRITE_PATH: []const u8 = "/share/vn_sayori.png";

/// On-screen sprite slot. DDLC source sprites are 960×960 — we downscale.
const SPRITE_DST_H: u32 = 540;
const SPRITE_DST_W: u32 = 540; // source is square 960×960 → keep square

/// One line of dialogue. `who == null` is narration (no speaker tag).
const Line = struct {
    who: ?[]const u8,
    what: []const u8,
};

/// Hardcoded test script. Replaced in the next iteration by the JSON AST
/// loader; this proves the render pipeline before that lands.
const test_script = [_]Line{
    .{ .who = "MC", .what = "Welcome to the ZigOS visual-novel engine." },
    .{ .who = "Sayori", .what = "Yeah! It's actually working! Click to read the next line." },
    .{ .who = null, .what = "...the wind picks up outside." },
    .{ .who = "MC", .what = "(Skeleton only — assets and scripting land next iteration.)" },
    .{ .who = "MC", .what = "Click once more to exit." },
};

// --- Layout constants --------------------------------------------------------

const TEXTBOX_HEIGHT: u32 = 220;
const TEXTBOX_MARGIN: u32 = 24;
const TEXTBOX_PADDING: u32 = 24;
const NAME_TAG_HEIGHT: u32 = 36;
const TEXTBOX_BG: u32 = 0x000000;
const TEXTBOX_BG_ALPHA: u8 = 192; // 75%
const TEXTBOX_BORDER: u32 = 0xFFE0EA; // pale pink
const NAME_TAG_BG: u32 = 0xE96B95; // DDLC pink
const TEXT_FG: u32 = 0xFFFFFF;
const NARRATION_FG: u32 = 0xE8E8E8;

// --- Per-layer draw fns ------------------------------------------------------

fn drawBackground(canvas: *gfx.Canvas, w: u32, h: u32, tick: u32) void {
    if (bg_image) |bg| {
        // Real BG asset path. drawPixmapAlphaScaled handles arbitrary
        // src→dst resolution mismatch with Q16 nearest-neighbor; sunset.png
        // is 1920×1080 → window is 1280×720, so we downscale by 1.5×.
        canvas.drawPixmapAlphaScaled(0, 0, w, h, bg.width, bg.height, bg.pixels);
        return;
    }
    // Fallback: procedural gradient when no asset is loaded (or load failed).
    // Slowly tick the top hue so it's visible the frame loop is alive even
    // mid-statement.
    const t = (tick / 4) % 256;
    const top = (@as(u32, 0x60) + @as(u32, @intCast(t / 4))) << 8 | 0x202050;
    const bot: u32 = 0x101025;
    ui.verticalGradient(canvas, 0, 0, w, h, top, bot);
}

/// Read an entire file into a malloc'd byte slice. Sizes the allocation to
/// the file's actual size (+4 KB headroom), not to a max-bytes cap, so a
/// 100 KB PNG doesn't reserve 16 MB of user heap. Same pattern as
/// app/wallpaper.zig — could factor into libc later.
fn readEntireFile(path: []const u8, max_bytes: usize) ?[]u8 {
    var st: libc.FileStat = undefined;
    if (!libc.stat(path, &st)) return null;
    const want: usize = @as(usize, st.file_size);
    if (want == 0 or want > max_bytes) return null;
    const fd = libc.open(path) orelse return null;
    defer libc.close(fd);
    const cap: usize = want + 4096;
    const buf_ptr = libc.malloc(cap) orelse return null;
    const buf = buf_ptr[0..cap];
    var total: usize = 0;
    while (total < cap) {
        const remaining = cap - total;
        const chunk = if (remaining > 65536) 65536 else remaining;
        const n = libc.fread(fd, buf[total..][0..chunk]);
        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

/// Load a PNG into a Pixel via the per-process heap. Decoded pixels survive
/// for the lifetime of the process — DDLC's asset count is small enough to
/// keep BGs/sprites all resident once a proper cache lands. Silently
/// returns null when the file is missing (caller falls back to a
/// placeholder).
fn loadImage(path: []const u8) ?image.Pixel {
    // 32 MB cap: more than enough for any single PNG we'd want to ship.
    const file_data = readEntireFile(path, 32 * 1024 * 1024) orelse return null;
    defer libc.free(file_data.ptr);
    return image.decode(file_data, 4) catch null;
}

fn loadAssets() void {
    bg_image = loadImage(BG_PATH);
    sprite_image = loadImage(SPRITE_PATH);
}

fn drawSprite(canvas: *gfx.Canvas, w: u32, h: u32) void {
    _ = h;
    const sx: u32 = (w -| SPRITE_DST_W) / 2;
    const sy: u32 = 40;
    if (sprite_image) |sp| {
        // Real sprite path. drawPixmapAlphaScaled does Q16 nearest-neighbor
        // scale + straight-alpha src-over blend; sprite has transparent
        // pixels around the character silhouette, so the BG (already drawn)
        // shows through.
        canvas.drawPixmapAlphaScaled(sx, sy, SPRITE_DST_W, SPRITE_DST_H, sp.width, sp.height, sp.pixels);
        return;
    }
    // Fallback placeholder when asset I/O fails — same rectangle so the
    // composition is still readable, just clearly a placeholder.
    canvas.fillRectAlpha(sx, sy, SPRITE_DST_W, SPRITE_DST_H, 0xFFFFFF, 32);
    ui.drawRect1px(canvas, sx, sy, SPRITE_DST_W, SPRITE_DST_H, 0x4060A0);
    const cx = sx + SPRITE_DST_W / 2 -| 64;
    const cy = sy + SPRITE_DST_H / 2 -| 12;
    fa.drawText(canvas, @intCast(cx), @intCast(cy), "(sprite slot)", 0xA0B0D0, &fa.default_24);
}

fn drawTextbox(
    canvas: *gfx.Canvas,
    w: u32,
    h: u32,
    line: Line,
    tick: u32,
    advance_visible: bool,
) void {
    const bx = TEXTBOX_MARGIN;
    const by = h -| TEXTBOX_HEIGHT -| TEXTBOX_MARGIN;
    const bw = w -| 2 * TEXTBOX_MARGIN;
    const bh = TEXTBOX_HEIGHT;

    // Body panel.
    canvas.fillRectAlpha(bx, by, bw, bh, TEXTBOX_BG, TEXTBOX_BG_ALPHA);
    ui.drawRect1px(canvas, bx, by, bw, bh, TEXTBOX_BORDER);

    // Name tag — only when there's a speaker.
    if (line.who) |who| {
        const tag_w = fa.default_24.measure(who) + 32;
        const tag_x = bx + 16;
        const tag_y = by -| NAME_TAG_HEIGHT + 6;
        canvas.fillRect(tag_x, tag_y, tag_w, NAME_TAG_HEIGHT, NAME_TAG_BG);
        ui.drawRect1px(canvas, tag_x, tag_y, tag_w, NAME_TAG_HEIGHT, TEXTBOX_BORDER);
        fa.drawText(
            canvas,
            @intCast(tag_x + 16),
            @intCast(tag_y + 6),
            who,
            TEXT_FG,
            &fa.default_24,
        );
    }

    // Body text — word-wrapped into available width.
    const text_x: i32 = @intCast(bx + TEXTBOX_PADDING);
    const text_y_start: i32 = @intCast(by + TEXTBOX_PADDING);
    const text_w_max: u32 = bw -| 2 * TEXTBOX_PADDING;
    const fg = if (line.who == null) NARRATION_FG else TEXT_FG;
    drawWrapped(canvas, line.what, text_x, text_y_start, text_w_max, fg);

    // Blinking advance indicator ▶ when the line is "complete" (always true
    // for now since we don't typewriter yet).
    if (advance_visible and (tick / 30) % 2 == 0) {
        const ix: i32 = @intCast(bx + bw -| 28);
        const iy: i32 = @intCast(by + bh -| 28);
        fa.drawText(canvas, ix, iy, "\xE2\x96\xBC", TEXTBOX_BORDER, &fa.default_24);
    }
}

/// Word-wrap `text` into lines that each measure ≤ `max_w` px in default_24,
/// drawing them in `color` from `(x, y_start)` downward. Returns nothing —
/// the layout is fully deterministic from the inputs.
fn drawWrapped(
    canvas: *gfx.Canvas,
    text: []const u8,
    x: i32,
    y_start: i32,
    max_w: u32,
    color: u32,
) void {
    const font = &fa.default_24;
    const line_h: u32 = font.line_height + 4;
    var y = y_start;
    var i: usize = 0;
    while (i < text.len) {
        // Find the longest prefix from i that fits in max_w, breaking on
        // word boundaries when possible. If a single word exceeds max_w,
        // we still draw it (it'll overflow visually rather than infinite-loop).
        var end: usize = text.len;
        var last_break: usize = 0;
        var j: usize = i;
        while (j <= text.len) : (j += 1) {
            const slice = text[i..j];
            if (font.measure(slice) > max_w) {
                end = if (last_break > i) last_break else (if (j > i + 1) j - 1 else j);
                break;
            }
            if (j < text.len and text[j] == ' ') last_break = j;
        }
        fa.drawText(canvas, x, y, text[i..end], color, font);
        y += @intCast(line_h);
        // Skip the space at the break to avoid leading space on next line.
        i = if (end < text.len and text[end] == ' ') end + 1 else end;
    }
}

// --- Main loop ---------------------------------------------------------------

export fn _start() linksection(".text.entry") callconv(.c) void {
    const win = libc.createWindowEx(WIN_W, WIN_H, WIN_W, WIN_H) orelse libc.exit();
    var canvas = gfx.Canvas.init(win.fb, win.alloc_w, win.alloc_h);
    _ = libc.getWindowAlloc();
    fa.ensureLoaded();
    loadAssets();

    var cur_line: usize = 0;
    var tick: u32 = 0;
    var prev_left: bool = false;
    var cur_btns: u32 = 0;

    while (true) {
        var should_quit = false;
        var advance_clicked = false;

        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => should_quit = true,
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (ch == 0x1B) {
                        should_quit = true;
                    } else if (ch == ' ' or ch == '\r' or ch == '\n') {
                        advance_clicked = true;
                    }
                },
                .mouse_button => {
                    cur_btns = ev.buttonsState();
                },
                else => {},
            }
        }
        if (should_quit) break;

        const left_now = (cur_btns & 1) != 0;
        // Edge-detect release for "click to advance" (not press, so dragging
        // doesn't trigger).
        if (!left_now and prev_left) advance_clicked = true;
        prev_left = left_now;

        if (advance_clicked) {
            cur_line += 1;
            if (cur_line >= test_script.len) break;
        }

        // --- Draw frame ---
        drawBackground(&canvas, WIN_W, WIN_H, tick);
        drawSprite(&canvas, WIN_W, WIN_H);
        drawTextbox(&canvas, WIN_W, WIN_H, test_script[cur_line], tick, true);

        libc.present();
        libc.sleep(16);
        tick +%= 1;
    }

    libc.destroyWindow();
    libc.exit();
}
