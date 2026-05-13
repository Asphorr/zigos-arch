// sigil — the ZigOS "calling card" window.
//
// One-shot window app that paints a large 3D-extruded Z logo using the
// Spleen 8x16 block elements (atlas slots 0x80..0x85 — see bdf_to_zig.py
// EXTRA_GLYPHS), the ZigOS wordmark beneath it, and key system info pulled
// from real syscalls. Press Esc / Enter / q or close the window to exit.
//
// Block element glyph map (single-byte indices into font8x16.data):
//   0x80 █ FULL BLOCK         front face (brightest)
//   0x81 ░ LIGHT SHADE        cast shadow (darkest)
//   0x82 ▒ MEDIUM SHADE       side face (mid)
//   0x83 ▓ DARK SHADE         top/under-edge face (lit at angle)
//   0x84 ▀ UPPER HALF         (reserved — unused here, kept for callers)
//   0x85 ▄ LOWER HALF         (reserved — unused here)

const std = @import("std");
const libc = @import("libc");
const gfx = @import("graphics");
const fa = @import("font_atlas");

const WIN_W: u32 = 480;
const WIN_H: u32 = 360;
const CHAR_W: u32 = 8;
const CHAR_H: u32 = 16;

// === Colors ===
const C_BG: u32 = 0x101018;
const C_LOGO_FRONT: u32 = 0xF7A41D; // Zig brand orange
const C_LOGO_MID: u32 = 0xC97F11;   // dimmer for ▓/▒ — same hue, less luma
const C_SHADOW: u32 = 0x2A2218;     // very dark warm gray for ░
const C_WORDMARK: u32 = 0xFFB840;   // bright orange for "ZigOS"
const C_TEXT: u32 = 0xCCCCCC;
const C_DIM: u32 = 0x707088;
const C_LABEL: u32 = 0x88AACC;

// === Logo bytes ===
// Single-byte constants for each glyph slot. We use Zig's `**` array repeat
// to build each row at comptime; the resulting `[N]u8` arrays are sliced into
// the LOGO_LINES table below.
const FB: [1]u8 = .{0x80}; // █
const LS: [1]u8 = .{0x81}; // ░
const MS: [1]u8 = .{0x82}; // ▒
const DS: [1]u8 = .{0x83}; // ▓
const SP: [1]u8 = .{' '};

// Each row constructed by concatenating run-length blocks. Comments at the
// end show the intended visual shape (read left-to-right):
//   front face = █, top edge = ▓, side face = ▒, cast shadow = ░
const ROW0 = FB ** 23;                                                        // █████████████████████████ (top bar front)
const ROW1 = SP ++ DS ** 16 ++ FB ** 4 ++ MS ** 2 ++ LS;                      //  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████▒▒░  (top bar bottom-edge + diagonal R end)
const ROW2 = SP ++ LS ** 14 ++ FB ** 4 ++ MS ** 2 ++ LS ** 2;                 //  ░░░░░░░░░░░░░░████▒▒░░   (under-shadow + diagonal)
const ROW3 = SP ** 13 ++ FB ** 4 ++ MS ** 2 ++ LS ** 2;                       //              ████▒▒░░
const ROW4 = SP ** 11 ++ FB ** 4 ++ MS ** 2 ++ LS ** 2;                       //            ████▒▒░░
const ROW5 = SP ** 9 ++ FB ** 4 ++ MS ** 2 ++ LS ** 2;                        //          ████▒▒░░
const ROW6 = SP ** 7 ++ FB ** 4 ++ MS ** 2 ++ LS ** 11;                       //        ████▒▒░░░░░░░░░░░  (diagonal L end + cast shadow trail)
const ROW7 = SP ** 7 ++ FB ** 4 ++ DS ** 13;                                  //        ████▓▓▓▓▓▓▓▓▓▓▓▓▓  (bottom bar top-edge)
const ROW8 = SP ** 7 ++ FB ** 17;                                             //        █████████████████  (bottom bar front)
const ROW9 = SP ** 7 ++ LS ** 17;                                             //        ░░░░░░░░░░░░░░░░░  (cast shadow on ground)

const LOGO_LINES = [_][]const u8{
    &ROW0, &ROW1, &ROW2, &ROW3, &ROW4, &ROW5, &ROW6, &ROW7, &ROW8, &ROW9,
};
const LOGO_ROWS: u32 = LOGO_LINES.len;
const LOGO_COLS: u32 = 24; // widest row (rows 1, 6, 7, 8, 9 are 24 cells wide)

// === CPUID — same trick as fastfetch, for the brand string ===
const CpuId = struct { eax: u32, ebx: u32, ecx: u32, edx: u32 };

fn cpuid(leaf: u32, sub: u32) CpuId {
    var ra: u32 = leaf;
    var rb: u32 = undefined;
    var rc: u32 = sub;
    var rd: u32 = undefined;
    asm volatile ("cpuid"
        : [ra] "+{eax}" (ra),
          [rb] "={ebx}" (rb),
          [rc] "+{ecx}" (rc),
          [rd] "={edx}" (rd),
    );
    return .{ .eax = ra, .ebx = rb, .ecx = rc, .edx = rd };
}

fn writeU32LE(buf: []u8, val: u32) void {
    buf[0] = @truncate(val);
    buf[1] = @truncate(val >> 8);
    buf[2] = @truncate(val >> 16);
    buf[3] = @truncate(val >> 24);
}

fn cpuBrand(out: *[48]u8) []const u8 {
    const leaves = [_]u32{ 0x80000002, 0x80000003, 0x80000004 };
    for (leaves, 0..) |leaf, i| {
        const r = cpuid(leaf, 0);
        const base = i * 16;
        writeU32LE(out[base..][0..4], r.eax);
        writeU32LE(out[base + 4 ..][0..4], r.ebx);
        writeU32LE(out[base + 8 ..][0..4], r.ecx);
        writeU32LE(out[base + 12 ..][0..4], r.edx);
    }
    var start: usize = 0;
    while (start < 48 and (out[start] == ' ' or out[start] == 0)) start += 1;
    var end: usize = 48;
    while (end > start and (out[end - 1] == ' ' or out[end - 1] == 0)) end -= 1;
    return out[start..end];
}

fn readBuildId(buf: *[16]u8) ?[]const u8 {
    const fd = libc.open("/BUILD.ID") orelse return null;
    defer libc.close(fd);
    const n = libc.fread(fd, buf[0..]);
    if (n < 16) return null;
    return buf[0..16];
}

// === Drawing ===

/// Pick the foreground color for one logo cell. Block-element slots map to
/// the 3D-extrusion palette; everything else (spaces, fallback) gets the
/// background so they render invisibly.
fn colorFor(ch: u8) u32 {
    return switch (ch) {
        0x80 => C_LOGO_FRONT, // █ bright front face
        0x82 => C_LOGO_MID,   // ▒ side face — same hue, lower luma
        0x83 => C_LOGO_MID,   // ▓ top edge — same hue, lower luma
        0x81 => C_SHADOW,     // ░ cast shadow
        else => C_BG,
    };
}

fn drawLogo(canvas: *gfx.Canvas, ox: u32, oy: u32) void {
    for (LOGO_LINES, 0..) |line, row| {
        const y = oy + @as(u32, @intCast(row)) * CHAR_H;
        for (line, 0..) |ch, col| {
            const x = ox + @as(u32, @intCast(col)) * CHAR_W;
            if (ch == ' ') continue; // skip blank cells — bg already painted
            const fg = colorFor(ch);
            canvas.drawChar16(x, y, ch, fg, C_BG);
        }
    }
}

fn measure(text: []const u8) u32 {
    return fa.default_16.measure(text);
}

fn drawCenteredAA(canvas: *gfx.Canvas, y: u32, text: []const u8, color: u32) void {
    const w = measure(text);
    const x: u32 = if (WIN_W > w) (WIN_W - w) / 2 else 0;
    fa.drawText(canvas, @intCast(x), @intCast(y), text, color, &fa.default_16);
}

fn drawLabelValueAA(canvas: *gfx.Canvas, y: u32, label: []const u8, value: []const u8) void {
    // Two-column row: label on the left of center, value on the right.
    // Center the assembled label+":  "+value combo for visual coherence.
    const sep = ":  ";
    const total = measure(label) + measure(sep) + measure(value);
    const x: u32 = if (WIN_W > total) (WIN_W - total) / 2 else 0;
    var cx = x;
    fa.drawText(canvas, @intCast(cx), @intCast(y), label, C_LABEL, &fa.default_16);
    cx += measure(label);
    fa.drawText(canvas, @intCast(cx), @intCast(y), sep, C_DIM, &fa.default_16);
    cx += measure(sep);
    fa.drawText(canvas, @intCast(cx), @intCast(y), value, C_TEXT, &fa.default_16);
}

// === Main ===

export fn _start() linksection(".text.entry") callconv(.c) void {
    const win = libc.createWindow(WIN_W, WIN_H) orelse libc.exit();
    var canvas = gfx.Canvas.init(win.fb, win.alloc_w, win.alloc_h);
    fa.ensureLoaded();

    canvas.fillRect(0, 0, WIN_W, WIN_H, C_BG);

    // Logo placement: horizontally centered, near top.
    const logo_w = LOGO_COLS * CHAR_W; // 24 * 8 = 192
    const logo_x: u32 = (WIN_W - logo_w) / 2;
    const logo_y: u32 = 24;
    drawLogo(&canvas, logo_x, logo_y);

    // Wordmark + tagline immediately below the logo.
    const wordmark_y: u32 = logo_y + LOGO_ROWS * CHAR_H + 12;
    drawCenteredAA(&canvas, wordmark_y, "ZigOS", C_WORDMARK);
    drawCenteredAA(&canvas, wordmark_y + 26, "x86_64 hobby kernel in Zig", C_DIM);

    // Info block — uptime, build id, CPU. Small label:value rows.
    var info_y: u32 = wordmark_y + 58;
    const line_h: u32 = 20;

    // Uptime — formatted as Hh Mm.
    {
        const ticks = libc.uptime();
        const total_s = ticks / 100;
        const hours = total_s / 3600;
        const mins = (total_s % 3600) / 60;
        var buf: [40]u8 = undefined;
        const v = std.fmt.bufPrint(&buf, "{d}h {d}m", .{ hours, mins }) catch buf[0..0];
        drawLabelValueAA(&canvas, info_y, "Uptime", v);
        info_y += line_h;
    }

    // Build ID.
    {
        var bid_buf: [16]u8 = undefined;
        if (readBuildId(&bid_buf)) |bid| {
            drawLabelValueAA(&canvas, info_y, "Build", bid);
        } else {
            drawLabelValueAA(&canvas, info_y, "Build", "(unknown)");
        }
        info_y += line_h;
    }

    // CPU brand (truncated if very long).
    {
        var brand_buf: [48]u8 = undefined;
        const brand = cpuBrand(&brand_buf);
        drawLabelValueAA(&canvas, info_y, "CPU", brand);
        info_y += line_h;
    }

    // Footer hint at bottom — barely visible.
    fa.drawText(&canvas, 8, @intCast(WIN_H - 22), "press q or esc to close", C_DIM, &fa.default_16);

    libc.present();

    // Event loop — exit on Esc/q/Enter/close.
    while (true) {
        var should_close = false;
        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (ch == 'q' or ch == 'Q' or ch == 0x1B or ch == '\n' or ch == '\r') {
                        should_close = true;
                    }
                },
                .close_request => should_close = true,
                else => {},
            }
        }
        if (should_close) break;
        libc.sleep(30);
    }

    libc.destroyWindow();
    libc.exit();
}
