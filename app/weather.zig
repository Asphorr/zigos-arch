// weather — GUI weather widget. Geocodes a city, fetches Open-Meteo,
// draws a gradient sky with a vector icon (sun/moon/cloud/etc.) and
// an info panel underneath.
//
// Usage: weather [city]
//
// Reload by pressing R. Esc / close button exits.

const std = @import("std");
const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const weather = @import("weather");

const INIT_W: u32 = 380;
const INIT_H: u32 = 260;

const DEFAULT_CITY: []const u8 = "Berlin";

var alloc_w: u32 = 0;
var alloc_h: u32 = 0;
var vis_w: u32 = INIT_W;
var vis_h: u32 = INIT_H;

var city_buf: [128]u8 = undefined;
var city_len: usize = 0;
var cond: weather.Conditions = undefined;
var cond_loaded: bool = false;
var last_error: ?[]const u8 = null;

fn copyArg(idx: u32, buf: []u8) ?[]u8 {
    const n = libc.getArgv(idx, buf);
    if (n == 0 or n == 0xFFFFFFFF) return null;
    return buf[0..n];
}

fn city() []const u8 {
    return city_buf[0..city_len];
}

fn reload() void {
    weather.fetch(city(), &cond) catch |err| {
        cond_loaded = false;
        last_error = @errorName(err);
        return;
    };
    cond_loaded = true;
    last_error = null;
}

// ---------------------------------------------------------------------
// Color picks per weather kind + time of day. Same palette as wx.elf
// where it makes sense; the GUI has the luxury of true gradients.

const Palette = struct {
    sky_top: u32,
    sky_bot: u32,
    panel: u32,
    text: u32,
    accent: u32,
};

fn paletteFor(c: weather.Conditions) Palette {
    const kind = weather.kindOf(c.code);
    if (c.is_day) {
        return switch (kind) {
            .clear => .{ .sky_top = 0x4DA6E0, .sky_bot = 0xB8DCF2, .panel = 0x1A2540, .text = 0xFFFFFF, .accent = 0xFFC940 },
            .partly_cloudy => .{ .sky_top = 0x6FB0DD, .sky_bot = 0xCFDFE8, .panel = 0x1A2540, .text = 0xFFFFFF, .accent = 0xFFC940 },
            .overcast, .fog => .{ .sky_top = 0x7E8AA0, .sky_bot = 0xB6BFCB, .panel = 0x202832, .text = 0xFFFFFF, .accent = 0xC4D0D8 },
            .rain => .{ .sky_top = 0x4B5970, .sky_bot = 0x8493AA, .panel = 0x1A2030, .text = 0xFFFFFF, .accent = 0x6FB0FF },
            .snow => .{ .sky_top = 0x8FA3B8, .sky_bot = 0xE0EAF4, .panel = 0x1F2A36, .text = 0xFFFFFF, .accent = 0xFFFFFF },
            .storm => .{ .sky_top = 0x2A2F44, .sky_bot = 0x5A6080, .panel = 0x14181F, .text = 0xFFFFFF, .accent = 0xFFE633 },
        };
    } else {
        return switch (kind) {
            .clear => .{ .sky_top = 0x0A1A3E, .sky_bot = 0x223266, .panel = 0x080F1F, .text = 0xFFFFFF, .accent = 0xE6E6F0 },
            .partly_cloudy => .{ .sky_top = 0x1A2342, .sky_bot = 0x3A4470, .panel = 0x0B1322, .text = 0xFFFFFF, .accent = 0xCCD2E8 },
            .overcast, .fog => .{ .sky_top = 0x2A2F40, .sky_bot = 0x5A6080, .panel = 0x14181F, .text = 0xFFFFFF, .accent = 0xB0B6C2 },
            .rain => .{ .sky_top = 0x1B2030, .sky_bot = 0x3D475A, .panel = 0x0F141C, .text = 0xFFFFFF, .accent = 0x6FB0FF },
            .snow => .{ .sky_top = 0x2A3040, .sky_bot = 0x6A7484, .panel = 0x14181F, .text = 0xFFFFFF, .accent = 0xFFFFFF },
            .storm => .{ .sky_top = 0x141622, .sky_bot = 0x2A3050, .panel = 0x0A0C12, .text = 0xFFFFFF, .accent = 0xFFE633 },
        };
    }
}

// ---------------------------------------------------------------------
// Icon drawing — vector primitives instead of ASCII art. Sized
// relative to the canvas so resizing scales the icon proportionally.

fn drawIcon(canvas: *gfx.Canvas, x: i32, y: i32, r: i32, pal: Palette, c: weather.Conditions) void {
    const kind = weather.kindOf(c.code);
    switch (kind) {
        .clear => if (c.is_day) drawSun(canvas, x, y, r) else drawMoon(canvas, x, y, r, pal),
        .partly_cloudy => {
            const sx = x - @divTrunc(r, 3);
            const sy = y - @divTrunc(r, 4);
            const sr = @divTrunc(r * 7, 10);
            if (c.is_day) drawSun(canvas, sx, sy, sr) else drawMoon(canvas, sx, sy, sr, pal);
            drawCloud(canvas, x + @divTrunc(r, 4), y + @divTrunc(r, 6), @divTrunc(r * 9, 10), 0xF0F2F5, 0xC8CCD2);
        },
        .overcast => drawCloud(canvas, x, y, r, 0xDDE0E6, 0xB0B5BC),
        .fog => drawFog(canvas, x, y, r, 0xD0D5DC),
        .rain => {
            drawCloud(canvas, x, y - @divTrunc(r, 6), r, 0xB8BEC8, 0x8E94A0);
            drawRain(canvas, x, y + @divTrunc(r, 2), r);
        },
        .snow => {
            drawCloud(canvas, x, y - @divTrunc(r, 6), r, 0xD0D6DE, 0xA0A6AE);
            drawSnow(canvas, x, y + @divTrunc(r, 2), r);
        },
        .storm => {
            drawCloud(canvas, x, y - @divTrunc(r, 6), r, 0x5A6276, 0x3E4458);
            drawBolt(canvas, x, y + @divTrunc(r, 2), r);
        },
    }
}

fn drawSun(canvas: *gfx.Canvas, cx: i32, cy: i32, r: i32) void {
    // 8 rays.
    const ray_r: i32 = r + 18;
    const ray_inner: i32 = r + 6;
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        const ang_q16 = @as(i32, @intCast(i * 8192)); // i * (65536 / 8)
        const sx = sin_q16(ang_q16);
        const cs = cos_q16(ang_q16);
        const x0 = cx + @divTrunc(cs * ray_inner, 65536);
        const y0 = cy + @divTrunc(sx * ray_inner, 65536);
        const x1 = cx + @divTrunc(cs * ray_r, 65536);
        const y1 = cy + @divTrunc(sx * ray_r, 65536);
        canvas.drawLineAA(x0, y0, x1, y1, 0xFFD840);
    }
    canvas.fillCircle(cx, cy, @intCast(r), 0xFFC940);
    canvas.fillCircle(cx, cy, @intCast(@divTrunc(r * 8, 10)), 0xFFE780);
}

fn drawMoon(canvas: *gfx.Canvas, cx: i32, cy: i32, r: i32, pal: Palette) void {
    // Crescent: bright disk + offset dark disk to cut a chunk.
    canvas.fillCircle(cx, cy, @intCast(r), 0xF0F3F8);
    canvas.fillCircle(cx + @divTrunc(r, 3), cy - @divTrunc(r, 8), @intCast(r), pal.sky_top);
    // A few stars sprinkled.
    drawStar(canvas, cx + r * 2, cy - r);
    drawStar(canvas, cx - r * 2, cy);
    drawStar(canvas, cx + r * 2 + @divTrunc(r, 2), cy + r);
    drawStar(canvas, cx - @divTrunc(r * 3, 2), cy - @divTrunc(r * 3, 2));
}

fn drawStar(canvas: *gfx.Canvas, cx: i32, cy: i32) void {
    canvas.fillCircle(cx, cy, 1, 0xFFFFFF);
    canvas.putPixel(cx + 2, cy, 0xCDDCFF);
    canvas.putPixel(cx - 2, cy, 0xCDDCFF);
    canvas.putPixel(cx, cy + 2, 0xCDDCFF);
    canvas.putPixel(cx, cy - 2, 0xCDDCFF);
}

fn drawCloud(canvas: *gfx.Canvas, cx: i32, cy: i32, r: i32, light: u32, mid: u32) void {
    const lobe_r: i32 = @divTrunc(r * 5, 10);
    const q = @divTrunc(lobe_r, 4);
    const half = @divTrunc(lobe_r, 2);
    const third = @divTrunc(lobe_r, 3);
    canvas.fillCircle(cx - lobe_r, cy + q, @intCast(lobe_r), mid);
    canvas.fillCircle(cx + lobe_r, cy + q, @intCast(lobe_r), mid);
    canvas.fillCircle(cx - half, cy - third, @intCast(@divTrunc(lobe_r * 11, 10)), light);
    canvas.fillCircle(cx + half, cy - third, @intCast(lobe_r), light);
    // Flat base.
    const base_w: u32 = @intCast(lobe_r * 4);
    const base_h: u32 = @intCast(@divTrunc(lobe_r * 3, 5));
    const bx: i32 = cx - @as(i32, @intCast(base_w / 2));
    const by: i32 = cy + q;
    canvas.fillRect(@intCast(@max(0, bx)), @intCast(@max(0, by)), base_w, base_h, mid);
}

fn drawFog(canvas: *gfx.Canvas, cx: i32, cy: i32, r: i32, color: u32) void {
    const w: u32 = @intCast(r * 2);
    const x0 = cx - r;
    var i: i32 = -2;
    while (i <= 2) : (i += 1) {
        const dy = cy + i * (@divTrunc(r, 4));
        canvas.fillRect(@intCast(@max(0, x0)), @intCast(@max(0, dy)), w, 4, color);
    }
}

fn drawRain(canvas: *gfx.Canvas, cx: i32, cy: i32, r: i32) void {
    var i: i32 = -3;
    while (i <= 3) : (i += 1) {
        const dx = cx + i * (@divTrunc(r, 4)) + (if (@mod(i, 2) == 0) @as(i32, 0) else @as(i32, 2));
        const dy = cy + (if (@mod(i, 2) == 0) @as(i32, 0) else @as(i32, 8));
        canvas.drawLineAA(dx, dy, dx - 4, dy + 14, 0x6FB0FF);
    }
}

fn drawSnow(canvas: *gfx.Canvas, cx: i32, cy: i32, r: i32) void {
    var i: i32 = -2;
    while (i <= 2) : (i += 1) {
        const dx = cx + i * (@divTrunc(r, 3));
        const dy_a = cy + 2;
        const dy_b = cy + 16;
        canvas.fillCircle(dx, dy_a, 2, 0xFFFFFF);
        if (i != -2 and i != 2) canvas.fillCircle(dx + @divTrunc(r, 6), dy_b, 2, 0xFFFFFF);
    }
}

fn drawBolt(canvas: *gfx.Canvas, cx: i32, cy: i32, r: i32) void {
    const w: i32 = @divTrunc(r, 5);
    // Zig-zag in two strokes for a chunkier bolt.
    canvas.drawLineAA(cx - w, cy - 4, cx, cy + 4, 0xFFE633);
    canvas.drawLineAA(cx, cy + 4, cx - w + 2, cy + 4, 0xFFE633);
    canvas.drawLineAA(cx - w + 2, cy + 4, cx + w, cy + 18, 0xFFE633);
    // Second thicker stroke for emphasis.
    canvas.drawLineAA(cx - w + 1, cy - 4, cx + 1, cy + 4, 0xFFEF66);
    canvas.drawLineAA(cx + 1, cy + 4, cx - w + 3, cy + 4, 0xFFEF66);
    canvas.drawLineAA(cx - w + 3, cy + 4, cx + w + 1, cy + 18, 0xFFEF66);
}

// ---------------------------------------------------------------------
// Crude sine/cosine in Q16 fixed point. Input is angle * (65536/2π),
// so a full circle is 65536. ~0.5% error from the third-order Taylor
// truncation; plenty for centering 8 rays.

fn sin_q16(angle_q16: i32) i32 {
    // Map angle into [-32768, 32768] by mod 65536.
    var a = @mod(angle_q16, 65536);
    if (a > 32768) a -= 65536;
    // Reflect to [-16384, 16384].
    if (a > 16384) a = 32768 - a;
    if (a < -16384) a = -32768 - a;
    // Now a in [-π/2, π/2] * (65536/2π). Use 5-term Taylor.
    const x: i64 = a;
    const x2: i64 = @divTrunc(x * x, 65536);
    const x3: i64 = @divTrunc(x2 * x, 65536);
    const x5: i64 = @divTrunc(x3 * x2, 65536);
    const t1: i64 = @divTrunc(x3 * 10746, 65536); // x - x^3 * (1/6 * 2π)
    const t2: i64 = @divTrunc(x5 * 5371, 65536);
    return @intCast(x - t1 + @divTrunc(t2, 2));
}

fn cos_q16(angle_q16: i32) i32 {
    return sin_q16(angle_q16 + 16384);
}

// ---------------------------------------------------------------------
// Layout + draw.

fn drawAll(canvas: *gfx.Canvas) void {
    const pal = if (cond_loaded) paletteFor(cond) else Palette{
        .sky_top = 0x4DA6E0,
        .sky_bot = 0xB8DCF2,
        .panel = 0x1A2540,
        .text = 0xFFFFFF,
        .accent = 0xFFC940,
    };

    const panel_h: u32 = vis_h / 3;
    const sky_h: u32 = vis_h - panel_h;

    // Sky gradient.
    ui.verticalGradient(canvas, 0, 0, vis_w, sky_h, pal.sky_top, pal.sky_bot);
    // Panel.
    canvas.fillRect(0, sky_h, vis_w, panel_h, pal.panel);

    if (cond_loaded) {
        // Icon centered in sky area.
        const ix: i32 = @intCast(vis_w / 2);
        const iy: i32 = @intCast(sky_h / 2);
        const r: i32 = @intCast(@min(sky_h / 4, vis_w / 6));
        drawIcon(canvas, ix, iy, r, pal, cond);

        // Info text in panel. Rendered via the AA atlas (same path
        // about.elf uses); the atlas falls back to a half-em gap on
        // out-of-range bytes, so non-ASCII city names are safe.
        const tx: i32 = 14;
        var ty: i32 = @intCast(sky_h + 10);
        fa.drawText(canvas, tx, ty, cond.location[0..cond.location_len], pal.text, &fa.default_16);
        ty += 22;

        // Temp big — 24-pt AA.
        var temp_buf: [16]u8 = undefined;
        const tb = formatTemp(&temp_buf, cond.temp_c);
        fa.drawText(canvas, tx, ty, tb, pal.accent, &fa.default_24);
        ty += 30;

        // Condition.
        fa.drawText(canvas, tx, ty, weather.weatherName(cond.code), 0xC4D0E0, &fa.default_16);
        ty += 20;

        // Humidity + wind.
        var info_buf: [64]u8 = undefined;
        const info = formatInfo(&info_buf, cond.humidity, cond.wind_kmh);
        fa.drawText(canvas, tx, ty, info, 0xA0A8B8, &fa.default_16);
    } else {
        const iy: i32 = @intCast(sky_h / 2);
        fa.drawTextCentered(canvas, 0, iy, vis_w, "loading...", 0xFFFFFF, &fa.default_16);
        if (last_error) |e| {
            fa.drawTextCentered(canvas, 0, @intCast(sky_h + 16), vis_w, "fetch failed:", 0xFF8080, &fa.default_16);
            fa.drawTextCentered(canvas, 0, @intCast(sky_h + 32), vis_w, e, 0xFF8080, &fa.default_16);
        }
    }

    // Footer hint.
    const hint = "R: refresh   Esc: quit";
    fa.drawTextCentered(canvas, 0, @intCast(vis_h -| 14), vis_w, hint, 0x808898, &fa.default_16);
}

fn formatTemp(buf: []u8, t: f64) []const u8 {
    var pos: usize = 0;
    var v = t;
    if (v < 0) {
        buf[pos] = '-';
        pos += 1;
        v = -v;
    }
    const int_part: u32 = @intFromFloat(v);
    pos += writeU32(buf[pos..], int_part);
    buf[pos] = '.';
    pos += 1;
    var frac = v - @as(f64, @floatFromInt(int_part));
    frac *= 10;
    const d: u8 = @intFromFloat(frac);
    buf[pos] = '0' + d;
    pos += 1;
    // Degree sign at codepoint 0xB0. font_atlas falls back to a
    // half-em gap on out-of-range bytes, so this is safe even if the
    // atlas happens to be missing it.
    const suffix = " \xB0C";
    @memcpy(buf[pos..][0..suffix.len], suffix);
    pos += suffix.len;
    return buf[0..pos];
}

fn formatInfo(buf: []u8, humidity: u8, wind_kmh: f64) []const u8 {
    var pos: usize = 0;
    const h_label = "humidity ";
    @memcpy(buf[pos..][0..h_label.len], h_label);
    pos += h_label.len;
    pos += writeU32(buf[pos..], humidity);
    buf[pos] = '%';
    pos += 1;
    const sep = "   wind ";
    @memcpy(buf[pos..][0..sep.len], sep);
    pos += sep.len;
    var v = wind_kmh;
    if (v < 0) v = 0;
    const int_part: u32 = @intFromFloat(v);
    pos += writeU32(buf[pos..], int_part);
    buf[pos] = '.';
    pos += 1;
    var frac = v - @as(f64, @floatFromInt(int_part));
    frac *= 10;
    const d: u8 = @intFromFloat(frac);
    buf[pos] = '0' + d;
    pos += 1;
    const kmh = " km/h";
    @memcpy(buf[pos..][0..kmh.len], kmh);
    pos += kmh.len;
    return buf[0..pos];
}

fn writeU32(out: []u8, n: u32) usize {
    var v = n;
    var tmp: [10]u8 = undefined;
    var i: usize = tmp.len;
    if (v == 0) {
        i -= 1;
        tmp[i] = '0';
    } else {
        while (v != 0) {
            i -= 1;
            tmp[i] = @intCast('0' + (v % 10));
            v /= 10;
        }
    }
    const len = tmp.len - i;
    @memcpy(out[0..len], tmp[i..]);
    return len;
}

// ---------------------------------------------------------------------

export fn _start() linksection(".text.entry") callconv(.c) void {
    // Parse city (joins argv[1..]).
    city_len = 0;
    if (libc.getArgc() >= 2) {
        var i: u32 = 1;
        while (i < libc.getArgc()) : (i += 1) {
            var tmp: [64]u8 = undefined;
            const part = copyArg(i, &tmp) orelse continue;
            if (city_len != 0 and city_len + 1 < city_buf.len) {
                city_buf[city_len] = ' ';
                city_len += 1;
            }
            const want = @min(part.len, city_buf.len - city_len);
            @memcpy(city_buf[city_len..][0..want], part[0..want]);
            city_len += want;
        }
    }
    if (city_len == 0) {
        @memcpy(city_buf[0..DEFAULT_CITY.len], DEFAULT_CITY);
        city_len = DEFAULT_CITY.len;
    }

    const scr = libc.getScreenSize();
    alloc_w = @min(INIT_W * 2, scr.w);
    alloc_h = @min(INIT_H * 2, scr.h);

    const win = libc.createWindowEx(alloc_w, alloc_h, INIT_W, INIT_H) orelse {
        libc.exit();
    };
    alloc_w = win.alloc_w;
    alloc_h = win.alloc_h;
    var canvas = gfx.Canvas.init(win.fb, alloc_w, alloc_h);

    // First fetch.
    reload();
    drawAll(&canvas);
    libc.present();

    var needs_redraw: bool = false;
    while (true) {
        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => {
                    libc.destroyWindow();
                    libc.exit();
                },
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (ch == 0x1B) {
                        libc.destroyWindow();
                        libc.exit();
                    }
                    if (ch == 'r' or ch == 'R') {
                        cond_loaded = false;
                        last_error = null;
                        drawAll(&canvas);
                        libc.present();
                        reload();
                        needs_redraw = true;
                    }
                },
                .resize => {
                    const new_w = @min(ev.a, alloc_w);
                    const new_h = @min(ev.b, alloc_h);
                    if (new_w != vis_w or new_h != vis_h) {
                        vis_w = new_w;
                        vis_h = new_h;
                        needs_redraw = true;
                    }
                },
                else => {},
            }
        }

        if (needs_redraw) {
            needs_redraw = false;
            drawAll(&canvas);
            libc.present();
        }
        libc.sleep(30);
    }
}
