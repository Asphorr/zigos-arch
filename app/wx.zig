// wx — terminal weather: a small picture of the sky, the readings beside it.
//
//   wx                 the default city
//   wx New York        the arguments are joined into one name
//   wx --icons         every picture, day and night; no network
//
// The picture is PIC_W by PIC_H pixels, two to a terminal cell: an upper
// half block in the upper pixel's color on a background of the lower one's.
// A cell is twice as tall as it is wide, so the pixels are square. A pixel
// is the mean of SS x SS samples of the scene, which is what rounds the
// discs and the clouds.

const std = @import("std");
const libc = @import("libc");
const weather = @import("weather");

const DEFAULT_CITY: []const u8 = "Berlin";

const PIC_W = 30;
const PIC_H = 16;
const PIC_ROWS = PIC_H / 2;
const SS = 4;

/// A pixel that shows the terminal through: the picture's corners.
const CLEAR: u32 = 0xFFFF_FFFF;
/// 0xRRGGBB or CLEAR.
const Picture = [PIC_H][PIC_W]u32;

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const UPPER_HALF = "\u{2580}";
const LOWER_HALF = "\u{2584}";

// --- The scene -------------------------------------------------------------

const Rgb = struct {
    r: f32,
    g: f32,
    b: f32,

    fn hex(v: u24) Rgb {
        return .{ .r = @floatFromInt(v >> 16), .g = @floatFromInt((v >> 8) & 0xFF), .b = @floatFromInt(v & 0xFF) };
    }

    fn mix(a: Rgb, b: Rgb, t: f32) Rgb {
        return .{ .r = a.r + (b.r - a.r) * t, .g = a.g + (b.g - a.g) * t, .b = a.b + (b.b - a.b) * t };
    }
};

/// 0 up to e0, 1 from e1, an S-curve between.
fn smooth(e0: f32, e1: f32, x: f32) f32 {
    const t = std.math.clamp((x - e0) / (e1 - e0), 0, 1);
    return t * t * (3 - 2 * t);
}

fn dist(x: f32, y: f32, cx: f32, cy: f32) f32 {
    return @sqrt((x - cx) * (x - cx) + (y - cy) * (y - cy));
}

fn inDisc(x: f32, y: f32, cx: f32, cy: f32, r: f32) bool {
    return (x - cx) * (x - cx) + (y - cy) * (y - cy) <= r * r;
}

/// How far (x, y) is from the segment a-b.
fn segDist(x: f32, y: f32, ax: f32, ay: f32, bx: f32, by: f32) f32 {
    const vx = bx - ax;
    const vy = by - ay;
    const t = std.math.clamp(((x - ax) * vx + (y - ay) * vy) / (vx * vx + vy * vy), 0, 1);
    return dist(x, y, ax + vx * t, ay + vy * t);
}

const Point = struct { x: f32, y: f32 };
/// A point with a size or a brightness.
const Dot = struct { x: f32, y: f32, v: f32 };

/// Round lobes over a flat-bottomed bar with round ends, x0..x1 by y0..y1.
const Cloud = struct {
    lobes: []const Dot,
    x0: f32,
    x1: f32,
    y0: f32,
    y1: f32,
    /// The top of the highest lobe.
    top: f32,

    fn init(comptime lobes: []const Dot, x0: f32, x1: f32, y0: f32, y1: f32) Cloud {
        var top: f32 = y0;
        for (lobes) |l| top = @min(top, l.y - l.v);
        return .{ .lobes = lobes, .x0 = x0, .x1 = x1, .y0 = y0, .y1 = y1, .top = top };
    }

    fn has(c: *const Cloud, x: f32, y: f32) bool {
        if (y > c.y1) return false;
        for (c.lobes) |l| {
            if (inDisc(x, y, l.x, l.y, l.v)) return true;
        }
        if (y < c.y0) return false;
        const r = (c.y1 - c.y0) / 2;
        if (x >= c.x0 + r and x <= c.x1 - r) return true;
        return inDisc(x, y, c.x0 + r, c.y0 + r, r) or inDisc(x, y, c.x1 - r, c.y0 + r, r);
    }
};

const CLOUD_BIG = Cloud.init(&.{
    .{ .x = 3.2, .y = 4.3, .v = 2.3 }, .{ .x = 6.6, .y = 3.0, .v = 3.0 },
    .{ .x = 10.4, .y = 3.9, .v = 2.6 }, .{ .x = 13.0, .y = 5.0, .v = 1.8 },
}, 1.6, 14.4, 4.6, 6.8);
const CLOUD_SMALL = Cloud.init(&.{
    .{ .x = 2.4, .y = 3.2, .v = 1.7 }, .{ .x = 4.9, .y = 2.3, .v = 2.2 }, .{ .x = 7.6, .y = 3.2, .v = 1.7 },
}, 1.2, 8.9, 3.3, 4.9);

// Stars sit on pixel centers; `v` is how bright.
const STARS = [_]Dot{
    .{ .x = 2.5, .y = 1.5, .v = 1.0 },    .{ .x = 7.5, .y = 3.5, .v = 0.55 },  .{ .x = 13.5, .y = 1.5, .v = 0.7 },
    .{ .x = 19.5, .y = 2.5, .v = 1.0 },   .{ .x = 25.5, .y = 1.5, .v = 0.6 },  .{ .x = 27.5, .y = 5.5, .v = 0.9 },
    .{ .x = 22.5, .y = 7.5, .v = 0.5 },   .{ .x = 4.5, .y = 8.5, .v = 0.6 },   .{ .x = 1.5, .y = 12.5, .v = 0.8 },
    .{ .x = 17.5, .y = 11.5, .v = 0.55 }, .{ .x = 24.5, .y = 12.5, .v = 0.9 }, .{ .x = 9.5, .y = 13.5, .v = 0.5 },
    .{ .x = 28.5, .y = 10.5, .v = 0.5 },  .{ .x = 15.5, .y = 6.5, .v = 0.45 },
};
// The top pixel of each drop: on the pixel grid, so that drops stay sharp.
const RAIN = [_]Point{
    .{ .x = 5, .y = 9 },  .{ .x = 8, .y = 10 }, .{ .x = 11, .y = 9 },  .{ .x = 14, .y = 10 }, .{ .x = 17, .y = 9 },
    .{ .x = 20, .y = 10 }, .{ .x = 23, .y = 9 }, .{ .x = 6, .y = 13 },  .{ .x = 9, .y = 12 },  .{ .x = 12, .y = 13 },
    .{ .x = 15, .y = 12 }, .{ .x = 18, .y = 13 }, .{ .x = 21, .y = 12 }, .{ .x = 24, .y = 13 },
};
// Flakes; `v` is the radius.
const SNOW = [_]Dot{
    .{ .x = 4.5, .y = 9.5, .v = 0.62 },   .{ .x = 8.5, .y = 11.5, .v = 0.5 },   .{ .x = 12.5, .y = 9.5, .v = 0.55 },
    .{ .x = 16.5, .y = 11.5, .v = 0.62 }, .{ .x = 20.5, .y = 9.5, .v = 0.5 },   .{ .x = 24.5, .y = 11.5, .v = 0.55 },
    .{ .x = 6.5, .y = 13.5, .v = 0.55 },  .{ .x = 10.5, .y = 14.5, .v = 0.45 }, .{ .x = 14.5, .y = 13.5, .v = 0.62 },
    .{ .x = 18.5, .y = 14.5, .v = 0.5 },  .{ .x = 22.5, .y = 13.5, .v = 0.55 }, .{ .x = 26.5, .y = 14.5, .v = 0.45 },
};
const BOLT = [_]Point{ .{ .x = 16.5, .y = 7.2 }, .{ .x = 13.5, .y = 11.0 }, .{ .x = 16.5, .y = 11.0 }, .{ .x = 13.0, .y = 15.4 } };
// Fog: bands from x0 to x1 at height y.
const FOG = [_]struct { x0: f32, x1: f32, y: f32 }{
    .{ .x0 = 3, .x1 = 22, .y = 6.0 }, .{ .x0 = 7, .x1 = 27, .y = 8.6 },
    .{ .x0 = 2, .x1 = 19, .y = 11.2 }, .{ .x0 = 9, .x1 = 26, .y = 13.8 },
};

/// One sample of a scene being painted: `c` is the color so far at (x, y).
/// The scene's parts go on back to front.
const Brush = struct {
    x: f32,
    y: f32,
    c: Rgb,

    fn over(b: *Brush, color: Rgb, alpha: f32) void {
        b.c = Rgb.mix(b.c, color, alpha);
    }

    /// A halo around (cx, cy): `alpha` up to r0, gone by r1.
    fn glow(b: *Brush, cx: f32, cy: f32, r0: f32, r1: f32, color: u24, alpha: f32) void {
        const t = 1 - smooth(r0, r1, dist(b.x, b.y, cx, cy));
        b.over(Rgb.hex(color), alpha * t * t);
    }

    fn sun(b: *Brush, cx: f32, cy: f32, r: f32, strength: f32) void {
        b.glow(cx, cy, r, r + 7, 0xFFF1B8, 0.55 * strength);
        if (inDisc(b.x, b.y, cx, cy, r))
            b.over(Rgb.mix(Rgb.hex(0xFFEE8A), Rgb.hex(0xFFB02E), smooth(cy - r, cy + r, b.y)), strength);
    }

    /// A crescent: the disc less a second one set up and to the right.
    fn moon(b: *Brush, cx: f32, cy: f32, r: f32) void {
        b.glow(cx, cy, r, r + 6, 0xAFC4FF, 0.30);
        if (inDisc(b.x, b.y, cx, cy, r) and !inDisc(b.x, b.y, cx + r * 0.52, cy - r * 0.30, r * 0.92))
            b.over(Rgb.mix(Rgb.hex(0xFFFBE6), Rgb.hex(0xD9D2B0), smooth(cy - r, cy + r, b.y)), 1);
    }

    fn stars(b: *Brush, strength: f32) void {
        for (STARS) |s| {
            if (inDisc(b.x, b.y, s.x, s.y, 0.5)) b.over(Rgb.hex(0xE8EEFF), s.v * strength);
        }
    }

    /// `shape` with its origin at (ox, oy), lit from above.
    fn cloud(b: *Brush, shape: *const Cloud, ox: f32, oy: f32, light: u24, shade: u24) void {
        const y = b.y - oy;
        if (!shape.has(b.x - ox, y)) return;
        b.over(Rgb.mix(Rgb.hex(light), Rgb.hex(shade), smooth(shape.top + 1, shape.y1 + 0.5, y)), 1);
    }

    /// Drops one pixel wide and two tall, the lower pixel the brighter.
    /// `gap` leaves out the ones where the lightning comes down.
    fn rain(b: *Brush, color: u24, alpha: f32, gap: bool) void {
        for (RAIN) |d| {
            if (gap and d.x >= 11 and d.x <= 18) continue;
            if (b.x >= d.x and b.x < d.x + 1 and b.y >= d.y and b.y < d.y + 2)
                b.over(Rgb.hex(color), if (b.y < d.y + 1) alpha * 0.45 else alpha);
        }
    }

    fn snow(b: *Brush, alpha: f32) void {
        for (SNOW) |s| {
            if (inDisc(b.x, b.y, s.x, s.y, s.v)) b.over(Rgb.hex(0xFFFFFF), alpha);
        }
    }
};

const Sky = struct { top: u24, bottom: u24 };

fn skyOf(kind: weather.Kind, day: bool) Sky {
    return if (day) switch (kind) {
        .clear => .{ .top = 0x2E7FDB, .bottom = 0x8FCBF5 },
        .partly_cloudy => .{ .top = 0x3A86D9, .bottom = 0x9BCFF3 },
        .overcast => .{ .top = 0x7C8EA3, .bottom = 0xB3BFCB },
        .fog => .{ .top = 0x9AA5AE, .bottom = 0xC9CED2 },
        .rain => .{ .top = 0x4E6178, .bottom = 0x7F93A8 },
        .snow => .{ .top = 0x8497AD, .bottom = 0xC3CFDB },
        .storm => .{ .top = 0x2B3040, .bottom = 0x4F566B },
    } else switch (kind) {
        .clear => .{ .top = 0x070B22, .bottom = 0x1B2B5C },
        .partly_cloudy => .{ .top = 0x090E26, .bottom = 0x1F2D58 },
        .overcast => .{ .top = 0x14192A, .bottom = 0x2B3348 },
        .fog => .{ .top = 0x1E232D, .bottom = 0x3A404B },
        .rain => .{ .top = 0x0E1422, .bottom = 0x25304A },
        .snow => .{ .top = 0x161C2D, .bottom = 0x38435E },
        .storm => .{ .top = 0x0B0C16, .bottom = 0x23263A },
    };
}

/// The scene's color at (x, y), in pixels from the picture's top left.
fn sample(kind: weather.Kind, day: bool, x: f32, y: f32) Rgb {
    const sky = skyOf(kind, day);
    var b = Brush{ .x = x, .y = y, .c = Rgb.mix(Rgb.hex(sky.top), Rgb.hex(sky.bottom), smooth(0, PIC_H, y)) };
    switch (kind) {
        .clear => if (day) b.sun(10.0, 7.6, 3.7, 1) else {
            b.stars(1);
            b.moon(11.0, 7.4, 3.6);
        },
        .partly_cloudy => if (day) {
            b.sun(9.5, 5.6, 3.4, 1);
            b.cloud(&CLOUD_BIG, 10.5, 5.2, 0xFFFFFF, 0xC9D6E6);
        } else {
            b.stars(0.9);
            b.moon(9.5, 5.4, 3.3);
            b.cloud(&CLOUD_BIG, 10.5, 5.2, 0x8E9AB8, 0x4A5676);
        },
        .overcast => if (day) {
            b.cloud(&CLOUD_SMALL, 15.5, 1.6, 0xD3DAE2, 0xA9B4C0);
            b.cloud(&CLOUD_BIG, 5.0, 4.6, 0xF7F9FB, 0xBCC7D3);
        } else {
            b.cloud(&CLOUD_SMALL, 15.5, 1.6, 0x5B6580, 0x3A425A);
            b.cloud(&CLOUD_BIG, 5.0, 4.6, 0x8691AD, 0x4B5571);
        },
        .fog => {
            if (day) b.sun(15.0, 5.4, 3.0, 0.55) else b.moon(15.0, 5.4, 2.9);
            const band = Rgb.hex(if (day) 0xE9EDF0 else 0x8A93A3);
            for (FOG, 0..) |f, i| {
                if (segDist(x, y, f.x0, f.y, f.x1, f.y) < 0.75) b.over(band, if (i % 2 == 0) 0.80 else 0.55);
            }
        },
        .rain => if (day) {
            b.cloud(&CLOUD_BIG, 7.0, 0.6, 0xD5DCE5, 0x8794A6);
            b.rain(0x9CC8FF, 0.85, false);
        } else {
            b.cloud(&CLOUD_BIG, 7.0, 0.6, 0x7A859F, 0x434C66);
            b.rain(0x7FA9E8, 0.80, false);
        },
        .snow => if (day) {
            b.cloud(&CLOUD_BIG, 7.0, 0.6, 0xF4F7FA, 0xA9B6C6);
            b.snow(0.95);
        } else {
            b.cloud(&CLOUD_BIG, 7.0, 0.6, 0x8B96B0, 0x4B5570);
            b.snow(0.85);
        },
        .storm => {
            var d: f32 = std.math.floatMax(f32);
            for (BOLT[0 .. BOLT.len - 1], BOLT[1..]) |p, q| d = @min(d, segDist(x, y, p.x, p.y, q.x, q.y));
            // The flash lights the sky behind the cloud; the bolt itself
            // goes on last, over the rain.
            const halo = 1 - smooth(0.4, 3.2, d);
            b.over(Rgb.hex(0xFFE98A), 0.22 * halo * halo);
            if (day) b.cloud(&CLOUD_BIG, 7.0, 0.6, 0x8E96A8, 0x454B5E) else b.cloud(&CLOUD_BIG, 7.0, 0.6, 0x5E6680, 0x2A2F42);
            b.rain(0x8FB4EE, 0.6, true);
            if (d < 0.55) b.over(Rgb.mix(Rgb.hex(0xFFF7C2), Rgb.hex(0xFFD23F), smooth(7.0, 15.5, y)), 1);
        },
    }
    return b.c;
}

fn channel(sum: f32) u32 {
    return @intFromFloat(std.math.clamp(@round(sum / (SS * SS)), 0, 255));
}

fn render(kind: weather.Kind, day: bool, pic: *Picture) void {
    for (pic, 0..) |*row, j| {
        for (row, 0..) |*px, i| {
            if ((i == 0 or i == PIC_W - 1) and (j == 0 or j == PIC_H - 1)) {
                px.* = CLEAR;
                continue;
            }
            var sum = Rgb{ .r = 0, .g = 0, .b = 0 };
            for (0..SS) |sj| {
                for (0..SS) |si| {
                    const c = sample(
                        kind,
                        day,
                        @as(f32, @floatFromInt(i)) + (@as(f32, @floatFromInt(si)) + 0.5) / SS,
                        @as(f32, @floatFromInt(j)) + (@as(f32, @floatFromInt(sj)) + 0.5) / SS,
                    );
                    sum = .{ .r = sum.r + c.r, .g = sum.g + c.g, .b = sum.b + c.b };
                }
            }
            px.* = (channel(sum.r) << 16) | (channel(sum.g) << 8) | channel(sum.b);
        }
    }
}

// --- Output ----------------------------------------------------------------

/// Text gathered and written a row at a time.
const Out = struct {
    buf: [2048]u8 = undefined,
    len: usize = 0,

    fn flush(o: *Out) void {
        libc.print(o.buf[0..o.len]);
        o.len = 0;
    }

    fn str(o: *Out, s: []const u8) void {
        if (o.len + s.len > o.buf.len) o.flush();
        const n = @min(s.len, o.buf.len);
        @memcpy(o.buf[o.len..][0..n], s[0..n]);
        o.len += n;
    }

    fn num(o: *Out, n: u64) void {
        var tmp: [20]u8 = undefined;
        var i: usize = tmp.len;
        var v = n;
        while (true) {
            i -= 1;
            tmp[i] = @intCast('0' + v % 10);
            v /= 10;
            if (v == 0) break;
        }
        o.str(tmp[i..]);
    }

    /// `v` to one decimal.
    fn fixed1(o: *Out, v: f64) void {
        const tenths: i64 = @intFromFloat(@round(std.math.clamp(v, -9999, 9999) * 10));
        if (tenths < 0) o.str("-");
        const a: u64 = @abs(tenths);
        o.num(a / 10);
        o.str(".");
        o.num(a % 10);
    }

    /// Foreground ('3') or background ('4') to `rgb`.
    fn color(o: *Out, layer: u8, rgb: u32) void {
        o.str("\x1b[");
        o.str(&.{layer});
        o.str("8;2;");
        o.num(rgb >> 16);
        o.str(";");
        o.num((rgb >> 8) & 0xFF);
        o.str(";");
        o.num(rgb & 0xFF);
        o.str("m");
    }

    fn fg(o: *Out, rgb: u32) void {
        o.color('3', rgb);
    }
};

/// Cell row `row` of the picture, the colors reset after it.
fn pictureRow(o: *Out, pic: *const Picture, row: usize) void {
    // The colors in force.
    var fg: u32 = CLEAR;
    var bg: u32 = CLEAR;
    for (0..PIC_W) |i| {
        const upper = pic[row * 2][i];
        const lower = pic[row * 2 + 1][i];
        // A pixel that is clear leaves the default background in its half.
        var glyph: []const u8 = " ";
        var want_fg = fg;
        var want_bg = CLEAR;
        if (upper != CLEAR) {
            glyph = UPPER_HALF;
            want_fg = upper;
            want_bg = lower;
        } else if (lower != CLEAR) {
            glyph = LOWER_HALF;
            want_fg = lower;
        }
        if (want_bg != bg) {
            if (want_bg == CLEAR) o.str("\x1b[49m") else o.color('4', want_bg);
            bg = want_bg;
        }
        if (want_fg != fg) {
            o.fg(want_fg);
            fg = want_fg;
        }
        o.str(glyph);
    }
    o.str(RESET);
}

const LABEL: u32 = 0x8A8A8A;
const VALUE: u32 = 0xC8C8C8;

/// Cold reads blue, warm amber.
fn tempColor(t: f64) u32 {
    if (t < -10) return 0x8FB8FF;
    if (t < 0) return 0x8CC8FF;
    if (t < 10) return 0xA6DDE6;
    if (t < 20) return 0xFFE08A;
    if (t < 28) return 0xFFBE55;
    return 0xFF8F5A;
}

/// The wind's name by where it blows from.
fn compass(deg: u16) []const u8 {
    const names = [8][]const u8{ "N", "NE", "E", "SE", "S", "SW", "W", "NW" };
    return names[((@as(u32, deg) * 2 + 45) / 90) % 8];
}

/// What stands beside cell row `row` of the picture.
fn readingsRow(o: *Out, c: *const weather.Conditions, row: usize) void {
    switch (row) {
        1 => {
            o.str(BOLD);
            o.fg(0xFFFFFF);
            o.str(c.location[0..c.location_len]);
        },
        3 => {
            o.str(BOLD);
            o.fg(tempColor(c.temp_c));
            o.fixed1(c.temp_c);
            o.str(" \u{00B0}C" ++ RESET ++ "  ");
            o.fg(VALUE);
            o.str(weather.weatherName(c.code));
        },
        4 => {
            o.fg(LABEL);
            o.str("feels like ");
            o.fg(VALUE);
            o.fixed1(c.feels_c);
            o.str(" \u{00B0}C");
        },
        6 => {
            o.fg(LABEL);
            o.str("humidity ");
            o.fg(VALUE);
            o.num(c.humidity);
            o.str("%   ");
            o.fg(LABEL);
            o.str("wind ");
            o.fg(VALUE);
            o.fixed1(c.wind_kmh);
            o.str(" km/h");
            if (c.wind_kmh >= 1) {
                o.str(" ");
                o.str(compass(c.wind_from_deg));
            }
        },
        else => return,
    }
    o.str(RESET);
}

fn report(c: *const weather.Conditions) void {
    var pic: Picture = undefined;
    render(weather.kindOf(c.code), c.is_day, &pic);
    var o = Out{};
    o.str("\n");
    for (0..PIC_ROWS) |row| {
        o.str("  ");
        pictureRow(&o, &pic, row);
        o.str("   ");
        readingsRow(&o, c, row);
        o.str("\n");
        o.flush();
    }
    o.str("\n");
    o.flush();
}

/// Every picture: day on the left, night on the right.
fn gallery() void {
    const kinds = [_]struct { kind: weather.Kind, name: []const u8 }{
        .{ .kind = .clear, .name = "Clear" },
        .{ .kind = .partly_cloudy, .name = "Partly cloudy" },
        .{ .kind = .overcast, .name = "Overcast" },
        .{ .kind = .fog, .name = "Fog" },
        .{ .kind = .rain, .name = "Rain" },
        .{ .kind = .snow, .name = "Snow" },
        .{ .kind = .storm, .name = "Thunderstorm" },
    };
    var day: Picture = undefined;
    var night: Picture = undefined;
    var o = Out{};
    for (kinds) |k| {
        render(k.kind, true, &day);
        render(k.kind, false, &night);
        o.str("\n");
        for (0..PIC_ROWS) |row| {
            o.str("  ");
            pictureRow(&o, &day, row);
            o.str("  ");
            pictureRow(&o, &night, row);
            if (row == PIC_ROWS / 2 - 1) {
                o.str("  ");
                o.fg(VALUE);
                o.str(k.name);
                o.str(RESET);
            }
            o.str("\n");
            o.flush();
        }
    }
    o.str("\n");
    o.flush();
}

fn copyArg(idx: u32, buf: []u8) ?[]u8 {
    const n = libc.getArgv(idx, buf);
    if (n == 0 or n == 0xFFFFFFFF) return null;
    return buf[0..n];
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var city_buf: [128]u8 = undefined;
    var city: []const u8 = DEFAULT_CITY;

    if (libc.getArgc() >= 2) {
        // Join argv[1..] with spaces so `wx New York` works without quotes.
        var pos: usize = 0;
        var i: u32 = 1;
        while (i < libc.getArgc()) : (i += 1) {
            var tmp: [64]u8 = undefined;
            const part = copyArg(i, &tmp) orelse continue;
            if (i == 1 and std.mem.eql(u8, part, "--icons")) {
                gallery();
                libc.exit();
            }
            if (pos != 0 and pos + 1 < city_buf.len) {
                city_buf[pos] = ' ';
                pos += 1;
            }
            const want = @min(part.len, city_buf.len - pos);
            @memcpy(city_buf[pos..][0..want], part[0..want]);
            pos += want;
        }
        if (pos > 0) city = city_buf[0..pos];
    }

    var o = Out{};
    o.str("\n  ");
    o.fg(LABEL);
    o.str("fetching ");
    o.str(city);
    o.str(" ..." ++ RESET ++ "\n");
    o.flush();

    var c: weather.Conditions = undefined;
    weather.fetch(city, &c) catch |err| {
        o.str("\x1b[31m  wx: failed: ");
        o.str(@errorName(err));
        o.str(RESET ++ "\n");
        o.flush();
        libc.exit();
    };

    // The report takes the place of the two lines above: the second is
    // wiped, the cursor goes back to the first.
    o.str("\x1b[1A\x1b[2K\x1b[1A");
    o.flush();
    report(&c);
    libc.exit();
}
