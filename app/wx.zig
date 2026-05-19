// wx — terminal weather. Fetches current conditions for a city and
// prints a colored ASCII-art icon plus the temp/condition/humidity/wind.
//
// Usage:
//   wx                       use default city (Berlin)
//   wx London                multi-word names: wx "New York"
//   wx Tokyo
//
// Icons branch on (weather_kind, is_day) so a clear sky at night gets
// the moon-and-stars treatment instead of a sun. Block-element glyphs
// (0x80-0x8F) draw the cloud bodies; rain/snow/lightning are plain
// ASCII.

const std = @import("std");
const libc = @import("libc");
const weather = @import("weather");

const DEFAULT_CITY: []const u8 = "Berlin";

fn copyArg(idx: u32, buf: []u8) ?[]u8 {
    const n = libc.getArgv(idx, buf);
    if (n == 0 or n == 0xFFFFFFFF) return null;
    return buf[0..n];
}

// ---------------------------------------------------------------------
// ANSI color helpers. We use the truecolor 24-bit form everywhere
// (terminal.zig supports it) so palette mode doesn't shift the look.

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

fn fg(r: u8, g: u8, b: u8) void {
    var buf: [24]u8 = undefined;
    var pos: usize = 0;
    const prefix = "\x1b[38;2;";
    @memcpy(buf[pos..][0..prefix.len], prefix);
    pos += prefix.len;
    pos += writeU8(buf[pos..], r);
    buf[pos] = ';';
    pos += 1;
    pos += writeU8(buf[pos..], g);
    buf[pos] = ';';
    pos += 1;
    pos += writeU8(buf[pos..], b);
    buf[pos] = 'm';
    pos += 1;
    libc.print(buf[0..pos]);
}

fn writeU8(out: []u8, n: u8) usize {
    var v: u32 = n;
    var tmp: [3]u8 = undefined;
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

// Palettes (named so they compose cleanly per icon).
fn sunColor() void {
    fg(255, 200, 50);
}
fn rayColor() void {
    fg(255, 230, 130);
}
fn moonColor() void {
    fg(240, 240, 245);
}
fn starColor() void {
    fg(180, 220, 255);
}
fn cloudLight() void {
    fg(220, 220, 220);
}
fn cloudMid() void {
    fg(170, 170, 175);
}
fn cloudDark() void {
    fg(110, 110, 120);
}
fn rainColor() void {
    fg(110, 170, 255);
}
fn snowColor() void {
    fg(240, 250, 255);
}
fn boltColor() void {
    fg(255, 230, 70);
}
fn fogColor() void {
    fg(190, 195, 200);
}

// ---------------------------------------------------------------------
// Icons. Each one ends with a RESET on its own line. Width ~24 cols.

fn iconClearDay() void {
    // Sun with a generous halo of rays. Sun body uses full blocks for a
    // solid disc; the ▒ rim softens its edge. Eight rays spaced around it.
    rayColor();
    libc.print("       \\    .    /\n");
    libc.print("        \\   .   /\n");
    sunColor();
    libc.print("          \x82\x80\x80\x82\n");
    rayColor();
    libc.print("    ──── ");
    sunColor();
    libc.print("\x80\x80\x80\x80\x80\x80");
    rayColor();
    libc.print(" ────\n");
    sunColor();
    libc.print("         \x80\x80\x80\x80\x80\x80\n");
    rayColor();
    libc.print("    ──── ");
    sunColor();
    libc.print("\x80\x80\x80\x80\x80\x80");
    rayColor();
    libc.print(" ────\n");
    sunColor();
    libc.print("          \x82\x80\x80\x82\n");
    rayColor();
    libc.print("        /   '   \\\n");
    libc.print("       /    .    \\\n");
    libc.print(RESET);
}

fn iconClearNight() void {
    // Dense starfield — varied star glyphs (· small, . tiny, * medium, '
    // faint accent) scattered with irregular spacing so it doesn't read
    // as a grid. The crescent moon sits in the middle: full blocks for
    // the lit face, ▓/▒ on the dark edge to suggest a curved 3-D limb.
    starColor();
    libc.print("  ");
    libc.print(BOLD);
    libc.print("·");
    libc.print(RESET);
    starColor();
    libc.print("    ");
    libc.print(BOLD);
    libc.print("*");
    libc.print(RESET);
    starColor();
    libc.print("      .       '         ");
    libc.print(BOLD);
    libc.print("·");
    libc.print(RESET);
    libc.print("\n");
    starColor();
    libc.print("        .                   .\n");
    libc.print("  ");
    libc.print(BOLD);
    libc.print("*");
    libc.print(RESET);
    starColor();
    libc.print("       ·     '    ·           ");
    libc.print(BOLD);
    libc.print("*");
    libc.print(RESET);
    libc.print("\n");
    moonColor();
    libc.print("            \x82\x83\x80\x80\x82\n");
    libc.print("           \x82\x80\x80\x80\x80\x80\n");
    libc.print("           \x82\x80\x80\x80\x80\x83\n");
    libc.print("            \x82\x80\x80\x80\x82\n");
    libc.print("             \x82\x83\x83\x82\n");
    starColor();
    libc.print("  ");
    libc.print(BOLD);
    libc.print("*");
    libc.print(RESET);
    starColor();
    libc.print("    .          ·            ");
    libc.print(BOLD);
    libc.print("·");
    libc.print(RESET);
    libc.print("\n");
    libc.print(RESET);
}

fn iconPartlyCloudyDay() void {
    rayColor();
    libc.print("    \\   .\n");
    sunColor();
    libc.print("     \x80\x80\x80\n");
    rayColor();
    libc.print("   ─ ");
    sunColor();
    libc.print("\x80\x80\x80\x80\x80   ");
    cloudLight();
    libc.print("\x82\x82\x82\n");
    rayColor();
    libc.print("     ");
    sunColor();
    libc.print("\x80\x80\x80");
    cloudLight();
    libc.print("  \x82\x82\x82\x82\x82\x82\x82\n");
    cloudMid();
    libc.print("        \x83\x82\x82\x82\x82\x82\x82\x82\n");
    cloudLight();
    libc.print("         \x82\x82\x82\x82\x82\n");
    libc.print(RESET);
}

fn iconPartlyCloudyNight() void {
    // Crescent moon peeking through a low cloud bank, surrounded by stars.
    // Top two rows = sky/stars; middle three rows = moon on the left + a
    // mid-tone cloud forming on the right; bottom rows = denser cloud body
    // and a final scatter of star accents to balance the frame.
    starColor();
    libc.print("    .       '         ·            ");
    libc.print(BOLD);
    libc.print("*");
    libc.print(RESET);
    libc.print("\n");
    starColor();
    libc.print("  ");
    libc.print(BOLD);
    libc.print("*");
    libc.print(RESET);
    starColor();
    libc.print("                   .\n");
    moonColor();
    libc.print("       \x82\x80\x80\x82                 .\n");
    libc.print("      \x82\x80\x80\x80\x80    ");
    cloudLight();
    libc.print("\x82\x82\x82\x82\n");
    moonColor();
    libc.print("       \x82\x80\x80\x83   ");
    cloudLight();
    libc.print("\x82\x82\x82\x82\x82\x82\x82\x82\n");
    cloudMid();
    libc.print("             \x83\x82\x83\x82\x82\x83\x82\x83\x82\n");
    cloudLight();
    libc.print("              \x82\x82\x82\x82\x82\x82\x82\n");
    starColor();
    libc.print("  .             ");
    libc.print(BOLD);
    libc.print("*");
    libc.print(RESET);
    starColor();
    libc.print("                ·\n");
    libc.print(RESET);
}

fn iconOvercast() void {
    cloudLight();
    libc.print("\n");
    libc.print("       \x82\x82\x82\x82\x82\x82\x82\x82\n");
    cloudMid();
    libc.print("    \x82\x82\x82\x83\x83\x83\x83\x83\x83\x82\x82\x82\n");
    libc.print("   \x82\x83\x83\x83\x83\x83\x83\x83\x83\x83\x83\x83\x83\n");
    cloudLight();
    libc.print("    \x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\n");
    libc.print("      \x82\x82\x82\x82\x82\x82\x82\n");
    libc.print(RESET);
}

fn iconFog() void {
    fogColor();
    libc.print("\n");
    libc.print("   \x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\n");
    libc.print(DIM);
    libc.print("   \x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\n");
    libc.print(RESET);
    fogColor();
    libc.print("   \x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\n");
    libc.print(DIM);
    libc.print("   \x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\n");
    libc.print(RESET);
    fogColor();
    libc.print("   \x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\x81\n");
    libc.print(RESET);
}

fn iconRain() void {
    cloudLight();
    libc.print("\n");
    libc.print("    \x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\n");
    cloudMid();
    libc.print("   \x82\x83\x83\x83\x83\x83\x83\x83\x83\x82\x82\n");
    cloudLight();
    libc.print("    \x82\x82\x82\x82\x82\x82\x82\x82\x82\n");
    rainColor();
    libc.print("     |  |  |  |  |\n");
    libc.print("    |  |  |  |  |\n");
    libc.print("       |  |  |\n");
    libc.print(RESET);
}

fn iconSnow() void {
    cloudLight();
    libc.print("\n");
    libc.print("    \x82\x82\x82\x82\x82\x82\x82\x82\x82\x82\n");
    cloudMid();
    libc.print("   \x82\x83\x83\x83\x83\x83\x83\x83\x83\x82\x82\n");
    cloudLight();
    libc.print("    \x82\x82\x82\x82\x82\x82\x82\x82\x82\n");
    snowColor();
    libc.print(BOLD);
    libc.print("     *   *   *   *\n");
    libc.print("    *   *   *   *\n");
    libc.print("       *   *   *\n");
    libc.print(RESET);
}

fn iconStorm() void {
    cloudDark();
    libc.print("\n");
    libc.print("    \x82\x83\x83\x83\x83\x83\x83\x82\x82\n");
    libc.print("   \x83\x80\x80\x80\x80\x80\x80\x80\x83\x82\n");
    libc.print("    \x83\x83\x83\x83\x83\x83\x83\x83\n");
    boltColor();
    libc.print(BOLD);
    libc.print("       /\\/\n");
    libc.print("        /\n");
    libc.print("       /_\n");
    libc.print(RESET);
}

fn drawIcon(kind: weather.Kind, is_day: bool) void {
    switch (kind) {
        .clear => if (is_day) iconClearDay() else iconClearNight(),
        .partly_cloudy => if (is_day) iconPartlyCloudyDay() else iconPartlyCloudyNight(),
        .overcast => iconOvercast(),
        .fog => iconFog(),
        .rain => iconRain(),
        .snow => iconSnow(),
        .storm => iconStorm(),
    }
}

// ---------------------------------------------------------------------
// Info block — printed below the icon. Two columns of label/value
// pairs in dim color, with the headline temp + condition in bold.

fn printFloat(n: f64, decimals: u8) void {
    var v = n;
    if (v < 0) {
        libc.printChar('-');
        v = -v;
    }
    const int_part: u32 = @intFromFloat(v);
    libc.printNum(int_part);
    if (decimals > 0) {
        libc.printChar('.');
        var frac = v - @as(f64, @floatFromInt(int_part));
        var i: u8 = 0;
        while (i < decimals) : (i += 1) {
            frac *= 10;
            const d: u8 = @intFromFloat(frac);
            libc.printChar('0' + d);
            frac -= @as(f64, @floatFromInt(d));
        }
    }
}

fn printInfoBlock(c: weather.Conditions) void {
    libc.print(BOLD);
    fg(255, 255, 255);
    libc.print("  ");
    libc.print(c.location[0..c.location_len]);
    libc.print(RESET);
    libc.print("\n");

    libc.print(BOLD);
    fg(255, 200, 50);
    libc.print("  ");
    printFloat(c.temp_c, 1);
    libc.print(" °C  ");
    libc.print(RESET);
    fg(200, 200, 200);
    libc.print(weather.weatherName(c.code));
    libc.print(RESET);
    libc.print("\n");

    libc.print(DIM);
    libc.print("  ");
    libc.print("humidity ");
    libc.print(RESET);
    fg(110, 170, 255);
    libc.printNum(c.humidity);
    libc.print("%");
    libc.print(RESET);
    libc.print("   ");
    libc.print(DIM);
    libc.print("wind ");
    libc.print(RESET);
    fg(180, 220, 255);
    printFloat(c.wind_kmh, 1);
    libc.print(" km/h");
    libc.print(RESET);
    libc.print("\n");
    libc.print(DIM);
    libc.print("  ");
    if (c.is_day) {
        libc.print("daytime");
    } else {
        libc.print("nighttime");
    }
    libc.print("\n");
    libc.print(RESET);
}

// ---------------------------------------------------------------------

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

    libc.print("\n");
    libc.print(DIM);
    libc.print("  ");
    libc.print("fetching ");
    libc.print(city);
    libc.print(" ...");
    libc.print(RESET);
    libc.print("\n");

    var c: weather.Conditions = undefined;
    weather.fetch(city, &c) catch |err| {
        libc.print("\x1b[31m  wx: failed: ");
        libc.print(@errorName(err));
        libc.print("\x1b[0m\n");
        libc.exit();
    };

    // Clear the "fetching..." line and redraw fresh.
    libc.print("\x1b[2A\x1b[K");

    libc.print("\n");
    drawIcon(weather.kindOf(c.code), c.is_day);
    libc.print("\n");
    printInfoBlock(c);
    libc.print("\n");
    libc.exit();
}
