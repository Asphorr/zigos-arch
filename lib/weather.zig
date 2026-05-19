// Open-Meteo client. Two-step lookup: geocode a city name to lat/lon
// via geocoding-api.open-meteo.com, then fetch current conditions from
// api.open-meteo.com. No API key required. Not Cloudflare-fronted, so
// our handcrafted TLS handshake works.
//
// Returns a Conditions struct with the bits any UI would want: temp,
// humidity, wind, weather code, day/night flag, location label.
//
// Usage:
//   var c: weather.Conditions = undefined;
//   try weather.fetch("Berlin", &c);
//   c.temp_c, c.code, c.is_day, c.location[0..c.location_len], ...

const std = @import("std");
const libc = @import("libc");
const http = @import("http");
const json = @import("json");

pub const Error = error{
    HttpFailed,
    JsonFailed,
    NoResults,
    BadResponse,
};

pub const Conditions = struct {
    /// Resolved place name (e.g. "Berlin, Germany"). Inline storage so
    /// no allocator dependency creeps into the caller.
    location: [96]u8,
    location_len: usize,

    latitude: f64,
    longitude: f64,
    temp_c: f64,
    humidity: u8,
    wind_kmh: f64,

    /// WMO weather code. 0=clear, 1-3=partial/overcast, 45/48=fog,
    /// 51-57=drizzle, 61-67=rain, 71-77=snow, 80-86=showers, 95-99=storm.
    /// Pass to `weatherName(code)` for a human label, or to the app's
    /// own icon picker.
    code: u16,
    is_day: bool,
};

/// Buffers sized for the two requests' headers. Bodies stream past us
/// so we don't need response-sized space.
var hdr_buf: [4 * 1024]u8 = undefined;
/// Body scratch — we materialize the JSON into a contiguous slice
/// before parsing. Open-Meteo responses are small (~300 bytes for
/// geocode, ~600 for forecast); 8 KiB is generous.
var body_buf: [8 * 1024]u8 = undefined;

pub fn fetch(city: []const u8, out: *Conditions) Error!void {
    var lat: f64 = 0;
    var lon: f64 = 0;
    try geocode(city, out, &lat, &lon);
    try forecast(lat, lon, out);
}

fn geocode(city: []const u8, out: *Conditions, lat_out: *f64, lon_out: *f64) Error!void {
    // URL: geocoding-api.open-meteo.com/v1/search?name=<city>&count=1&format=json
    var url_buf: [256]u8 = undefined;
    const prefix = "geocoding-api.open-meteo.com/v1/search?name=";
    const suffix = "&count=1&format=json";
    if (prefix.len + city.len + suffix.len > url_buf.len) return Error.HttpFailed;
    var pos: usize = 0;
    @memcpy(url_buf[pos..][0..prefix.len], prefix);
    pos += prefix.len;
    // URL-encode spaces as %20. Open-Meteo accepts plain spaces too,
    // but encoded is safer.
    for (city) |c| {
        if (c == ' ') {
            url_buf[pos] = '%';
            url_buf[pos + 1] = '2';
            url_buf[pos + 2] = '0';
            pos += 3;
        } else {
            url_buf[pos] = c;
            pos += 1;
        }
    }
    @memcpy(url_buf[pos..][0..suffix.len], suffix);
    pos += suffix.len;

    const body_len = try streamToBuf(url_buf[0..pos]);

    var root = json.parse(body_buf[0..body_len]) catch return Error.JsonFailed;
    defer root.deinit();

    const results = root.get("results") orelse return Error.NoResults;
    if (results != .array or results.array.len == 0) return Error.NoResults;
    const first = results.array[0];

    const lat_v = first.get("latitude") orelse return Error.BadResponse;
    const lon_v = first.get("longitude") orelse return Error.BadResponse;
    lat_out.* = lat_v.asNumber() orelse return Error.BadResponse;
    lon_out.* = lon_v.asNumber() orelse return Error.BadResponse;

    // Build "Name, Country" label.
    var loc_len: usize = 0;
    if (first.get("name")) |n| {
        if (n.asString()) |s| {
            const want = @min(s.len, out.location.len);
            @memcpy(out.location[loc_len..][0..want], s[0..want]);
            loc_len += want;
        }
    }
    if (first.get("country")) |co| {
        if (co.asString()) |s| {
            if (loc_len + 2 + s.len <= out.location.len) {
                out.location[loc_len] = ',';
                out.location[loc_len + 1] = ' ';
                loc_len += 2;
                @memcpy(out.location[loc_len..][0..s.len], s);
                loc_len += s.len;
            }
        }
    }
    out.location_len = loc_len;
    out.latitude = lat_out.*;
    out.longitude = lon_out.*;
}

fn forecast(lat: f64, lon: f64, out: *Conditions) Error!void {
    // URL: api.open-meteo.com/v1/forecast?latitude=X&longitude=Y&current=temperature_2m,relative_humidity_2m,is_day,weather_code,wind_speed_10m
    var url_buf: [400]u8 = undefined;
    var pos: usize = 0;
    const p1 = "api.open-meteo.com/v1/forecast?latitude=";
    @memcpy(url_buf[pos..][0..p1.len], p1);
    pos += p1.len;
    pos += writeFloat(url_buf[pos..], lat);
    const p2 = "&longitude=";
    @memcpy(url_buf[pos..][0..p2.len], p2);
    pos += p2.len;
    pos += writeFloat(url_buf[pos..], lon);
    const p3 = "&current=temperature_2m,relative_humidity_2m,is_day,weather_code,wind_speed_10m";
    @memcpy(url_buf[pos..][0..p3.len], p3);
    pos += p3.len;

    const body_len = try streamToBuf(url_buf[0..pos]);

    var root = json.parse(body_buf[0..body_len]) catch return Error.JsonFailed;
    defer root.deinit();

    const current = root.get("current") orelse return Error.BadResponse;
    out.temp_c = (current.get("temperature_2m") orelse return Error.BadResponse).asNumber() orelse 0;
    out.humidity = @intCast((current.get("relative_humidity_2m") orelse return Error.BadResponse).asInt() orelse 0);
    out.wind_kmh = (current.get("wind_speed_10m") orelse return Error.BadResponse).asNumber() orelse 0;
    out.code = @intCast((current.get("weather_code") orelse return Error.BadResponse).asInt() orelse 0);
    const is_day_i: i64 = (current.get("is_day") orelse return Error.BadResponse).asInt() orelse 1;
    out.is_day = is_day_i != 0;
}

/// Open a streaming HTTP request and copy the body into body_buf.
/// Returns the body length. We use streaming so the same lib works
/// against responses bigger than body_buf would otherwise allow — we
/// just truncate if it doesn't fit (Open-Meteo responses are small).
fn streamToBuf(url: []const u8) Error!usize {
    var stream: http.Stream = undefined;
    http.openStream(.{ .url = url }, &hdr_buf, &stream) catch return Error.HttpFailed;
    defer stream.close();
    const resp = stream.response();
    if (resp.status < 200 or resp.status >= 300) return Error.HttpFailed;

    var pos: usize = 0;
    while (pos < body_buf.len) {
        const n = stream.readChunk(body_buf[pos..]) catch return Error.HttpFailed;
        if (n == 0) break;
        pos += n;
    }
    return pos;
}

/// Pretty name for a WMO weather code. Picks the umbrella category;
/// callers wanting more granularity can switch on `code` directly.
pub fn weatherName(code: u16) []const u8 {
    return switch (code) {
        0 => "Clear",
        1 => "Mainly clear",
        2 => "Partly cloudy",
        3 => "Overcast",
        45, 48 => "Fog",
        51, 53, 55 => "Drizzle",
        56, 57 => "Freezing drizzle",
        61, 63, 65 => "Rain",
        66, 67 => "Freezing rain",
        71, 73, 75 => "Snow",
        77 => "Snow grains",
        80, 81, 82 => "Rain showers",
        85, 86 => "Snow showers",
        95 => "Thunderstorm",
        96, 99 => "Thunderstorm w/ hail",
        else => "Unknown",
    };
}

/// Coarse category — handy for picking an ASCII icon. Multiple codes
/// collapse to the same kind.
pub const Kind = enum {
    clear,
    partly_cloudy,
    overcast,
    fog,
    rain,
    snow,
    storm,
};

pub fn kindOf(code: u16) Kind {
    return switch (code) {
        0, 1 => .clear,
        2 => .partly_cloudy,
        3 => .overcast,
        45, 48 => .fog,
        51, 53, 55, 56, 57, 61, 63, 65, 66, 67, 80, 81, 82 => .rain,
        71, 73, 75, 77, 85, 86 => .snow,
        95, 96, 99 => .storm,
        else => .overcast,
    };
}

/// Write a finite f64 as a decimal string with up to 4 fractional
/// digits. Good enough for lat/lon — the API rounds anyway. Doesn't
/// handle NaN/Inf (would never come from us).
fn writeFloat(out: []u8, v: f64) usize {
    var pos: usize = 0;
    var f = v;
    if (f < 0) {
        out[pos] = '-';
        pos += 1;
        f = -f;
    }
    const int_part: u64 = @intFromFloat(f);
    pos += writeU64(out[pos..], int_part);
    var frac = f - @as(f64, @floatFromInt(int_part));
    if (frac > 0) {
        out[pos] = '.';
        pos += 1;
        // Up to 4 decimal digits.
        var i: u8 = 0;
        while (i < 4 and frac > 0) : (i += 1) {
            frac *= 10;
            const d: u8 = @intFromFloat(frac);
            out[pos] = '0' + d;
            pos += 1;
            frac -= @as(f64, @floatFromInt(d));
        }
    }
    return pos;
}

fn writeU64(out: []u8, n: u64) usize {
    var tmp: [20]u8 = undefined;
    var v = n;
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
