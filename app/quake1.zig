// ZigOS Quake 1 port — platform layer + libc shim for id Software's
// 1996 WinQuake software renderer source (vendored at quake_src/).
//
// Pattern mirrors app/doom_real.zig: _start sets up a window, calls
// quake_main (defined in sys_zigos.c), and provides:
//   - C-ABI primitives the platform stubs call (zq_time_ms, zq_exit, zq_print)
//   - Frame present + key/mouse event delivery (via Sys_SendKeyEvents path)
//   - Full libc surface (malloc/free, string ops, stdio, math)
//
// Phase A goal: link clean. Runtime wiring (frame blit, input, audio)
// gets filled in across subsequent phases — most of the platform stubs
// in sys_zigos.c are no-ops at this stage.

const std = @import("std");
const libc = @import("libc");

// ============================================================
// Window
// ============================================================

const Q_WIDTH: u32 = 320;
const Q_HEIGHT: u32 = 200;
const SCALE: u32 = 2;
const WIN_W: u32 = Q_WIDTH * SCALE;
const WIN_H: u32 = Q_HEIGHT * SCALE;

var fb: [*]volatile u32 = undefined;
var start_ticks: u32 = 0;

// C globals exported by sys_zigos.c / screen.c
const Viddef = extern struct {
    buffer: ?[*]u8,
    colormap: ?[*]u8,
    colormap16: ?[*]u16,
    fullbright: c_int,
    rowbytes: c_uint,
    width: c_uint,
    height: c_uint,
    aspect: f32,
    numpages: c_int,
    recalc_refdef: c_int,
    conbuffer: ?[*]u8,
    conrowbytes: c_int,
    conwidth: c_uint,
    conheight: c_uint,
    maxwarpwidth: c_int,
    maxwarpheight: c_int,
    direct: ?[*]u8,
};
extern var vid: Viddef;
extern var zq_palette: [768]u8;
extern var zq_dirty: c_int;

extern fn quake_main(argc: c_int, argv: [*][*:0]u8) c_int;

// ============================================================
// Primitives sys_zigos.c links against
// ============================================================

export fn zq_time_ms() c_uint {
    return (libc.uptime() -% start_ticks) * 10;
}

export fn zq_exit(code: c_int) callconv(.c) noreturn {
    _ = code;
    libc.destroyWindow();
    libc.exit();
}

export fn zq_print(s: ?[*:0]const u8) void {
    if (s) |str| {
        var n: usize = 0;
        while (str[n] != 0) : (n += 1) {}
        libc.print(str[0..n]);
    }
}

// Premultiplied 8→24 palette LUT, kept in sync with zq_palette[768] which
// sys_zigos.c writes from VID_SetPalette / VID_ShiftPalette. Rebuilt
// lazily on first present after a palette change so the hot path is just
// one indirect load per pixel.
var palette_lut: [256]u32 = [_]u32{0} ** 256;
var palette_lut_built: bool = false;

fn rebuildPaletteLut() void {
    for (0..256) |i| {
        const r: u32 = zq_palette[i * 3 + 0];
        const g: u32 = zq_palette[i * 3 + 1];
        const b: u32 = zq_palette[i * 3 + 2];
        palette_lut[i] = (0xFF << 24) | (r << 16) | (g << 8) | b;
    }
    palette_lut_built = true;
}

// Called from sys_zigos.c VID_Update. Expands the 320x200 8bpp palettized
// `vid.buffer` to our 640x400 RGBA window FB (nearest-neighbor 2× scale),
// then presents. Q1's "dirty" optimization (vrect_t list) is ignored —
// the rect tracking is fine-grained but our compositor presents whole
// windows, so a full blit is cheaper than walking N rects.
export fn zq_present() void {
    // VID_SetPalette / VID_ShiftPalette toggle zq_dirty. Rebuild LUT once
    // per palette change, not per frame.
    if (!palette_lut_built or zq_dirty != 0) {
        rebuildPaletteLut();
        zq_dirty = 0;
    }
    const src = vid.buffer orelse return;
    // 2× nearest-neighbor expand into the output FB.
    var y: u32 = 0;
    while (y < Q_HEIGHT) : (y += 1) {
        const src_row = y * Q_WIDTH;
        const dst_row_a = (y * SCALE) * WIN_W;
        const dst_row_b = dst_row_a + WIN_W;
        var x: u32 = 0;
        while (x < Q_WIDTH) : (x += 1) {
            const px = palette_lut[src[src_row + x]];
            const dx = x * SCALE;
            fb[dst_row_a + dx] = px;
            fb[dst_row_a + dx + 1] = px;
            fb[dst_row_b + dx] = px;
            fb[dst_row_b + dx + 1] = px;
        }
    }
    libc.present();
}

// ============================================================
// Entry
// ============================================================

export fn _start() linksection(".text.entry") callconv(.c) void {
    start_ticks = libc.uptime();

    const win = libc.createWindow(WIN_W, WIN_H) orelse {
        libc.exit();
        return;
    };
    fb = win.fb;
    libc.setCursorVisible(false);

    var argv = [_][*:0]u8{
        @ptrCast(@constCast("quake")),
        @ptrCast(@constCast("-basedir")),
        @ptrCast(@constCast("/share/quake")),
    };
    _ = quake_main(3, &argv);

    libc.destroyWindow();
    libc.exit();
}

// ============================================================
// Math — backed by std.math (Q1 is float-heavy unlike DOOM)
// ============================================================

export fn sqrt(x: f64) f64 {
    return @sqrt(x);
}
export fn sqrtf(x: f32) f32 {
    return @sqrt(x);
}
export fn sin(x: f64) f64 {
    return @sin(x);
}
export fn sinf(x: f32) f32 {
    return @sin(x);
}
export fn cos(x: f64) f64 {
    return @cos(x);
}
export fn cosf(x: f32) f32 {
    return @cos(x);
}
export fn tan(x: f64) f64 {
    return std.math.tan(x);
}
export fn atan(x: f64) f64 {
    return std.math.atan(x);
}
export fn atan2(y: f64, x: f64) f64 {
    return std.math.atan2(y, x);
}
export fn asin(x: f64) f64 {
    return std.math.asin(x);
}
export fn acos(x: f64) f64 {
    return std.math.acos(x);
}
export fn floor(x: f64) f64 {
    return @floor(x);
}
export fn floorf(x: f32) f32 {
    return @floor(x);
}
export fn ceil(x: f64) f64 {
    return @ceil(x);
}
export fn ceilf(x: f32) f32 {
    return @ceil(x);
}
export fn fabs(x: f64) f64 {
    return @abs(x);
}
export fn fabsf(x: f32) f32 {
    return @abs(x);
}
export fn pow(x: f64, y: f64) f64 {
    return std.math.pow(f64, x, y);
}
export fn exp(x: f64) f64 {
    return @exp(x);
}
export fn log(x: f64) f64 {
    return @log(x);
}
export fn fmod(x: f64, y: f64) f64 {
    return @mod(x, y);
}

// ============================================================
// Memory
// ============================================================

export fn malloc(size: usize) ?[*]u8 {
    return libc.malloc(size);
}
export fn calloc(nmemb: usize, size: usize) ?[*]u8 {
    return libc.calloc(nmemb, size);
}
export fn realloc(old_ptr: ?[*]u8, new_size: usize) ?[*]u8 {
    return libc.realloc(old_ptr, new_size);
}
export fn free(ptr: ?*anyopaque) void {
    libc.free(@ptrCast(@alignCast(ptr)));
}

// ============================================================
// String / mem ops
// ============================================================

const CUint = u32;
const CLong = i64;
const CUlong = u64;

export fn memcpy(dest: ?[*]u8, src: ?[*]const u8, n: usize) ?[*]u8 {
    if (dest == null or src == null) return dest;
    @memcpy(dest.?[0..n], src.?[0..n]);
    return dest;
}

export fn memmove(dest: ?[*]u8, src: ?[*]const u8, n: usize) ?[*]u8 {
    if (dest == null or src == null or n == 0) return dest;
    const d = dest.?;
    const s = src.?;
    if (@intFromPtr(d) < @intFromPtr(s)) {
        @memcpy(d[0..n], s[0..n]);
    } else {
        var i = n;
        while (i > 0) {
            i -= 1;
            d[i] = s[i];
        }
    }
    return dest;
}

export fn memset(dest: ?[*]u8, c_val: c_int, n: usize) ?[*]u8 {
    if (dest) |d| {
        const byte: u8 = @truncate(@as(CUint, @bitCast(c_val)));
        @memset(d[0..n], byte);
    }
    return dest;
}

export fn memcmp(s1: ?[*]const u8, s2: ?[*]const u8, n: usize) c_int {
    if (s1 == null or s2 == null) return 0;
    const a = s1.?;
    const b = s2.?;
    for (0..n) |i| {
        if (a[i] != b[i]) return @as(c_int, a[i]) - @as(c_int, b[i]);
    }
    return 0;
}

export fn memchr(s: ?[*]const u8, c_val: c_int, n: usize) ?[*]const u8 {
    if (s == null) return null;
    const ch: u8 = @truncate(@as(CUint, @bitCast(c_val)));
    const p = s.?;
    for (0..n) |i| if (p[i] == ch) return p + i;
    return null;
}

export fn strlen(s: ?[*:0]const u8) usize {
    if (s == null) return 0;
    var n: usize = 0;
    while (s.?[n] != 0) n += 1;
    return n;
}

export fn strcpy(dest: [*:0]u8, src: [*:0]const u8) [*:0]u8 {
    var i: usize = 0;
    while (src[i] != 0) : (i += 1) dest[i] = src[i];
    dest[i] = 0;
    return dest;
}

export fn strncpy(dest: [*]u8, src: [*]const u8, n: usize) [*]u8 {
    var i: usize = 0;
    while (i < n and src[i] != 0) : (i += 1) dest[i] = src[i];
    while (i < n) : (i += 1) dest[i] = 0;
    return dest;
}

export fn strcat(dest: [*:0]u8, src: [*:0]const u8) [*:0]u8 {
    var i = strlen(dest);
    var j: usize = 0;
    while (src[j] != 0) : (j += 1) {
        dest[i] = src[j];
        i += 1;
    }
    dest[i] = 0;
    return dest;
}

export fn strncat(dest: [*:0]u8, src: [*:0]const u8, n: usize) [*:0]u8 {
    var i = strlen(dest);
    var j: usize = 0;
    while (j < n and src[j] != 0) : (j += 1) {
        dest[i] = src[j];
        i += 1;
    }
    dest[i] = 0;
    return dest;
}

export fn strcmp(s1: [*:0]const u8, s2: [*:0]const u8) c_int {
    var i: usize = 0;
    while (s1[i] != 0 and s1[i] == s2[i]) i += 1;
    return @as(c_int, s1[i]) - @as(c_int, s2[i]);
}

export fn strncmp(s1: [*]const u8, s2: [*]const u8, n: usize) c_int {
    for (0..n) |i| {
        if (s1[i] != s2[i] or s1[i] == 0) return @as(c_int, s1[i]) - @as(c_int, s2[i]);
    }
    return 0;
}

fn toLowerByte(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

export fn strcasecmp(s1: [*:0]const u8, s2: [*:0]const u8) c_int {
    var i: usize = 0;
    while (s1[i] != 0 and toLowerByte(s1[i]) == toLowerByte(s2[i])) i += 1;
    return @as(c_int, toLowerByte(s1[i])) - @as(c_int, toLowerByte(s2[i]));
}

export fn strncasecmp(s1: [*]const u8, s2: [*]const u8, n: usize) c_int {
    for (0..n) |i| {
        const a = toLowerByte(s1[i]);
        const b = toLowerByte(s2[i]);
        if (a != b or a == 0) return @as(c_int, a) - @as(c_int, b);
    }
    return 0;
}

export fn strdup(s: [*:0]const u8) ?[*:0]u8 {
    const len = strlen(s);
    const buf = libc.malloc(len + 1) orelse return null;
    @memcpy(buf[0 .. len + 1], s[0 .. len + 1]);
    return @ptrCast(buf);
}

export fn strchr(s: [*:0]const u8, c_val: c_int) ?[*:0]const u8 {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c_val)));
    var i: usize = 0;
    while (true) {
        if (s[i] == ch) return s + i;
        if (s[i] == 0) return null;
        i += 1;
    }
}

export fn strrchr(s: [*:0]const u8, c_val: c_int) ?[*:0]const u8 {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c_val)));
    var last: ?[*:0]const u8 = null;
    var i: usize = 0;
    while (true) {
        if (s[i] == ch) last = s + i;
        if (s[i] == 0) return last;
        i += 1;
    }
}

export fn strstr(haystack: [*:0]const u8, needle: [*:0]const u8) ?[*:0]const u8 {
    const nlen = strlen(needle);
    if (nlen == 0) return haystack;
    var i: usize = 0;
    while (haystack[i] != 0) : (i += 1) {
        if (strncmp(haystack + i, needle, nlen) == 0) return haystack + i;
    }
    return null;
}

export fn strerror(errnum: c_int) [*:0]const u8 {
    _ = errnum;
    return "error";
}

// ============================================================
// ctype
// ============================================================

export fn isalpha(c: c_int) c_int {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c)));
    return @intFromBool((ch >= 'A' and ch <= 'Z') or (ch >= 'a' and ch <= 'z'));
}
export fn isdigit(c: c_int) c_int {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c)));
    return @intFromBool(ch >= '0' and ch <= '9');
}
export fn isxdigit(c: c_int) c_int {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c)));
    return @intFromBool((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f') or (ch >= 'A' and ch <= 'F'));
}
export fn isalnum(c: c_int) c_int {
    return @intFromBool(isalpha(c) != 0 or isdigit(c) != 0);
}
export fn isspace(c: c_int) c_int {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c)));
    return @intFromBool(ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r' or ch == 0x0B or ch == 0x0C);
}
export fn isprint(c: c_int) c_int {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c)));
    return @intFromBool(ch >= 0x20 and ch <= 0x7E);
}
export fn isupper(c: c_int) c_int {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c)));
    return @intFromBool(ch >= 'A' and ch <= 'Z');
}
export fn islower(c: c_int) c_int {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c)));
    return @intFromBool(ch >= 'a' and ch <= 'z');
}
export fn toupper(c: c_int) c_int {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c)));
    return if (ch >= 'a' and ch <= 'z') c - 32 else c;
}
export fn tolower(c: c_int) c_int {
    const ch: u8 = @truncate(@as(CUint, @bitCast(c)));
    return if (ch >= 'A' and ch <= 'Z') c + 32 else c;
}

// ============================================================
// vsnprintf — minimal, supports %d %u %x %X %s %c %p %f %%
// ============================================================

const VaList = @import("std").builtin.VaList;
fn va_arg(ap: *VaList, comptime T: type) T {
    return @cVaArg(ap, T);
}

fn fmtInt(buf: [*]u8, max: usize, pos: *usize, val: i64, base: u32, upper: bool, width: u32, zero_pad: bool, negative: bool) void {
    var tmp: [24]u8 = undefined;
    var len: u32 = 0;
    var v: u64 = if (negative) @bitCast(-val) else @bitCast(val);
    if (v == 0) {
        tmp[0] = '0';
        len = 1;
    } else {
        while (v > 0) {
            const digit: u8 = @truncate(v % base);
            tmp[len] = if (digit < 10) @as(u8, '0') + digit else (if (upper) @as(u8, 'A') else @as(u8, 'a')) + digit - 10;
            len += 1;
            v /= base;
        }
    }
    if (negative) {
        tmp[len] = '-';
        len += 1;
    }
    const pad_char: u8 = if (zero_pad) '0' else ' ';
    if (width > len) {
        const pad_count = width - len;
        for (0..pad_count) |_| {
            if (pos.* < max) buf[pos.*] = pad_char;
            pos.* += 1;
        }
    }
    var i: u32 = len;
    while (i > 0) {
        i -= 1;
        if (pos.* < max) buf[pos.*] = tmp[i];
        pos.* += 1;
    }
}

fn fmtFloat(buf: [*]u8, max: usize, pos: *usize, val: f64, prec: u32) void {
    var v = val;
    if (v < 0) {
        if (pos.* < max) buf[pos.*] = '-';
        pos.* += 1;
        v = -v;
    }
    const int_part: u64 = @intFromFloat(v);
    var frac: f64 = v - @as(f64, @floatFromInt(int_part));
    fmtInt(buf, max, pos, @bitCast(int_part), 10, false, 0, false, false);
    if (pos.* < max) buf[pos.*] = '.';
    pos.* += 1;
    const p: u32 = if (prec == 0) 6 else prec;
    for (0..p) |_| {
        frac *= 10.0;
        const d: u32 = @intFromFloat(frac);
        if (pos.* < max) buf[pos.*] = '0' + @as(u8, @intCast(d % 10));
        pos.* += 1;
        frac -= @floor(frac);
    }
}

export fn vsnprintf(buf: ?[*]u8, size: usize, fmt: ?[*:0]const u8, ap: *VaList) c_int {
    if (buf == null or fmt == null) return 0;
    const b = buf.?;
    const f = fmt.?;
    var pos: usize = 0;
    const max = if (size > 0) size - 1 else 0;
    var i: usize = 0;

    while (f[i] != 0) {
        if (f[i] != '%') {
            if (pos < max) b[pos] = f[i];
            pos += 1;
            i += 1;
            continue;
        }
        i += 1;
        var zero_pad = false;
        while (f[i] == '0' or f[i] == '-' or f[i] == '+' or f[i] == ' ') {
            if (f[i] == '0') zero_pad = true;
            i += 1;
        }
        var width: u32 = 0;
        while (f[i] >= '0' and f[i] <= '9') {
            width = width * 10 + (f[i] - '0');
            i += 1;
        }
        var prec: u32 = 0;
        if (f[i] == '.') {
            i += 1;
            while (f[i] >= '0' and f[i] <= '9') {
                prec = prec * 10 + (f[i] - '0');
                i += 1;
            }
        }
        var is_long = false;
        if (f[i] == 'l') {
            is_long = true;
            i += 1;
        }
        if (f[i] == 'l') i += 1;
        if (f[i] == 'h') i += 1;

        switch (f[i]) {
            'd', 'i' => {
                const val: i64 = if (is_long) va_arg(ap, CLong) else @as(i64, va_arg(ap, c_int));
                fmtInt(b, max, &pos, val, 10, false, width, zero_pad, val < 0);
            },
            'u' => {
                const val: u64 = if (is_long) @as(u64, va_arg(ap, CUlong)) else @as(u64, @as(CUint, @bitCast(va_arg(ap, c_int))));
                fmtInt(b, max, &pos, @bitCast(val), 10, false, width, zero_pad, false);
            },
            'x' => {
                const val: u64 = if (is_long) @as(u64, va_arg(ap, CUlong)) else @as(u64, @as(CUint, @bitCast(va_arg(ap, c_int))));
                fmtInt(b, max, &pos, @bitCast(val), 16, false, width, zero_pad, false);
            },
            'X' => {
                const val: u64 = if (is_long) @as(u64, va_arg(ap, CUlong)) else @as(u64, @as(CUint, @bitCast(va_arg(ap, c_int))));
                fmtInt(b, max, &pos, @bitCast(val), 16, true, width, zero_pad, false);
            },
            'p' => {
                const val: u64 = @intFromPtr(va_arg(ap, ?*anyopaque));
                if (pos < max) b[pos] = '0';
                pos += 1;
                if (pos < max) b[pos] = 'x';
                pos += 1;
                fmtInt(b, max, &pos, @bitCast(val), 16, false, 0, false, false);
            },
            'f', 'g', 'e' => {
                const val: f64 = va_arg(ap, f64);
                fmtFloat(b, max, &pos, val, prec);
            },
            's' => {
                const s: ?[*:0]const u8 = va_arg(ap, ?[*:0]const u8);
                const addr = @intFromPtr(s);
                if (s != null and addr >= 0x1000 and addr < 0x80000000) {
                    const str = s.?;
                    var j: usize = 0;
                    while (str[j] != 0) : (j += 1) {
                        if (pos < max) b[pos] = str[j];
                        pos += 1;
                    }
                } else {
                    for ("(null)") |ch| {
                        if (pos < max) b[pos] = ch;
                        pos += 1;
                    }
                }
            },
            'c' => {
                const ch: u8 = @truncate(@as(CUint, @bitCast(va_arg(ap, c_int))));
                if (pos < max) b[pos] = ch;
                pos += 1;
            },
            '%' => {
                if (pos < max) b[pos] = '%';
                pos += 1;
            },
            else => {
                if (pos < max) b[pos] = f[i];
                pos += 1;
            },
        }
        i += 1;
    }

    if (size > 0) b[@min(pos, max)] = 0;
    return @intCast(pos);
}

export fn snprintf(buf: ?[*]u8, size: usize, fmt: ?[*:0]const u8, ...) c_int {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    return vsnprintf(buf, size, fmt, &ap);
}

export fn sprintf(buf: ?[*]u8, fmt: ?[*:0]const u8, ...) c_int {
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    return vsnprintf(buf, 4096, fmt, &ap);
}

export fn vsprintf(buf: ?[*]u8, fmt: ?[*:0]const u8, ap: VaList) c_int {
    var ap_copy = ap;
    return vsnprintf(buf, 4096, fmt, &ap_copy);
}

var last_msg: [512]u8 = undefined;
var last_msg_len: usize = 0;

export fn printf(fmt: ?[*:0]const u8, ...) c_int {
    var tmp: [512]u8 = undefined;
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    const len = vsnprintf(&tmp, 512, fmt, &ap);
    if (len > 0) {
        const slen: usize = @intCast(@min(len, 511));
        libc.print(tmp[0..slen]);
        const clen = @min(slen, last_msg.len);
        @memcpy(last_msg[0..clen], tmp[0..clen]);
        last_msg_len = clen;
    }
    return len;
}

export fn fprintf(fp: ?*anyopaque, fmt: ?[*:0]const u8, ...) c_int {
    _ = fp;
    var tmp: [512]u8 = undefined;
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    const len = vsnprintf(&tmp, 512, fmt, &ap);
    if (len > 0) libc.print(tmp[0..@intCast(@min(len, 511))]);
    return len;
}

export fn vfprintf(fp: ?*anyopaque, fmt: ?[*:0]const u8, in_ap: VaList) c_int {
    _ = fp;
    var tmp: [512]u8 = undefined;
    var ap_copy = in_ap;
    const len = vsnprintf(&tmp, 512, fmt, &ap_copy);
    if (len > 0) libc.print(tmp[0..@intCast(@min(len, 511))]);
    return len;
}

export fn puts(s: ?[*:0]const u8) c_int {
    if (s) |str| {
        var n: usize = 0;
        while (str[n] != 0) n += 1;
        libc.print(str[0..n]);
    }
    libc.printChar('\n');
    return 0;
}

export fn putchar(c: c_int) c_int {
    libc.printChar(@truncate(@as(CUint, @bitCast(c))));
    return c;
}

export fn fputs(s: ?[*:0]const u8, fp: ?*anyopaque) c_int {
    _ = fp;
    if (s) |str| {
        var n: usize = 0;
        while (str[n] != 0) n += 1;
        libc.print(str[0..n]);
    }
    return 0;
}

export fn fputc(c: c_int, fp: ?*anyopaque) c_int {
    _ = fp;
    libc.printChar(@truncate(@as(CUint, @bitCast(c))));
    return c;
}

// ============================================================
// File I/O — FILE* backed by libc.open/fread (memory-resident copy)
// ============================================================

const FILE = extern struct {
    data: ?[*]u8,
    size: u32,
    pos: u32,
    mode: u8,
    at_eof: u8,
    is_mmap: u8 = 0,
    _pad: u8 = 0,
};

const MAX_FILES_OPEN = 16;
var file_pool: [MAX_FILES_OPEN]FILE = [_]FILE{.{ .data = null, .size = 0, .pos = 0, .mode = 0, .at_eof = 0 }} ** MAX_FILES_OPEN;
var stdout_file: FILE = .{ .data = null, .size = 0, .pos = 0, .mode = 2, .at_eof = 0 };
var stderr_file: FILE = .{ .data = null, .size = 0, .pos = 0, .mode = 2, .at_eof = 0 };

export const stdin: *FILE = &stderr_file;
export const stdout: *FILE = &stdout_file;
export const stderr: *FILE = &stderr_file;

export fn fopen(path: ?[*:0]const u8, mode: ?[*:0]const u8) ?*FILE {
    if (path == null) return null;
    _ = mode;
    const p = path.?;
    var plen: usize = 0;
    while (p[plen] != 0) plen += 1;

    const fd = libc.open(p[0..plen]) orelse return null;

    var data: [*]u8 = undefined;
    var size: u32 = 0;
    var is_mmap: u8 = 0;
    if (libc.fsize(p[0..plen])) |sz| {
        if (sz > 0) {
            if (libc.mmapFile(fd, 0, sz)) |buf| {
                data = buf.ptr;
                size = @intCast(sz);
                is_mmap = 1;
            }
        }
    }
    if (is_mmap == 0) {
        const chunk: u32 = 65536;
        var total: u32 = 0;
        var capacity: u32 = if (libc.fsize(p[0..plen])) |sz| sz + chunk else 64 * 1024;
        var buf = libc.malloc(capacity) orelse {
            libc.close(fd);
            return null;
        };
        while (true) {
            if (total + chunk > capacity) {
                const new_cap = capacity * 2;
                const new_buf = libc.malloc(new_cap) orelse break;
                @memcpy(new_buf[0..total], buf[0..total]);
                capacity = new_cap;
                buf = new_buf;
            }
            const n = libc.fread(fd, buf[total..][0..chunk]);
            if (n == 0) break;
            total += n;
        }
        data = buf;
        size = total;
    }
    libc.close(fd);

    for (&file_pool) |*slot| {
        if (slot.mode == 0) {
            slot.data = data;
            slot.size = size;
            slot.pos = 0;
            slot.mode = 1;
            slot.at_eof = 0;
            slot.is_mmap = is_mmap;
            return slot;
        }
    }
    if (is_mmap != 0) {
        const aligned: usize = (@as(usize, size) + 0xFFF) & ~@as(usize, 0xFFF);
        _ = libc.munmap(data[0..aligned]);
    }
    return null;
}

export fn fclose(fp: ?*FILE) c_int {
    if (fp) |f| {
        if (f == &stdout_file or f == &stderr_file) return 0;
        if (f.is_mmap != 0) {
            if (f.data) |d| {
                const aligned: usize = (@as(usize, f.size) + 0xFFF) & ~@as(usize, 0xFFF);
                _ = libc.munmap(d[0..aligned]);
            }
        }
        f.mode = 0;
        f.data = null;
        f.is_mmap = 0;
    }
    return 0;
}

export fn fread(ptr: ?[*]u8, size: usize, nmemb: usize, fp: ?*FILE) usize {
    if (ptr == null or fp == null) return 0;
    const f = fp.?;
    if (f.data == null or f.mode == 0) return 0;
    const total = size * nmemb;
    const avail = f.size - f.pos;
    const to_read = if (total < avail) @as(u32, @intCast(total)) else avail;
    if (to_read == 0) {
        f.at_eof = 1;
        return 0;
    }
    @memcpy(ptr.?[0..to_read], f.data.?[f.pos..][0..to_read]);
    f.pos += to_read;
    return to_read / size;
}

export fn fwrite(ptr: ?[*]const u8, size: usize, nmemb: usize, fp: ?*FILE) usize {
    if (ptr == null or fp == null) return 0;
    const f = fp.?;
    if (f == &stdout_file or f == &stderr_file) {
        const total = size * nmemb;
        libc.print(ptr.?[0..total]);
        return nmemb;
    }
    return 0;
}

export fn fseek(fp: ?*FILE, offset: c_long, whence: c_int) c_int {
    if (fp == null) return -1;
    const f = fp.?;
    var new_pos: i64 = switch (whence) {
        0 => offset,
        1 => @as(i64, f.pos) + offset,
        2 => @as(i64, f.size) + offset,
        else => return -1,
    };
    if (new_pos < 0) new_pos = 0;
    if (new_pos > @as(i64, f.size)) new_pos = @as(i64, f.size);
    f.pos = @intCast(new_pos);
    f.at_eof = 0;
    return 0;
}

export fn ftell(fp: ?*FILE) c_long {
    if (fp) |f| return @intCast(f.pos);
    return -1;
}

export fn feof(fp: ?*FILE) c_int {
    if (fp) |f| return @as(c_int, f.at_eof);
    return 1;
}

export fn ferror(fp: ?*FILE) c_int {
    _ = fp;
    return 0;
}

export fn rewind(fp: ?*FILE) void {
    if (fp) |f| {
        f.pos = 0;
        f.at_eof = 0;
    }
}

export fn fflush(fp: ?*FILE) c_int {
    _ = fp;
    return 0;
}

export fn fgetc(fp: ?*FILE) c_int {
    if (fp == null) return -1;
    const f = fp.?;
    if (f.data == null or f.pos >= f.size) {
        f.at_eof = 1;
        return -1;
    }
    const ch = f.data.?[f.pos];
    f.pos += 1;
    return ch;
}

export fn fgets(s: ?[*]u8, size: c_int, fp: ?*FILE) ?[*]u8 {
    if (s == null or fp == null or size <= 0) return null;
    const buf = s.?;
    const f = fp.?;
    var i: usize = 0;
    const max: usize = @intCast(size - 1);
    while (i < max) {
        const ch = fgetc(f);
        if (ch == -1) break;
        buf[i] = @intCast(ch);
        i += 1;
        if (ch == '\n') break;
    }
    if (i == 0) return null;
    buf[i] = 0;
    return s;
}

export fn sscanf(str: ?[*:0]const u8, fmt: ?[*:0]const u8, ...) c_int {
    _ = str;
    _ = fmt;
    return 0;
}

// ============================================================
// Misc
// ============================================================

export var errno: c_int = 0;

export fn exit(status: c_int) callconv(.c) noreturn {
    _ = status;
    if (last_msg_len > 0) {
        libc.print("Quake exit: ");
        libc.print(last_msg[0..last_msg_len]);
        libc.printChar('\n');
    } else {
        libc.print("Quake exit (no message)\n");
    }
    libc.sleep(3000);
    libc.destroyWindow();
    libc.exit();
}

export fn abort() callconv(.c) noreturn {
    libc.destroyWindow();
    libc.exit();
}

export fn abs(x: c_int) c_int {
    return if (x < 0) -x else x;
}
export fn labs(x: c_long) c_long {
    return if (x < 0) -x else x;
}

export fn atoi(s: ?[*:0]const u8) c_int {
    if (s == null) return 0;
    const str = s.?;
    var i: usize = 0;
    while (str[i] == ' ') i += 1;
    var neg = false;
    if (str[i] == '-') {
        neg = true;
        i += 1;
    } else if (str[i] == '+') i += 1;
    var val: c_int = 0;
    while (str[i] >= '0' and str[i] <= '9') {
        val = val * 10 + @as(c_int, str[i] - '0');
        i += 1;
    }
    return if (neg) -val else val;
}

export fn atof(s: ?[*:0]const u8) f64 {
    if (s == null) return 0.0;
    const str = s.?;
    var i: usize = 0;
    while (str[i] == ' ') i += 1;
    var neg = false;
    if (str[i] == '-') {
        neg = true;
        i += 1;
    } else if (str[i] == '+') i += 1;
    var val: f64 = 0.0;
    while (str[i] >= '0' and str[i] <= '9') {
        val = val * 10.0 + @as(f64, @floatFromInt(str[i] - '0'));
        i += 1;
    }
    if (str[i] == '.') {
        i += 1;
        var frac: f64 = 0.1;
        while (str[i] >= '0' and str[i] <= '9') {
            val += @as(f64, @floatFromInt(str[i] - '0')) * frac;
            frac *= 0.1;
            i += 1;
        }
    }
    return if (neg) -val else val;
}

export fn atol(s: ?[*:0]const u8) c_long {
    return @as(c_long, atoi(s));
}

export fn strtol(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base: c_int) c_long {
    _ = base;
    if (endptr) |ep| ep.* = null;
    return @as(c_long, atoi(s));
}

export fn strtoul(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8, base: c_int) c_ulong {
    _ = base;
    if (endptr) |ep| ep.* = null;
    const v = atoi(s);
    return if (v < 0) 0 else @intCast(v);
}

export fn strtod(s: ?[*:0]const u8, endptr: ?*?[*:0]const u8) f64 {
    if (endptr) |ep| ep.* = null;
    return atof(s);
}

export fn getenv(name: ?[*:0]const u8) ?[*:0]const u8 {
    _ = name;
    return null;
}

export fn time(t: ?*i64) i64 {
    const v: i64 = @as(i64, libc.uptime()) * 10;
    if (t) |p| p.* = v;
    return v;
}

var rand_state: u32 = 1;
export fn rand() c_int {
    rand_state = rand_state *% 1103515245 +% 12345;
    return @as(c_int, @intCast((rand_state >> 16) & 0x7fff));
}

export fn srand(seed: c_uint) void {
    rand_state = seed;
}

export fn fscanf(fp: ?*FILE, fmt: ?[*:0]const u8, ...) c_int {
    _ = fp;
    _ = fmt;
    return 0;
}

export fn getc(fp: ?*FILE) c_int {
    return fgetc(fp);
}

// POSIX low-level I/O — Q1 uses these in a couple of places (sys_*.c paths
// we replaced, plus host_cmd.c's screenshot dump path via open/write/close).
// Stub them to "fail" — the screenshot path will gracefully no-op.
export fn open(path: ?[*:0]const u8, flags: c_int, ...) c_int {
    _ = path;
    _ = flags;
    return -1;
}
export fn close(fd: c_int) c_int {
    _ = fd;
    return -1;
}
export fn read(fd: c_int, buf: ?[*]u8, count: usize) c_long {
    _ = fd;
    _ = buf;
    _ = count;
    return -1;
}
export fn write(fd: c_int, buf: ?[*]const u8, count: usize) c_long {
    _ = fd;
    _ = buf;
    _ = count;
    return -1;
}
export fn unlink(path: ?[*:0]const u8) c_int {
    _ = path;
    return -1;
}
export fn lseek(fd: c_int, offset: c_long, whence: c_int) c_long {
    _ = fd;
    _ = offset;
    _ = whence;
    return -1;
}

// Dedicated-server mode flag. net_main flips its code paths on this; we're
// always a client, so it stays false. Defined here rather than in
// sys_zigos.c so the C side sees an external definition with the right
// linkage (qboolean is a 32-bit int in Q1).
export var isDedicated: c_int = 0;

// VCR (Video Cassette Recorder — Q1's replay debug feature) symbol. We
// don't compile net_vcr.c but net_main keeps a reference. Stub returns
// failure so net_main's optional VCR init silently no-ops.
export fn VCR_Init() c_int {
    return -1;
}

export fn qsort(base: ?[*]u8, nmemb: usize, size: usize, compar: *const fn (?*const anyopaque, ?*const anyopaque) callconv(.c) c_int) void {
    if (base == null or nmemb < 2) return;
    const b = base.?;
    var tmp_buf: [256]u8 = undefined;
    if (size > 256) return;
    var swapped = true;
    while (swapped) {
        swapped = false;
        for (0..nmemb - 1) |i| {
            const a_ptr = b + i * size;
            const b_ptr = b + (i + 1) * size;
            if (compar(a_ptr, b_ptr) > 0) {
                @memcpy(tmp_buf[0..size], a_ptr[0..size]);
                @memcpy(a_ptr[0..size], b_ptr[0..size]);
                @memcpy(b_ptr[0..size], tmp_buf[0..size]);
                swapped = true;
            }
        }
    }
}
