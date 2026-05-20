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

// ============================================================
// Input — zq_poll_keys / zq_next_key / zq_get_mouse_delta
// (driven by sys_zigos.c IN_Commands + Sys_SendKeyEvents + IN_Move)
// ============================================================

// Q1 key codes — must match quake_src/keys.h
const K_TAB: u8 = 9;
const K_ENTER: u8 = 13;
const K_ESCAPE: u8 = 27;
const K_SPACE: u8 = 32;
const K_BACKSPACE: u8 = 127;
const K_UPARROW: u8 = 128;
const K_DOWNARROW: u8 = 129;
const K_LEFTARROW: u8 = 130;
const K_RIGHTARROW: u8 = 131;
const K_ALT: u8 = 132;
const K_CTRL: u8 = 133;
const K_SHIFT: u8 = 134;
const K_F1: u8 = 135;
const K_INS: u8 = 147;
const K_DEL: u8 = 148;
const K_PGDN: u8 = 149;
const K_PGUP: u8 = 150;
const K_HOME: u8 = 151;
const K_END: u8 = 152;
const K_MOUSE1: u8 = 200;
const K_MOUSE2: u8 = 201;
const K_MOUSE3: u8 = 202;

// Scancodes we sample each tick. Letter rows + number row + special
// keys + arrows. Anything not here is invisible to Q1.
const poll_scancodes = [_]u8{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x2A, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x36, 0x38, 0x39, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42,
    0x43, 0x44, 0x47, 0x48, 0x49, 0x4B, 0x4D, 0x4F, 0x50, 0x51, 0x52,
    0x53, 0x57, 0x58,
};

fn scancodeToQ1Key(sc: u8) u8 {
    return switch (sc) {
        0x01 => K_ESCAPE,
        0x02 => '1',
        0x03 => '2',
        0x04 => '3',
        0x05 => '4',
        0x06 => '5',
        0x07 => '6',
        0x08 => '7',
        0x09 => '8',
        0x0A => '9',
        0x0B => '0',
        0x0C => '-',
        0x0D => '=',
        0x0E => K_BACKSPACE,
        0x0F => K_TAB,
        0x10 => 'q',
        0x11 => 'w',
        0x12 => 'e',
        0x13 => 'r',
        0x14 => 't',
        0x15 => 'y',
        0x16 => 'u',
        0x17 => 'i',
        0x18 => 'o',
        0x19 => 'p',
        0x1C => K_ENTER,
        0x1D => K_CTRL,
        0x1E => 'a',
        0x1F => 's',
        0x20 => 'd',
        0x21 => 'f',
        0x22 => 'g',
        0x23 => 'h',
        0x24 => 'j',
        0x25 => 'k',
        0x26 => 'l',
        0x2A, 0x36 => K_SHIFT,
        0x2C => 'z',
        0x2D => 'x',
        0x2E => 'c',
        0x2F => 'v',
        0x30 => 'b',
        0x31 => 'n',
        0x32 => 'm',
        0x38 => K_ALT,
        0x39 => K_SPACE,
        0x3B => K_F1,
        0x3C => K_F1 + 1,
        0x3D => K_F1 + 2,
        0x3E => K_F1 + 3,
        0x3F => K_F1 + 4,
        0x40 => K_F1 + 5,
        0x41 => K_F1 + 6,
        0x42 => K_F1 + 7,
        0x43 => K_F1 + 8,
        0x44 => K_F1 + 9,
        0x47 => K_HOME,
        0x48 => K_UPARROW,
        0x49 => K_PGUP,
        0x4B => K_LEFTARROW,
        0x4D => K_RIGHTARROW,
        0x4F => K_END,
        0x50 => K_DOWNARROW,
        0x51 => K_PGDN,
        0x52 => K_INS,
        0x53 => K_DEL,
        0x57 => K_F1 + 10,
        0x58 => K_F1 + 11,
        else => 0,
    };
}

const KeyEvent = struct { key: u8, down: u8 };
var key_queue: [128]KeyEvent = undefined;
var key_head: u32 = 0;
var key_tail: u32 = 0;

fn pushKey(key: u8, down: bool) void {
    if (key == 0) return;
    const next = (key_head + 1) % 128;
    if (next == key_tail) return; // full, drop
    key_queue[key_head] = .{ .key = key, .down = @intFromBool(down) };
    key_head = next;
}

var prev_key_state: [256]bool = [_]bool{false} ** 256;
var prev_mouse_buttons: u32 = 0;
var accum_dx: i32 = 0;
var accum_dy: i32 = 0;

export fn zq_poll_keys() void {
    // 1) Sample physical keys, emit press/release transitions
    for (poll_scancodes) |sc| {
        const q1_key = scancodeToQ1Key(sc);
        if (q1_key == 0) continue;
        const held = libc.keyHeld(sc);
        if (held != prev_key_state[q1_key]) {
            pushKey(q1_key, held);
            prev_key_state[q1_key] = held;
        }
    }
    // 2) Drain readable text from the char ring (typed chars not covered
    //    by scancodes — only useful for console input, which Q1 doesn't
    //    need for gameplay).
    while (libc.readChar() != 0) {}
    // 3) Sample mouse — accumulate motion, emit transitions for buttons
    const ms = libc.getMouse();
    accum_dx +%= ms.dx;
    accum_dy +%= ms.dy;
    const btn = ms.buttons;
    const cur_l = (btn & 1) != 0;
    const cur_r = (btn & 2) != 0;
    const cur_m = (btn & 4) != 0;
    const prev_l = (prev_mouse_buttons & 1) != 0;
    const prev_r = (prev_mouse_buttons & 2) != 0;
    const prev_m = (prev_mouse_buttons & 4) != 0;
    if (cur_l != prev_l) pushKey(K_MOUSE1, cur_l);
    if (cur_r != prev_r) pushKey(K_MOUSE2, cur_r);
    if (cur_m != prev_m) pushKey(K_MOUSE3, cur_m);
    prev_mouse_buttons = btn;
}

export fn zq_next_key(down_out: *c_int) c_int {
    if (key_tail == key_head) return 0;
    const ev = key_queue[key_tail];
    key_tail = (key_tail + 1) % 128;
    down_out.* = ev.down;
    return @intCast(ev.key);
}

export fn zq_get_mouse_delta(dx: *c_int, dy: *c_int) void {
    dx.* = accum_dx;
    dy.* = accum_dy;
    accum_dx = 0;
    accum_dy = 0;
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
// Math shims for Q1's C code. We must avoid Zig's @sin/@cos/@floor/etc.
// AND std.math.sin (which is just @sin) on this target
// (`x86_64-freestanding-none -mcpu baseline`): they lower to llvm.*
// intrinsics that resolve to a broken software fallback (no SSE4.1 →
// no ROUNDSD; missing libm symbols for transcendentals). The hang
// manifests as @sin/@cos/@floor never returning. Caught 2026-05-20.
// Hand-rolled software implementations below use only SSE2 ops
// (+, -, *, /, comparisons, cvttsd2si) which are always available
// on x86_64.

const PI: f64 = 3.14159265358979323846;
const TWO_PI: f64 = 6.28318530717958647692;
const HALF_PI: f64 = 1.57079632679489661923;

inline fn truncF64(x: f64) f64 {
    // SSE2 cvttsd2si truncates toward zero. Works for |x| < 2^63.
    return @as(f64, @floatFromInt(@as(i64, @intFromFloat(x))));
}

inline fn floorF64(x: f64) f64 {
    const t = truncF64(x);
    // Truncation = floor for x>=0; for negative non-integer, subtract 1.
    if (x < 0 and t != x) return t - 1.0;
    return t;
}

inline fn ceilF64(x: f64) f64 {
    const t = truncF64(x);
    if (x > 0 and t != x) return t + 1.0;
    return t;
}

// Range-reduced Taylor series for sin. Reduces y to [-π, π] then
// evaluates the standard Maclaurin series to 7 terms — good to ~1e-12
// over the range. Q1 uses sin/cos for animation phases and view
// rotation; double-precision overkill but the cost is one polynomial.
fn softSin(x_in: f64) f64 {
    var x = x_in;
    if (x > PI or x < -PI) {
        const k = floorF64(x / TWO_PI + 0.5);
        x = x - k * TWO_PI;
    }
    const x2 = x * x;
    // sin(x) = x - x^3/3! + x^5/5! - x^7/7! + x^9/9! - x^11/11! + x^13/13!
    var t = x;
    var sum = x;
    t = t * x2;
    sum -= t / 6.0;
    t = t * x2;
    sum += t / 120.0;
    t = t * x2;
    sum -= t / 5040.0;
    t = t * x2;
    sum += t / 362880.0;
    t = t * x2;
    sum -= t / 39916800.0;
    t = t * x2;
    sum += t / 6227020800.0;
    return sum;
}

fn softCos(x: f64) f64 {
    // cos(x) = sin(x + π/2)
    return softSin(x + HALF_PI);
}

export fn sin(x: f64) f64 {
    return softSin(x);
}
export fn sinf(x: f32) f32 {
    return @floatCast(softSin(@floatCast(x)));
}
export fn cos(x: f64) f64 {
    return softCos(x);
}
export fn cosf(x: f32) f32 {
    return @floatCast(softCos(@floatCast(x)));
}
export fn tan(x: f64) f64 {
    return softSin(x) / softCos(x);
}
export fn atan(x: f64) f64 {
    // atan via series; good enough for Q1 (mostly used in view angles).
    // For |x| > 1, use atan(x) = π/2 - atan(1/x) (sign-preserving).
    if (x > 1.0) return HALF_PI - atanCore(1.0 / x);
    if (x < -1.0) return -HALF_PI - atanCore(1.0 / x);
    return atanCore(x);
}
fn atanCore(x: f64) f64 {
    // Maclaurin series, converges for |x| <= 1.
    const x2 = x * x;
    var t = x;
    var sum = x;
    t = t * x2;
    sum -= t / 3.0;
    t = t * x2;
    sum += t / 5.0;
    t = t * x2;
    sum -= t / 7.0;
    t = t * x2;
    sum += t / 9.0;
    t = t * x2;
    sum -= t / 11.0;
    return sum;
}
export fn atan2(y: f64, x: f64) f64 {
    if (x > 0) return atan(y / x);
    if (x < 0 and y >= 0) return atan(y / x) + PI;
    if (x < 0 and y < 0) return atan(y / x) - PI;
    if (x == 0 and y > 0) return HALF_PI;
    if (x == 0 and y < 0) return -HALF_PI;
    return 0;
}
export fn asin(x: f64) f64 {
    // asin(x) = atan(x / sqrt(1 - x^2)) for |x| < 1
    if (x >= 1.0) return HALF_PI;
    if (x <= -1.0) return -HALF_PI;
    return atan(x / @sqrt(1.0 - x * x));
}
export fn acos(x: f64) f64 {
    return HALF_PI - asin(x);
}
export fn floor(x: f64) f64 {
    return floorF64(x);
}
export fn floorf(x: f32) f32 {
    return @floatCast(floorF64(@floatCast(x)));
}
export fn ceil(x: f64) f64 {
    return ceilF64(x);
}
export fn ceilf(x: f32) f32 {
    return @floatCast(ceilF64(@floatCast(x)));
}
export fn fabs(x: f64) f64 {
    return @abs(x);
}
export fn fabsf(x: f32) f32 {
    return @abs(x);
}
// Q1 doesn't actually call pow/exp/log in normal play (only in some
// software-renderer corner cases like coloured-lighting falloff which
// we don't compile). If anything does call them, return passable
// defaults instead of pulling in a transcendental impl. Replace with a
// real soft impl on first reported needs.
export fn pow(x: f64, y: f64) f64 {
    _ = y;
    return x;
}
export fn exp(x: f64) f64 {
    return 1.0 + x;
}
export fn log(x: f64) f64 {
    _ = x;
    return 0.0;
}
export fn fmod(x: f64, y: f64) f64 {
    // x - trunc(x/y) * y
    if (y == 0) return 0;
    return x - truncF64(x / y) * y;
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

// IMPORTANT: do NOT use @memcpy / @memset inside these — Zig lowers
// those builtins to `call memcpy` / `call memset`, which recurses into
// us infinitely (jmp <self>). Lifted from doom_real.zig where this was
// already done right.
export fn memcpy(dest: ?[*]u8, src: ?[*]const u8, n: usize) ?[*]u8 {
    if (dest == null or src == null) return dest;
    const d = dest.?;
    const s = src.?;
    const words = n / 8;
    const d64: [*]align(1) u64 = @ptrCast(d);
    const s64: [*]align(1) const u64 = @ptrCast(s);
    for (0..words) |i| d64[i] = s64[i];
    for (words * 8..n) |i| d[i] = s[i];
    return dest;
}

export fn memmove(dest: ?[*]u8, src: ?[*]const u8, n: usize) ?[*]u8 {
    if (dest == null or src == null or n == 0) return dest;
    const d = dest.?;
    const s = src.?;
    if (@intFromPtr(d) < @intFromPtr(s)) {
        // Forward, hand-rolled (same reason as memcpy above).
        const words = n / 8;
        const d64: [*]align(1) u64 = @ptrCast(d);
        const s64: [*]align(1) const u64 = @ptrCast(s);
        for (0..words) |i| d64[i] = s64[i];
        for (words * 8..n) |i| d[i] = s[i];
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
        const word: u64 = @as(u64, byte) * 0x0101010101010101;
        const words = n / 8;
        const d64: [*]align(1) u64 = @ptrCast(d);
        for (0..words) |i| d64[i] = word;
        for (words * 8..n) |i| d[i] = byte;
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
    // NOTE: previous version called `frac -= @floor(frac)`, which Zig
    // lowers to llvm.floor on freestanding-x86_64-baseline (no ROUNDSD
    // available pre-SSE4.1) and the resulting builtin hung Q1 for the
    // first sprintf("%f", 0.0f) call from Cvar_SetValue. Caught 2026-05-20.
    // Since `d` is already the truncated-toward-zero integer part of
    // `frac` (which is non-negative at this point), converting it back
    // to f64 and subtracting yields the same result as @floor without
    // hitting the broken builtin.
    for (0..p) |_| {
        frac *= 10.0;
        const d: u32 = @intFromFloat(frac);
        if (pos.* < max) buf[pos.*] = '0' + @as(u8, @intCast(d % 10));
        pos.* += 1;
        frac -= @as(f64, @floatFromInt(d));
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

// C ABI for `va_list` on x86_64 SysV: __va_list_tag[1] decayed to
// __va_list_tag*. Zig's `ap: VaList` parameter would expect the 24-byte
// array; mismatch produces garbage. Take the pointer directly so both
// sides agree on "8 bytes in rdx". Caught 2026-05-20 — Q1's va() chain
// produced "(null)" for basedir, breaking pak0.pak path construction.
export fn vsprintf(buf: ?[*]u8, fmt: ?[*:0]const u8, ap: *VaList) c_int {
    return vsnprintf(buf, 4096, fmt, ap);
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

export fn vfprintf(fp: ?*anyopaque, fmt: ?[*:0]const u8, in_ap: *VaList) c_int {
    _ = fp;
    var tmp: [512]u8 = undefined;
    const len = vsnprintf(&tmp, 512, fmt, in_ap);
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
// File I/O — streaming FILE* (kernel fd + cursor, no preload)
// ============================================================
//
// Doom's wrapper used libc.mmapFile to slurp doom1.wad (4 MB) on open.
// For Q1's 18 MB pak0.pak that pinned ~18 MB of physical frames for
// the lifetime of the file handle — Q1 walks the PAK linearly during
// COM_LoadPackFile, so every page faulted in but nothing got dropped,
// leaving the OS effectively out of RAM by Host_Init's end.
//
// Streaming model: FILE* holds {kernel_fd, size, pos}. fread issues a
// real sysFread; fseek issues sysSeek (new syscall #111). No buffer
// retained between calls. Q1's read pattern (header + per-entry
// fseek+fread) is naturally low-memory.

const FILE = extern struct {
    fd: u32, // kernel file descriptor (0xFFFFFFFF = invalid)
    size: u32, // total file size from fsize (cached)
    pos: u32, // user-side cursor; kernel cursor is kept in sync
    mode: u8, // 0=closed, 1=stream-read, 2=write-only console sink
    at_eof: u8,
    _pad: [2]u8 = .{ 0, 0 },
};

const MAX_FILES_OPEN = 16;
var file_pool: [MAX_FILES_OPEN]FILE = [_]FILE{.{ .fd = 0xFFFFFFFF, .size = 0, .pos = 0, .mode = 0, .at_eof = 0 }} ** MAX_FILES_OPEN;
var stdout_file: FILE = .{ .fd = 0xFFFFFFFF, .size = 0, .pos = 0, .mode = 2, .at_eof = 0 };
var stderr_file: FILE = .{ .fd = 0xFFFFFFFF, .size = 0, .pos = 0, .mode = 2, .at_eof = 0 };

export const stdin: *FILE = &stderr_file;
export const stdout: *FILE = &stdout_file;
export const stderr: *FILE = &stderr_file;

export fn fopen(path: ?[*:0]const u8, mode: ?[*:0]const u8) ?*FILE {
    if (path == null) return null;
    _ = mode;
    const p = path.?;
    var plen: usize = 0;
    while (p[plen] != 0) plen += 1;

    const sz = libc.fsize(p[0..plen]) orelse return null;
    const fd = libc.open(p[0..plen]) orelse return null;

    for (&file_pool) |*slot| {
        if (slot.mode == 0) {
            slot.fd = fd;
            slot.size = sz;
            slot.pos = 0;
            slot.mode = 1;
            slot.at_eof = 0;
            return slot;
        }
    }
    libc.close(fd);
    return null;
}

export fn fclose(fp: ?*FILE) c_int {
    if (fp) |f| {
        if (f == &stdout_file or f == &stderr_file) return 0;
        if (f.mode != 0 and f.fd != 0xFFFFFFFF) {
            libc.close(f.fd);
        }
        f.mode = 0;
        f.fd = 0xFFFFFFFF;
    }
    return 0;
}

export fn fread(ptr: ?[*]u8, size: usize, nmemb: usize, fp: ?*FILE) usize {
    if (ptr == null or fp == null or size == 0 or nmemb == 0) return 0;
    const f = fp.?;
    if (f.mode != 1 or f.fd == 0xFFFFFFFF) return 0;
    const total: usize = size * nmemb;
    const avail: usize = @as(usize, f.size) -| @as(usize, f.pos);
    const to_read: u32 = @intCast(@min(total, avail));
    if (to_read == 0) {
        f.at_eof = 1;
        return 0;
    }
    const got = libc.fread(f.fd, ptr.?[0..to_read]);
    if (got < to_read) f.at_eof = 1;
    f.pos += got;
    return got / size;
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
    if (f.mode != 1 or f.fd == 0xFFFFFFFF) return -1;
    var new_pos: i64 = switch (whence) {
        0 => offset, // SEEK_SET
        1 => @as(i64, f.pos) + offset, // SEEK_CUR
        2 => @as(i64, f.size) + offset, // SEEK_END
        else => return -1,
    };
    if (new_pos < 0) new_pos = 0;
    if (new_pos > @as(i64, f.size)) new_pos = @as(i64, f.size);
    const np: u32 = @intCast(new_pos);
    // Sync kernel cursor. SEEK_SET on the kernel side is `whence=0`.
    _ = libc.seek(f.fd, np, 0) orelse return -1;
    f.pos = np;
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
        if (f.mode == 1 and f.fd != 0xFFFFFFFF) {
            _ = libc.seek(f.fd, 0, 0);
        }
        f.pos = 0;
        f.at_eof = 0;
    }
}

export fn fflush(fp: ?*FILE) c_int {
    _ = fp;
    return 0;
}

export fn fgetc(fp: ?*FILE) c_int {
    var ch: [1]u8 = .{0};
    const n = fread(&ch, 1, 1, fp);
    if (n == 0) return -1;
    return @as(c_int, ch[0]);
}

export fn fgets(s: ?[*]u8, size: c_int, fp: ?*FILE) ?[*]u8 {
    if (s == null or fp == null or size <= 0) return null;
    const buf = s.?;
    var i: usize = 0;
    const max: usize = @intCast(size - 1);
    while (i < max) {
        const ch = fgetc(fp);
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
    // Original integer-loop formulation (`val = val*10 + @floatFromInt(str[i]-'0')`)
    // miscompiled under Zig 0.15.2 ReleaseSafe: the inner `@floatFromInt` returned
    // the raw byte (e.g. atof("544") -> 53.0 = '5'), so info_player_start origin
    // "544 288 32" parsed as (53, 50, 51) and Quake's player spawned outside the
    // map. Caught 2026-05-21. Use an explicit u32 accumulator + one @floatFromInt
    // at the end — pattern that survives the codegen path used by atoi.
    if (s == null) return 0.0;
    const str = s.?;
    var i: usize = 0;
    while (str[i] == ' ') i += 1;
    var neg = false;
    if (str[i] == '-') {
        neg = true;
        i += 1;
    } else if (str[i] == '+') i += 1;

    var int_acc: u64 = 0;
    while (str[i] >= '0' and str[i] <= '9') {
        const digit: u8 = str[i] - '0';
        int_acc = int_acc * 10 + @as(u64, digit);
        i += 1;
    }
    var val: f64 = @as(f64, @floatFromInt(int_acc));

    if (str[i] == '.') {
        i += 1;
        var frac_acc: u64 = 0;
        var frac_div: f64 = 1.0;
        while (str[i] >= '0' and str[i] <= '9') {
            const digit: u8 = str[i] - '0';
            frac_acc = frac_acc * 10 + @as(u64, digit);
            frac_div *= 10.0;
            i += 1;
        }
        val += @as(f64, @floatFromInt(frac_acc)) / frac_div;
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
