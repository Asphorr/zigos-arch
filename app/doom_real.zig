// ZigOS DOOM port — platform layer + libc shim for doomgeneric
// Provides _start entry, DG_* platform bridge functions, and all C library
// functions needed by the DOOM engine (exported with C ABI).

const libc = @import("libc");

// --- C externs from doomgeneric ---
extern fn doomgeneric_Create(argc: c_int, argv: [*][*:0]u8) void;
extern fn doomgeneric_Tick() void;
extern var DG_ScreenBuffer: [*]u32;

// --- Constants ---
const DOOM_W: u32 = 640;
const DOOM_H: u32 = 400;

// DOOM key definitions
const KEY_RIGHTARROW: u8 = 0xae;
const KEY_LEFTARROW: u8 = 0xac;
const KEY_UPARROW: u8 = 0xad;
const KEY_DOWNARROW: u8 = 0xaf;
const KEY_ESCAPE: u8 = 27;
const KEY_ENTER: u8 = 13;
const KEY_TAB: u8 = 9;
const KEY_STRAFE_L: u8 = 0xa0;
const KEY_STRAFE_R: u8 = 0xa1;
const KEY_USE: u8 = 0xa2;
const KEY_FIRE: u8 = 0xa3;
const KEY_RSHIFT: u8 = 0x80 + 0x36;
const KEY_RCTRL: u8 = 0x80 + 0x1d;
const KEY_RALT: u8 = 0x80 + 0x38;

// --- State ---
var fb: [*]volatile u32 = undefined;
var start_ticks: u32 = 0;

// Mouse tracking

// Key event queue
const KeyEvent = struct { pressed: u8, key: u8 };
var key_queue: [64]KeyEvent = undefined;
var key_head: u32 = 0;
var key_tail: u32 = 0;

// Track logical DOOM key state with debounce (not physical scancodes)
var logical_state: [256]bool = [_]bool{false} ** 256;
var release_timers: [256]u32 = [_]u32{0} ** 256;
var repeat_timers: [256]u32 = [_]u32{0} ** 256;

const poll_scancodes = [_]u8{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x2A, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
    0x36, 0x38, 0x39, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42,
    0x43, 0x44, 0x48, 0x4B, 0x4D, 0x50, 0x57, 0x58,
};

fn scancodeToKey(sc: u8) u8 {
    return switch (sc) {
        0x01 => KEY_ESCAPE,
        0x0E => 127,
        0x0F => KEY_TAB,
        0x1C => KEY_ENTER,
        0x1D => KEY_FIRE, // Ctrl = fire
        0x39 => KEY_USE, // Space = use/open
        0x48 => KEY_UPARROW,
        0x50 => KEY_DOWNARROW,
        0x4B => KEY_LEFTARROW,
        0x4D => KEY_RIGHTARROW,
        // WASD mapped to DOOM's movement keys
        0x11 => KEY_UPARROW, // W = forward
        0x1F => KEY_DOWNARROW, // S = backward
        0x1E => KEY_STRAFE_L, // A = strafe left
        0x20 => KEY_STRAFE_R, // D = strafe right
        0x2A, 0x36 => KEY_RSHIFT,
        0x38 => KEY_RALT,
        // Letters for cheat codes
        0x10 => 'q',
        0x12 => 'e',
        0x13 => 'r',
        0x14 => 't',
        0x15 => 'y',
        0x16 => 'u',
        0x17 => 'i',
        0x18 => 'o',
        0x19 => 'p',
        0x21 => 'f',
        0x22 => 'g',
        0x23 => 'h',
        0x24 => 'j',
        0x25 => 'k',
        0x26 => 'l',
        0x2C => 'z',
        0x2D => 'x',
        0x2E => 'c',
        0x2F => 'v',
        0x30 => 'b',
        0x31 => 'n',
        0x32 => 'm',
        // Numbers (weapon select)
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
        else => 0,
    };
}

fn pushKeyEvent(pressed: bool, key: u8) void {
    if (key == 0) return;
    const next = (key_head + 1) % 64;
    if (next == key_tail) return;
    key_queue[key_head] = .{ .pressed = @intFromBool(pressed), .key = key };
    key_head = next;
}

fn pollKeys() void {
    while (libc.readChar() != 0) {}

    const now = libc.uptime();

    // 1. Collect physical state into logical DOOM keys
    //    (merges W + Up arrow into single KEY_UPARROW)
    var current_physical = [_]bool{false} ** 256;
    for (poll_scancodes) |sc| {
        if (libc.keyHeld(sc)) {
            const doom_key = scancodeToKey(sc);
            if (doom_key != 0) current_physical[doom_key] = true;
        }
    }

    // 2. Apply debounce and generate events
    for (0..256) |k| {
        const doom_key: u8 = @intCast(k);
        const physical_held = current_physical[doom_key];

        if (physical_held) {
            release_timers[doom_key] = 0; // Cancel false release

            if (!logical_state[doom_key]) {
                // Fresh press
                logical_state[doom_key] = true;
                pushKeyEvent(true, doom_key);
                repeat_timers[doom_key] = now +% 40; // 400ms before repeat
            } else {
                // Typematic repeat for menus
                if (now >= repeat_timers[doom_key]) {
                    pushKeyEvent(true, doom_key);
                    repeat_timers[doom_key] = now +% 5; // Repeat every 50ms
                }
            }
        } else {
            if (logical_state[doom_key]) {
                if (release_timers[doom_key] == 0) {
                    release_timers[doom_key] = now +% 5; // 50ms debounce window
                } else if (now >= release_timers[doom_key]) {
                    // Key truly released for 50ms — believe it
                    logical_state[doom_key] = false;
                    release_timers[doom_key] = 0;
                    pushKeyEvent(false, doom_key);
                }
            }
        }
    }
}

// ============================================================
// Entry point
// ============================================================

export fn _start() linksection(".text.entry") callconv(.c) void {
    start_ticks = libc.uptime();

    const win = libc.createWindow(DOOM_W, DOOM_H) orelse {
        libc.exit();
        return;
    };
    fb = win.fb;
    libc.setCursorVisible(false);

    // Probe both possible WAD locations and pick whichever exists. Order
    // matters: ext2 is the new primary FS (run-uefi-ext2.sh swaps disk.img
    // out for ext2.img on IDE2), so /ext2/share/doom1.wad is the modern
    // path. /fat/doom1.wad is the legacy path used when booting with
    // FAT32 disk.img still on IDE2.
    //
    // Without the probe, hardcoding /fat/ panics doom on the ext2 boot
    // path: D_FindIWAD returns NULL → I_Error("can't find IWAD") →
    // vsnprintf NULL-derefs (separate libc bug, but the proximate cause
    // is just "wrong path").
    const wad_path: [*:0]const u8 = blk: {
        if (libc.fsize("/ext2/share/doom1.wad")) |_| break :blk "/ext2/share/doom1.wad";
        if (libc.fsize("/fat/doom1.wad")) |_| break :blk "/fat/doom1.wad";
        // Last-ditch: cwd-relative. Some setups put it next to the binary.
        break :blk "doom1.wad";
    };
    var argv = [_][*:0]u8{
        @ptrCast(@constCast("doom")),
        @ptrCast(@constCast("-iwad")),
        @ptrCast(@constCast(wad_path)),
    };
    doomgeneric_Create(3, &argv);

    while (true) {
        pollKeys(); // Snapshot keyboard state once per tick
        doomgeneric_Tick();
    }
}

// ============================================================
// DG_* Platform bridge (exported for C)
// ============================================================

export fn DG_Init() void {}

var frame_num: u32 = 0;

export fn DG_DrawFrame() void {
    frame_num +%= 1;
    // Copy DOOM's 640x400 XRGB buffer to our framebuffer
    const pixels = DOOM_W * DOOM_H;
    const src = DG_ScreenBuffer;
    @memcpy(fb[0..pixels], src[0..pixels]);
    libc.present();
}

export fn DG_SleepMs(ms: u32) void {
    if (ms > 0) libc.sleep(ms);
}

export fn DG_GetTicksMs() u32 {
    return (libc.uptime() -% start_ticks) * 10;
}

export fn DG_GetKey(pressed: *c_int, doom_key: *u8) c_int {
    // pollKeys() is called once per tick in _start, NOT here
    if (key_tail == key_head) return 0;
    const ev = key_queue[key_tail];
    key_tail = (key_tail + 1) % 64;
    pressed.* = ev.pressed;
    doom_key.* = ev.key;
    return 1;
}

export fn DG_SetWindowTitle(title: [*:0]const u8) void {
    _ = title;
}

export fn DG_GetMouse(dx: *c_int, dy: *c_int, buttons: *c_int) c_int {
    const ms = libc.getMouse();
    const btn: u32 = ms.buttons;

    // Remap: OS bit0=left, bit1=right, bit2=middle
    // DOOM: bit0=left(fire), bit1=right(strafe), bit2=middle
    var doom_btn: c_int = 0;
    if (btn & 1 != 0) doom_btn |= 1; // left = fire
    if (btn & 2 != 0) doom_btn |= 2; // right = strafe
    if (btn & 4 != 0) doom_btn |= 4; // middle

    // Use kernel-accumulated deltas (no centering needed, no feedback loop)
    const sensitivity: i32 = 4;
    const sdx = ms.dx * sensitivity;
    const sdy = ms.dy * sensitivity;
    dx.* = if (sdx > 200) @as(i32, 200) else if (sdx < -200) @as(i32, -200) else sdx;
    dy.* = if (sdy > 200) @as(i32, 200) else if (sdy < -200) @as(i32, -200) else sdy;
    buttons.* = doom_btn;
    return @intFromBool(ms.dx != 0 or ms.dy != 0 or doom_btn != 0);
}

// ============================================================
// Memory management
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
// String functions
// ============================================================

export fn memcpy(dest: ?[*]u8, src: ?[*]const u8, n: usize) ?[*]u8 {
    if (dest == null or src == null) return dest;
    const d = dest.?;
    const s = src.?;
    // Word-sized copy for bulk, then byte tail
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
        // Word-sized fill for bulk, then byte tail
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

export fn strlen(s: ?[*:0]const u8) usize {
    if (s == null) return 0;
    var len: usize = 0;
    while (s.?[len] != 0) len += 1;
    return len;
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

export fn strlcpy(dst: [*]u8, src: [*:0]const u8, siz: usize) usize {
    const slen = strlen(src);
    if (siz > 0) {
        const copy = if (slen < siz - 1) slen else siz - 1;
        @memcpy(dst[0..copy], src[0..copy]);
        dst[copy] = 0;
    }
    return slen;
}

export fn strlcat(dst: [*:0]u8, src: [*:0]const u8, siz: usize) usize {
    const dlen = strlen(dst);
    const slen = strlen(src);
    if (dlen >= siz) return siz + slen;
    const avail = siz - dlen - 1;
    const copy = if (slen < avail) slen else avail;
    @memcpy(dst[dlen..][0..copy], src[0..copy]);
    dst[dlen + copy] = 0;
    return dlen + slen;
}

// ============================================================
// Character classification
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
// Formatted I/O — minimal vsnprintf supporting %d %u %x %X %s %c %p %%
// ============================================================

const CUint = u32;

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
    // Pad
    const pad_char: u8 = if (zero_pad) '0' else ' ';
    if (width > len) {
        const pad_count = width - len;
        for (0..pad_count) |_| {
            if (pos.* < max) buf[pos.*] = pad_char;
            pos.* += 1;
        }
    }
    // Write digits in reverse
    var i: u32 = len;
    while (i > 0) {
        i -= 1;
        if (pos.* < max) buf[pos.*] = tmp[i];
        pos.* += 1;
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
        i += 1; // skip '%'

        // Parse flags
        var zero_pad = false;
        while (f[i] == '0' or f[i] == '-') {
            if (f[i] == '0') zero_pad = true;
            // '-' (left-align) parsed but not implemented
            i += 1;
        }

        // Parse width
        var width: u32 = 0;
        while (f[i] >= '0' and f[i] <= '9') {
            width = width * 10 + (f[i] - '0');
            i += 1;
        }

        // Parse precision (e.g., %.3d)
        if (f[i] == '.') {
            i += 1;
            var prec: u32 = 0;
            while (f[i] >= '0' and f[i] <= '9') {
                prec = prec * 10 + (f[i] - '0');
                i += 1;
            }
            // For integers, precision = minimum digits (zero-padded)
            if (prec > width) {
                width = prec;
                zero_pad = true;
            }
        }

        // Parse length modifier
        var is_long = false;
        if (f[i] == 'l') {
            is_long = true;
            i += 1;
        }
        if (f[i] == 'l') {
            i += 1;
        } // ll

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
            's' => {
                const s: ?[*:0]const u8 = va_arg(ap, ?[*:0]const u8);
                const addr = @intFromPtr(s);
                // Validate pointer: must be non-null and in a reasonable address range
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

const VaList = @import("std").builtin.VaList;
fn va_arg(ap: *VaList, comptime T: type) T {
    return @cVaArg(ap, T);
}

const CLong = i64;
const CUlong = u64;

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

export fn printf(fmt: ?[*:0]const u8, ...) c_int {
    var tmp: [512]u8 = undefined;
    var ap = @cVaStart();
    defer @cVaEnd(&ap);
    const len = vsnprintf(&tmp, 512, fmt, &ap);
    if (len > 0) {
        const slen: usize = @intCast(@min(len, 511));
        libc.print(tmp[0..slen]);
        // Save last message for exit diagnostics
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
    if (len > 0) {
        const slen: usize = @intCast(@min(len, 511));
        libc.print(tmp[0..slen]);
        const clen = @min(slen, last_msg.len);
        @memcpy(last_msg[0..clen], tmp[0..clen]);
        last_msg_len = clen;
    }
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
        var len: usize = 0;
        while (str[len] != 0) len += 1;
        libc.print(str[0..len]);
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
        var len: usize = 0;
        while (str[len] != 0) len += 1;
        libc.print(str[0..len]);
    }
    return 0;
}

export fn fputc(c: c_int, fp: ?*anyopaque) c_int {
    _ = fp;
    libc.printChar(@truncate(@as(CUint, @bitCast(c))));
    return c;
}

export fn perror(s: ?[*:0]const u8) void {
    if (s) |str| {
        _ = puts(str);
    }
}

// ============================================================
// File I/O — memory-mapped FILE*
// ============================================================

const FILE = extern struct {
    data: ?[*]u8,
    size: u32,
    pos: u32,
    mode: u8, // 0=closed, 1=read, 2=write
    at_eof: u8,
    // 1 = `data` is an mmap region from libc.mmapFile (page-aligned, demand-
    // paged), 0 = malloc'd + fread fallback. fclose has to do different
    // cleanup for each. C side never inspects these — FILE is opaque to
    // doomgeneric — so adding fields is safe.
    is_mmap: u8 = 0,
    _pad: u8 = 0,
};

const MAX_FILES_OPEN = 8;
var file_pool: [MAX_FILES_OPEN]FILE = [_]FILE{.{ .data = null, .size = 0, .pos = 0, .mode = 0, .at_eof = 0 }} ** MAX_FILES_OPEN;

// stdout/stderr as special FILEs
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

    // Fast path: file-backed mmap. fsize tells the kernel exactly how much
    // VA to reserve; pages stream in on first touch via the page-fault
    // handler instead of a 64 KB-chunk fread loop. For the IWAD this used
    // to burn ~100 seconds of CPU in our fread (760ms per chunk × 64
    // chunks); mmap turns it into "open + fsize + mmap" with no copy.
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

    // Fallback: malloc + chunked fread. Used when fsize fails (devices, pipes)
    // or mmap fails (large file under PMM fragmentation — allocContiguous
    // wants contiguous frames). Existing capacity-doubling logic preserved.
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

    // file_pool full — release the mmap mapping (malloc fallback leaks, same
    // as before this change; matches the existing realloc-fail comment).
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
    return 0; // writing to files not supported
}

export fn fseek(fp: ?*FILE, offset: c_long, whence: c_int) c_int {
    if (fp == null) return -1;
    const f = fp.?;
    var new_pos: i64 = switch (whence) {
        0 => offset, // SEEK_SET
        1 => @as(i64, f.pos) + offset, // SEEK_CUR
        2 => @as(i64, f.size) + offset, // SEEK_END
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

// ============================================================
// sscanf — minimal: supports %d and %s
// ============================================================

export fn sscanf(str: ?[*:0]const u8, fmt: ?[*:0]const u8, ...) c_int {
    _ = str;
    _ = fmt;
    return 0; // stub — DOOM config parsing will get defaults
}

// ============================================================
// Other stubs
// ============================================================

export var errno: c_int = 0;

var last_msg: [512]u8 = undefined;
var last_msg_len: usize = 0;

export fn exit(status: c_int) callconv(.c) noreturn {
    _ = status;
    // Print last message DOOM printed (likely I_Error) so it shows on screen
    if (last_msg_len > 0) {
        libc.print("DOOM exit: ");
        libc.print(last_msg[0..last_msg_len]);
        libc.printChar('\n');
    } else {
        libc.print("DOOM exit (no message)\n");
    }
    // Wait a bit so user can see the message in the terminal
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

export fn atof(s: ?[*:0]const u8) f64 {    if (s == null) return 0.0;    const str = s.?;    var i: usize = 0;    while (str[i] == 0x20) i += 1;    var neg = false;    if (str[i] == 0x2d) { neg = true; i += 1; }    else if (str[i] == 0x2b) i += 1;    var val: f64 = 0.0;    while (str[i] >= 0x30 and str[i] <= 0x39) {        val = val * 10.0 + @as(f64, @floatFromInt(str[i] - 0x30));        i += 1;    }    if (str[i] == 0x2e) {        i += 1;        var frac: f64 = 0.1;        while (str[i] >= 0x30 and str[i] <= 0x39) {            val += @as(f64, @floatFromInt(str[i] - 0x30)) * frac;            frac *= 0.1;            i += 1;        }    }    return if (neg) -val else val;}
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

export fn getenv(name: ?[*:0]const u8) ?[*:0]const u8 {
    _ = name;
    return null;
}

export fn system(cmd: ?[*:0]const u8) c_int {
    _ = cmd;
    return -1;
}

export fn access(path: ?[*:0]const u8, mode: c_int) c_int {
    _ = path;
    _ = mode;
    return -1;
}

export fn stat(path: ?[*:0]const u8, buf: ?*anyopaque) c_int {
    _ = path;
    _ = buf;
    return -1;
}

export fn mkdir(path: ?[*:0]const u8, mode: c_uint) c_int {
    _ = path;
    _ = mode;
    return -1;
}

export fn rename(old: ?[*:0]const u8, new_path: ?[*:0]const u8) c_int {
    _ = old;
    _ = new_path;
    return -1;
}

export fn remove(path: ?[*:0]const u8) c_int {
    _ = path;
    return -1;
}

export fn signal(signum: c_int, handler: ?*anyopaque) ?*anyopaque {
    _ = signum;
    _ = handler;
    return null;
}

export fn time(t: ?*i64) i64 {
    const v: i64 = @as(i64, libc.uptime()) * 10;
    if (t) |p| p.* = v;
    return v;
}

export fn localtime(timer: ?*const i64) ?*anyopaque {
    _ = timer;
    return null;
}

export fn clock() i64 {
    return @as(i64, libc.uptime()) * 10000;
}

var rand_state: u32 = 1;
export fn rand() c_int {
    rand_state = rand_state *% 1103515245 +% 12345;
    return @as(c_int, @intCast((rand_state >> 16) & 0x7fff));
}

export fn srand(seed: c_uint) void {
    rand_state = seed;
}

export fn qsort(base: ?[*]u8, nmemb: usize, size: usize, compar: *const fn (?*const anyopaque, ?*const anyopaque) callconv(.c) c_int) void {
    // Simple bubble sort (DOOM rarely calls qsort)
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

// ============================================================
// DOOM Sound Module — 8-channel software mixer → AC97
// ============================================================

const NUM_CHANNELS = 8;
const MIX_RATE = 22050;
const MIX_BUF_SAMPLES = MIX_RATE / 35 + 1; // ~630 samples per game tick

const Channel = struct {
    data: ?[*]const u8 = null, // WAD sound data (8-bit unsigned, after 8-byte header)
    length: u32 = 0, // total samples
    pos: u32 = 0, // current position (fixed-point 16.16)
    step: u32 = 0, // step per output sample (fixed-point 16.16)
    vol_left: i32 = 0,
    vol_right: i32 = 0,
    active: bool = false,
};

var channels: [NUM_CHANNELS]Channel = [_]Channel{.{}} ** NUM_CHANNELS;
var mix_buf: [MIX_BUF_SAMPLES * 2]i16 = undefined; // stereo interleaved

// C externs for WAD lump access
extern fn W_CheckNumForName(name: [*:0]const u8) c_int; // returns -1 if not found (safe)
extern fn W_LumpLength(lump: c_int) c_int;
extern fn W_CacheLumpNum(lump: c_int, tag: c_int) ?[*]const u8;

const PU_STATIC: c_int = 1;
const SNDDEVICE_SB: c_int = 3;

// sfxinfo_t — must match C struct layout
const SfxInfo = extern struct {
    tagname: ?[*:0]u8,
    name: [9]u8,
    priority: c_int,
    link: ?*SfxInfo,
    pitch: c_int,
    volume: c_int,
    usefulness: c_int,
    lumpnum: c_int,
    numchannels: c_int,
    driver_data: ?*anyopaque,
};

fn sndInit(_: c_int) callconv(.c) c_int {
    return 1; // success
}

fn sndShutdown() callconv(.c) void {}

fn sndGetSfxLumpNum(sfx: *SfxInfo) callconv(.c) c_int {
    var buf: [12]u8 = undefined;
    buf[0] = 'd';
    buf[1] = 's';
    var i: usize = 0;
    while (i < 9 and sfx.name[i] != 0) : (i += 1) {
        buf[2 + i] = sfx.name[i];
    }
    buf[2 + i] = 0;
    return W_CheckNumForName(@ptrCast(&buf)); // safe: returns -1 if missing
}

fn sndUpdate() callconv(.c) void {
    // Mix all active channels into mix_buf
    @memset(@as([*]u8, @ptrCast(&mix_buf))[0 .. MIX_BUF_SAMPLES * 4], 0);

    for (&channels) |*ch| {
        if (!ch.active) continue;
        const data = ch.data orelse continue;

        for (0..MIX_BUF_SAMPLES) |i| {
            const sample_idx = ch.pos >> 16;
            if (sample_idx >= ch.length) {
                ch.active = false;
                break;
            }
            // Convert 8-bit unsigned to 16-bit signed
            const raw: i32 = @as(i32, data[sample_idx]) - 128;
            const sample: i32 = raw * 256; // scale to 16-bit range

            // Mix with saturation clamping
            const left = @as(i32, mix_buf[i * 2]) + @divTrunc(sample * ch.vol_left, 128);
            const right = @as(i32, mix_buf[i * 2 + 1]) + @divTrunc(sample * ch.vol_right, 128);
            mix_buf[i * 2] = @intCast(if (left < -32768) @as(i32, -32768) else if (left > 32767) @as(i32, 32767) else left);
            mix_buf[i * 2 + 1] = @intCast(if (right < -32768) @as(i32, -32768) else if (right > 32767) @as(i32, 32767) else right);

            ch.pos += ch.step;
        }
    }

    // TODO: audio output disabled for debugging — mixer runs but no output
    //_ = libc.audioWrite(&mix_buf, MIX_BUF_SAMPLES);
}

fn sndUpdateParams(channel: c_int, vol: c_int, sep: c_int) callconv(.c) void {
    if (channel < 0 or channel >= NUM_CHANNELS) return;
    const ch = &channels[@intCast(channel)];
    // sep: 0=right, 128=center, 255=left
    ch.vol_left = @divTrunc(@as(i32, vol) * (255 - @as(i32, sep)), 255);
    ch.vol_right = @divTrunc(@as(i32, vol) * @as(i32, sep), 255);
}

fn sndStartSound(sfx: ?*SfxInfo, channel: c_int, vol: c_int, sep: c_int) callconv(.c) c_int {
    if (channel < 0 or channel >= NUM_CHANNELS) return -1;
    const s = sfx orelse return -1;
    const lump = s.lumpnum;
    if (lump < 0) return -1;

    const lump_data = W_CacheLumpNum(lump, PU_STATIC) orelse return -1;
    const lump_len = W_LumpLength(lump);
    if (lump_len < 8) return -1;

    // DOOM sound lump format: [0..1]=format, [2..3]=sample_rate, [4..7]=sample_count, [8..]=data
    const sample_rate: u32 = @as(u32, lump_data[2]) | (@as(u32, lump_data[3]) << 8);
    const num_samples: u32 = @as(u32, lump_data[4]) | (@as(u32, lump_data[5]) << 8) |
        (@as(u32, lump_data[6]) << 16) | (@as(u32, lump_data[7]) << 24);

    const ch = &channels[@intCast(channel)];
    ch.data = lump_data + 8; // skip header
    ch.length = @min(num_samples, @as(u32, @intCast(lump_len)) -| 8);
    ch.pos = 0;
    ch.step = if (sample_rate > 0) (sample_rate << 16) / MIX_RATE else (1 << 16);
    ch.active = true;
    sndUpdateParams(channel, vol, sep);
    return channel;
}

fn sndStopSound(channel: c_int) callconv(.c) void {
    if (channel >= 0 and channel < NUM_CHANNELS) channels[@intCast(channel)].active = false;
}

fn sndIsPlaying(channel: c_int) callconv(.c) c_int {
    if (channel < 0 or channel >= NUM_CHANNELS) return 0;
    return @intFromBool(channels[@intCast(channel)].active);
}

fn sndCacheSounds(_: ?*SfxInfo, _: c_int) callconv(.c) void {}

// --- Music module stub (no music support yet) ---
fn musInit() callconv(.c) c_int { return 0; }
fn musShutdown() callconv(.c) void {}
fn musSetVol(_: c_int) callconv(.c) void {}
fn musPause() callconv(.c) void {}
fn musResume() callconv(.c) void {}
fn musRegister(_: ?*anyopaque, _: c_int) callconv(.c) ?*anyopaque { return null; }
fn musUnRegister(_: ?*anyopaque) callconv(.c) void {}
fn musPlay(_: ?*anyopaque, _: c_int) callconv(.c) void {}
fn musStop() callconv(.c) void {}
fn musIsPlaying() callconv(.c) c_int { return 0; }
fn musPoll() callconv(.c) void {}

export const DG_music_module: extern struct {
    sound_devices: [*]c_int,
    num_sound_devices: c_int,
    Init: *const fn () callconv(.c) c_int,
    Shutdown: *const fn () callconv(.c) void,
    SetMusicVolume: *const fn (c_int) callconv(.c) void,
    PauseMusic: *const fn () callconv(.c) void,
    ResumeMusic: *const fn () callconv(.c) void,
    RegisterSong: *const fn (?*anyopaque, c_int) callconv(.c) ?*anyopaque,
    UnRegisterSong: *const fn (?*anyopaque) callconv(.c) void,
    PlaySong: *const fn (?*anyopaque, c_int) callconv(.c) void,
    StopSong: *const fn () callconv(.c) void,
    MusicIsPlaying: *const fn () callconv(.c) c_int,
    PollMusic: *const fn () callconv(.c) void,
} = .{
    .sound_devices = &snd_devices,
    .num_sound_devices = 1,
    .Init = &musInit,
    .Shutdown = &musShutdown,
    .SetMusicVolume = &musSetVol,
    .PauseMusic = &musPause,
    .ResumeMusic = &musResume,
    .RegisterSong = &musRegister,
    .UnRegisterSong = &musUnRegister,
    .PlaySong = &musPlay,
    .StopSong = &musStop,
    .MusicIsPlaying = &musIsPlaying,
    .PollMusic = &musPoll,
};

// Stubs for features we don't implement
export var use_libsamplerate: c_int = 0;
export fn libsamplerate_scale(_: c_int, _: [*]u8, _: c_int, _: c_int) c_int {
    return 0;
}

var snd_devices = [_]c_int{SNDDEVICE_SB};

// C sound_module_t: 2 fields + 9 function pointers = 11 fields
// C music_module_t: 2 fields + 11 function pointers = 13 fields
// Comptime assertions prevent vtable mismatch bugs (like missing UnRegisterSong)
comptime {
    const SndMod = @TypeOf(DG_sound_module);
    const MusMod = @TypeOf(DG_music_module);
    // sound_module_t: ptr(8) + int(4) + pad(4) + 9 ptrs(72) = 84 bytes → aligned to 88
    if (@sizeOf(SndMod) != 88) @compileError("DG_sound_module size mismatch — check field count vs C sound_module_t");
    // music_module_t: ptr(8) + int(4) + pad(4) + 11 ptrs(88) = 100 bytes → aligned to 104
    if (@sizeOf(MusMod) != 104) @compileError("DG_music_module size mismatch — check field count vs C music_module_t");
}

export const DG_sound_module: extern struct {
    sound_devices: [*]c_int,
    num_sound_devices: c_int,
    Init: *const fn (c_int) callconv(.c) c_int,
    Shutdown: *const fn () callconv(.c) void,
    GetSfxLumpNum: *const fn (*SfxInfo) callconv(.c) c_int,
    Update: *const fn () callconv(.c) void,
    UpdateSoundParams: *const fn (c_int, c_int, c_int) callconv(.c) void,
    StartSound: *const fn (?*SfxInfo, c_int, c_int, c_int) callconv(.c) c_int,
    StopSound: *const fn (c_int) callconv(.c) void,
    SoundIsPlaying: *const fn (c_int) callconv(.c) c_int,
    CacheSounds: *const fn (?*SfxInfo, c_int) callconv(.c) void,
} = .{
    .sound_devices = &snd_devices,
    .num_sound_devices = 1,
    .Init = &sndInit,
    .Shutdown = &sndShutdown,
    .GetSfxLumpNum = &sndGetSfxLumpNum,
    .Update = &sndUpdate,
    .UpdateSoundParams = &sndUpdateParams,
    .StartSound = &sndStartSound,
    .StopSound = &sndStopSound,
    .SoundIsPlaying = &sndIsPlaying,
    .CacheSounds = &sndCacheSounds,
};
