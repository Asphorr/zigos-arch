// C-ABI shims for vendor/photo_lib.c / stb_truetype's text_lib.c /
// stb_vorbis's vorbis_lib.c — the static-library root module they all
// share. Used to `@import("libc")` and call `libc.malloc`/`free`/
// `realloc` directly; that produced a separate libc compilation
// (and a separate copy of every heap-state global) inside each
// static .a, which silently fork-ed the heap accounting from the
// exe's own libc instance — see [[libc-static-lib-dup-globals]].
//
// Fix: route `malloc`/`free`/`realloc` through C-ABI extern symbols
// that resolve at exe-link time to the single libc instance the exe
// compiles. Each static .a now has UNDEFINED references to
// `__libc_malloc` / `__libc_free` / `__libc_realloc`; whichever exe
// links these libs provides them from its own libc.zig (which
// declares them as `export fn`).
//
// memset / memcpy / memmove / memcmp / abs / strlen don't touch the
// heap, so they stay self-contained byte loops in the static .a.

extern fn __libc_malloc(size: usize) ?[*]u8;
extern fn __libc_realloc(old_ptr: ?[*]u8, new_size: usize) ?[*]u8;
extern fn __libc_free(ptr: ?[*]u8) void;

export fn malloc(size: usize) ?[*]u8 {
    return __libc_malloc(size);
}

export fn realloc(old_ptr: ?[*]u8, new_size: usize) ?[*]u8 {
    return __libc_realloc(old_ptr, new_size);
}

export fn free(ptr: ?[*]u8) void {
    __libc_free(ptr);
}

export fn memset(dest: ?[*]u8, c_val: c_int, n: usize) ?[*]u8 {
    if (dest) |d| {
        const byte: u8 = @truncate(@as(c_uint, @bitCast(c_val)));
        for (0..n) |i| d[i] = byte;
    }
    return dest;
}

export fn memcpy(dest: ?[*]u8, src: ?[*]const u8, n: usize) ?[*]u8 {
    if (dest == null or src == null) return dest;
    const d = dest.?;
    const s = src.?;
    for (0..n) |i| d[i] = s[i];
    return dest;
}

export fn memmove(dest: ?[*]u8, src: ?[*]const u8, n: usize) ?[*]u8 {
    if (dest == null or src == null or n == 0) return dest;
    const d = dest.?;
    const s = src.?;
    if (@intFromPtr(d) < @intFromPtr(s)) {
        for (0..n) |i| d[i] = s[i];
    } else {
        var i = n;
        while (i > 0) {
            i -= 1;
            d[i] = s[i];
        }
    }
    return dest;
}

export fn memcmp(a: ?[*]const u8, b: ?[*]const u8, n: usize) c_int {
    if (a == null or b == null) return 0;
    const x = a.?;
    const y = b.?;
    for (0..n) |i| {
        if (x[i] != y[i]) return @as(c_int, x[i]) - @as(c_int, y[i]);
    }
    return 0;
}

export fn abs(x: c_int) c_int {
    return if (x < 0) -x else x;
}

export fn strlen(s: ?[*:0]const u8) usize {
    if (s) |str| {
        var n: usize = 0;
        while (str[n] != 0) : (n += 1) {}
        return n;
    }
    return 0;
}
