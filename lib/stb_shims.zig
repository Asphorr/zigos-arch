// Shared libc shims that any app linking against vendor/photo_lib.c (the
// stb_image implementation TU) needs. Each app importing this file gets
// the C ABI surface — the `export fn` declarations land in the app's own
// linked ELF independently. Re-exporting libc.malloc/free/etc keeps
// stb_image's allocations going through our own per-process heap.
//
// Use:
//   _ = @import("stb_shims");  // pulls the exports into the link unit
//
// or add the module to .imports in build.zig:
//   .{ .name = "stb_shims", .module = stb_shims_mod }

const libc = @import("libc");

export fn malloc(size: usize) ?[*]u8 {
    return libc.malloc(size);
}

export fn realloc(old_ptr: ?[*]u8, new_size: usize) ?[*]u8 {
    return libc.realloc(old_ptr, new_size);
}

export fn free(ptr: ?[*]u8) void {
    libc.free(ptr);
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
