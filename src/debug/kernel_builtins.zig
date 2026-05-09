// Kernel-side compiler-rt replacements.
//
// `zig build-exe` automatically links compiler-rt, supplying symbols like
// `memcpy` / `memset` / `memmove` that LLVM emits for `@memcpy`, struct
// copies, and large @memset calls. The KASAN IR-pass build pipeline takes
// the kernel's bitcode through `opt → llc → ld` directly, bypassing Zig's
// compiler-rt linking. Without these exports, the final `ld` step fails
// with "undefined reference to memset" everywhere `@memset` got lowered.
//
// These are byte-by-byte (or word-stride) implementations. Performance is
// not the goal — correctness is. The kernel has its own SIMD-friendly
// fillRect/blitToScreen for hot paths; nothing here is on a critical loop.
//
// IMPORTANT: this file lives on the KASAN denylist
// (`tools/kasan_inject.py`). Instrumenting these would lead to either
// circular checks (memcpy used by KASAN itself) or massive bloat.

const std = @import("std");

export fn memcpy(dest: ?[*]u8, src: ?[*]const u8, n: usize) callconv(.c) ?[*]u8 {
    const d = dest orelse return null;
    const s = src orelse return dest;
    var i: usize = 0;
    while (i < n) : (i += 1) d[i] = s[i];
    return dest;
}

export fn memmove(dest: ?[*]u8, src: ?[*]const u8, n: usize) callconv(.c) ?[*]u8 {
    const d = dest orelse return null;
    const s = src orelse return dest;
    if (@intFromPtr(d) < @intFromPtr(s)) {
        var i: usize = 0;
        while (i < n) : (i += 1) d[i] = s[i];
    } else {
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            d[i] = s[i];
        }
    }
    return dest;
}

export fn memset(dest: ?[*]u8, c_val: c_int, n: usize) callconv(.c) ?[*]u8 {
    const d = dest orelse return null;
    const byte: u8 = @truncate(@as(c_uint, @bitCast(c_val)));
    var i: usize = 0;
    while (i < n) : (i += 1) d[i] = byte;
    return dest;
}

export fn memcmp(a: ?[*]const u8, b: ?[*]const u8, n: usize) callconv(.c) c_int {
    const aa = a orelse return 0;
    const bb = b orelse return 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (aa[i] != bb[i]) {
            return @as(c_int, aa[i]) - @as(c_int, bb[i]);
        }
    }
    return 0;
}

// Zig also calls `__zig_probe_stack` (stack probe for large frames). The
// real implementation paints touch pages to extend the kstack guard area.
// In our kernel kstacks are pre-allocated to a fixed size — there's nothing
// to probe — so a zero-overhead no-op suffices.
export fn __zig_probe_stack() callconv(.naked) void {
    asm volatile ("retq");
}
