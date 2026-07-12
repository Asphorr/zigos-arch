// Kernel-side compiler-rt replacements.
//
// `zig build-exe` automatically links compiler-rt, supplying symbols like
// `memcpy` / `memset` / `memmove` that LLVM emits for `@memcpy`, struct
// copies, and large @memset calls. The KASAN IR-pass build pipeline takes
// the kernel's bitcode through `opt → llc → ld` directly, bypassing Zig's
// compiler-rt linking. Without these exports, the final `ld` step fails
// with "undefined reference to memset" everywhere `@memset` got lowered.
//
// The fill/copy cores are `rep stosb` / `rep movsb` INLINE ASM, not Zig
// loops — and that is load-bearing, not a style choice: LLVM's loop-idiom
// pass raises plain fill/copy loops into calls to memset/memcpy, and inside
// these very functions such a call is SELF-RECURSION. Inline asm is
// invisible to that pass, permanently. ERMSB (Ivy Bridge+) makes rep-string
// as fast as SSE-unrolled loops anyway (same idiom as kcsan.zig's
// __tsan_mem*, minus its std/cld — see memmove).
//
// History: under 0.15.2's LLVM the old byte-loop bodies happened to compile
// to real loops, so the hazard stayed latent. Zig 0.16.0's newer LLVM
// recognized memset's fill loop and compiled the body to literally
// `jmp memset` (itself) — the kernel spun forever at the FIRST padded-hex
// serial print (Io.Writer.splatByteAll's 12-byte '0' fill was the first
// runtime memset call), which presented for days as a "0.16 codegen
// mystery" early-boot hang. Root-caused 2026-07-05 via TCG + gdbstub: RIP
// parked on the self-jmp with rsi='0', rcx=12. memcpy/memmove had compiled
// to real loops that day — same hazard class, one LLVM heuristic away —
// hence asm for all three.
//
// These functions must also never be built with KASAN instrumentation:
// this file lives on the KASAN denylist (`tools/kasan_inject.py`).
// Instrumenting them would lead to either circular checks (memcpy used by
// KASAN itself) or massive bloat.

const std = @import("std");

export fn memcpy(dest: ?[*]u8, src: ?[*]const u8, n: usize) callconv(.c) ?[*]u8 {
    const d = dest orelse return null;
    const s = src orelse return dest;
    asm volatile ("rep movsb"
        :
        : [_] "{rdi}" (d),
          [_] "{rsi}" (s),
          [_] "{rcx}" (n),
        : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true });
    return dest;
}

export fn memmove(dest: ?[*]u8, src: ?[*]const u8, n: usize) callconv(.c) ?[*]u8 {
    const d = dest orelse return null;
    const s = src orelse return dest;
    if (@intFromPtr(d) < @intFromPtr(s) or n == 0) {
        asm volatile ("rep movsb"
            :
            : [_] "{rdi}" (d),
              [_] "{rsi}" (s),
              [_] "{rcx}" (n),
            : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true });
    } else if (@intFromPtr(d) > @intFromPtr(s)) {
        // Backward (overlap-safe) copy: indexed byte loop, deliberately NOT
        // `std; rep movsb; cld`. rep is interruptible, and an IRQ landing in
        // the DF=1 window would run the handler's compiler-generated string
        // ops backwards — LLVM assumes DF=0 per SysV and our ISR stubs don't
        // cld. (kcsan.zig's __tsan_memmove does use std/cld; that flavor is
        // dev-build-only — don't copy the idiom here.) Copies n bytes at
        // indices n-1..0; n > 0 is guaranteed by the branch above.
        asm volatile (
            \\1:
            \\ decq %%rcx
            \\ movb (%%rsi,%%rcx), %%al
            \\ movb %%al, (%%rdi,%%rcx)
            \\ jnz 1b
            :
            : [_] "{rdi}" (d),
              [_] "{rsi}" (s),
              [_] "{rcx}" (n),
            : .{ .rax = true, .rcx = true, .memory = true });
    }
    return dest;
}

export fn memset(dest: ?[*]u8, c_val: c_int, n: usize) callconv(.c) ?[*]u8 {
    const d = dest orelse return null;
    const byte: u8 = @truncate(@as(c_uint, @bitCast(c_val)));
    asm volatile ("rep stosb"
        :
        : [_] "{rdi}" (d),
          [_] "{al}" (byte),
          [_] "{rcx}" (n),
        : .{ .rdi = true, .rcx = true, .memory = true });
    return dest;
}

// memcmp stays a Zig loop: loop-idiom recognition raises only fill/copy
// shapes, not early-exit difference loops, so the self-call hazard above
// doesn't apply here.
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
