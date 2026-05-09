//! KCSAN — concurrent-access detection.
//!
//! Two coexisting layers:
//!
//! 1) **Manual checkU64 / checkU8** (the original kcsan-lite). Inserted by
//!    hand at suspect points. Sample → pause → resample. See `checkU64`.
//!
//! 2) **Compiler-emitted instrumentation** via the LLVM `tsan` IR pass
//!    (driven by `tools/kcsan_pipeline.sh` + `-Dkcsan=true`). Every memory
//!    access in instrumented (allowlisted) functions becomes a call to
//!    `__tsan_read{1,2,4,8,16}` or `__tsan_write{1,2,4,8,16}`. Our runtime
//!    implements those with the watchpoint protocol:
//!
//!      a. With probability 1/SAMPLE_DENOM, set up a watchpoint:
//!         per-CPU slot = (addr, size, is_write). Read `before`. Pause
//!         ~µs. Read `after`. If before != after → report (some non-
//!         instrumented writer hit our window).
//!
//!      b. Always: walk the per-CPU watchpoint table. If our access
//!         overlaps any OTHER cpu's active watchpoint, atomically clear
//!         that slot and report (instrumented-vs-instrumented race).
//!
//! Cost of full instrumentation: ~5–10× slowdown when active. For bug
//! hunts only — never ship with this on by default.
//!
//! Knobs:
//!   - ENABLE / RUNTIME_ACTIVE: master switches.
//!   - SAMPLE_DENOM: 1 in N accesses sets up a watchpoint. Higher = less
//!     overhead, lower hit rate. Linux KCSAN default = 2000.
//!   - PAUSE_LOOPS: window width.
//!   - PANIC_ON_HIT: panic at first detection (good for repro), or just
//!     log and continue (good for soak).

const std = @import("std");
const debug = @import("debug.zig");
const serial = @import("serial.zig");

pub const ENABLE: bool = true;

/// Set true once the watchpoint table + per-CPU storage are wired and
/// safe to call. Until then the compiler-emitted __tsan_* hooks no-op.
/// kcsan.init() flips this on.
var RUNTIME_ACTIVE: bool = false;

const PAUSE_LOOPS: u32 = 100;
const PANIC_ON_HIT: bool = false;
/// 1 in N accesses sets up a sample watchpoint. Bumped from 2000 → 50_000
/// because the kernel's hot paths (schedule, IRQ entry, memcpy-heavy code)
/// generate millions of accesses per second; 1/2000 was firing the 100-cycle
/// pause window often enough to make the system unusably slow. Cross-CPU
/// detection still runs on EVERY access — the rare path is just the resample.
const SAMPLE_DENOM: u32 = 50_000;
/// Match smp.MAX_CPUS so we have a slot for every possible LAPIC id we might
/// see. Empty slots are cheap (single atomic load == 0), so oversizing is OK.
const MAX_CPUS: usize = 32;

inline fn pauseSpin(n: u32) void {
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        asm volatile ("pause" ::: .{ .memory = true });
    }
}

inline fn currentCpuId() u8 {
    const apic = @import("../time/apic.zig");
    if (!apic.apic_active) return 0;
    return @truncate(apic.getLapicId());
}

// =============================================================================
// Watchpoint table
// =============================================================================
//
// Encoded form (single u64 for atomic CAS):
//   bits  0..47 = addr (canonical lower-half VAs only — kernel data lives below
//                 0x0000_8000_0000_0000)
//   bits 48..62 = size (15 bits, plenty for 16-byte max access)
//   bit       63 = is_write
//
// Empty slot = 0. Encoding 0 is impossible for a real address since size>0.

const ENC_SIZE_SHIFT: u6 = 48;
const ENC_WRITE_BIT: u64 = 1 << 63;
const ENC_ADDR_MASK: u64 = (1 << 48) - 1;
const ENC_SIZE_MASK: u64 = 0x7FFF << ENC_SIZE_SHIFT;

inline fn encodeWp(addr: u64, size: u8, is_write: bool) u64 {
    const a: u64 = addr & ENC_ADDR_MASK;
    const s: u64 = (@as(u64, size) << ENC_SIZE_SHIFT);
    const w: u64 = if (is_write) ENC_WRITE_BIT else 0;
    return a | s | w;
}

inline fn wpAddr(enc: u64) u64 {
    return enc & ENC_ADDR_MASK;
}
inline fn wpSize(enc: u64) u8 {
    return @intCast((enc & ENC_SIZE_MASK) >> ENC_SIZE_SHIFT);
}
inline fn wpIsWrite(enc: u64) bool {
    return (enc & ENC_WRITE_BIT) != 0;
}

/// Per-CPU single-slot watchpoint. Cache-padded to avoid false sharing.
const WatchSlot = extern struct {
    encoded: u64 align(64) = 0,
    _pad: [56]u8 = [_]u8{0} ** 56,
};

var watchpoints: [MAX_CPUS]WatchSlot = [_]WatchSlot{.{}} ** MAX_CPUS;

/// Global "any watchpoint armed" counter. The hot path (every memory access
/// in instrumented code) reads this first; if 0 (the vast majority of the
/// time), it skips the entire MAX_CPUS-iteration walk over `watchpoints`.
/// Bumped+decremented by setupWatchpointAndResample around the resample
/// window. With SAMPLE_DENOM=50_000 and ~32 cpus, this is 0 for >99% of
/// accesses, dropping per-access cost from ~200 cycles to ~5.
var armed_count: u32 = 0;

/// Single global counter — incremented atomically on every access; we sample
/// when (counter % SAMPLE_DENOM) == 0. Single-cacheline contention across
/// cpus, but it's an `lock xadd` (~25 cycles) only on hot-path. Avoids the
/// per-cpu PRNG state lookup that would require a fast currentCpuId().
var sample_tick: u32 = 0;

inline fn shouldSample() bool {
    const t = @atomicRmw(u32, &sample_tick, .Add, 1, .monotonic);
    return (t % SAMPLE_DENOM) == 0;
}

// =============================================================================
// Race report
// =============================================================================

// Low-stack hex emitters. Formatted serial.print pulls in std.fmt + bufPrint,
// which (a) burns 600+ bytes of kstack per call, and (b) goes through
// llvm.memcpy → __tsan_memcpy → checkAccess → could re-enter the runtime.
// These write directly via serial.write([]const u8), no allocator, no fmt.

inline fn emitHex(v: u64) void {
    const hexchars = "0123456789ABCDEF";
    var buf: [18]u8 = undefined;
    buf[0] = '0';
    buf[1] = 'x';
    var i: usize = 16;
    var x = v;
    while (i > 0) {
        i -= 1;
        buf[2 + i] = hexchars[x & 0xF];
        x >>= 4;
    }
    serial.write(&buf);
}

inline fn emitDec(v: u64) void {
    if (v == 0) {
        serial.write("0");
        return;
    }
    var buf: [20]u8 = undefined;
    var i: usize = 20;
    var x = v;
    while (x > 0) {
        i -= 1;
        buf[i] = @intCast(@as(u64, '0') + (x % 10));
        x /= 10;
    }
    serial.write(buf[i..]);
}

inline fn emitWR(is_write: bool) void {
    serial.write(if (is_write) "W" else "R");
}

fn reportResample(addr: u64, size: u8, is_write: bool, before: u64, after: u64) void {
    // Disable runtime first — in case PANIC_ON_HIT triggers further code on
    // an instrumented path, we don't want recursion. Also covers the case
    // where serial.write itself contains an instrumented memcpy.
    RUNTIME_ACTIVE = false;
    serial.write("\n!!! KCSAN race (resample) cpu=");
    emitDec(currentCpuId());
    serial.write(" ");
    emitWR(is_write);
    serial.write(" sz=");
    emitDec(size);
    serial.write(" addr=");
    emitHex(addr);
    serial.write(" before=");
    emitHex(before);
    serial.write(" after=");
    emitHex(after);
    serial.write("\n");
    if (PANIC_ON_HIT) @panic("kcsan: concurrent access detected (resample)");
    RUNTIME_ACTIVE = true;
}

fn reportCrossCpu(my_addr: u64, my_size: u8, my_write: bool, other_cpu: u8, other_enc: u64) void {
    RUNTIME_ACTIVE = false;
    serial.write("\n!!! KCSAN race (cross-cpu) cpu=");
    emitDec(currentCpuId());
    serial.write(" ");
    emitWR(my_write);
    serial.write(" sz=");
    emitDec(my_size);
    serial.write(" addr=");
    emitHex(my_addr);
    serial.write("  VS cpu=");
    emitDec(other_cpu);
    serial.write(" ");
    emitWR(wpIsWrite(other_enc));
    serial.write(" sz=");
    emitDec(wpSize(other_enc));
    serial.write(" addr=");
    emitHex(wpAddr(other_enc));
    serial.write("\n");
    if (PANIC_ON_HIT) @panic("kcsan: concurrent access detected (cross-cpu)");
    RUNTIME_ACTIVE = true;
}

fn report(comptime name: []const u8, addr_val: u64, before: u64, after: u64) void {
    RUNTIME_ACTIVE = false;
    serial.write("[kcsan] manual RACE on '");
    serial.write(name);
    serial.write("' addr=");
    emitHex(addr_val);
    serial.write(" cpu=");
    emitDec(currentCpuId());
    serial.write(" before=");
    emitHex(before);
    serial.write(" after=");
    emitHex(after);
    serial.write("\n");
    if (PANIC_ON_HIT) @panic("kcsan: concurrent-write race detected");
    RUNTIME_ACTIVE = true;
}

// =============================================================================
// Watchpoint protocol — overlap check + sample-and-resample
// =============================================================================

inline fn rangesOverlap(a_addr: u64, a_size: u8, b_addr: u64, b_size: u8) bool {
    return (a_addr < b_addr + b_size) and (b_addr < a_addr + a_size);
}

/// Walk the per-CPU watchpoint table. If our access overlaps another CPU's
/// active watchpoint, atomically clear it and report a cross-CPU race.
/// Cold path — guarded by armed_count > 0 in checkAccess. Out-of-line so
/// the hot path is just a global load + branch, not a 32-iteration loop.
fn checkAgainstWatchpointsCold(addr: u64, size: u8, is_write: bool) void {
    const my_cpu = currentCpuId();
    for (0..MAX_CPUS) |cpu_idx| {
        if (cpu_idx == my_cpu) continue;
        const slot = &watchpoints[cpu_idx].encoded;
        const enc = @atomicLoad(u64, slot, .acquire);
        if (enc == 0) continue;
        const other_addr = wpAddr(enc);
        const other_size = wpSize(enc);
        const other_write = wpIsWrite(enc);
        if (!rangesOverlap(addr, size, other_addr, other_size)) continue;
        if (!is_write and !other_write) continue;
        if (@cmpxchgStrong(u64, slot, enc, 0, .acq_rel, .acquire) == null) {
            _ = @atomicRmw(u32, &armed_count, .Sub, 1, .acq_rel);
            reportCrossCpu(addr, size, is_write, @intCast(cpu_idx), enc);
        }
    }
}

/// Set our slot, read `before`, pause, read `after`. If our slot is still
/// occupied (no one cleared it) and the value changed, report.
fn setupWatchpointAndResampleCold(addr: u64, size: u8, is_write: bool) void {
    const cpu = currentCpuId();
    const slot = &watchpoints[cpu].encoded;
    const enc = encodeWp(addr, size, is_write);
    @atomicStore(u64, slot, enc, .release);
    _ = @atomicRmw(u32, &armed_count, .Add, 1, .acq_rel);

    var before: u64 = 0;
    var after: u64 = 0;
    var did_resample = false;
    if (!is_write and size <= 8) {
        before = readUpTo8(addr, size);
        pauseSpin(PAUSE_LOOPS);
        after = readUpTo8(addr, size);
        did_resample = true;
    } else {
        pauseSpin(PAUSE_LOOPS);
    }

    const cleared = @cmpxchgStrong(u64, slot, enc, 0, .acq_rel, .acquire);
    if (cleared != null) return; // someone caught us, they reported (and decremented armed_count)
    _ = @atomicRmw(u32, &armed_count, .Sub, 1, .acq_rel);
    if (did_resample and before != after) {
        reportResample(addr, size, is_write, before, after);
    }
}

inline fn readUpTo8(addr: u64, size: u8) u64 {
    const p: *align(1) const volatile u64 = @ptrFromInt(addr & ~@as(u64, 7));
    const off: u6 = @intCast((addr & 7) * 8);
    const mask: u64 = if (size >= 8) ~@as(u64, 0) else (@as(u64, 1) << @intCast(size * 8)) - 1;
    return (p.* >> off) & mask;
}

/// Range filter — only watch addresses inside the kernel data ranges we
/// expect to actually share. Skip MMIO, user VAs, anything obviously out
/// of bounds. Cuts noise and avoids touching unmapped pages.
inline fn addrInteresting(addr: u64) bool {
    // Kernel image + heap + stacks live in the low identity-mapped region.
    // 0x100000 (1 MB) up to 0x1000_0000 (256 MB) covers them; same range
    // KASAN's REGION_LO/HI uses.
    return addr >= 0x100000 and addr < 0x1000_0000;
}

/// The hot path called from every __tsan_readN / __tsan_writeN. Goal:
/// stay under ~5 cycles in the no-watchpoints-armed case (which is >99% of
/// calls). All cold work is out-of-line.
inline fn checkAccess(addr: u64, size: u8, is_write: bool) void {
    if (!RUNTIME_ACTIVE) return;
    // Global short-circuit: if NO cpu has a watchpoint armed, the cross-CPU
    // walk is guaranteed to find nothing. Skip it. Atomic-relaxed load is a
    // single mov on x86 — no fences. The bump/decrement in the cold paths
    // uses .acq_rel so updates are eventually visible.
    if (@atomicLoad(u32, &armed_count, .monotonic) != 0) {
        if (addrInteresting(addr)) {
            @call(.never_inline, checkAgainstWatchpointsCold, .{ addr, size, is_write });
        }
    }
    // Sampling: atomic counter % SAMPLE_DENOM. Locked xadd is ~25 cycles
    // but only the rare branch reaches the cold setup path with the pause.
    if (shouldSample() and addrInteresting(addr)) {
        @call(.never_inline, setupWatchpointAndResampleCold, .{ addr, size, is_write });
    }
}

// =============================================================================
// Compiler-emitted entry points (LLVM tsan pass)
// =============================================================================
//
// The pass emits CALLS to these symbols at every memory access in tagged
// (`sanitize_thread`) functions. Signatures match Linux KCSAN/TSAN ABI.

comptime {
    const sizes = [_]u8{ 1, 2, 4, 8, 16 };
    for (sizes) |sz| {
        const Hooks = struct {
            fn read(addr: usize) callconv(.c) void {
                checkAccess(addr, sz, false);
            }
            fn write(addr: usize) callconv(.c) void {
                checkAccess(addr, sz, true);
            }
        };
        @export(&Hooks.read, .{ .name = std.fmt.comptimePrint("__tsan_read{d}", .{sz}) });
        @export(&Hooks.write, .{ .name = std.fmt.comptimePrint("__tsan_write{d}", .{sz}) });
        @export(&Hooks.read, .{ .name = std.fmt.comptimePrint("__tsan_unaligned_read{d}", .{sz}) });
        @export(&Hooks.write, .{ .name = std.fmt.comptimePrint("__tsan_unaligned_write{d}", .{sz}) });
        // Volatile variants — emitted when --tsan-distinguish-volatile=true.
        // Same semantics for us; volatile doesn't change race detection.
        @export(&Hooks.read, .{ .name = std.fmt.comptimePrint("__tsan_volatile_read{d}", .{sz}) });
        @export(&Hooks.write, .{ .name = std.fmt.comptimePrint("__tsan_volatile_write{d}", .{sz}) });
        @export(&Hooks.read, .{ .name = std.fmt.comptimePrint("__tsan_unaligned_volatile_read{d}", .{sz}) });
        @export(&Hooks.write, .{ .name = std.fmt.comptimePrint("__tsan_unaligned_volatile_write{d}", .{sz}) });
    }
}

/// Memory-intrinsic instrumentation (memcpy/memmove/memset). Walk in
/// chunks of 16 bytes; cheap because we only sample 1/SAMPLE_DENOM anyway.
export fn __tsan_read_range(addr: usize, size: usize) callconv(.c) void {
    if (!RUNTIME_ACTIVE) return;
    var off: usize = 0;
    while (off < size) : (off += 16) {
        const chunk: u8 = if (size - off >= 16) 16 else @intCast(size - off);
        checkAccess(addr + off, chunk, false);
    }
}

export fn __tsan_write_range(addr: usize, size: usize) callconv(.c) void {
    if (!RUNTIME_ACTIVE) return;
    var off: usize = 0;
    while (off < size) : (off += 16) {
        const chunk: u8 = if (size - off >= 16) 16 else @intCast(size - off);
        checkAccess(addr + off, chunk, true);
    }
}

// memcpy/memmove/memset — the tsan pass replaces `llvm.memcpy.*` /
// `llvm.memset.*` intrinsics with calls to these wrappers, which:
//   1. Range-check src + dst,
//   2. Perform the actual copy/set.
// Must return the destination pointer (matches libc ABI).
//
// Implementation: byte-loop. Slow, but: (a) instrumented builds are slow
// anyway, (b) calling the in-tree memcpy/memset would itself be on a
// denylisted path (kernel_builtins.zig) so no recursion through tsan, but
// they're not exposed as Zig functions here. Inline byte loop is simpler
// and stays self-contained.

// memcpy/memset/memmove use `rep movsb` / `rep stosb` — modern x86 (ERMSB
// since Ivy Bridge) makes these as fast as SSE-unrolled loops. A naive
// byte-for-loop here was making KCSAN unusably slow because EVERY framebuffer
// blit, EVERY large struct copy went through it.

export fn __tsan_memcpy(dst: usize, src: usize, n: usize) callconv(.c) usize {
    if (RUNTIME_ACTIVE) {
        __tsan_write_range(dst, n);
        __tsan_read_range(src, n);
    }
    asm volatile ("rep movsb"
        :
        : [_] "{rdi}" (dst),
          [_] "{rsi}" (src),
          [_] "{rcx}" (n),
        : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
    );
    return dst;
}

export fn __tsan_memmove(dst: usize, src: usize, n: usize) callconv(.c) usize {
    if (RUNTIME_ACTIVE) {
        __tsan_write_range(dst, n);
        __tsan_read_range(src, n);
    }
    if (dst < src or n == 0) {
        asm volatile ("rep movsb"
            :
            : [_] "{rdi}" (dst),
              [_] "{rsi}" (src),
              [_] "{rcx}" (n),
            : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
        );
    } else if (dst > src) {
        // Backward copy via std (rep movsb DF=1).
        asm volatile (
            \\ std
            \\ rep movsb
            \\ cld
            :
            : [_] "{rdi}" (dst + n - 1),
              [_] "{rsi}" (src + n - 1),
              [_] "{rcx}" (n),
            : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
        );
    }
    return dst;
}

export fn __tsan_memset(dst: usize, c: c_int, n: usize) callconv(.c) usize {
    if (RUNTIME_ACTIVE) {
        __tsan_write_range(dst, n);
    }
    const byte: u8 = @intCast(@as(c_uint, @bitCast(c)) & 0xFF);
    asm volatile ("rep stosb"
        :
        : [_] "{rdi}" (dst),
          [_] "{al}" (byte),
          [_] "{rcx}" (n),
        : .{ .rdi = true, .rcx = true, .memory = true }
    );
    return dst;
}

/// Module init — called once per compilation unit. Linux makes this a
/// no-op since they have a single kernel module; us too.
export fn __tsan_init() callconv(.c) void {}

/// func_entry / func_exit are emitted only when --tsan-instrument-func-
/// entry-exit=true. We pass false to opt-20 so these should never be
/// called, but provide stubs in case the pass enables them.
export fn __tsan_func_entry(_: usize) callconv(.c) void {}
export fn __tsan_func_exit() callconv(.c) void {}

// Atomic-op hooks (__tsan_atomic*_load / __tsan_atomic*_store) are NOT
// emitted because we pass --tsan-instrument-atomics=false to opt-20. If
// that flag changes, real implementations would be needed here that don't
// recurse through @atomicLoad/@atomicStore.

// =============================================================================
// Init / public API
// =============================================================================

pub fn init() void {
    if (!ENABLE) return;
    for (0..MAX_CPUS) |i| {
        watchpoints[i].encoded = 0;
    }
    sample_tick = 0;
    armed_count = 0;
    RUNTIME_ACTIVE = true;
    debug.klog("[kcsan] runtime active — {d} cpus, sample 1/{d}, pause {d}\n", .{
        MAX_CPUS, SAMPLE_DENOM, PAUSE_LOOPS,
    });
}

/// Stop the runtime. Useful in panic paths to prevent recursion through
/// instrumented code while we're dumping state.
pub fn shutdown() void {
    RUNTIME_ACTIVE = false;
    for (0..MAX_CPUS) |i| {
        @atomicStore(u64, &watchpoints[i].encoded, 0, .release);
    }
}

// =============================================================================
// Manual instrumentation API (kept for selective hot-path use)
// =============================================================================

/// Watch a u64 location for concurrent writes during a short window.
pub inline fn checkU64(comptime name: []const u8, addr: *align(1) const u64) void {
    if (!ENABLE) return;
    const v: *align(1) const volatile u64 = @ptrCast(addr);
    const before = v.*;
    pauseSpin(PAUSE_LOOPS);
    const after = v.*;
    if (before != after) report(name, @intFromPtr(addr), before, after);
}

pub inline fn checkU8(comptime name: []const u8, addr: *const u8) void {
    if (!ENABLE) return;
    const before = @atomicLoad(u8, addr, .acquire);
    pauseSpin(PAUSE_LOOPS);
    const after = @atomicLoad(u8, addr, .acquire);
    if (before != after) report(name, @intFromPtr(addr), before, after);
}
