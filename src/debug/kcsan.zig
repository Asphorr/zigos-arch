//! KCSAN — concurrent-access detection.
//!
//! Two coexisting layers:
//!
//! 1) **Manual checkU64 / checkU8** (the original kcsan-lite). Inserted by
//!    hand at suspect points. Sample → pause → resample. See `checkU64`.
//!
//! 2) **Compiler-emitted instrumentation** via the LLVM `tsan` IR pass
//!    (`-Dkcsan`: build.zig, instrumentedObject). Every memory
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
//!    A watchpoint sits on kernel data only (`watchable`), and interrupts
//!    are off for its window: what changes the value is another CPU, not a
//!    handler on this one. A volatile access sets none up — the code says
//!    the memory changes under it — but is checked against the others'.
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
const build_options = @import("build_options");
const debug = @import("debug.zig");
const serial = @import("serial.zig");
const symbols = @import("symbols.zig");
const smp = @import("../cpu/smp.zig");
const memmap = @import("../mm/memmap.zig");
const vmalloc = @import("../mm/vmalloc.zig");

/// Both layers are a -Dkcsan build's. The manual checks pause too, and they
/// sit on the dispatch path.
pub const ENABLE: bool = build_options.kcsan_enabled;

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
/// == smp.MAX_CPUS; one watchpoint slot per cpu id.
const MAX_CPUS: usize = 32;

comptime {
    if (MAX_CPUS != smp.MAX_CPUS) @compileError("kcsan MAX_CPUS must equal smp.MAX_CPUS");
}

inline fn pauseSpin(n: u32) void {
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        asm volatile ("pause" ::: .{ .memory = true });
    }
}

/// rdtscp, not the LAPIC ID register (a VM exit). smp.zig is on the
/// kcsan_inject denylist, so this cannot re-enter the hooks.
inline fn currentCpuId() u8 {
    return smp.myCpuId();
}

inline fn irqSave() u64 {
    var flags: u64 = undefined;
    asm volatile ("pushfq; pop %[f]; cli"
        : [f] "=r" (flags),
    );
    return flags;
}

inline fn irqRestore(flags: u64) void {
    if (flags & 0x200 != 0) asm volatile ("sti");
}

// =============================================================================
// What may be watched
// =============================================================================

const Span = struct {
    lo: u64 = 0,
    hi: u64 = 0,

    inline fn has(span: Span, addr: u64) bool {
        return addr >= span.lo and addr < span.hi;
    }
};

/// The loader's usable regions as the physmap shows them. A map with more
/// runs than this leaves the rest unwatched.
const MAX_RAM_SPANS = 32;
var ram_spans: [MAX_RAM_SPANS]Span = undefined;
var ram_span_count: usize = 0;
/// The scanout and the back buffer: drawn into and read at once, by design.
var pixel_spans: [2]Span = .{ .{}, .{} };
var image_span: Span = .{};

fn physmapSpan(base: u64, end: u64) Span {
    return .{ .lo = memmap.PHYSMAP_BASE + base, .hi = memmap.PHYSMAP_BASE + end };
}

fn learnMemory() void {
    image_span = .{ .lo = memmap.KERNEL_VIRT_BASE, .hi = memmap.kernelEnd() };

    const fb = memmap.guestFb();
    const back = memmap.backBuffer();
    pixel_spans = .{ physmapSpan(fb.base, fb.end()), physmapSpan(back.base, back.end()) };

    ram_span_count = 0;
    for (memmap.bootMap()) |region| {
        if (region.kind != .usable or region.base >= memmap.PHYSMAP_SIZE) continue;
        const span = physmapSpan(region.base, @min(region.base +| region.length, memmap.PHYSMAP_SIZE));
        if (ram_span_count != 0 and ram_spans[ram_span_count - 1].hi == span.lo) {
            ram_spans[ram_span_count - 1].hi = span.hi;
            continue;
        }
        if (ram_span_count == MAX_RAM_SPANS) break;
        ram_spans[ram_span_count] = span;
        ram_span_count += 1;
    }
}

/// Whether a watchpoint may sit on `addr`: kernel data — the image, RAM
/// through the physmap, the vmalloc arena. Not a process's memory, which
/// its threads write whenever they like; not device memory, which the
/// resample would read twice more than the code does; not the pixels.
fn watchable(addr: u64) bool {
    if (addr < memmap.PHYSMAP_BASE) return false;
    // Nothing lies above the image window.
    if (addr >= image_span.lo) return addr < image_span.hi;
    if (addr -% vmalloc.VMALLOC_BASE < vmalloc.VMALLOC_SIZE) return true;
    for (pixel_spans) |span| {
        if (span.has(addr)) return false;
    }
    for (ram_spans[0..ram_span_count]) |span| {
        if (span.has(addr)) return true;
    }
    return false;
}

// =============================================================================
// Watchpoint table
// =============================================================================
//
// Encoded form (single u64 for atomic CAS):
//   bits  0..47 = the address's low 48 bits; a canonical address is their
//                 sign extension
//   bits 48..62 = size (15 bits, plenty for 16-byte max access)
//   bit       63 = is_write
//
// Empty slot = 0. Encoding 0 is impossible for a real address since size>0.

const ENC_ADDR_BITS: u6 = 48;
const ENC_SIZE_SHIFT: u6 = ENC_ADDR_BITS;
const ENC_WRITE_BIT: u64 = 1 << 63;
const ENC_ADDR_MASK: u64 = (1 << ENC_ADDR_BITS) - 1;
const ENC_SIZE_MASK: u64 = 0x7FFF << ENC_SIZE_SHIFT;

inline fn encodeWp(addr: u64, size: u8, is_write: bool) u64 {
    const a: u64 = addr & ENC_ADDR_MASK;
    const s: u64 = (@as(u64, size) << ENC_SIZE_SHIFT);
    const w: u64 = if (is_write) ENC_WRITE_BIT else 0;
    return a | s | w;
}

inline fn wpAddr(enc: u64) u64 {
    const dropped: u6 = 63 - ENC_ADDR_BITS + 1;
    return @bitCast(@as(i64, @bitCast(enc << dropped)) >> dropped);
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
    /// Where the watching access is, for the report of whoever trips it.
    /// Written before `encoded`, so a set slot has its own.
    site: u64 = 0,
    _pad: [48]u8 = [_]u8{0} ** 48,
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

/// A report is one line built on the stack and written in one call: whole
/// under serial's lock, and without std.fmt, whose 600+ bytes of kstack and
/// memcpy calls an access hook has no room for.
const Line = struct {
    buf: [320]u8 = undefined,
    len: usize = 0,

    fn str(line: *Line, text: []const u8) void {
        for (text) |c| {
            if (line.len == line.buf.len) return;
            line.buf[line.len] = c;
            line.len += 1;
        }
    }

    /// At least `min_digits` of them.
    fn hex(line: *Line, v: u64, min_digits: u6) void {
        const digits = "0123456789ABCDEF";
        line.str("0x");
        var i: u6 = 16;
        while (i > 0) {
            i -= 1;
            const nibble: usize = @intCast((v >> (i * 4)) & 0xF);
            if (nibble == 0 and i >= min_digits and (v >> (i * 4)) == 0) continue;
            line.str(digits[nibble..][0..1]);
        }
    }

    fn dec(line: *Line, v: u64) void {
        var digits: [20]u8 = undefined;
        var i: usize = digits.len;
        var rest = v;
        while (true) {
            i -= 1;
            digits[i] = @intCast('0' + rest % 10);
            rest /= 10;
            if (rest == 0) break;
        }
        line.str(digits[i..]);
    }

    /// "W sz=8 addr=0x… at function+0x…": the function once the symbol
    /// table is loaded, the bare address until then.
    fn access(line: *Line, is_write: bool, size: u8, addr: u64, site: u64) void {
        line.str(if (is_write) "W sz=" else "R sz=");
        line.dec(size);
        line.str(" addr=");
        line.hex(addr, 16);
        if (site == 0) return;
        line.str(" at ");
        if (symbols.resolveKernel(site)) |hit| {
            line.str(hit.name);
            line.str("+");
            line.hex(hit.offset, 1);
        } else {
            line.hex(site, 16);
        }
    }

    fn write(line: *Line) void {
        serial.write(line.buf[0..line.len]);
    }
};

/// A pair of places is reported once: a race on a hot path would bury the
/// log under its own repeats.
const SEEN_SLOTS = 256;
var seen: [SEEN_SLOTS]u64 = [_]u64{0} ** SEEN_SLOTS;
var seen_full_said: bool = false;

/// Whether this pair of sites is new, taking its slot if so. Lock-free: a
/// report comes from any context on any CPU.
fn firstSight(site_a: u64, site_b: u64) bool {
    const lo = @min(site_a, site_b);
    const hi = @max(site_a, site_b);
    // Odd, so never the empty slot's 0.
    const key: u64 = ((lo *% 0x9E3779B97F4A7C15) ^ hi) | 1;
    const start: usize = @intCast((key >> 32) % SEEN_SLOTS);
    for (0..SEEN_SLOTS) |probe| {
        const slot = &seen[(start + probe) % SEEN_SLOTS];
        const there = @cmpxchgStrong(u64, slot, 0, key, .acq_rel, .acquire) orelse return true;
        if (there == key) return false;
    }
    if (@cmpxchgStrong(bool, &seen_full_said, false, true, .acq_rel, .acquire) == null) {
        serial.write("[kcsan] " ++ std.fmt.comptimePrint("{d}", .{SEEN_SLOTS}) ++ " distinct races reported; no more will be\n");
    }
    return false;
}

fn afterReport(comptime what: []const u8) void {
    if (!PANIC_ON_HIT) return;
    // The panic path is instrumented code.
    shutdown();
    @panic("kcsan: " ++ what);
}

fn reportResample(addr: u64, size: u8, is_write: bool, site: u64, before: u64, after: u64) void {
    if (!firstSight(site, 0)) return;
    var line: Line = .{};
    line.str("\n!!! KCSAN race (resample) cpu=");
    line.dec(currentCpuId());
    line.str(" ");
    line.access(is_write, size, addr, site);
    line.str(" before=");
    line.hex(before, 1);
    line.str(" after=");
    line.hex(after, 1);
    line.str("\n");
    line.write();
    afterReport("concurrent access detected (resample)");
}

fn reportCrossCpu(my_addr: u64, my_size: u8, my_write: bool, my_site: u64, other_cpu: u8, other_enc: u64, other_site: u64) void {
    if (!firstSight(my_site, other_site)) return;
    var line: Line = .{};
    line.str("\n!!! KCSAN race (cross-cpu) cpu=");
    line.dec(currentCpuId());
    line.str(" ");
    line.access(my_write, my_size, my_addr, my_site);
    line.str("  VS cpu=");
    line.dec(other_cpu);
    line.str(" ");
    line.access(wpIsWrite(other_enc), wpSize(other_enc), wpAddr(other_enc), other_site);
    line.str("\n");
    line.write();
    afterReport("concurrent access detected (cross-cpu)");
}

fn reportManual(comptime name: []const u8, addr_val: u64, before: u64, after: u64) void {
    var line: Line = .{};
    line.str("[kcsan] manual RACE on '" ++ name ++ "' addr=");
    line.hex(addr_val, 16);
    line.str(" cpu=");
    line.dec(currentCpuId());
    line.str(" before=");
    line.hex(before, 1);
    line.str(" after=");
    line.hex(after, 1);
    line.str("\n");
    line.write();
    afterReport("concurrent-write race detected");
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
fn checkAgainstWatchpointsCold(addr: u64, size: u8, is_write: bool, site: u64) void {
    const my_cpu = currentCpuId();
    for (0..MAX_CPUS) |cpu_idx| {
        if (cpu_idx == my_cpu) continue;
        const slot = &watchpoints[cpu_idx];
        const enc = @atomicLoad(u64, &slot.encoded, .acquire);
        if (enc == 0) continue;
        if (!rangesOverlap(addr, size, wpAddr(enc), wpSize(enc))) continue;
        if (!is_write and !wpIsWrite(enc)) continue;
        const other_site = @atomicLoad(u64, &slot.site, .monotonic);
        if (@cmpxchgStrong(u64, &slot.encoded, enc, 0, .acq_rel, .acquire) == null) {
            _ = @atomicRmw(u32, &armed_count, .Sub, 1, .acq_rel);
            reportCrossCpu(addr, size, is_write, site, @intCast(cpu_idx), enc, other_site);
        }
    }
}

/// Set our slot, read `before`, pause, read `after`. If our slot is still
/// occupied (no one cleared it) and the value changed, report.
fn setupWatchpointAndResampleCold(addr: u64, size: u8, is_write: bool, site: u64) void {
    // Off for the window: a handler on this CPU would change the value
    // itself, or sample and take the slot from under this one.
    const flags = irqSave();
    const slot = &watchpoints[currentCpuId()];
    const enc = encodeWp(addr, size, is_write);
    @atomicStore(u64, &slot.site, site, .monotonic);
    @atomicStore(u64, &slot.encoded, enc, .release);
    _ = @atomicRmw(u32, &armed_count, .Add, 1, .acq_rel);

    // The hook runs before its access: a write's old value is still there,
    // and another CPU's write over it shows the same way a read's does.
    var before: u64 = 0;
    var after: u64 = 0;
    if (size <= 8) {
        before = readUpTo8(addr, size);
        pauseSpin(PAUSE_LOOPS);
        after = readUpTo8(addr, size);
    } else {
        pauseSpin(PAUSE_LOOPS);
    }

    // A slot someone else cleared is a race they caught: they reported it
    // and took armed_count down.
    const ours = @cmpxchgStrong(u64, &slot.encoded, enc, 0, .acq_rel, .acquire) == null;
    if (ours) _ = @atomicRmw(u32, &armed_count, .Sub, 1, .acq_rel);
    irqRestore(flags);
    if (ours and before != after) reportResample(addr, size, is_write, site, before, after);
}

inline fn readUpTo8(addr: u64, size: u8) u64 {
    const p: *align(1) const volatile u64 = @ptrFromInt(addr & ~@as(u64, 7));
    const off: u6 = @intCast((addr & 7) * 8);
    const mask: u64 = if (size >= 8) ~@as(u64, 0) else (@as(u64, 1) << @intCast(size * 8)) - 1;
    return (p.* >> off) & mask;
}

/// The hot path called from every __tsan_readN / __tsan_writeN. Goal:
/// stay under ~5 cycles in the no-watchpoints-armed case (which is >99% of
/// calls). All cold work is out-of-line. `site` is the access's own code.
inline fn checkAccess(addr: u64, size: u8, is_write: bool, comptime may_watch: bool, site: u64) void {
    if (!RUNTIME_ACTIVE) return;
    // Global short-circuit: if NO cpu has a watchpoint armed, the cross-CPU
    // walk is guaranteed to find nothing. Skip it. Atomic-relaxed load is a
    // single mov on x86 — no fences. The bump/decrement in the cold paths
    // uses .acq_rel so updates are eventually visible. A watchpoint is on
    // kernel data, so an address below the kernel's half overlaps none.
    if (@atomicLoad(u32, &armed_count, .monotonic) != 0 and addr >= memmap.PHYSMAP_BASE) {
        @call(.never_inline, checkAgainstWatchpointsCold, .{ addr, size, is_write, site });
    }
    // Sampling: atomic counter % SAMPLE_DENOM. Locked xadd is ~25 cycles
    // but only the rare branch reaches the cold setup path with the pause.
    if (may_watch and shouldSample() and watchable(addr)) {
        @call(.never_inline, setupWatchpointAndResampleCold, .{ addr, size, is_write, site });
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
                checkAccess(addr, sz, false, true, @returnAddress());
            }
            fn write(addr: usize) callconv(.c) void {
                checkAccess(addr, sz, true, true, @returnAddress());
            }
            // Emitted under --tsan-distinguish-volatile=true.
            fn volatileRead(addr: usize) callconv(.c) void {
                checkAccess(addr, sz, false, false, @returnAddress());
            }
            fn volatileWrite(addr: usize) callconv(.c) void {
                checkAccess(addr, sz, true, false, @returnAddress());
            }
        };
        @export(&Hooks.read, .{ .name = std.fmt.comptimePrint("__tsan_read{d}", .{sz}) });
        @export(&Hooks.write, .{ .name = std.fmt.comptimePrint("__tsan_write{d}", .{sz}) });
        @export(&Hooks.read, .{ .name = std.fmt.comptimePrint("__tsan_unaligned_read{d}", .{sz}) });
        @export(&Hooks.write, .{ .name = std.fmt.comptimePrint("__tsan_unaligned_write{d}", .{sz}) });
        @export(&Hooks.volatileRead, .{ .name = std.fmt.comptimePrint("__tsan_volatile_read{d}", .{sz}) });
        @export(&Hooks.volatileWrite, .{ .name = std.fmt.comptimePrint("__tsan_volatile_write{d}", .{sz}) });
        @export(&Hooks.volatileRead, .{ .name = std.fmt.comptimePrint("__tsan_unaligned_volatile_read{d}", .{sz}) });
        @export(&Hooks.volatileWrite, .{ .name = std.fmt.comptimePrint("__tsan_unaligned_volatile_write{d}", .{sz}) });
    }
}

/// Memory-intrinsic instrumentation (memcpy/memmove/memset). Walk in
/// chunks of 16 bytes; cheap because we only sample 1/SAMPLE_DENOM anyway.
fn checkRange(addr: usize, size: usize, is_write: bool, site: u64) void {
    var off: usize = 0;
    while (off < size) : (off += 16) {
        const chunk: u8 = if (size - off >= 16) 16 else @intCast(size - off);
        checkAccess(addr + off, chunk, is_write, true, site);
    }
}

export fn __tsan_read_range(addr: usize, size: usize) callconv(.c) void {
    if (!RUNTIME_ACTIVE) return;
    checkRange(addr, size, false, @returnAddress());
}

export fn __tsan_write_range(addr: usize, size: usize) callconv(.c) void {
    if (!RUNTIME_ACTIVE) return;
    checkRange(addr, size, true, @returnAddress());
}

// memcpy/memmove/memset — the tsan pass replaces `llvm.memcpy.*` /
// `llvm.memset.*` intrinsics with calls to these wrappers, which:
//   1. Range-check src + dst,
//   2. Perform the actual copy/set.
// Must return the destination pointer (matches libc ABI).
//
// memcpy/memset/memmove use `rep movsb` / `rep stosb` — modern x86 (ERMSB
// since Ivy Bridge) makes these as fast as SSE-unrolled loops. A naive
// byte-for-loop here was making KCSAN unusably slow because EVERY framebuffer
// blit, EVERY large struct copy went through it.

export fn __tsan_memcpy(dst: usize, src: usize, n: usize) callconv(.c) usize {
    if (RUNTIME_ACTIVE) {
        checkRange(dst, n, true, @returnAddress());
        checkRange(src, n, false, @returnAddress());
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
        checkRange(dst, n, true, @returnAddress());
        checkRange(src, n, false, @returnAddress());
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
        checkRange(dst, n, true, @returnAddress());
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

/// After memmap.init: what may be watched is read off the loader's map.
pub fn init() void {
    if (!ENABLE) return;
    learnMemory();
    for (&watchpoints) |*slot| slot.* = .{};
    sample_tick = 0;
    armed_count = 0;
    RUNTIME_ACTIVE = true;
    debug.klog("[kcsan] runtime active — sample 1/{d}, pause {d}; watching the image, vmalloc and {d} run(s) of RAM\n", .{
        SAMPLE_DENOM, PAUSE_LOOPS, ram_span_count,
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
    if (before != after) reportManual(name, @intFromPtr(addr), before, after);
}

pub inline fn checkU8(comptime name: []const u8, addr: *const u8) void {
    if (!ENABLE) return;
    const before = @atomicLoad(u8, addr, .acquire);
    pauseSpin(PAUSE_LOOPS);
    const after = @atomicLoad(u8, addr, .acquire);
    if (before != after) reportManual(name, @intFromPtr(addr), before, after);
}
