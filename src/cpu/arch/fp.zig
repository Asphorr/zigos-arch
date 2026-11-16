// FPU/SSE context save/restore plumbing.
//
// On every user↔kernel transition we fxsave (or fxrstor) a 512-byte block on
// the kernel stack so user processes don't see each other's XMM state — and
// don't see kernel-side SSE spills leaking into their registers.
//
// Layout details:
//   * 512 bytes, 16-byte aligned (fxsave/fxrstor requirement).
//   * Format defined by Intel SDM Vol 1 §10.5.1 (FXSAVE save area).
//
// This module owns the canonical "init" FP state — captured once at boot via
// `fninit; fxsave64` — that retToUserStub (sched_asm.zig) fxrstors directly
// from this .data symbol on first dispatch. It is read-only after boot and
// shared by every new process; nothing copies it onto the kstack.
//
// Why .data, not kstack? Earlier we copied init_template into a 512B block at
// stack_top - 672 on every new process. That put MXCSR at stack_top - 648 —
// the same address where the syscall-entry / IRQ-stub `call` instruction
// later pushes its return address. If anything re-stamped the init bytes on
// a live kstack (slot reuse, mid-flight re-init, etc.), the saved ret addr
// turned into 0x0000FFFF00001F80 (MXCSR + MXCSR_MASK) and the next `ret`
// faulted in kernel mode. Eliminating the kstack copy removes the alias.

const std = @import("std");
const serial = @import("../../debug/serial.zig");
const protect = @import("protect.zig");
const MAX_PROCS = @import("../../config.zig").MAX_PROCS;

/// Canonical "init" FXSAVE state, captured at boot from a clean FPU. Loaded
/// directly via `fxrstorq init_template(%rip)` in retToUserStub for the first
/// user-mode dispatch (gives a defined FPU/MXCSR for new tasks). Exported so
/// the linker symbol is visible to inline asm.
///
/// 16-byte aligned because fxsave/fxrstor #GP on misaligned destinations.
pub export var init_template: [512]u8 align(16) = [_]u8{0} ** 512;

/// Capture the FPU/SSE "init" state once at boot. Run after enableSSE() so
/// CR0.MP/CR4.OSFXSR are set, otherwise fxsave traps #UD or #NM.
///
/// `init_template` is a single global shared by all CPUs — there are no
/// per-CPU templates because `fninit` is deterministic across cores of the
/// same microarch, so any CPU would capture the same bytes. Call from the
/// BSP only; APs read the same buffer.
pub fn captureInitTemplate() void {
    asm volatile (
        \\ fninit
        \\ fxsaveq %[buf]
        : [buf] "=m" (init_template),
    );

    // Sanity-check MXCSR (FXSAVE offset 24, 4 bytes). Expected value is the
    // x86 reset default 0x1F80: all six FP exceptions masked, round-to-
    // nearest, no flush-to-zero. Any other value here means either (a) the
    // CPU/firmware came up with a non-standard MXCSR, or (b) some earlier
    // boot code touched MXCSR before we got to capture the "clean" state.
    // Both turn into baffling FP-rounding/exception bugs in user mode that
    // are nearly impossible to reproduce without this anchor — fail loud
    // here instead.
    const mxcsr: u32 = @as(*const u32, @ptrCast(@alignCast(&init_template[24]))).*;
    if (mxcsr != 0x1F80) {
        @panic("fp.captureInitTemplate: unexpected MXCSR (FPU init state polluted before capture)");
    }

    // Every task's AVX area starts as the init state: XRSTOR of it loads
    // MXCSR too, so its legacy region must hold the clean one.
    @memcpy(init_area.bytes[0..512], &init_template);
    for (&areas) |*a| a.* = init_area;
}

// --- AVX state ---------------------------------------------------------------
//
// With CR4.OSXSAVE and XCR0 = x87|SSE|AVX, user code may use the YMM
// registers, as on Linux. Their low halves (the XMM registers) are in the
// FXSAVE image every kernel entry takes; their upper halves are saved per
// task at each context switch (switchExtended). That is enough because the
// kernel is built without AVX: its SSE instructions, legacy-encoded, leave
// the upper halves as they are, so from one switch to the next the
// registers hold the upper halves of the task current on the CPU.

/// XCR0: x87, SSE and AVX state.
const XCR0_AVX: u32 = 0b111;
/// XSAVE/XRSTOR's requested-feature mask: the AVX component alone. With
/// SSE or AVX requested they move MXCSR as well.
const RFBM_AVX: u32 = 1 << 2;
/// The AVX component in a standard-format XSAVE area: after the 512-byte
/// legacy region and the 64-byte header.
const AVX_OFFSET: u32 = 576;
const AVX_SIZE: u32 = 256;

const Area = extern struct { bytes: [AVX_OFFSET + AVX_SIZE]u8 align(64) };

comptime {
    // XSAVE wants 64-byte alignment: the array keeps it for each element.
    if (@sizeOf(Area) % 64 != 0) @compileError("XSAVE areas must stay 64-byte multiples");
}

/// A task's upper YMM halves (and MXCSR) while it is off the CPU, by
/// slot. Only the switching CPU touches a slot's area: the outgoing task's
/// at switch-out, the incoming one's at switch-in.
var areas: [MAX_PROCS]Area = [_]Area{.{ .bytes = [_]u8{0} ** @sizeOf(Area) }} ** MAX_PROCS;
/// The AVX init state: zero upper halves, header zero, MXCSR clean.
var init_area: Area = .{ .bytes = [_]u8{0} ** @sizeOf(Area) };

/// Set once by the BSP, before any task or AP exists.
pub var avx: bool = false;
var probed: bool = false;

/// Whether the CPU can give user tasks AVX state as laid out here.
fn probeAvx() bool {
    const r1 = protect.cpuidLeaf(1, 0);
    const has_xsave = r1.ecx & (1 << 26) != 0;
    const has_avx = r1.ecx & (1 << 28) != 0;
    if (!has_xsave or !has_avx) return false;
    const d0 = protect.cpuidLeaf(0xD, 0);
    if (d0.eax & XCR0_AVX != XCR0_AVX) return false;
    const d2 = protect.cpuidLeaf(0xD, 2);
    return d2.eax == AVX_SIZE and d2.ebx == AVX_OFFSET;
}

/// Per CPU, at bring-up and after S3: CR4.OSXSAVE and XCR0 for AVX state.
/// The BSP's first call decides for all.
pub fn enableExtended() void {
    if (!probed) {
        probed = true;
        avx = probeAvx();
        serial.print("[fp] AVX state for user tasks: {s}\n", .{if (avx) "on (XSAVE, XCR0=x87|SSE|AVX)" else "off"});
    }
    if (!avx) return;
    var cr4 = asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> u64),
    );
    cr4 |= 1 << 18; // OSXSAVE
    asm volatile ("mov %[val], %%cr4"
        :
        : [val] "r" (cr4),
    );
    // xsetbv, as bytes: the kernel's target has no XSAVE feature to
    // assemble it with.
    asm volatile (".byte 0x0f, 0x01, 0xd1"
        :
        : [xcr] "{ecx}" (@as(u32, 0)),
          [lo] "{eax}" (XCR0_AVX),
          [hi] "{edx}" (@as(u32, 0)),
    );
}

/// xsave64 (%rdi) of the AVX component.
inline fn xsave(a: *Area) void {
    asm volatile (".byte 0x48, 0x0f, 0xae, 0x27"
        :
        : [area] "{rdi}" (a),
          [lo] "{eax}" (RFBM_AVX),
          [hi] "{edx}" (@as(u32, 0)),
        : .{ .memory = true });
}

/// xrstor64 (%rdi) of the AVX component.
inline fn xrstor(a: *const Area) void {
    asm volatile (".byte 0x48, 0x0f, 0xae, 0x2f"
        :
        : [area] "{rdi}" (a),
          [lo] "{eax}" (RFBM_AVX),
          [hi] "{edx}" (@as(u32, 0)),
        : .{ .memory = true });
}

/// Context switch, interrupts off: the outgoing task's AVX state off the
/// CPU (none when `prev` isn't a slot: a dying task), the incoming one's on.
pub fn switchExtended(prev: usize, next: usize) void {
    if (!avx) return;
    if (prev < MAX_PROCS) xsave(&areas[prev]);
    xrstor(&areas[next]);
}

/// A new task in slot `pid` starts with the AVX init state.
pub fn resetExtended(pid: usize) void {
    areas[pid] = init_area;
}

/// A forked or cloned `child` starts with the caller's AVX state, as it
/// starts with its XMM registers.
pub fn inheritExtended(child: usize) void {
    if (avx) xsave(&areas[child]);
}

/// The caller's AVX registers to the init state (execve: a new image
/// starts with them clear).
pub fn resetLiveExtended() void {
    if (avx) xrstor(&init_area);
}

/// The upper YMM halves as a signal frame carries them.
pub const UPPER_BYTES: usize = AVX_SIZE;

const XSTATE_BV_AT: usize = 512;

/// The calling task's upper YMM halves into `out`; false, `out` untouched,
/// when they are in the init state (all zero).
pub fn saveUpper(out: *[UPPER_BYTES]u8) bool {
    if (!avx) return false;
    var a: Area = undefined;
    @memset(a.bytes[XSTATE_BV_AT..AVX_OFFSET], 0);
    xsave(&a);
    // XSAVE skips the component's bytes when it is in the init state.
    if (std.mem.readInt(u64, a.bytes[XSTATE_BV_AT..][0..8], .little) & RFBM_AVX == 0) return false;
    @memcpy(out, a.bytes[AVX_OFFSET..][0..AVX_SIZE]);
    return true;
}

/// The calling task's upper YMM halves from `ymm`, or the init state.
/// A switch in between is harmless: it puts back what it took off.
pub fn loadUpper(ymm: ?*const [UPPER_BYTES]u8) void {
    if (!avx) return;
    var a: Area = undefined;
    // XRSTOR checks the whole header; XSAVE fills in MXCSR, which XRSTOR
    // of the AVX component loads as well.
    @memset(a.bytes[XSTATE_BV_AT..AVX_OFFSET], 0);
    xsave(&a);
    var bv: u64 = 0;
    if (ymm) |y| {
        @memcpy(a.bytes[AVX_OFFSET..][0..AVX_SIZE], y);
        bv = RFBM_AVX;
    }
    std.mem.writeInt(u64, a.bytes[XSTATE_BV_AT..][0..8], bv, .little);
    xrstor(&a);
}
