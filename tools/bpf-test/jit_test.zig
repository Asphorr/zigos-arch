// Differential test for src/bpf/jit.zig — the x86-64 JIT.
//
// The property: for EVERY program the verifier accepts and the JIT supports,
// the JIT-compiled native code leaves the SAME value in r0 as the interpreter.
// We run on the x86-64 build host, so the JIT's output is executed for real
// (mmap'd executable), then diffed against vm.zig over many random ctx values.
//
// Soundness of the comparison: value operands are restricted to r0..r9 — never
// the r10 frame pointer — so the absolute stack address (which legitimately
// differs between the interpreter's internal stack and the JIT's external one)
// never flows into r0. r10 appears only as a load/store base, where only the
// (zeroed or just-stored) data is observed, identical on both sides.
//
// Deterministic (fixed seed) so a failure reproduces.

const std = @import("std");
const i = @import("src/bpf/insn.zig");
const vm = @import("src/bpf/vm.zig");
const v = @import("src/bpf/verifier.zig");
const jit = @import("src/bpf/jit.zig");

const CTX_LEN = 16;
const CFG = v.Config{ .ctx_len = CTX_LEN, .ctx_writable = false, .helpers = &.{} };
const IHELPERS = [_]?vm.HelperFn{};
const FUEL: u64 = 1 << 20; // huge: a verified DAG always finishes well under this

// Helper table for CALL tests, callconv(.c) — the pinned helper ABI both the
// interpreter and the JIT call through. hWeighted's distinct per-argument
// coefficients make a mis-ordered argument shuffle observable; hConst99 ignores
// its args; hInc has a result that chains into later instructions.
fn hWeighted(a: u64, b: u64, c: u64, d: u64, e: u64) callconv(.c) u64 {
    return a +% (b *% 2) +% (c *% 3) +% (d *% 4) +% (e *% 5);
}
fn hConst99(_: u64, _: u64, _: u64, _: u64, _: u64) callconv(.c) u64 {
    return 99;
}
fn hInc(a: u64, _: u64, _: u64, _: u64, _: u64) callconv(.c) u64 {
    return a +% 1;
}
const THELPERS = [_]?vm.HelperFn{ null, hWeighted, hConst99, hInc };

// === executable code buffer (host) ===

var code_page: []align(std.heap.page_size_min) u8 = undefined;

fn mapCode() !void {
    code_page = try std.posix.mmap(
        null,
        4096,
        std.posix.PROT.READ | std.posix.PROT.WRITE | std.posix.PROT.EXEC,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );
}

/// Compile + execute under `helpers`. Returns null if the JIT can't lower it.
fn runJitH(prog: []const i.Insn, ctx_ptr: u64, helpers: []const ?vm.HelperFn) !?u64 {
    const n = jit.compile(prog, code_page, helpers) catch |err| switch (err) {
        error.Unsupported => return null,
        else => return err,
    };
    std.debug.assert(n <= code_page.len);
    var stack: [i.STACK_SIZE]u8 align(8) = [_]u8{0} ** i.STACK_SIZE;
    const f: jit.CompiledFn = @ptrFromInt(@intFromPtr(code_page.ptr));
    return f(ctx_ptr, @intFromPtr(&stack));
}
fn runJit(prog: []const i.Insn, ctx_ptr: u64) !?u64 {
    return runJitH(prog, ctx_ptr, &IHELPERS);
}

fn runInterpH(prog: []const i.Insn, ctx: *[CTX_LEN]u8, helpers: []const ?vm.HelperFn) !u64 {
    const env = vm.Env{
        .regions = &[_]vm.Region{.{ .base = @intFromPtr(ctx), .len = CTX_LEN, .writable = false }},
        .helpers = helpers,
    };
    var machine = vm.Vm{};
    const res = try machine.runEnv(prog, @intFromPtr(ctx), FUEL, env);
    return res.r0;
}
fn runInterp(prog: []const i.Insn, ctx: *[CTX_LEN]u8) !u64 {
    return runInterpH(prog, ctx, &IHELPERS);
}

// === hand-written sanity programs ===

fn expectProgH(prog: []const i.Insn, want: u64, helpers: []const ?vm.HelperFn) !void {
    var ctx: [CTX_LEN]u8 align(8) = [_]u8{0} ** CTX_LEN;
    const interp = try runInterpH(prog, &ctx, helpers);
    const jitted = (try runJitH(prog, @intFromPtr(&ctx), helpers)) orelse return error.UnexpectedUnsupported;
    try std.testing.expectEqual(want, interp);
    try std.testing.expectEqual(want, jitted);
}
fn expectProg(prog: []const i.Insn, want: u64) !void {
    return expectProgH(prog, want, &IHELPERS);
}

test "jit: mov imm + exit" {
    try mapCode();
    try expectProg(&.{ i.mov64Imm(0, 42), i.exit() }, 42);
}

test "jit: 64-bit add reg" {
    try expectProg(&.{ i.mov64Imm(0, 5), i.mov64Imm(2, 3), i.alu64Reg(.add, 0, 2), i.exit() }, 8);
}

test "jit: ld_imm64" {
    const p = i.ldImm64(0, 0x1122_3344_5566_7788);
    try expectProg(&.{ p[0], p[1], i.exit() }, 0x1122_3344_5566_7788);
}

test "jit: 32-bit mov zero-extends" {
    // mov32 r0, -1  => r0 = 0x0000_0000_FFFF_FFFF
    try expectProg(&.{ i.alu32Imm(.mov, 0, -1), i.exit() }, 0xFFFF_FFFF);
}

test "jit: sub imm" {
    try expectProg(&.{ i.mov64Imm(0, 100), i.alu64Imm(.sub, 0, 58), i.exit() }, 42);
}

test "jit: shifts" {
    try expectProg(&.{ i.mov64Imm(0, 1), i.alu64Imm(.lsh, 0, 10), i.exit() }, 1024);
    try expectProg(&.{ i.mov64Imm(0, 1), i.mov64Imm(3, 5), i.alu64Reg(.lsh, 0, 3), i.exit() }, 32);
}

test "jit: mul" {
    try expectProg(&.{ i.mov64Imm(0, 6), i.mov64Imm(2, 7), i.alu64Reg(.mul, 0, 2), i.exit() }, 42);
    try expectProg(&.{ i.mov64Imm(0, 6), i.alu64Imm(.mul, 0, 7), i.exit() }, 42);
}

test "jit: branch not-taken falls through" {
    // r0=1; r2=2; if r0==r2 goto +1; r0=99; exit
    try expectProg(&.{
        i.mov64Imm(0, 1),
        i.mov64Imm(2, 2),
        i.jmpReg(.jeq, 0, 2, 1),
        i.mov64Imm(0, 99),
        i.exit(),
    }, 99);
}

test "jit: branch taken skips" {
    // r0=7; r2=7; if r0==r2 goto +1; r0=99; exit  => 7
    try expectProg(&.{
        i.mov64Imm(0, 7),
        i.mov64Imm(2, 7),
        i.jmpReg(.jeq, 0, 2, 1),
        i.mov64Imm(0, 99),
        i.exit(),
    }, 7);
}

test "jit: stack store then load" {
    // r2=12345; *(u64*)(r10-8)=r2; r0=*(u64*)(r10-8); exit
    try expectProg(&.{
        i.mov64Imm(2, 12345),
        i.stx(.dw, 10, 2, -8),
        i.ldx(.dw, 0, 10, -8),
        i.exit(),
    }, 12345);
}

test "jit: store imm byte then load zero-extended" {
    // *(u8*)(r10-1) = 0xAB ; r0 = *(u8*)(r10-1) ; exit  => 0xAB
    try expectProg(&.{
        i.st(.b, 10, -1, 0xAB),
        i.ldx(.b, 0, 10, -1),
        i.exit(),
    }, 0xAB);
}

test "jit: ja forward" {
    // r0=1; ja +1; r0=2(skipped? no — ja skips the next); exit
    // layout: [0]mov r0,1 [1]ja +1 [2]mov r0,2 [3]exit  => ja jumps over [2] => r0=1
    try expectProg(&.{
        i.mov64Imm(0, 1),
        i.ja(1),
        i.mov64Imm(0, 2),
        i.exit(),
    }, 1);
}

// === helper CALL ===
// NOTE: r1..r5 are caller-saved — undefined after a CALL (the verifier marks
// them uninit; the JIT really clobbers them; the interpreter happens to leave
// them intact). These programs therefore never READ r1..r5 after a call, which
// is exactly the contract a verified program obeys, so interp and JIT agree.

test "jit: call helper passes args in order, returns r0" {
    try mapCode();
    // r1..r5 = 1,2,3,4,5; hWeighted = 1 + 2*2 + 3*3 + 4*4 + 5*5 = 55.
    // A swapped argument shuffle would give a different weighted sum.
    try expectProgH(&.{
        i.mov64Imm(1, 1),
        i.mov64Imm(2, 2),
        i.mov64Imm(3, 3),
        i.mov64Imm(4, 4),
        i.mov64Imm(5, 5),
        i.call(1),
        i.exit(),
    }, 55, &THELPERS);
}

test "jit: call helper ignoring its args" {
    try expectProgH(&.{
        i.mov64Imm(1, 123),
        i.call(2), // hConst99
        i.exit(),
    }, 99, &THELPERS);
}

test "jit: call result chains into later instructions" {
    // r1=10; r0 = hInc(10) = 11; r0 += 1 => 12  (reads r0, never the clobbered r1)
    try expectProgH(&.{
        i.mov64Imm(1, 10),
        i.call(3),
        i.alu64Imm(.add, 0, 1),
        i.exit(),
    }, 12, &THELPERS);
}

test "jit: two calls — arg re-set between them" {
    // r1=10 -> hInc=11; r1=20 -> hInc=21; exit 21
    try expectProgH(&.{
        i.mov64Imm(1, 10),
        i.call(3),
        i.mov64Imm(1, 20),
        i.call(3),
        i.exit(),
    }, 21, &THELPERS);
}

test "jit: call preserves callee-saved eBPF regs r6..r9" {
    // Set r6=1000 BEFORE a call; the helper (native C) must preserve x86 rbx/r13/
    // r14/r15 where r6..r9 live, so r6 survives. r0 = r6 + hInc(0)=1 => 1001.
    try expectProgH(&.{
        i.mov64Imm(6, 1000),
        i.mov64Imm(1, 0),
        i.call(3), // r0 = 1
        i.alu64Reg(.add, 0, 6), // r0 += r6 (1000) => 1001
        i.exit(),
    }, 1001, &THELPERS);
}

test "jit: unregistered helper id is declined (falls back to interpreter)" {
    try mapCode();
    // Id 0 is null in THELPERS: the JIT must NOT emit it (returns Unsupported so
    // the caller interprets, where it would surface as BadHelperId).
    var ctx: [CTX_LEN]u8 align(8) = [_]u8{0} ** CTX_LEN;
    const prog = [_]i.Insn{ i.mov64Imm(1, 0), i.call(0), i.exit() };
    const r = try runJitH(&prog, @intFromPtr(&ctx), &THELPERS);
    try std.testing.expect(r == null);
}

// === new opcodes (increment 1b): div/mod, endian/bswap, MOVSX, MEMSX, JMP32 ===

test "jit: div/mod unsigned (reg, imm, 32-bit)" {
    try mapCode();
    try expectProg(&.{ i.mov64Imm(0, 100), i.mov64Imm(2, 7), i.alu64Reg(.div, 0, 2), i.exit() }, 14);
    try expectProg(&.{ i.mov64Imm(0, 100), i.mov64Imm(2, 7), i.alu64Reg(.mod, 0, 2), i.exit() }, 2);
    try expectProg(&.{ i.mov64Imm(0, 100), i.alu64Imm(.div, 0, 7), i.exit() }, 14);
    try expectProg(&.{ i.mov64Imm(0, 100), i.alu64Imm(.mod, 0, 7), i.exit() }, 2);
    try expectProg(&.{ i.alu32Imm(.mov, 0, 100), i.alu32Imm(.div, 0, 7), i.exit() }, 14);
    // 32-bit mod by the (always-zero) r2 => spec leaves the low 32 of dst: 100.
    try expectProg(&.{ i.alu32Imm(.mov, 0, 100), i.alu32Reg(.mod, 0, 2), i.exit() }, 100);
}

test "jit: div/mod by zero follows the spec, no #DE" {
    try mapCode();
    try expectProg(&.{ i.mov64Imm(0, 5), i.mov64Imm(2, 0), i.alu64Reg(.div, 0, 2), i.exit() }, 0); // div/0 => 0
    try expectProg(&.{ i.mov64Imm(0, 5), i.mov64Imm(2, 0), i.alu64Reg(.mod, 0, 2), i.exit() }, 5); // mod/0 => dst
    try expectProg(&.{ i.mov64Imm(0, 5), i.alu64Imm(.div, 0, 0), i.exit() }, 0);
    try expectProg(&.{ i.mov64Imm(0, 5), i.alu64Imm(.mod, 0, 0), i.exit() }, 5);
}

test "jit: signed div/mod" {
    try mapCode();
    // -100 sdiv 7 = -14 ; -100 smod 7 = -2  (truncating, remainder takes dividend sign)
    try expectProg(&.{ i.mov64Imm(0, -100), i.mov64Imm(2, 7), i.alu64SignedReg(.div, 0, 2), i.exit() }, @bitCast(@as(i64, -14)));
    try expectProg(&.{ i.mov64Imm(0, -100), i.mov64Imm(2, 7), i.alu64SignedReg(.mod, 0, 2), i.exit() }, @bitCast(@as(i64, -2)));
}

test "jit: signed div/mod INT_MIN by -1 wraps (no #DE)" {
    try mapCode();
    const a = i.ldImm64(0, 0x8000_0000_0000_0000);
    try expectProg(&.{ a[0], a[1], i.mov64Imm(2, -1), i.alu64SignedReg(.div, 0, 2), i.exit() }, 0x8000_0000_0000_0000);
    const b = i.ldImm64(0, 0x8000_0000_0000_0000);
    try expectProg(&.{ b[0], b[1], i.mov64Imm(2, -1), i.alu64SignedReg(.mod, 0, 2), i.exit() }, 0);
}

test "jit: endian to_be / to_le" {
    try mapCode();
    try expectProg(&.{ i.mov64Imm(0, 0x1122), i.endian(true, 0, 16), i.exit() }, 0x2211);
    try expectProg(&.{ i.mov64Imm(0, 0x11223344), i.endian(true, 0, 32), i.exit() }, 0x44332211);
    const a = i.ldImm64(0, 0x1122_3344_5566_7788);
    try expectProg(&.{ a[0], a[1], i.endian(true, 0, 64), i.exit() }, 0x8877_6655_4433_2211);
    // to_le on a little-endian host just truncates to the width.
    const b = i.ldImm64(0, 0x1122_3344_5566_7788);
    try expectProg(&.{ b[0], b[1], i.endian(false, 0, 16), i.exit() }, 0x7788);
    const c = i.ldImm64(0, 0x1122_3344_5566_7788);
    try expectProg(&.{ c[0], c[1], i.endian(false, 0, 32), i.exit() }, 0x5566_7788);
}

test "jit: bswap" {
    try mapCode();
    try expectProg(&.{ i.mov64Imm(0, 0x1122), i.bswap(0, 16), i.exit() }, 0x2211);
    try expectProg(&.{ i.mov64Imm(0, 0x11223344), i.bswap(0, 32), i.exit() }, 0x44332211);
    const a = i.ldImm64(0, 0x1122_3344_5566_7788);
    try expectProg(&.{ a[0], a[1], i.bswap(0, 64), i.exit() }, 0x8877_6655_4433_2211);
}

test "jit: MOVSX register 8/16/32" {
    try mapCode();
    try expectProg(&.{ i.mov64Imm(2, 0x80), i.mov64Sx(0, 2, 8), i.exit() }, 0xFFFF_FFFF_FFFF_FF80);
    try expectProg(&.{ i.mov64Imm(2, 0x8000), i.mov64Sx(0, 2, 16), i.exit() }, 0xFFFF_FFFF_FFFF_8000);
    try expectProg(&.{ i.alu32Imm(.mov, 2, @bitCast(@as(u32, 0x8000_0000))), i.mov64Sx(0, 2, 32), i.exit() }, 0xFFFF_FFFF_8000_0000);
}

test "jit: MOVSX 32-bit class zero-extends the sign-extension" {
    try mapCode();
    // mov32sx r0, r2 width 8 : sign-extend r2[7:0] to 32, then zero-extend to 64.
    var x = i.alu32Reg(.mov, 0, 2);
    x.offset = 8;
    try expectProg(&.{ i.mov64Imm(2, 0x80), x, i.exit() }, 0xFFFF_FF80);
}

test "jit: MEMSX sign-extending loads" {
    try mapCode();
    try expectProg(&.{ i.st(.b, 10, -1, 0x80), i.ldxSx(.b, 0, 10, -1), i.exit() }, 0xFFFF_FFFF_FFFF_FF80);
    try expectProg(&.{ i.st(.h, 10, -2, 0x8000), i.ldxSx(.h, 0, 10, -2), i.exit() }, 0xFFFF_FFFF_FFFF_8000);
    try expectProg(&.{ i.st(.w, 10, -4, @bitCast(@as(u32, 0x8000_0000))), i.ldxSx(.w, 0, 10, -4), i.exit() }, 0xFFFF_FFFF_8000_0000);
}

test "jit: JMP32 compares the low 32 bits only" {
    try mapCode();
    // r0 = 0x1_0000_0001 (low32 == 1), r2 = 1. A 32-bit jeq is TAKEN (a 64-bit
    // one would not be) and skips the r0=99 — so r0 keeps its value.
    const a = i.ldImm64(0, 0x1_0000_0001);
    try expectProg(&.{
        a[0], a[1],
        i.mov64Imm(2, 1),
        i.jmp32Reg(.jeq, 0, 2, 1),
        i.mov64Imm(0, 99),
        i.exit(),
    }, 0x1_0000_0001);
}

test "jit: JMP32 long JA uses the imm displacement" {
    try mapCode();
    // pc1 is a JMP32 long-JA with imm=1 => target = 1+1+1 = 3, skipping [2].
    try expectProg(&.{
        i.mov64Imm(0, 1),
        i.jmp32Imm(.ja, 0, 1, 0),
        i.mov64Imm(0, 2),
        i.exit(),
    }, 1);
}

// === atomics (STX | MODE_ATOMIC) ===
// expectProg runs both interp and JIT and compares to `want`; each program
// surfaces the atomic's memory and/or register effect into r0 so any divergence
// shows up. All accesses are 8-aligned stack slots (in-bounds by construction).

test "jit: atomic add writes memory (dw and w)" {
    try mapCode();
    try expectProg(&.{ // dw: 100 + 5 = 105
        i.st(.dw, 10, -8, 100),
        i.mov64Imm(2, 5),
        i.atomic(.dw, i.ATOMIC_ADD, 10, 2, -8),
        i.ldx(.dw, 0, 10, -8),
        i.exit(),
    }, 105);
    try expectProg(&.{ // w: 0 + 7 = 7
        i.st(.w, 10, -8, 0),
        i.mov64Imm(2, 7),
        i.atomic(.w, i.ATOMIC_ADD, 10, 2, -8),
        i.ldx(.w, 0, 10, -8),
        i.exit(),
    }, 7);
}

test "jit: atomic or/and/xor (non-fetch)" {
    try mapCode();
    try expectProg(&.{ i.st(.dw, 10, -8, 0xF0), i.mov64Imm(2, 0x0F), i.atomic(.dw, i.ATOMIC_OR, 10, 2, -8), i.ldx(.dw, 0, 10, -8), i.exit() }, 0xFF);
    try expectProg(&.{ i.st(.dw, 10, -8, 0xFF), i.mov64Imm(2, 0x0F), i.atomic(.dw, i.ATOMIC_AND, 10, 2, -8), i.ldx(.dw, 0, 10, -8), i.exit() }, 0x0F);
    try expectProg(&.{ i.st(.dw, 10, -8, 0xFF), i.mov64Imm(2, 0x0F), i.atomic(.dw, i.ATOMIC_XOR, 10, 2, -8), i.ldx(.dw, 0, 10, -8), i.exit() }, 0xF0);
}

test "jit: atomic fetch-add returns old value, updates memory" {
    try mapCode();
    try expectProg(&.{ // r2 receives the old value (100)
        i.st(.dw, 10, -8, 100),
        i.mov64Imm(2, 5),
        i.atomic(.dw, i.ATOMIC_ADD | i.ATOMIC_FETCH, 10, 2, -8),
        i.mov64Reg(0, 2),
        i.exit(),
    }, 100);
    try expectProg(&.{ // memory became 105
        i.st(.dw, 10, -8, 100),
        i.mov64Imm(2, 5),
        i.atomic(.dw, i.ATOMIC_ADD | i.ATOMIC_FETCH, 10, 2, -8),
        i.ldx(.dw, 0, 10, -8),
        i.exit(),
    }, 105);
}

test "jit: atomic xchg swaps register and memory" {
    try mapCode();
    // r2=0xBB -> mem; r2 receives old 0xAA. r0 = (old<<8) | new_mem = 0xAABB.
    try expectProg(&.{
        i.st(.dw, 10, -8, 0xAA),
        i.mov64Imm(2, 0xBB),
        i.atomic(.dw, i.ATOMIC_XCHG, 10, 2, -8),
        i.ldx(.dw, 3, 10, -8), // r3 = mem = 0xBB
        i.alu64Imm(.lsh, 2, 8), // r2 = 0xAA00
        i.alu64Reg(.add, 2, 3), // r2 = 0xAABB
        i.mov64Reg(0, 2),
        i.exit(),
    }, 0xAABB);
}

test "jit: atomic cmpxchg — match stores new" {
    try mapCode();
    try expectProg(&.{
        i.st(.dw, 10, -8, 100),
        i.mov64Imm(0, 100), // comparand == mem
        i.mov64Imm(2, 999), // new value
        i.atomic(.dw, i.ATOMIC_CMPXCHG, 10, 2, -8), // mem 100->999, r0=old 100
        i.ldx(.dw, 0, 10, -8), // r0 = mem = 999
        i.exit(),
    }, 999);
}

test "jit: atomic cmpxchg — mismatch leaves memory, returns current" {
    try mapCode();
    try expectProg(&.{
        i.st(.dw, 10, -8, 100),
        i.mov64Imm(0, 55), // comparand != mem
        i.mov64Imm(2, 999),
        i.atomic(.dw, i.ATOMIC_CMPXCHG, 10, 2, -8), // no store; r0 = old 100
        i.ldx(.dw, 3, 10, -8), // r3 = mem (still 100)
        i.alu64Reg(.add, 0, 3), // 100 + 100 = 200
        i.exit(),
    }, 200);
}

test "jit: atomic cmpxchg 32-bit zero-extends the old value into r0" {
    try mapCode();
    const a = i.ldImm64(0, 0x8000_0000); // r0 low32 matches the stored word
    try expectProg(&.{
        a[0], a[1],
        i.st(.w, 10, -8, @bitCast(@as(u32, 0x8000_0000))),
        i.mov64Imm(2, 1),
        i.atomic(.w, i.ATOMIC_CMPXCHG, 10, 2, -8), // matches; r0 = old (zero-extended)
        i.exit(),
    }, 0x8000_0000);
}

test "jit: fetch-and-bitwise atomics fall back to the interpreter" {
    try mapCode();
    var ctx: [CTX_LEN]u8 align(8) = [_]u8{0} ** CTX_LEN;
    inline for (.{ i.ATOMIC_OR, i.ATOMIC_AND, i.ATOMIC_XOR }) |base_op| {
        const prog = [_]i.Insn{
            i.st(.dw, 10, -8, 0),
            i.mov64Imm(2, 1),
            i.atomic(.dw, base_op | i.ATOMIC_FETCH, 10, 2, -8),
            i.exit(),
        };
        const r = try runJit(&prog, @intFromPtr(&ctx));
        try std.testing.expect(r == null); // declined → interpreter handles it
    }
}

// === random differential ===

const MAXLEN = 48;

fn valReg(r: std.Random) u4 {
    return @intCast(r.intRangeAtMost(u8, 0, 9)); // never r10 as a value operand
}
fn memBase(r: std.Random, writable: bool) u4 {
    if (writable) return 10; // only the stack is writable -> base must be r10
    return switch (r.intRangeAtMost(u8, 0, 3)) {
        0, 1 => 10, // stack
        2 => 1, // ctx pointer
        else => valReg(r), // usually OOB -> verifier rejects (fine)
    };
}
fn memOff(r: std.Random, base: u4) i16 {
    return switch (base) {
        10 => @intCast(r.intRangeAtMost(i32, -64, -8)), // inside the 512B stack
        1 => @intCast(r.intRangeAtMost(i32, 0, 8)), // inside the 16B ctx
        else => @intCast(r.intRangeAtMost(i32, -64, 64)),
    };
}
fn aSize(r: std.Random) i.Size {
    return switch (r.intRangeAtMost(u8, 0, 3)) {
        0 => .b,
        1 => .h,
        2 => .w,
        else => .dw,
    };
}
fn aSizeWDw(r: std.Random) i.Size {
    return if (r.boolean()) .w else .dw; // atomics are 32/64-bit only
}
fn aOff(r: std.Random) i16 {
    // 8-aligned stack slot in [-64,-8]: in-bounds for both .w and .dw atomics.
    return @as(i16, @intCast(r.intRangeAtMost(i32, -8, -1))) * 8;
}
fn atomicOp(r: std.Random) i32 {
    return switch (r.intRangeAtMost(u8, 0, 9)) {
        0 => i.ATOMIC_ADD,
        1 => i.ATOMIC_ADD | i.ATOMIC_FETCH,
        2 => i.ATOMIC_OR,
        3 => i.ATOMIC_OR | i.ATOMIC_FETCH,
        4 => i.ATOMIC_AND,
        5 => i.ATOMIC_AND | i.ATOMIC_FETCH,
        6 => i.ATOMIC_XOR,
        7 => i.ATOMIC_XOR | i.ATOMIC_FETCH,
        8 => i.ATOMIC_XCHG,
        else => i.ATOMIC_CMPXCHG,
    };
}
fn aluCode(r: std.Random) i.AluCode {
    return switch (r.intRangeAtMost(u8, 0, 8)) {
        0 => .add,
        1 => .sub,
        2 => .@"and",
        3 => .@"or",
        4 => .xor,
        5 => .mul,
        6 => .lsh,
        7 => .rsh,
        else => .arsh,
    };
}
fn jmpCode(r: std.Random) i.JmpCode {
    return switch (r.intRangeAtMost(u8, 0, 10)) {
        0 => .jeq,
        1 => .jne,
        2 => .jgt,
        3 => .jge,
        4 => .jlt,
        5 => .jle,
        6 => .jset,
        7 => .jsgt,
        8 => .jsge,
        9 => .jslt,
        else => .jsle,
    };
}
/// Like aluCode but includes div/mod (and neg) — the full ALU repertoire.
fn aluCodeAny(r: std.Random) i.AluCode {
    return switch (r.intRangeAtMost(u8, 0, 11)) {
        0 => .add,
        1 => .sub,
        2 => .mul,
        3 => .div,
        4 => .@"or",
        5 => .@"and",
        6 => .lsh,
        7 => .rsh,
        8 => .neg,
        9 => .mod,
        10 => .xor,
        else => .arsh,
    };
}
fn endWidth(r: std.Random) i32 {
    return switch (r.intRangeAtMost(u8, 0, 2)) {
        0 => 16,
        1 => 32,
        else => 64,
    };
}
fn sxWidth(r: std.Random) i16 {
    return switch (r.intRangeAtMost(u8, 0, 2)) {
        0 => 8,
        1 => 16,
        else => 32,
    };
}

/// Generate a supported-subset program. Forward-only jumps => a DAG that always
/// terminates (no hang risk while the JIT's loop handling is still unproven).
fn gen(r: std.Random, buf: *[MAXLEN]i.Insn) usize {
    const len = r.intRangeAtMost(usize, 2, MAXLEN);
    var pc: usize = 0;
    while (pc < len) {
        const room = len - pc - 1;
        const fwd: i16 = if (room == 0) 0 else @intCast(r.intRangeAtMost(usize, 0, room - 1));
        const small_imm: i32 = r.intRangeAtMost(i32, -64, 64);

        if (pc == len - 1) {
            buf[pc] = i.exit();
            break;
        }
        switch (r.intRangeAtMost(u8, 0, 14)) {
            0 => buf[pc] = i.mov64Imm(valReg(r), small_imm),
            1 => buf[pc] = i.mov64Reg(valReg(r), valReg(r)),
            2 => buf[pc] = i.alu64Imm(aluCode(r), valReg(r), small_imm),
            3 => buf[pc] = i.alu64Reg(aluCode(r), valReg(r), valReg(r)),
            4 => buf[pc] = i.alu32Imm(aluCode(r), valReg(r), small_imm),
            5 => buf[pc] = i.alu32Reg(aluCode(r), valReg(r), valReg(r)),
            6 => {
                const b = memBase(r, false);
                if (r.boolean()) {
                    buf[pc] = i.ldx(aSize(r), valReg(r), b, memOff(r, b));
                } else {
                    // MEMSX (sign-extending load), b/h/w only (dw sx is a no-op).
                    const sz: i.Size = switch (r.intRangeAtMost(u8, 0, 2)) {
                        0 => .b,
                        1 => .h,
                        else => .w,
                    };
                    buf[pc] = i.ldxSx(sz, valReg(r), b, memOff(r, b));
                }
            },
            7 => buf[pc] = i.st(aSize(r), 10, memOff(r, 10), small_imm),
            8 => buf[pc] = i.stx(aSize(r), 10, valReg(r), memOff(r, 10)),
            9 => buf[pc] = i.jmpImm(jmpCode(r), valReg(r), small_imm, fwd),
            10 => buf[pc] = i.jmpReg(jmpCode(r), valReg(r), valReg(r), fwd),
            11 => buf[pc] = i.ja(fwd),
            12 => {
                if (pc + 1 < len - 1) {
                    const pair = i.ldImm64(valReg(r), r.int(u64));
                    buf[pc] = pair[0];
                    buf[pc + 1] = pair[1];
                    pc += 2;
                    continue;
                }
                buf[pc] = i.mov64Imm(valReg(r), small_imm);
            },
            13 => buf[pc] = i.atomic(aSizeWDw(r), atomicOp(r), 10, valReg(r), aOff(r)), // stack-only (writable)
            else => buf[pc] = i.exit(),
        }
        pc += 1;
    }
    return len;
}

test "jit: differential vs interpreter over random verified programs" {
    try mapCode();
    var prng = std.Random.DefaultPrng.init(0x1F2E3D4C5B6A7988);
    const r = prng.random();

    const ITERS = 200_000;
    var accepted: u64 = 0;
    var unsupported: u64 = 0;
    var tested: u64 = 0;
    var compared: u64 = 0;

    var buf: [MAXLEN]i.Insn = undefined;
    var ctx: [CTX_LEN]u8 align(8) = undefined;

    var it: usize = 0;
    while (it < ITERS) : (it += 1) {
        const len = gen(r, &buf);
        const prog = buf[0..len];

        v.verify(prog, CFG) catch {
            continue;
        };
        accepted += 1;

        // Does the JIT support every opcode here? Probe once with a zero ctx.
        @memset(&ctx, 0);
        const probe = runJit(prog, @intFromPtr(&ctx)) catch |err| {
            std.debug.print("\nJIT compile error {s} on accepted program:\n", .{@errorName(err)});
            dumpProg(prog);
            return err;
        };
        if (probe == null) {
            unsupported += 1;
            continue;
        }
        tested += 1;

        var trial: usize = 0;
        while (trial < 4) : (trial += 1) {
            r.bytes(ctx[0..]);
            const interp = runInterp(prog, &ctx) catch |err| {
                // A verified program faulting in the interpreter is a verifier
                // soundness bug, not a JIT bug — surface it, don't hide it.
                std.debug.print("\ninterpreter error {s} on accepted program:\n", .{@errorName(err)});
                dumpProg(prog);
                return err;
            };
            const jitted = (try runJit(prog, @intFromPtr(&ctx))).?;
            if (interp != jitted) {
                std.debug.print("\nJIT DIVERGENCE: interp=0x{x} jit=0x{x} ctx=", .{ interp, jitted });
                for (ctx) |bb| std.debug.print("{x:0>2}", .{bb});
                std.debug.print(" on program ({d} insns):\n", .{len});
                dumpProg(prog);
                return error.JitDivergence;
            }
            compared += 1;
        }
    }

    std.debug.print(
        "\n[jit] {d} iters: {d} accepted, {d} jit-tested ({d} unsupported), {d} native vs interp comparisons — 0 divergences\n",
        .{ ITERS, accepted, tested, unsupported, compared },
    );
    try std.testing.expect(tested > 1000); // the corpus must actually exercise the JIT
}

fn dumpProg(prog: []const i.Insn) void {
    for (prog, 0..) |ins, idx| {
        std.debug.print("  [{d:0>3}] op=0x{x:0>2} dst=r{d} src=r{d} off={d} imm={d}\n", .{ idx, ins.opcode, ins.dst(), ins.src(), ins.offset, ins.imm });
    }
}

// === memory-free ALU/JMP differential ===
// The verifier-gated corpus above proves memory safety before running raw JIT
// code, but the verifier rejects many operand shapes (unprovable bounds), so the
// new ALU/JMP opcodes — div/mod, endian/bswap, MOVSX, JMP32, long-JA — barely get
// exercised there. This corpus contains NO memory access at all, so it is safe to
// run UNVERIFIED: a program can't escape the sandbox without a load/store. That
// lets us throw the full ALU/JMP repertoire with arbitrary operands straight at
// the JIT and diff against the interpreter. r1 (the ctx value) is passed
// identically to both sides; with no loads, its value is never dereferenced, so
// programs may use it freely as data without divergence. Forward-only jumps over
// single-slot instructions => every path reaches EXIT (no hang, no mid-insn land).

fn genAlu(r: std.Random, buf: *[MAXLEN]i.Insn) usize {
    const len = r.intRangeAtMost(usize, 2, MAXLEN);
    var pc: usize = 0;
    while (pc < len) {
        const room = len - pc - 1;
        const fwd: i16 = if (room == 0) 0 else @intCast(r.intRangeAtMost(usize, 0, room - 1));
        const small_imm: i32 = r.intRangeAtMost(i32, -64, 64);

        if (pc == len - 1) {
            buf[pc] = i.exit();
            break;
        }
        switch (r.intRangeAtMost(u8, 0, 17)) {
            0 => buf[pc] = i.mov64Imm(valReg(r), small_imm),
            1 => buf[pc] = i.mov64Reg(valReg(r), valReg(r)),
            2 => buf[pc] = i.alu64Imm(aluCodeAny(r), valReg(r), small_imm),
            3 => buf[pc] = i.alu64Reg(aluCodeAny(r), valReg(r), valReg(r)),
            4 => buf[pc] = i.alu32Imm(aluCodeAny(r), valReg(r), small_imm),
            5 => buf[pc] = i.alu32Reg(aluCodeAny(r), valReg(r), valReg(r)),
            6 => buf[pc] = i.alu64SignedReg(if (r.boolean()) .div else .mod, valReg(r), valReg(r)),
            7 => { // 32-bit signed div/mod (offset=1 selector on the ALU class)
                var x = i.alu32Reg(if (r.boolean()) .div else .mod, valReg(r), valReg(r));
                x.offset = 1;
                buf[pc] = x;
            },
            8 => buf[pc] = i.endian(r.boolean(), valReg(r), endWidth(r)),
            9 => buf[pc] = i.bswap(valReg(r), endWidth(r)),
            10 => buf[pc] = i.mov64Sx(valReg(r), valReg(r), sxWidth(r)),
            11 => { // 32-bit-class MOVSX
                var x = i.alu32Reg(.mov, valReg(r), valReg(r));
                x.offset = sxWidth(r);
                buf[pc] = x;
            },
            12 => buf[pc] = i.jmpImm(jmpCode(r), valReg(r), small_imm, fwd),
            13 => buf[pc] = i.jmpReg(jmpCode(r), valReg(r), valReg(r), fwd),
            14 => buf[pc] = i.jmp32Imm(jmpCode(r), valReg(r), small_imm, fwd),
            15 => buf[pc] = i.jmp32Reg(jmpCode(r), valReg(r), valReg(r), fwd),
            16 => buf[pc] = i.ja(fwd),
            17 => buf[pc] = i.jmp32Imm(.ja, 0, @intCast(fwd), 0), // JMP32 long-JA: delta in imm
            else => buf[pc] = i.exit(),
        }
        pc += 1;
    }
    return len;
}

test "jit: ALU/JMP differential without memory (full opcode coverage)" {
    try mapCode();
    var prng = std.Random.DefaultPrng.init(0x0A11CE5_DEADBEEF);
    const r = prng.random();

    const ITERS = 200_000;
    var tested: u64 = 0;
    var compared: u64 = 0;

    var buf: [MAXLEN]i.Insn = undefined;
    var stack: [i.STACK_SIZE]u8 align(8) = [_]u8{0} ** i.STACK_SIZE;

    var it: usize = 0;
    while (it < ITERS) : (it += 1) {
        const len = genAlu(r, &buf);
        const prog = buf[0..len];

        const n = jit.compile(prog, code_page, &IHELPERS) catch |err| switch (err) {
            error.Unsupported => continue, // every ALU/JMP form should emit; tolerate gaps
            else => {
                std.debug.print("\nJIT compile error {s}:\n", .{@errorName(err)});
                dumpProg(prog);
                return err;
            },
        };
        std.debug.assert(n <= code_page.len);
        tested += 1;
        const f: jit.CompiledFn = @ptrFromInt(@intFromPtr(code_page.ptr));

        var trial: usize = 0;
        while (trial < 3) : (trial += 1) {
            const ctx_val: u64 = r.int(u64); // becomes r1, identically on both sides
            var machine = vm.Vm{};
            const interp = machine.run(prog, ctx_val, FUEL) catch |err| {
                // No memory + in-range forward jumps => the interpreter never errors;
                // if it does, the generator produced something malformed.
                std.debug.print("\ninterp error {s} on memory-free program:\n", .{@errorName(err)});
                dumpProg(prog);
                return err;
            };
            @memset(&stack, 0);
            const jitted = f(ctx_val, @intFromPtr(&stack));
            if (interp.r0 != jitted) {
                std.debug.print("\nJIT DIVERGENCE (no-mem): interp=0x{x} jit=0x{x} r1=0x{x} on program ({d} insns):\n", .{ interp.r0, jitted, ctx_val, len });
                dumpProg(prog);
                return error.JitDivergence;
            }
            compared += 1;
        }
    }

    std.debug.print(
        "\n[jit-alu] {d} iters: {d} jit-tested, {d} native vs interp comparisons — 0 divergences\n",
        .{ ITERS, tested, compared },
    );
    try std.testing.expect(tested > 100_000); // the whole ALU/JMP set must compile
}

// === loops (backward jumps) — the random corpus is forward-only, so cover
//     the back-edge case explicitly with known-terminating programs ===

test "jit: bounded loop sums 0..19" {
    try mapCode();
    // r0=0; r1=0; LOOP: r0+=r1; r1+=1; if r1 < 20 goto LOOP; exit  => 190
    try expectProg(&.{
        i.mov64Imm(0, 0),
        i.mov64Imm(1, 0),
        i.alu64Reg(.add, 0, 1), // [2] LOOP target
        i.alu64Imm(.add, 1, 1),
        i.jmpImm(.jlt, 1, 20, -3), // pc 4: 4+1-3 = 2
        i.exit(),
    }, 190);
}

test "jit: nested-ish loop with a multiply" {
    // r0=1; r1=1; LOOP: r0 *= r1; r1 += 1; if r1 <= 6 goto LOOP; exit => 6! = 720
    try expectProg(&.{
        i.mov64Imm(0, 1),
        i.mov64Imm(1, 1),
        i.alu64Reg(.mul, 0, 1), // [2]
        i.alu64Imm(.add, 1, 1),
        i.jmpImm(.jle, 1, 6, -3),
        i.exit(),
    }, 720);
}

test "jit: perf — native JIT vs interpreter (informational)" {
    try mapCode();
    // A hot bounded loop: 100k iterations of a small mix.
    const prog = [_]i.Insn{
        i.mov64Imm(0, 0),
        i.mov64Imm(1, 0),
        i.alu64Reg(.add, 0, 1), // [2]
        i.alu64Imm(.mul, 0, 3),
        i.alu64Imm(.xor, 0, 0x5A),
        i.alu64Imm(.add, 1, 1),
        i.jmpImm(.jlt, 1, 100_000, -5), // pc 6: 6+1-5 = 2
        i.exit(),
    };

    const code_len = try jit.compile(&prog, code_page, &IHELPERS);
    std.debug.assert(code_len <= code_page.len);
    const f: jit.CompiledFn = @ptrFromInt(@intFromPtr(code_page.ptr));

    var ctx: [CTX_LEN]u8 align(8) = [_]u8{0} ** CTX_LEN;
    var stack: [i.STACK_SIZE]u8 align(8) = [_]u8{0} ** i.STACK_SIZE;
    const env = vm.Env{
        .regions = &[_]vm.Region{.{ .base = @intFromPtr(&ctx), .len = CTX_LEN, .writable = false }},
        .helpers = &IHELPERS,
    };

    // Correctness first: same result.
    const jit_r = f(@intFromPtr(&ctx), @intFromPtr(&stack));
    var m = vm.Vm{};
    const interp_r = (try m.runEnv(&prog, @intFromPtr(&ctx), FUEL, env)).r0;
    try std.testing.expectEqual(interp_r, jit_r);

    const REPS = 200;
    var timer = try std.time.Timer.start();

    timer.reset();
    var s: usize = 0;
    while (s < REPS) : (s += 1) {
        var mm = vm.Vm{};
        _ = try mm.runEnv(&prog, @intFromPtr(&ctx), FUEL, env);
    }
    const interp_ns = timer.read();

    timer.reset();
    s = 0;
    while (s < REPS) : (s += 1) {
        @memset(&stack, 0);
        _ = f(@intFromPtr(&ctx), @intFromPtr(&stack));
    }
    const jit_ns = timer.read();

    const speedup = @as(f64, @floatFromInt(interp_ns)) / @as(f64, @floatFromInt(jit_ns));
    std.debug.print(
        "\n[jit-perf] {d} reps x 100k-iter loop ({d}B of code): interp {d} ms, JIT {d} ms => {d:.1}x faster, result=0x{x}\n",
        .{ REPS, code_len, interp_ns / 1_000_000, jit_ns / 1_000_000, speedup, jit_r },
    );
}
