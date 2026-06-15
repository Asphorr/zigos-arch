// Off-target test harness for src/bpf/{insn,vm}.zig — the zBPF interpreter.
//
// Model: programs are hand-assembled with insn.zig's builders (the Zig
// spellings of the kernel BPF_* macros) and executed in a stack-only Vm.
// run.sh copies the live kernel sources in (gitignored), so the harness
// always tests current code — same pattern as net-test / hrtimer-test.
//
// What M1 asserts, by group:
//   * ALU64/ALU32 semantics: wrapping arith, 32-bit zero-extension, shift
//     masking, RFC 9669 div/mod-by-zero (continue with 0 / dividend),
//     signed div/mod incl. the INT_MIN/-1 wrap, MOVSX, endian/bswap.
//   * Control flow: signed/unsigned compares in both JMP widths, JSET,
//     backward jumps (a real loop), v4 long-JA, fall-off-end rejection.
//   * Memory: stack store/load roundtrips at all 4 sizes, sign-extending
//     loads, the zeroed-stack guarantee, and the sandbox — every access
//     outside the 512-byte stack must be error.OutOfBounds, never a crash.
//   * Fuel: infinite loops halt with error.TimeLimit.
//   * Malformed input: bad opcodes / truncated LD_IMM64 / empty programs
//     are clean errors. The interpreter is the sandbox until the verifier
//     (M3) exists, so "garbage in, Error out" is the core M1 contract.

const std = @import("std");
const i = @import("src/bpf/insn.zig");
const bpf = @import("src/bpf/vm.zig");

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;

const FUEL: u64 = 100_000;

fn run(prog: []const i.Insn) bpf.Error!u64 {
    var vm = bpf.Vm{};
    const res = try vm.run(prog, 0, FUEL);
    return res.r0;
}

fn runCtx(prog: []const i.Insn, ctx: u64) bpf.Error!u64 {
    var vm = bpf.Vm{};
    const res = try vm.run(prog, ctx, FUEL);
    return res.r0;
}

// === ALU ===

test "mov + add + exit" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, 40),
        i.alu64Imm(.add, 0, 2),
        i.exit(),
    };
    try expectEqual(@as(u64, 42), try run(&prog));
}

test "alu64 reg ops: sub/mul/or/and/xor" {
    const prog = [_]i.Insn{
        i.mov64Imm(1, 100),
        i.mov64Imm(2, 7),
        i.mov64Reg(0, 1),
        i.alu64Reg(.sub, 0, 2), // 93
        i.alu64Reg(.mul, 0, 2), // 651
        i.alu64Imm(.@"or", 0, 0x1000), // 0x128B | 0x1000 = 0x128B|0x1000
        i.alu64Imm(.@"and", 0, 0xFFF0),
        i.alu64Imm(.xor, 0, 0x0F),
        i.exit(),
    };
    const expected: u64 = ((651 | 0x1000) & 0xFFF0) ^ 0x0F;
    try expectEqual(expected, try run(&prog));
}

test "alu64 wrapping add" {
    var pair = i.ldImm64(0, 0xFFFF_FFFF_FFFF_FFFF);
    const prog = [_]i.Insn{
        pair[0],
        pair[1],
        i.alu64Imm(.add, 0, 1), // wraps to 0
        i.exit(),
    };
    _ = &pair;
    try expectEqual(@as(u64, 0), try run(&prog));
}

test "alu32 zero-extends the result" {
    var pair = i.ldImm64(0, 0xAAAA_BBBB_FFFF_FFFF);
    const prog = [_]i.Insn{
        pair[0],
        pair[1],
        i.alu32Imm(.add, 0, 1), // 32-bit lane wraps to 0; upper 32 cleared
        i.exit(),
    };
    _ = &pair;
    try expectEqual(@as(u64, 0), try run(&prog));
}

test "neg" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, 5),
        i.alu64Imm(.neg, 0, 0),
        i.exit(),
    };
    try expectEqual(@as(u64, @bitCast(@as(i64, -5))), try run(&prog));
}

test "shift masking: lsh by 64+3 == lsh by 3" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, 1),
        i.alu64Imm(.lsh, 0, 67),
        i.exit(),
    };
    try expectEqual(@as(u64, 8), try run(&prog));
}

test "arsh keeps the sign" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, -16), // sign-extended imm
        i.alu64Imm(.arsh, 0, 2),
        i.exit(),
    };
    try expectEqual(@as(u64, @bitCast(@as(i64, -4))), try run(&prog));
}

test "div/mod by zero: RFC semantics (0 / dividend), run continues" {
    const div_prog = [_]i.Insn{
        i.mov64Imm(0, 100),
        i.mov64Imm(1, 0),
        i.alu64Reg(.div, 0, 1), // => 0
        i.alu64Imm(.add, 0, 7), // proves execution continued
        i.exit(),
    };
    try expectEqual(@as(u64, 7), try run(&div_prog));

    const mod_prog = [_]i.Insn{
        i.mov64Imm(0, 100),
        i.mov64Imm(1, 0),
        i.alu64Reg(.mod, 0, 1), // => dividend (100)
        i.exit(),
    };
    try expectEqual(@as(u64, 100), try run(&mod_prog));
}

test "runStrict turns div-by-zero into an error" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, 100),
        i.mov64Imm(1, 0),
        i.alu64Reg(.div, 0, 1),
        i.exit(),
    };
    var vm = bpf.Vm{};
    try expectError(error.DivideByZero, vm.runStrict(&prog, 0, FUEL));
}

test "signed div/mod incl INT_MIN/-1" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, -100),
        i.mov64Imm(1, 3),
        i.alu64SignedReg(.div, 0, 1), // trunc(-100/3) = -33
        i.exit(),
    };
    try expectEqual(@as(u64, @bitCast(@as(i64, -33))), try run(&prog));

    // INT_MIN / -1 must not trap; eBPF wraps to INT_MIN.
    var pair = i.ldImm64(0, @bitCast(@as(i64, std.math.minInt(i64))));
    const ovf = [_]i.Insn{
        pair[0],
        pair[1],
        i.mov64Imm(1, -1),
        i.alu64SignedReg(.div, 0, 1),
        i.exit(),
    };
    _ = &pair;
    try expectEqual(@as(u64, @bitCast(@as(i64, std.math.minInt(i64)))), try run(&ovf));

    var pair2 = i.ldImm64(0, @bitCast(@as(i64, std.math.minInt(i64))));
    const ovf_mod = [_]i.Insn{
        pair2[0],
        pair2[1],
        i.mov64Imm(1, -1),
        i.alu64SignedReg(.mod, 0, 1), // => 0
        i.exit(),
    };
    _ = &pair2;
    try expectEqual(@as(u64, 0), try run(&ovf_mod));
}

test "movsx sign-extends 8/16/32-bit sources" {
    const prog = [_]i.Insn{
        i.mov64Imm(1, 0xFF), // low byte = -1 as i8
        i.mov64Sx(0, 1, 8),
        i.exit(),
    };
    try expectEqual(@as(u64, @bitCast(@as(i64, -1))), try run(&prog));
}

test "malformed movsx width is a clean error, not a panic" {
    var bad = i.mov64Sx(0, 1, 13);
    const prog = [_]i.Insn{ bad, i.exit() };
    _ = &bad;
    try expectError(error.UnknownOpcode, run(&prog));
}

test "endian: to_be16 on a little-endian host swaps, to_le16 doesn't" {
    const be = [_]i.Insn{
        i.mov64Imm(0, 0x1234),
        i.endian(true, 0, 16),
        i.exit(),
    };
    try expectEqual(@as(u64, 0x3412), try run(&be));

    const le = [_]i.Insn{
        i.mov64Imm(0, 0x1234),
        i.endian(false, 0, 16),
        i.exit(),
    };
    try expectEqual(@as(u64, 0x1234), try run(&le));
}

test "bswap64 (v4) is unconditional" {
    var pair = i.ldImm64(0, 0x0102030405060708);
    const prog = [_]i.Insn{
        pair[0],
        pair[1],
        i.bswap(0, 64),
        i.exit(),
    };
    _ = &pair;
    try expectEqual(@as(u64, 0x0807060504030201), try run(&prog));
}

test "ld_imm64 loads a full 64-bit constant" {
    var pair = i.ldImm64(0, 0xDEAD_BEEF_CAFE_BABE);
    const prog = [_]i.Insn{ pair[0], pair[1], i.exit() };
    _ = &pair;
    try expectEqual(@as(u64, 0xDEAD_BEEF_CAFE_BABE), try run(&prog));
}

// === control flow ===

test "jeq taken and not taken" {
    const prog = [_]i.Insn{
        i.mov64Imm(1, 5),
        i.jmpImm(.jeq, 1, 5, 2), // taken: skip the next two
        i.mov64Imm(0, 111),
        i.exit(),
        i.mov64Imm(0, 222),
        i.exit(),
    };
    try expectEqual(@as(u64, 222), try run(&prog));
}

test "signed compare: -1 jsgt 1 is false, 1 jsgt -1 is true" {
    const prog = [_]i.Insn{
        i.mov64Imm(1, 1),
        i.jmpImm(.jsgt, 1, -1, 2), // 1 > -1 signed => taken
        i.mov64Imm(0, 0),
        i.exit(),
        i.mov64Imm(0, 1),
        i.exit(),
    };
    try expectEqual(@as(u64, 1), try run(&prog));

    // Unsigned view of the same operands flips the answer.
    const uns = [_]i.Insn{
        i.mov64Imm(1, 1),
        i.jmpImm(.jgt, 1, -1, 2), // 1 > 0xFFFF..FF unsigned => NOT taken
        i.mov64Imm(0, 0),
        i.exit(),
        i.mov64Imm(0, 1),
        i.exit(),
    };
    try expectEqual(@as(u64, 0), try run(&uns));
}

test "jmp32 compares only the low 32 bits" {
    var pair = i.ldImm64(1, 0xFFFF_FFFF_0000_0005);
    const prog = [_]i.Insn{
        pair[0],
        pair[1],
        i.jmp32Imm(.jeq, 1, 5, 2), // low lane == 5 => taken
        i.mov64Imm(0, 0),
        i.exit(),
        i.mov64Imm(0, 1),
        i.exit(),
    };
    _ = &pair;
    try expectEqual(@as(u64, 1), try run(&prog));
}

test "jset tests bits" {
    const prog = [_]i.Insn{
        i.mov64Imm(1, 0b1010),
        i.jmpImm(.jset, 1, 0b0010, 2),
        i.mov64Imm(0, 0),
        i.exit(),
        i.mov64Imm(0, 1),
        i.exit(),
    };
    try expectEqual(@as(u64, 1), try run(&prog));
}

test "backward jump: sum 1..10 in a real loop" {
    // r1 = counter, r0 = acc
    const prog = [_]i.Insn{
        i.mov64Imm(1, 10),
        i.mov64Imm(0, 0),
        i.alu64Reg(.add, 0, 1), // loop:
        i.alu64Imm(.sub, 1, 1),
        i.jmpImm(.jne, 1, 0, -3), // while r1 != 0
        i.exit(),
    };
    try expectEqual(@as(u64, 55), try run(&prog));
}

test "v4 long JA uses imm in jmp32 class" {
    const prog = [_]i.Insn{
        i.jmp32Imm(.ja, 0, 2, 0), // jump over the next two via imm
        i.mov64Imm(0, 111),
        i.exit(),
        i.mov64Imm(0, 222),
        i.exit(),
    };
    try expectEqual(@as(u64, 222), try run(&prog));
}

test "falling off the end without exit is BadJump" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, 1),
    };
    try expectError(error.BadJump, run(&prog));
}

test "jump out of range is BadJump" {
    const prog = [_]i.Insn{
        i.ja(100),
        i.exit(),
    };
    try expectError(error.BadJump, run(&prog));
}

// === memory / sandbox ===

test "stack store/load roundtrip at all sizes" {
    var pair = i.ldImm64(1, 0x1122_3344_5566_7788);
    const prog = [_]i.Insn{
        pair[0],
        pair[1],
        i.stx(.dw, 10, 1, -8),
        i.stx(.w, 10, 1, -12),
        i.stx(.h, 10, 1, -14),
        i.stx(.b, 10, 1, -15),
        i.ldx(.dw, 0, 10, -8), // full value back
        i.ldx(.w, 2, 10, -12), // low 32: 0x55667788
        i.ldx(.h, 3, 10, -14), // low 16: 0x7788
        i.ldx(.b, 4, 10, -15), // low 8:  0x88
        i.alu64Reg(.add, 0, 2),
        i.alu64Reg(.add, 0, 3),
        i.alu64Reg(.add, 0, 4),
        i.exit(),
    };
    _ = &pair;
    const want: u64 = 0x1122_3344_5566_7788 + 0x5566_7788 + 0x7788 + 0x88;
    try expectEqual(want, try run(&prog));
}

test "st stores an immediate" {
    const prog = [_]i.Insn{
        i.st(.w, 10, -4, 1234),
        i.ldx(.w, 0, 10, -4),
        i.exit(),
    };
    try expectEqual(@as(u64, 1234), try run(&prog));
}

test "sign-extending load (memsx)" {
    const prog = [_]i.Insn{
        i.st(.b, 10, -1, -1), // 0xFF
        i.ldxSx(.b, 0, 10, -1),
        i.exit(),
    };
    try expectEqual(@as(u64, @bitCast(@as(i64, -1))), try run(&prog));
}

test "stack is zeroed every run" {
    const prog = [_]i.Insn{
        i.ldx(.dw, 0, 10, -8),
        i.exit(),
    };
    // First run dirties the stack, second must still read zero.
    var vm = bpf.Vm{};
    const dirty = [_]i.Insn{
        i.st(.w, 10, -8, -1),
        i.st(.w, 10, -4, -1),
        i.mov64Imm(0, 0),
        i.exit(),
    };
    _ = try vm.run(&dirty, 0, FUEL);
    const res = try vm.run(&prog, 0, FUEL);
    try expectEqual(@as(u64, 0), res.r0);
}

test "sandbox: access below, above, and astride the stack is OutOfBounds" {
    // One past the top (r10 itself).
    const above = [_]i.Insn{
        i.ldx(.b, 0, 10, 0),
        i.exit(),
    };
    try expectError(error.OutOfBounds, run(&above));

    // Below the base.
    const below = [_]i.Insn{
        i.ldx(.b, 0, 10, -513),
        i.exit(),
    };
    try expectError(error.OutOfBounds, run(&below));

    // Straddling the top edge: 8-byte read whose tail crosses out.
    const straddle = [_]i.Insn{
        i.ldx(.dw, 0, 10, -4),
        i.exit(),
    };
    try expectError(error.OutOfBounds, run(&straddle));
}

test "sandbox: dereferencing the ctx scalar is OutOfBounds in M1" {
    // r1 arrives holding a caller value, but M1 registers no region for it —
    // treating it as a pointer must fail cleanly, even when the value is a
    // real host address.
    var marker: u64 = 0x5151_5151_5151_5151;
    const prog = [_]i.Insn{
        i.ldx(.dw, 0, 1, 0),
        i.exit(),
    };
    try expectError(error.OutOfBounds, runCtx(&prog, @intFromPtr(&marker)));
    try expectEqual(@as(u64, 0x5151_5151_5151_5151), marker); // untouched
}

test "sandbox: write through a wild pointer is OutOfBounds" {
    var pair = i.ldImm64(1, 0x12345678);
    const prog = [_]i.Insn{
        pair[0],
        pair[1],
        i.stx(.dw, 1, 10, 0),
        i.exit(),
    };
    _ = &pair;
    try expectError(error.OutOfBounds, run(&prog));
}

// === fuel + malformed input ===

test "infinite loop halts with TimeLimit" {
    const prog = [_]i.Insn{
        i.ja(-1),
        i.exit(),
    };
    try expectError(error.TimeLimit, run(&prog));
}

test "fuel is accounted" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, 42),
        i.exit(),
    };
    var vm = bpf.Vm{};
    const res = try vm.run(&prog, 0, FUEL);
    try expectEqual(@as(u64, 2), res.steps);
}

test "malformed atomics and legacy packet loads are cleanly rejected" {
    // Atomics are now supported (see the atomic tests) — but a BYTE-size atomic
    // is malformed (W/DW only), and the interpreter rejects it defence-in-depth.
    var bad_size = i.atomic(.w, i.ATOMIC_ADD, 10, 1, -4);
    bad_size.opcode = i.MODE_ATOMIC | @intFromEnum(i.Size.b) | i.CLASS_STX;
    const sz_prog = [_]i.Insn{ i.mov64Imm(1, 1), bad_size, i.exit() };
    try expectError(error.UnknownOpcode, run(&sz_prog));

    // An unknown atomic operation in imm is rejected too.
    const op_prog = [_]i.Insn{ i.mov64Imm(1, 1), i.atomic(.dw, 0x33, 10, 1, -8), i.exit() };
    try expectError(error.UnknownOpcode, run(&op_prog));

    // Legacy cBPF ABS packet load — still unsupported.
    var abs = i.ldx(.w, 0, 0, 0);
    abs.opcode = i.MODE_ABS | @intFromEnum(i.Size.w) | i.CLASS_LD;
    const l_prog = [_]i.Insn{ abs, i.exit() };
    _ = &abs;
    try expectError(error.UnknownOpcode, run(&l_prog));
}

test "truncated and malformed ld_imm64 are BadImm64" {
    var pair = i.ldImm64(0, 0x1);
    const truncated = [_]i.Insn{pair[0]}; // second slot missing entirely
    _ = &pair;
    try expectError(error.BadImm64, run(&truncated));

    var pair2 = i.ldImm64(0, 0x1);
    const wrong_second = [_]i.Insn{ pair2[0], i.exit() }; // wrong pseudo-slot
    _ = &pair2;
    try expectError(error.BadImm64, run(&wrong_second));
}

test "empty program is BadProgram" {
    const prog = [_]i.Insn{};
    try expectError(error.BadProgram, run(&prog));
}

test "garbage opcode is UnknownOpcode" {
    const prog = [_]i.Insn{
        .{ .opcode = 0xFF, .regs = 0, .offset = 0, .imm = 0 },
        i.exit(),
    };
    try expectError(error.UnknownOpcode, run(&prog));
}

// === M2: regions (real ctx structs) + helper calls ===

test "ctx region: program reads a real struct's fields" {
    const Ctx = extern struct { nr: u64, pid: u64 };
    var ctx = Ctx{ .nr = 7, .pid = 42 };
    const prog = [_]i.Insn{
        i.ldx(.dw, 2, 1, 0), // r2 = ctx->nr
        i.ldx(.dw, 0, 1, 8), // r0 = ctx->pid
        i.alu64Reg(.add, 0, 2), // r0 = pid + nr
        i.exit(),
    };
    var vm = bpf.Vm{};
    const env = bpf.Env{
        .regions = &[_]bpf.Region{
            .{ .base = @intFromPtr(&ctx), .len = @sizeOf(Ctx) },
        },
    };
    const res = try vm.runEnv(&prog, @intFromPtr(&ctx), FUEL, env);
    try expectEqual(@as(u64, 49), res.r0);
}

test "ctx region is read-only: store into it is OutOfBounds" {
    var ctx: u64 = 7;
    const prog = [_]i.Insn{
        i.st(.dw, 1, 0, 99),
        i.exit(),
    };
    var vm = bpf.Vm{};
    const env = bpf.Env{
        .regions = &[_]bpf.Region{
            .{ .base = @intFromPtr(&ctx), .len = 8, .writable = false },
        },
    };
    try expectError(error.OutOfBounds, vm.runEnv(&prog, @intFromPtr(&ctx), FUEL, env));
    try expectEqual(@as(u64, 7), ctx); // untouched
}

test "writable region: program output lands in host memory" {
    var out: u64 = 0;
    const prog = [_]i.Insn{
        i.st(.dw, 1, 0, 1234),
        i.mov64Imm(0, 0),
        i.exit(),
    };
    var vm = bpf.Vm{};
    const env = bpf.Env{
        .regions = &[_]bpf.Region{
            .{ .base = @intFromPtr(&out), .len = 8, .writable = true },
        },
    };
    _ = try vm.runEnv(&prog, @intFromPtr(&out), FUEL, env);
    try expectEqual(@as(u64, 1234), out);
}

test "region edges: access straddling a region boundary is OutOfBounds" {
    var ctx: [8]u8 = undefined;
    const prog = [_]i.Insn{
        i.ldx(.dw, 0, 1, 4), // 8-byte read at +4 of an 8-byte region
        i.exit(),
    };
    var vm = bpf.Vm{};
    const env = bpf.Env{
        .regions = &[_]bpf.Region{
            .{ .base = @intFromPtr(&ctx), .len = ctx.len },
        },
    };
    try expectError(error.OutOfBounds, vm.runEnv(&prog, @intFromPtr(&ctx), FUEL, env));
}

// Helper-call scaffolding: module-level state because HelperFn is a plain
// fn pointer (no closure ctx) — exactly the constraint kernel helpers have.
var helper_log: [5]u64 = undefined;
fn helperRecordArgs(a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) callconv(.c) u64 {
    helper_log = .{ a1, a2, a3, a4, a5 };
    return a1 + a2 + a3 + a4 + a5;
}
var counter_slots: [4]u64 = [_]u64{0} ** 4;
fn helperCount(idx: u64, _: u64, _: u64, _: u64, _: u64) callconv(.c) u64 {
    if (idx >= counter_slots.len) return 1; // helper validates its own args
    counter_slots[@intCast(idx)] += 1;
    return 0;
}
const TEST_HELPERS = [_]?bpf.HelperFn{
    null, // id 0 reserved — must reject
    helperRecordArgs, // 1
    helperCount, // 2
};

test "helper call: r1-r5 arrive as args, result lands in r0" {
    const prog = [_]i.Insn{
        i.mov64Imm(1, 10),
        i.mov64Imm(2, 20),
        i.mov64Imm(3, 30),
        i.mov64Imm(4, 40),
        i.mov64Imm(5, 50),
        i.call(1),
        i.exit(),
    };
    var vm = bpf.Vm{};
    const res = try vm.runEnv(&prog, 0, FUEL, .{ .helpers = &TEST_HELPERS });
    try expectEqual(@as(u64, 150), res.r0);
    try expectEqual(@as(u64, 10), helper_log[0]);
    try expectEqual(@as(u64, 50), helper_log[4]);
}

test "helper id misuse: null slot, out-of-range id, bpf-to-bpf call" {
    var vm = bpf.Vm{};

    const null_slot = [_]i.Insn{ i.call(0), i.exit() };
    try expectError(error.BadHelperId, vm.runEnv(&null_slot, 0, FUEL, .{ .helpers = &TEST_HELPERS }));

    const oob = [_]i.Insn{ i.call(99), i.exit() };
    try expectError(error.BadHelperId, vm.runEnv(&oob, 0, FUEL, .{ .helpers = &TEST_HELPERS }));

    var local = i.call(1);
    local.regs = 1 << 4; // src=1: bpf-to-bpf call — not supported yet
    const l_prog = [_]i.Insn{ local, i.exit() };
    _ = &local;
    try expectError(error.BadHelperId, vm.runEnv(&l_prog, 0, FUEL, .{ .helpers = &TEST_HELPERS }));

    // And with NO env at all (the M1 wrappers), any call must reject.
    const m1 = [_]i.Insn{ i.call(1), i.exit() };
    try expectError(error.BadHelperId, vm.run(&m1, 0, FUEL));
}

test "end-to-end M2 shape: the syscall-counter program against a fake ctx" {
    // Byte-for-byte the program bpf/kernel.zig attaches at syscall entry,
    // driven here against a fake context + the counting helper above.
    const Ctx = extern struct { nr: u64, pid: u64 };
    const prog = [_]i.Insn{
        i.ldx(.dw, 2, 1, 0), // r2 = ctx->nr
        i.ldx(.dw, 1, 1, 8), // r1 = ctx->pid
        i.call(2), // count(pid)
        i.mov64Imm(0, 0),
        i.exit(),
    };
    counter_slots = [_]u64{0} ** 4;

    var vm = bpf.Vm{};
    var pid: u64 = 0;
    while (pid < 3) : (pid += 1) {
        var reps: u64 = 0;
        while (reps < pid + 1) : (reps += 1) {
            var ctx = Ctx{ .nr = 8, .pid = pid };
            const env = bpf.Env{
                .regions = &[_]bpf.Region{
                    .{ .base = @intFromPtr(&ctx), .len = @sizeOf(Ctx) },
                },
                .helpers = &TEST_HELPERS,
            };
            const res = try vm.runEnv(&prog, @intFromPtr(&ctx), FUEL, env);
            try expectEqual(@as(u64, 0), res.r0);
        }
    }
    try expectEqual(@as(u64, 1), counter_slots[0]);
    try expectEqual(@as(u64, 2), counter_slots[1]);
    try expectEqual(@as(u64, 3), counter_slots[2]);

    // A pid the helper must refuse: returns 1, counts untouched.
    var ctx = Ctx{ .nr = 8, .pid = 9999 };
    const env = bpf.Env{
        .regions = &[_]bpf.Region{
            .{ .base = @intFromPtr(&ctx), .len = @sizeOf(Ctx) },
        },
        .helpers = &TEST_HELPERS,
    };
    const res = try vm.runEnv(&prog, @intFromPtr(&ctx), FUEL, env);
    try expectEqual(@as(u64, 0), res.r0); // program ignores helper rc; map just doesn't move
    try expectEqual(@as(u64, 1), counter_slots[0]);
}

// === a real program: fizzbuzz-style classification, end to end ===

test "end-to-end: classify ctx value via div/mod/branches" {
    // r0 = 3 if ctx%15==0, 1 if ctx%3==0, 2 if ctx%5==0, else 0.
    const prog = [_]i.Insn{
        i.mov64Reg(2, 1), // r2 = n
        i.alu64Imm(.mod, 2, 15),
        i.jmpImm(.jne, 2, 0, 2),
        i.mov64Imm(0, 3),
        i.exit(),
        i.mov64Reg(2, 1),
        i.alu64Imm(.mod, 2, 3),
        i.jmpImm(.jne, 2, 0, 2),
        i.mov64Imm(0, 1),
        i.exit(),
        i.mov64Reg(2, 1),
        i.alu64Imm(.mod, 2, 5),
        i.jmpImm(.jne, 2, 0, 2),
        i.mov64Imm(0, 2),
        i.exit(),
        i.mov64Imm(0, 0),
        i.exit(),
    };
    try expectEqual(@as(u64, 3), try runCtx(&prog, 30));
    try expectEqual(@as(u64, 1), try runCtx(&prog, 9));
    try expectEqual(@as(u64, 2), try runCtx(&prog, 10));
    try expectEqual(@as(u64, 0), try runCtx(&prog, 7));
}

// === atomics — the interpreter is the semantic contract the JIT matches ===

fn runProg(prog: []const i.Insn) !u64 {
    var vm = bpf.Vm{};
    return (try vm.run(prog, 0, FUEL)).r0; // M1 run: own stack, runtime-checked
}

test "atomic: add / fetch-add / xchg / cmpxchg on the stack" {
    // add: 100 + 5, read back => 105
    try expectEqual(@as(u64, 105), try runProg(&.{
        i.st(.dw, 10, -8, 100), i.mov64Imm(2, 5),
        i.atomic(.dw, i.ATOMIC_ADD, 10, 2, -8),
        i.ldx(.dw, 0, 10, -8), i.exit(),
    }));
    // fetch-add: the old value (100) lands in the src register
    try expectEqual(@as(u64, 100), try runProg(&.{
        i.st(.dw, 10, -8, 100), i.mov64Imm(2, 5),
        i.atomic(.dw, i.ATOMIC_ADD | i.ATOMIC_FETCH, 10, 2, -8),
        i.mov64Reg(0, 2), i.exit(),
    }));
    // xchg: memory becomes the new value
    try expectEqual(@as(u64, 0xBB), try runProg(&.{
        i.st(.dw, 10, -8, 0xAA), i.mov64Imm(2, 0xBB),
        i.atomic(.dw, i.ATOMIC_XCHG, 10, 2, -8),
        i.ldx(.dw, 0, 10, -8), i.exit(),
    }));
    // cmpxchg match: stores the new value
    try expectEqual(@as(u64, 999), try runProg(&.{
        i.st(.dw, 10, -8, 100), i.mov64Imm(0, 100), i.mov64Imm(2, 999),
        i.atomic(.dw, i.ATOMIC_CMPXCHG, 10, 2, -8),
        i.ldx(.dw, 0, 10, -8), i.exit(),
    }));
    // cmpxchg mismatch: r0 receives the current value, memory untouched
    try expectEqual(@as(u64, 100), try runProg(&.{
        i.st(.dw, 10, -8, 100), i.mov64Imm(0, 55), i.mov64Imm(2, 999),
        i.atomic(.dw, i.ATOMIC_CMPXCHG, 10, 2, -8),
        i.exit(), // r0 = old = 100
    }));
}

test "atomic: 32-bit add operates on the low word only" {
    try expectEqual(@as(u64, 3), try runProg(&.{
        i.st(.w, 10, -8, 1), i.mov64Imm(2, 2),
        i.atomic(.w, i.ATOMIC_ADD, 10, 2, -8),
        i.ldx(.w, 0, 10, -8), i.exit(),
    }));
}
