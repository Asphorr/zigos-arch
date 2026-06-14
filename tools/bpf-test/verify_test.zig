// Off-target test harness for src/bpf/verifier.zig — zBPF's M3a static pass.
//
// run.sh copies the live kernel sources in (gitignored), so this always tests
// current code — same pattern as test.zig (the interpreter harness).
//
// The suite is organized as: ACCEPT cases (well-formed programs the verifier
// must admit, including the real builtin, pointer arithmetic, and branch
// joins), then one REJECT case per VerifyError — each a minimal program that
// trips exactly that static check before it could ever reach the interpreter.

const std = @import("std");
const i = @import("src/bpf/insn.zig");
const v = @import("src/bpf/verifier.zig");

const expectError = std.testing.expectError;

// The contract the syscall-entry hook runs under: a 16-byte read-only ctx
// (SyscallCtx{nr,pid}) and one helper, count(pid), reading a single argument.
const HELPERS = [_]?v.HelperSig{
    null, // 0: reserved/unregistered
    .{ .n_args = 1 }, // 1: count(pid)
};
const CFG = v.Config{ .ctx_len = 16, .ctx_writable = false, .helpers = &HELPERS };

fn ok(prog: []const i.Insn) !void {
    return v.verify(prog, CFG);
}

// =========================== ACCEPT ===========================

test "accept: the real builtin syscall counter" {
    // Byte-for-byte the program in bpf/kernel.zig — the first dogfood.
    const prog = [_]i.Insn{
        i.ldx(.dw, 2, 1, 0), // r2 = ctx->nr
        i.ldx(.dw, 1, 1, 8), // r1 = ctx->pid
        i.call(1), // count(r1)
        i.mov64Imm(0, 0), // r0 = 0
        i.exit(),
    };
    try ok(&prog);
}

test "accept: bare exit" {
    const prog = [_]i.Insn{i.exit()};
    try ok(&prog);
}

test "accept: stack scratch via pointer arithmetic" {
    const prog = [_]i.Insn{
        i.mov64Reg(2, 10), // r2 = r10 (frame ptr, off 512)
        i.alu64Imm(.add, 2, -8), // r2 = &stack[-8]  (off 504)
        i.st(.dw, 2, 0, 0), // *(u64*)(r2+0) = 0   → [504,512) ⊆ stack, writable
        i.ldx(.dw, 3, 2, 0), // r3 = *(u64*)(r2+0)  → reads it back
        i.mov64Imm(0, 0),
        i.exit(),
    };
    try ok(&prog);
}

test "accept: forward branch with a clean join" {
    // r0 is written on BOTH paths before the join, then mov (no read) at the
    // join — must not false-positive on uninit.
    const prog = [_]i.Insn{
        i.mov64Imm(2, 0), // r2 = 0
        i.jmpImm(.jeq, 2, 0, 1), // if r2==0 → +1 (skip the next mov)
        i.mov64Imm(0, 7), // r0 = 7   (not-taken path)
        i.mov64Imm(0, 9), // r0 = 9   (join: mov doesn't read r0)
        i.exit(),
    };
    try ok(&prog);
}

test "accept: ctx loads at the exact end boundary" {
    const prog = [_]i.Insn{
        i.ldx(.dw, 2, 1, 8), // last 8 bytes [8,16) of the 16-byte ctx
        i.mov64Imm(0, 0),
        i.exit(),
    };
    try ok(&prog);
}

// --- M3b range tracking: computed offsets that M3a could not prove ---

test "accept (M3b): masked index gives a bounded stack offset" {
    const prog = [_]i.Insn{
        i.ldx(.w, 2, 1, 0), // r2 = ctx word -> [0, 2^32)
        i.alu64Imm(.@"and", 2, 0x1F), // r2 &= 31 -> [0,31]
        i.mov64Reg(3, 10), // r3 = frame ptr (off 512)
        i.alu64Imm(.add, 3, -64), // r3 -> off 448
        i.alu64Reg(.add, 3, 2), // r3 -> off [448, 479]
        i.ldx(.dw, 4, 3, 0), // [448,479]+8 <= 512 — provably in-stack
        i.mov64Imm(0, 0),
        i.exit(),
    };
    try ok(&prog);
}

test "accept (M3b): bounds-checked variable ctx index via narrowing" {
    const prog = [_]i.Insn{
        i.ldx(.w, 2, 1, 0), // r2 = ctx word -> [0, 2^32)
        i.jmpImm(.jgt, 2, 7, 3), // if r2 > 7 -> skip the access
        i.mov64Reg(3, 1), // r3 = ctx ptr (off 0)
        i.alu64Reg(.add, 3, 2), // fall-through: r2 in [0,7] -> off [0,7]
        i.ldx(.b, 4, 3, 0), // [0,7]+1 <= 16 — provably in-ctx
        i.mov64Imm(0, 0), // <- jgt target
        i.exit(),
    };
    try ok(&prog);
}

test "reject (M3b): an UNchecked variable index stays out of bounds" {
    const prog = [_]i.Insn{
        i.ldx(.w, 2, 1, 0), // r2 = ctx word -> [0, 2^32), never narrowed
        i.mov64Reg(3, 1), // r3 = ctx ptr
        i.alu64Reg(.add, 3, 2), // r3 -> off [0, 2^32)
        i.ldx(.b, 4, 3, 0), // hi = 2^32 > ctx_len 16
        i.mov64Imm(0, 0),
        i.exit(),
    };
    try expectError(error.OutOfBoundsAccess, ok(&prog));
}

// =========================== REJECT (one per VerifyError) ===========================

test "reject: empty program" {
    try expectError(error.EmptyProgram, v.verify(&[_]i.Insn{}, CFG));
}

test "reject: falls off the end without exit" {
    const prog = [_]i.Insn{i.mov64Imm(0, 0)};
    try expectError(error.NoExit, ok(&prog));
}

test "reject: reads an uninitialized register" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, 0), // r0 init
        i.alu64Reg(.add, 0, 3), // r0 += r3, but r3 was never set
        i.exit(),
    };
    try expectError(error.UninitReg, ok(&prog));
}

test "reject: register live on only one branch" {
    const prog = [_]i.Insn{
        i.mov64Imm(2, 0),
        i.jmpImm(.jeq, 2, 0, 1), // taken path skips the r0 init
        i.mov64Imm(0, 7), // r0 set only on the not-taken path
        i.alu64Imm(.add, 0, 1), // reads r0 → uninit on the taken path
        i.exit(),
    };
    try expectError(error.UninitReg, ok(&prog));
}

test "reject: write to the read-only frame pointer r10" {
    const prog = [_]i.Insn{
        i.mov64Imm(10, 0), // r10 = 0  — illegal
        i.exit(),
    };
    try expectError(error.WriteToR10, ok(&prog));
}

// --- M4 loops: back-edges are now allowed, but must provably terminate ---

test "accept (M4): a bounded counted loop" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, 0), // r0 = 0
        i.jmpImm(.jge, 0, 5, 2), // L: if r0 >= 5 goto E
        i.alu64Imm(.add, 0, 1), //    r0 += 1
        i.ja(-3), //    goto L
        i.exit(), // E: exit
    };
    try ok(&prog); // unrolls r0 = 0..5, exit edge fires — provably terminates
}

test "reject (M4): an infinite self-loop is UnboundedLoop" {
    const prog = [_]i.Insn{
        i.ja(-1), // jumps to itself with an unchanging state
        i.exit(),
    };
    try expectError(error.UnboundedLoop, ok(&prog));
}

test "reject (M4): a counter that never reaches an exit is TooComplex" {
    const prog = [_]i.Insn{
        i.mov64Imm(0, 0),
        i.alu64Imm(.add, 0, 1), // r0 grows forever; state never repeats
        i.ja(-2), // ... so it is rejected only when it exhausts the step budget
        i.exit(),
    };
    try expectError(error.TooComplex, ok(&prog));
}

test "reject: jump target out of range" {
    const prog = [_]i.Insn{
        i.ja(5), // target 6, past the end
        i.exit(),
    };
    try expectError(error.JumpOutOfRange, ok(&prog));
}

test "reject: jump into the second slot of an LD_IMM64" {
    const li = i.ldImm64(0, 0xdeadbeef);
    const prog = [_]i.Insn{
        i.ja(1), // target 2 = the LD_IMM64 high slot
        li[0],
        li[1],
        i.exit(),
    };
    try expectError(error.JumpIntoImm64, ok(&prog));
}

test "reject: stack access past the top" {
    const prog = [_]i.Insn{
        i.st(.dw, 10, 0, 0), // *(u64*)(r10+0) — [512,520), off the top
        i.exit(),
    };
    try expectError(error.OutOfBoundsAccess, ok(&prog));
}

test "reject: ctx load past the end" {
    const prog = [_]i.Insn{
        i.ldx(.dw, 0, 1, 16), // *(u64*)(ctx+16) — [16,24), past the 16-byte ctx
        i.exit(),
    };
    try expectError(error.OutOfBoundsAccess, ok(&prog));
}

test "reject: store into the read-only ctx" {
    const prog = [_]i.Insn{
        i.st(.dw, 1, 0, 42), // *(u64*)(ctx+0) = 42 — ctx is read-only
        i.exit(),
    };
    try expectError(error.WriteToReadonly, ok(&prog));
}

test "reject: dereference a scalar" {
    const prog = [_]i.Insn{
        i.mov64Imm(2, 12345), // r2 is a scalar, not a pointer
        i.ldx(.dw, 0, 2, 0), // *(u64*)(r2+0)
        i.exit(),
    };
    try expectError(error.NotAPointer, ok(&prog));
}

test "reject: call to an unregistered helper id" {
    const prog = [_]i.Insn{
        i.call(5), // only ids 0..1 exist
        i.exit(),
    };
    try expectError(error.UnknownHelper, ok(&prog));
}

test "reject: call with an uninitialized argument register" {
    const prog = [_]i.Insn{
        i.call(1), // count(r1) but r1 was clobbered/never set... actually r1=ctx at entry
        i.exit(),
    };
    // r1 is the ctx pointer at entry — initialized — so this particular program
    // is fine; assert it verifies, then a real uninit-arg case below.
    try ok(&prog);
}

test "reject: call reads an uninitialized arg after a clobber" {
    const prog = [_]i.Insn{
        i.call(1), // first call clobbers r1..r5
        i.call(1), // second call: r1 now uninit → arg check fires
        i.exit(),
    };
    try expectError(error.UninitReg, ok(&prog));
}

test "reject: bpf-to-bpf call flavor (src != 0)" {
    var c = i.call(1);
    c.regs = (1 << 4); // src = 1 (pseudo-call), dst = 0
    const prog = [_]i.Insn{ c, i.exit() };
    try expectError(error.BadCall, ok(&prog));
}

test "reject: register field names r12" {
    var bad = i.mov64Imm(0, 0);
    bad.regs = 12; // dst = 12
    const prog = [_]i.Insn{ bad, i.exit() };
    try expectError(error.BadRegister, ok(&prog));
}

test "reject: atomic store (unsupported mode)" {
    var atomic = i.stx(.dw, 2, 0, 0);
    atomic.opcode = i.MODE_ATOMIC | 0x18 | i.CLASS_STX;
    const prog = [_]i.Insn{ atomic, i.exit() };
    try expectError(error.UnknownOpcode, ok(&prog));
}

test "reject: malformed LD_IMM64 (missing second slot)" {
    const li = i.ldImm64(0, 0x1234);
    const prog = [_]i.Insn{li[0]}; // high slot truncated away
    try expectError(error.BadImm64, ok(&prog));
}

test "reject: program longer than MAX_INSNS" {
    var big: [i.MAX_INSNS + 1]i.Insn = undefined;
    for (&big) |*slot| slot.* = i.mov64Imm(0, 0);
    big[big.len - 1] = i.exit();
    try expectError(error.ProgramTooLong, ok(&big));
}
