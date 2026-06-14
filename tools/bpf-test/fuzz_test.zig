// Soundness fuzzer for src/bpf/verifier.zig — the property that justifies the
// whole verifier: EVERY program verify() accepts, the interpreter runs to
// completion WITHOUT a sandbox-violation error (OutOfBounds / BadJump /
// BadHelperId / TimeLimit). We generate hundreds of thousands of random
// (mostly-decodable) programs; each accepted one is run under several ctx
// values and any sandbox fault is a soundness bug, dumped and failed.
//
// It doubles as a robustness check: verify() must never PANIC on any input,
// only accept or return a VerifyError — if it ever crashed on garbage, this
// test would crash with it. Deterministic (fixed seed) so a failure reproduces.

const std = @import("std");
const i = @import("src/bpf/insn.zig");
const vm = @import("src/bpf/vm.zig");
const v = @import("src/bpf/verifier.zig");

// The verifier Config and the interpreter Env MUST describe the same world, or
// the fuzzer would flag phantom violations.
const VHELPERS = [_]?v.HelperSig{ null, .{ .n_args = 1 } };
const CFG = v.Config{ .ctx_len = 16, .ctx_writable = false, .helpers = &VHELPERS };

fn dummyHelper(_: u64, _: u64, _: u64, _: u64, _: u64) u64 {
    return 0;
}
const IHELPERS = [_]?vm.HelperFn{ null, dummyHelper };

const MAXLEN = 64;
const FUEL: u64 = 4096; // a DAG of <=64 insns halts in <=64 steps; TimeLimit ⇒ bug

fn dstReg(r: std.Random) u4 {
    return @intCast(r.intRangeAtMost(u8, 0, 9)); // never r10 — a trivial reject we don't want to dominate
}
fn anyReg(r: std.Random) u4 {
    return @intCast(r.intRangeAtMost(u8, 0, 10));
}
fn aSize(r: std.Random) i.Size {
    return switch (r.intRangeAtMost(u8, 0, 3)) {
        0 => .b,
        1 => .h,
        2 => .w,
        else => .dw,
    };
}
fn aluCode(r: std.Random) i.AluCode {
    return switch (r.intRangeAtMost(u8, 0, 7)) {
        0 => .add,
        1 => .sub,
        2 => .@"and",
        3 => .@"or",
        4 => .xor,
        5 => .mul,
        6 => .lsh,
        else => .rsh,
    };
}
fn jmpCode(r: std.Random) i.JmpCode {
    return switch (r.intRangeAtMost(u8, 0, 7)) {
        0 => .jeq,
        1 => .jne,
        2 => .jgt,
        3 => .jge,
        4 => .jlt,
        5 => .jle,
        6 => .jsgt,
        else => .jslt,
    };
}

/// Generate a random, mostly-decodable program into `buf`; return its length.
/// Biased toward valid forms (forward in-range jumps, a trailing EXIT) so the
/// accept path is actually exercised, but free to produce rejects too.
fn gen(r: std.Random, buf: *[MAXLEN]i.Insn) usize {
    const len = r.intRangeAtMost(usize, 2, MAXLEN);
    var pc: usize = 0;
    while (pc < len) {
        const room = len - pc - 1; // instructions after this one
        const fwd: i16 = if (room == 0) 0 else @intCast(r.intRangeAtMost(usize, 0, room - 1));
        // A jump displacement that is forward ~half the time and BACKWARD the
        // rest (a loop) — this is what exercises the M4 path simulator: most
        // back-edges are infinite (rejected fast as UnboundedLoop / by budget),
        // and any that the verifier ACCEPTS must still run + terminate below.
        const jdisp: i16 = if (pc > 0 and r.boolean())
            @intCast(@as(i64, @intCast(r.intRangeAtMost(usize, 0, pc))) - @as(i64, @intCast(pc)) - 1)
        else
            fwd;
        const small_off: i16 = @intCast(r.intRangeAtMost(i32, -16, 16));
        const small_imm: i32 = r.intRangeAtMost(i32, -64, 64);

        if (pc == len - 1) { // last slot is always EXIT
            buf[pc] = i.exit();
            break;
        }
        switch (r.intRangeAtMost(u8, 0, 13)) {
            0 => buf[pc] = i.mov64Imm(dstReg(r), small_imm),
            1 => buf[pc] = i.mov64Reg(dstReg(r), anyReg(r)),
            2 => buf[pc] = i.alu64Imm(aluCode(r), dstReg(r), small_imm),
            3 => buf[pc] = i.alu64Reg(aluCode(r), dstReg(r), anyReg(r)),
            4 => buf[pc] = i.alu32Imm(aluCode(r), dstReg(r), small_imm),
            5 => buf[pc] = i.ldx(aSize(r), dstReg(r), anyReg(r), small_off),
            6 => buf[pc] = i.st(aSize(r), anyReg(r), small_off, small_imm),
            7 => buf[pc] = i.stx(aSize(r), anyReg(r), anyReg(r), small_off),
            8 => buf[pc] = i.jmpImm(jmpCode(r), dstReg(r), small_imm, jdisp),
            9 => buf[pc] = i.jmpReg(jmpCode(r), anyReg(r), anyReg(r), jdisp),
            10 => buf[pc] = i.ja(jdisp),
            11 => buf[pc] = i.call(r.intRangeAtMost(i32, 0, 2)),
            12 => {
                if (pc + 1 < len - 1) { // LD_IMM64 needs two slots before the EXIT
                    const pair = i.ldImm64(dstReg(r), r.int(u64));
                    buf[pc] = pair[0];
                    buf[pc + 1] = pair[1];
                    pc += 2;
                    continue;
                }
                buf[pc] = i.mov64Imm(dstReg(r), small_imm);
            },
            else => buf[pc] = i.exit(),
        }
        pc += 1;
    }
    return len;
}

test "soundness fuzz: every accepted program runs without a sandbox fault" {
    var prng = std.Random.DefaultPrng.init(0xBADC0FFEE0DDF00D); // fixed seed: reproducible
    const r = prng.random();

    const ITERS = 100_000;
    var accepted: u64 = 0;
    var rejected: u64 = 0;
    var ran: u64 = 0;

    var buf: [MAXLEN]i.Insn = undefined;
    var ctx: [16]u8 align(8) = undefined;

    var it: usize = 0;
    while (it < ITERS) : (it += 1) {
        const len = gen(r, &buf);
        const prog = buf[0..len];

        v.verify(prog, CFG) catch {
            rejected += 1;
            continue;
        };
        accepted += 1;

        const env = vm.Env{
            .regions = &[_]vm.Region{.{ .base = @intFromPtr(&ctx), .len = ctx.len, .writable = false }},
            .helpers = &IHELPERS,
        };
        var trial: usize = 0;
        while (trial < 4) : (trial += 1) {
            r.bytes(ctx[0..]); // the verifier claims safety for ALL inputs
            var machine = vm.Vm{};
            if (machine.runEnv(prog, @intFromPtr(&ctx), FUEL, env)) |_| {
                ran += 1;
            } else |e| switch (e) {
                // The sandbox-violation class the verifier exists to make
                // impossible. Any of these on an accepted program is unsound.
                error.OutOfBounds, error.BadJump, error.BadHelperId, error.TimeLimit => {
                    std.debug.print("\nSOUNDNESS VIOLATION ({s}) on accepted program ({d} insns):\n", .{ @errorName(e), len });
                    dumpProg(prog);
                    return error.Unsound;
                },
                // Non-sandbox outcomes are fine: div-by-zero is defined under
                // runEnv (returns 0), and the structural error classes cannot
                // occur on a program the verifier already accepted.
                else => ran += 1,
            }
        }
    }

    std.debug.print("\n[fuzz] {d} iters: {d} accepted, {d} rejected, {d} interpreter runs — 0 violations\n", .{ ITERS, accepted, rejected, ran });
    try std.testing.expect(accepted > 500); // the corpus must actually exercise the accept path
}

fn dumpProg(prog: []const i.Insn) void {
    for (prog, 0..) |ins, idx| {
        std.debug.print("  [{d:0>3}] op=0x{x:0>2} dst=r{d} src=r{d} off={d} imm={d}\n", .{ idx, ins.opcode, ins.dst(), ins.src(), ins.offset, ins.imm });
    }
}
