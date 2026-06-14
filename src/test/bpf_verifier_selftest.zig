// zBPF verifier self-test — boot_mode = 15 entry.
//
// The in-kernel mirror of tools/bpf-test/verify_test.zig. The off-target harness
// proves the verifier's LOGIC under `zig test` on the host; this proves the SAME
// code, compiled FREESTANDING into the kernel, accepts and rejects identically —
// the kernel target has no std.testing, different codegen, and the verifier's
// module-static analysis scratch lives in real kernel BSS. A clean boot never
// loads an untrusted program, so without this there'd be no in-kernel evidence
// the pass works — same rationale as the WITNESS and page-cache self-tests.
//
// Run with boot_mode = 15. PASS criterion:
//   [zbpf-vrf] PASS — all N checks green ...
// in serial.log, then the box idles so the log can be read at leisure.

const serial = @import("../debug/serial.zig");
const insn = @import("../bpf/insn.zig");
const verifier = @import("../bpf/verifier.zig");

// Same contract as the syscall-entry hook: a 16-byte read-only ctx and one
// helper, count(pid), that reads a single argument.
const HELPERS = [_]?verifier.HelperSig{ null, .{ .n_args = 1 } };
const CFG = verifier.Config{ .ctx_len = 16, .ctx_writable = false, .helpers = &HELPERS };

var pass_count: u32 = 0;
var fail_count: u32 = 0;

fn accept(prog: []const insn.Insn, name: []const u8) void {
    if (verifier.verify(prog, CFG)) |_| {
        pass_count += 1;
    } else |e| {
        serial.print("[zbpf-vrf] FAIL: {s} — expected accept, got {s}\n", .{ name, @errorName(e) });
        fail_count += 1;
    }
}

fn reject(prog: []const insn.Insn, want: verifier.VerifyError, name: []const u8) void {
    if (verifier.verify(prog, CFG)) |_| {
        serial.print("[zbpf-vrf] FAIL: {s} — expected {s}, but accepted\n", .{ name, @errorName(want) });
        fail_count += 1;
    } else |got| {
        if (got == want) {
            pass_count += 1;
        } else {
            serial.print("[zbpf-vrf] FAIL: {s} — expected {s}, got {s}\n", .{ name, @errorName(want), @errorName(got) });
            fail_count += 1;
        }
    }
}

pub fn taskEntry() callconv(.c) noreturn {
    serial.print("\n[zbpf-vrf] === verifier self-test start ===\n", .{});

    // --- ACCEPT ---
    {
        const p = [_]insn.Insn{
            insn.ldx(.dw, 2, 1, 0), // r2 = ctx->nr
            insn.ldx(.dw, 1, 1, 8), // r1 = ctx->pid
            insn.call(1),
            insn.mov64Imm(0, 0),
            insn.exit(),
        };
        accept(&p, "builtin syscall counter");
    }
    {
        const p = [_]insn.Insn{
            insn.mov64Reg(2, 10), // r2 = frame ptr
            insn.alu64Imm(.add, 2, -8), // r2 = &stack[-8]
            insn.st(.dw, 2, 0, 0), // *(u64*)(r2) = 0
            insn.mov64Imm(0, 0),
            insn.exit(),
        };
        accept(&p, "stack scratch via pointer arithmetic");
    }
    {
        const p = [_]insn.Insn{
            insn.mov64Imm(2, 0),
            insn.jmpImm(.jeq, 2, 0, 1), // diamond: both paths set r0 before the join
            insn.mov64Imm(0, 7),
            insn.mov64Imm(0, 9),
            insn.exit(),
        };
        accept(&p, "forward branch with clean join");
    }
    { // M3b: an AND-masked index gives a bounded stack offset
        const p = [_]insn.Insn{
            insn.ldx(.w, 2, 1, 0), // r2 = ctx word -> [0, 2^32)
            insn.alu64Imm(.@"and", 2, 0x1F), // r2 &= 31 -> [0,31]
            insn.mov64Reg(3, 10), // r3 = frame ptr (off 512)
            insn.alu64Imm(.add, 3, -64), // r3 -> off 448
            insn.alu64Reg(.add, 3, 2), // r3 -> off [448,479]
            insn.ldx(.dw, 4, 3, 0), // +8 <= 512: provably in-stack
            insn.mov64Imm(0, 0),
            insn.exit(),
        };
        accept(&p, "M3b masked index -> bounded stack offset");
    }
    { // M3b: a bounds-checked variable index, admitted via branch narrowing
        const p = [_]insn.Insn{
            insn.ldx(.w, 2, 1, 0), // r2 = ctx word -> [0, 2^32)
            insn.jmpImm(.jgt, 2, 7, 3), // if r2 > 7 -> skip the access
            insn.mov64Reg(3, 1), // r3 = ctx ptr (off 0)
            insn.alu64Reg(.add, 3, 2), // fall-through: r2 in [0,7] -> off [0,7]
            insn.ldx(.b, 4, 3, 0), // +1 <= 16: provably in-ctx
            insn.mov64Imm(0, 0),
            insn.exit(),
        };
        accept(&p, "M3b bounds-checked ctx index via narrowing");
    }

    // --- REJECT (one per representative class) ---
    {
        const p = [_]insn.Insn{ insn.mov64Imm(0, 0), insn.alu64Reg(.add, 0, 3), insn.exit() };
        reject(&p, error.UninitReg, "read of uninitialized register");
    }
    {
        const p = [_]insn.Insn{ insn.mov64Imm(10, 0), insn.exit() };
        reject(&p, error.WriteToR10, "write to frame pointer r10");
    }
    {
        const p = [_]insn.Insn{ insn.mov64Imm(0, 0), insn.alu64Imm(.add, 0, 1), insn.ja(-2), insn.exit() };
        reject(&p, error.BackEdge, "backward jump (loop)");
    }
    {
        const p = [_]insn.Insn{ insn.st(.dw, 10, 0, 0), insn.exit() };
        reject(&p, error.OutOfBoundsAccess, "stack access past top");
    }
    {
        const p = [_]insn.Insn{ insn.ldx(.dw, 0, 1, 16), insn.exit() };
        reject(&p, error.OutOfBoundsAccess, "ctx load past end");
    }
    {
        const p = [_]insn.Insn{ insn.st(.dw, 1, 0, 42), insn.exit() };
        reject(&p, error.WriteToReadonly, "store into read-only ctx");
    }
    {
        const p = [_]insn.Insn{ insn.mov64Imm(2, 12345), insn.ldx(.dw, 0, 2, 0), insn.exit() };
        reject(&p, error.NotAPointer, "dereference a scalar");
    }
    {
        const p = [_]insn.Insn{ insn.call(5), insn.exit() };
        reject(&p, error.UnknownHelper, "call to unregistered helper");
    }
    {
        var atomic = insn.stx(.dw, 2, 0, 0);
        atomic.opcode = insn.MODE_ATOMIC | 0x18 | insn.CLASS_STX;
        const p = [_]insn.Insn{ atomic, insn.exit() };
        reject(&p, error.UnknownOpcode, "atomic store (unsupported)");
    }

    if (fail_count == 0) {
        serial.print("[zbpf-vrf] PASS — all {d} checks green (accept builtin/ptr-arith/join/M3b-mask/M3b-narrow; reject uninit/r10/loop/OOB-stack/OOB-ctx/RO/scalar/helper/atomic)\n", .{pass_count});
    } else {
        serial.print("[zbpf-vrf] FAIL — {d} of {d} checks failed (see [zbpf-vrf] FAIL lines above)\n", .{ fail_count, pass_count + fail_count });
    }
    serial.print("[zbpf-vrf] === end; idling ===\n", .{});
    idle();
}

fn idle() noreturn {
    while (true) asm volatile ("hlt");
}
