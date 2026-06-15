//! bpf/jit — an x86-64 JIT for VERIFIED eBPF programs.
//!
//! The interpreter (vm.zig) is the semantic contract; this module emits native
//! x86-64 that produces a byte-identical result (the value left in r0 at EXIT,
//! plus the same memory side effects) for every program the verifier accepts.
//! It is the natural level-up from a bytecode VM: no per-instruction decode or
//! dispatch, registers live in hardware registers, branches are native jumps.
//!
//! SAFETY MODEL. compile() runs AFTER verifier.verify(). The verifier proves
//! every memory access in range, every jump in range, and termination, so the
//! emitted code can use raw loads/stores and native jumps. (A future hardening
//! pass can re-add inline bounds checks for defence-in-depth, mirroring vm.zig's
//! checkMem; the interpreter keeps its runtime checks regardless.) Until then
//! the JIT must ONLY ever be handed verified programs — same rule the run-once
//! sys_bpf path already enforces.
//!
//! COVERAGE. Emits nearly the whole ISA: ALU64/ALU32 (add/sub/mul/div/mod/and/
//! or/xor/lsh/rsh/arsh/neg/mov — incl. signed div/mod, MOVSX, and endian/bswap),
//! LD_IMM64, LDX/ST/STX (b/h/w/dw) including MODE_MEMSX sign-extending loads,
//! every CLASS_JMP + CLASS_JMP32 branch (the 32-bit-compare forms and the JMP32
//! long JA included) plus JA + EXIT, the helper CALL (an aligned native call
//! into the embedder's helper table), and the common atomics (lock add/or/and/
//! xor, fetch-add via xadd, xchg, cmpxchg). The only forms still handed back as
//! error.Unsupported — for the caller to run on the interpreter — are the
//! fetch-and-bitwise atomics (OR/AND/XOR with BPF_FETCH, which need a cmpxchg
//! retry loop). Partial coverage + clean fallback is the design: every opcode
//! emitted here is one the differential harness has proven byte-identical to
//! vm.zig.
//!
//! REGISTER ALLOCATION (no spills — 11 eBPF regs fit). The mapping is chosen so
//! it agrees with BOTH calling conventions at once: eBPF callee-saved r6..r9 +
//! the r10 frame pointer land in x86-64 callee-saved registers (survive a future
//! helper CALL for free), and eBPF caller-saved r0..r5 land in x86-64
//! caller-saved registers (clobbered by a CALL exactly as eBPF requires).
//!
//!     eBPF   x86-64        eBPF   x86-64
//!     r0  -> rsi           r6  -> rbx   (callee-saved)
//!     r1  -> rdi           r7  -> r13   (callee-saved)
//!     r2  -> r8            r8  -> r14   (callee-saved)
//!     r3  -> r9            r9  -> r15   (callee-saved)
//!     r4  -> r10           r10 -> r12   (callee-saved, frame ptr, read-only)
//!     r5  -> r11
//!
//! Scratch: rax, rcx (shift count / CL), rdx. rbp + rsp reserved (native stack).
//!
//! ENTRY. The compiled blob is `fn(ctx: u64, stack_base: u64) callconv(.c) u64`
//! (SysV: rdi=ctx, rsi=stack_base, return rax). The prologue saves the x86
//! callee-saved registers, sets r1=ctx, r10=stack_base+512 (frame pointer at
//! stack top, per RFC §4.4), and zeroes the rest — mirroring vm.zig's reset.
//! The CALLER owns the 512-byte stack buffer and MUST zero it before each run
//! (vm.zig @memset's its stack per run); the JIT does not.

const insn = @import("insn.zig");
const Insn = insn.Insn;

pub const JitError = error{
    /// An opcode/form v1 doesn't emit yet — caller should run the interpreter.
    Unsupported,
    /// Output code buffer too small.
    Overflow,
    /// Empty / over-long program (mirrors vm.Error.BadProgram).
    BadProgram,
    /// Malformed LD_IMM64 (second slot missing or non-zero opcode).
    BadImm64,
};

/// Signature of a compiled program. Matches Vm.run semantics.
pub const CompiledFn = *const fn (ctx: u64, stack_base: u64) callconv(.c) u64;

// === x86-64 register numbers ===
const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const RSP: u8 = 4;
const RBP: u8 = 5;
const RSI: u8 = 6;
const RDI: u8 = 7;
const R12: u8 = 12;
const R13: u8 = 13;
const R14: u8 = 14;
const R15: u8 = 15;

/// eBPF register -> x86-64 register number. Indexed by `i.dst()`/`i.src()`,
/// which are u4 (0..15), but this table has only 11 entries — so the index is
/// in-bounds ONLY because the verifier rejects any program referencing r11..r15
/// (verifier.zig's BadRegister gate). compile() runs strictly post-verify and
/// must never be handed an unverified program: a dst/src > 10 indexes past REG[].
const REG = [insn.NUM_REGS]u8{
    RSI, // r0
    RDI, // r1
    8, // r2 -> r8
    9, // r3 -> r9
    10, // r4 -> r10
    11, // r5 -> r11
    RBX, // r6
    R13, // r7
    R14, // r8
    R15, // r9
    R12, // r10 (frame pointer)
};

/// x86 callee-saved registers we clobber and must save/restore, in push order.
const SAVED = [_]u8{ RBX, RBP, R12, R13, R14, R15 };

const STACK_TOP_OFFSET: i32 = @intCast(insn.STACK_SIZE);

// === module-static codegen scratch (NOT REENTRANT — caller serializes) ===
// Lives in BSS, not on the (lean) kernel stack: a [MAX_INSNS] map of u32 is 16 KB
// and the fixup table another 32 KB. The kernel already holds verify_lock across
// verify+run, which is the serialization this shares; the off-target harness is
// single-threaded.
var s_insn_off: [insn.MAX_INSNS + 1]u32 = undefined;

const Fixup = struct {
    /// Byte offset of the rel32 field to patch within the output buffer.
    at: u32,
    /// Target eBPF instruction index.
    target_pc: u32,
};
var s_fixups: [insn.MAX_INSNS]Fixup = undefined;
var s_nfix: usize = 0;

// === the byte emitter ===

const Emit = struct {
    buf: []u8,
    len: usize = 0,
    err: ?JitError = null,

    fn byte(self: *Emit, b: u8) void {
        if (self.err != null) return;
        if (self.len >= self.buf.len) {
            self.err = error.Overflow;
            return;
        }
        self.buf[self.len] = b;
        self.len += 1;
    }

    fn i16le(self: *Emit, v: i16) void {
        const u: u16 = @bitCast(v);
        self.byte(@truncate(u));
        self.byte(@truncate(u >> 8));
    }
    fn i32le(self: *Emit, v: i32) void {
        const u: u32 = @bitCast(v);
        self.byte(@truncate(u));
        self.byte(@truncate(u >> 8));
        self.byte(@truncate(u >> 16));
        self.byte(@truncate(u >> 24));
    }
    fn u64le(self: *Emit, v: u64) void {
        var k: u6 = 0;
        while (k < 8) : (k += 1) self.byte(@truncate(v >> (@as(u6, k) * 8)));
    }

    /// Patch a previously-emitted rel32 at absolute offset `at`.
    fn patch32(self: *Emit, at: usize, v: i32) void {
        const u: u32 = @bitCast(v);
        self.buf[at + 0] = @truncate(u);
        self.buf[at + 1] = @truncate(u >> 8);
        self.buf[at + 2] = @truncate(u >> 16);
        self.buf[at + 3] = @truncate(u >> 24);
    }

    fn boolBit(b: bool, shift: u3) u8 {
        return (@as(u8, @intFromBool(b))) << shift;
    }

    /// REX prefix, emitted only when required (W set, or any extended reg, or
    /// `force` for byte-register access to spl/bpl/sil/dil).
    fn rex(self: *Emit, w: bool, reg: u8, rm: u8, force: bool) void {
        const r = reg >= 8;
        const b = rm >= 8;
        if (w or r or b or force)
            self.byte(0x40 | boolBit(w, 3) | boolBit(r, 2) | boolBit(b, 0));
    }

    fn modrmReg(self: *Emit, reg: u8, rm: u8) void {
        self.byte(0xC0 | ((reg & 7) << 3) | (rm & 7));
    }

    // --- register/register ALU: `op` is the r/m,r form (reg=src, rm=dst) ---
    fn rr(self: *Emit, w: bool, op: u8, reg: u8, rm: u8) void {
        self.rex(w, reg, rm, false);
        self.byte(op);
        self.modrmReg(reg, rm);
    }

    // --- two-byte 0F register/register (reg=dst for imul/movzx) ---
    fn rr0f(self: *Emit, w: bool, op2: u8, reg: u8, rm: u8) void {
        self.rex(w, reg, rm, false);
        self.byte(0x0F);
        self.byte(op2);
        self.modrmReg(reg, rm);
    }

    // --- register/imm32 with a /digit opcode extension in the reg field ---
    fn ri(self: *Emit, w: bool, op: u8, digit: u8, rm: u8, imm: i32) void {
        self.rex(w, 0, rm, false);
        self.byte(op);
        self.modrmReg(digit, rm);
        self.i32le(imm);
    }

    // --- unary /digit op (neg, shift-by-CL) on a register, no immediate ---
    fn unary(self: *Emit, w: bool, op: u8, digit: u8, rm: u8) void {
        self.rex(w, 0, rm, false);
        self.byte(op);
        self.modrmReg(digit, rm);
    }

    // --- shift by imm8 (C1 /digit ib) ---
    fn shiftImm(self: *Emit, w: bool, digit: u8, rm: u8, count: u8) void {
        self.rex(w, 0, rm, false);
        self.byte(0xC1);
        self.modrmReg(digit, rm);
        self.byte(count);
    }

    // --- mov r, imm64 (REX.W B8+rd io) ---
    fn movImm64(self: *Emit, rm: u8, imm: u64) void {
        self.rex(true, 0, rm, false);
        self.byte(0xB8 + (rm & 7));
        self.u64le(imm);
    }

    // --- mov r32, imm32 (B8+rd id, zero-extends to 64) ---
    fn movImm32(self: *Emit, rm: u8, imm: i32) void {
        self.rex(false, 0, rm, false);
        self.byte(0xB8 + (rm & 7));
        self.i32le(imm);
    }

    fn pushR(self: *Emit, r: u8) void {
        if (r >= 8) self.byte(0x41);
        self.byte(0x50 + (r & 7));
    }
    fn popR(self: *Emit, r: u8) void {
        if (r >= 8) self.byte(0x41);
        self.byte(0x58 + (r & 7));
    }

    /// Emit a [base + disp32] memory operand: optional legacy/`0x66` prefix is
    /// the caller's job, this does REX + opcode(s) + ModRM(+SIB) + disp32.
    /// `regf` is the reg field (a register number, or a /digit extension).
    fn mem(self: *Emit, w: bool, force_rex: bool, ops: []const u8, regf: u8, base: u8, disp: i32) void {
        self.rex(w, regf, base, force_rex);
        for (ops) |o| self.byte(o);
        const rm = base & 7;
        // mod = 10 (disp32). rm = base low 3 bits; rm==4 (rsp/r12) needs a SIB.
        self.byte((0b10 << 6) | ((regf & 7) << 3) | rm);
        if (rm == 4) self.byte(0x24); // SIB: scale=1 index=none base=rm
        self.i32le(disp);
    }

    // --- bswap r (0F C8+rd); REX.W for the 64-bit form ---
    fn bswap(self: *Emit, w: bool, r: u8) void {
        self.rex(w, 0, r, false);
        self.byte(0x0F);
        self.byte(0xC8 + (r & 7));
    }

    // --- LOCAL forward branches (within one instruction's lowering, e.g. the
    // div-by-zero guard). Emit a Jcc/jmp with a rel32 placeholder and return the
    // byte offset of that rel32; bindFwd() later patches it to the current pos.
    // (Inter-instruction branches use the s_fixups table + recordFixup instead.)
    fn jccFwd(self: *Emit, cc: u8) usize {
        self.byte(0x0F);
        self.byte(0x80 + cc);
        const at = self.len;
        self.i32le(0);
        return at;
    }
    fn jmpFwd(self: *Emit) usize {
        self.byte(0xE9);
        const at = self.len;
        self.i32le(0);
        return at;
    }
    fn bindFwd(self: *Emit, at: usize) void {
        if (self.err != null) return; // overflow truncated the body; `at` is stale
        if (at + 4 > self.len) return;
        const rel: i64 = @as(i64, @intCast(self.len)) - @as(i64, @intCast(at)) - 4;
        self.patch32(at, @intCast(rel));
    }
};

// === ALU opcode tables (eBPF AluCode -> x86 encodings) ===
// reg form: `dst OP= src` is the x86 r/m,r opcode (reg field = src, rm = dst).
// imm form: 0x81 /digit id (reg field = digit).
fn aluRegOpcode(code: u8) ?u8 {
    return switch (code) {
        @intFromEnum(insn.AluCode.add) => 0x01,
        @intFromEnum(insn.AluCode.sub) => 0x29,
        @intFromEnum(insn.AluCode.@"and") => 0x21,
        @intFromEnum(insn.AluCode.@"or") => 0x09,
        @intFromEnum(insn.AluCode.xor) => 0x31,
        else => null,
    };
}
fn aluImmDigit(code: u8) ?u8 {
    return switch (code) {
        @intFromEnum(insn.AluCode.add) => 0,
        @intFromEnum(insn.AluCode.@"or") => 1,
        @intFromEnum(insn.AluCode.@"and") => 4,
        @intFromEnum(insn.AluCode.sub) => 5,
        @intFromEnum(insn.AluCode.xor) => 6,
        else => null,
    };
}

/// x86 condition code (low nibble of the 0F 8x Jcc) for an eBPF JmpCode.
fn condCode(op: u8) ?u8 {
    return switch (op) {
        @intFromEnum(insn.JmpCode.jeq) => 0x4, // E
        @intFromEnum(insn.JmpCode.jne) => 0x5, // NE
        @intFromEnum(insn.JmpCode.jgt) => 0x7, // A  (unsigned >)
        @intFromEnum(insn.JmpCode.jge) => 0x3, // AE (unsigned >=)
        @intFromEnum(insn.JmpCode.jlt) => 0x2, // B  (unsigned <)
        @intFromEnum(insn.JmpCode.jle) => 0x6, // BE (unsigned <=)
        @intFromEnum(insn.JmpCode.jset) => 0x5, // NE after TEST
        @intFromEnum(insn.JmpCode.jsgt) => 0xF, // G  (signed >)
        @intFromEnum(insn.JmpCode.jsge) => 0xD, // GE (signed >=)
        @intFromEnum(insn.JmpCode.jslt) => 0xC, // L  (signed <)
        @intFromEnum(insn.JmpCode.jsle) => 0xE, // LE (signed <=)
        else => null,
    };
}

// === the compiler ===

/// Compile `prog` into x86-64 machine code in `out`. Returns the code length.
/// `out.ptr` is then callable as a CompiledFn once made executable. NOT
/// reentrant (module-static scratch); callers serialize (the verify_lock the
/// run path already holds). MUST be called only on verifier-accepted programs.
///
/// `helpers` is the embedder's helper table (indexed by the CALL immediate, null
/// slots unregistered) — the SAME table the interpreter runs under. A CALL is
/// lowered to a native call of helpers[id]; an empty table means any CALL falls
/// back (error.Unsupported), exactly as the verifier-rejected case would.
pub fn compile(prog: []const Insn, out: []u8, helpers: []const ?insn.HelperFn) JitError!usize {
    if (prog.len == 0 or prog.len > insn.MAX_INSNS) return error.BadProgram;

    var e = Emit{ .buf = out };
    s_nfix = 0;

    emitPrologue(&e);

    var pc: usize = 0;
    while (pc < prog.len) {
        s_insn_off[pc] = @intCast(e.len);
        const i = prog[pc];
        const class = i.opcode & 0x07;
        switch (class) {
            insn.CLASS_ALU, insn.CLASS_ALU64 => {
                try emitAlu(&e, i, class == insn.CLASS_ALU64);
                pc += 1;
            },
            insn.CLASS_JMP => {
                if (!try emitJmp(&e, i, pc, false, helpers)) return error.Unsupported;
                pc += 1;
            },
            insn.CLASS_JMP32 => {
                if (!try emitJmp(&e, i, pc, true, helpers)) return error.Unsupported;
                pc += 1;
            },
            insn.CLASS_LDX => {
                try emitLoad(&e, i);
                pc += 1;
            },
            insn.CLASS_ST, insn.CLASS_STX => {
                try emitStore(&e, i, class == insn.CLASS_STX);
                pc += 1;
            },
            insn.CLASS_LD => {
                if (i.opcode != insn.OP_LD_IMM64) return error.Unsupported;
                if (pc + 1 >= prog.len) return error.BadImm64;
                const hi = prog[pc + 1];
                if (hi.opcode != 0) return error.BadImm64;
                s_insn_off[pc + 1] = @intCast(e.len);
                const lo_bits: u64 = @as(u32, @bitCast(i.imm));
                const hi_bits: u64 = @as(u32, @bitCast(hi.imm));
                e.movImm64(REG[i.dst()], lo_bits | (hi_bits << 32));
                pc += 2;
            },
            else => return error.Unsupported,
        }
        if (e.err) |err| return err;
    }
    s_insn_off[prog.len] = @intCast(e.len);

    // A verified program never falls off the end without EXIT, but guard it: a
    // ud2 faults loudly instead of executing whatever follows in the buffer.
    e.byte(0x0F);
    e.byte(0x0B);

    // Resolve branch displacements now that every instruction's offset is known.
    var k: usize = 0;
    while (k < s_nfix) : (k += 1) {
        const f = s_fixups[k];
        if (f.target_pc > prog.len) return error.BadProgram;
        const target_off: i64 = s_insn_off[f.target_pc];
        const rel: i64 = target_off - @as(i64, f.at) - 4;
        if (rel < -0x8000_0000 or rel > 0x7FFF_FFFF) return error.Overflow;
        e.patch32(f.at, @intCast(rel));
    }

    if (e.err) |err| return err;
    return e.len;
}

fn emitPrologue(e: *Emit) void {
    // Save x86 callee-saved registers for the Zig caller.
    for (SAVED) |r| e.pushR(r);
    // STACK ALIGNMENT: on entry RSP ≡ 8 (mod 16) — the caller's CALL pushed the
    // return address. SAVED is 6 regs = 48 bytes ≡ 0 (mod 16), so the body runs
    // at RSP ≡ 8 (mod 16). The body itself never touches the native stack, so
    // this invariant holds everywhere — EXCEPT a helper CALL, where SysV demands
    // RSP ≡ 0 at the call site; emitCall brackets the `call` with sub/add rsp,8
    // to realign just there, keeping the rest of the body at the ≡ 8 invariant.
    // r10 (frame pointer) = stack_base (rsi) + 512, BEFORE we clobber rsi (=r0).
    //   lea r12, [rsi + 512]
    e.mem(true, false, &.{0x8D}, R12, RSI, STACK_TOP_OFFSET);
    // r1 (rdi) already holds ctx (SysV arg0). Zero every other eBPF register.
    const zero = [_]u4{ 0, 2, 3, 4, 5, 6, 7, 8, 9 };
    for (zero) |br| {
        const x = REG[br];
        e.rr(false, 0x31, x, x); // xor x32, x32  (clears full 64-bit reg)
    }
}

fn emitEpilogue(e: *Emit) void {
    // r0 -> rax (return value): mov rax, rsi
    e.rr(true, 0x89, REG[0], RAX);
    var idx: usize = SAVED.len;
    while (idx > 0) {
        idx -= 1;
        e.popR(SAVED[idx]);
    }
    e.byte(0xC3); // ret
}

fn emitAlu(e: *Emit, i: Insn, is64: bool) JitError!void {
    const op = i.opcode & 0xF0;
    const use_x = (i.opcode & insn.SRC_X) != 0;
    const d = REG[i.dst()];

    switch (op) {
        @intFromEnum(insn.AluCode.add),
        @intFromEnum(insn.AluCode.sub),
        @intFromEnum(insn.AluCode.@"and"),
        @intFromEnum(insn.AluCode.@"or"),
        @intFromEnum(insn.AluCode.xor),
        => {
            if (use_x) {
                e.rr(is64, aluRegOpcode(op).?, REG[i.src()], d);
            } else {
                e.ri(is64, 0x81, aluImmDigit(op).?, d, i.imm);
            }
        },
        @intFromEnum(insn.AluCode.mul) => {
            if (use_x) {
                e.rr0f(is64, 0xAF, d, REG[i.src()]); // imul d, src
            } else {
                // imul d, d, imm32  (0x69 /r id) — low bits match unsigned mul.
                e.rex(is64, d, d, false);
                e.byte(0x69);
                e.modrmReg(d, d);
                e.i32le(i.imm);
            }
        },
        @intFromEnum(insn.AluCode.lsh),
        @intFromEnum(insn.AluCode.rsh),
        @intFromEnum(insn.AluCode.arsh),
        => {
            const digit: u8 = switch (op) {
                @intFromEnum(insn.AluCode.lsh) => 4, // shl
                @intFromEnum(insn.AluCode.rsh) => 5, // shr
                else => 7, // sar (arsh)
            };
            if (use_x) {
                e.rr(true, 0x89, REG[i.src()], RCX); // mov rcx, src (only CL used)
                e.unary(is64, 0xD3, digit, d); // shl/shr/sar d, cl
            } else {
                // x86 masks the count to the operand width, same as eBPF's &63/&31.
                e.shiftImm(is64, digit, d, @truncate(@as(u32, @bitCast(i.imm))));
            }
        },
        @intFromEnum(insn.AluCode.neg) => {
            e.unary(is64, 0xF7, 3, d); // neg d
        },
        @intFromEnum(insn.AluCode.mov) => {
            if (i.offset == 0) {
                if (use_x) {
                    e.rr(is64, 0x89, REG[i.src()], d); // mov d, src
                } else if (is64) {
                    e.ri(true, 0xC7, 0, d, i.imm); // mov d, imm32 (sign-extended)
                } else {
                    e.movImm32(d, i.imm); // mov d32, imm32 (zero-extended)
                }
            } else {
                try emitMovsx(e, i, is64); // MOVSX (v4): sign-extend 8/16/32-bit src
            }
        },
        @intFromEnum(insn.AluCode.div),
        @intFromEnum(insn.AluCode.mod),
        => emitDivMod(e, i, is64, op == @intFromEnum(insn.AluCode.mod)),
        @intFromEnum(insn.AluCode.end) => emitEndian(e, i, is64),
        else => return error.Unsupported,
    }
}

fn emitMovsx(e: *Emit, i: Insn, is64: bool) JitError!void {
    const width = i.offset; // 8 | 16 | 32
    if (width != 8 and width != 16 and width != 32) return error.Unsupported;
    const d = REG[i.dst()];
    const use_x = (i.opcode & insn.SRC_X) != 0;

    if (!use_x) {
        // Non-standard imm MOVSX (the verifier permits offset 8/16/32 on a mov
        // regardless of source): the result is a compile-time constant.
        var src_val: u64 = @bitCast(@as(i64, i.imm));
        if (!is64) src_val &= 0xFFFF_FFFF;
        var r = signExtendBitsC(src_val, @intCast(width));
        if (!is64) {
            r &= 0xFFFF_FFFF;
            e.movImm32(d, @bitCast(@as(u32, @truncate(r))));
        } else {
            e.movImm64(d, r);
        }
        return;
    }

    const s = REG[i.src()];
    switch (width) {
        8 => {
            // movsx d, src8. An 8-bit source register that is sil/dil (x86 regs
            // 4..7) needs a REX prefix, else the byte operand decodes as ah/…/bh.
            const force = (s >= 4 and s < 8);
            e.rex(is64, d, s, force);
            e.byte(0x0F);
            e.byte(0xBE);
            e.modrmReg(d, s);
        },
        16 => e.rr0f(is64, 0xBF, d, s), // movsx d, src16
        32 => if (is64) {
            e.rex(true, d, s, false);
            e.byte(0x63); // movsxd rdst, src32
            e.modrmReg(d, s);
        } else {
            // 32-bit class: sign-extend-to-32 then mask-to-32 == plain 32-bit copy.
            e.rr(false, 0x89, s, d);
        },
        else => return error.Unsupported,
    }
}

/// div/mod, signed or unsigned, ALU or ALU64. eBPF mandates NO trap on a zero
/// or INT_MIN/-1 divisor (RFC §4.1) — both of which raise #DE on x86 — so those
/// are guarded out before any div/idiv: folded at compile time for an immediate
/// divisor, branched around at run time for a register one.
fn emitDivMod(e: *Emit, i: Insn, is64: bool, is_mod: bool) void {
    const d = REG[i.dst()];
    const signed = (i.offset == 1); // v4 SDIV/SMOD selector
    const use_x = (i.opcode & insn.SRC_X) != 0;

    if (!use_x) {
        const imm = i.imm; // divisor known now — fold the special cases.
        if (imm == 0) {
            if (is_mod) {
                if (!is64) e.rr(false, 0x89, d, d); // mod/0 => dst (32: zero-extend)
                // 64-bit mod/0 leaves dst unchanged: nothing to emit.
            } else {
                e.rr(false, 0x31, d, d); // div/0 => 0
            }
            return;
        }
        if (signed and imm == -1) {
            if (is_mod) {
                e.rr(false, 0x31, d, d); // x smod -1 => 0
            } else {
                e.unary(is64, 0xF7, 3, d); // x sdiv -1 => -x (neg wraps INT_MIN)
                if (!is64) e.rr(false, 0x89, d, d);
            }
            return;
        }
        // General constant (nonzero, and != -1 when signed): load + divide.
        if (is64) {
            e.ri(true, 0xC7, 0, RCX, imm); // mov rcx, imm32 (sign-extended)
        } else {
            e.movImm32(RCX, imm); // mov ecx, imm32 (low 32, zero-extended)
        }
        emitDivCore(e, d, is64, is_mod, signed);
        return;
    }

    // Register divisor: guard zero (and, when signed, -1) at run time.
    const s = REG[i.src()];
    e.rr(true, 0x89, s, RCX); // mov rcx, s

    e.rr(is64, 0x85, RCX, RCX); // test (r/e)cx, (r/e)cx
    const j_nonzero = e.jccFwd(0x5); // jne -> divisor != 0
    if (is_mod) {
        if (!is64) e.rr(false, 0x89, d, d);
    } else {
        e.rr(false, 0x31, d, d);
    }
    const j_done0 = e.jmpFwd();
    e.bindFwd(j_nonzero);

    if (signed) {
        e.ri(is64, 0x81, 7, RCX, -1); // cmp (r/e)cx, -1
        const j_real = e.jccFwd(0x5); // jne -> safe to idiv
        if (is_mod) {
            e.rr(false, 0x31, d, d); // x smod -1 => 0
        } else {
            e.unary(is64, 0xF7, 3, d); // x sdiv -1 => -x
            if (!is64) e.rr(false, 0x89, d, d);
        }
        const j_done1 = e.jmpFwd();
        e.bindFwd(j_real);
        emitDivCore(e, d, is64, is_mod, true);
        e.bindFwd(j_done1);
    } else {
        emitDivCore(e, d, is64, is_mod, false);
    }
    e.bindFwd(j_done0);
}

/// The division itself: divisor already in rcx and proven safe. Dividend = d,
/// result (quotient for div, remainder for mod) -> d.
fn emitDivCore(e: *Emit, d: u8, is64: bool, is_mod: bool, signed: bool) void {
    e.rr(is64, 0x89, d, RAX); // mov (r/e)ax, d  (dividend)
    if (signed) {
        if (is64) e.byte(0x48); // REX.W => cqo (else cdq): sign-extend (r/e)ax into (r/e)dx
        e.byte(0x99);
        e.unary(is64, 0xF7, 7, RCX); // idiv (r/e)cx
    } else {
        e.rr(is64, 0x31, RDX, RDX); // xor (r/e)dx, (r/e)dx
        e.unary(is64, 0xF7, 6, RCX); // div (r/e)cx
    }
    const res = if (is_mod) RDX else RAX;
    e.rr(is64, 0x89, res, d); // mov d, quotient|remainder (32-bit form zero-extends)
}

/// END/BSWAP. On this little-endian host: ALU64 BSWAP always swaps; the ALU
/// to-big form swaps; the ALU to-little form is a truncate+zero-extend. Width
/// 16/32/64; any other width leaves dst unchanged, matching the interpreter.
fn emitEndian(e: *Emit, i: Insn, is64: bool) void {
    const d = REG[i.dst()];
    const to_be = (i.opcode & insn.SRC_X) != 0;
    const do_swap = is64 or to_be;
    switch (i.imm) {
        16 => if (do_swap) {
            e.bswap(false, d); // bswap edst ...
            e.shiftImm(false, 5, d, 16); // ... shr edst,16 => low 16 swapped, zero-extended
        } else {
            e.rr0f(false, 0xB7, d, d); // movzx edst, dx => dst & 0xFFFF
        },
        32 => if (do_swap) {
            e.bswap(false, d); // bswap edst => low 32 swapped, zero-extended
        } else {
            e.rr(false, 0x89, d, d); // mov edst, edst => dst & 0xFFFF_FFFF
        },
        64 => if (do_swap) {
            e.bswap(true, d); // bswap rdst
        } else {
            // to-little of a 64-bit value on an LE host is a no-op.
        },
        else => {}, // malformed width: leave dst unchanged (verifier rejects it)
    }
}

fn signExtendBitsC(val: u64, bits: u32) u64 {
    if (bits >= 64) return val;
    const shift: u6 = @intCast(64 - bits);
    const sv: i64 = @bitCast(val << shift);
    return @bitCast(sv >> shift);
}

fn emitJmp(e: *Emit, i: Insn, pc: usize, is32: bool, helpers: []const ?insn.HelperFn) JitError!bool {
    const op = i.opcode & 0xF0;

    if (op == @intFromEnum(insn.JmpCode.exit)) {
        emitEpilogue(e);
        return true;
    }
    if (op == @intFromEnum(insn.JmpCode.call)) {
        // CALL exists only in CLASS_JMP; a JMP32 "call" is malformed — fall back.
        if (is32) return false;
        return emitCall(e, i, helpers);
    }
    if (op == @intFromEnum(insn.JmpCode.ja)) {
        // CLASS_JMP JA uses the 16-bit offset; the CLASS_JMP32 long JA (v4) takes
        // its 32-bit displacement from imm instead.
        const delta: i64 = if (is32) i.imm else i.offset;
        e.byte(0xE9); // jmp rel32
        recordFixup(e, jumpTarget(pc, delta));
        e.i32le(0);
        return true;
    }

    // Conditional: compute flags at the comparison width (JMP=64, JMP32=32 — a
    // 32-bit cmp/test reads only the low dwords, exactly eBPF's is32 masking),
    // then Jcc to the taken target. The taken displacement is the 16-bit offset
    // for BOTH classes; only the long JA above differs.
    const w = !is32;
    const use_x = (i.opcode & insn.SRC_X) != 0;
    const d = REG[i.dst()];
    if (op == @intFromEnum(insn.JmpCode.jset)) {
        if (use_x) {
            e.rr(w, 0x85, REG[i.src()], d); // test d, src
        } else {
            e.ri(w, 0xF7, 0, d, i.imm); // test d, imm32
        }
    } else {
        if (use_x) {
            e.rr(w, 0x39, REG[i.src()], d); // cmp d, src
        } else {
            e.ri(w, 0x81, 7, d, i.imm); // cmp d, imm32 (sign-extended)
        }
    }
    const cc = condCode(op) orelse return false;
    e.byte(0x0F);
    e.byte(0x80 + cc); // Jcc rel32
    recordFixup(e, jumpTarget(pc, i.offset));
    e.i32le(0);
    return true;
}

/// Helper CALL: native call of helpers[imm]. eBPF arg regs r1..r5 are shuffled
/// into the SysV integer arg regs, the stack is realigned to 16 for the call,
/// and r0 takes the return value — matching vm.zig's `h(r1,r2,r3,r4,r5)` exactly.
/// Returns false (→ fall back to the interpreter) for any form not lowered:
/// src!=0 (bpf-to-bpf / runtime-fn) or an unregistered id. Those are also what
/// the verifier rejects, so this never fires for a verified program; it is the
/// JIT's own belt-and-suspenders, since compile() trusts but never re-verifies.
fn emitCall(e: *Emit, i: Insn, helpers: []const ?insn.HelperFn) bool {
    if (i.src() != 0) return false; // only helper-by-id is emitted
    const id = i.imm;
    if (id < 0 or @as(usize, @intCast(id)) >= helpers.len) return false;
    const h = helpers[@intCast(id)] orelse return false;
    const addr: u64 = @intFromPtr(h);

    // eBPF -> SysV argument shuffle. r1 already lives in rdi (arg0). r2..r5 live
    // in r8..r11; move them down to rsi/rdx/rcx/r8. ORDER: r2's home (r8) is also
    // arg5's destination, so write rsi (from r8) BEFORE clobbering r8 from r11.
    e.rr(true, 0x89, REG[2], RSI); // mov rsi, r8   (arg2 = r2)
    e.rr(true, 0x89, REG[3], RDX); // mov rdx, r9   (arg3 = r3)
    e.rr(true, 0x89, REG[4], RCX); // mov rcx, r10  (arg4 = r4)
    e.rr(true, 0x89, REG[5], REG[2]); // mov r8, r11   (arg5 = r5) — last

    // Realign to RSP ≡ 0 (mod 16) across the call (the body runs at ≡ 8). eBPF
    // r6..r10 sit in x86 callee-saved registers, so the helper preserves them;
    // r0..r5 (caller-saved) are clobbered, exactly as eBPF mandates after a CALL.
    e.byte(0x48);
    e.byte(0x83);
    e.byte(0xEC);
    e.byte(0x08); // sub rsp, 8
    e.movImm64(RAX, addr); // movabs rax, &helper
    e.byte(0xFF);
    e.byte(0xD0); // call rax
    e.byte(0x48);
    e.byte(0x83);
    e.byte(0xC4);
    e.byte(0x08); // add rsp, 8

    e.rr(true, 0x89, RAX, REG[0]); // mov rsi, rax  (r0 = return value)
    return true;
}

fn emitLoad(e: *Emit, i: Insn) JitError!void {
    const mode = i.opcode & 0xE0;
    const size: insn.Size = @enumFromInt(i.opcode & 0x18);
    const dst = REG[i.dst()];
    const base = REG[i.src()];
    const disp: i32 = i.offset;
    if (mode == insn.MODE_MEM) {
        switch (size) {
            .dw => e.mem(true, false, &.{0x8B}, dst, base, disp), // mov dst, [base+disp]
            .w => e.mem(false, false, &.{0x8B}, dst, base, disp), // mov dst32 (zero-ext)
            .h => e.mem(false, false, &.{ 0x0F, 0xB7 }, dst, base, disp), // movzx dst, m16
            .b => e.mem(false, false, &.{ 0x0F, 0xB6 }, dst, base, disp), // movzx dst, m8
        }
    } else if (mode == insn.MODE_MEMSX) {
        // Sign-extending load (v4): always widens into the full 64-bit dst.
        switch (size) {
            .b => e.mem(true, false, &.{ 0x0F, 0xBE }, dst, base, disp), // movsx rdst, m8
            .h => e.mem(true, false, &.{ 0x0F, 0xBF }, dst, base, disp), // movsx rdst, m16
            .w => e.mem(true, false, &.{0x63}, dst, base, disp), // movsxd rdst, m32
            .dw => e.mem(true, false, &.{0x8B}, dst, base, disp), // 64-bit sx == plain load
        }
    } else return error.Unsupported; // atomics / legacy ABS/IND modes
}

fn emitStore(e: *Emit, i: Insn, from_reg: bool) JitError!void {
    const mode = i.opcode & 0xE0;
    if (mode == insn.MODE_ATOMIC) {
        if (!from_reg) return error.Unsupported; // atomics are STX only
        return emitAtomic(e, i);
    }
    if (mode != insn.MODE_MEM) return error.Unsupported;
    const size: insn.Size = @enumFromInt(i.opcode & 0x18);
    const base = REG[i.dst()];
    const disp: i32 = i.offset;

    if (from_reg) {
        const src = REG[i.src()];
        switch (size) {
            .dw => e.mem(true, false, &.{0x89}, src, base, disp), // mov [b+d], src
            .w => e.mem(false, false, &.{0x89}, src, base, disp),
            .h => {
                e.byte(0x66); // 16-bit operand-size prefix (before REX)
                e.mem(false, false, &.{0x89}, src, base, disp);
            },
            .b => e.mem(false, true, &.{0x88}, src, base, disp), // force REX (sil/dil)
        }
    } else {
        // ST: *(size*)(dst+off) = imm (sign-extended to the store width).
        const imm = i.imm;
        switch (size) {
            .dw => {
                e.mem(true, false, &.{0xC7}, 0, base, disp); // mov qword [b+d], imm32(sx)
                e.i32le(imm);
            },
            .w => {
                e.mem(false, false, &.{0xC7}, 0, base, disp);
                e.i32le(imm);
            },
            .h => {
                e.byte(0x66);
                e.mem(false, false, &.{0xC7}, 0, base, disp);
                e.i16le(@truncate(imm));
            },
            .b => {
                e.mem(false, false, &.{0xC6}, 0, base, disp);
                e.byte(@truncate(@as(u32, @bitCast(imm))));
            },
        }
    }
}

/// Atomic RMW (STX | MODE_ATOMIC), size W or DW. Each form is the x86 lock op
/// whose value semantics match vm.zig's execAtomic exactly (the sandbox is
/// single-threaded, so the lock is invisible to the program — but free, and it
/// keeps the kernel-side map updates well-defined). The rare fetch-and-bitwise
/// forms (OR/AND/XOR | BPF_FETCH) would need a cmpxchg retry loop; they return
/// error.Unsupported and run on the interpreter instead — clean partial coverage.
fn emitAtomic(e: *Emit, i: Insn) JitError!void {
    const size: insn.Size = @enumFromInt(i.opcode & 0x18);
    if (size != .w and size != .dw) return error.Unsupported;
    const w = (size == .dw); // REX.W for the 64-bit form; 32-bit zero-extends
    const base = REG[i.dst()]; // memory base pointer
    const src = REG[i.src()]; // operand (and, for fetch/xchg, receives the old)
    const disp: i32 = i.offset;

    switch (i.imm) {
        // Non-fetch RMW: lock <op> [base+disp], src
        insn.ATOMIC_ADD => emitLockRM(e, w, 0x01, src, base, disp), // lock add
        insn.ATOMIC_OR => emitLockRM(e, w, 0x09, src, base, disp), // lock or
        insn.ATOMIC_AND => emitLockRM(e, w, 0x21, src, base, disp), // lock and
        insn.ATOMIC_XOR => emitLockRM(e, w, 0x31, src, base, disp), // lock xor

        // ADD|FETCH: lock xadd [mem], src — src receives the pre-add value.
        insn.ATOMIC_ADD | insn.ATOMIC_FETCH => {
            e.byte(0xF0); // lock
            e.mem(w, false, &.{ 0x0F, 0xC1 }, src, base, disp); // xadd r/m, src
        },

        // XCHG: a memory-operand xchg is implicitly locked; src <- old mem.
        insn.ATOMIC_XCHG => e.mem(w, false, &.{0x87}, src, base, disp), // xchg r/m, src

        // CMPXCHG: stage r0 in (e/r)ax, lock cmpxchg, then read the old value —
        // which cmpxchg always leaves in (e/r)ax — back into r0.
        insn.ATOMIC_CMPXCHG => {
            e.rr(w, 0x89, REG[0], RAX); // mov (e)ax, r0
            e.byte(0xF0); // lock
            e.mem(w, false, &.{ 0x0F, 0xB1 }, src, base, disp); // cmpxchg r/m, src
            e.rr(w, 0x89, RAX, REG[0]); // mov r0, (e)ax
        },

        else => return error.Unsupported, // OR/AND/XOR | FETCH: interpreter handles it
    }
}

/// lock <op> [base+disp], src — the shared shape of the non-fetch atomics. The
/// LOCK (0xF0) prefix precedes REX, which e.mem emits next.
fn emitLockRM(e: *Emit, w: bool, op: u8, src: u8, base: u8, disp: i32) void {
    e.byte(0xF0);
    e.mem(w, false, &.{op}, src, base, disp);
}

/// next_pc = (pc + 1) + delta, per RFC (delta relative to the FOLLOWING insn).
/// delta is the 16-bit offset for most branches, or the 32-bit imm for a JMP32
/// long JA — hence i64.
fn jumpTarget(pc: usize, delta: i64) usize {
    const t: i64 = @as(i64, @intCast(pc)) + 1 + delta;
    // Verified programs keep this in range; a negative/oob value is clamped to a
    // sentinel the patch step rejects (BadProgram) rather than indexing OOB.
    if (t < 0) return insn.MAX_INSNS + 1;
    return @intCast(t);
}

fn recordFixup(e: *Emit, target_pc: usize) void {
    if (s_nfix >= s_fixups.len) {
        e.err = error.Overflow;
        return;
    }
    s_fixups[s_nfix] = .{ .at = @intCast(e.len), .target_pc = @intCast(@min(target_pc, insn.MAX_INSNS + 1)) };
    s_nfix += 1;
}
