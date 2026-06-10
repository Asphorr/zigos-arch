//! bpf/vm — the eBPF interpreter.
//!
//! Executes a verified instruction stream against a per-run context. M1 has no
//! verifier yet, so the interpreter is itself the last line of defence: every
//! operation that could escape the sandbox (memory access, division, jumps,
//! instruction count) is bounds-checked at run time and turns a violation into
//! a clean `error.*` return rather than a wild access. When the verifier lands
//! (M3) it will prove most of these checks redundant ahead of time, but the
//! interpreter keeps them — defence in depth, and the off-target harness leans
//! on them to assert "this malformed program is rejected, not crashing."
//!
//! Memory model (M1): a program sees exactly ONE writable region — its own
//! 512-byte stack, addressed through r10 (the read-only frame pointer, which
//! starts at stack-top). Context pointers and maps arrive in M2; until then
//! r1 is loaded with the caller-supplied `ctx` scalar but there is no region
//! it may dereference, so any load/store outside the stack is EACCES. This is
//! the smallest possible sandbox that still runs real arithmetic/branch logic
//! — and it cannot touch kernel memory by construction.
//!
//! Execution bound: every step decrements a fuel counter (`max_insns`). A
//! program that loops forever halts with error.TimeLimit instead of hanging
//! the caller — the property that lets us run untrusted-ish logic in ring 0
//! later without the wedge class the kernel spends audit rounds preventing.

const std = @import("std");
const insn = @import("insn.zig");
const Insn = insn.Insn;

pub const Error = error{
    /// Ran past max_insns — possible infinite loop.
    TimeLimit,
    /// Memory access outside the program stack (or any non-stack region in M1).
    OutOfBounds,
    /// Divide or modulo by zero (eBPF defines these as producing 0/dst, but we
    /// surface it so the harness can distinguish; runStrict treats it as fatal).
    DivideByZero,
    /// Opcode not implemented / not permitted (legacy packet modes, atomics,
    /// calls before helpers exist).
    UnknownOpcode,
    /// Program counter left the instruction array (bad jump / missing EXIT).
    BadJump,
    /// Malformed LD_IMM64 (second slot missing or wrong).
    BadImm64,
    /// Program is empty or exceeds MAX_INSNS.
    BadProgram,
};

/// Result of a completed run: the value left in r0, plus how much fuel it burned.
pub const RunResult = struct {
    r0: u64,
    steps: u64,
};

pub const Vm = struct {
    regs: [insn.NUM_REGS]u64 = [_]u64{0} ** insn.NUM_REGS,
    stack: [insn.STACK_SIZE]u8 align(8) = undefined,

    /// Execute `prog` with `ctx` placed in r1 (the program's first argument).
    /// `fuel` caps executed instructions. Returns r0 + step count, or an Error.
    ///
    /// eBPF division-by-zero semantics (RFC §4.1): div-by-0 yields 0, mod-by-0
    /// yields the dividend, and execution CONTINUES. We follow the spec here so
    /// real clang output runs unmodified; `runStrict` is the fail-fast variant.
    pub fn run(self: *Vm, prog: []const Insn, ctx: u64, fuel: u64) Error!RunResult {
        return self.runImpl(prog, ctx, fuel, false);
    }

    /// Like `run`, but div/mod by zero is a fatal error.DivideByZero instead of
    /// the spec's continue-with-0. Used by tests that want to assert a program
    /// never divides by zero.
    pub fn runStrict(self: *Vm, prog: []const Insn, ctx: u64, fuel: u64) Error!RunResult {
        return self.runImpl(prog, ctx, fuel, true);
    }

    fn runImpl(self: *Vm, prog: []const Insn, ctx: u64, fuel: u64, strict_div: bool) Error!RunResult {
        if (prog.len == 0 or prog.len > insn.MAX_INSNS) return error.BadProgram;

        // Reset architectural state. r10 = read-only frame pointer at stack top.
        // The stack is zeroed per-run: without a verifier there is no
        // read-before-write proof, so a stale stack would (a) make programs
        // nondeterministic and (b) once this runs in ring 0, leak whatever
        // kernel bytes the previous occupant of this Vm left behind. 512
        // bytes of memset per invocation is noise next to interpretation.
        @memset(&self.regs, 0);
        @memset(&self.stack, 0);
        self.regs[1] = ctx;
        self.regs[10] = @intFromPtr(&self.stack) + insn.STACK_SIZE;

        var pc: usize = 0;
        var steps: u64 = 0;

        while (pc < prog.len) {
            if (steps >= fuel) return error.TimeLimit;
            steps += 1;

            const i = prog[pc];
            const class = i.opcode & 0x07;
            const d = i.dst();

            switch (class) {
                insn.CLASS_ALU, insn.CLASS_ALU64 => {
                    try self.execAlu(i, class == insn.CLASS_ALU64, strict_div);
                    pc += 1;
                },
                insn.CLASS_JMP, insn.CLASS_JMP32 => {
                    const op = i.opcode & 0xf0;
                    if (op == @intFromEnum(insn.JmpCode.exit)) {
                        return .{ .r0 = self.regs[0], .steps = steps };
                    }
                    if (op == @intFromEnum(insn.JmpCode.call)) {
                        // Helpers/sub-calls arrive in M2. For now a call is a
                        // clean rejection, not a crash.
                        return error.UnknownOpcode;
                    }
                    // JA: CLASS_JMP uses the 16-bit offset; CLASS_JMP32 long-JA
                    // (v4) uses the 32-bit imm.
                    if (op == @intFromEnum(insn.JmpCode.ja)) {
                        const delta: i64 = if (class == insn.CLASS_JMP32) i.imm else i.offset;
                        pc = try advance(pc, delta, prog.len);
                        continue;
                    }
                    const taken = self.evalBranch(i, class == insn.CLASS_JMP32);
                    if (taken) {
                        pc = try advance(pc, i.offset, prog.len);
                    } else {
                        pc += 1;
                    }
                },
                insn.CLASS_LDX => {
                    try self.execLoad(i);
                    pc += 1;
                },
                insn.CLASS_ST, insn.CLASS_STX => {
                    try self.execStore(i, class == insn.CLASS_STX);
                    pc += 1;
                },
                insn.CLASS_LD => {
                    // The only LD form we accept is the two-slot LD_IMM64.
                    if (i.opcode != insn.OP_LD_IMM64) return error.UnknownOpcode;
                    if (pc + 1 >= prog.len) return error.BadImm64;
                    const hi = prog[pc + 1];
                    if (hi.opcode != 0) return error.BadImm64;
                    const lo_bits: u64 = @as(u32, @bitCast(i.imm));
                    const hi_bits: u64 = @as(u32, @bitCast(hi.imm));
                    self.regs[d] = lo_bits | (hi_bits << 32);
                    pc += 2; // consumes both slots
                },
                else => return error.UnknownOpcode,
            }
        }
        // Fell off the end without EXIT.
        return error.BadJump;
    }

    // --- ALU (CLASS_ALU = 32-bit, CLASS_ALU64 = 64-bit) ---
    fn execAlu(self: *Vm, i: Insn, is64: bool, strict_div: bool) Error!void {
        const d = i.dst();
        const use_x = (i.opcode & insn.SRC_X) != 0;
        const op = i.opcode & 0xf0;

        // BSWAP/END is special: operand is the dst itself, width in imm.
        if (op == @intFromEnum(insn.AluCode.end)) {
            self.execEndian(i, is64);
            return;
        }

        // Source operand: register (masked to 32 bits in ALU class) or imm.
        var src_val: u64 = if (use_x) self.regs[i.src()] else @as(u64, @bitCast(@as(i64, i.imm)));
        if (!is64) src_val &= 0xFFFF_FFFF;

        var a: u64 = self.regs[d];
        if (!is64) a &= 0xFFFF_FFFF;

        var r: u64 = a;
        switch (op) {
            @intFromEnum(insn.AluCode.add) => r = a +% src_val,
            @intFromEnum(insn.AluCode.sub) => r = a -% src_val,
            @intFromEnum(insn.AluCode.mul) => r = a *% src_val,
            @intFromEnum(insn.AluCode.@"or") => r = a | src_val,
            @intFromEnum(insn.AluCode.@"and") => r = a & src_val,
            @intFromEnum(insn.AluCode.xor) => r = a ^ src_val,
            @intFromEnum(insn.AluCode.lsh) => r = shiftLeft(a, src_val, is64),
            @intFromEnum(insn.AluCode.rsh) => r = shiftRightLogical(a, src_val, is64),
            @intFromEnum(insn.AluCode.arsh) => r = shiftRightArith(a, src_val, is64),
            @intFromEnum(insn.AluCode.neg) => r = (0 -% a),
            @intFromEnum(insn.AluCode.mov) => {
                // MOVSX widths are exactly 8/16/32 (v4). Anything else in the
                // offset field is a malformed instruction — reject it instead
                // of feeding it to an @intCast that would safety-panic, which
                // in ring 0 would turn a bad program into a kernel panic.
                if (i.offset != 0 and i.offset != 8 and i.offset != 16 and i.offset != 32)
                    return error.UnknownOpcode;
                r = movMaybeSx(i, src_val, is64);
            },
            @intFromEnum(insn.AluCode.div) => {
                if (src_val == 0) {
                    if (strict_div) return error.DivideByZero;
                    r = 0; // spec: div by zero => 0
                } else {
                    r = if (i.offset == 1) signedDiv(a, src_val, is64) else divUnsigned(a, src_val, is64);
                }
            },
            @intFromEnum(insn.AluCode.mod) => {
                if (src_val == 0) {
                    if (strict_div) return error.DivideByZero;
                    r = a; // spec: mod by zero => dividend unchanged
                } else {
                    r = if (i.offset == 1) signedMod(a, src_val, is64) else modUnsigned(a, src_val, is64);
                }
            },
            else => return error.UnknownOpcode,
        }

        // 32-bit ALU ops zero-extend the result into the 64-bit register.
        if (!is64) r &= 0xFFFF_FFFF;
        self.regs[d] = r;
    }

    fn execEndian(self: *Vm, i: Insn, is64: bool) void {
        const d = i.dst();
        const width = i.imm;
        const v = self.regs[d];
        // CLASS_ALU: SRC_K = convert to little-endian, SRC_X = to big-endian.
        // CLASS_ALU64: unconditional bswap (v4), regardless of host endianness.
        const to_be = (i.opcode & insn.SRC_X) != 0;
        const host_is_le = @import("builtin").cpu.arch.endian() == .little;

        self.regs[d] = switch (width) {
            16 => blk: {
                const t: u16 = @truncate(v);
                const swapped: u64 = @byteSwap(t);
                const native: u64 = t;
                break :blk pick(is64, to_be, host_is_le, native, swapped);
            },
            32 => blk: {
                const t: u32 = @truncate(v);
                const swapped: u64 = @byteSwap(t);
                const native: u64 = t;
                break :blk pick(is64, to_be, host_is_le, native, swapped);
            },
            64 => blk: {
                const swapped: u64 = @byteSwap(v);
                break :blk pick(is64, to_be, host_is_le, v, swapped);
            },
            else => v, // malformed width: leave unchanged (verifier will reject later)
        };
    }

    // --- memory load: dst = *(size *)(src + off) ---
    fn execLoad(self: *Vm, i: Insn) Error!void {
        const size: insn.Size = @enumFromInt(i.opcode & 0x18);
        const mode = i.opcode & 0xe0;
        if (mode != insn.MODE_MEM and mode != insn.MODE_MEMSX) return error.UnknownOpcode;

        const addr = self.regs[i.src()] +% @as(u64, @bitCast(@as(i64, i.offset)));
        const n = size.bytes();
        const off = try self.checkStack(addr, n);

        var val: u64 = 0;
        var b: u64 = 0;
        while (b < n) : (b += 1) {
            val |= @as(u64, self.stack[off + b]) << @intCast(b * 8);
        }
        if (mode == insn.MODE_MEMSX) val = signExtend(val, n);
        self.regs[i.dst()] = val;
    }

    // --- memory store: *(size *)(dst + off) = (src reg | imm) ---
    fn execStore(self: *Vm, i: Insn, from_reg: bool) Error!void {
        const size: insn.Size = @enumFromInt(i.opcode & 0x18);
        const mode = i.opcode & 0xe0;
        if (mode == insn.MODE_ATOMIC) return error.UnknownOpcode; // M2+
        if (mode != insn.MODE_MEM) return error.UnknownOpcode;

        const addr = self.regs[i.dst()] +% @as(u64, @bitCast(@as(i64, i.offset)));
        const n = size.bytes();
        const off = try self.checkStack(addr, n);

        const val: u64 = if (from_reg) self.regs[i.src()] else @as(u64, @bitCast(@as(i64, i.imm)));
        var b: u64 = 0;
        while (b < n) : (b += 1) {
            self.stack[off + b] = @truncate(val >> @intCast(b * 8));
        }
    }

    /// Map an absolute address to a stack byte-offset, or fail. This is the
    /// single chokepoint that confines all program memory access to the
    /// program's own stack — the M1 sandbox boundary.
    fn checkStack(self: *Vm, addr: u64, n: u64) Error!usize {
        const base = @intFromPtr(&self.stack);
        if (addr < base) return error.OutOfBounds;
        const off = addr - base;
        // off + n must not overflow and must stay within the stack.
        if (off > insn.STACK_SIZE or n > insn.STACK_SIZE - off) return error.OutOfBounds;
        return @intCast(off);
    }

    fn evalBranch(self: *Vm, i: Insn, is32: bool) bool {
        const use_x = (i.opcode & insn.SRC_X) != 0;
        const op = i.opcode & 0xf0;

        var a = self.regs[i.dst()];
        var bv: u64 = if (use_x) self.regs[i.src()] else @as(u64, @bitCast(@as(i64, i.imm)));
        if (is32) {
            a &= 0xFFFF_FFFF;
            bv &= 0xFFFF_FFFF;
        }
        const sa: i64 = if (is32) @as(i32, @bitCast(@as(u32, @truncate(a)))) else @bitCast(a);
        const sb: i64 = if (is32) @as(i32, @bitCast(@as(u32, @truncate(bv)))) else @bitCast(bv);

        return switch (op) {
            @intFromEnum(insn.JmpCode.jeq) => a == bv,
            @intFromEnum(insn.JmpCode.jne) => a != bv,
            @intFromEnum(insn.JmpCode.jgt) => a > bv,
            @intFromEnum(insn.JmpCode.jge) => a >= bv,
            @intFromEnum(insn.JmpCode.jlt) => a < bv,
            @intFromEnum(insn.JmpCode.jle) => a <= bv,
            @intFromEnum(insn.JmpCode.jset) => (a & bv) != 0,
            @intFromEnum(insn.JmpCode.jsgt) => sa > sb,
            @intFromEnum(insn.JmpCode.jsge) => sa >= sb,
            @intFromEnum(insn.JmpCode.jslt) => sa < sb,
            @intFromEnum(insn.JmpCode.jsle) => sa <= sb,
            else => false,
        };
    }
};

// === pure helpers ===

fn pick(is64: bool, to_be: bool, host_is_le: bool, native: u64, swapped: u64) u64 {
    if (is64) return swapped; // ALU64 bswap is unconditional
    // to_be => result big-endian; to_le => result little-endian.
    const want_le = !to_be;
    if (want_le == host_is_le) return native;
    return swapped;
}

fn advance(pc: usize, delta: i64, len: usize) Error!usize {
    // Next pc = (pc + 1) + delta, per RFC: offset is relative to the FOLLOWING
    // instruction. Range-check against [0, len).
    const next = @as(i64, @intCast(pc)) + 1 + delta;
    if (next < 0 or next >= @as(i64, @intCast(len))) return error.BadJump;
    return @intCast(next);
}

fn shiftLeft(a: u64, sh: u64, is64: bool) u64 {
    const mask: u64 = if (is64) 63 else 31;
    return a << @intCast(sh & mask);
}
fn shiftRightLogical(a: u64, sh: u64, is64: bool) u64 {
    const mask: u64 = if (is64) 63 else 31;
    if (is64) return a >> @intCast(sh & mask);
    return (a & 0xFFFF_FFFF) >> @intCast(sh & mask);
}
fn shiftRightArith(a: u64, sh: u64, is64: bool) u64 {
    const mask: u64 = if (is64) 63 else 31;
    if (is64) {
        const sa: i64 = @bitCast(a);
        return @bitCast(sa >> @intCast(sh & mask));
    }
    const sa: i32 = @bitCast(@as(u32, @truncate(a)));
    return @as(u32, @bitCast(sa >> @intCast(sh & mask)));
}

fn divUnsigned(a: u64, b: u64, is64: bool) u64 {
    if (is64) return a / b;
    return (@as(u32, @truncate(a))) / (@as(u32, @truncate(b)));
}
fn modUnsigned(a: u64, b: u64, is64: bool) u64 {
    if (is64) return a % b;
    return (@as(u32, @truncate(a))) % (@as(u32, @truncate(b)));
}
fn signedDiv(a: u64, b: u64, is64: bool) u64 {
    if (is64) {
        const x: i64 = @bitCast(a);
        const y: i64 = @bitCast(b);
        // INT_MIN / -1 overflows; eBPF leaves it as INT_MIN (wrap).
        if (x == std.math.minInt(i64) and y == -1) return a;
        return @bitCast(@divTrunc(x, y));
    }
    const x: i32 = @bitCast(@as(u32, @truncate(a)));
    const y: i32 = @bitCast(@as(u32, @truncate(b)));
    if (x == std.math.minInt(i32) and y == -1) return @as(u32, @truncate(a));
    return @as(u32, @bitCast(@divTrunc(x, y)));
}
fn signedMod(a: u64, b: u64, is64: bool) u64 {
    if (is64) {
        const x: i64 = @bitCast(a);
        const y: i64 = @bitCast(b);
        if (x == std.math.minInt(i64) and y == -1) return 0;
        return @bitCast(@rem(x, y));
    }
    const x: i32 = @bitCast(@as(u32, @truncate(a)));
    const y: i32 = @bitCast(@as(u32, @truncate(b)));
    if (x == std.math.minInt(i32) and y == -1) return 0;
    return @as(u32, @bitCast(@rem(x, y)));
}

fn movMaybeSx(i: Insn, src_val: u64, is64: bool) u64 {
    // MOVSX (v4): offset = source width (8/16/32) => sign-extend that many bits.
    if (i.offset == 0) return src_val;
    const bits: u6 = @intCast(i.offset);
    const r = signExtendBits(src_val, bits);
    return if (is64) r else (r & 0xFFFF_FFFF);
}

fn signExtend(val: u64, n_bytes: u64) u64 {
    return signExtendBits(val, @intCast(n_bytes * 8));
}
fn signExtendBits(val: u64, bits: u6) u64 {
    if (bits >= 64) return val;
    const shift: u6 = @intCast(64 - @as(u32, bits));
    const sv: i64 = @bitCast(val << shift);
    return @bitCast(sv >> shift);
}
