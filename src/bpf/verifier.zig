//! bpf/verifier — zBPF's static safety pass (M3a).
//!
//! Runs BEFORE an untrusted program is accepted, proving ahead of time the
//! properties the interpreter (vm.zig) otherwise has to enforce at run time.
//! The contract is SOUNDNESS: every program verify() accepts, the interpreter
//! runs to completion WITHOUT ever returning a sandbox-violation error
//! (OutOfBounds / BadJump / BadHelperId / TimeLimit). The interpreter keeps its
//! own checks regardless — defence in depth — but a verified program never
//! trips them. The verifier is deliberately a CONSERVATIVE under-approximation:
//! it may reject a safe-but-clever program (those are M3b/M4's job to admit),
//! but it must never accept an unsafe one.
//!
//! ============================== THREE PASSES =================================
//! Pass A1 (linear decode): every opcode is known & permitted, register fields
//!   are in range (r0..r10), LD_IMM64 occupies two well-formed slots, MOVSX /
//!   endian / div-mod-signedness sub-encodings are valid, CALL names a
//!   registered helper. Also builds `g_starts` — which byte offsets are real
//!   instruction starts vs the hidden second slot of an LD_IMM64.
//!
//! Pass A2 (control flow): every jump target lands in-range, ON an instruction
//!   start (never inside an LD_IMM64 pair), and STRICTLY FORWARD. Rejecting all
//!   back-edges makes the CFG a DAG, which (a) proves the program halts without
//!   any loop-bound reasoning — fuel in the interpreter is then pure belt-and-
//!   suspenders — and (b) means every predecessor of an instruction has a lower
//!   index, so Pass B is a single forward sweep with no fixpoint iteration.
//!   Bounded loops need numeric range tracking; they are M4, not here.
//!
//! Pass B (abstract interpretation): a forward sweep over the DAG carrying an
//!   abstract register file. A tiny lattice — uninit / scalar / ctx_ptr(off) /
//!   stack_ptr(off) — is enough to prove: no read of an uninitialized register,
//!   every memory access in-bounds of its region (size-aware), no store into a
//!   read-only region, and every CALL's argument registers initialized. At a
//!   join (two paths into one instruction) the per-register states are merged
//!   conservatively: uninit ⊔ anything = uninit (so a maybe-unset register
//!   poisons any later read), and a pointer that loses its exact offset becomes
//!   un-dereferenceable rather than silently in-bounds.
//!
//! M3a tracks pointer OFFSETS as exact constants (needed to bounds-check), but
//! does NOT track scalar VALUES — so a pointer derived via a runtime-computed
//! offset is conservatively un-dereferenceable until M3b adds value ranges.
//!
//! NOT REENTRANT: the analysis scratch lives in module statics, so the kernel
//! load path must serialize calls behind a load lock (wired in the kernel-
//! integration slice). The off-target harness drives it single-threaded.

const std = @import("std");
const insn = @import("insn.zig");
const Insn = insn.Insn;

pub const VerifyError = error{
    EmptyProgram, // zero instructions
    ProgramTooLong, // exceeds insn.MAX_INSNS
    UnknownOpcode, // opcode / sub-encoding not recognized or not permitted
    BadRegister, // a register field names r11..r15
    WriteToR10, // r10 is the read-only frame pointer
    BadImm64, // malformed LD_IMM64 pair (missing/!=0 second slot)
    JumpOutOfRange, // jump target outside [0, len)
    JumpIntoImm64, // jump target lands on an LD_IMM64's second slot
    BackEdge, // a backward jump (loop) — not permitted in M3a
    NoExit, // a reachable path runs off the end without EXIT
    UninitReg, // reads a register that may be uninitialized
    UnknownHelper, // CALL to an unregistered helper id
    BadCall, // unsupported CALL flavor (bpf-to-bpf, runtime fn)
    NotAPointer, // memory access through a non-pointer / unbounded register
    OutOfBoundsAccess, // static access outside the region bounds
    WriteToReadonly, // store into a read-only region (e.g. ctx)
};

/// What the embedder promises about a helper id: how many of r1..r5 it reads
/// (so the verifier can require those argument registers be initialized).
pub const HelperSig = struct {
    n_args: u8 = 0,
};

/// The program-type contract the verifier checks against — the static mirror
/// of vm.Env. `helpers` is indexed by the CALL immediate; null = unregistered.
pub const Config = struct {
    ctx_len: u32 = 0,
    ctx_writable: bool = false,
    helpers: []const ?HelperSig = &.{},
};

// === abstract register state ===

const Kind = enum(u8) { uninit, scalar, ctx_ptr, stack_ptr };

const RegState = struct {
    kind: Kind = .uninit,
    /// Pointer kinds only: is `off` a compile-time constant? A pointer whose
    /// offset became runtime-dependent is still a pointer, just one we cannot
    /// bounds-check — so any dereference of it is rejected.
    off_known: bool = true,
    /// Pointer kinds only: byte offset from the region base. For stack_ptr the
    /// region base is the LOW end of the 512-byte stack, so r10 (the frame
    /// pointer, which points at the TOP) starts at off = STACK_SIZE and programs
    /// reach into the stack with negative instruction offsets.
    off: i64 = 0,

    fn isPtr(self: RegState) bool {
        return self.kind == .ctx_ptr or self.kind == .stack_ptr;
    }

    fn eql(a: RegState, b: RegState) bool {
        if (a.kind != b.kind) return false;
        if (a.isPtr()) return a.off_known == b.off_known and (!a.off_known or a.off == b.off);
        return true;
    }
};

const RegFile = [insn.NUM_REGS]RegState;

/// Lattice join of two register states. Monotone and bounded-height, so the
/// forward sweep converges trivially (and would even over a cyclic CFG, which
/// is why this same shape is what a future bounded-loop verifier builds on).
fn joinReg(a: RegState, b: RegState) RegState {
    if (a.eql(b)) return a;
    // If either side might be uninitialized, the merge might be — poison it so
    // a later read is rejected. (uninit is the conservative top for liveness.)
    if (a.kind == .uninit or b.kind == .uninit) return .{ .kind = .uninit };
    // Same region, differing offset/knownness → still that pointer, but we no
    // longer know where, so it becomes un-dereferenceable.
    if (a.kind == b.kind and a.isPtr()) return .{ .kind = a.kind, .off_known = false };
    // Differing kinds (ptr vs scalar, ctx vs stack) collapse to scalar. Sound:
    // a scalar can't be dereferenced, which is exactly the uncertainty here.
    return .{ .kind = .scalar };
}

// === analysis scratch (see NOT REENTRANT note in the header) ===

var g_states: [insn.MAX_INSNS]RegFile = undefined;
var g_seen: [insn.MAX_INSNS]bool = undefined;
var g_starts: [insn.MAX_INSNS]bool = undefined;

/// Verify `prog` against the program-type contract `cfg`. Returns cleanly on
/// success, or the first VerifyError found.
pub fn verify(prog: []const Insn, cfg: Config) VerifyError!void {
    const len = prog.len;
    if (len == 0) return error.EmptyProgram;
    if (len > insn.MAX_INSNS) return error.ProgramTooLong;

    // ---- Pass A1: decode + well-formedness, and build the start map. ----
    for (0..len) |k| g_starts[k] = false;
    var pc: usize = 0;
    while (pc < len) {
        g_starts[pc] = true;
        pc += try decodeShape(prog[pc], prog, pc, len, cfg);
    }

    // ---- Pass A2: validate jump targets (in-range, start-aligned, forward). ----
    pc = 0;
    while (pc < len) : (pc += 1) {
        if (g_starts[pc]) try checkJumpTargets(prog[pc], pc, len);
    }

    // ---- Pass B: forward single-sweep abstract interpretation. ----
    for (0..len) |k| g_seen[k] = false;
    var entry: RegFile = undefined;
    for (&entry) |*r| r.* = .{}; // all uninit
    entry[1] = .{ .kind = .ctx_ptr, .off = 0 }; // r1 = ctx pointer at entry
    entry[10] = .{ .kind = .stack_ptr, .off = @intCast(insn.STACK_SIZE) }; // r10 = frame ptr
    g_states[0] = entry;
    g_seen[0] = true;

    pc = 0;
    while (pc < len) : (pc += 1) {
        if (g_seen[pc]) try step(prog, pc, len, cfg);
    }
}

/// Merge `out` into successor `s`'s entry state (first arrival seeds it).
fn pushSucc(s: usize, out: RegFile) void {
    if (!g_seen[s]) {
        g_states[s] = out;
        g_seen[s] = true;
        return;
    }
    for (&g_states[s], out) |*d, o| d.* = joinReg(d.*, o);
}

fn fallthrough(pc: usize, len: usize, out: RegFile) VerifyError!void {
    const nxt = pc + 1;
    if (nxt >= len) return error.NoExit; // ran off the end without EXIT
    pushSucc(nxt, out);
}

fn jumpTarget(pc: usize, delta: i64) usize {
    return @intCast(@as(i64, @intCast(pc)) + 1 + delta);
}

// === Pass B per-instruction transfer ===

fn step(prog: []const Insn, pc: usize, len: usize, cfg: Config) VerifyError!void {
    const i = prog[pc];
    const class = i.opcode & 0x07;
    var out = g_states[pc]; // copy of this instruction's entry state

    switch (class) {
        insn.CLASS_ALU, insn.CLASS_ALU64 => {
            try execAlu(&out, i, class == insn.CLASS_ALU64);
            try fallthrough(pc, len, out);
        },
        insn.CLASS_LD => {
            // LD_IMM64 (shape validated in A1): loads a 64-bit constant scalar
            // and consumes two slots, so the successor is pc+2.
            const d = i.dst();
            if (d == 10) return error.WriteToR10;
            out[d] = .{ .kind = .scalar };
            const nxt = pc + 2;
            if (nxt >= len) return error.NoExit;
            pushSucc(nxt, out);
        },
        insn.CLASS_LDX => {
            try execLoad(&out, i, cfg);
            try fallthrough(pc, len, out);
        },
        insn.CLASS_ST, insn.CLASS_STX => {
            try execStore(out, i, cfg, class == insn.CLASS_STX);
            try fallthrough(pc, len, out); // stores leave the register file unchanged
        },
        insn.CLASS_JMP, insn.CLASS_JMP32 => {
            const op = i.opcode & 0xf0;
            if (op == @intFromEnum(insn.JmpCode.exit)) return; // terminates this path

            if (op == @intFromEnum(insn.JmpCode.call)) {
                const sig = cfg.helpers[@intCast(i.imm)].?; // A1 proved this non-null
                var a: usize = 1;
                while (a <= sig.n_args) : (a += 1) {
                    if (out[a].kind == .uninit) return error.UninitReg;
                }
                // eBPF calling convention: r0 = return scalar, r1..r5 clobbered,
                // r6..r9 + r10 preserved.
                out[0] = .{ .kind = .scalar };
                var r: usize = 1;
                while (r <= 5) : (r += 1) out[r] = .{};
                try fallthrough(pc, len, out);
                return;
            }

            const is32 = class == insn.CLASS_JMP32;
            if (op == @intFromEnum(insn.JmpCode.ja)) {
                const delta: i64 = if (is32) i.imm else i.offset;
                pushSucc(jumpTarget(pc, delta), out); // target validated in A2
                return;
            }

            // Conditional branch: both operands are read, two successors. M3a
            // does not narrow register state along the taken/not-taken edges
            // (that refinement is M3b), so both successors get the same state.
            if (out[i.dst()].kind == .uninit) return error.UninitReg;
            if ((i.opcode & insn.SRC_X) != 0 and out[i.src()].kind == .uninit) return error.UninitReg;
            pushSucc(jumpTarget(pc, i.offset), out); // taken
            try fallthrough(pc, len, out); // not taken
        },
        else => unreachable, // classes 0..7 are all handled above
    }
}

fn execAlu(out: *RegFile, i: Insn, is64: bool) VerifyError!void {
    const d = i.dst();
    const s = i.src();
    const op = i.opcode & 0xf0;
    const src_x = (i.opcode & insn.SRC_X) != 0;
    if (d == 10) return error.WriteToR10;
    if (src_x and out[s].kind == .uninit) return error.UninitReg;

    const mov = @intFromEnum(insn.AluCode.mov);
    const add = @intFromEnum(insn.AluCode.add);
    const sub = @intFromEnum(insn.AluCode.sub);

    if (op == mov) {
        if (!src_x) {
            out[d] = .{ .kind = .scalar }; // mov imm
        } else if (i.offset != 0) {
            out[d] = .{ .kind = .scalar }; // MOVSX reinterprets — never a pointer
        } else if (!is64 and out[s].isPtr()) {
            out[d] = .{ .kind = .scalar }; // 32-bit mov truncates a pointer away
        } else {
            out[d] = out[s]; // pointer-preserving copy
        }
        return;
    }

    // Every non-mov ALU op reads dst as an operand.
    if (out[d].kind == .uninit) return error.UninitReg;

    // The one pointer-preserving arithmetic: 64-bit add/sub of a constant just
    // shifts the offset (this is how programs form &stack[-8] etc.).
    if ((op == add or op == sub) and is64 and out[d].isPtr()) {
        const dstate = out[d];
        if (!src_x) {
            const imm: i64 = i.imm;
            const delta: i64 = if (op == sub) -imm else imm;
            out[d] = if (dstate.off_known)
                .{ .kind = dstate.kind, .off = dstate.off + delta }
            else
                dstate;
        } else if (out[s].isPtr()) {
            out[d] = .{ .kind = .scalar }; // ptr ± ptr is not a pointer
        } else {
            out[d] = .{ .kind = dstate.kind, .off_known = false }; // ptr ± unknown scalar
        }
        return;
    }

    // Anything else (mul/div/and/shifts/neg/bswap, or pointer math we don't
    // model) yields a scalar — sound, just no longer dereferenceable.
    out[d] = .{ .kind = .scalar };
}

fn execLoad(out: *RegFile, i: Insn, cfg: Config) VerifyError!void {
    const d = i.dst();
    if (d == 10) return error.WriteToR10;
    const size: insn.Size = @enumFromInt(i.opcode & 0x18);
    try checkAccess(out.*, i.src(), i.offset, size.bytes(), cfg, false);
    out[d] = .{ .kind = .scalar }; // a loaded value is opaque in M3a
}

fn execStore(rf: RegFile, i: Insn, cfg: Config, from_reg: bool) VerifyError!void {
    const size: insn.Size = @enumFromInt(i.opcode & 0x18);
    if (from_reg and rf[i.src()].kind == .uninit) return error.UninitReg;
    try checkAccess(rf, i.dst(), i.offset, size.bytes(), cfg, true);
}

/// The static analogue of vm.zig's checkMem: prove that `*(n bytes)(base+off)`
/// lands wholly inside the region `base` points at, with write permission if
/// this is a store.
fn checkAccess(rf: RegFile, base_reg: u4, off: i16, n: u64, cfg: Config, write: bool) VerifyError!void {
    const p = rf[base_reg];
    switch (p.kind) {
        .uninit => return error.UninitReg,
        .scalar => return error.NotAPointer,
        .ctx_ptr, .stack_ptr => {},
    }
    if (!p.off_known) return error.NotAPointer; // unbounded offset → cannot prove safe

    const region_len: i64 = if (p.kind == .stack_ptr) @intCast(insn.STACK_SIZE) else @intCast(cfg.ctx_len);
    const writable = if (p.kind == .stack_ptr) true else cfg.ctx_writable;
    if (write and !writable) return error.WriteToReadonly;

    const eff: i64 = p.off + off;
    if (eff < 0) return error.OutOfBoundsAccess;
    if (eff + @as(i64, @intCast(n)) > region_len) return error.OutOfBoundsAccess;
}

// === Pass A1: per-instruction shape validation; returns slot width (1 or 2) ===

fn decodeShape(i: Insn, prog: []const Insn, pc: usize, len: usize, cfg: Config) VerifyError!usize {
    if (i.dst() > 10 or i.src() > 10) return error.BadRegister;
    const class = i.opcode & 0x07;
    switch (class) {
        insn.CLASS_ALU, insn.CLASS_ALU64 => {
            try validAluOp(i.opcode & 0xf0, i);
            return 1;
        },
        insn.CLASS_JMP, insn.CLASS_JMP32 => {
            try validJmpOp(i.opcode & 0xf0, class == insn.CLASS_JMP32, i, cfg);
            return 1;
        },
        insn.CLASS_LDX => {
            const mode = i.opcode & 0xe0;
            if (mode != insn.MODE_MEM and mode != insn.MODE_MEMSX) return error.UnknownOpcode;
            return 1;
        },
        insn.CLASS_ST, insn.CLASS_STX => {
            if ((i.opcode & 0xe0) != insn.MODE_MEM) return error.UnknownOpcode; // reject ATOMIC/legacy
            return 1;
        },
        insn.CLASS_LD => {
            if (i.opcode != insn.OP_LD_IMM64) return error.UnknownOpcode;
            if (i.src() != 0) return error.UnknownOpcode; // map-fd / btf-id pseudo forms unsupported
            if (pc + 1 >= len) return error.BadImm64;
            if (prog[pc + 1].opcode != 0) return error.BadImm64;
            return 2;
        },
        else => unreachable,
    }
}

fn validAluOp(op: u8, i: Insn) VerifyError!void {
    const A = insn.AluCode;
    switch (op) {
        @intFromEnum(A.add), @intFromEnum(A.sub), @intFromEnum(A.mul), @intFromEnum(A.div), @intFromEnum(A.@"or"), @intFromEnum(A.@"and"), @intFromEnum(A.lsh), @intFromEnum(A.rsh), @intFromEnum(A.neg), @intFromEnum(A.mod), @intFromEnum(A.xor), @intFromEnum(A.arsh) => {},
        @intFromEnum(A.mov) => {
            if (i.offset != 0 and i.offset != 8 and i.offset != 16 and i.offset != 32) return error.UnknownOpcode;
        },
        @intFromEnum(A.end) => {
            if (i.imm != 16 and i.imm != 32 and i.imm != 64) return error.UnknownOpcode;
        },
        else => return error.UnknownOpcode,
    }
    if (op == @intFromEnum(A.div) or op == @intFromEnum(A.mod)) {
        if (i.offset != 0 and i.offset != 1) return error.UnknownOpcode; // signedness selector
    }
}

fn validJmpOp(op: u8, is32: bool, i: Insn, cfg: Config) VerifyError!void {
    const J = insn.JmpCode;
    switch (op) {
        @intFromEnum(J.ja), @intFromEnum(J.jeq), @intFromEnum(J.jgt), @intFromEnum(J.jge), @intFromEnum(J.jset), @intFromEnum(J.jne), @intFromEnum(J.jsgt), @intFromEnum(J.jsge), @intFromEnum(J.jlt), @intFromEnum(J.jle), @intFromEnum(J.jslt), @intFromEnum(J.jsle) => {},
        @intFromEnum(J.call) => {
            if (is32) return error.UnknownOpcode; // CALL only exists in CLASS_JMP
            if (i.src() != 0) return error.BadCall; // bpf-to-bpf / runtime-fn: unsupported
            if (i.imm < 0 or @as(usize, @intCast(i.imm)) >= cfg.helpers.len) return error.UnknownHelper;
            if (cfg.helpers[@intCast(i.imm)] == null) return error.UnknownHelper;
        },
        @intFromEnum(J.exit) => {
            if (is32) return error.UnknownOpcode; // EXIT only exists in CLASS_JMP
        },
        else => return error.UnknownOpcode,
    }
}

// === Pass A2: jump-target validation ===

fn checkJumpTargets(i: Insn, pc: usize, len: usize) VerifyError!void {
    const class = i.opcode & 0x07;
    if (class != insn.CLASS_JMP and class != insn.CLASS_JMP32) return;
    const op = i.opcode & 0xf0;
    if (op == @intFromEnum(insn.JmpCode.exit) or op == @intFromEnum(insn.JmpCode.call)) return;

    const is32 = class == insn.CLASS_JMP32;
    // Only a JMP32 long-JA takes its displacement from imm; every other branch
    // (incl. JMP32 conditionals) uses the 16-bit offset.
    const delta: i64 = if (op == @intFromEnum(insn.JmpCode.ja) and is32) i.imm else i.offset;
    const t: i64 = @as(i64, @intCast(pc)) + 1 + delta;
    if (t < 0 or t >= @as(i64, @intCast(len))) return error.JumpOutOfRange;
    const tu: usize = @intCast(t);
    if (!g_starts[tu]) return error.JumpIntoImm64;
    if (tu <= pc) return error.BackEdge; // forward-only ⇒ acyclic ⇒ halts
}
