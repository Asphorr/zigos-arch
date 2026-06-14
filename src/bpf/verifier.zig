//! bpf/verifier — zBPF's static safety pass (M3a structural + M3b ranges).
//!
//! Runs BEFORE an untrusted program is accepted, proving ahead of time the
//! properties the interpreter (vm.zig) otherwise has to enforce at run time.
//! The contract is SOUNDNESS: every program verify() accepts, the interpreter
//! runs to completion WITHOUT ever returning a sandbox-violation error
//! (OutOfBounds / BadJump / BadHelperId / TimeLimit). The interpreter keeps its
//! own checks regardless — defence in depth — but a verified program never
//! trips them. The verifier is deliberately a CONSERVATIVE under-approximation:
//! it may reject a safe-but-clever program (those are later milestones to
//! admit), but it must never accept an unsafe one. tools/bpf-test/fuzz_test.zig
//! hammers that contract: random programs in, and every accepted one is run to
//! prove it never faults.
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
//!   index, so Pass B is a single forward sweep with NO fixpoint iteration.
//!
//! Pass B (abstract interpretation): a forward sweep over the DAG carrying an
//!   abstract register file. Lattice: uninit / scalar[lo,hi] / ctx_ptr[lo,hi] /
//!   stack_ptr[lo,hi]. A scalar carries an inclusive value range; a pointer
//!   carries an inclusive byte-offset range from its region base. This proves:
//!   no read of an uninitialized register, every memory access in-bounds of its
//!   region for the WHOLE offset range (size-aware), no store into a read-only
//!   region, every CALL's argument registers initialized.
//!
//!   M3b's ranges are why a *computed* pointer offset can now be proven safe:
//!   `r2 = r10; r2 += (idx & 31)` gives an offset range, and a load through it
//!   is admitted iff that whole range fits the region. Conditional branches
//!   NARROW the range along each edge (`if r2 < 8` ⇒ taken edge has r2 ∈ [0,7]),
//!   which is how a bounds-checked variable index is admitted.
//!
//!   Termination is trivial here precisely BECAUSE loops are banned: over a DAG
//!   each node's range is computed once, from already-finished predecessors, so
//!   the interval domain never needs a widening operator to converge (that —
//!   range tracking across a back-edge — is the hard problem M4 takes on).
//!
//! NOT REENTRANT: the analysis scratch lives in module statics, so the kernel
//! load path must serialize calls behind a load lock (bpf/kernel.zig's
//! verify_lock). Keeping verifier.zig free of kernel imports is deliberate — it
//! is what lets the off-target harness test it in isolation. The off-target
//! harness drives it single-threaded.

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
    BackEdge, // a backward jump (loop) — not permitted yet
    NoExit, // a reachable path runs off the end without EXIT
    UninitReg, // reads a register that may be uninitialized
    UnknownHelper, // CALL to an unregistered helper id
    BadCall, // unsupported CALL flavor (bpf-to-bpf, runtime fn)
    NotAPointer, // memory access through a non-pointer register
    OutOfBoundsAccess, // access can fall outside the region bounds
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

// "Don't know anything" range — the full i64 interval. A scalar set to this is
// any 64-bit value; a pointer offset set to this is un-dereferenceable (the
// bounds check below can never prove it fits). All range math saturates to
// these rather than wrapping, so an over/underflow only ever loses precision.
const FULL_LO: i64 = std.math.minInt(i64);
const FULL_HI: i64 = std.math.maxInt(i64);

const RegState = struct {
    kind: Kind = .uninit,
    /// scalar: inclusive value range. pointer: inclusive byte-offset range from
    /// the region base (stack's base is its LOW end, so r10 — the frame pointer
    /// at the TOP — starts at lo=hi=STACK_SIZE and programs reach in with
    /// negative offsets). lo == hi means an exact constant.
    lo: i64 = 0,
    hi: i64 = 0,

    fn isPtr(self: RegState) bool {
        return self.kind == .ctx_ptr or self.kind == .stack_ptr;
    }
    fn eql(a: RegState, b: RegState) bool {
        return a.kind == b.kind and a.lo == b.lo and a.hi == b.hi;
    }
};

fn scalar(lo: i64, hi: i64) RegState {
    return .{ .kind = .scalar, .lo = lo, .hi = hi };
}
fn scalarConst(v: i64) RegState {
    return .{ .kind = .scalar, .lo = v, .hi = v };
}
fn scalarFull() RegState {
    return .{ .kind = .scalar, .lo = FULL_LO, .hi = FULL_HI };
}

const RegFile = [insn.NUM_REGS]RegState;

/// Lattice join of two register states (a UNION of ranges — a conservative
/// superset, hence sound). Over a DAG this is computed once per node from
/// finished predecessors, so it never needs to iterate to a fixpoint.
fn joinReg(a: RegState, b: RegState) RegState {
    if (a.eql(b)) return a;
    // If either side might be uninitialized, the merge might be — poison it so
    // a later read is rejected. (uninit is the conservative top for liveness.)
    if (a.kind == .uninit or b.kind == .uninit) return .{ .kind = .uninit };
    // Same region: keep it a pointer, widening the offset to the union range.
    if (a.kind == b.kind and a.isPtr()) {
        return .{ .kind = a.kind, .lo = @min(a.lo, b.lo), .hi = @max(a.hi, b.hi) };
    }
    if (a.kind == .scalar and b.kind == .scalar) {
        return scalar(@min(a.lo, b.lo), @max(a.hi, b.hi));
    }
    // Differing kinds (ptr vs scalar, ctx vs stack): we no longer know what it
    // is or holds — a scalar of unknown value, which can't be dereferenced.
    return scalarFull();
}

// Saturating arithmetic — overflow only ever loses precision (widens), never
// wraps into a falsely-narrow range.
fn satAdd(a: i64, b: i64) i64 {
    return std.math.add(i64, a, b) catch (if (b >= 0) FULL_HI else FULL_LO);
}
fn satSub(a: i64, b: i64) i64 {
    return std.math.sub(i64, a, b) catch (if (b >= 0) FULL_LO else FULL_HI);
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
    entry[1] = .{ .kind = .ctx_ptr, .lo = 0, .hi = 0 }; // r1 = ctx pointer at entry
    entry[10] = .{ .kind = .stack_ptr, .lo = @intCast(insn.STACK_SIZE), .hi = @intCast(insn.STACK_SIZE) };
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
            // LD_IMM64 (shape validated in A1): loads a 64-bit constant and
            // consumes two slots, so the successor is pc+2.
            const d = i.dst();
            if (d == 10) return error.WriteToR10;
            const lo_bits: u64 = @as(u32, @bitCast(i.imm));
            const hi_bits: u64 = @as(u32, @bitCast(prog[pc + 1].imm));
            out[d] = scalarConst(@bitCast(lo_bits | (hi_bits << 32)));
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
                out[0] = scalarFull();
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

            // Conditional branch: both operands are read; two successors, each
            // with the compared register's range NARROWED by the condition.
            const d = i.dst();
            if (out[d].kind == .uninit) return error.UninitReg;
            const src_x = (i.opcode & insn.SRC_X) != 0;
            if (src_x and out[i.src()].kind == .uninit) return error.UninitReg;

            var taken = out;
            var fall = out;
            // Narrow only 64-bit register-vs-immediate compares (a JMP32 only
            // constrains the low 32 bits; reg-vs-reg narrowing is M3b+).
            if (!is32 and !src_x) narrowImm(out[d], op, i.imm, &taken[d], &fall[d]);

            const nxt = pc + 1;
            if (nxt >= len) return error.NoExit;
            pushSucc(jumpTarget(pc, i.offset), taken); // taken (target validated in A2)
            pushSucc(nxt, fall); // not taken
        },
        else => unreachable, // classes 0..7 are all handled above
    }
}

/// Refine a scalar register's range along the taken / not-taken edges of an
/// unsigned register-vs-immediate compare. Only fires for a non-negative scalar
/// against a non-negative immediate — the bounds-check idiom — and only ever
/// SHRINKS a range, so it is always sound; anything else passes through.
fn narrowImm(orig: RegState, op: u8, imm: i32, taken: *RegState, fall: *RegState) void {
    taken.* = orig;
    fall.* = orig;
    if (orig.kind != .scalar or orig.lo < 0 or imm < 0) return;
    const K: i64 = imm;
    const lo = orig.lo;
    const hi = orig.hi;
    const J = insn.JmpCode;
    switch (op) {
        @intFromEnum(J.jlt) => { // unsigned <
            setRange(taken, lo, @min(hi, K - 1));
            setRange(fall, @max(lo, K), hi);
        },
        @intFromEnum(J.jle) => {
            setRange(taken, lo, @min(hi, K));
            setRange(fall, @max(lo, K + 1), hi);
        },
        @intFromEnum(J.jgt) => {
            setRange(taken, @max(lo, K + 1), hi);
            setRange(fall, lo, @min(hi, K));
        },
        @intFromEnum(J.jge) => {
            setRange(taken, @max(lo, K), hi);
            setRange(fall, lo, @min(hi, K - 1));
        },
        @intFromEnum(J.jeq) => setRange(taken, K, K), // fall unchanged
        @intFromEnum(J.jne) => setRange(fall, K, K), // taken unchanged
        else => {},
    }
}

/// Apply a narrowed [lo,hi] only if it is a non-empty interval — an empty one
/// would mean that edge is infeasible, which we conservatively ignore (leave
/// the pre-narrow range) rather than encode.
fn setRange(s: *RegState, lo: i64, hi: i64) void {
    if (lo <= hi) {
        s.lo = lo;
        s.hi = hi;
    }
}

fn execAlu(out: *RegFile, i: Insn, is64: bool) VerifyError!void {
    const d = i.dst();
    const s = i.src();
    const op = i.opcode & 0xf0;
    const src_x = (i.opcode & insn.SRC_X) != 0;
    if (d == 10) return error.WriteToR10;
    if (src_x and out[s].kind == .uninit) return error.UninitReg;

    const A = insn.AluCode;
    const mov = @intFromEnum(A.mov);
    const add = @intFromEnum(A.add);
    const sub = @intFromEnum(A.sub);
    const @"and" = @intFromEnum(A.@"and");

    if (op == mov) {
        if (!src_x) {
            // mov imm: 64-bit sign-extends the i32; 32-bit zero-extends to u32.
            out[d] = if (is64) scalarConst(i.imm) else scalarConst(@as(i64, @as(u32, @bitCast(i.imm))));
        } else if (i.offset != 0) {
            out[d] = scalarFull(); // MOVSX reinterprets — never a pointer
        } else if (!is64 and out[s].isPtr()) {
            out[d] = scalar(0, 0xFFFF_FFFF); // 32-bit mov truncates a pointer to a u32 scalar
        } else if (!is64 and out[s].kind == .scalar) {
            out[d] = trunc32(out[s]); // 32-bit mov zero-extends low 32 bits
        } else {
            out[d] = out[s]; // 64-bit pointer/scalar-preserving copy
        }
        return;
    }

    // Every non-mov ALU op reads dst as an operand.
    if (out[d].kind == .uninit) return error.UninitReg;

    // Pointer arithmetic: 64-bit add/sub keeps a pointer, shifting its offset
    // range by the (constant or ranged) operand. This is how programs form
    // &stack[-8], &ctx[idx], etc.
    if ((op == add or op == sub) and is64 and out[d].isPtr()) {
        const p = out[d];
        if (!src_x) {
            const k: i64 = i.imm;
            out[d] = .{ .kind = p.kind, .lo = satAdd(p.lo, if (op == sub) -k else k), .hi = satAdd(p.hi, if (op == sub) -k else k) };
        } else if (out[s].kind == .scalar) {
            const v = out[s];
            out[d] = if (op == add)
                .{ .kind = p.kind, .lo = satAdd(p.lo, v.lo), .hi = satAdd(p.hi, v.hi) }
            else
                .{ .kind = p.kind, .lo = satSub(p.lo, v.hi), .hi = satSub(p.hi, v.lo) };
        } else {
            out[d] = scalarFull(); // ptr ± ptr is not a pointer
        }
        return;
    }

    // Scalar arithmetic with a little range precision where it is cheap and
    // load-bearing (constants, add/sub, the AND mask); everything else widens.
    const dval = out[d];
    if (op == add or op == sub) {
        const v = if (src_x) out[s] else scalarConst(i.imm);
        // A pointer operand here means we've lost the pointer (e.g. scalar+ptr) —
        // treat the result as an unknown scalar.
        if (dval.kind != .scalar or v.kind != .scalar) {
            out[d] = clampWidth(scalarFull(), is64);
        } else {
            const r = if (op == add)
                scalar(satAdd(dval.lo, v.lo), satAdd(dval.hi, v.hi))
            else
                scalar(satSub(dval.lo, v.hi), satSub(dval.hi, v.lo));
            out[d] = clampWidth(r, is64);
        }
    } else if (op == @"and") {
        out[d] = clampWidth(andRange(dval, if (src_x) out[s] else scalarConst(i.imm), is64), is64);
    } else {
        // mul/div/mod/or/xor/shifts/neg/bswap and anything else: widen. A 32-bit
        // result is still zero-extended into [0, 2^32), which is tighter than full.
        out[d] = clampWidth(scalarFull(), is64);
    }
}

/// AND can only clear bits, so `x & y` is bounded above by whichever operand we
/// can bound — provided both are known non-negative (so the high bit is clear).
fn andRange(a: RegState, b: RegState, is64: bool) RegState {
    var ub: i64 = FULL_HI;
    if (a.kind == .scalar and a.lo >= 0) ub = @min(ub, a.hi);
    if (b.kind == .scalar and b.lo >= 0) ub = @min(ub, b.hi);
    if (ub == FULL_HI) return scalarFull();
    _ = is64;
    return scalar(0, ub);
}

/// Zero-extension of a 32-bit ALU result: clamp the range into [0, 2^32) unless
/// the operation was 64-bit. Saturates conservatively — if the range can't be
/// represented as a sub-interval of [0, 2^32), fall back to that whole window.
fn clampWidth(r: RegState, is64: bool) RegState {
    if (is64) return r;
    if (r.kind != .scalar) return scalar(0, 0xFFFF_FFFF);
    if (r.lo >= 0 and r.hi <= 0xFFFF_FFFF) return r; // already inside the 32-bit window
    return scalar(0, 0xFFFF_FFFF);
}

fn trunc32(s: RegState) RegState {
    if (s.lo >= 0 and s.hi <= 0xFFFF_FFFF) return s;
    return scalar(0, 0xFFFF_FFFF);
}

fn execLoad(out: *RegFile, i: Insn, cfg: Config) VerifyError!void {
    const d = i.dst();
    if (d == 10) return error.WriteToR10;
    const size: insn.Size = @enumFromInt(i.opcode & 0x18);
    const n = size.bytes();
    try checkAccess(out.*, i.src(), i.offset, n, cfg, false);
    // A plain (zero-extending) load of n<8 bytes lands in [0, 2^(8n)). This is
    // load-bearing: it is what lets a loaded byte/half/word later be narrowed
    // and used as a bounded index. A sign-extending load can be negative.
    const mode = i.opcode & 0xe0;
    out[d] = if (mode == insn.MODE_MEM and n < 8)
        scalar(0, (@as(i64, 1) << @intCast(8 * n)) - 1)
    else
        scalarFull();
}

fn execStore(rf: RegFile, i: Insn, cfg: Config, from_reg: bool) VerifyError!void {
    const size: insn.Size = @enumFromInt(i.opcode & 0x18);
    if (from_reg and rf[i.src()].kind == .uninit) return error.UninitReg;
    try checkAccess(rf, i.dst(), i.offset, size.bytes(), cfg, true);
}

/// The static analogue of vm.zig's checkMem: prove that `*(n bytes)(base+off)`
/// lands wholly inside the region `base` points at, for the WHOLE offset range,
/// with write permission if this is a store.
fn checkAccess(rf: RegFile, base_reg: u4, off: i16, n: u64, cfg: Config, write: bool) VerifyError!void {
    const p = rf[base_reg];
    switch (p.kind) {
        .uninit => return error.UninitReg,
        .scalar => return error.NotAPointer,
        .ctx_ptr, .stack_ptr => {},
    }
    const region_len: i64 = if (p.kind == .stack_ptr) @intCast(insn.STACK_SIZE) else @intCast(cfg.ctx_len);
    const writable = if (p.kind == .stack_ptr) true else cfg.ctx_writable;
    if (write and !writable) return error.WriteToReadonly;

    // Lowest and highest byte the access can touch, across the offset range.
    const lo = satAdd(p.lo, off);
    const hi = satAdd(satAdd(p.hi, off), @as(i64, @intCast(n)));
    if (lo < 0) return error.OutOfBoundsAccess; // some offset could dip below the region
    if (hi > region_len) return error.OutOfBoundsAccess; // some offset could run past it
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
