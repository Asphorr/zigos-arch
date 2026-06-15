//! bpf/verifier — zBPF's static safety pass (M3a structural, M3b ranges, M4 loops).
//!
//! Runs BEFORE an untrusted program is accepted, proving ahead of time the
//! properties the interpreter (vm.zig) otherwise has to enforce at run time.
//! The contract is SOUNDNESS: every program verify() accepts, the interpreter
//! runs to completion WITHOUT ever returning a sandbox-violation error
//! (OutOfBounds / BadJump / BadHelperId / TimeLimit). The interpreter keeps its
//! own checks regardless — defence in depth — but a verified program never
//! trips them. The verifier is deliberately a CONSERVATIVE under-approximation:
//! it may reject a safe-but-clever program, but it must never accept an unsafe
//! one. tools/bpf-test/fuzz_test.zig hammers that contract: random programs in
//! (now including back-edges), and every accepted one is run to prove it never
//! faults AND terminates within fuel.
//!
//! ================================ PASSES =====================================
//! Pass A1 (linear decode): every opcode is known & permitted, register fields
//!   are in range (r0..r10), LD_IMM64 occupies two well-formed slots, MOVSX /
//!   endian / div-mod-signedness sub-encodings are valid, CALL names a
//!   registered helper. Also builds `g_starts` — which byte offsets are real
//!   instruction starts vs the hidden second slot of an LD_IMM64.
//!
//! Pass A2 (control flow): every jump target lands in-range and ON an
//!   instruction start (never inside an LD_IMM64 pair). Back-edges (target <=
//!   source) are now ALLOWED — they are loops — and each back-edge's target is
//!   recorded in `g_header` so Pass B only pays for cycle detection at the few
//!   real loop headers.
//!
//! Pass B (bounded symbolic execution): a depth-first walk of every FEASIBLE
//!   path, carrying an abstract register file. Lattice: uninit / scalar[lo,hi] /
//!   ctx_ptr[lo,hi] / stack_ptr[lo,hi] — a scalar's value range, a pointer's
//!   byte-offset range from its region base. This proves: no read of an
//!   uninitialized register, every memory access in-bounds for the WHOLE offset
//!   range (size-aware), no store into a read-only region, every CALL's argument
//!   registers initialized. Conditional branches NARROW the compared register
//!   along each edge and PRUNE provably-infeasible edges, so a progressing loop
//!   counter is unrolled exactly until its exit condition fires.
//!
//!   M4 — LOOPS. There is no DAG assumption any more, so termination is earned,
//!   two ways at once:
//!     * Program termination. Exact unrolling: a loop with a progressing counter
//!       narrows each iteration until the exit edge is the only feasible one. An
//!       infinite loop manifests as either (a) revisiting an IDENTICAL state at a
//!       loop header — a non-progressing cycle, rejected UnboundedLoop on the
//!       spot — or (b) unbounded growth that never repeats, caught when it
//!       exhausts the step budget (TooComplex). Both are sound rejections.
//!     * Verifier termination. A hard STEP_BUDGET on total simulated
//!       instructions and a MAX_DEPTH on path length: the analysis itself can
//!       never hang, regardless of input.
//!
//!   No state-pruning yet (M4-b): a loop is admitted only if its TOTAL unrolled
//!   work fits the budget; big or branchy loops are rejected TooComplex. Sound,
//!   just conservative. The fuel in vm.zig remains as defence in depth.
//!
//! NOT REENTRANT: the analysis scratch lives in module statics, so the kernel
//! load path must serialize calls behind a load lock (bpf/kernel.zig's
//! verify_lock). Keeping verifier.zig free of kernel imports is deliberate — it
//! is what lets the off-target harness test it in isolation.

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
    NoExit, // a reachable path runs off the end without EXIT
    UninitReg, // reads a register that may be uninitialized
    UnknownHelper, // CALL to an unregistered helper id
    BadCall, // unsupported CALL flavor (bpf-to-bpf, runtime fn)
    NotAPointer, // memory access through a non-pointer register
    OutOfBoundsAccess, // access can fall outside the region bounds
    WriteToReadonly, // store into a read-only region (e.g. ctx)
    UnboundedLoop, // a loop revisits an identical state — cannot terminate
    TooComplex, // exceeded the step/depth budget (incl. a loop too large to unroll)
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
// any 64-bit value; a pointer offset set to this is un-dereferenceable. All
// range math saturates to these rather than wrapping, so over/underflow only
// loses precision, never produces a falsely-narrow range.
const FULL_LO: i64 = std.math.minInt(i64);
const FULL_HI: i64 = std.math.maxInt(i64);

const RegState = struct {
    kind: Kind = .uninit,
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

fn regfileEql(a: RegFile, b: RegFile) bool {
    for (a, b) |x, y| {
        if (!x.eql(y)) return false;
    }
    return true;
}

// Saturating arithmetic — overflow only ever widens, never wraps narrow.
fn satAdd(a: i64, b: i64) i64 {
    return std.math.add(i64, a, b) catch (if (b >= 0) FULL_HI else FULL_LO);
}
fn satSub(a: i64, b: i64) i64 {
    return std.math.sub(i64, a, b) catch (if (b >= 0) FULL_LO else FULL_HI);
}

// === analysis scratch (see NOT REENTRANT note in the header) ===

// The DFS budget. STEP_BUDGET caps total simulated instructions across all
// paths (the verifier-termination guarantee); MAX_DEPTH caps a single path's
// length (so a loop unrolls only so far) and sizes the path arrays.
const MAX_DEPTH: usize = 1024;
const MAX_WORK: usize = 2 * MAX_DEPTH; // DFS frontier of a binary branch tree is O(depth)
const STEP_BUDGET: u64 = 60_000;

var g_starts: [insn.MAX_INSNS]bool = undefined;
var g_header: [insn.MAX_INSNS]bool = undefined; // back-edge targets = loop headers

// The current root-to-node path: path_state[0..depth] are the ancestors of the
// node at `depth`. The DFS only ever writes depths >= a node's own, so a node's
// ancestors are never clobbered by a sibling subtree (see the cycle check).
var path_pc: [MAX_DEPTH]u32 = undefined;
var path_state: [MAX_DEPTH]RegFile = undefined;

// The DFS work stack of not-yet-explored branch alternatives.
var work_pc: [MAX_WORK]u32 = undefined;
var work_depth: [MAX_WORK]u32 = undefined;
var work_state: [MAX_WORK]RegFile = undefined;

/// Verify `prog` against the program-type contract `cfg`. Returns cleanly on
/// success, or the first VerifyError found.
pub fn verify(prog: []const Insn, cfg: Config) VerifyError!void {
    const len = prog.len;
    if (len == 0) return error.EmptyProgram;
    if (len > insn.MAX_INSNS) return error.ProgramTooLong;

    // ---- Pass A1: decode + well-formedness, build the start map. ----
    for (0..len) |k| {
        g_starts[k] = false;
        g_header[k] = false;
    }
    var pc: usize = 0;
    while (pc < len) {
        g_starts[pc] = true;
        pc += try decodeShape(prog[pc], prog, pc, len, cfg);
    }

    // ---- Pass A2: validate jump targets, record loop headers. ----
    pc = 0;
    while (pc < len) : (pc += 1) {
        if (g_starts[pc]) try checkJumpTargets(prog[pc], pc, len);
    }

    // ---- Pass B: bounded symbolic execution (DFS over feasible paths). ----
    var entry: RegFile = undefined;
    for (&entry) |*r| r.* = .{}; // all uninit
    entry[1] = .{ .kind = .ctx_ptr, .lo = 0, .hi = 0 }; // r1 = ctx pointer
    entry[10] = .{ .kind = .stack_ptr, .lo = @intCast(insn.STACK_SIZE), .hi = @intCast(insn.STACK_SIZE) };

    work_pc[0] = 0;
    work_depth[0] = 0;
    work_state[0] = entry;
    var top: usize = 1;
    var steps: u64 = 0;

    while (top > 0) {
        top -= 1;
        const node_pc: usize = work_pc[top];
        const d: usize = work_depth[top];
        if (d >= MAX_DEPTH) return error.TooComplex;
        path_pc[d] = @intCast(node_pc);
        path_state[d] = work_state[top];
        const st = path_state[d];

        steps += 1;
        if (steps > STEP_BUDGET) return error.TooComplex;

        // Cycle detection — only at real loop headers (cheap elsewhere). If an
        // ancestor at this same pc holds an identical state, the loop can repeat
        // without progress: it cannot terminate.
        if (g_header[node_pc]) {
            var a: usize = 0;
            while (a < d) : (a += 1) {
                if (@as(usize, path_pc[a]) == node_pc and regfileEql(path_state[a], st)) return error.UnboundedLoop;
            }
        }

        var spc: [2]usize = undefined;
        var sst: [2]RegFile = undefined;
        const n = try simulateOne(prog, node_pc, len, cfg, st, &spc, &sst);

        var k: usize = 0;
        while (k < n) : (k += 1) {
            if (top >= MAX_WORK) return error.TooComplex;
            work_pc[top] = @intCast(spc[k]);
            work_depth[top] = @intCast(d + 1);
            work_state[top] = sst[k];
            top += 1;
        }
    }
}

/// Simulate one instruction at `pc` from state `in`, writing 0/1/2 feasible
/// successors into spc/sst and returning the count. EXIT yields 0; a fall-off-
/// the-end is NoExit.
fn simulateOne(prog: []const Insn, pc: usize, len: usize, cfg: Config, in: RegFile, spc: *[2]usize, sst: *[2]RegFile) VerifyError!u8 {
    const i = prog[pc];
    const class = i.opcode & 0x07;
    var out = in;

    switch (class) {
        insn.CLASS_ALU, insn.CLASS_ALU64 => {
            try execAlu(&out, i, class == insn.CLASS_ALU64);
            return emit1(pc + 1, len, out, spc, sst);
        },
        insn.CLASS_LD => {
            const d = i.dst();
            if (d == 10) return error.WriteToR10;
            const lo_bits: u64 = @as(u32, @bitCast(i.imm));
            const hi_bits: u64 = @as(u32, @bitCast(prog[pc + 1].imm));
            out[d] = scalarConst(@bitCast(lo_bits | (hi_bits << 32)));
            return emit1(pc + 2, len, out, spc, sst);
        },
        insn.CLASS_LDX => {
            try execLoad(&out, i, cfg);
            return emit1(pc + 1, len, out, spc, sst);
        },
        insn.CLASS_ST => {
            try execStore(out, i, cfg, false);
            return emit1(pc + 1, len, out, spc, sst);
        },
        insn.CLASS_STX => {
            if ((i.opcode & 0xe0) == insn.MODE_ATOMIC) {
                try execAtomic(&out, i, cfg);
            } else {
                try execStore(out, i, cfg, true);
            }
            return emit1(pc + 1, len, out, spc, sst);
        },
        insn.CLASS_JMP, insn.CLASS_JMP32 => {
            const op = i.opcode & 0xf0;
            if (op == @intFromEnum(insn.JmpCode.exit)) return 0; // path complete

            if (op == @intFromEnum(insn.JmpCode.call)) {
                const sig = cfg.helpers[@intCast(i.imm)].?; // A1 proved this non-null
                var a: usize = 1;
                while (a <= sig.n_args) : (a += 1) {
                    if (out[a].kind == .uninit) return error.UninitReg;
                }
                out[0] = scalarFull(); // r0 = return scalar, r1..r5 clobbered
                var r: usize = 1;
                while (r <= 5) : (r += 1) out[r] = .{};
                return emit1(pc + 1, len, out, spc, sst);
            }

            const is32 = class == insn.CLASS_JMP32;
            if (op == @intFromEnum(insn.JmpCode.ja)) {
                const delta: i64 = if (is32) i.imm else i.offset;
                spc[0] = jumpTarget(pc, delta); // validated in A2 (may be a back-edge)
                sst[0] = out;
                return 1;
            }

            // Conditional: read both operands; emit the FEASIBLE successors with
            // the compared register narrowed along each edge.
            const d = i.dst();
            if (out[d].kind == .uninit) return error.UninitReg;
            const src_x = (i.opcode & insn.SRC_X) != 0;
            if (src_x and out[i.src()].kind == .uninit) return error.UninitReg;

            var taken: RegFile = undefined;
            var fall: RegFile = undefined;
            const fe = narrowCond(out, i, is32, &taken, &fall);

            var n: u8 = 0;
            if (fe.taken_ok) {
                spc[n] = jumpTarget(pc, i.offset); // validated in A2
                sst[n] = taken;
                n += 1;
            }
            if (fe.fall_ok) {
                if (pc + 1 >= len) return error.NoExit;
                spc[n] = pc + 1;
                sst[n] = fall;
                n += 1;
            }
            return n;
        },
        else => unreachable,
    }
}

fn emit1(nxt: usize, len: usize, out: RegFile, spc: *[2]usize, sst: *[2]RegFile) VerifyError!u8 {
    if (nxt >= len) return error.NoExit; // ran off the end without EXIT
    spc[0] = nxt;
    sst[0] = out;
    return 1;
}

fn jumpTarget(pc: usize, delta: i64) usize {
    return @intCast(@as(i64, @intCast(pc)) + 1 + delta);
}

/// Narrow the compared scalar register along the taken / not-taken edges of an
/// unsigned register-vs-immediate compare, reporting which edges are FEASIBLE.
/// Because the narrowing is an exact intersection (for a non-negative scalar vs
/// a non-negative immediate), an empty result PROVES that edge unreachable, so
/// pruning it is sound — and it is what lets a counted loop unroll precisely.
/// Anything else (JMP32, reg-vs-reg, signed, negative imm, non-scalar) passes
/// through with both edges feasible.
fn narrowCond(out: RegFile, i: Insn, is32: bool, taken: *RegFile, fall: *RegFile) struct { taken_ok: bool, fall_ok: bool } {
    taken.* = out;
    fall.* = out;
    const src_x = (i.opcode & insn.SRC_X) != 0;
    if (is32 or src_x) return .{ .taken_ok = true, .fall_ok = true };

    const d = i.dst();
    const orig = out[d];
    if (orig.kind != .scalar or orig.lo < 0 or i.imm < 0) return .{ .taken_ok = true, .fall_ok = true };

    const K: i64 = i.imm;
    const lo = orig.lo;
    const hi = orig.hi;
    var t_lo = lo;
    var t_hi = hi;
    var f_lo = lo;
    var f_hi = hi;
    const J = insn.JmpCode;
    switch (i.opcode & 0xf0) {
        @intFromEnum(J.jlt) => { // r < K
            t_hi = @min(hi, K - 1);
            f_lo = @max(lo, K);
        },
        @intFromEnum(J.jle) => {
            t_hi = @min(hi, K);
            f_lo = @max(lo, K + 1);
        },
        @intFromEnum(J.jgt) => {
            t_lo = @max(lo, K + 1);
            f_hi = @min(hi, K);
        },
        @intFromEnum(J.jge) => {
            t_lo = @max(lo, K);
            f_hi = @min(hi, K - 1);
        },
        @intFromEnum(J.jeq) => { // taken: r == K
            t_lo = @max(lo, K);
            t_hi = @min(hi, K);
        },
        @intFromEnum(J.jne) => { // not-taken: r == K
            f_lo = @max(lo, K);
            f_hi = @min(hi, K);
        },
        else => return .{ .taken_ok = true, .fall_ok = true },
    }
    const t_ok = t_lo <= t_hi;
    const f_ok = f_lo <= f_hi;
    if (t_ok) {
        taken[d].lo = t_lo;
        taken[d].hi = t_hi;
    }
    if (f_ok) {
        fall[d].lo = f_lo;
        fall[d].hi = f_hi;
    }
    return .{ .taken_ok = t_ok, .fall_ok = f_ok };
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
            out[d] = if (is64) scalarConst(i.imm) else scalarConst(@as(i64, @as(u32, @bitCast(i.imm))));
        } else if (i.offset != 0) {
            out[d] = scalarFull(); // MOVSX reinterprets — never a pointer
        } else if (!is64 and out[s].isPtr()) {
            out[d] = scalar(0, 0xFFFF_FFFF); // 32-bit mov truncates a pointer to a u32 scalar
        } else if (!is64 and out[s].kind == .scalar) {
            out[d] = trunc32(out[s]);
        } else {
            out[d] = out[s]; // 64-bit pointer/scalar-preserving copy
        }
        return;
    }

    if (out[d].kind == .uninit) return error.UninitReg; // every non-mov op reads dst

    // Pointer arithmetic: 64-bit add/sub shifts a pointer's offset range.
    if ((op == add or op == sub) and is64 and out[d].isPtr()) {
        const p = out[d];
        if (!src_x) {
            const k: i64 = i.imm;
            const delta: i64 = if (op == sub) -k else k;
            out[d] = .{ .kind = p.kind, .lo = satAdd(p.lo, delta), .hi = satAdd(p.hi, delta) };
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

    const dval = out[d];
    if (op == add or op == sub) {
        const v = if (src_x) out[s] else scalarConst(i.imm);
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
        out[d] = clampWidth(andRange(dval, if (src_x) out[s] else scalarConst(i.imm)), is64);
    } else {
        out[d] = clampWidth(scalarFull(), is64);
    }
}

/// AND can only clear bits, so `x & y` is bounded above by whichever operand we
/// can bound — provided both are known non-negative (so the high bit is clear).
fn andRange(a: RegState, b: RegState) RegState {
    var ub: i64 = FULL_HI;
    if (a.kind == .scalar and a.lo >= 0) ub = @min(ub, a.hi);
    if (b.kind == .scalar and b.lo >= 0) ub = @min(ub, b.hi);
    if (ub == FULL_HI) return scalarFull();
    return scalar(0, ub);
}

/// Zero-extension of a 32-bit ALU result: clamp into [0, 2^32).
fn clampWidth(r: RegState, is64: bool) RegState {
    if (is64) return r;
    if (r.kind != .scalar) return scalar(0, 0xFFFF_FFFF);
    if (r.lo >= 0 and r.hi <= 0xFFFF_FFFF) return r;
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
    const mode = i.opcode & 0xe0;
    // A plain (zero-extending) load of n<8 bytes lands in [0, 2^(8n)) — what lets
    // a loaded byte/word be narrowed and used as a bounded index.
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

/// Atomic RMW (STX | MODE_ATOMIC). Like a store it reads-and-writes memory, so
/// the access must be in-bounds and WRITABLE; additionally it has register
/// effects the abstract state must track. src always supplies an operand;
/// CMPXCHG also reads r0 (the comparand). A fetched OLD value (FETCH/XCHG → src,
/// CMPXCHG → r0) becomes an unknown scalar of the access width.
fn execAtomic(out: *RegFile, i: Insn, cfg: Config) VerifyError!void {
    const size: insn.Size = @enumFromInt(i.opcode & 0x18);
    const n = size.bytes();
    const src = i.src();
    const is_cmpxchg = (i.imm == insn.ATOMIC_CMPXCHG);

    if (out[src].kind == .uninit) return error.UninitReg;
    if (is_cmpxchg and out[0].kind == .uninit) return error.UninitReg;

    try checkAccess(out.*, i.dst(), i.offset, n, cfg, true);

    if ((i.imm & insn.ATOMIC_FETCH) != 0) {
        const dstreg: u4 = if (is_cmpxchg) 0 else src;
        if (dstreg == 10) return error.WriteToR10; // can't fetch into the frame pointer
        out[dstreg] = if (n < 8) scalar(0, (@as(i64, 1) << @intCast(8 * n)) - 1) else scalarFull();
    }
}

/// The static analogue of vm.zig's checkMem: prove `*(n bytes)(base+off)` lands
/// wholly inside the region `base` points at, for the WHOLE offset range.
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

    const lo = satAdd(p.lo, off);
    const hi = satAdd(satAdd(p.hi, off), @as(i64, @intCast(n)));
    if (lo < 0) return error.OutOfBoundsAccess;
    if (hi > region_len) return error.OutOfBoundsAccess;
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
        insn.CLASS_ST => {
            if ((i.opcode & 0xe0) != insn.MODE_MEM) return error.UnknownOpcode; // ST has no atomic form
            return 1;
        },
        insn.CLASS_STX => {
            const mode = i.opcode & 0xe0;
            if (mode == insn.MODE_MEM) return 1;
            if (mode == insn.MODE_ATOMIC) {
                try validAtomic(i);
                return 1;
            }
            return error.UnknownOpcode; // legacy/other store modes
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

/// An atomic (STX | MODE_ATOMIC) is well-formed iff its size is W or DW and its
/// imm names a known operation. The exact-value match also rejects a stray
/// FETCH bit on XCHG/CMPXCHG (which already carry it) or a missing one.
fn validAtomic(i: Insn) VerifyError!void {
    const size: insn.Size = @enumFromInt(i.opcode & 0x18);
    if (size != .w and size != .dw) return error.UnknownOpcode; // 32/64-bit only
    switch (i.imm) {
        insn.ATOMIC_ADD,
        insn.ATOMIC_ADD | insn.ATOMIC_FETCH,
        insn.ATOMIC_OR,
        insn.ATOMIC_OR | insn.ATOMIC_FETCH,
        insn.ATOMIC_AND,
        insn.ATOMIC_AND | insn.ATOMIC_FETCH,
        insn.ATOMIC_XOR,
        insn.ATOMIC_XOR | insn.ATOMIC_FETCH,
        insn.ATOMIC_XCHG,
        insn.ATOMIC_CMPXCHG,
        => {},
        else => return error.UnknownOpcode,
    }
}

// === Pass A2: jump-target validation + loop-header marking ===

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
    if (tu <= pc) g_header[tu] = true; // a back-edge: tu is a loop header
}
