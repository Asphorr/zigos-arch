// zbpf — userspace BPF loader. Hand-assembles programs, hands them to the
// kernel via sys_bpf (#122), and the verifier decides whether each may run:
//   [1] a good compute program runs sandboxed and returns its result
//   [2] a bounded counted loop (M4) is PROVEN to terminate, then run
//   [3] an out-of-bounds read is REJECTED at load
//   [4] an infinite loop is REJECTED at load
// [3] and [4] are the redteam angle: untrusted code probing the ring-0 sandbox
// boundary, bounced by the verifier before it executes a single instruction.

const libc = @import("libc");

// Byte-identical to insn.Insn (kernel) and the on-wire RFC 9669 encoding.
const Insn = extern struct { opcode: u8, regs: u8, offset: i16, imm: i32 };

// Byte-identical to bpf/kernel.zig's BpfAttr.
const BpfAttr = extern struct {
    ret: u64 = 0,
    prog: u32 = 0,
    prog_cnt: u32 = 0,
    ctx: u32 = 0,
    ctx_len: u32 = 0,
    ctx_writable: u32 = 0,
    flags: u32 = 0,
};

fn ins(opcode: u8, dst: u4, src: u4, offset: i16, imm: i32) Insn {
    return .{ .opcode = opcode, .regs = (@as(u8, src) << 4) | @as(u8, dst), .offset = offset, .imm = imm };
}

// The few opcodes this demo needs (class | source | op, per RFC 9669).
const LDX_DW = 0x79; // r[dst] = *(u64*)(r[src] + off)
const ST_DW = 0x7a; // *(u64*)(r[dst] + off) = imm
const MOV64_K = 0xb7; // r[dst] = imm
const MOV64_X = 0xbf; // r[dst] = r[src]
const ADD64_K = 0x07; // r[dst] += imm
const ADD64_X = 0x0f; // r[dst] += r[src]
const ATOMIC_DW = 0xdb; // atomic *(u64*)(r[dst]+off) op= r[src], op in imm (STX|DW|ATOMIC)
const ATOMIC_FETCH_ADD = 0x01; // imm: BPF_ADD | BPF_FETCH — return the old value in src
const JGE_K = 0x35; // if r[dst] >= imm goto +off  (unsigned)
const JA = 0x05; // goto +off
const EXIT = 0x95;

const Result = struct { rc: u32, ret: u64 };

fn runBpf(prog: []const Insn, ctx: ?[]u8, writable: bool) Result {
    var attr = BpfAttr{
        .prog = @truncate(@intFromPtr(prog.ptr)),
        .prog_cnt = @intCast(prog.len),
    };
    if (ctx) |c| {
        attr.ctx = @truncate(@intFromPtr(c.ptr));
        attr.ctx_len = @intCast(c.len);
        attr.ctx_writable = if (writable) 1 else 0;
    }
    const rc = libc.syscall3(122, 0, @truncate(@intFromPtr(&attr)), @sizeOf(BpfAttr));
    return .{ .rc = rc, .ret = attr.ret };
}

fn report(label: []const u8, r: Result) void {
    libc.print(label);
    if (r.rc == 0) {
        libc.print(" -> ran in sandbox, r0=");
        libc.printNum(@truncate(r.ret));
        libc.printChar('\n');
    } else {
        libc.print(" -> REJECTED by verifier (rc=");
        libc.printNum(r.rc);
        libc.print(")\n");
    }
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.println("zbpf: loading userspace programs via sys_bpf (#122) — the verifier gates each one");

    // [1] good compute: r0 = ctx[0] + 42
    {
        var ctx: [8]u8 align(8) = undefined;
        @as(*align(8) u64, @ptrCast(&ctx)).* = 100;
        const prog = [_]Insn{
            ins(LDX_DW, 0, 1, 0, 0), // r0 = *(u64*)(ctx+0)
            ins(ADD64_K, 0, 0, 0, 42), // r0 += 42
            ins(EXIT, 0, 0, 0, 0),
        };
        report("[1] compute (ctx[0]=100, +42; expect 142)", runBpf(&prog, ctx[0..], false));
    }

    // [2] bounded counted loop (M4): r0 = sum(0..9) = 45
    {
        const prog = [_]Insn{
            ins(MOV64_K, 0, 0, 0, 0), // r0 = 0   (sum)
            ins(MOV64_K, 2, 0, 0, 0), // r2 = 0   (i)
            ins(JGE_K, 2, 0, 3, 10), // L: if r2 >= 10 goto E
            ins(ADD64_X, 0, 2, 0, 0), //    r0 += r2
            ins(ADD64_K, 2, 0, 0, 1), //    r2 += 1
            ins(JA, 0, 0, -4, 0), //    goto L
            ins(EXIT, 0, 0, 0, 0), // E:
        };
        report("[2] bounded loop sum(0..9) (expect 45)", runBpf(&prog, null, false));
    }

    // [3] redteam: out-of-bounds ctx read past the 8-byte context
    {
        var ctx: [8]u8 align(8) = undefined;
        @as(*align(8) u64, @ptrCast(&ctx)).* = 0;
        const prog = [_]Insn{
            ins(LDX_DW, 0, 1, 1000, 0), // r0 = *(u64*)(ctx+1000)
            ins(EXIT, 0, 0, 0, 0),
        };
        report("[3] redteam: out-of-bounds read", runBpf(&prog, ctx[0..], false));
    }

    // [4] redteam: an infinite loop
    {
        const prog = [_]Insn{
            ins(JA, 0, 0, -1, 0), // jump to self forever
            ins(EXIT, 0, 0, 0, 0),
        };
        report("[4] redteam: infinite loop", runBpf(&prog, null, false));
    }

    // [5] atomic fetch-add on the program's own stack — verified, then JIT-
    //     compiled to a native `lock xadd`. r0 = old(100) + new_mem(108) = 208.
    {
        const prog = [_]Insn{
            ins(ST_DW, 10, 0, -8, 100), // *(u64*)(r10-8) = 100
            ins(MOV64_K, 1, 0, 0, 8), // r1 = 8
            ins(ATOMIC_DW, 10, 1, -8, ATOMIC_FETCH_ADD), // r1 = old(100); mem = 108
            ins(MOV64_X, 0, 1, 0, 0), // r0 = r1 = 100
            ins(LDX_DW, 2, 10, -8, 0), // r2 = mem = 108
            ins(ADD64_X, 0, 2, 0, 0), // r0 = 100 + 108
            ins(EXIT, 0, 0, 0, 0),
        };
        report("[5] atomic fetch-add (expect old+new = 208)", runBpf(&prog, null, false));
    }

    libc.println("zbpf: done — [1]/[2]/[5] ran in the kernel sandbox; [3]/[4] never executed a single instruction.");
    libc.exit();
}
