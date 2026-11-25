// entrytest — the legacy way into the kernel must behave like the real one.
//
// `int 0x80` takes the call's number in rax and its arguments in rbx, rcx,
// rdx. No program in the tree enters that way any more, but ring 3 can, so
// the gate has to give the right answer and hand back every register it
// was not asked to change — the FP/SSE ones included. The kernel is built
// to use SSE: what it left in those registers would be the kernel's data
// in the caller's hands, and the caller's own gone.
//
// The verdict also goes to the kernel log (libc.klog): what a terminal
// shows does not reach serial.

const std = @import("std");
const libc = @import("libc");

const SYS_GETPID: u32 = 6;
const SYS_KLOG: u32 = 67;

fn int80(num: u32, a1: u32, a2: u32, a3: u32) u32 {
    var ret: u32 = undefined;
    asm volatile ("int $0x80"
        : [ret] "={eax}" (ret),
        : [num] "{eax}" (num),
          [a1] "{ebx}" (a1),
          [a2] "{ecx}" (a2),
          [a3] "{edx}" (a3),
        : .{ .memory = true });
    return ret;
}

/// `movdqu` between sixteen 16-byte slots and xmm0..xmm15.
fn xmmMoves(comptime load: bool) []const u8 {
    @setEvalBranchQuota(20_000);
    var text: []const u8 = "";
    for (0..16) |i| {
        const one: []const u8 = if (load)
            std.fmt.comptimePrint("movdqu {d}(%[in]), %%xmm{d}\n", .{ i * 16, i })
        else
            std.fmt.comptimePrint("movdqu %%xmm{d}, {d}(%[out])\n", .{ i, i * 16 });
        text = text ++ one;
    }
    return text;
}

/// Fill every XMM register, have the kernel copy a string on the far side
/// of the gate, and read the registers back.
fn xmmKept() bool {
    var in: [16 * 16]u8 = undefined;
    for (&in, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    var out: [16 * 16]u8 = undefined;
    const line = "[entrytest] a line long enough for the kernel to copy it sixteen bytes at a time, which is what puts its data in the registers this is about\n";
    var ret: u32 = undefined;
    asm volatile (xmmMoves(true) ++ "int $0x80\n" ++ xmmMoves(false)
        : [ret] "={eax}" (ret),
        : [in] "r" (&in),
          [out] "r" (&out),
          [num] "{eax}" (SYS_KLOG),
          [a1] "{ebx}" (@as(u32, @truncate(@intFromPtr(line.ptr)))),
          [a2] "{ecx}" (@as(u32, line.len)),
        : .{
          .xmm0 = true,  .xmm1 = true,  .xmm2 = true,  .xmm3 = true,
          .xmm4 = true,  .xmm5 = true,  .xmm6 = true,  .xmm7 = true,
          .xmm8 = true,  .xmm9 = true,  .xmm10 = true, .xmm11 = true,
          .xmm12 = true, .xmm13 = true, .xmm14 = true, .xmm15 = true,
          .memory = true,
      });
    return std.mem.eql(u8, &in, &out);
}

fn fail(what: []const u8) noreturn {
    libc.klog("[entrytest] FAIL\n");
    libc.print("\x1b[31m[entrytest] FAIL: ");
    libc.print(what);
    libc.print("\x1b[0m\n");
    libc.exitWith(0xDEAD0046);
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.print("[entrytest] starting\n");

    if (int80(SYS_GETPID, 0, 0, 0) != libc.getpid()) fail("getpid through int 0x80 is not getpid");
    if (!xmmKept()) fail("int 0x80 came back with other values in the XMM registers");

    libc.klog("[entrytest] OK\n");
    libc.print("\x1b[32m[entrytest] OK (int 0x80: result, XMM state)\x1b[0m\n");
    libc.exitWith(0xCAFE0046);
}
