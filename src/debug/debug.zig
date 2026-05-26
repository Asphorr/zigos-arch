const std = @import("std");
const vga = @import("../ui/vga.zig");
const serial = @import("serial.zig");

/// CPU state pushed by unified ISR stub. Matches stack layout exactly.
/// In x86_64 long mode, the CPU always pushes SS:RSP (even for same-privilege).
pub const CpuState = packed struct {
    // Pushed by ISR stub (reverse order — first pushed = highest offset)
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
    // Pushed by exception stub
    int_no: u64,
    error_code: u64,
    // Pushed by CPU (always, including same-privilege in long mode)
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

/// Print to both VGA and serial simultaneously.
pub fn klog(comptime format: []const u8, args: anytype) void {
    serial.print(format, args);
    vga.print(format, args);
}

/// Recoverable-warning facade. Use for "this shouldn't happen, but we
/// can keep going" — sibling to klog (info) and panic (fatal). Logs a
/// [kwarn] line with the source location plus a bump of the global
/// warn_count counter. The counter turns "did this fire?" into a
/// metric instead of relying on a human scanning logs.
///
/// Discipline:
///   * klog  — normal informational output, expected events.
///   * kwarn — invariant violated but recovery is correct. Should be
///             rare; non-zero count at shutdown is itself a finding.
///   * panic — invariant violated AND we can't reason about subsequent
///             state. Aborts.
///
/// Mirrors Linux's WARN_ON / BUG_ON distinction.
pub var warn_count: u64 = 0;

pub fn kwarn(comptime src: std.builtin.SourceLocation, comptime fmt: []const u8, args: anytype) void {
    _ = @atomicRmw(u64, &warn_count, .Add, 1, .monotonic);
    klog("[kwarn] {s}:{d}: ", .{ src.file, src.line });
    klog(fmt, args);
    // Caller is expected to provide the trailing newline if multi-line;
    // for one-liners we add one here.
    if (fmt.len == 0 or fmt[fmt.len - 1] != '\n') klog("\n", .{});
}

/// Dump full CPU state to both VGA and serial.
pub fn dumpState(state: *const CpuState) void {
    klog("  RAX={X:0>16} RBX={X:0>16} RCX={X:0>16} RDX={X:0>16}\n", .{ state.rax, state.rbx, state.rcx, state.rdx });
    klog("  RSI={X:0>16} RDI={X:0>16} RBP={X:0>16} RSP={X:0>16}\n", .{ state.rsi, state.rdi, state.rbp, state.rsp });
    klog("  R8 ={X:0>16} R9 ={X:0>16} R10={X:0>16} R11={X:0>16}\n", .{ state.r8, state.r9, state.r10, state.r11 });
    klog("  R12={X:0>16} R13={X:0>16} R14={X:0>16} R15={X:0>16}\n", .{ state.r12, state.r13, state.r14, state.r15 });
    klog("  RIP={X:0>16} RFLAGS={X:0>16} ERR={X:0>16}\n", .{ state.rip, state.rflags, state.error_code });
    klog("  CS={X:0>4} SS={X:0>4}\n", .{ state.cs, state.ss });

    if (state.int_no == 14) {
        const cr2 = asm volatile ("mov %%cr2, %[ret]"
            : [ret] "=r" (-> u64),
        );
        klog("  CR2={X:0>16} (faulting address)\n", .{cr2});
    }
}

/// Heuristically map a crash signature to a one-line "likely cause" hint. The
/// goal isn't accuracy — it's nudging the next debugger toward the right
/// neighborhood the same way a senior engineer reading a panic would say
/// *"that smells like…"*. If you find yourself often hitting a class of crash
/// the classifier doesn't name, add a branch.
///
/// Inputs available at the panic site:
///   `int_no`     — the exception vector (only meaningful for #PF/#GP/#UD; for
///                  generic kernel panics pass 255)
///   `rip`        — saved RIP at fault
///   `cr2`        — faulting address (only meaningful for #PF)
///   `rsp`        — saved RSP at fault (used for stack-overflow detection)
pub fn classifyCrash(int_no: u64, rip: u64, cr2: u64, rsp: u64) []const u8 {
    // Kernel `.text` heuristic — kernel is loaded around 0x100000–0x4000000.
    const rip_in_kernel = rip >= 0x100000 and rip < 0x4000000;
    const rip_in_user = rip >= 0x400000 and rip < 0x500000;

    return switch (int_no) {
        // #UD — invalid opcode
        6 => if (rip_in_kernel)
            "Likely cause: jumped to corrupt return address (stack smash) or wrong codegen target"
        else if (rip == 0)
            "Likely cause: called through a null function pointer"
        else
            "Likely cause: ran off the end of valid code; check return-address smashing",

        // #GP — general protection fault
        13 => if (rip_in_kernel)
            "Likely cause: stack misalignment for SSE move (recheck push counts in trampolines)"
        else
            "Likely cause: bad segment / canonical address / privileged insn from user",

        // #PF — page fault
        14 => blk: {
            // Definitive: cr2 in a kstack pool guard region → kernel stack
            // overflow, full stop. Beats the heuristic below.
            if (@import("../proc/process.zig").addrInKstackGuard(@intCast(cr2)) != null) {
                break :blk "Likely cause: kernel stack overflow — guard page hit; reduce locals or bump KSTACK_SIZE";
            }
            // Heuristic fallback: cr2 within ~16KB of saved RSP for non-pool
            // stacks (BSP boot stack, ISR stacks, AP stacks).
            const guard: u64 = 16 * 4096;
            if (rip_in_kernel and (cr2 +% guard >= rsp) and cr2 < rsp +% 0x1000) {
                break :blk "Likely cause: kernel stack overflow (canary?) — bump stack or reduce locals";
            }
            if (cr2 == 0) break :blk "Likely cause: null-pointer deref";
            if (rip_in_user and cr2 < 0x100000) break :blk "Likely cause: user app deref'd low address (uninit pointer?)";
            break :blk "Likely cause: non-present page or USER-bit mismatch (lazy region not faulted in?)";
        },

        // Generic kernel panic / @panic call
        255 => if (rip == 0 or (!rip_in_kernel and !rip_in_user))
            "Likely cause: corrupt return address propagated to panic handler"
        else if (rip_in_kernel)
            "Likely cause: invariant violation — see message above; check recent inline-asm or ABI edits"
        else
            "Likely cause: user-mode trap escalated to kernel panic",

        else => "(no specific hint for this exception class)",
    };
}

/// Kernel assertion — panics with message if condition is false.
/// Use for invariant checks at critical points.
pub inline fn kassert(ok: bool, comptime msg: []const u8) void {
    if (!ok) @panic("ASSERT: " ++ msg);
}

/// Kernel assertion with a value — panics and logs the value if condition is false.
pub fn kassertVal(ok: bool, comptime msg: []const u8, val: anytype) void {
    if (!ok) {
        serial.print("[ASSERT FAIL] " ++ msg ++ " val=0x{X}\n", .{val});
        @panic("ASSERT: " ++ msg);
    }
}

/// Dump CPU state to serial only (for crash logs, doesn't touch VGA).
pub fn dumpStateSerial(state: *const CpuState) void {
    serial.print("  RAX={X:0>16} RBX={X:0>16} RCX={X:0>16} RDX={X:0>16}\n", .{ state.rax, state.rbx, state.rcx, state.rdx });
    serial.print("  RSI={X:0>16} RDI={X:0>16} RBP={X:0>16} RSP={X:0>16}\n", .{ state.rsi, state.rdi, state.rbp, state.rsp });
    serial.print("  R8 ={X:0>16} R9 ={X:0>16} R10={X:0>16} R11={X:0>16}\n", .{ state.r8, state.r9, state.r10, state.r11 });
    serial.print("  R12={X:0>16} R13={X:0>16} R14={X:0>16} R15={X:0>16}\n", .{ state.r12, state.r13, state.r14, state.r15 });
    serial.print("  RIP={X:0>16} RFLAGS={X:0>16} ERR={X:0>16}\n", .{ state.rip, state.rflags, state.error_code });
    serial.print("  CS={X:0>4} SS={X:0>4}\n", .{ state.cs, state.ss });
    if (state.int_no == 14) {
        const cr2 = asm volatile ("mov %%cr2, %[ret]"
            : [ret] "=r" (-> u64),
        );
        serial.print("  CR2={X:0>16}\n", .{cr2});
    }
}
