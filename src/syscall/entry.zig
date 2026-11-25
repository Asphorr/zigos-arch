// The SYSCALL entry: the MSRs that arm it on a CPU, and the code LSTAR
// points at.
//
// SYSCALL switches no stack and leaves every register spoken for — rcx and
// r11 hold the user's RIP and RFLAGS, rax the call's number, the rest its
// arguments or the caller's own. What is free, and already per-CPU, is RIP:
// LSTAR is an MSR. So each CPU enters at a head of its own, a few
// instructions that know their CPU by where they stand; they put RSP on the
// task's kernel stack and jump to the one body all CPUs share.
//
// The kernel stack is `cpus[N].tss.rsp0` — the field the hardware itself
// reads on an interrupt from ring 3, so the two ways in land on one stack
// by construction and there is no second copy to drift.
//
// No GS base and no swapgs: nothing to pair up on every kernel↔user edge,
// and no window in which an NMI finds the kernel on the user's GS.
//
// `init()` runs on each CPU (the `syscall` entry of cpu/cpu_state.zig) and
// points that CPU's LSTAR at that CPU's head.

const smp = @import("../cpu/smp.zig");
const gdt = @import("../cpu/arch/gdt.zig");
const std = @import("std");
const msr = @import("../cpu/arch/msr.zig");
const rflags = @import("../cpu/arch/cr.zig").rflags;
const frames = @import("../proc/frames.zig");

const sc = frames.syscall;
const dec = frames.decimal;

/// SYSCALL loads CS from STAR[47:32] and SS from that + 8. SYSRET to 64-bit
/// code loads SS from STAR[63:48] + 8 and CS from STAR[63:48] + 16, both
/// with RPL 3 — which is why the GDT has user data under user code.
const sysret_base: u16 = (gdt.sel.user_data & ~@as(u16, 3)) - 8;
const STAR_VALUE: u64 = (@as(u64, gdt.sel.kernel_code) << 32) | (@as(u64, sysret_base) << 48);

comptime {
    std.debug.assert(gdt.sel.kernel_data == gdt.sel.kernel_code + 8);
    std.debug.assert(gdt.sel.user_code == (sysret_base + 16) | 3);
    std.debug.assert(STAR_VALUE == (@as(u64, 0x08) << 32) | (@as(u64, 0x10) << 48));
}

/// Initialize syscall/sysret support on the calling CPU. Picks this CPU's
/// dedicated entry head and writes it to LSTAR.
pub fn init() void {
    const debug = @import("../debug/debug.zig");

    // Enable syscall/sysret in EFER (SCE) and NX execution control (NXE).
    // NXE makes the CPU honor PTE bit 63 (NX) — without it mprotect's NX
    // flag would be silently ignored. Both are per-CPU MSRs so every AP runs
    // through this path.
    var efer = msr.read(msr.EFER);
    debug.klog("[syscall] EFER before: 0x{X:0>16}\n", .{efer});
    efer |= msr.Efer.SCE | msr.Efer.NXE;
    msr.write(msr.EFER, efer);
    efer = msr.read(msr.EFER);
    debug.klog("[syscall] EFER after: 0x{X:0>16}\n", .{efer});

    msr.write(msr.STAR, STAR_VALUE);
    debug.klog("[syscall] STAR: 0x{X:0>16}\n", .{STAR_VALUE});

    // LSTAR: this CPU's own head, by the id myCpu() indexes cpus[] with.
    // Not by the LAPIC ID register: the boot CPU gets here before its LAPIC
    // mode is set, and is CPU 0 whatever that register would say.
    const my_id = smp.myCpuId();
    const head_addr = @intFromPtr(cpu_entries[my_id]);
    msr.write(msr.LSTAR, head_addr);
    debug.klog("[syscall] LSTAR(cpu{d}): 0x{X:0>16}\n", .{ my_id, head_addr });

    // SFMASK clears IF: the entry runs on the user RSP until it has switched
    // stacks. doSyscall enables interrupts for the handler body only. It
    // clears DF too: user code may enter with DF=1 (musl's backward memmove
    // is `std; rep movsb; cld`), and the kernel's rep-string memcpy/memset
    // would then run backwards. TF too: a single step would trap at the
    // head's first instruction, in ring 0 on the user's RSP. And NT: an
    // iretq with it set faults. SYSRET restores the user's own from R11.
    msr.write(msr.SFMASK, rflags.TF | rflags.IF | rflags.DF | rflags.IOPL | rflags.NT);
    debug.klog("[syscall] syscall/sysret initialized\n", .{});
}

/// Sanity-check the per-CPU syscall MSRs on the *calling CPU*. Halts loudly
/// on mismatch — boot regression tripwire that catches "AP forgot to call
/// init()" and "BSP MSR overwritten by some later code" alike. Cheap (4 rdmsr,
/// no allocations); call after init() on every CPU.
pub fn verifyMsrs(cpu_label: []const u8) void {
    const debug = @import("../debug/debug.zig");
    const efer = msr.read(msr.EFER);
    const star = msr.read(msr.STAR);
    const lstar = msr.read(msr.LSTAR);

    if (efer & msr.Efer.SCE == 0) {
        debug.klog("[syscall-verify] FAIL {s}: EFER.SCE=0 (efer=0x{X})\n", .{ cpu_label, efer });
        @panic("syscall MSR verify: EFER.SCE not set");
    }
    if (star != STAR_VALUE) {
        debug.klog("[syscall-verify] FAIL {s}: STAR=0x{X:0>16} expected 0x{X:0>16}\n", .{ cpu_label, star, STAR_VALUE });
        @panic("syscall MSR verify: STAR mismatch");
    }
    const my_id = smp.myCpuId();
    const expected_lstar: u64 = @intFromPtr(cpu_entries[my_id]);
    if (lstar != expected_lstar) {
        debug.klog("[syscall-verify] FAIL {s}: LSTAR=0x{X:0>16} expected 0x{X:0>16}\n", .{ cpu_label, lstar, expected_lstar });
        @panic("syscall MSR verify: LSTAR mismatch");
    }
    debug.klog("[syscall-verify] OK {s}: EFER.SCE=1 STAR ok LSTAR(cpu{d})=0x{X}\n", .{ cpu_label, my_id, lstar });
}

extern fn doSyscall(num: u32, arg1: u32, arg2: u32, arg3: u32, frame: ?*anyopaque) callconv(.c) u64;

/// One CPU's way in: all of the entry that depends on which CPU it is.
///
/// Layout the two operands rest on (asserted in smp.zig):
///   per_cpu_user_rsp[N] = per_cpu_user_rsp + N*8
///   cpus[N].tss.rsp0    = cpus + N*sizeOf(CpuLocal) + offsetOf(tss) + offsetOf(rsp0)
/// and the 8-byte read of rsp0 does not straddle a cache line, so this CPU
/// sees its own setTssRsp0 whole.
fn CpuEntry(comptime cpu_id: u8) type {
    const user_rsp_slot = std.fmt.comptimePrint("per_cpu_user_rsp+{d}(%%rip)", .{@as(usize, cpu_id) * 8});
    const rsp0_off = std.fmt.comptimePrint("{d}", .{
        @as(usize, cpu_id) * @sizeOf(smp.CpuLocal) + @offsetOf(smp.CpuLocal, "tss") + @offsetOf(gdt.Tss64, "rsp0"),
    });
    return struct {
        pub fn entry() callconv(.naked) noreturn {
            asm volatile (
            // The slot is a bridge. The copy that lasts is the push below,
            // on the task's own stack: a task that blocks in its call leaves
            // this CPU, and the slot, to the next one.
                "movq %%rsp, " ++ user_rsp_slot ++ "\n" ++
                    // RSP is the one register free to compute with, and
                    // nothing can push while it holds &cpus[0]: IF is off
                    // (SFMASK) and an NMI has a stack of its own (IST2).
                    // Through cpus_base because CpuLocal is not extern-
                    // compatible (see smp.zig).
                    "movq cpus_base(%%rip), %%rsp\n" ++
                    "movq " ++ rsp0_off ++ "(%%rsp), %%rsp\n" ++
                    "pushq " ++ user_rsp_slot ++ "\n" ++
                    "jmp syscall_entry_common\n");
        }
    };
}

// One head per possible CPU. Each CpuEntry(i) is a distinct type, hence a
// distinct function. The quota: comptimePrint, twice per head.
const cpu_entries = blk: {
    @setEvalBranchQuota(@as(u32, smp.MAX_CPUS) * 2000 + 5000);
    var arr: [smp.MAX_CPUS]*const fn () callconv(.naked) noreturn = undefined;
    for (0..smp.MAX_CPUS) |i| {
        arr[i] = &CpuEntry(@as(u8, i)).entry;
    }
    break :blk arr;
};

/// The exit that gives every register back (rt_sigreturn): rcx and r11
/// too, which sysret needs for itself, so it leaves by iretq. The record
/// is built in the FXSAVE image, free once fxrstor has read it, from the
/// frame's slots sysret would have used; rax is the call's result.
const full_restore: []const u8 = blk: {
    var text: []const u8 =
        "movq " ++ dec(sc.offset(.rcx)) ++ "(%%rsp), %%rcx\n" ++ // the frame's rcx: rip
        "movq %%rcx, " ++ dec(sc.iretqOffset(.rip)) ++ "(%%rsp)\n" ++
        "movq $" ++ dec(gdt.sel.user_code) ++ ", " ++ dec(sc.iretqOffset(.cs)) ++ "(%%rsp)\n" ++
        "movq " ++ dec(sc.offset(.r11)) ++ "(%%rsp), %%rcx\n" ++ // the frame's r11: rflags
        "movq %%rcx, " ++ dec(sc.iretqOffset(.rflags)) ++ "(%%rsp)\n" ++
        "movq " ++ dec(sc.user_rsp_offset) ++ "(%%rsp), %%rcx\n" ++
        "movq %%rcx, " ++ dec(sc.iretqOffset(.rsp)) ++ "(%%rsp)\n" ++
        "movq $" ++ dec(gdt.sel.user_data) ++ ", " ++ dec(sc.iretqOffset(.ss)) ++ "(%%rsp)\n" ++
        "movq " ++ dec(sc.full_rcx_offset) ++ "(%%rsp), %%rcx\n" ++
        "movq " ++ dec(sc.full_r11_offset) ++ "(%%rsp), %%r11\n";
    for (sc.saved.regs) |r| {
        if (r == .rcx or r == .r11) continue;
        text = text ++ "movq " ++ dec(sc.offset(r)) ++ "(%%rsp), %%" ++ @tagName(r) ++ "\n";
    }
    break :blk text ++
        "addq $" ++ dec(sc.iretq_offset) ++ ", %%rsp\n" ++
        "iretq\n";
};

/// Where every head jumps: RSP on the task's kernel stack, the user's RSP
/// pushed, every other register still the user's. Builds frames.syscall,
/// calls doSyscall with the frame, and leaves the way the frame's exit
/// mode says.
export fn syscall_entry_common() callconv(.naked) noreturn {
    asm volatile (sc.saved.push_asm ++
            // The call's ABI to SysV's: rax = number and rdi, rsi, rdx =
            // arguments become rdi, rsi, rdx, rcx. The user's own values
            // are in the frame by now, where signal delivery rewrites them
            // and sigreturn puts them back.
            "movq %%rdx, %%rcx\n" ++
            "movq %%rsi, %%rdx\n" ++
            "movq %%rdi, %%rsi\n" ++
            "movq %%rax, %%rdi\n" ++
            "subq $" ++ dec(sc.fp_below) ++ ", %%rsp\n" ++
            "movq $0, " ++ dec(sc.exit_mode_offset) ++ "(%%rsp)\n" ++ // leave by sysret
            "fxsaveq (%%rsp)\n" ++
            "leaq " ++ dec(sc.fp_below) ++ "(%%rsp), %%r8\n" ++ // 5th argument: the frame
            // tss.rsp0 is the one thing the layout cannot vouch for.
            "testq $0xF, %%rsp\n" ++
            "jnz syscall_align_panic\n" ++
            "call doSyscall\n" ++
            // doSyscall returns with IF off; this makes it structural. From
            // `popq %rsp` to sysretq RSP is the user's, in ring 0, where no
            // interrupt may land.
            "cli\n" ++
            "fxrstorq (%%rsp)\n" ++
            "cmpq $0, " ++ dec(sc.exit_mode_offset) ++ "(%%rsp)\n" ++
            "jne 7f\n" ++
            "addq $" ++ dec(sc.fp_below) ++ ", %%rsp\n" ++
            sc.saved.pop_asm ++
            // The frame's last word is the user's RSP. What popq would add
            // to RSP is lost in the load, and need not be kept: the next
            // entry starts from tss.rsp0 again.
            "popq %%rsp\n" ++
            "sysretq\n" ++
            "7:\n" ++
            full_restore);
}

/// The entry found RSP off a 16-byte boundary at `call doSyscall`: the
/// tss.rsp0 it started from was not 16-aligned.
pub export fn syscall_align_panic() callconv(.c) noreturn {
    @panic("syscall entry: RSP misaligned at call doSyscall — tss.rsp0 is not 16-aligned");
}
