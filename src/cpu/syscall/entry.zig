// Fast syscall/sysret implementation for x86_64
// Replaces int 0x80 with native syscall instruction (40% faster).
//
// Per-CPU dispatch without GS_BASE: each CPU has its own LSTAR target — a
// dedicated naked entry stub that loads the kernel stack pointer from
// `cpus[N].tss.rsp0`, the same TSS field the CPU hardware reads on every
// IDT-gate entry. The stub does a two-instruction indirect load:
//
//   movq cpus_base(%rip), %r11   ; base = &cpus[0], stamped in smp.init()
//   movq <off>(%r11), %rsp       ; off = N*sizeOf(CpuLocal)+offsetOf(tss)+4
//
// Indirect (not RIP-relative direct) because CpuLocal isn't extern-
// compatible — see smp.zig cpus_base comment. One extra cycle on the
// syscall hot path, negligible. Both the syscall path and the IDT-gate
// path now land on the same kstack by construction — no `per_cpu_asm`
// mirror to drift.
//
// The previous design read `%gs:0` / `%gs:8` and depended on `swapgs` having
// been issued correctly on every kernel↔user CPL transition (8 sites across
// 4 files). Missing any one of them triple-faulted on the trampoline's first
// instruction. That bug class is now structurally impossible.
//
// LSTAR is naturally per-CPU (it's an MSR), and `init()` is invoked on each
// CPU separately (BSP from main, APs from `apEntry`). At init() time we read
// the calling CPU's LAPIC ID and write LSTAR to point at that CPU's stub.

const syscall = @import("../syscall.zig");
const smp = @import("../smp.zig");
const gdt = @import("../arch/gdt.zig");
const apic = @import("../../time/apic.zig");
const std = @import("std");

// MSR numbers
const MSR_STAR: u32 = 0xC0000081;
const MSR_LSTAR: u32 = 0xC0000082;
const MSR_SFMASK: u32 = 0xC0000084;
const MSR_EFER: u32 = 0xC0000080;

/// Initialize syscall/sysret support on the calling CPU. Picks this CPU's
/// dedicated entry stub via LAPIC ID and writes it to LSTAR.
pub fn init() void {
    const debug = @import("../../debug/debug.zig");

    // Enable syscall/sysret in EFER (bit 0 = SCE) and NX execution control
    // (bit 11 = NXE). NXE makes the CPU honor PTE bit 63 (NX) — without it
    // mprotect's NX flag would be silently ignored. Both are per-CPU MSRs so
    // every AP runs through this path.
    var efer = rdmsr(MSR_EFER);
    debug.klog("[syscall] EFER before: 0x{X:0>16}\n", .{efer});
    efer |= 1 | (1 << 11);
    wrmsr(MSR_EFER, efer);
    efer = rdmsr(MSR_EFER);
    debug.klog("[syscall] EFER after: 0x{X:0>16}\n", .{efer});

    // STAR: Segment selectors for syscall/sysret
    // Bits 32-47: Kernel CS/SS base (syscall loads CS from here, SS from +8)
    // Bits 48-63: User CS/SS base (sysret loads CS from here+16, SS from +8)
    //
    // Our GDT (reordered for syscall/sysret compatibility):
    // 0x00: null, 0x08: kcode, 0x10: kdata, 0x18: udata, 0x20: ucode
    //
    // syscall: CS = STAR[32:47], SS = STAR[32:47]+8
    //   Want: CS=0x08 (kcode), SS=0x10 (kdata)
    //   So: STAR[32:47] = 0x08 ✓
    //
    // sysret: CS = STAR[48:63]+16 | 3, SS = STAR[48:63]+8 | 3
    //   Want: CS=0x23 (0x20|3, ucode), SS=0x1B (0x18|3, udata)
    //   So: STAR[48:63]+16 = 0x20 → STAR[48:63] = 0x10 ✓
    //       STAR[48:63]+8 = 0x18 → STAR[48:63] = 0x10 ✓
    const star: u64 = (@as(u64, 0x08) << 32) | (@as(u64, 0x10) << 48);
    wrmsr(MSR_STAR, star);
    debug.klog("[syscall] STAR: 0x{X:0>16}\n", .{star});

    // LSTAR: this CPU's dedicated entry stub. Picking by LAPIC ID matches
    // how `myCpu()` indexes `cpus[]` in smp.zig. x2APIC hardware can hand
    // us LAPIC IDs > 255 — silently truncating to u8 would alias a high-ID
    // CPU onto cpu0's stub and race on per_cpu_user_rsp[0]; bounds-check
    // first and panic with a clear hint rather than letting the array
    // OOB-panic with a generic message.
    const id_full = apic.getLapicId();
    if (id_full >= smp.MAX_CPUS) {
        debug.klog("[syscall] LAPIC ID {d} exceeds MAX_CPUS {d}\n", .{ id_full, smp.MAX_CPUS });
        @panic("syscall init: LAPIC ID exceeds MAX_CPUS — bump smp.MAX_CPUS");
    }
    const my_id: u8 = @intCast(id_full);
    const stub_addr = @intFromPtr(cpu_entries[my_id]);
    wrmsr(MSR_LSTAR, stub_addr);
    debug.klog("[syscall] LSTAR(cpu{d}): 0x{X:0>16}\n", .{ my_id, stub_addr });

    // SFMASK: RFLAGS bits to clear on syscall (clear IF to disable interrupts)
    wrmsr(MSR_SFMASK, 0x200); // Clear IF (bit 9)
    debug.klog("[syscall] syscall/sysret initialized\n", .{});
}

/// Sanity-check the per-CPU syscall MSRs on the *calling CPU*. Halts loudly
/// on mismatch — boot regression tripwire that catches "AP forgot to call
/// init()" and "BSP MSR overwritten by some later code" alike. Cheap (4 rdmsr,
/// no allocations); call after init() on every CPU.
pub fn verifyMsrs(cpu_label: []const u8) void {
    const debug = @import("../../debug/debug.zig");
    const efer = rdmsr(MSR_EFER);
    const star = rdmsr(MSR_STAR);
    const lstar = rdmsr(MSR_LSTAR);

    if ((efer & 1) == 0) {
        debug.klog("[syscall-verify] FAIL {s}: EFER.SCE=0 (efer=0x{X})\n", .{ cpu_label, efer });
        @panic("syscall MSR verify: EFER.SCE not set");
    }
    const expected_star: u64 = (@as(u64, 0x08) << 32) | (@as(u64, 0x10) << 48);
    if (star != expected_star) {
        debug.klog("[syscall-verify] FAIL {s}: STAR=0x{X:0>16} expected 0x{X:0>16}\n", .{ cpu_label, star, expected_star });
        @panic("syscall MSR verify: STAR mismatch");
    }
    // Same x2APIC bounds rationale as init(): never silently truncate.
    const id_full = apic.getLapicId();
    if (id_full >= smp.MAX_CPUS) {
        debug.klog("[syscall-verify] FAIL {s}: LAPIC ID {d} exceeds MAX_CPUS {d}\n", .{ cpu_label, id_full, smp.MAX_CPUS });
        @panic("syscall MSR verify: LAPIC ID exceeds MAX_CPUS");
    }
    const my_id: u8 = @intCast(id_full);
    const expected_lstar: u64 = @intFromPtr(cpu_entries[my_id]);
    if (lstar != expected_lstar) {
        debug.klog("[syscall-verify] FAIL {s}: LSTAR=0x{X:0>16} expected 0x{X:0>16}\n", .{ cpu_label, lstar, expected_lstar });
        @panic("syscall MSR verify: LSTAR mismatch");
    }
    debug.klog("[syscall-verify] OK {s}: EFER.SCE=1 STAR ok LSTAR(cpu{d})=0x{X}\n", .{ cpu_label, my_id, lstar });
}

fn rdmsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | low;
}

fn wrmsr(msr: u32, value: u64) void {
    const low: u32 = @truncate(value);
    const high: u32 = @truncate(value >> 32);
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
    );
}

// --- Per-CPU syscall entry stubs ---
//
// Each stub is an independent naked function. The CPU's per-CPU slots
// are addressed as RIP-relative references to `per_cpu_user_rsp` (hot,
// unprotected) and `cpus[N].tss.rsp0` (the canonical TSS field the CPU
// hardware reads on every IDT-gate entry). No GS_BASE, no swapgs, no
// MSR reads, no duplicated state to keep in sync.
//
// Reading directly from the TSS field that the hardware itself reads
// eliminates the "two fields out of sync" desync class (cpu-alias FAIL
// on tss.rsp0 vs per_cpu_asm.syscall_stack_top, 2026-05-17): the syscall
// path and the IDT-gate path land on the *same* kstack by construction.
//
// Layout invariants (enforced in smp.zig comptime):
//   per_cpu_user_rsp[N]    = per_cpu_user_rsp + N*8
//   cpus[N].tss.rsp0       = cpus + N*sizeof(CpuLocal) + offsetOf(tss) + 4
// The smp.zig assert guarantees the 8-byte read doesn't straddle a cache
// line, so a same-CPU setTssRsp0 update is observed atomically here.

extern fn doSyscall(num: u32, arg1: u32, arg2: u32, arg3: u32, frame: *anyopaque) callconv(.c) u64;

fn CpuEntry(comptime cpu_id: u8) type {
    const off_user_rsp_str = std.fmt.comptimePrint("{d}", .{@as(usize, cpu_id) * 8});
    const tss_rsp0_off = @as(usize, cpu_id) * @sizeOf(smp.CpuLocal)
        + @offsetOf(smp.CpuLocal, "tss")
        + @offsetOf(gdt.Tss64, "rsp0");
    const off_tss_rsp0_str = std.fmt.comptimePrint("{d}", .{tss_rsp0_off});
    return struct {
        pub fn entry() callconv(.naked) noreturn {
            asm volatile (
            // Save user RSP into this CPU's user_rsp slot — TRANSIENT bridge
            // only. The persistent copy goes onto the kernel stack two lines
            // below.
                "movq %%rsp, per_cpu_user_rsp+" ++ off_user_rsp_str ++ "(%%rip)\n" ++
                    // Two-step indirect load to cpus[N].tss.rsp0. We can't
                    // safely scratch any GPR — rcx/r11 hold user RIP/RFLAGS
                    // for sysret, rax holds syscall_num, rdi/rsi/rdx/r10
                    // hold user args, callee-saves are user-owned. So we
                    // use RSP itself as the scratch: SYSCALL/SFMASK cleared
                    // IF, no IRQ can land between the two loads, and step 2
                    // overwrites RSP with the real kernel stack top before
                    // any push happens.
                    "movq cpus_base(%%rip), %%rsp\n" ++          // rsp = &cpus[0]
                    "movq " ++ off_tss_rsp0_str ++ "(%%rsp), %%rsp\n" ++ // rsp = cpus[N].tss.rsp0
                    // PUSH user RSP FIRST — ends up at the highest address among the
                    // 15 pushes, matching SyscallFrame.user_rsp's trailing position.
                    // Lifetime is now tied to the kernel stack (per-thread), so it
                    // survives int $0x20 reschedules from sysFutex/sysSleep/etc.
                    "pushq per_cpu_user_rsp+" ++ off_user_rsp_str ++ "(%%rip)\n" ++
                    // Save callee-saved + user state. Save r8/r9/r10 across the C
                    // call too — SysV-volatile, but user expects only rcx/r11 plus
                    // rdi/rsi/rdx (the shuffle below) to change.
                    "push %%r11\n" ++
                    "push %%rcx\n" ++
                    "push %%rbx\n" ++
                    "push %%rbp\n" ++
                    "push %%r12\n" ++
                    "push %%r13\n" ++
                    "push %%r14\n" ++
                    "push %%r15\n" ++
                    // Save user's syscall args (rdi/rsi/rdx) BEFORE the shuffle.
                    // Required so signal delivery on syscall return can rewrite
                    // these slots with handler args (signo/siginfo/ucontext) and
                    // sigreturn can restore the user's pre-syscall values.
                    "push %%rdi\n" ++
                    "push %%rsi\n" ++
                    "push %%rdx\n" ++
                    // Shuffle syscall ABI → SysV ABI. RAX=num, RDI=a1, RSI=a2,
                    // RDX=a3 → RDI=num, RSI=a1, RDX=a2, RCX=a3.
                    "mov %%rdx, %%rcx\n" ++
                    "mov %%rsi, %%rdx\n" ++
                    "mov %%rdi, %%rsi\n" ++
                    "mov %%rax, %%rdi\n" ++
                    "push %%r8\n" ++
                    "push %%r9\n" ++
                    "push %%r10\n" ++
                    // 520 = 512 FXSAVE + 8 padding. 15 prior pushes (120B)
                    // + 520 = 640, 640%16==0; CALL pushes 8 → callee at %16==8.
                    "sub $520, %%rsp\n" ++
                    "fxsaveq (%%rsp)\n" ++
                    // 5th arg to doSyscall = pointer to the saved frame (start of
                    // the GPR area, just above the 520-byte FXSAVE block). Layout
                    // matches signals.SyscallFrame — 14 u64 GPRs starting at r10,
                    // followed by user_rsp at offset 112.
                    "leaq 520(%%rsp), %%r8\n" ++
                    "test $0xF, %%rsp\n" ++
                    "jnz syscall_align_panic\n" ++
                    "call doSyscall\n" ++
                    "fxrstorq (%%rsp)\n" ++
                    "add $520, %%rsp\n" ++
                    "pop %%r10\n" ++
                    "pop %%r9\n" ++
                    "pop %%r8\n" ++
                    "pop %%rdx\n" ++
                    "pop %%rsi\n" ++
                    "pop %%rdi\n" ++
                    "pop %%r15\n" ++
                    "pop %%r14\n" ++
                    "pop %%r13\n" ++
                    "pop %%r12\n" ++
                    "pop %%rbp\n" ++
                    "pop %%rbx\n" ++
                    "pop %%rcx\n" ++
                    "pop %%r11\n" ++
                    // pop %rsp loads from [%rsp] into %rsp — gives user_rsp directly.
                    // The post-pop RSP increment is overwritten by the load, so the
                    // 8 bytes of "leak" on the kernel stack don't matter (next
                    // syscall resets RSP from cpus[N].tss.rsp0).
                    "pop %%rsp\n" ++
                    "sysretq\n");
        }
    };
}

// Materialize one entry function per CPU. Each `CpuEntry(i)` is a distinct
// type → distinct function instance, so the linker emits one stub per CPU.
// Comptime loop instantiates one slot per MAX_CPUS, so bumping the
// constant in smp.zig automatically grows the table. The eval-branch
// quota has to climb in lockstep — each CpuEntry runs comptimePrint twice
// internally and that burns ~1500 branches per CPU.
const cpu_entries = blk: {
    @setEvalBranchQuota(@as(u32, smp.MAX_CPUS) * 2000 + 5000);
    var arr: [smp.MAX_CPUS]*const fn () callconv(.naked) noreturn = undefined;
    for (0..smp.MAX_CPUS) |i| {
        arr[i] = &CpuEntry(@as(u8, i)).entry;
    }
    break :blk arr;
};

/// Reached when the inline-asm trampoline pushes a count that breaks the
/// 16-byte stack alignment expected at `call doSyscall`. If this fires,
/// re-count the pushes and adjust the `sub $N, %rsp` so push_count*8 + N ≡ 0
/// (mod 16).
pub export fn syscall_align_panic() callconv(.c) noreturn {
    @panic("syscall_entry: RSP misaligned at call doSyscall — count pushes vs sub");
}
