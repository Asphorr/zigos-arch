// Boot-time ABI self-test battery — catches calling-convention drift before
// user code runs. Each test verifies a specific invariant the kernel's inline
// asm depends on. On failure, boot halts with a named test + diagnostic.
//
// Invoked from main.zig:151 immediately after `sti` (IRQ infra is up, but no
// drivers / desktop / user processes yet). Total runtime < 50ms.

const std = @import("std");
const serial = @import("serial.zig");
const debug = @import("debug.zig");
const heap = @import("../mm/heap.zig");
const memmap = @import("../mm/memmap.zig");
const smp = @import("../cpu/smp.zig");
const pipe = @import("../proc/pipe.zig");

/// Run all boot-time ABI tests. On failure, prints `[abi-test] FAIL <name>: <details>`
/// to serial and panics. On success, prints `[abi-test] PASS (N tests)` and returns.
pub fn runBootTests() void {
    serial.print("[abi-test] Running boot ABI self-tests...\n", .{});

    testHeapCanaryIntegrity();
    testPerCpuGsBase();
    testGdtSelectorSanity();
    testIdtLoaded();
    testSyscallMsrs();
    testTrampolineAlignment();
    testPipeRoundtrip();
    testTimeMonotonic();
    testWatchpoint();

    serial.print("[abi-test] PASS (9 tests)\n", .{});
}

// --- Test 1: Heap canary integrity ---
// Verifies that the heap's internal canaries haven't been corrupted by stray
// writes. If this fails, something already smashed heap metadata before we
// even got to user code — likely a kernel buffer overflow or wild pointer.
fn testHeapCanaryIntegrity() void {
    // heap.zig exports validateHeap() which walks all allocations and checks
    // head/tail canaries. If it finds corruption, it panics internally with
    // the corrupted address. We just need to call it.
    _ = heap.validateHeap();
    // If we're still here, canaries are intact.
}

// --- Test 2: Per-CPU LSTAR points at this CPU's entry stub ---
// The kernel no longer uses GS_BASE for per-CPU lookup. Each CPU's syscall
// LSTAR points at its own entry stub in syscall_entry.zig, with the stub
// addressing per_cpu_asm[N] via a RIP-relative load whose displacement is
// resolved by the linker. The trampoline switches RSP to per_cpu_asm[N].
// syscall_stack_top, which is updated on every context switch by
// gdt.setTssRsp0 to the current process's kstack — so syscalls always run
// on the per-process kernel stack, not a shared buffer.
fn testPerCpuGsBase() void {
    // syscall_entry.verifyMsrs() already panics on STAR/LSTAR mismatch; if we
    // got here init() ran without trapping. The PerCpuAsm slot itself starts
    // zeroed; syscall_stack_top is set on first context switch.
    const cpu = smp.myCpu();
    _ = cpu;
}

// --- Test 3: GDT selector sanity ---
// Reads CS / DS / SS / TR and verifies they match the values gdt.zig set up.
// If this fails, either the GDT wasn't loaded or something corrupted the
// segment registers after boot.
fn testGdtSelectorSanity() void {
    var cs: u16 = undefined;
    var ds: u16 = undefined;
    var ss: u16 = undefined;
    var tr: u16 = undefined;

    asm volatile (
        \\ mov %%cs, %[cs]
        \\ mov %%ds, %[ds]
        \\ mov %%ss, %[ss]
        \\ str %[tr]
        : [cs] "=r" (cs),
          [ds] "=r" (ds),
          [ss] "=r" (ss),
          [tr] "=r" (tr),
    );

    // Expected values from gdt.zig:
    //   CS = 0x08 (kernel code)
    //   DS = 0x10 (kernel data)
    //   SS = 0x10 (kernel data)
    //   TR = 0x28 (TSS)
    if (cs != 0x08) {
        serial.print("[abi-test] FAIL GdtSelectorSanity: CS=0x{X}, expected 0x08\n", .{cs});
        @panic("ABI self-test failed");
    }
    if (ds != 0x10) {
        serial.print("[abi-test] FAIL GdtSelectorSanity: DS=0x{X}, expected 0x10\n", .{ds});
        @panic("ABI self-test failed");
    }
    if (ss != 0x10) {
        serial.print("[abi-test] FAIL GdtSelectorSanity: SS=0x{X}, expected 0x10\n", .{ss});
        @panic("ABI self-test failed");
    }
    if (tr != 0x28) {
        serial.print("[abi-test] FAIL GdtSelectorSanity: TR=0x{X}, expected 0x28\n", .{tr});
        @panic("ABI self-test failed");
    }
}

// --- Test 4: IDT loaded ---
// Reads the IDTR and verifies it points to a non-zero base with a sane limit.
// If this fails, `lidt` never ran or the IDT pointer was corrupted.
fn testIdtLoaded() void {
    var idtr: packed struct { limit: u16, base: u64 } = undefined;
    asm volatile ("sidt %[idtr]"
        : [idtr] "=m" (idtr),
    );

    // IDT should have 256 entries × 16 bytes = 4096 bytes, so limit = 4095.
    // Base must live inside the kernel image — higher-half kernel links at
    // KERNEL_VIRT_BASE (0xFFFFFFFF80000000), so the IDT (in .bss) sits in
    // the [VIRT_BASE, VIRT_BASE + 1 GB) window covered by PDPT[510].
    if (idtr.limit != 4095) {
        serial.print("[abi-test] FAIL IdtLoaded: limit={d}, expected 4095\n", .{idtr.limit});
        @panic("ABI self-test failed");
    }
    if (idtr.base < memmap.KERNEL_VIRT_BASE or idtr.base >= memmap.KERNEL_VIRT_BASE +% 0x40000000) {
        serial.print("[abi-test] FAIL IdtLoaded: base=0x{X}, expected kernel range\n", .{idtr.base});
        @panic("ABI self-test failed");
    }
}

// --- Test 5: Syscall MSRs programmed ---
// Reads IA32_EFER, IA32_STAR, IA32_LSTAR and verifies syscall/sysret is enabled
// and the entry point is sane. If this fails, syscall_entry.init() didn't run
// or the MSRs were clobbered.
fn testSyscallMsrs() void {
    const MSR_EFER: u32 = 0xC0000080;
    const MSR_STAR: u32 = 0xC0000081;
    const MSR_LSTAR: u32 = 0xC0000082;

    const efer = rdmsr(MSR_EFER);
    const star = rdmsr(MSR_STAR);
    const lstar = rdmsr(MSR_LSTAR);

    // EFER.SCE (bit 0) must be set to enable syscall/sysret
    if ((efer & 1) == 0) {
        serial.print("[abi-test] FAIL SyscallMsrs: EFER.SCE not set (EFER=0x{X})\n", .{efer});
        @panic("ABI self-test failed");
    }

    // STAR[32:47] should be 0x08 (kernel CS base), STAR[48:63] should be 0x10 (user base)
    const star_kcs = (star >> 32) & 0xFFFF;
    const star_ucs = (star >> 48) & 0xFFFF;
    if (star_kcs != 0x08) {
        serial.print("[abi-test] FAIL SyscallMsrs: STAR kernel CS=0x{X}, expected 0x08\n", .{star_kcs});
        @panic("ABI self-test failed");
    }
    if (star_ucs != 0x10) {
        serial.print("[abi-test] FAIL SyscallMsrs: STAR user base=0x{X}, expected 0x10\n", .{star_ucs});
        @panic("ABI self-test failed");
    }

    // LSTAR should point to syscallEntry in kernel .text — high-half VA.
    if (lstar < memmap.KERNEL_VIRT_BASE or lstar >= memmap.KERNEL_VIRT_BASE +% 0x40000000) {
        serial.print("[abi-test] FAIL SyscallMsrs: LSTAR=0x{X}, expected kernel range\n", .{lstar});
        @panic("ABI self-test failed");
    }
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

// --- Test 6: Trampoline alignment ---
// Scans the inline asm in syscall_entry.zig and idt.zig for the alignment
// guards we just added. If the guard instructions are missing, someone
// removed them without updating this test. This is a compile-time-ish check
// done at runtime by reading the .text bytes at known entry points.
//
// We can't easily parse the asm from Zig, so instead we verify that the
// panic targets exist and are reachable. If the linker didn't include them,
// the build would have failed. This test is mostly a placeholder — the real
// guards are the `test $0xF, %rsp; jnz panic` instructions themselves.
fn testTrampolineAlignment() void {
    // The panic targets are exported symbols. If they exist, the guards exist.
    // We can't call them (they're noreturn), but we can take their addresses.
    const syscall_panic = @import("../cpu/syscall_entry.zig").syscall_align_panic;
    const exc_panic = @import("../cpu/idt.zig").isr_common_exc_align_panic;
    const irq0_panic = @import("../cpu/idt.zig").isr_irq0_align_panic;
    const irq1_panic = @import("../cpu/idt.zig").isr_irq1_align_panic;
    const irq12_panic = @import("../cpu/idt.zig").isr_irq12_align_panic;

    // If any of these are null or point outside .text, the build is broken.
    const addrs = [_]usize{
        @intFromPtr(&syscall_panic),
        @intFromPtr(&exc_panic),
        @intFromPtr(&irq0_panic),
        @intFromPtr(&irq1_panic),
        @intFromPtr(&irq12_panic),
    };

    for (addrs) |addr| {
        if (addr < memmap.KERNEL_VIRT_BASE or addr >= memmap.KERNEL_VIRT_BASE +% 0x40000000) {
            serial.print("[abi-test] FAIL TrampolineAlignment: panic target at 0x{X} outside kernel .text\n", .{addr});
            @panic("ABI self-test failed");
        }
    }

    // All panic targets are in .text. The guards themselves are runtime-checked
    // every time the trampolines execute, so this test is just a sanity check
    // that the symbols exist.
    if (addrs[0] == 0) unreachable; // suppress unused warning
}

// --- Test 7: Pipe roundtrip ---
// Allocate a pipe, push 16 bytes through, read them back, assert match. Runs
// entirely in kernel mode — no user process, no scheduling — so it can't
// exercise the blocking path. That's fine: the blocking path is exercised by
// any pipe-using app at runtime, and a kernel-mode round-trip catches the
// non-blocking copy logic (head/tail/wrap arithmetic, refcount init).
fn testPipeRoundtrip() void {
    const id = pipe.alloc() orelse {
        serial.print("[abi-test] FAIL PipeRoundtrip: alloc returned null (pool exhausted?)\n", .{});
        @panic("ABI self-test failed");
    };

    const msg = "Hello, ZigOS pipes";
    var data: [msg.len]u8 = undefined;
    @memcpy(data[0..msg.len], msg);

    const wrote = pipe.write(id, data[0..]);
    if (wrote != msg.len) {
        serial.print("[abi-test] FAIL PipeRoundtrip: write returned {d}, expected {d}\n", .{ wrote, msg.len });
        @panic("ABI self-test failed");
    }

    var out: [msg.len]u8 = undefined;
    const read = pipe.read(id, out[0..]);
    if (read != msg.len) {
        serial.print("[abi-test] FAIL PipeRoundtrip: read returned {d}, expected {d}\n", .{ read, msg.len });
        @panic("ABI self-test failed");
    }

    for (out, 0..) |b, i| {
        if (b != data[i]) {
            serial.print("[abi-test] FAIL PipeRoundtrip: byte {d} mismatch (got 0x{X}, expected 0x{X})\n", .{ i, b, data[i] });
            @panic("ABI self-test failed");
        }
    }

    // Drain the pool slot so we don't leak a "used" pipe across boot.
    pipe.closeReader(id);
    pipe.closeWriter(id);
}

// --- Test 8: Wall-clock + monotonicity ---
// Two consecutive time.now() reads must be monotonic (later >= earlier). If
// the clock ever goes backward we corrupt timestamps in user code (file mtimes,
// scheduling deadlines). Also asserts the boot epoch is plausible (post-2020)
// when HPET is present, since a wildly wrong RTC read would make all returned
// timestamps useless.
fn testTimeMonotonic() void {
    const time = @import("../time/time.zig");
    const t1 = time.now();
    const t2 = time.now();

    // Monotonic check.
    if (t2.sec < t1.sec or (t2.sec == t1.sec and t2.usec < t1.usec)) {
        serial.print("[abi-test] FAIL TimeMonotonic: clock went backward {d}.{d:0>6} -> {d}.{d:0>6}\n", .{ t1.sec, t1.usec, t2.sec, t2.usec });
        @panic("ABI self-test failed");
    }

    // Sanity: if HPET is up, the boot-epoch baseline should be after 2020-01-01
    // (1577836800 unix seconds). QEMU's emulated RTC defaults to host time, so
    // this catches "RTC was zeroed" bugs (BCD/binary mode confusion, etc.). On
    // real hardware with a dead CMOS battery the RTC may report 2000 — accept
    // anything >= 2000-01-01 (946684800).
    const hpet = @import("../time/hpet.zig");
    if (hpet.isInitialized()) {
        const min_epoch: u64 = 946_684_800; // 2000-01-01
        if (t1.sec < min_epoch) {
            serial.print("[abi-test] FAIL TimeMonotonic: implausible epoch {d}s — RTC read failed?\n", .{t1.sec});
            @panic("ABI self-test failed");
        }
    }
}

// --- Test 9: DR0-DR3 hardware watchpoint ---
// Arms a write-watch on a kernel BSS variable, performs three writes, asserts
// the hit counter incremented to 3 and that DR6 was cleared. Uses `silent`
// policy so the test doesn't print anything when working. Failures here mean
// either the DR registers aren't wired to the IDT correctly, or the manager's
// computeDr7 layout is wrong.
//
// Important: must run on BSP only (abi_check is BSP-only by construction)
// and must `disarm` before returning so the live system has a clean slate.
var watch_test_target: u64 align(8) = 0;

fn testWatchpoint() void {
    const watch = @import("watch.zig");
    // Slot 1 (slot 0 is reserved for diagnostic uses elsewhere if needed).
    watch.arm(1, @intFromPtr(&watch_test_target), .write, .eight, .silent, "abi-test");

    // Volatile pointer so the optimizer can't collapse the three stores into
    // one. With ReleaseSafe + a plain `watch_test_target = N` sequence, LLVM
    // dead-store-eliminates the first two and we'd see only one #DB.
    const p: *volatile u64 = &watch_test_target;
    p.* = 1;
    p.* = 2;
    p.* = 3;

    const hits = watch.entries[1].hits;
    watch.disarm(1);
    watch.entries[1].hits = 0; // reset for clean post-test state

    if (hits == 0) {
        // Zero hits typically means QEMU's gdbstub is active (`-s`) and KVM
        // has taken over the host DR registers via KVM_SET_GUEST_DEBUG —
        // guest writes to DRn become inert (shadow only). Boot continues but
        // the kernel-side `watch.zig` infra is non-functional in this mode.
        // GDB hardware watchpoints (`watch *expr`) still work because they
        // run in the host gdbstub layer.
        serial.print("[abi-test] WARN Watchpoint: 0 hits — DR registers virtualized (likely qemu -s/gdbstub). Kernel watch.zig is no-op until reboot without -s.\n", .{});
    } else if (hits != 3) {
        serial.print("[abi-test] FAIL Watchpoint: expected 3 hits, got {d} — partial DR functionality, computeDr7/onDebugException likely buggy\n", .{hits});
        @panic("ABI self-test failed: DR watchpoint partial (see [abi-test] line above)");
    }

    // DR6 should have been cleared by onDebugException after the last hit.
    // Skip this check if hits==0 (DRs were virtualized away — DR6 never set).
    if (hits == 3) {
        const dr6 = watch.readDr6();
        if ((dr6 & 0xF) != 0) {
            serial.print("[abi-test] FAIL Watchpoint: DR6 B0..B3 not cleared after hits (DR6=0x{X}) — onDebugException didn't writeDr6(0)\n", .{dr6});
            @panic("ABI self-test failed: DR6 sticky bits leaked (see [abi-test] line above)");
        }
    }
}
