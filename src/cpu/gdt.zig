// TSS64 layout must match Intel spec exactly:
// Offset 0x00: reserved (4 bytes), then RSP0 at 0x04, RSP1 at 0x0C, etc.
// Using align(4) on u64 fields prevents C ABI from inserting padding after the u32.
pub const Tss64 = extern struct {
    reserved0: u32 = 0,
    rsp0: u64 align(4) = 0,
    rsp1: u64 align(4) = 0,
    rsp2: u64 align(4) = 0,
    reserved1: u64 align(4) = 0,
    ist1: u64 align(4) = 0,
    ist2: u64 align(4) = 0,
    ist3: u64 align(4) = 0,
    ist4: u64 align(4) = 0,
    ist5: u64 align(4) = 0,
    ist6: u64 align(4) = 0,
    ist7: u64 align(4) = 0,
    reserved2: u64 align(4) = 0,
    reserved3: u16 = 0,
    iomap_base: u16 = @sizeOf(Tss64),
};

// Layout invariants: the lgdt + ltr instructions and the syscall/sysret MSR
// programming all assume these exact sizes. A stray field reorder or
// alignment change would silently corrupt boot.
comptime {
    if (@sizeOf(Tss64) != 104) @compileError("Tss64 must be 104 bytes (Intel SDM Vol 3 §7.7)");
    if (@offsetOf(Tss64, "rsp0") != 4) @compileError("Tss64.rsp0 must be at offset 4");
    // GDT entries are flat u64; segment descriptor format encoded in makeEntry.
    // Anyone migrating to a struct must keep `@sizeOf(GdtEntry) == 8`.
}

// 7 GDT entries: null, kcode, kdata, ucode, udata, tss_low, tss_high
var entries: [7]u64 = undefined;

// Hardware `lgdt m16:64` reads exactly limit (offset 0, 2 bytes) + base
// (offset 2, 8 bytes). `packed` keeps `base` at byte offset 2; if a
// refactor drops `packed`, Zig aligns u64 and `base` jumps to offset 8 —
// lgdt loads garbage into GDTR.base and the next segment-load triple-
// faults silently. Comptime offset check catches it. (We don't assert
// @sizeOf because Zig may round the backing integer up to 16 bytes; the
// trailing pad bytes are after `base` and lgdt ignores them.)
pub const GdtPtr = packed struct {
    limit: u16,
    base: u64,
};
comptime {
    if (@offsetOf(GdtPtr, "base") != 2) @compileError("GdtPtr.base must be at offset 2");
}

var gdt_ptr: GdtPtr = undefined;

var tss: Tss64 = .{};

// Dedicated kernel stack for ISR handlers (used by TSS RSP0)
var isr_stack: [16384]u8 align(16) = undefined; // 16KB ISR stack

// Update the kernel stack the CPU will switch to on user→kernel transitions:
// the per-CPU TSS.RSP0. ONE field, ONE writer, ONE store.
//
// Both the IDT-gate path (CPU hardware) and the SYSCALL path (per-CPU LSTAR
// stub in syscall_entry.zig) read this same memory location, so by
// construction they land on the SAME kstack — no duplicated state to keep
// in sync. The previous design maintained a separate
// `per_cpu_asm[N].syscall_stack_top` mirror updated alongside tss.rsp0;
// the two writes could tear under a nested setTssRsp0 (cpu-alias FAIL
// 2026-05-17). Collapsing to one field makes the desync class
// structurally impossible.
//
// Atomicity: the smp.zig comptime check guarantees `cpus[N].tss.rsp0`
// lies entirely within one cache line, so this single 8-byte store is
// atomic to the syscall stub on the same CPU and to any cross-CPU reader.
//
// `pid` is the process being dispatched; `rsp0` should equal procs[pid].
// kernel_stack_top. We cross-check against process.expected_kstack_tops[pid]
// (the immutable witness recorded at create() time) — mismatch means a
// wild writer corrupted procs[pid].kernel_stack_top between create and
// dispatch, and we panic HERE pointing at the bad slot rather than letting
// the wild value leak into TSS.RSP0 and crash deep inside doSyscall.
pub fn setTssRsp0(pid: usize, rsp0: u64) void {
    const smp = @import("smp.zig");
    const process = @import("../proc/process.zig");
    // Per-PID exact match against the immutable witness set at create()
    // time. The shape-check (isValidKstackTopShape) accepted ANY value
    // that happened to be a valid pool top OR a registered heap kstack,
    // which silently passed when desktop's heap-kstack value (0x312000)
    // leaked into procs[3].kernel_stack_top — that's the wild-RIP smoking
    // gun we caught via sched ring autopsy. The expected-tops witness
    // lives in a separate static array (not inside procs[]) so a wild
    // writer scribbling inside one PCB can't simultaneously corrupt the
    // witness.
    if (!process.isValidKstackTop(pid, rsp0)) {
        const debug = @import("../debug/debug.zig");
        const expected = if (pid < @import("../config.zig").MAX_PROCS)
            @atomicLoad(usize, &process.expected_kstack_tops[pid], .acquire)
        else
            0;
        const shape_ok = process.isValidKstackTopShape(rsp0);
        debug.klog(
            "[setTssRsp0] CORRUPTION pid={d} rsp0=0x{X:0>16} expected=0x{X:0>16} shape_ok={any}\n",
            .{ pid, rsp0, expected, shape_ok },
        );
        // Dump all kdbg rings so we can see who else dispatched this
        // slot — typically the wild writer's PID is the dispatch
        // immediately before the corruption.
        @import("../debug/kdbg.zig").enterCritical();
        @import("../debug/kdbg.zig").dumpAll();
        @panic("setTssRsp0: rsp0 mismatch — pcb.kernel_stack_top corrupted (cross-PCB leak?)");
    }
    const cpu = smp.myCpu();
    // KCSAN-lite: watch the TSS slot we're about to overwrite for an
    // overlapping write from another CPU (shouldn't happen — TSS is
    // per-CPU — but a wild writer would show up here).
    @import("../debug/kcsan.zig").checkU64("tss.rsp0", &cpu.tss.rsp0);
    // Single atomic 8-byte store — same cache-line guarantee from the
    // smp.zig comptime assert. No bracketing needed: there's nothing
    // for an IRQ-driven nested setTssRsp0 to leave half-updated.
    cpu.tss.rsp0 = rsp0;
    // (Removed: legacy global tss write. setTssRsp0 only runs after
    // smp.init's `initPerCpuGdt` migrates BSP to its per-CPU TSS, so the
    // legacy `tss` is unreferenced by hardware from that point on. Its
    // initial RSP0 still gets stamped in `init()` for the early-boot
    // `ltr 0x28` path, but nothing rewrites it after.)
    // kdbg sched-ring breadcrumb: every TSS.RSP0 write is potentially
    // visible to the IRQ machinery — if a wild iretq fires we want to
    // know exactly which CPU rewired its TSS in the µs before. PID is
    // the dispatch target (`pid` arg), not stale `current_pid`. rsp0
    // truncated to low 32b.
    @import("../debug/kdbg.zig").schedEvent(
        .tss_rsp0,
        @intCast(pid),
        0,
        0,
        @truncate(rsp0),
    );

    // STACK-ALIAS DETECTOR (task #233). Fires the moment two CPUs have the
    // same kstack as their TSS.RSP0 — the precondition for the observed
    // cross-CPU corruption (one cpu's IDT-gate entry overwriting another
    // cpu's iretq frame on the shared kstack). Walks the small cpus table;
    // cheap because setTssRsp0 is only called on dispatch (not hot path).
    // When it fires, dumps both cpus' current_pid so we can pin the
    // protocol violation to a specific transition.
    {
        const debug = @import("../debug/debug.zig");
        for (0..smp.MAX_CPUS) |other| {
            if (other == cpu.cpu_id) continue;
            const other_top = smp.cpus[other].tss.rsp0;
            if (other_top != rsp0) continue;
            const my_pid: i32 = if (smp.cpus[cpu.cpu_id].current_pid) |p| @intCast(p) else -1;
            const other_pid: i32 = if (smp.cpus[other].current_pid) |p| @intCast(p) else -1;
            const my_state: u8 = if (my_pid >= 0) @import("../proc/process.zig").getStateRaw(@intCast(my_pid)) else 0xFF;
            const other_state: u8 = if (other_pid >= 0) @import("../proc/process.zig").getStateRaw(@intCast(other_pid)) else 0xFF;
            debug.klog(
                "[stack-alias] cpu{d}.tss.rsp0 = cpu{d}.tss.rsp0 = 0x{X}  cpu{d}.pid={d}(state={d}) cpu{d}.pid={d}(state={d})\n",
                .{ cpu.cpu_id, other, rsp0, cpu.cpu_id, my_pid, my_state, other, other_pid, other_state },
            );
        }
    }
}

pub fn getEntries() *const [7]u64 {
    return &entries;
}

/// Load the shared IDT (for AP use)
pub fn loadIdt() void {
    const idt_mod = @import("idt.zig");
    idt_mod.loadIdtForAP();
}

/// Install a GDT and reload all segment registers + TSS in one shot.
/// Used by both the BSP early-boot path (`init`) and per-CPU GDT setup
/// (`smp.initPerCpuGdt`) — same hardware ritual, single source of truth.
///
/// The asm: `lgdt` loads the table, the push-RIP-then-lretq trick reloads
/// CS (mov-to-CS is illegal in long mode), then we reload the data segs
/// to 0x10 (kdata) and load TR with 0x28 (the TSS descriptor at index 5).
/// The whole sequence assumes the GDT layout produced by `init` /
/// `initPerCpuGdt`: index 1 = kcode, 2 = kdata, 5 = TSS.
pub fn loadAndReload(ptr: *const GdtPtr) void {
    asm volatile (
        \\ lgdt (%[gdt])
        \\ pushq $0x08
        \\ leaq 1f(%%rip), %%rax
        \\ pushq %%rax
        \\ lretq
        \\ 1:
        \\ movw $0x10, %%ax
        \\ movw %%ax, %%ds
        \\ movw %%ax, %%es
        \\ movw %%ax, %%fs
        \\ movw %%ax, %%gs
        \\ movw %%ax, %%ss
        \\ movw $0x28, %%ax
        \\ ltr %%ax
        :
        : [gdt] "r" (ptr),
        : .{ .rax = true }
    );
}

pub fn makeEntry(base: u32, limit: u32, access: u8, flags: u4) u64 {
    const f: u64 = flags;
    return @as(u64, limit & 0xFFFF) |
        (@as(u64, base & 0xFFFF) << 16) |
        (@as(u64, (base >> 16) & 0xFF) << 32) |
        (@as(u64, access) << 40) |
        (@as(u64, (limit >> 16) & 0xF) << 48) |
        (f << 52) |
        (@as(u64, (base >> 24) & 0xFF) << 56);
}

pub fn init() void {
    const tss_base: u64 = @intFromPtr(&tss);
    const tss_limit: u32 = @sizeOf(Tss64) - 1;

    // Set TSS RSP0 to top of dedicated ISR stack (legacy global, used
    // only pre-SMP; smp.init's initPerCpuGdt migrates BSP to per-CPU TSS
    // shortly after this).
    tss.rsp0 = @intFromPtr(&isr_stack) + isr_stack.len;
    // IST1 for IRQ0 / dyn IRQs (see smp.initPerCpuGdt comment) — same
    // buffer as RSP0 here since this TSS is only live for the brief
    // pre-SMP window; per-CPU TSS takes over before any task is running.
    tss.ist1 = @intFromPtr(&isr_stack) + isr_stack.len;

    entries[0] = 0; // Null                     (0x00)
    entries[1] = makeEntry(0, 0xFFFFF, 0x9A, 0xA); // Kernel Code (0x08) L=1, D=0
    entries[2] = makeEntry(0, 0xFFFFF, 0x92, 0xC); // Kernel Data (0x10)
    entries[3] = makeEntry(0, 0xFFFFF, 0xF2, 0xC); // User Data   (0x18) - swapped for syscall/sysret
    entries[4] = makeEntry(0, 0xFFFFF, 0xFA, 0xA); // User Code   (0x20) - swapped for syscall/sysret

    // TSS descriptor is 16 bytes in long mode (two consecutive u64 entries)
    const tss_base_lo: u32 = @truncate(tss_base);
    entries[5] = makeEntry(tss_base_lo, tss_limit, 0x89, 0x0); // TSS low  (0x28)
    entries[6] = tss_base >> 32; // TSS high — upper 32 bits of base address

    gdt_ptr = .{
        .limit = @as(u16, @sizeOf(@TypeOf(entries)) - 1),
        .base = @intFromPtr(&entries),
    };

    loadAndReload(&gdt_ptr);
}
