// kdbg — Kernel debug rings + crash autopsy.
//
// Problem: serial.log fills with perf dumps and one-shot klog lines, so
// "what happened just before the crash" needs grep + luck. Kdbg fixes that
// by recording structured events into per-category fixed-size ring buffers
// (cheap: one atomic increment + struct copy). Nothing prints to serial
// at log time — rings are dumped on crash, on demand, or by a future CLI
// command.
//
// Design notes:
//   - Each ring is a fixed array. Head is an unbounded counter, modulo
//     RING_SIZE for indexing. seq_cst atomics on head so cross-CPU writes
//     don't tear; writes to the entry happen after acquiring the slot.
//   - Caller's return address is passed explicitly (not via @returnAddress
//     in the helper) so callers can choose to attribute events to their
//     own caller via @returnAddress() at the call site.
//   - Resolution to symbols is deferred until dump time. The kernel sym
//     table is the only resolver kdbg knows about — user-side RIPs are
//     printed raw and decoded by hand against the per-process .elf if the
//     crash is in a user process. (Future: pass in pcb.sym_table for the
//     crashing PID.)

const std = @import("std");
const serial = @import("serial.zig");
const symbols = @import("symbols.zig");
const addrinfo = @import("addrinfo.zig");

const RING_SIZE: usize = 64; // per-category history depth — pow-of-2 for cheap modulo
const SCHED_RING_SIZE: usize = 1024; // bigger — every dispatch + state change + tss/switch breadcrumbs
const IRQ_RING_SIZE: usize = 128;
// PMM free ring needs to be MUCH bigger than the generic RING_SIZE.
// Canary-mismatch lookups walk this ring backwards looking for the most-recent
// freer of a given phys, so the bug-of-interest's free event must still be
// present. With mtswap-style stress doing 17k+ frees per run, RING_SIZE=64
// rotates ~270×, losing the event before the mismatch fires. 8192 × 24 B
// PmmFreeEvent = 192 KB BSS; covers several seconds of load.
const PMM_FREE_RING_SIZE: usize = 8192;

inline fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

inline fn currentCpuId() u8 {
    // Use smp's per-CPU lookup. Cheap (TSS read + index). At very early
    // boot before SMP init, cpus[0] is the implicit BSP, so this returns 0.
    const smp = @import("../cpu/smp.zig");
    return smp.myCpu().cpu_id;
}

inline fn readCr3() u64 {
    var v: u64 = undefined;
    asm volatile ("movq %%cr3, %[out]"
        : [out] "=r" (v),
    );
    return v;
}

// === Event types ============================================================

pub const PmmAllocEvent = struct {
    tsc: u64 = 0,
    phys: u64 = 0,
    count: u32 = 0,
    caller_ra: u64 = 0,
};

pub const PmmFreeEvent = struct {
    tsc: u64 = 0,
    phys: u64 = 0,
    caller_ra: u64 = 0,
};

pub const ProcEvent = struct {
    pub const Kind = enum(u8) { create, destroy, kill, exec };
    tsc: u64 = 0,
    kind: Kind = .create,
    pid: u8 = 0,
    parent_pid: u8 = 0,
    status: u32 = 0,
};

pub const PFEvent = struct {
    tsc: u64 = 0,
    pid: u8 = 0,
    cr2: u64 = 0,
    err: u32 = 0,
    rip: u64 = 0,
    handled: bool = false,
};

pub const MmapEvent = struct {
    tsc: u64 = 0,
    pid: u8 = 0,
    virt: u64 = 0,
    phys: u64 = 0,
    flags: u64 = 0,
};

/// Scheduler ring — every state transition + dispatch. Designed for
/// cross-CPU SMP debugging: who claimed which PID, when, and what the
/// state was right before. The biggest ring (SCHED_RING_SIZE entries)
/// because schedules churn fast and we want enough history to see a
/// race window. cpu_id is recorded so a multi-CPU race shows up as
/// interleaved cpu0/cpu1 entries.
pub const SchedEvent = struct {
    pub const Op = enum(u8) {
        dispatch, // CPU claimed a PID (CAS .ready→.running succeeded)
        preempt, // CPU saved current PID and set state .ready
        sleep, // PID transitioning to .sleeping (extra=wait_target)
        wake, // PID transitioning .sleeping → .ready
        exit, // PID destroyed
        no_op, // CPU pickNext returned null, going to hlt
        tss_rsp0, // CPU updated its TSS.RSP0 (extra = low 32b of rsp0)
        switch_in, // about to call switchTo (pid=from, extra=to_pid)
        switch_out, // returned from switchTo (pid=this, extra=who-we-came-from-pid)
    };
    tsc: u64 = 0,
    cpu_id: u8 = 0,
    pid: u8 = 0,
    op: Op = .dispatch,
    old_state: u8 = 0,
    new_state: u8 = 0,
    extra: u32 = 0,
};

/// IRQ ring — per-CPU IRQ entries. Useful for "which CPU was where when
/// the crash hit" reconstruction. Logged from handleIRQ0 / handleException
/// at the start of each entry, before any reschedule logic runs.
pub const IrqEvent = struct {
    tsc: u64 = 0,
    cpu_id: u8 = 0,
    vec: u8 = 0,
    pid: u8 = 0,
    rip: u64 = 0,
    cs: u16 = 0,
};

// === Ring storage (one per category) ========================================

fn Ring(comptime T: type, comptime size: usize) type {
    return struct {
        const Self = @This();
        head: usize = 0, // unbounded counter; head % size = next slot
        items: [size]T = [_]T{T{}} ** size,

        pub fn record(self: *Self, ev: T) void {
            const slot = @atomicRmw(usize, &self.head, .Add, 1, .seq_cst) % size;
            self.items[slot] = ev;
        }

        // Iteration in chronological order (oldest first). Callers receive a
        // pointer to each entry so they can format selectively.
        pub fn count(self: *const Self) usize {
            const h = @atomicLoad(usize, &self.head, .seq_cst);
            return @min(h, size);
        }

        pub fn at(self: *const Self, i: usize) *const T {
            // i in [0, count). Map to the correct slot accounting for wrap.
            const h = @atomicLoad(usize, &self.head, .seq_cst);
            const start = if (h <= size) 0 else h % size;
            const idx = (start + i) % size;
            return &self.items[idx];
        }
    };
}

pub var pmm_alloc_ring: Ring(PmmAllocEvent, RING_SIZE) = .{};
pub var pmm_free_ring: Ring(PmmFreeEvent, PMM_FREE_RING_SIZE) = .{};
pub var proc_ring: Ring(ProcEvent, RING_SIZE) = .{};
pub var pf_ring: Ring(PFEvent, RING_SIZE) = .{};
pub var mmap_ring: Ring(MmapEvent, RING_SIZE) = .{};
pub var sched_ring: Ring(SchedEvent, SCHED_RING_SIZE) = .{};
pub var irq_ring: Ring(IrqEvent, IRQ_RING_SIZE) = .{};

// === Public record API ======================================================

pub fn pmmAlloc(phys: u64, count: u32, caller_ra: u64) void {
    pmm_alloc_ring.record(.{ .tsc = rdtsc(), .phys = phys, .count = count, .caller_ra = caller_ra });
}

pub fn pmmFree(phys: u64, caller_ra: u64) void {
    pmm_free_ring.record(.{ .tsc = rdtsc(), .phys = phys, .caller_ra = caller_ra });
}

/// Scan the free ring backwards for the most recent free event matching `phys`
/// (frame-aligned compare — caller's `phys` may be the bare frame address while
/// recorded events are also frame-aligned). Diagnostic-only, used by pmm's
/// underflow path to name "who freed this frame BEFORE the double-free".
pub fn pmmFindLastFree(phys: u64) ?PmmFreeEvent {
    const target = phys & ~@as(u64, 0xFFF);
    const n = pmm_free_ring.count();
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        const ev = pmm_free_ring.at(i);
        if ((ev.phys & ~@as(u64, 0xFFF)) == target) return ev.*;
    }
    return null;
}

/// Scan the alloc ring backwards for the most recent alloc that covers `phys`
/// (event covers [phys, phys + count*4096)). Diagnostic-only — paired with
/// pmmFindLastFree so the underflow dump can show alloc → free → free chains.
pub fn pmmFindLastAlloc(phys: u64) ?PmmAllocEvent {
    const target = phys & ~@as(u64, 0xFFF);
    const n = pmm_alloc_ring.count();
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        const ev = pmm_alloc_ring.at(i);
        const ev_base = ev.phys & ~@as(u64, 0xFFF);
        const ev_end = ev_base + @as(u64, ev.count) * 4096;
        if (target >= ev_base and target < ev_end) return ev.*;
    }
    return null;
}

pub fn procEvent(kind: ProcEvent.Kind, pid: u8, parent_pid: u8, status: u32) void {
    proc_ring.record(.{ .tsc = rdtsc(), .kind = kind, .pid = pid, .parent_pid = parent_pid, .status = status });
}

pub fn pfEvent(pid: u8, cr2: u64, err: u32, rip: u64, handled: bool) void {
    pf_ring.record(.{ .tsc = rdtsc(), .pid = pid, .cr2 = cr2, .err = err, .rip = rip, .handled = handled });
}

pub fn mmapEvent(pid: u8, virt: u64, phys: u64, flags: u64) void {
    mmap_ring.record(.{ .tsc = rdtsc(), .pid = pid, .virt = virt, .phys = phys, .flags = flags });
}

pub fn schedEvent(op: SchedEvent.Op, pid: u8, old_state: u8, new_state: u8, extra: u32) void {
    sched_ring.record(.{
        .tsc = rdtsc(),
        .cpu_id = currentCpuId(),
        .pid = pid,
        .op = op,
        .old_state = old_state,
        .new_state = new_state,
        .extra = extra,
    });
}

pub fn irqEvent(vec: u8, pid: u8, rip: u64, cs: u16) void {
    irq_ring.record(.{
        .tsc = rdtsc(),
        .cpu_id = currentCpuId(),
        .vec = vec,
        .pid = pid,
        .rip = rip,
        .cs = cs,
    });
}

/// Snapshot of an iretq frame at IRQ entry, used by iretqValidate to detect
/// writes during the IRQ handler. Stored on the caller's stack (NOT a global
/// per-CPU array) because tasks migrate between CPUs across schedule() — a
/// per-CPU snap would compare against the wrong IRQ's values when the task
/// wakes up on a different CPU. Stack-local snaps travel with the task.
pub const IretqSnap = struct {
    cs: u64,
    ss: u64,
    rip: u64,
};

/// Take a snapshot of CS/SS/RIP from the iretq frame. Caller stores the
/// returned struct in a local and passes it to iretqValidate later.
pub fn iretqSnapshot(frame_base: [*]const u64) IretqSnap {
    return .{
        .cs = frame_base[16],
        .ss = frame_base[19],
        .rip = frame_base[15],
    };
}

/// Software snap+validate for handleIRQ0's saved-return-address slot.
///
/// The hardware watch approach (DR0) had two issues in practice:
///   1. The arm() in kdbg sets the canonical entries[].addr globally and
///      applies to local DR registers. But other CPUs' DR0 is set lazily
///      via applyLocal at the next IRQ, so for some window each CPU's DR0
///      is stale. Concurrent arm/disarm across CPUs makes this ugly.
///   2. Address is dynamic (per IRQ on each CPU), so the canonical
///      entries[0] gets rewritten every IRQ, which then propagates to all
///      CPUs at their next applyLocal — including ones that didn't ask
///      for that watch.
/// Both manifested as early-boot false positives: a legit prologue push
/// matching a stale DR0 from a previous CPU's arm.
///
/// Software snap+validate avoids all that — it just reads the slot's
/// current value at IRQ entry and compares at exit. No DR juggling, no
/// per-CPU races. Misses the writer's RIP (we only know corruption
/// happened, not who did it), but for narrowing down "did the corruption
/// happen during THIS IRQ?" it's reliable.
///
/// Address derivation: rsp_arg is the pointer handleIRQ0 receives, set
/// by isr_irq0's `lea 0x200(%rsp), %rdi` BEFORE the `call`. So:
///   pre_call_RSP    = rsp_arg - 0x200
///   saved_ret_slot  = pre_call_RSP - 8 = rsp_arg - 0x208 = rsp_arg - 520
pub fn snapshotHandleIRQ0RetAddr(rsp_arg: u64) u64 {
    const slot_va = rsp_arg - 520;
    const ptr: *const u64 = @ptrFromInt(slot_va);
    return ptr.*;
}

pub fn validateHandleIRQ0RetAddr(rsp_arg: u64, snap: u64) void {
    const slot_va = rsp_arg - 520;
    const ptr: *const u64 = @ptrFromInt(slot_va);
    const now = ptr.*;
    if (now == snap) return;

    serial.print("\n!!! handleIRQ0 saved-return-address corrupted before ret !!!\n", .{});
    serial.print("  slot_addr = 0x{X:0>16}\n", .{slot_va});
    serial.print("  at entry  = 0x{X:0>16} ", .{snap});
    if (symbols.resolveKernel(snap)) |r| serial.print("({s}+0x{X})", .{ r.name, r.offset });
    serial.print("\n  now       = 0x{X:0>16} ", .{now});
    if (symbols.resolveKernel(now)) |r| serial.print("({s}+0x{X})", .{ r.name, r.offset });
    serial.print("  <-- CHANGED during IRQ\n", .{});

    dumpAll();
    @panic("handleIRQ0 saved-return-address corrupted (kdbg.validateHandleIRQ0RetAddr)");
}

/// Validate that the iretq frame's CS and SS still match the snapshot taken
/// at IRQ entry. Any drift means the slots got overwritten between IRQ
/// entry and IRQ exit — exactly the symptom we're hunting for the post-
/// click iretq #GP.
///
/// Active diagnostic: if the frame doesn't match, dump everything (current
/// vs snapshot, kdbg rings, registers) AND panic, refusing to execute the
/// known-bad iretq. That way we get a full autopsy at the point of
/// detection rather than a triple-fault.
/// Skip symbol resolution for addresses that obviously aren't kernel-text:
/// non-canonical (high half of 64-bit address space without proper sign
/// extension), null, BIOS ROM area, or outside the kernel image at high VA.
/// Without this, dumping a wild-write report tries to format a corrupt
/// `name.ptr` slice from `resolveKernel(bogus_rip)` and #GPs in the printer.
///
/// Phase 3 layout: kernel image is mapped at PML4[511]+PDPT[510], a 1 GB
/// window starting at 0xFFFFFFFF80000000. Anything below that (or in the
/// non-canonical hole) is not kernel text. The legacy [0x100000, 0x4000000)
/// range stays accepted so backtraces taken before enterFirstTask (where
/// some boot code still has low-phys aliases via the dropped low identity)
/// still resolve symbols correctly.
inline fn looksLikeKernelText(addr: u64) bool {
    // Legacy low-phys window — only valid pre-PML4[0]-drop.
    if (addr >= 0x100000 and addr < 0x4000000) return true;
    // Kernel high-half image (1 GB at -2 GB).
    if (addr >= 0xFFFFFFFF80000000 and addr < 0xFFFFFFFFC0000000) return true;
    return false;
}

fn safeSymbolPrint(addr: u64) void {
    if (!looksLikeKernelText(addr)) {
        serial.print("(bogus addr — skipping symbol lookup)", .{});
        return;
    }
    if (symbols.resolveKernel(addr)) |r| {
        serial.print("({s}+0x{X})", .{ r.name, r.offset });
    }
}

pub fn iretqValidate(frame_base: [*]const u64, snap: IretqSnap) void {
    const cs_now = frame_base[16];
    const ss_now = frame_base[19];
    const cs_ok = cs_now == snap.cs;
    const ss_ok = ss_now == snap.ss;
    if (cs_ok and ss_ok) return;

    // Capture LBR before any further kernel work pushes the writer's
    // branches out of the 32-entry ring. Caveat: the call into snapshot()
    // already costs us some entries — if the writer was much earlier in
    // the IRQ handler, those branches may already be gone.
    const lbr_snap = @import("lbr.zig").snapshot();

    const id = currentCpuId();

    // Bad frame — print snapshot vs current. The diff tells us EXACTLY which
    // slot changed during the IRQ handler.
    serial.print("\n!!! iretq frame corruption detected before iretq (cpu={d}) !!!\n", .{id});
    serial.print("  frame_addr=0x{X:0>16}\n", .{@intFromPtr(&frame_base[15])});
    serial.print("  RIP at entry: 0x{X:0>16} ", .{snap.rip});
    safeSymbolPrint(snap.rip);
    serial.print("\n  RIP now:      0x{X:0>16} ", .{frame_base[15]});
    safeSymbolPrint(frame_base[15]);
    serial.print("\n", .{});
    serial.print("  CS at entry:  0x{X:0>16}\n", .{snap.cs});
    serial.print("  CS now:       0x{X:0>16}", .{cs_now});
    if (!cs_ok) serial.print("  <-- CHANGED during IRQ", .{});
    serial.print("\n  RFLAGS now:   0x{X:0>16}\n", .{frame_base[17]});
    serial.print("  RSP now:      0x{X:0>16}\n", .{frame_base[18]});
    serial.print("  SS at entry:  0x{X:0>16}\n", .{snap.ss});
    serial.print("  SS now:       0x{X:0>16}", .{ss_now});
    if (!ss_ok) serial.print("  <-- CHANGED during IRQ", .{});
    serial.print("\n", .{});

    // Dump the kdbg rings so we can see what just happened (last syscalls,
    // schedule events, IRQs). The corrupting code path is in here somewhere.
    dumpAll();

    @import("lbr.zig").dump(&lbr_snap);

    @panic("iretq frame corrupted (kdbg.iretqValidate)");
}

// === Return-to-user RIP range check ========================================
//
// Wild-RIP hunt (task #224). When user-mode tries to execute a kernel address
// (saw 0x80000C — `&heap[0].canary_head`), the trip is a #GP from CPL=3 hitting
// a supervisor page. The dump tells us the bad VALUE but nothing about who
// wrote it into the iretq/sysretq frame slot.
//
// Instead of waiting for the user-mode #GP, validate RIP at the BIDIRECTIONAL
// boundary — just before iretq returns to user mode. Bad RIP at that moment
// means the writer is on the kernel stack we're about to pop. Full kdbg
// autopsy gives us the call path that produced it.

const memmap = @import("../mm/memmap.zig");

inline fn ripIsValidUser(rip: u64) bool {
    // USER_VA_FLOOR..USER_VA_MAX matches what the kernel actually maps for
    // user processes (see memmap.zig). The lower bound catches every "RIP <
    // load base" stale-pointer case; the upper bound catches kernel-half
    // pointers leaked into user RIP (e.g. 0x80000C, 0x800010, fmt strings).
    return rip >= memmap.USER_VA_FLOOR and rip < memmap.USER_VA_MAX;
}

/// Call from `defer` at the end of every handleIRQ0 / handleException path
/// that may iretq back to user. CS=0x23 means user-mode return; if RIP is
/// outside the user VA window, dump everything and panic right HERE — that
/// freezes the kernel stack with the writer's call path still on it.
///
/// `rip_index` and `cs_index` are the offsets of saved RIP/CS in
/// frame_base (handleIRQ0 uses 15/16; handleException uses 17/18 because
/// the ISR stub also pushed int_no and error_code).
pub fn validateUserReturnIretq(frame_base: [*]const u64, comptime rip_index: usize, comptime cs_index: usize) void {
    const cs = frame_base[cs_index];
    if (cs != 0x23) return; // returning to kernel, nothing to check
    const rip = frame_base[rip_index];
    if (ripIsValidUser(rip)) return;

    const lbr_snap = @import("lbr.zig").snapshot();
    const id = currentCpuId();

    serial.print("\n!!! WILD RIP about to iretq to user-mode (cpu={d}) !!!\n", .{id});
    serial.print("  frame_addr   = 0x{X:0>16}\n", .{@intFromPtr(&frame_base[rip_index])});
    serial.print("  saved RIP    = 0x{X:0>16} ", .{rip});
    safeSymbolPrint(rip);
    serial.print("  <-- not in user range [0x{X}, 0x{X})\n", .{ memmap.USER_VA_FLOOR, memmap.USER_VA_MAX });
    serial.print("  saved CS     = 0x{X:0>16}\n", .{cs});
    serial.print("  saved RFLAGS = 0x{X:0>16}\n", .{frame_base[rip_index + 2]});
    serial.print("  saved RSP    = 0x{X:0>16}\n", .{frame_base[rip_index + 3]});
    serial.print("  saved SS     = 0x{X:0>16}\n", .{frame_base[rip_index + 4]});

    // Dump the SAVED GPRs from the IRQ frame too — useful to see if any
    // register held the bad RIP value.
    const reg_names = [_][]const u8{
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
        "r8 ", "r9 ", "r10", "r11", "r12", "r13", "r14", "r15",
    };
    serial.print("  GPRs at frame entry:\n", .{});
    for (reg_names, 0..) |name, i| {
        serial.print("    {s} = 0x{X:0>16}\n", .{ name, frame_base[i] });
    }

    dumpAll();
    @import("lbr.zig").dump(&lbr_snap);
    @panic("wild RIP at iretq to user (kdbg.validateUserReturnIretq)");
}

/// Call from `doSyscall` JUST BEFORE returning. Inspects the saved user RIP
/// in the SyscallFrame (RCX field — syscall instruction stashes user RIP
/// there). Same intent as validateUserReturnIretq but for the sysretq path.
pub fn validateUserReturnSysret(saved_rcx: u64, saved_r11: u64) void {
    if (ripIsValidUser(saved_rcx)) return;

    const lbr_snap = @import("lbr.zig").snapshot();
    const id = currentCpuId();

    serial.print("\n!!! WILD RIP about to sysretq to user-mode (cpu={d}) !!!\n", .{id});
    serial.print("  saved user RIP (RCX) = 0x{X:0>16} ", .{saved_rcx});
    safeSymbolPrint(saved_rcx);
    serial.print("  <-- not in user range [0x{X}, 0x{X})\n", .{ memmap.USER_VA_FLOOR, memmap.USER_VA_MAX });
    serial.print("  saved RFLAGS (R11)   = 0x{X:0>16}\n", .{saved_r11});

    dumpAll();
    @import("lbr.zig").dump(&lbr_snap);
    @panic("wild RIP at sysretq to user (kdbg.validateUserReturnSysret)");
}

// === Symbol formatting helper ==============================================

fn printSym(addr: u64) void {
    if (symbols.resolveKernel(addr)) |r| {
        serial.print("{s}+0x{X}", .{ r.name, r.offset });
    } else {
        serial.print("0x{X:0>16}", .{addr});
    }
}

fn stateName(s: u8) []const u8 {
    // MUST match `proc.process.State` enum order. If you reorder/insert
    // there, update here too — otherwise every autopsy label drifts and
    // race-hunting wastes hours chasing nonexistent "weird" transitions.
    return switch (s) {
        0 => "unused",
        1 => "loading",
        2 => "ready",
        3 => "running",
        4 => "sleeping",
        5 => "zombie",
        else => "?",
    };
}

fn waitKindName(k: u8) []const u8 {
    return switch (k) {
        0 => "none",
        1 => "waitpid",
        2 => "pipe_r",
        3 => "pipe_w",
        4 => "futex",
        else => "?",
    };
}

fn schedOpName(op: SchedEvent.Op) []const u8 {
    return switch (op) {
        .dispatch => "DISPATCH",
        .preempt => "PREEMPT ",
        .sleep => "SLEEP   ",
        .wake => "WAKE    ",
        .exit => "EXIT    ",
        .no_op => "NO_OP   ",
        .tss_rsp0 => "TSS_RSP0",
        .switch_in => "SW_IN   ",
        .switch_out => "SW_OUT  ",
    };
}

fn procKindName(k: ProcEvent.Kind) []const u8 {
    return switch (k) {
        .create => "create",
        .destroy => "destroy",
        .kill => "kill",
        .exec => "exec",
    };
}

// === Provenance: who allocated/freed a given phys frame? ===================

pub fn findFrame(phys: u64) void {
    serial.print("[kdbg] findFrame(0x{X:0>16}):\n", .{phys});
    var found = false;

    const ac = pmm_alloc_ring.count();
    var i: usize = 0;
    while (i < ac) : (i += 1) {
        const ev = pmm_alloc_ring.at(i);
        const end = ev.phys + @as(u64, ev.count) * 4096;
        if (phys >= ev.phys and phys < end) {
            serial.print("  alloc: phys=0x{X}+{d}p by ", .{ ev.phys, ev.count });
            printSym(ev.caller_ra);
            serial.print(" tsc={d}\n", .{ev.tsc});
            found = true;
        }
    }

    const fc = pmm_free_ring.count();
    i = 0;
    while (i < fc) : (i += 1) {
        const ev = pmm_free_ring.at(i);
        if (ev.phys == phys) {
            serial.print("  free:  phys=0x{X} by ", .{ev.phys});
            printSym(ev.caller_ra);
            serial.print(" tsc={d}\n", .{ev.tsc});
            found = true;
        }
    }
    if (!found) serial.print("  (no provenance — frame not in alloc/free rings)\n", .{});
}

// === Heap corruption auto-bisect ===========================================
//
// On a heap canary fire (kfree's tail-canary mismatch, validateHeap's
// header/footer disagreement, or any other "this byte should not have
// been written"), call attributeHeapCorruptor with the virtual address
// of the corrupted byte. The function:
//
//   1. Resolves virt → phys via paging.virtToPhys.
//   2. Looks up pmmFindLastAlloc(phys): who currently OWNS this frame.
//   3. Looks up pmmFindLastFree(phys): who LAST released this frame.
//   4. Computes which of the two is more recent and infers verdict:
//        - alloc more recent than free  → buffer overflow into a live alloc
//        - free  more recent than alloc → use-after-free (frame was returned
//          to PMM after the kernel-heap region was released, dangling write)
//   5. Walks irq_ring/sched_ring for the time-window between the relevant
//      anchor (most recent alloc/free) and now, surfacing the count of
//      events so the human sees how busy the window was — a small count
//      means a tight blast radius.
//
// Output is one "[autopsy] strongest culprit" line plus sub-lines for
// each contributor. The detector path is already inside a panic context;
// printing here adds noise to an already-loud log but turns a 5-min ring
// grep into one glance. Proposal P5 in the debug infra survey 2026-05-28.

pub fn attributeHeapCorruptor(bad_virt: u64) void {
    const paging = @import("../mm/paging.zig");
    serial.print("[autopsy] heap-corruptor bisect for virt=0x{X:0>16}\n", .{bad_virt});

    const phys_opt = paging.virtToPhys(bad_virt);
    if (phys_opt == null) {
        serial.print("[autopsy]   virt not mapped — no phys to query rings with\n", .{});
        return;
    }
    const phys = phys_opt.?;
    serial.print("[autopsy]   phys=0x{X:0>16}\n", .{phys});

    const last_alloc = pmmFindLastAlloc(phys);
    const last_free = pmmFindLastFree(phys);

    if (last_alloc == null and last_free == null) {
        serial.print("[autopsy]   no alloc/free events for this frame in {d}/{d}-entry rings\n", .{ pmm_alloc_ring.count(), pmm_free_ring.count() });
        return;
    }

    if (last_alloc) |a| {
        serial.print("[autopsy]   last_alloc: tsc=0x{X:0>12} phys=0x{X}+{d}p caller=", .{ a.tsc, a.phys, a.count });
        printSym(a.caller_ra);
        serial.print("\n", .{});
    } else {
        serial.print("[autopsy]   last_alloc: (none in ring — frame allocated before ring wrap)\n", .{});
    }
    if (last_free) |f| {
        serial.print("[autopsy]   last_free:  tsc=0x{X:0>12} phys=0x{X} caller=", .{ f.tsc, f.phys });
        printSym(f.caller_ra);
        serial.print("\n", .{});
    } else {
        serial.print("[autopsy]   last_free:  (none — frame still held since alloc)\n", .{});
    }

    // Verdict + window scan.
    if (last_alloc != null and last_free != null) {
        const a = last_alloc.?;
        const f = last_free.?;
        if (a.tsc >= f.tsc) {
            // Most recent owner is the current alloc; the free was an
            // earlier life of this frame. Likely buffer overflow inside
            // the current alloc — its caller_ra is the suspect window.
            const age = a.tsc;
            serial.print("[autopsy]   verdict: BUFFER OVERFLOW into LIVE alloc (alloc tsc 0x{X:0>12} > prior free tsc 0x{X:0>12})\n", .{ a.tsc, f.tsc });
            describeWindow(age);
        } else {
            // Free is more recent → use-after-free. The freer's caller_ra
            // is where the frame was returned to PMM, and the corruption
            // must have come from a writer holding a stale pointer.
            serial.print("[autopsy]   verdict: USE-AFTER-FREE (free tsc 0x{X:0>12} > alloc tsc 0x{X:0>12}) — page returned to PMM after release\n", .{ f.tsc, a.tsc });
            describeWindow(f.tsc);
        }
    } else if (last_alloc) |a| {
        serial.print("[autopsy]   verdict: corruption INSIDE first-and-only alloc (no prior free) — overflow/UAF from caller above\n", .{});
        describeWindow(a.tsc);
    } else if (last_free) |f| {
        serial.print("[autopsy]   verdict: write to a freed frame (no alloc in ring) — stale-pointer writer\n", .{});
        describeWindow(f.tsc);
    }
}

/// Tally the number of irq_ring/sched_ring events with tsc >= anchor_tsc
/// — gives a sense of how busy the window-since-anchor was. A small count
/// (1-10) means a tight blast radius; thousands means the corruption was
/// in flight for a long time and the per-event RIP walk-back would be the
/// next manual step.
fn describeWindow(anchor_tsc: u64) void {
    var irq_in_window: usize = 0;
    const irq_n = irq_ring.count();
    var i: usize = 0;
    while (i < irq_n) : (i += 1) {
        if (irq_ring.at(i).tsc >= anchor_tsc) irq_in_window += 1;
    }
    var sched_in_window: usize = 0;
    const sched_n = sched_ring.count();
    i = 0;
    while (i < sched_n) : (i += 1) {
        if (sched_ring.at(i).tsc >= anchor_tsc) sched_in_window += 1;
    }
    serial.print("[autopsy]   window-since-anchor: {d} irq events, {d} sched events\n", .{ irq_in_window, sched_in_window });
}

// === Cross-CPU snapshot ====================================================
//
// Walks smp.cpus[] and prints each live CPU's "what process do you think
// you're running" answer. Crucial for diagnosing SMP races where two CPUs
// disagree about ownership of a PID — visible here as both showing the
// same current_pid simultaneously.

fn dumpCpuSnapshot() void {
    const smp = @import("../cpu/smp.zig");
    serial.print("[kdbg] CPU snapshot ({d} live):\n", .{smp.cpu_count});
    for (0..smp.MAX_CPUS) |i| {
        const cpu = &smp.cpus[i];
        if (i > 0 and !cpu.alive) continue;
        const pid_s: i32 = if (cpu.current_pid) |p| @intCast(p) else -1;
        const idle_s: i32 = if (cpu.idle_pid) |p| @intCast(p) else -1;
        serial.print("  cpu{d}: alive={} lapic_id={d} current_pid={d} idle_pid={d}\n", .{
            i, cpu.alive, cpu.lapic_id, pid_s, idle_s,
        });
        // TSS dump — caught today's netstat-crash bug class would have
        // been one cpu showing tss.rsp0 = wrong-pid's-top. Both the IDT
        // gate and the SYSCALL path read this same field (LSTAR stub
        // loads RSP from cpus[N].tss.rsp0), so it's the canonical source.
        serial.print("        tss.rsp0=0x{X:0>16} tss.rsp1=0x{X:0>16} tss.rsp2=0x{X:0>16}\n", .{
            cpu.tss.rsp0, cpu.tss.rsp1, cpu.tss.rsp2,
        });
    }
    // Per-CPU breadcrumb dump — what each CPU was doing at the moment of
    // capture. Often more useful than the bare current_pid because it
    // identifies the kernel transition (SYSCALL X / IRQ0 / SCHED_ENTER /
    // SWITCH_TO / EXC vec=N) the CPU was inside.
    @import("breadcrumb.zig").dump();
    // Per-CPU save-trace ring — every recent switchTo save with its
    // saved-RIP plausibility verdict. A BAD-RIP entry is the smoking gun
    // for kesp-clobber bugs (netstat-desktop 2026-05-17 class): the bad
    // value was already in the slot at save time, dispatch just exposed it.
    @import("save_trace.zig").dumpAll();
    // Per-CPU current_pid transition ring. Same-pid races (per_cpu_asm
    // alias bug class) show as two CPUs both having entries with the
    // SAME new_pid at near-identical TSC values.
    @import("pid_trace.zig").dumpAll();
}

// === All-process snapshot ==================================================
//
// Dumps every used PCB — answers "who else exists, what state are they in,
// who's blocked on what". On a scheduler crash this is the equivalent of
// `ps + state` at the moment of failure.

fn dumpProcSnapshot() void {
    const process = @import("../proc/process.zig");
    serial.print("[kdbg] Process snapshot:\n", .{});
    serial.print("  {s:>3} {s:<8} {s:<8} {s:>4} {s:<8} {s:>10} {s}\n", .{
        "pid", "state", "wait", "lcpu", "wtarget", "kesp", "name",
    });
    for (0..process.MAX_PROCS) |i| {
        const p = &process.procs[i];
        if (p.state == .unused) continue;
        const name = if (p.name_len == 0) "(unnamed)" else p.name[0..@min(p.name_len, p.name.len)];
        serial.print("  {d:>3} {s:<8} {s:<8} {d:>4} 0x{X:0>6} 0x{X:0>8} {s}\n", .{
            i,
            stateName(@intFromEnum(p.state)),
            waitKindName(@intFromEnum(p.wait_kind)),
            p.last_cpu,
            p.wait_target,
            p.kernel_esp,
            name,
        });
    }
}

// === Hex dump around an arbitrary kernel/user address =====================

/// Dump `qwords` u64s starting at `base`. Resolves possible kernel return
/// addresses (any value in the kernel .text range) so a stack frame's
/// saved RIPs are immediately readable. Defensive: refuses non-canonical
/// or null-page addresses to avoid faulting the autopsy itself.
pub fn hexDump(base: u64, qwords: u32, label: []const u8) void {
    serial.print("[kdbg] Hex dump ({s}) at 0x{X:0>16}:\n", .{ label, base });
    var i: u32 = 0;
    while (i < qwords) : (i += 1) {
        const addr = base + @as(u64, i) * 8;
        // Reject obvious bad addrs: low 4KB, non-canonical band.
        if (addr < 0x1000 or
            (addr >= 0x0000_8000_0000_0000 and addr < 0xFFFF_8000_0000_0000))
        {
            serial.print("  +0x{X:0>3}: <invalid 0x{X}>\n", .{ i * 8, addr });
            return;
        }
        const ptr: *const u64 = @ptrFromInt(@as(usize, @intCast(addr)));
        const v = ptr.*;
        serial.print("  +0x{X:0>3}: 0x{X:0>16}", .{ i * 8, v });
        // Annotate via addrinfo when the value looks like a pointer (any
        // canonical kernel half address or any plausible low-VA region).
        // Skip the print when describe says "unmapped/unknown" — keeps
        // the dump readable for non-pointer-shaped values.
        const looks_like_ptr = v >= 0xFFFF_8000_0000_0000 or
            (v >= 0x1000 and v < 0x10000000);
        if (looks_like_ptr) {
            const desc = addrinfo.describe(@intCast(v));
            if (desc.len < 8 or !std.mem.eql(u8, desc[0..8], "unmapped")) {
                serial.print("  // {s}", .{desc});
            }
        }
        serial.print("\n", .{});
    }
}

// === Crash autopsy: dump everything the rings know ==========================

/// Dump just pmm_alloc + pmm_free rings. Useful for OOM diagnostics — far
/// cheaper than dumpAll() (no sched / irq / proc / pf / mmap rings) and
/// answers the only question that matters under memory pressure: who's
/// been allocating? Each pmm_alloc entry resolves caller_ra to a kernel
/// symbol so the leaking call site is grep-able. 2026-05-20: added for
/// Q1 memory-budget audit.
pub fn dumpPmmAllocRing() void {
    serial.print("[kdbg] pmm_alloc (last {d}):\n", .{pmm_alloc_ring.count()});
    var i: usize = 0;
    while (i < pmm_alloc_ring.count()) : (i += 1) {
        const ev = pmm_alloc_ring.at(i);
        serial.print("  tsc={d} phys=0x{X}+{d}p by ", .{ ev.tsc, ev.phys, ev.count });
        printSym(ev.caller_ra);
        serial.print("\n", .{});
    }
    serial.print("[kdbg] pmm_free (last {d}):\n", .{pmm_free_ring.count()});
    i = 0;
    while (i < pmm_free_ring.count()) : (i += 1) {
        const ev = pmm_free_ring.at(i);
        serial.print("  tsc={d} phys=0x{X} by ", .{ ev.tsc, ev.phys });
        printSym(ev.caller_ra);
        serial.print("\n", .{});
    }
    // mmap ring: every PTE install. If the same `virt` appears twice
    // (same pid) with different `phys`, the PTE got overwritten and the
    // first phys is leaked — the smoking gun for the lazy-fault leak
    // class we're hunting 2026-05-20.
    serial.print("[kdbg] mmap (last {d}):\n", .{mmap_ring.count()});
    i = 0;
    while (i < mmap_ring.count()) : (i += 1) {
        const ev = mmap_ring.at(i);
        serial.print("  tsc={d} pid={d} virt=0x{X:0>16} -> phys=0x{X:0>16} flags=0x{X}\n", .{ ev.tsc, ev.pid, ev.virt, ev.phys, ev.flags });
    }
    // pf ring: every user-mode page fault. If we see the same cr2
    // repeated with the same pid, the fault handler isn't actually
    // resolving the fault (TLB stale, wrong PD, PTE not getting written).
    serial.print("[kdbg] pf (last {d}):\n", .{pf_ring.count()});
    i = 0;
    while (i < pf_ring.count()) : (i += 1) {
        const ev = pf_ring.at(i);
        serial.print("  tsc={d} pid={d} cr2=0x{X:0>16} err=0x{X} rip=0x{X:0>16} handled={}\n", .{ ev.tsc, ev.pid, ev.cr2, ev.err, ev.rip, ev.handled });
    }
}

/// Full ring dump. Called from crashAutopsy() AND from any code that wants
/// just-the-rings (the older Ring-3 crash path used dumpAll() directly).
pub fn dumpAll() void {
    serial.print("\n[kdbg] ====== ring dumps ======\n", .{});

    // Sched ring first — most informative for SMP issues. Each entry is one
    // line so 256 entries fit in a manageable scroll.
    serial.print("[kdbg] sched (last {d}):\n", .{sched_ring.count()});
    var i: usize = 0;
    while (i < sched_ring.count()) : (i += 1) {
        const ev = sched_ring.at(i);
        serial.print("  tsc={d} cpu{d} {s} pid={d:>2} {s}->{s} extra=0x{X}\n", .{
            ev.tsc, ev.cpu_id, schedOpName(ev.op), ev.pid,
            stateName(ev.old_state), stateName(ev.new_state),
            ev.extra,
        });
    }

    serial.print("[kdbg] irq (last {d}):\n", .{irq_ring.count()});
    i = 0;
    while (i < irq_ring.count()) : (i += 1) {
        const ev = irq_ring.at(i);
        serial.print("  tsc={d} cpu{d} vec={d} pid={d} cs=0x{X} rip=0x{X:0>16}", .{
            ev.tsc, ev.cpu_id, ev.vec, ev.pid, ev.cs, ev.rip,
        });
        if ((ev.cs & 3) == 0) {
            serial.print(" ", .{});
            printSym(ev.rip);
        }
        serial.print("\n", .{});
    }

    serial.print("[kdbg] proc (last {d}):\n", .{proc_ring.count()});
    i = 0;
    while (i < proc_ring.count()) : (i += 1) {
        const ev = proc_ring.at(i);
        serial.print("  tsc={d} {s} pid={d} parent={d} status=0x{X}\n", .{
            ev.tsc, procKindName(ev.kind), ev.pid, ev.parent_pid, ev.status,
        });
    }

    serial.print("[kdbg] pf (last {d}):\n", .{pf_ring.count()});
    i = 0;
    while (i < pf_ring.count()) : (i += 1) {
        const ev = pf_ring.at(i);
        serial.print("  tsc={d} pid={d} cr2=0x{X:0>16} err=0x{X} rip=0x{X:0>16} handled={}\n", .{ ev.tsc, ev.pid, ev.cr2, ev.err, ev.rip, ev.handled });
    }

    serial.print("[kdbg] mmap (last {d}):\n", .{mmap_ring.count()});
    i = 0;
    while (i < mmap_ring.count()) : (i += 1) {
        const ev = mmap_ring.at(i);
        serial.print("  tsc={d} pid={d} virt=0x{X:0>16} -> phys=0x{X:0>16} flags=0x{X}\n", .{ ev.tsc, ev.pid, ev.virt, ev.phys, ev.flags });
    }

    serial.print("[kdbg] pmm_alloc (last {d}):\n", .{pmm_alloc_ring.count()});
    i = 0;
    while (i < pmm_alloc_ring.count()) : (i += 1) {
        const ev = pmm_alloc_ring.at(i);
        serial.print("  tsc={d} phys=0x{X}+{d}p by ", .{ ev.tsc, ev.phys, ev.count });
        printSym(ev.caller_ra);
        serial.print("\n", .{});
    }

    serial.print("[kdbg] pmm_free (last {d}):\n", .{pmm_free_ring.count()});
    i = 0;
    while (i < pmm_free_ring.count()) : (i += 1) {
        const ev = pmm_free_ring.at(i);
        serial.print("  tsc={d} phys=0x{X} by ", .{ ev.tsc, ev.phys });
        printSym(ev.caller_ra);
        serial.print("\n", .{});
    }

    serial.print("[kdbg] ====== end ======\n\n", .{});
}

/// One-stop crash dump. Pass whichever fields you have at the call site —
/// each section prints only when its inputs are non-null. The intent is
/// that handleException (Ring 3) AND any kernel-mode panic both end up
/// here so we get a uniform autopsy.
pub const AutopsyOpts = struct {
    /// Page-fault address (#PF) or null otherwise.
    cr2: ?u64 = null,
    /// Per-process symbol table for resolving user RIPs in the stack walk.
    app_syms: ?*symbols.SymTable = null,
    /// Kernel RSP at the fault. If set, dumps qwords from there.
    kernel_rsp: ?u64 = null,
    /// User RBP for backtrace (Ring 3 faults). Null skips the user walk.
    user_rbp: ?u64 = null,
    /// User RIP (for the `Insn:` annotation). Falls through to hexDump.
    user_rip: ?u64 = null,
    /// Exception vector — 6/13/14 for #UD/#GP/#PF, 255 for generic @panic.
    /// Used by crashSummary's classifier and the [crash-fp] grep line.
    int_no: u64 = 255,
    /// Saved RIP at fault — kernel address when ring 0, user address when
    /// the fault came from ring 3. Distinct from user_rip (annotation only).
    crash_rip: ?u64 = null,
    /// Pre-computed CPU id. crashSummary falls back to apic.getLapicId
    /// when null, but callers in IRQ context should pass it in if they
    /// already have it cached — saves a MSR read mid-panic.
    cpu_id: ?u32 = null,
    /// Optional message for @panic-class crashes. Null otherwise.
    msg: ?[]const u8 = null,
};

// =============================================================================
// NMI snapshot (task #247) — for "OS frozen, no panic" debugging
// =============================================================================
//
// When the OS hangs silently (no exception, no canary, just stuck), our
// existing tools fire on nothing because they require an event. NMI snapshot
// solves that: ANY CPU can call broadcastNMI() to send NMIs to all other
// CPUs. Each receiving CPU's NMI handler dumps a one-line state digest
// (RIP, RSP, CS, current_pid) to serial and IRETs back. Works even when
// the target CPU has IF=0 (NMI is non-maskable, hence the name).
//
// Use cases:
//   - Manual: from a panic path or gdb stub, call broadcastNMI() to see
//     where the other CPU is currently stuck.
//   - Auto: a watchdog timer detects "no scheduler progress for N ticks"
//     and broadcasts to capture the wedge state. (TODO: wire up watchdog.)

/// Set to true by the panic path before broadcastNMI; receivers halt after
/// snapshot instead of IRETing back. Without this the panicking CPU's
/// `cli; hlt` only stops itself; other CPUs continue running on (now
/// possibly-corrupt) state and can later trigger a second cascading panic
/// while the first victim is still wedged in the panic handler.
pub var nmi_halt_after_snapshot: bool = false;

pub fn nmiSnapshot(rsp: u64, saved_rip: u64, saved_cs: u64) void {
    // Do NOT enter the panic critical section here — the caller of
    // broadcastNMI() likely holds it, and we'd deadlock waiting forever.
    // Each NMI snapshot is short so even interleaved output stays
    // grep-able (the post-`broadcastNMI` 50 ms wait + peers halting
    // gives us mostly-clean output in practice).
    const apic = @import("../time/apic.zig");
    const smp = @import("../cpu/smp.zig");
    const process = @import("../proc/process.zig");
    const cpu_id: u32 = @intCast(apic.getLapicId());
    const cur_pid_opt: ?usize = if (cpu_id < smp.MAX_CPUS)
        smp.cpus[cpu_id].current_pid
    else
        null;
    const cur_pid: i32 = if (cur_pid_opt) |p| @intCast(p) else -1;

    serial.print("[nmi-snap cpu{d}] rip=0x{X:0>16} cs=0x{X:0>4} rsp=0x{X:0>16} pid={d}", .{
        cpu_id, saved_rip, saved_cs, rsp, cur_pid,
    });
    if (symbols.resolveKernel(saved_rip)) |r| {
        serial.print(" fn={s}+0x{X}", .{ r.name, r.offset });
    }
    // Decode CPU+PCB state on a second line so the per-line lock keeps
    // it from byte-interleaving with the rip line above. Tells us
    // whether the wedged CPU was: running a normal task, parked in
    // .sleeping (and on what wait_kind/target), or in idle.
    if (cur_pid_opt) |p| {
        if (p < process.MAX_PROCS) {
            const pcb = &process.procs[p];
            const name_slice = pcb.name[0..@min(pcb.name_len, pcb.name.len)];
            serial.print("\n[nmi-snap cpu{d}] name='{s}' state={d} wait_kind={d} wait_target=0x{X} is_idle={any}\n", .{
                cpu_id, name_slice,
                @intFromEnum(pcb.state),
                @intFromEnum(pcb.wait_kind),
                pcb.wait_target,
                pcb.is_idle,
            });
        } else {
            serial.print("\n", .{});
        }
    } else {
        serial.print("\n[nmi-snap cpu{d}] current_pid=null (no task on this CPU)\n", .{cpu_id});
    }

    // Panic-path receivers stop here; non-panic diagnostic callers
    // (spinlock contention reporter, etc.) IRET back to whatever they
    // were doing.
    if (nmi_halt_after_snapshot) {
        while (true) asm volatile ("cli; hlt");
    }
}

/// Send NMI to every alive CPU except self. Each receiving CPU runs
/// nmiSnapshot() and IRETs back. Caller should already be in panic
/// critical section (or about to enter one).
pub fn broadcastNMI() void {
    const apic = @import("../time/apic.zig");
    const smp = @import("../cpu/smp.zig");
    const my_id = apic.getLapicId();
    serial.print("[nmi-broadcast] from cpu{d} — soliciting snapshots\n", .{my_id});
    for (&smp.cpus) |*cpu| {
        if (!cpu.alive) continue;
        if (cpu.lapic_id == my_id) continue;
        apic.sendNMI(cpu.lapic_id);
    }
    // Brief wait for NMI handlers to fire and print. Each handler enters
    // the critical section (which we own), prints, exits — they queue
    // behind us if we hold it. We don't release; caller is mid-panic.
    // 50M pause spins ≈ 50ms on a 1GHz CPU — long enough.
    var spins: u32 = 0;
    while (spins < 50_000_000) : (spins += 1) {
        asm volatile ("pause");
    }
}

/// Cross-CPU panic-section serialization. Without this, two CPUs panicing
/// simultaneously interleave their print output at byte granularity and the
/// log is unreadable (we lost critical signal in task #233 because of this).
///
/// Design: per-CPU re-entrant lock. The first CPU to enter claims ownership;
/// subsequent CPUs spin-wait. If a CPU never releases (halts mid-dump),
/// waiters give up after CRITICAL_WAIT_SPINS and steal — better shredded
/// output than no output.
///
/// Re-entrancy is required because the dump chain often goes
///   iretq_canary.report → @panic → main.panic
/// and each step takes the section. Without per-CPU re-entrancy detection,
/// the second `enterCritical` would deadlock on its own CPU's claim.
const NO_OWNER: u32 = 0xFFFFFFFF;
var critical_owner_cpu: u32 = NO_OWNER;
const CRITICAL_WAIT_SPINS: u32 = 50_000_000;

/// Enter the panic critical section. Idempotent per-CPU — calling twice
/// from the same CPU is a no-op for the second call. Never released; the
/// caller is expected to halt.
pub fn enterCritical() void {
    serial.panicResetLock();
    const my_cpu: u32 = @intCast(@import("../time/apic.zig").getLapicId());

    // Already ours? (e.g., main.panic called from iretq_canary.report)
    if (@atomicLoad(u32, &critical_owner_cpu, .acquire) == my_cpu) return;

    var spins: u32 = 0;
    while (@cmpxchgWeak(u32, &critical_owner_cpu, NO_OWNER, my_cpu, .acquire, .monotonic) != null) {
        // Someone else owns. Wait their turn — or steal after timeout.
        spins += 1;
        if (spins > CRITICAL_WAIT_SPINS) {
            @atomicStore(u32, &critical_owner_cpu, my_cpu, .release);
            return;
        }
        asm volatile ("pause");
    }
}

/// Tight TL;DR block — emitted at the TOP of every panic/autopsy path so
/// triage doesn't require scrolling past 1000+ lines of ring dumps. Six
/// to eight lines + one greppable `[crash-fp]` line that `tools/crash_db.sh`
/// ingests to dedupe crashes across boots.
///
/// Fingerprint design: line is intentionally flat key=value so awk/cut
/// parses it without quoting. Same `vec` + same `rip_sym` across boots =
/// same crash signature (build_id is informational metadata, not part of
/// the dedup key — repro across rebuilds should still match).
/// Decode the call-site immediately preceding the saved RIP and, if it's
/// a `call <something>`, print the resolved target. Zig's runtime safety
/// checks (integer overflow, out-of-bounds index, misaligned ptr cast,
/// reached unreachable, etc.) compile to a `call <Panic.helper>` and
/// execution stops there; the autopsy's saved RIP is the byte AFTER the
/// call (the return address). Without this annotation the user has to
/// objdump kernel.elf around RIP to figure out which safety check fired
/// — e.g. an alignment panic at +0xfe1 hides that the actual `call
/// integerOverflow` was at +0xfdc and a different safety check at +0xfe1.
fn printPanicCallSite(rip: u64) void {
    if (rip < 0xFFFFFFFF80000000 + 5) return;
    if (!looksLikeKernelText(rip - 5)) return;

    const ip_call: [*]const u8 = @ptrFromInt(rip - 5);
    // Only handle the most common form: E8 disp32 (near relative call,
    // 5 bytes). Indirect calls (FF /2) and far calls don't appear in
    // compiler-generated safety stubs.
    if (ip_call[0] != 0xE8) return;

    const lo = @as(u32, ip_call[1]);
    const lo2 = @as(u32, ip_call[2]) << 8;
    const lo3 = @as(u32, ip_call[3]) << 16;
    const lo4 = @as(u32, ip_call[4]) << 24;
    const disp32: i32 = @bitCast(lo | lo2 | lo3 | lo4);
    // disp is relative to the instruction AFTER the call, which is `rip`
    // itself (the saved return address). Sign-extend to i64, wrap-add.
    const sign_extended: u64 = @bitCast(@as(i64, disp32));
    const target = rip +% sign_extended;

    if (!looksLikeKernelText(target)) return;
    if (symbols.resolveKernel(target)) |r| {
        serial.print("[kdbg] PanicCall:{s}+0x{X} (call at RIP-5)\n", .{ r.name, r.offset });
    }
}

pub fn crashSummary(opts: AutopsyOpts) void {
    const build_options = @import("build_options");
    const build_id = build_options.build_id;
    const cpu_id: u32 = opts.cpu_id orelse @as(u32, @intCast(@import("../time/apic.zig").getLapicId()));

    serial.print("\n[kdbg] ====== CRASH SUMMARY ======\n", .{});
    serial.print("[kdbg] Build:    0x{X:0>16}\n", .{build_id});
    serial.print("[kdbg] CPU:      cpu{d}\n", .{cpu_id});

    const type_str: []const u8 = switch (opts.int_no) {
        6 => "#UD invalid opcode",
        13 => "#GP general protection",
        14 => "#PF page fault",
        255 => "@panic / kernel assert",
        else => "exception",
    };
    serial.print("[kdbg] Type:     {s} (vec={d})\n", .{ type_str, opts.int_no });

    if (opts.msg) |m| {
        serial.print("[kdbg] Msg:      {s}\n", .{m});
    }

    // Resolve crash RIP once — used both for display and the [crash-fp] line.
    var rip_sym_buf: [128]u8 = undefined;
    var rip_sym_slice: []const u8 = "(none)";
    if (opts.crash_rip) |rip| {
        if (looksLikeKernelText(rip)) {
            if (symbols.resolveKernel(rip)) |r| {
                rip_sym_slice = std.fmt.bufPrint(&rip_sym_buf, "{s}+0x{X}", .{ r.name, r.offset }) catch "(fmt-fail)";
            } else if (symbols.resolveKernelNearest(rip)) |r| {
                // Bound by 16 KB — anything farther is more likely a wild RIP
                // than a real "near sysFoo" hit, and a misleading annotation
                // is worse than a bare hex address.
                if (r.offset < 0x4000) {
                    rip_sym_slice = std.fmt.bufPrint(&rip_sym_buf, "(near {s}+0x{X})", .{ r.name, r.offset }) catch "(fmt-fail)";
                } else {
                    rip_sym_slice = std.fmt.bufPrint(&rip_sym_buf, "0x{X:0>16}", .{rip}) catch "(fmt-fail)";
                }
            } else {
                rip_sym_slice = std.fmt.bufPrint(&rip_sym_buf, "0x{X:0>16}", .{rip}) catch "(fmt-fail)";
            }
        } else {
            rip_sym_slice = std.fmt.bufPrint(&rip_sym_buf, "wild=0x{X:0>16}", .{rip}) catch "(fmt-fail)";
        }
        serial.print("[kdbg] RIP:      {s}\n", .{rip_sym_slice});
        // DWARF source-line annotation. Cheap binary search; harmless if
        // KERNEL.LINE wasn't loaded (returns null, line below is skipped).
        if (@import("dwarf_line.zig").lookup(rip)) |loc| {
            serial.print("[kdbg] Source:   {s}:{d}\n", .{ loc.file, loc.line });
        }
        printPanicCallSite(rip);
    } else {
        serial.print("[kdbg] RIP:      (not provided)\n", .{});
    }

    if (opts.cr2) |cr2| {
        const decode: []const u8 = if (cr2 < 0x1000)
            "low 4KB — null deref?"
        else if (cr2 >= 0x0000_8000_0000_0000 and cr2 < 0xFFFF_8000_0000_0000)
            "non-canonical — wild pointer!"
        else if (cr2 < memmap.KERNEL_PHYS_START)
            "below kernel image"
        else if (cr2 >= memmap.USER_VA_FLOOR and cr2 < memmap.USER_VA_MAX)
            "user range"
        else
            "kernel range";
        serial.print("[kdbg] CR2:      0x{X:0>16} ({s})\n", .{ cr2, decode });
    }

    const rsp_for_hint: u64 = opts.kernel_rsp orelse 0;
    const rip_for_hint: u64 = opts.crash_rip orelse 0;
    const cr2_for_hint: u64 = opts.cr2 orelse 0;
    const hint = @import("debug.zig").classifyCrash(opts.int_no, rip_for_hint, cr2_for_hint, rsp_for_hint);
    serial.print("[kdbg] Hint:     {s}\n", .{hint});

    // Greppable single-line fingerprint for tools/crash_db.sh. Stable
    // key=value layout so awk '/^\[crash-fp\]/{...}' parses without quoting.
    serial.print("[crash-fp] build=0x{X:0>16} vec={d} cpu={d} rip_sym={s} cr2=0x{X:0>16}\n", .{
        build_id,
        opts.int_no,
        cpu_id,
        rip_sym_slice,
        opts.cr2 orelse 0,
    });

    serial.print("[kdbg] ====== END SUMMARY ======\n\n", .{});
}

pub fn crashAutopsy(opts: AutopsyOpts) void {
    enterCritical();

    const cpu_id: u32 = opts.cpu_id orelse @as(u32, @intCast(@import("../time/apic.zig").getLapicId()));

    // TL;DR first — the [crash-fp] line gives the host script everything it
    // needs to dedupe and triage without grepping the rest of the autopsy.
    crashSummary(opts);

    serial.print("\n[kdbg] ===== CRASH AUTOPSY (cpu{d}) =====\n", .{cpu_id});
    dumpCpuSnapshot();
    dumpProcSnapshot();
    if (opts.cr2) |cr2| {
        const cr3 = readCr3();
        walkUserPT(cr3, cr2);
        findFrame(cr2 & ~@as(u64, 0xFFF));
    }
    if (opts.kernel_rsp) |rsp| hexDump(rsp, 64, "kernel RSP (deep)");
    if (opts.user_rip) |rip| {
        hexDump(rip, 4, "user RIP bytes");
    }
    if (opts.user_rbp) |rbp| walkUserStack(rbp, opts.app_syms);
    dumpAll();
    // Per-CPU execution trail — last 32 IRQ/syscall samples per alive CPU.
    // Recent execution history when the stack walk isn't useful (corrupt
    // rbp, leaf-function freeze, NMI handler that never returned).
    serial.print("\n[kdbg] ====== exec trails ======\n", .{});
    @import("exectrail.zig").dumpAll(32);
    serial.print("[kdbg] ===== END AUTOPSY (cpu{d}) =====\n\n", .{cpu_id});
}

// === Page-table walk =======================================================

const PRESENT: u64 = 1 << 0;
const READ_WRITE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const PAGE_SIZE_FLAG: u64 = 1 << 7;
const PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

fn printFlags(entry: u64) void {
    // Compact representation: PWUL where P=present, W=writable, U=user-accessible, L=large page.
    if (entry & PRESENT == 0) {
        serial.print("---", .{});
        return;
    }
    const f0: u8 = 'P';
    const f1: u8 = if (entry & READ_WRITE != 0) 'W' else 'R';
    const f2: u8 = if (entry & USER != 0) 'U' else 'k';
    const f3: u8 = if (entry & PAGE_SIZE_FLAG != 0) 'L' else '-';
    serial.print("{c}{c}{c}{c}", .{ f0, f1, f2, f3 });
}

/// Walk a user PD's mapping for `virt` and print each level. Called from
/// the crash handler so we can answer "what's actually mapped at CR2?"
/// without sprinkling klog through vmm.zig.
pub fn walkUserPT(pml4_phys_raw: u64, virt: u64) void {
    serial.print("[kdbg] PT walk for virt=0x{X:0>16} (CR3=0x{X}):\n", .{ virt, pml4_phys_raw });

    if (pml4_phys_raw == 0) {
        serial.print("  CR3=0 — no address space\n", .{});
        return;
    }

    // Callers usually pass CR3 directly, which carries PCID in bits 0..11
    // when CR4.PCIDE=1 (always, on ZigOS post-PCID rollout). Mask down to
    // the PML4 phys page — without this the [*]const u64 cast below
    // hits Zig's alignment safety check ("incorrect alignment") on the
    // first `pml4[idx]` deref. That was the cascade-panic source on the
    // 2026-05-14 photo.elf #PF: CR3=0x7CB00F → PCID=0xF, phys=0x7CB000.
    const pml4_phys = pml4_phys_raw & PAGE_MASK;
    if (pml4_phys != pml4_phys_raw) {
        serial.print("  (masked CR3 flags/PCID: phys=0x{X:0>16})\n", .{pml4_phys});
    }

    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    const paging = @import("../mm/paging.zig");

    // Belt-and-suspenders: refuse any level pointer that isn't 8-aligned.
    // Phys-page-aligned values masked above should always satisfy this,
    // but a corrupted CR3 (e.g. accidental kernel-image-vs-CR3 confusion)
    // could still reach here. Better to print "(misaligned)" than to
    // re-panic inside the panic path.
    if (!checkAligned(pml4_phys)) {
        serial.print("  PML4 phys misaligned — skipping walk\n", .{});
        return;
    }
    const pml4: [*]const u64 = @ptrFromInt(paging.physToVirt(pml4_phys));
    const pml4e = pml4[pml4_idx];
    serial.print("  PML4[{d}]=0x{X:0>16} ", .{ pml4_idx, pml4e });
    printFlags(pml4e);
    serial.print("\n", .{});
    if (pml4e & PRESENT == 0) return;

    const pdpt_phys = pml4e & PAGE_MASK;
    if (!checkAligned(pdpt_phys)) {
        serial.print("  PDPT phys misaligned — skipping walk\n", .{});
        return;
    }
    const pdpt: [*]const u64 = @ptrFromInt(paging.physToVirt(pdpt_phys));
    const pdpte = pdpt[pdpt_idx];
    serial.print("  PDPT[{d}]=0x{X:0>16} ", .{ pdpt_idx, pdpte });
    printFlags(pdpte);
    serial.print("\n", .{});
    if (pdpte & PRESENT == 0 or pdpte & PAGE_SIZE_FLAG != 0) return;

    const pd_phys = pdpte & PAGE_MASK;
    if (!checkAligned(pd_phys)) {
        serial.print("  PD phys misaligned — skipping walk\n", .{});
        return;
    }
    const pd: [*]const u64 = @ptrFromInt(paging.physToVirt(pd_phys));
    const pde = pd[pd_idx];
    serial.print("  PD[{d}]=0x{X:0>16} ", .{ pd_idx, pde });
    printFlags(pde);
    serial.print("\n", .{});
    if (pde & PRESENT == 0 or pde & PAGE_SIZE_FLAG != 0) return;

    const pt_phys = pde & PAGE_MASK;
    if (!checkAligned(pt_phys)) {
        serial.print("  PT phys misaligned — skipping walk\n", .{});
        return;
    }
    const pt: [*]const u64 = @ptrFromInt(paging.physToVirt(pt_phys));
    const pte = pt[pt_idx];
    serial.print("  PT[{d}]=0x{X:0>16} ", .{ pt_idx, pte });
    printFlags(pte);
    serial.print("\n", .{});
}

inline fn checkAligned(phys: u64) bool {
    return (phys & 0xFFF) == 0;
}

// === User stack walk =======================================================

/// Walk the user RBP chain and print each return address with its symbol.
/// The crash handler is in kernel mode but the user PD is still active, so
/// dereferencing user pointers Just Works as long as the page is mapped.
/// Defensive: bound depth, validate range, and stop on the first deref
/// outside [USER_LO, USER_HI). Symbol resolution uses pcb.sym_table when
/// available.
pub fn walkUserStack(rbp_in: u64, app_syms: ?*symbols.SymTable) void {
    const USER_LO: u64 = 0x400000;
    const USER_HI: u64 = 0x10000000;
    serial.print("[kdbg] User stack (RBP chain):\n", .{});
    var rbp: u64 = rbp_in;
    var depth: u32 = 0;
    while (depth < 16) : (depth += 1) {
        if (rbp < USER_LO or rbp + 16 > USER_HI) break;
        if ((rbp & 7) != 0) break; // misaligned — corrupt rbp
        const frame: [*]const u64 = @ptrFromInt(@as(usize, @intCast(rbp)));
        const ret = frame[1];
        const next = frame[0];
        serial.print("  [{d}] rbp=0x{X:0>16} ret=0x{X:0>16} ", .{ depth, rbp, ret });
        if (app_syms) |syms| {
            if (symbols.resolveUser(syms, ret)) |r| {
                serial.print("{s}+0x{X}\n", .{ r.name, r.offset });
            } else {
                serial.print("(no sym)\n", .{});
            }
        } else {
            serial.print("(no syms)\n", .{});
        }
        if (next == 0 or next <= rbp) break;
        rbp = next;
    }
}
