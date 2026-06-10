const std = @import("std");
const pic = @import("../time/pic.zig");
const syscall = @import("syscall.zig");
const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");
const symbols = @import("../debug/symbols.zig");
const boot_phase = @import("../boot/boot_phase.zig");

// Sub-modules — bodies live here, idt.zig is a thin façade that wires
// them via init() and re-exports the public surface.
const dynirq = @import("idt/dynirq.zig");
const misc_irq = @import("idt/misc_irq.zig");
const irq0 = @import("idt/irq0.zig");
const exception = @import("idt/exception.zig");

// Public re-exports — keep this file as the single import target for
// external callers (msix, virtio_gpu, sched, watch). Splitting the
// internals out shouldn't churn every caller's import paths.
pub const DYN_IRQ_BASE = dynirq.DYN_IRQ_BASE;
pub const DYN_IRQ_COUNT = dynirq.DYN_IRQ_COUNT;
pub const DynHandler = dynirq.DynHandler;
pub const DYNIRQ_CANARY = dynirq.DYNIRQ_CANARY;
pub const allocDynVector = dynirq.allocDynVector;
pub const registerIrq = dynirq.registerIrq;
pub const IRQ0_CANARY = irq0.IRQ0_CANARY;

// Re-exports of align-panic targets. abi_check takes their addresses to
// prove the build-time asm-alignment-linter targets exist at runtime;
// that takeAddr requires the decl to be visible at idt module scope,
// hence these one-liners.
pub const isr_irq0_align_panic = irq0.isr_irq0_align_panic;
pub const isr_irq0_canary_panic = irq0.isr_irq0_canary_panic;
pub const isr_irq1_align_panic = misc_irq.isr_irq1_align_panic;
pub const isr_irq12_align_panic = misc_irq.isr_irq12_align_panic;
pub const isr_tlb_shootdown_align_panic = misc_irq.isr_tlb_shootdown_align_panic;
pub const isr_pmi_align_panic = misc_irq.isr_pmi_align_panic;
pub const isr_common_exc_align_panic = exception.isr_common_exc_align_panic;

// MMU write-watch state (RETIRED — see project_mmu_watch_obsolete). Re-
// exported so legacy `armWriteWatch` callers compile if any reappear; the
// state itself lives in idt/exception.zig now.
pub const WwEntry = exception.WwEntry;
pub const armWriteWatch = exception.armWriteWatch;

// x86_64 IDT entry: 16 bytes (128 bits). Consumed by hardware via `lidt`
// — the field order is THE wire format, so reorders silently break the
// CPU's interrupt dispatch. The bit-offset asserts at the bottom of this
// module nail the layout (a `@sizeOf == 16` check alone catches resize but
// not swapped fields).
const Entry = packed struct(u128) {
    offset_low: u16, // Bits 0..15 of handler address
    selector: u16, // Code segment selector
    ist: u3, // Interrupt Stack Table index (0 = don't switch)
    reserved0: u5, // Must be zero
    type_attr: u8, // Type and attributes (P, DPL, gate type)
    offset_mid: u16, // Bits 16..31 of handler address
    offset_high: u32, // Bits 32..63 of handler address
    reserved1: u32, // Must be zero
};

// IDTR (`lidt m16&64` operand): 2-byte limit followed by 8-byte base. Packed
// struct: Zig encodes the fields with no inter-field padding, giving the
// 10-byte memory layout the CPU reads. The `@bitSizeOf == 80` assert below
// catches a future refactor to `extern struct` (where the u64 would natural-
// align with 6 bytes of padding after `limit` and `lidt` would read garbage).
const Ptr = packed struct {
    limit: u16,
    base: u64,
};

// Layout invariants the asm trampolines and `lidt` instruction depend on.
// If any of these fail at compile time, look for accidental field reorders
// or u128 → u64 packing changes.
comptime {
    if (@sizeOf(Entry) != 16) @compileError("IDT Entry must be 16 bytes (x86_64 long mode)");
    // Bit-offset asserts — defense against a field-order refactor that
    // happens to keep size right (e.g. swapping selector + offset_low
    // would still be 16 bytes, but `lidt` would read garbage).
    if (@bitOffsetOf(Entry, "offset_low")  !=  0) @compileError("Entry.offset_low must be at bit 0");
    if (@bitOffsetOf(Entry, "selector")    != 16) @compileError("Entry.selector must be at bit 16");
    if (@bitOffsetOf(Entry, "ist")         != 32) @compileError("Entry.ist must be at bit 32");
    if (@bitOffsetOf(Entry, "reserved0")   != 35) @compileError("Entry.reserved0 must be at bit 35");
    if (@bitOffsetOf(Entry, "type_attr")   != 40) @compileError("Entry.type_attr must be at bit 40");
    if (@bitOffsetOf(Entry, "offset_mid")  != 48) @compileError("Entry.offset_mid must be at bit 48");
    if (@bitOffsetOf(Entry, "offset_high") != 64) @compileError("Entry.offset_high must be at bit 64");
    if (@bitOffsetOf(Entry, "reserved1")   != 96) @compileError("Entry.reserved1 must be at bit 96");

    // IDTR Ptr must be exactly 80 bits (16 limit + 64 base, no padding).
    // packed struct is bit-packed by Zig spec — this assert backs the
    // contract against future refactors to extern struct.
    if (@bitSizeOf(Ptr) != 80) @compileError("IDTR Ptr must be exactly 80 bits (16 limit + 64 base, no padding)");
    if (@bitOffsetOf(Ptr, "limit") !=  0) @compileError("IDTR Ptr.limit must be at bit 0");
    if (@bitOffsetOf(Ptr, "base")  != 16) @compileError("IDTR Ptr.base must follow limit at bit 16");

    // CpuState (in debug.zig) is dereferenced as `state.field` from asm-built
    // stack frames in handleException. 22 fields × 8 bytes = 176 bytes.
    if (@sizeOf(debug.CpuState) != 22 * 8)
        @compileError("debug.CpuState size must equal 22×8 bytes; asm stack layout assumes this");
}

var entries: [256]Entry = undefined;
var ptr: Ptr = undefined;

/// Raw byte view of the IDT entries — for src/debug/cpu_struct_hash.zig
/// (post-init integrity hashing). Read-only by convention.
pub fn entriesBytes() []const u8 {
    return @as([*]const u8, @ptrCast(&entries))[0..@sizeOf(@TypeOf(entries))];
}

fn setGate(num: u8, handler: usize, flags: u8) void {
    setGateIst(num, handler, flags, 0);
}

/// Compile-time-evaluated guard the IDT-install path runs at boot. Returns
/// false after `boot_phase.markComplete()` — once the scheduler is live, the
/// IDT is immutable and any setGate call would skip the serializing barrier
/// (`pic.init` on BSP, AP-startup IPI on APs) that published the previous
/// entry writes to the local CPU's instruction-fetch path.
inline fn idtInstallAllowed() bool {
    return !boot_phase.isComplete();
}

/// Same as setGate but with an explicit IST (Interrupt Stack Table) index.
/// IST=0 means "don't switch stacks" (use TSS.RSP0 on privilege change, or
/// keep the current RSP on same-privilege interrupts). IST=1..7 names a
/// TSS.ISTn slot — CPU AUTOMATICALLY loads RSP from TSS.ISTn on this
/// vector, regardless of CPL transition.
///
/// Use case: IRQ handlers that may call schedule() and consume stack must
/// NOT corrupt the preempted task's kstack (netstat-desktop crash class
/// 2026-05-17 — schedule's pushfq wrote RFLAGS onto desktop's saved
/// kesp+48). Putting IRQs on IST=1 isolates them on a per-CPU stack.
///
/// Constraint: a single IST slot is shared across all vectors that use it.
/// If two vectors use the same IST and one preempts the other, the second
/// CPU push reuses the same physical address → corrupts the in-flight
/// frame. Mitigation: IRQ handlers cli-on-entry (interrupt-gate type 0x8E
/// auto-clears IF) so no nesting on the same IST happens.
fn setGateIst(num: u8, handler: usize, flags: u8, ist: u3) void {
    // Invariant: IDT install is BSP-only during single-threaded boot, PLUS
    // each AP's loadIdtForAP() reload during its own bringup (also single-
    // threaded on that AP). After boot_phase.markComplete(), the IDT is
    // immutable — mutating a vector here would not be observed by peer
    // CPUs without an explicit IPI + lidt-reload, and the live device on
    // that vector could fire mid-rewrite (torn 16-byte entry write).
    if (!idtInstallAllowed()) {
        debug.kwarn(@src(), "setGate vec={d} after boot_phase complete — IDT mutation post-boot ignored", .{num});
        return;
    }
    entries[num] = .{
        .offset_low = @as(u16, @truncate(handler & 0xFFFF)),
        .selector = 0x08,
        .ist = ist,
        .reserved0 = 0,
        .type_attr = flags,
        .offset_mid = @as(u16, @truncate((handler >> 16) & 0xFFFF)),
        .offset_high = @as(u32, @truncate((handler >> 32) & 0xFFFFFFFF)),
        .reserved1 = 0,
    };
}


pub fn init() void {
    @memset(std.mem.asBytes(&entries), 0);

    // Exception handlers (comptime-generated stubs — body in idt/exception.zig)
    //
    // #DF (8) runs on IST1: its trigger is frequently "the CPU could not push
    // an exception frame on the current RSP" — i.e. a kernel stack overflow
    // into the slot guard page (the push #PFs, the #PF frame push fails on the
    // same dead RSP, the CPU escalates to #DF). With IST=0 that second push
    // failure is a silent triple fault, so the kstack guard pages could never
    // actually produce a diagnostic. IST1 (per-CPU isr_stack top, populated in
    // both the legacy and per-CPU TSS) hands the #DF stub a known-good stack.
    // The IST-vs-switchTo hazard that reverted IRQ0/dyn IRQs off IST1 (see
    // below) does not apply: the #DF path is terminal — ring-0 dump + halt,
    // or destroyCurrent of a doomed task — and never resumes the interrupted
    // context from the IST stack.
    inline for (exception.exceptions) |exc| {
        const ist: u3 = if (exc.num == 8) 1 else 0;
        setGateIst(exc.num, @intFromPtr(&exception.ExcStub(exc).handler), 0x8E, ist);
    }

    // IRQs
    // IRQ0 (timer) is IST=0 — it MUST run on the preempted task's kstack:
    // isr_irq0's kernel-to-kernel-ret model keeps its entry state there so it
    // survives task switches, and schedule()'s switchTo must save the task RSP
    // into kernel_esp. IST=1 for IRQ0 was tried 2026-05-17 and wedged virtio-gpu
    // (switchTo saved the IST RSP into kernel_esp). See feedback_ist1_irq0_incompatible.
    // The kesp+48 corruption class that originally motivated IST is instead
    // handled in software for the device IRQs that actually caused it — see the
    // Shape D trampoline in DynIrqStub below (handler body on per-CPU isr_stack,
    // schedule() back on the task kstack). IRQ1/IRQ12 stay IST=0 — they don't
    // reschedule and their handler chains are tiny.
    setGateIst(32, @intFromPtr(&irq0.isr_irq0), 0x8E, 0);
    setGate(33, @intFromPtr(&misc_irq.isr_irq1), 0x8E);
    setGate(44, @intFromPtr(&misc_irq.isr_irq12), 0x8E); // Mouse

    // TLB shootdown IPI (vector from mmu/tlb.zig). Receiver: full local TLB flush + ack.
    setGate(@import("mmu/tlb.zig").TLB_VECTOR, @intFromPtr(&misc_irq.isr_tlb_shootdown), 0x8E);

    // PMI (Performance Monitor Interrupt). LAPIC LVT.PMI delivers to this
    // vector when PMC0 overflows. Stub forwards saved RIP to pmu.onSample.
    setGate(@import("arch/pmu.zig").PMI_VECTOR, @intFromPtr(&misc_irq.isr_pmi), 0x8E);

    // Syscall (DPL=3: callable from Ring 3)
    setGate(128, @intFromPtr(&syscall.isr_syscall), 0xEE);

    // APIC spurious interrupt (vector 0xFF) — silently ignore
    setGate(0xFF, @intFromPtr(&misc_irq.isr_spurious), 0x8E);

    // Dynamic IRQ slots for MSI-X-driven device drivers (vectors 0x40..0x4F).
    // Each stub is a comptime-generated naked thunk that calls handleDynIrq
    // with its own vector number — see DynIrqStub below.
    //
    // IST=0 (hardware does not switch stacks). Stack isolation for the IRQ
    // *handler body* is done in software instead — see DynIrqStub's Shape D
    // trampoline, which runs handleDynIrq on the per-CPU isr_stack and switches
    // back to the task kstack before schedule(). A blanket IST=1 was tried
    // 2026-05-17 and wedged virtio-gpu (dyn IRQ count froze, desktop stuck in
    // blockOn(.gpu_io)) because the IST stack also caught schedule()'s switchTo,
    // which saved the IST RSP into kernel_esp — same failure as IRQ0-on-IST.
    // The trampoline keeps schedule() on the task kstack, so it's safe.
    inline for (0..dynirq.DYN_IRQ_COUNT) |i| {
        const v: u8 = dynirq.DYN_IRQ_BASE + @as(u8, @intCast(i));
        setGateIst(v, @intFromPtr(&dynirq.DynIrqStub(v).handler), 0x8E, 0);
    }

    ptr.limit = @sizeOf(@TypeOf(entries)) - 1;
    ptr.base = @intFromPtr(&entries);

    pic.init();
    asm volatile ("lidt (%[p])"
        :
        : [p] "r" (&ptr),
    );
}

/// Load the shared IDT on an AP (no PIC init, just lidt)
pub fn loadIdtForAP() void {
    asm volatile ("lidt (%[p])"
        :
        : [p] "r" (&ptr),
    );
}


//   [17] rip  [18] cs  [19] rflags  [20] rsp  [21] ss  (pushed by CPU)


/// Pre-iretq sanity panic. Reached when an iretq site is about to pop a
/// frame whose CS slot isn't 0x08 (kernel) or 0x23 (user). Catches the
/// "wild iretq frame" class of corruption BEFORE iretq fires, so the
/// kstack is still intact for autopsy. Without this, the corrupt frame
/// would iretq to garbage and the next #UD/#GP would be in a context
/// detached from the actual writer.
///
/// Stack layout at jump time: %rsp points at the iretq frame's RIP slot.
/// slots[0]=RIP, slots[1]=CS, slots[2]=RFLAGS, slots[3]=RSP, slots[4]=SS.
pub export fn isr_iretq_corrupt_panic() callconv(.c) noreturn {
    const sym = @import("../debug/symbols.zig");
    const rsp_now: u64 = asm volatile ("mov %%rsp, %[r]"
        : [r] "=r" (-> u64),
    );
    const slots: [*]const u64 = @ptrFromInt(rsp_now);

    serial.print("\n!!! IRETQ FRAME CORRUPTED — caught BEFORE iretq fired !!!\n", .{});
    serial.print("  iretq frame at 0x{X:0>16}:\n", .{rsp_now});
    serial.print("    RIP   =0x{X:0>16}", .{slots[0]});
    if (sym.resolveKernel(slots[0])) |r| {
        serial.print("  ({s}+0x{X})", .{ r.name, r.offset });
    }
    serial.print("\n    CS    =0x{X:0>4}     <-- expected 0x08 (kernel) or 0x23 (user)\n", .{slots[1]});
    serial.print("    RFLAGS=0x{X:0>16}\n", .{slots[2]});
    serial.print("    RSP   =0x{X:0>16}", .{slots[3]});
    if (sym.resolveKernel(slots[3])) |r| {
        serial.print("  (kernel addr! — {s}+0x{X})", .{ r.name, r.offset });
    }
    serial.print("\n    SS    =0x{X:0>4}\n", .{slots[4]});
    serial.print("  Surrounding stack (32 qwords from RSP):\n", .{});
    @import("../debug/kdbg.zig").crashAutopsy(.{ .kernel_rsp = rsp_now });
    @panic("iretq frame corrupted — caller jumped here from CS-validation in isr stub");
}

