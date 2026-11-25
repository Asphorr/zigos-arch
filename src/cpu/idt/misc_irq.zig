//! Minor IRQ handlers and their naked stubs:
//!   - keyboard (vec 0x21 / IRQ1)
//!   - mouse    (vec 0x2C / IRQ12)
//!   - spurious (vec 0xFF — no EOI on spurious deliveries)
//!   - TLB-shootdown IPI (vec from mmu/tlb.zig)
//!   - PMI (vec from arch/pmu.zig)
//!
//! The four that call a handler share one frame, `frames.entry.device`: the
//! registers a C handler may clobber and the FXSAVE image. The handlers are
//! tiny — the work is in the keyboard/mouse/tlb/pmu modules; this file owns
//! the stubs and the EOI bookkeeping.

const io = @import("../../io.zig");
const apic = @import("../../irq/apic.zig");
const keyboard = @import("../../driver.zig").keyboard;
const mouse = @import("../../driver.zig").mouse;
const stub = @import("stub.zig");
const device = @import("../../proc/frames.zig").entry.device;

// ctx: irq — PS/2 keyboard, IF=0 (tools/ctx_lint.zig root).
export fn handleIRQ1() callconv(.c) void {
    @import("../arch/protect.zig").disallowUserAccess();
    @import("../../proc/spinlock.zig").hardirqEnter();
    defer @import("../../proc/spinlock.zig").hardirqExit();
    const t = @import("../../debug/perf.zig").enter();
    defer @import("../../debug/perf.zig").leave(.irq1_kbd, t);
    defer @import("../../syscall.zig").chargeInterrupt(t);
    // Mirror of mouse.handleIRQ's status gate: bit 0 = a byte is actually
    // there (IRQ1 can fire spuriously), bit 5 clear = it's KEYBOARD data.
    // The i8042 is shared — an unconditional read here could swallow an
    // AUX (mouse) byte and feed it to the scancode decoder.
    const st = io.inb(0x64);
    if (st & 0x01 == 0 or st & 0x20 != 0) {
        sendEOI();
        return;
    }
    const scancode = io.inb(0x60);
    keyboard.handleScancode(scancode);
    sendEOI();
}

// ctx: irq — PS/2 mouse, IF=0 (tools/ctx_lint.zig root).
export fn handleIRQ12() callconv(.c) void {
    @import("../arch/protect.zig").disallowUserAccess();
    @import("../../proc/spinlock.zig").hardirqEnter();
    defer @import("../../proc/spinlock.zig").hardirqExit();
    const t = @import("../../debug/perf.zig").enter();
    defer @import("../../debug/perf.zig").leave(.irq12_mouse, t);
    defer @import("../../syscall.zig").chargeInterrupt(t);
    mouse.handleIRQ();
    if (!apic.apic_active) {
        io.outb(0xA0, 0x20); // Slave PIC EOI (only needed for legacy PIC)
    }
    sendEOI();
}

/// EOI helper — LAPIC path when apic_active, legacy-PIC fallback before
/// APIC init. Inline-callable; duplicated in idt/irq0.zig too because
/// putting it in idt.zig would force a circular import.
pub fn sendEOI() void {
    if (apic.apic_active) {
        apic.eoi();
    } else {
        io.outb(0x20, 0x20);
    }
}

pub fn isr_irq1() callconv(.naked) void {
    asm volatile (stub.handler(device, "handleIRQ1", .none));
}

pub fn isr_irq12() callconv(.naked) void {
    asm volatile (stub.handler(device, "handleIRQ12", .none));
}

pub fn isr_spurious() callconv(.naked) void {
    asm volatile ("iretq"); // No EOI for spurious interrupts
}

/// Count of 8259 spurious deliveries (IRQ7/IRQ15) — legacy-PIC mode only.
/// Pure breadcrumb: readable from a debugger/memory dump when a real-HW
/// PIC-fallback boot is acting up. Never read by kernel code.
pub export var pic_spurious_count: u32 = 0;

// 8259 spurious vectors — only reachable in legacy-PIC mode (APIC absent,
// or apic.init's calibration sanity check failed and unwound to the PIC).
// A request that vanishes between INT assertion and INTA makes the master
// 8259 deliver IRQ7 (vec 0x27) / the slave deliver IRQ15 (vec 0x2F) with
// NO ISR bit set. Both device lines are permanently masked in this kernel
// (pic.init mask 0xFC/0xFF; mouse only ever unmasks slave bit 4), so any
// delivery on these vectors is spurious by construction. Without these
// stubs the vectors hold non-present IDT entries — electrical noise on a
// real-HW legacy boot would #GP-panic the kernel. NOTE: keep IOAPIC
// routing away from vectors 0x27/0x2F — these stubs never EOI the LAPIC.
//
// `lock incl` clobbers RFLAGS, which is fine here: iretq restores the
// interrupted context's RFLAGS from the frame.
//
// Master spurious: no EOI at all (no ISR bit set anywhere).
pub fn isr_pic7_spurious() callconv(.naked) void {
    asm volatile (
        \\ lock incl pic_spurious_count(%%rip)
        \\ iretq
    );
}

// Slave spurious: the MASTER's cascade (IRQ2) ISR bit IS set — it saw a
// real request from the slave — so EOI the master only, never the slave.
pub fn isr_pic15_spurious() callconv(.naked) void {
    asm volatile (
        \\ lock incl pic_spurious_count(%%rip)
        \\ pushq %%rax
        \\ movb $0x20, %%al
        \\ outb %%al, $0x20
        \\ popq %%rax
        \\ iretq
    );
}

// TLB-shootdown IPI (vector from mmu/tlb.zig): the handler reloads CR3,
// acks and EOIs.
pub fn isr_tlb_shootdown() callconv(.naked) void {
    asm volatile (stub.handler(device, "handleTlbShootdown", .none));
}

// PMI (vector from arch/pmu.zig): LVT.PMI delivers here when PMC0
// overflows. The handler gets the RIP the sample landed on.
pub fn isr_pmi() callconv(.naked) void {
    asm volatile (stub.handler(device, "handlePmi", .rip));
}

// ctx: irq — LVT.PMI overflow, IF=0 (tools/ctx_lint.zig root).
export fn handlePmi(rip: u64) callconv(.c) void {
    @import("../arch/pmu.zig").onSample(rip);
}
