//! Minor IRQ handlers and their naked stubs:
//!   - keyboard (vec 0x21 / IRQ1)
//!   - mouse    (vec 0x2C / IRQ12)
//!   - spurious (vec 0xFF — no EOI on spurious deliveries)
//!   - TLB-shootdown IPI (vec from mmu/tlb.zig)
//!   - PMI (vec from arch/pmu.zig)
//!
//! All share the same caller-saved + FXSAVE shape as the keyboard stub —
//! 9 GPRs + 512 FXSAVE = 624B ≡ 0 mod 16 at `call`. The body Zig handlers
//! are tiny — most of the work is in keyboard/mouse/tlb/pmu modules; this
//! file just owns the asm trampolines + EOI bookkeeping.

const io = @import("../../io.zig");
const apic = @import("../../time/apic.zig");
const keyboard = @import("../../driver/keyboard.zig");
const mouse = @import("../../driver/mouse.zig");

export fn handleIRQ1() callconv(.c) void {
    @import("../arch/protect.zig").disallowUserAccess();
    const t = @import("../../debug/perf.zig").enter();
    defer @import("../../debug/perf.zig").leave(.irq1_kbd, t);
    const scancode = io.inb(0x60);
    keyboard.handleScancode(scancode);
    sendEOI();
}

export fn handleIRQ12() callconv(.c) void {
    @import("../arch/protect.zig").disallowUserAccess();
    const t = @import("../../debug/perf.zig").enter();
    defer @import("../../debug/perf.zig").leave(.irq12_mouse, t);
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

// Keyboard IRQ stub — push 9 caller-saved GPRs + FXSAVE.
// Alignment math at `call handleIRQ1`:
//   CPU frame = 40, 9 GPRs = 72, FXSAVE = 512 → 624B ≡ 0 mod 16 ✓
pub fn isr_irq1() callconv(.naked) void {
    asm volatile (
        \\ pushq %%rax
        \\ pushq %%rcx
        \\ pushq %%rdx
        \\ pushq %%rdi
        \\ pushq %%rsi
        \\ pushq %%r8
        \\ pushq %%r9
        \\ pushq %%r10
        \\ pushq %%r11
        \\ subq $512, %%rsp
        \\ fxsaveq (%%rsp)
        \\ test $0xF, %%rsp
        \\ jnz isr_irq1_align_panic
        \\ call handleIRQ1
        \\ fxrstorq (%%rsp)
        \\ addq $512, %%rsp
        \\ popq %%r11
        \\ popq %%r10
        \\ popq %%r9
        \\ popq %%r8
        \\ popq %%rsi
        \\ popq %%rdi
        \\ popq %%rdx
        \\ popq %%rcx
        \\ popq %%rax
        \\ iretq
    );
}

// Mouse IRQ stub — same pattern as keyboard.
// Alignment math: 40 + 72 + 512 = 624B ≡ 0 mod 16 ✓
pub fn isr_irq12() callconv(.naked) void {
    asm volatile (
        \\ pushq %%rax
        \\ pushq %%rcx
        \\ pushq %%rdx
        \\ pushq %%rdi
        \\ pushq %%rsi
        \\ pushq %%r8
        \\ pushq %%r9
        \\ pushq %%r10
        \\ pushq %%r11
        \\ subq $512, %%rsp
        \\ fxsaveq (%%rsp)
        \\ test $0xF, %%rsp
        \\ jnz isr_irq12_align_panic
        \\ call handleIRQ12
        \\ fxrstorq (%%rsp)
        \\ addq $512, %%rsp
        \\ popq %%r11
        \\ popq %%r10
        \\ popq %%r9
        \\ popq %%r8
        \\ popq %%rsi
        \\ popq %%rdi
        \\ popq %%rdx
        \\ popq %%rcx
        \\ popq %%rax
        \\ iretq
    );
}

pub fn isr_spurious() callconv(.naked) void {
    asm volatile ("iretq"); // No EOI for spurious interrupts
}

// TLB-shootdown IPI stub (vector from mmu/tlb.zig). Same caller-saved
// pattern as isr_irq1; handler does cr3 reload + ack decrement + eoi.
// Alignment: 40 + 72 + 512 = 624B ≡ 0 mod 16 ✓
pub fn isr_tlb_shootdown() callconv(.naked) void {
    asm volatile (
        \\ pushq %%rax
        \\ pushq %%rcx
        \\ pushq %%rdx
        \\ pushq %%rdi
        \\ pushq %%rsi
        \\ pushq %%r8
        \\ pushq %%r9
        \\ pushq %%r10
        \\ pushq %%r11
        \\ subq $512, %%rsp
        \\ fxsaveq (%%rsp)
        \\ test $0xF, %%rsp
        \\ jnz isr_tlb_shootdown_align_panic
        \\ call handleTlbShootdown
        \\ fxrstorq (%%rsp)
        \\ addq $512, %%rsp
        \\ popq %%r11
        \\ popq %%r10
        \\ popq %%r9
        \\ popq %%r8
        \\ popq %%rsi
        \\ popq %%rdi
        \\ popq %%rdx
        \\ popq %%rcx
        \\ popq %%rax
        \\ iretq
    );
}

pub export fn isr_tlb_shootdown_align_panic() callconv(.c) noreturn {
    @panic("isr_tlb_shootdown: RSP misaligned at call handleTlbShootdown");
}

// PMI (Performance Monitoring Interrupt) stub — vector from arch/pmu.zig.
// LAPIC's LVT.PMI delivers here when PMC0 overflows. Same caller-saved +
// fxsave shape as isr_tlb_shootdown. Reads the saved RIP off the iretq
// frame to hand to pmu.onSample for one-line "where did the sample land"
// log output.
pub fn isr_pmi() callconv(.naked) void {
    asm volatile (
        \\ pushq %%rax
        \\ pushq %%rcx
        \\ pushq %%rdx
        \\ pushq %%rdi
        \\ pushq %%rsi
        \\ pushq %%r8
        \\ pushq %%r9
        \\ pushq %%r10
        \\ pushq %%r11
        \\ subq $512, %%rsp
        \\ fxsaveq (%%rsp)
        \\ test $0xF, %%rsp
        \\ jnz isr_pmi_align_panic
        \\ movq 584(%%rsp), %%rdi
        \\ call handlePmi
        \\ fxrstorq (%%rsp)
        \\ addq $512, %%rsp
        \\ popq %%r11
        \\ popq %%r10
        \\ popq %%r9
        \\ popq %%r8
        \\ popq %%rsi
        \\ popq %%rdi
        \\ popq %%rdx
        \\ popq %%rcx
        \\ popq %%rax
        \\ iretq
    );
}

pub export fn isr_pmi_align_panic() callconv(.c) noreturn {
    @panic("isr_pmi: RSP misaligned at call handlePmi");
}

export fn handlePmi(rip: u64) callconv(.c) void {
    @import("../arch/pmu.zig").onSample(rip);
}

pub export fn isr_irq1_align_panic() callconv(.c) noreturn {
    @panic("isr_irq1: RSP misaligned at call handleIRQ1 — recount pushes");
}
pub export fn isr_irq12_align_panic() callconv(.c) noreturn {
    @panic("isr_irq12: RSP misaligned at call handleIRQ12 — recount pushes");
}
