//! 8254 PIT channel 0 — the boot-time 100 Hz tick source.
//!
//! Lifecycle: idt.zig programs the legacy PIC (vectors 0x20/0x28, IRQ0+1
//! unmasked), main.zig calls `init()` here, and the PIT drives IRQ0 until
//! apic.init() takes over (LAPIC timer becomes the tick; apic.init calls
//! `stop()` below). If APIC bring-up fails, this PIT/PIC pair IS the
//! system timer — see apic.init's fallback-unwind path.
//!
//! Channel 2 (speaker tone / calibration gate) is owned by speaker.zig and
//! apic.calibrateTimerPit — not touched here.

const io = @import("../io.zig");

pub fn init() void {
    const divisor: u16 = 11932; // 1193182 / 100 ≈ 11932 → ~100 Hz
    io.outb(0x43, 0x34); // Channel 0, lobyte/hibyte, mode 2 (rate generator)
    io.outb(0x40, @truncate(divisor));
    io.outb(0x40, @truncate(divisor >> 8));
}

/// Halt channel 0. Writing a control word with no count following stops
/// the count sequence (8254 datasheet: counting doesn't start until the
/// initial count is loaded) and drops OUT to mode 0's initial low state —
/// no more rising edges, so the dead-ended IRQ0 line stops latching a
/// phantom request into the masked PIC's IRR 100x/sec forever. Also
/// matches the post-S3 steady state, where the PIT returns unprogrammed.
pub fn stop() void {
    io.outb(0x43, 0x30); // Channel 0, lobyte/hibyte, mode 0 — count never loaded
}
