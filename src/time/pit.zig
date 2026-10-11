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

const PIT_HZ: u64 = 1_193_182;
const DIVISOR: u16 = 11932; // 1193182 / 100 ≈ 11932 → ~100 Hz

pub fn init() void {
    io.outb(0x43, 0x34); // Channel 0, lobyte/hibyte, mode 2 (rate generator)
    io.outb(0x40, @truncate(DIVISOR));
    io.outb(0x40, @truncate(DIVISOR >> 8));
}

/// Busy-wait `us` µs on channel 0's countdown — the only clock before
/// apic.init calibrates the TSC (acpi.init runs firmware methods, whose
/// Stall/Sleep must really wait). Gives up if the count stops moving, as it
/// does once stop() has run.
pub fn delayUs(us: u64) void {
    var left = us * PIT_HZ / 1_000_000;
    var prev = count();
    var still: u32 = 0;
    while (left > 0) {
        const cur = count();
        // Mode 2 counts DIVISOR..1 and reloads: a larger count means a wrap.
        const step = if (cur <= prev) prev - cur else prev + DIVISOR - cur;
        if (step == 0) {
            still += 1;
            if (still > 10_000) return;
            continue;
        }
        still = 0;
        left -|= step;
        prev = cur;
    }
}

fn count() u64 {
    io.outb(0x43, 0x00); // latch channel 0
    const lo: u64 = io.inb(0x40);
    const hi: u64 = io.inb(0x40);
    return hi << 8 | lo;
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
