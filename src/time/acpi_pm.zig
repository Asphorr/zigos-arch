//! The ACPI power-management timer: a free-running counter at 3.579545 MHz,
//! 24 or 32 bits wide, behind the I/O port the FADT names. It counts through
//! everything short of S3 — the stall detector (smi.zig) measures gaps on it,
//! and the clock takes it for a reference where there is no better one
//! (refclock.zig).

const acpi = @import("../acpi/acpi.zig");
const io = @import("../io.zig");

pub const HZ: u64 = 3_579_545;

var port: u16 = 0; // (c) set by init
var mask: u32 = 0; // (c) the counter's bits; 0 = no timer

/// Find the timer in the FADT. After acpi.init; any number of times. False
/// on a machine without one.
pub fn init() bool {
    if (mask != 0) return true;
    const f = acpi.getFadt() orelse return false;
    if (f.pm_tmr_blk == 0 or f.pm_tmr_len == 0) return false;
    port = @truncate(f.pm_tmr_blk);
    // FADT.flags bit 8, TMR_VAL_EXT: the counter is 32 bits wide, else 24.
    mask = if (f.flags & (1 << 8) != 0) 0xFFFF_FFFF else 0xFF_FFFF;
    return true;
}

pub fn present() bool {
    return mask != 0;
}

pub fn ioPort() u16 {
    return port;
}

/// The counter's width: its wrap is 4.7 s at 24 bits, 20 minutes at 32.
pub fn counterMask() u32 {
    return mask;
}

/// The counter now. One port read — an exit to the VMM under a hypervisor.
pub inline fn read() u32 {
    return io.inl(port) & mask;
}

/// Ticks from `prev` to `now`, taking them to be less than a wrap apart.
pub inline fn delta(prev: u32, now: u32) u32 {
    return (now -% prev) & mask;
}
