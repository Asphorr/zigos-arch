const io = @import("../io.zig");

pub fn init() void {
    const divisor: u16 = 11932; // 1193182 / 100 ≈ 11932 → ~100 Hz
    io.outb(0x43, 0x34); // Channel 0, lobyte/hibyte, mode 2 (rate generator)
    io.outb(0x40, @truncate(divisor));
    io.outb(0x40, @truncate(divisor >> 8));
}
