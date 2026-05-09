const io = @import("../io.zig");

pub fn init() void {
    io.outb(0x20, 0x11);
    io.outb(0xA0, 0x11);
    io.outb(0x21, 0x20);
    io.outb(0xA1, 0x28);
    io.outb(0x21, 0x04);
    io.outb(0xA1, 0x02);
    io.outb(0x21, 0x01);
    io.outb(0xA1, 0x01);
    io.outb(0x21, 0xFC); // IRQ0 (timer) + IRQ1 (keyboard)
    io.outb(0xA1, 0xFF);
}

pub fn enableIRQ(irq: u8) void {
    // Route through APIC if active
    if (@import("apic.zig").apic_active) {
        @import("apic.zig").enableIRQ(irq);
        return;
    }
    if (irq < 8) {
        const mask = io.inb(0x21);
        io.outb(0x21, mask & ~(@as(u8, 1) << @intCast(irq)));
    } else {
        // Enable cascade (IRQ2) on master
        const master_mask = io.inb(0x21);
        io.outb(0x21, master_mask & ~@as(u8, 4));
        // Enable specific slave IRQ
        const slave_mask = io.inb(0xA1);
        io.outb(0xA1, slave_mask & ~(@as(u8, 1) << @intCast(irq - 8)));
    }
}
