// Test stub: 64 KiB fake port space so SystemIO field I/O is exercisable natively.
pub var PORTS: [0x10000]u8 = [_]u8{0} ** 0x10000;
pub inline fn outb(port: u16, data: u8) void { PORTS[port] = data; }
pub inline fn inb(port: u16) u8 { return PORTS[port]; }
pub inline fn outw(port: u16, data: u16) void { PORTS[port] = @truncate(data); PORTS[port +% 1] = @truncate(data >> 8); }
pub inline fn inw(port: u16) u16 { return @as(u16, PORTS[port]) | (@as(u16, PORTS[port +% 1]) << 8); }
pub inline fn outl(port: u16, data: u32) void {
    PORTS[port] = @truncate(data); PORTS[port +% 1] = @truncate(data >> 8);
    PORTS[port +% 2] = @truncate(data >> 16); PORTS[port +% 3] = @truncate(data >> 24);
}
pub inline fn inl(port: u16) u32 {
    return @as(u32, PORTS[port]) | (@as(u32, PORTS[port +% 1]) << 8) |
           (@as(u32, PORTS[port +% 2]) << 16) | (@as(u32, PORTS[port +% 3]) << 24);
}
