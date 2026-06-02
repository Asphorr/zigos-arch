pub const PciDevice = struct { bus: u8 = 0, dev: u8 = 0, func: u8 = 0 };
var none = [_]PciDevice{};
pub fn allDevices() []const PciDevice { return &none; }
pub fn configRead16(bus: u8, dev: u8, func: u8, offset: u8) u16 { _ = bus; _ = dev; _ = func; _ = offset; return 0xFFFF; }
