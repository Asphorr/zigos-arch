const io = @import("../io.zig");
const paging = @import("../mm/paging.zig");
const debug = @import("../debug/debug.zig");

// BGA register ports
const VBE_DISPI_IOPORT_INDEX: u16 = 0x01CE;
const VBE_DISPI_IOPORT_DATA: u16 = 0x01CF;

// BGA register indices
const VBE_DISPI_INDEX_ID: u16 = 0;
const VBE_DISPI_INDEX_XRES: u16 = 1;
const VBE_DISPI_INDEX_YRES: u16 = 2;
const VBE_DISPI_INDEX_BPP: u16 = 3;
const VBE_DISPI_INDEX_ENABLE: u16 = 4;

// Enable flags
const VBE_DISPI_DISABLED: u16 = 0x00;
const VBE_DISPI_ENABLED: u16 = 0x01;
const VBE_DISPI_LFB_ENABLED: u16 = 0x40;

// PCI config
const PCI_CONFIG_ADDR: u16 = 0x0CF8;
const PCI_CONFIG_DATA: u16 = 0x0CFC;
// Bochs VGA: vendor 0x1234, device 0x1111
const BGA_PCI_VENDOR: u16 = 0x1234;
const BGA_PCI_DEVICE: u16 = 0x1111;

pub var framebuffer: [*]volatile u32 = undefined;
pub var fb_phys: u32 = 0;
pub var width: u32 = 0;
pub var height: u32 = 0;

fn writeRegister(index: u16, value: u16) void {
    io.outb16(VBE_DISPI_IOPORT_INDEX, index);
    io.outb16(VBE_DISPI_IOPORT_DATA, value);
}

fn readRegister(index: u16) u16 {
    io.outb16(VBE_DISPI_IOPORT_INDEX, index);
    return io.inw(VBE_DISPI_IOPORT_DATA);
}

fn pciConfigRead(bus: u8, dev: u8, func: u8, offset: u8) u32 {
    const addr: u32 = @as(u32, 1) << 31 |
        @as(u32, bus) << 16 |
        @as(u32, dev) << 11 |
        @as(u32, func) << 8 |
        (@as(u32, offset) & 0xFC);
    io.outl(PCI_CONFIG_ADDR, addr);
    return io.inl(PCI_CONFIG_DATA);
}

/// Scan PCI bus for the Bochs VGA device and return BAR0 (framebuffer address)
fn findFramebufferAddr() u32 {
    var dev: u8 = 0;
    while (dev < 32) : (dev += 1) {
        const id = pciConfigRead(0, dev, 0, 0);
        const vendor: u16 = @truncate(id);
        const device: u16 = @truncate(id >> 16);
        if (vendor == BGA_PCI_VENDOR and device == BGA_PCI_DEVICE) {
            const bar0 = pciConfigRead(0, dev, 0, 0x10);
            debug.klog("[bga] Found PCI device at bus=0 dev={d} BAR0=0x{X:0>8}\n", .{ dev, bar0 });
            return bar0 & 0xFFFFFFF0; // Mask lower bits (type/prefetchable flags)
        }
    }
    // Fallback to standard address
    debug.klog("[bga] PCI device not found, using default 0xE0000000\n", .{});
    return 0xE0000000;
}

pub fn init(xres: u16, yres: u16) bool {
    // Check BGA presence
    const id = readRegister(VBE_DISPI_INDEX_ID);
    if (id < 0xB0C0) {
        debug.klog("[bga] Not detected (id=0x{X:0>4})\n", .{id});
        return false;
    }
    debug.klog("[bga] Detected id=0x{X:0>4}\n", .{id});

    // Find actual framebuffer address from PCI
    fb_phys = findFramebufferAddr();

    // Disable display first
    writeRegister(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);

    // Set resolution and color depth
    writeRegister(VBE_DISPI_INDEX_XRES, xres);
    writeRegister(VBE_DISPI_INDEX_YRES, yres);
    writeRegister(VBE_DISPI_INDEX_BPP, 32);

    // Enable with linear framebuffer
    writeRegister(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);

    width = xres;
    height = yres;

    // Map framebuffer into kernel address space
    const fb_size = @as(u32, xres) * @as(u32, yres) * 4;
    paging.mapMMIO(fb_phys, fb_size);
    framebuffer = @ptrFromInt(paging.physToVirt(fb_phys));

    debug.klog("[bga] Mode set: {d}x{d}x32 fb=0x{X:0>8} size={d}\n", .{ xres, yres, fb_phys, fb_size });
    return true;
}

pub fn disable() void {
    writeRegister(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
    width = 0;
    height = 0;
    // Re-enable VGA display (attribute controller can be blanked after BGA mode change)
    _ = io.inb(0x3DA); // Reset attribute controller flip-flop
    io.outb(0x3C0, 0x20); // Set PAS bit to enable display
    debug.klog("[bga] Disabled, VGA text mode restored\n", .{});
}
