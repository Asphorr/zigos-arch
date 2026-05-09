const io = @import("../io.zig");
const acpi = @import("../time/acpi.zig");
const paging = @import("../mm/paging.zig");
const debug = @import("../debug/debug.zig");

const CONFIG_ADDR: u16 = 0x0CF8;
const CONFIG_DATA: u16 = 0x0CFC;

// MCFG-derived ECAM (Enhanced Configuration Access Mechanism). When
// present, replaces the legacy 0xCF8/0xCFC port pair with memory-mapped
// config space — a hard requirement for >256-bus PCIe systems and for
// PCIe-only registers (extended caps live above offset 0xFF, which the
// legacy port mechanism cannot reach). i440fx-class QEMU boards have
// no MCFG; q35 and most real hardware do.
var ecam_base: u64 = 0;
var ecam_start_bus: u8 = 0;
var ecam_end_bus: u8 = 0;

/// Parse MCFG (called once after acpi.init). Caches the first segment's
/// window for ECAM access; additional segments are logged but not used.
pub fn applyAcpi() void {
    const m = acpi.getMcfg() orelse return;
    const entries_off: usize = @sizeOf(acpi.Mcfg);
    if (m.header.length <= entries_off) return;
    const entries: [*]align(1) const acpi.McfgSegment = @ptrFromInt(@intFromPtr(m) + entries_off);
    const count = (m.header.length - entries_off) / @sizeOf(acpi.McfgSegment);

    var i: usize = 0;
    while (i < count) : (i += 1) {
        const seg = entries[i];
        debug.klog("[pci] MCFG seg{d}: base=0x{x} buses {d}..{d}\n", .{ i, seg.base, seg.start_bus, seg.end_bus });
        if (i == 0) {
            ecam_base = seg.base;
            ecam_start_bus = seg.start_bus;
            ecam_end_bus = seg.end_bus;
            const bus_count: usize = @as(usize, seg.end_bus - seg.start_bus) + 1;
            const window_size: usize = bus_count * 256 * 4096;
            paging.mapMMIO(@intCast(seg.base), window_size);
            debug.klog("[pci] ECAM enabled at 0x{x} ({d} MB)\n", .{ seg.base, window_size / (1024 * 1024) });
        }
    }
}

inline fn ecamPtr(bus: u8, dev: u8, func: u8, offset: u16) ?*volatile u32 {
    if (ecam_base == 0) return null;
    if (bus < ecam_start_bus or bus > ecam_end_bus) return null;
    const rel_bus: u64 = @as(u64, bus - ecam_start_bus);
    const addr: u64 = ecam_base +
        (rel_bus << 20) |
        (@as(u64, dev) << 15) |
        (@as(u64, func) << 12) |
        @as(u64, offset & 0xFFC);
    // ecam_base is a phys address (from MCFG); deref through the physmap so
    // ECAM works without the legacy low identity map.
    return @ptrFromInt(paging.physToVirt(addr));
}

pub const PciDevice = struct {
    bus: u8,
    dev: u8,
    func: u8,
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    bar0: usize, // Full 64-bit BAR address (handles UEFI high mappings)
    bar1: usize,
    irq_line: u8,
};

// --- Device cache ---------------------------------------------------------
//
// One-shot bus enumeration, populated by `enumerate()` during early boot.
// Drivers used to each call `findByClass` which re-walked the bus from
// scratch every time (4096 config-space reads × N drivers); worse, two
// drivers (nvme, virtio_sound) had hand-rolled bus walks because
// `findByClass` only returned the first match. With the cache:
//   - one walk total, logged in one place ("[pci] devices:" block)
//   - findByClass / findByVendorDevice / findAllByClass / forEachDevice
//     all return cache results, so adding a driver doesn't add a walk
//   - drivers stop duplicating the "vendor==0xFFFF / multi-function /
//     readBar64 / read IRQ line" boilerplate
//
// MAX_DEVICES is generously sized — a typical QEMU + UEFI guest has ~12
// devices (host bridge, ISA bridge, virtio-gpu, virtio-net, NVMe, AHCI,
// xHCI, AC97, ...) and even a server-class board with two PCIe roots and
// hot-plug slots stays well under 64.
const MAX_DEVICES: usize = 64;
var devices: [MAX_DEVICES]PciDevice = undefined;
var device_count: usize = 0;
// Parallel "did some driver claim this slot?" array. Each driver calls
// `markBound` after a successful init so `logUnbound` can call out devices
// that no driver picked up. Kept as a separate bitmask rather than a field
// on PciDevice so existing by-value APIs keep working unchanged.
var bound: [MAX_DEVICES]bool = [_]bool{false} ** MAX_DEVICES;

/// Walk every (bus, dev, func) triplet once, populate `devices`, and log
/// each found device with a readable class name. Idempotent: a second
/// call is a no-op (drivers can use the cache without coordinating
/// "who's first").
pub fn enumerate() void {
    if (device_count != 0) return;
    debug.klog("[pci] enumerating bus...\n", .{});
    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var dev_idx: u8 = 0;
        while (dev_idx < 32) : (dev_idx += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (readDevice(@truncate(bus), dev_idx, func)) |d| {
                    if (device_count < MAX_DEVICES) {
                        devices[device_count] = d;
                        device_count += 1;
                        debug.klog(
                            "[pci]   {x:0>2}:{x:0>2}.{d} {s} vendor=0x{x:0>4} device=0x{x:0>4} class={x:0>2}.{x:0>2}.{x:0>2} bar0=0x{x} irq={d}\n",
                            .{
                                d.bus, d.dev, d.func, classifyName(d.class_code, d.subclass),
                                d.vendor_id, d.device_id,
                                d.class_code, d.subclass, d.prog_if,
                                d.bar0, d.irq_line,
                            },
                        );
                    } else {
                        debug.klog("[pci] cache full (>{d}); ignoring further devices\n", .{MAX_DEVICES});
                        return;
                    }
                    if (func == 0) {
                        // Multi-function: bit 23 of header_type@0x0C set?
                        const header = configRead(@truncate(bus), dev_idx, 0, 0x0C);
                        if (header & 0x00800000 == 0) break;
                    }
                } else {
                    if (func == 0) break;
                }
            }
        }
    }
    debug.klog("[pci] {d} device(s) cached\n", .{device_count});
}

/// Iterate cached devices. Caller's `cb` is called once per device.
pub fn forEachDevice(comptime Ctx: type, ctx: *Ctx, cb: *const fn (*Ctx, PciDevice) void) void {
    for (devices[0..device_count]) |d| cb(ctx, d);
}

/// Fill `out` with every cached device matching (class, subclass, prog_if).
/// Returns count written. Drivers that handle multiple controllers (NVMe)
/// use this to find all of them in one pass.
pub fn findAllByClass(class: u8, subclass: u8, prog_if: u8, out: []PciDevice) usize {
    var n: usize = 0;
    for (devices[0..device_count]) |d| {
        if (d.class_code == class and d.subclass == subclass and d.prog_if == prog_if) {
            if (n >= out.len) break;
            out[n] = d;
            n += 1;
        }
    }
    return n;
}

/// Loose match: ignores prog_if. ATA driver wants this since legacy IDE
/// chipsets show up with prog_if 0x80 / 0x8A / 0x00 depending on whether
/// they're in compat or native mode.
pub fn findByClassPartial(class: u8, subclass: u8) ?PciDevice {
    for (devices[0..device_count]) |d| {
        if (d.class_code == class and d.subclass == subclass) return d;
    }
    return null;
}

/// Drivers call this after a successful init so `logUnbound` knows which
/// slots are covered. Quietly no-ops on unknown bdf (driver passing a
/// device it didn't get from the cache — unusual but not worth panicking).
pub fn markBound(dev: PciDevice) void {
    for (devices[0..device_count], 0..) |cached, i| {
        if (cached.bus == dev.bus and cached.dev == dev.dev and cached.func == dev.func) {
            bound[i] = true;
            return;
        }
    }
}

/// End-of-driver-init summary. Walks the device cache and logs any device
/// in an "interesting" class (storage / network / display / multimedia /
/// USB) that no driver claimed. The output points at the gap a real-HW
/// boot exposed — typically a NIC variant, a chipset SATA/NVMe quirk, or
/// an audio device we don't drive yet. Bridges (class 6) and base-system
/// devices (class 8) are skipped — we never bind those.
pub fn logUnbound() void {
    var unbound_count: u32 = 0;
    for (devices[0..device_count], 0..) |d, i| {
        if (bound[i]) continue;
        const interesting = switch (d.class_code) {
            0x01, 0x02, 0x03, 0x04, 0x0C => true,
            else => false,
        };
        if (!interesting) continue;
        if (unbound_count == 0) debug.klog("[pci] unbound interesting devices:\n", .{});
        unbound_count += 1;
        debug.klog(
            "[pci]   {x:0>2}:{x:0>2}.{d} {s} 0x{x:0>4}:0x{x:0>4} class={x:0>2}.{x:0>2} — no driver\n",
            .{
                d.bus, d.dev, d.func, classifyName(d.class_code, d.subclass),
                d.vendor_id, d.device_id,
                d.class_code, d.subclass,
            },
        );
    }
    if (unbound_count == 0) debug.klog("[pci] all interesting devices bound\n", .{});
}

/// Routine "I'm taking this device" boilerplate that nearly every driver
/// duplicates: enable Memory + I/O space decoding (PCI command bits 0/1),
/// enable Bus Master (bit 2), and disable legacy INTx (bit 10) so a
/// driver that arms MSI-X doesn't also see ghost interrupts on the
/// shared IOAPIC line.
///
/// Drivers can still poke the command register afterwards if they need
/// device-specific bits (e.g. AC97 doesn't want INTx disabled because it
/// has no MSI). Default to bindDevice for everyone using MSI/MSI-X.
pub fn bindDevice(dev: PciDevice) void {
    var cmd = configRead16(dev.bus, dev.dev, dev.func, 0x04);
    cmd |= 0x0007; // I/O space + Memory space + Bus Master
    cmd |= 0x0400; // Disable legacy INTx (MSI/MSI-X drivers want this)
    configWrite16(dev.bus, dev.dev, dev.func, 0x04, cmd);
    markBound(dev);
}

/// Like bindDevice but keeps INTx live. For drivers that have no MSI/MSI-X
/// path (legacy AC97, IDE in compat mode).
pub fn bindDeviceLegacyIrq(dev: PciDevice) void {
    var cmd = configRead16(dev.bus, dev.dev, dev.func, 0x04);
    cmd |= 0x0007; // I/O + Memory + Bus Master
    cmd &= ~@as(u16, 0x0400); // ensure INTx is enabled
    configWrite16(dev.bus, dev.dev, dev.func, 0x04, cmd);
    markBound(dev);
}

/// Read-friendly device-class label for the boot log. We don't need the
/// full PCI class table (that's hundreds of entries) — just enough to make
/// the enumerate() output instantly recognisable. Unknown classes show as
/// "class XX.YY".
fn classifyName(class: u8, subclass: u8) []const u8 {
    return switch (class) {
        0x00 => "unclassified",
        0x01 => switch (subclass) {
            0x01 => "ide",
            0x06 => "sata",
            0x08 => "nvme",
            else => "storage",
        },
        0x02 => switch (subclass) {
            0x00 => "ethernet",
            else => "network",
        },
        0x03 => switch (subclass) {
            0x00 => "vga",
            else => "display",
        },
        0x04 => switch (subclass) {
            0x01 => "audio",
            0x03 => "hd-audio",
            else => "multimedia",
        },
        0x06 => switch (subclass) {
            0x00 => "host-bridge",
            0x01 => "isa-bridge",
            0x04 => "pci-bridge",
            else => "bridge",
        },
        0x0C => switch (subclass) {
            0x03 => "usb",
            else => "serial-bus",
        },
        else => "device",
    };
}

/// Total cached device count. Mainly for diagnostics / sanity checks.
pub fn deviceCount() usize {
    return device_count;
}

// --- Config space access ---

pub fn configRead(bus: u8, dev: u8, func: u8, offset: u8) u32 {
    if (ecamPtr(bus, dev, func, offset)) |p| return p.*;
    const addr: u32 = @as(u32, 1) << 31 |
        @as(u32, bus) << 16 |
        @as(u32, dev) << 11 |
        @as(u32, func) << 8 |
        (@as(u32, offset) & 0xFC);
    io.outl(CONFIG_ADDR, addr);
    return io.inl(CONFIG_DATA);
}

pub fn configWrite(bus: u8, dev: u8, func: u8, offset: u8, value: u32) void {
    if (ecamPtr(bus, dev, func, offset)) |p| {
        p.* = value;
        return;
    }
    const addr: u32 = @as(u32, 1) << 31 |
        @as(u32, bus) << 16 |
        @as(u32, dev) << 11 |
        @as(u32, func) << 8 |
        (@as(u32, offset) & 0xFC);
    io.outl(CONFIG_ADDR, addr);
    io.outl(CONFIG_DATA, value);
}

pub fn configRead16(bus: u8, dev: u8, func: u8, offset: u8) u16 {
    const val32 = configRead(bus, dev, func, offset & 0xFC);
    const shift: u5 = @truncate((offset & 2) * 8);
    return @truncate(val32 >> shift);
}

pub fn configWrite16(bus: u8, dev: u8, func: u8, offset: u8, value: u16) void {
    const aligned = offset & 0xFC;
    var val32 = configRead(bus, dev, func, aligned);
    const shift: u5 = @truncate((offset & 2) * 8);
    val32 &= ~(@as(u32, 0xFFFF) << shift);
    val32 |= @as(u32, value) << shift;
    configWrite(bus, dev, func, aligned, val32);
}

// --- Device scanning ---

fn readDevice(bus: u8, dev: u8, func: u8) ?PciDevice {
    const id = configRead(bus, dev, func, 0x00);
    const vendor_id: u16 = @truncate(id);
    if (vendor_id == 0xFFFF) return null;

    const device_id: u16 = @truncate(id >> 16);
    const class_reg = configRead(bus, dev, func, 0x08);
    const class_code: u8 = @truncate(class_reg >> 24);
    const subclass: u8 = @truncate(class_reg >> 16);
    const prog_if: u8 = @truncate(class_reg >> 8);

    const irq = configRead(bus, dev, func, 0x3C);

    return .{
        .bus = bus,
        .dev = dev,
        .func = func,
        .vendor_id = vendor_id,
        .device_id = device_id,
        .class_code = class_code,
        .subclass = subclass,
        .prog_if = prog_if,
        .bar0 = readBar64(bus, dev, func, 0x10),
        .bar1 = readBar64(bus, dev, func, 0x18), // Skip BAR1 if BAR0 is 64-bit
        .irq_line = @truncate(irq),
    };
}

/// Read a BAR, handling 64-bit BARs (type 2 in bits 2:1).
pub fn readBar64(bus: u8, dev: u8, func: u8, offset: u8) usize {
    const bar_lo = configRead(bus, dev, func, offset);
    if (bar_lo & 1 != 0) return bar_lo & 0xFFFFFFFC; // I/O BAR
    const bar_type = (bar_lo >> 1) & 3;
    const base_lo: usize = bar_lo & 0xFFFFFFF0;
    if (bar_type == 2) {
        // 64-bit BAR: next register has upper 32 bits
        const bar_hi: usize = configRead(bus, dev, func, offset + 4);
        return base_lo | (bar_hi << 32);
    }
    return base_lo;
}

// --- MMIO bump allocator for unassigned BARs (UEFI/OVMF fallback) ---
// Starts at 32GB, well above 4GB BARs and any RAM. Sits below OVMF's
// auto-assigned BAR region (~0x810000000) but the 64GB UEFI identity map
// covers this range (PDPT entries 0..63 = 0..64GB).
var mmio_next: u64 = 0x800000000; // 32GB

/// Allocate a `size`-byte MMIO range aligned to `alignment`. Returns the base.
/// PCI requires BAR alignment ≥ size (typically equal). Caller passes both
/// equal for simplicity.
pub fn allocMmio64(size: u64, alignment: u64) u64 {
    const aligned = (mmio_next + alignment - 1) & ~(alignment - 1);
    mmio_next = aligned + size;
    return aligned;
}

/// Manually assign a 64-bit BAR base. Used when firmware (OVMF) leaves the
/// BAR unassigned. Disables MEM decode during the write to avoid stray
/// decodes from a partially-written BAR. Preserves type/prefetchable bits.
pub fn assignBar64(bus: u8, dev: u8, func: u8, bar_idx: u8, base: u64) void {
    const cmd_off: u8 = 0x04;
    const orig_cmd = configRead16(bus, dev, func, cmd_off);

    // Clear MEM decode (bit 1) during BAR write
    configWrite16(bus, dev, func, cmd_off, orig_cmd & ~@as(u16, 0x02));

    const bar_off: u8 = 0x10 + bar_idx * 4;
    const orig_lo = configRead(bus, dev, func, bar_off);
    const new_lo: u32 = (@as(u32, @truncate(base)) & 0xFFFFFFF0) | (orig_lo & 0x0F);
    const new_hi: u32 = @truncate(base >> 32);
    configWrite(bus, dev, func, bar_off, new_lo);
    configWrite(bus, dev, func, bar_off + 4, new_hi);

    // Re-enable MEM decode + bus master + I/O space (preserve original other bits)
    configWrite16(bus, dev, func, cmd_off, orig_cmd | 0x07);
}

/// Find a cached PCI device by class/subclass/prog_if. After
/// `enumerate()` runs (early in boot) this is a linear scan over a small
/// in-memory array — no config-space reads. Returns the first match.
pub fn findByClass(class: u8, subclass: u8, prog_if: u8) ?PciDevice {
    for (devices[0..device_count]) |d| {
        if (d.class_code == class and d.subclass == subclass and d.prog_if == prog_if) {
            return d;
        }
    }
    return null;
}

/// Find a cached PCI device by vendor/device ID. Same cache-backed scan
/// as findByClass.
pub fn findByVendorDevice(vendor: u16, device: u16) ?PciDevice {
    for (devices[0..device_count]) |d| {
        if (d.vendor_id == vendor and d.device_id == device) return d;
    }
    return null;
}

/// Get the size of a BAR by writing all-ones and reading back.
pub fn getBarSize(dev: PciDevice, bar_idx: u8) u32 {
    const offset: u8 = 0x10 + bar_idx * 4;
    const original = configRead(dev.bus, dev.dev, dev.func, offset);
    configWrite(dev.bus, dev.dev, dev.func, offset, 0xFFFFFFFF);
    const size_mask = configRead(dev.bus, dev.dev, dev.func, offset);
    configWrite(dev.bus, dev.dev, dev.func, offset, original); // Restore
    if (size_mask == 0 or size_mask == 0xFFFFFFFF) return 0;
    // For MMIO BARs: mask lower 4 bits, invert, add 1
    const masked = size_mask & 0xFFFFFFF0;
    return (~masked) +% 1;
}

/// Enable PCI bus mastering (required for DMA).
pub fn enableBusMaster(dev: PciDevice) void {
    var cmd = configRead16(dev.bus, dev.dev, dev.func, 0x04);
    cmd |= 0x06; // Bus Master (bit 2) + Memory Space (bit 1)
    configWrite16(dev.bus, dev.dev, dev.func, 0x04, cmd);
}

// --- Virtio modern PCI capability parsing ----------------------------------
//
// Modern virtio devices expose 5+ vendor-specific caps (cap_id 0x09)
// each describing where one piece of the device's register surface lives
// (common config, notify region, ISR, device config, PCI access window,
// shared memory). `findCapability` only matches by cap_id, so before
// this helper every virtio driver (gpu, sound, ...) carried a near-
// identical inner loop that walked the cap list and additionally
// matched on the `cfg_type` byte to find the right region.

pub const VirtioCap = struct {
    cfg_off: u8, // offset of the cap header in config space
    bar: u8, // BAR index that holds the region
    offset: u32, // offset within that BAR
    length: u32, // length of the region
    notify_off_mult: u32, // valid only for NOTIFY_CFG (cfg_type == 2)
};

/// Find a virtio modern cap with the given `cfg_type`. Spec values:
///   1 = common cfg, 2 = notify cfg, 3 = ISR, 4 = device cfg, 5 = PCI cfg,
///   8 = shared memory.
/// Drivers can pass their own named constant — we keep the helper
/// numeric so we don't pull in a virtio enum from the kernel core.
pub fn findVirtioCap(dev: PciDevice, cfg_type: u8) ?VirtioCap {
    const status = configRead16(dev.bus, dev.dev, dev.func, 0x06);
    if (status & 0x10 == 0) return null;
    var off: u8 = @truncate(configRead(dev.bus, dev.dev, dev.func, 0x34) & 0xFC);
    if (off == 0) return null;
    var hops: u8 = 0;
    while (off >= 0x40 and hops < 64) : (hops += 1) {
        const hdr = configRead(dev.bus, dev.dev, dev.func, off);
        const id: u8 = @truncate(hdr);
        const next: u8 = @truncate(hdr >> 8);
        if (id == 0x09) {
            const vtype: u8 = @truncate(hdr >> 24);
            if (vtype == cfg_type) {
                const data = configRead(dev.bus, dev.dev, dev.func, off + 4);
                const off_val = configRead(dev.bus, dev.dev, dev.func, off + 8);
                const len_val = configRead(dev.bus, dev.dev, dev.func, off + 12);
                // Only NOTIFY_CFG carries a notify_off_multiplier at +16;
                // gating the read avoids touching reserved space for the
                // other cfg_types.
                const mult: u32 = if (cfg_type == 2)
                    configRead(dev.bus, dev.dev, dev.func, off + 16)
                else
                    0;
                return .{
                    .cfg_off = off,
                    .bar = @truncate(data),
                    .offset = off_val,
                    .length = len_val,
                    .notify_off_mult = mult,
                };
            }
        }
        if (next == 0) return null;
        off = next & 0xFC;
    }
    return null;
}

/// Map a device's MMIO BAR and return its kernel physmap VA. Returns
/// null for I/O-space BARs (drivers using legacy port I/O — like
/// virtio_net's BAR0 — should keep using port reads).
///
/// `size` is the window length to map. Drivers usually pass a small
/// fixed value (4-64 KB) rather than calling `getBarSize` first, since
/// the size-probe protocol requires write-then-read on the BAR which
/// briefly disables decoding and is fragile on some chipsets. Dropping
/// 4 KB on a 64 KB BAR just means later accesses past the mapped window
/// would page-fault loudly — easy to spot and fix by raising `size`.
pub fn mapBar(dev: PciDevice, bar_idx: u8, size: usize) ?usize {
    const bar_off: u8 = 0x10 + bar_idx * 4;
    const bar_lo = configRead(dev.bus, dev.dev, dev.func, bar_off);
    if (bar_lo & 1 != 0) return null; // I/O space
    const phys = readBar64(dev.bus, dev.dev, dev.func, bar_off);
    if (phys == 0) return null;
    paging.mapMMIO(phys, size);
    return paging.physToVirt(phys);
}

/// Walk the PCI capability list looking for a cap with `cap_id`. Returns
/// the config-space byte offset of the cap header, or null. The cap list
/// itself only exists if STATUS bit 4 (Capabilities List) is set; we
/// check that first so devices without a cap list don't read garbage.
pub fn findCapability(dev: PciDevice, cap_id: u8) ?u8 {
    const status = configRead16(dev.bus, dev.dev, dev.func, 0x06);
    if (status & 0x10 == 0) return null; // no capabilities list
    var off: u8 = @truncate(configRead(dev.bus, dev.dev, dev.func, 0x34) & 0xFC);
    var hops: u8 = 0;
    while (off >= 0x40 and hops < 48) : (hops += 1) {
        const hdr = configRead(dev.bus, dev.dev, dev.func, off);
        const id: u8 = @truncate(hdr);
        if (id == cap_id) return off;
        const next: u8 = @truncate(hdr >> 8);
        if (next == 0) return null;
        off = next & 0xFC;
    }
    return null;
}
