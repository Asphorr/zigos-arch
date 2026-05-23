const io = @import("../io.zig");
const acpi = @import("../time/acpi.zig");
const paging = @import("../mm/paging.zig");
const debug = @import("../debug/debug.zig");
const time = @import("../time/time.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

const CONFIG_ADDR: u16 = 0x0CF8;
const CONFIG_DATA: u16 = 0x0CFC;

// Serializes config-space access. Necessary because configWrite16's RMW
// (read 32-bit slot → patch 16 bits → write back) is non-atomic, and
// because the BAR-sizing dance in getBarSize / BAR-rewrite in assignBar64
// briefly leaves the BAR in an all-FFs or partially-written state — any
// concurrent reader on another CPU must not observe that intermediate.
// Legacy port-I/O config access is also inherently non-atomic at the
// 0xCF8/0xCFC pair, so locking is the only way to make it safe across SMP.
var pci_lock: SpinLock = .{};

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
    // Parens matter: `+` binds tighter than `|` in Zig, so without the outer
    // parens this would parse as `(ecam_base + (rel_bus << 20)) | ...`. That
    // happens to produce the same result when ecam_base has zero bits in
    // the OR'd ranges (q35's 0xB0000000 satisfies that), but bites silently
    // on any ECAM base with set bits in the bus/dev/func/offset slots.
    const addr: u64 = ecam_base + ((rel_bus << 20) |
        (@as(u64, dev) << 15) |
        (@as(u64, func) << 12) |
        @as(u64, offset & 0xFFC));
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
    // PCI header type byte (offset 0x0E). Bit 7 = multi-function indicator;
    // bits 0-6 = header layout (0 = endpoint, 1 = PCI-PCI bridge, 2 = CardBus).
    // Cached here so `enumerate` doesn't have to re-read 0x0C to decide
    // whether to scan funcs 1-7 of a slot.
    header_type: u8,
    // All 6 BARs cached at enumeration. For 64-bit memory BARs (type bits 2:1
    // == 0b10), bars[i] holds the combined 64-bit address and bars[i+1] = 0.
    // I/O BARs have the I/O-port address with the type bit stripped. Drivers
    // can read any BAR without a second config-space round-trip; the
    // pre-cached value is identical to what `readBar64(... 0x10 + i*4)` would
    // return on demand. Slot 0 alias `bar0` was the old single-BAR field.
    bars: [6]usize,
    irq_line: u8,

    /// Convenience accessor. Equivalent to `dev.bars[idx]`; mostly for
    /// drivers that want a function call instead of an array index in the
    /// site (reads better next to `pci.mapBar` / `pci.getBarSize`).
    pub inline fn bar(self: PciDevice, idx: u8) usize {
        return self.bars[idx];
    }
};

// --- Device cache ---------------------------------------------------------
//
// One-shot bus enumeration, populated by `enumerate()` during early boot.
// Drivers used to each call `findByClass` which re-walked the bus from
// scratch every time (4096 config-space reads × N drivers); worse, two
// drivers (nvme, virtio_sound) had hand-rolled bus walks because
// `findByClass` only returned the first match. With the cache:
//   - one walk total, logged in one place ("[pci] devices:" block)
//   - findByClass / findByVendorDevice / findAllByClass / allDevices
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
    // When MCFG is present it describes the full PCI tree; buses outside
    // [start_bus, end_bus] simply do not exist on this platform, so we cap
    // the scan to that range. Saves 65536 - small × 1 µs per legacy-IO
    // config read, ~ms of boot under ECAM. Without MCFG, fall back to the
    // legacy 0..256 sweep.
    const first_bus: u16 = if (ecam_base != 0) ecam_start_bus else 0;
    const last_bus: u16 = if (ecam_base != 0) @as(u16, ecam_end_bus) + 1 else 256;
    var bus: u16 = first_bus;
    while (bus < last_bus) : (bus += 1) {
        var dev_idx: u8 = 0;
        while (dev_idx < 32) : (dev_idx += 1) {
            var func: u8 = 0;
            while (func < 8) : (func += 1) {
                if (readDevice(@truncate(bus), dev_idx, func)) |d| {
                    if (device_count < MAX_DEVICES) {
                        devices[device_count] = d;
                        device_count += 1;
                        logDevice(d);
                    } else {
                        debug.klog("[pci] cache full (>{d}); ignoring further devices\n", .{MAX_DEVICES});
                        return;
                    }
                    // Multi-function indicator lives in bit 7 of the header
                    // type, which `readDevice` already cached. Skip funcs
                    // 1..7 for single-function devices.
                    if (func == 0 and (d.header_type & 0x80) == 0) break;
                } else {
                    if (func == 0) break;
                }
            }
        }
    }
    debug.klog("[pci] {d} device(s) cached\n", .{device_count});
}

/// Single-device boot log line. Appends PCIe link info when the device
/// exposes the PCIe capability — useful for spotting links that trained
/// below their max speed/width (a common "device feels slow" cause on
/// real hardware that we can't see at all without this).
fn logDevice(d: PciDevice) void {
    debug.klog(
        "[pci]   {x:0>2}:{x:0>2}.{d} {s} vendor=0x{x:0>4} device=0x{x:0>4} class={x:0>2}.{x:0>2}.{x:0>2} bar0=0x{x} irq={d}\n",
        .{
            d.bus, d.dev, d.func, classifyName(d.class_code, d.subclass),
            d.vendor_id, d.device_id,
            d.class_code, d.subclass, d.prog_if,
            d.bars[0], d.irq_line,
        },
    );
    if (pcieLinkInfo(d)) |li| {
        debug.klog(
            "[pci]       pcie: link cur={s} x{d}, max={s} x{d}\n",
            .{ speedString(li.cur_speed), li.cur_width, speedString(li.max_speed), li.max_width },
        );
    }
}

/// Read-only view of the cached device list. Use with a plain for loop:
///   `for (pci.allDevices()) |d| { ... }`
pub fn allDevices() []const PciDevice {
    return devices[0..device_count];
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

/// Reverse of `markBound`. Drivers that fail init after `bindDevice`
/// already flipped the bit call this so `logUnbound` doesn't lie. The
/// `BoundHandle` returned by `bindDevice` exposes this through `.fail()`
/// for a defer-friendly pattern.
pub fn markUnbound(dev: PciDevice) void {
    for (devices[0..device_count], 0..) |cached, i| {
        if (cached.bus == dev.bus and cached.dev == dev.dev and cached.func == dev.func) {
            bound[i] = false;
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

/// Returned by `bindDevice`. Designed for `defer h.deinit()` — if the
/// driver returns without calling `.commit()`, the bound bit is reverted
/// so `logUnbound` still reports the slot. Drivers that always succeed
/// after `bindDevice` can ignore the handle and call `markBound` directly,
/// but the BoundHandle pattern is the recommended one for any driver with
/// fallible init beyond `bindDevice`.
pub const BoundHandle = struct {
    dev: PciDevice,
    committed: bool = false,

    pub fn commit(self: *BoundHandle) void {
        self.committed = true;
    }

    pub fn fail(self: *BoundHandle) void {
        if (!self.committed) {
            markUnbound(self.dev);
            self.committed = true; // prevent deinit double-unbind
        }
    }

    pub fn deinit(self: *BoundHandle) void {
        if (!self.committed) markUnbound(self.dev);
    }
};

/// Routine "I'm taking this device" boilerplate that nearly every driver
/// duplicates: wake to D0 if firmware left the device in D3, then enable
/// Memory + I/O space decoding (PCI command bits 0/1), enable Bus Master
/// (bit 2), and disable legacy INTx (bit 10) so a driver that arms MSI-X
/// doesn't also see ghost interrupts on the shared IOAPIC line.
///
/// Drivers can still poke the command register afterwards if they need
/// device-specific bits (e.g. AC97 doesn't want INTx disabled because it
/// has no MSI). Default to bindDevice for everyone using MSI/MSI-X.
///
/// Returns a `BoundHandle`: `defer h.deinit()` + `h.commit()` at the end
/// of a successful init reverts the bound bit on early-return failures.
/// Callers that don't care can `_ = pci.bindDevice(dev)` — the device
/// stays marked bound either way as long as the handle isn't deinit'd.
pub fn bindDevice(dev: PciDevice) BoundHandle {
    pmWakeToD0(dev);
    var cmd = configRead16(dev.bus, dev.dev, dev.func, 0x04);
    cmd |= 0x0007; // I/O space + Memory space + Bus Master
    cmd |= 0x0400; // Disable legacy INTx (MSI/MSI-X drivers want this)
    configWrite16(dev.bus, dev.dev, dev.func, 0x04, cmd);
    markBound(dev);
    return .{ .dev = dev };
}

/// Like bindDevice but keeps INTx live. For drivers that have no MSI/MSI-X
/// path (legacy AC97, IDE in compat mode).
pub fn bindDeviceLegacyIrq(dev: PciDevice) BoundHandle {
    pmWakeToD0(dev);
    var cmd = configRead16(dev.bus, dev.dev, dev.func, 0x04);
    cmd |= 0x0007; // I/O + Memory + Bus Master
    cmd &= ~@as(u16, 0x0400); // ensure INTx is enabled
    configWrite16(dev.bus, dev.dev, dev.func, 0x04, cmd);
    markBound(dev);
    return .{ .dev = dev };
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

/// Read the device's (subsystem-vendor-id, subsystem-id) pair from config
/// space offset 0x2C. Useful for telling apart variants that share the
/// same vendor/device-id (transitional virtio devices, OEM rebrands of
/// common chipsets, etc).
pub fn subsystemIds(dev: PciDevice) struct { svid: u16, sid: u16 } {
    const raw = configRead(dev.bus, dev.dev, dev.func, 0x2C);
    return .{ .svid = @truncate(raw), .sid = @truncate(raw >> 16) };
}

// --- Config space access ---
//
// Public APIs (configRead/configWrite/configRead16/configWrite16) lock
// pci_lock for the entire op so each call is atomic with respect to other
// CPUs. The `*Unlocked` siblings are for sequences inside this file that
// already hold pci_lock across multiple ops (e.g. getBarSize's size-probe
// dance, assignBar64's BAR write-with-decode-disabled). External callers
// must use the locked variants — they're the only public ones.

fn configReadUnlocked(bus: u8, dev: u8, func: u8, offset: u8) u32 {
    if (ecamPtr(bus, dev, func, offset)) |p| return p.*;
    const addr: u32 = @as(u32, 1) << 31 |
        @as(u32, bus) << 16 |
        @as(u32, dev) << 11 |
        @as(u32, func) << 8 |
        (@as(u32, offset) & 0xFC);
    io.outl(CONFIG_ADDR, addr);
    return io.inl(CONFIG_DATA);
}

fn configWriteUnlocked(bus: u8, dev: u8, func: u8, offset: u8, value: u32) void {
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

fn configRead16Unlocked(bus: u8, dev: u8, func: u8, offset: u8) u16 {
    const val32 = configReadUnlocked(bus, dev, func, offset & 0xFC);
    const shift: u5 = @truncate((offset & 2) * 8);
    return @truncate(val32 >> shift);
}

fn configWrite16Unlocked(bus: u8, dev: u8, func: u8, offset: u8, value: u16) void {
    const aligned = offset & 0xFC;
    var val32 = configReadUnlocked(bus, dev, func, aligned);
    const shift: u5 = @truncate((offset & 2) * 8);
    val32 &= ~(@as(u32, 0xFFFF) << shift);
    val32 |= @as(u32, value) << shift;
    configWriteUnlocked(bus, dev, func, aligned, val32);
}

pub fn configRead(bus: u8, dev: u8, func: u8, offset: u8) u32 {
    const flags = pci_lock.acquireIrqSave();
    defer pci_lock.releaseIrqRestore(flags);
    return configReadUnlocked(bus, dev, func, offset);
}

pub fn configWrite(bus: u8, dev: u8, func: u8, offset: u8, value: u32) void {
    const flags = pci_lock.acquireIrqSave();
    defer pci_lock.releaseIrqRestore(flags);
    configWriteUnlocked(bus, dev, func, offset, value);
}

pub fn configRead16(bus: u8, dev: u8, func: u8, offset: u8) u16 {
    const flags = pci_lock.acquireIrqSave();
    defer pci_lock.releaseIrqRestore(flags);
    return configRead16Unlocked(bus, dev, func, offset);
}

pub fn configWrite16(bus: u8, dev: u8, func: u8, offset: u8, value: u16) void {
    const flags = pci_lock.acquireIrqSave();
    defer pci_lock.releaseIrqRestore(flags);
    configWrite16Unlocked(bus, dev, func, offset, value);
}

// --- Extended config space (ECAM-only, offsets 0x100..0xFFC) ---
//
// PCIe extended config space holds the extended capability chain (AER,
// ARI, SR-IOV, ATS, ...). The legacy 0xCF8/0xCFC port pair physically
// can't reach this — the register field is 6 bits = 0x00..0xFC. ECAM has
// no such limit. These helpers return 0xFFFFFFFF when ECAM is absent so
// callers can probe-and-fall-back without checking ecam_base themselves.

fn configReadExtUnlocked(bus: u8, dev: u8, func: u8, offset: u16) u32 {
    if (ecamPtr(bus, dev, func, offset)) |p| return p.*;
    return 0xFFFFFFFF;
}

fn configWriteExtUnlocked(bus: u8, dev: u8, func: u8, offset: u16, value: u32) void {
    if (ecamPtr(bus, dev, func, offset)) |p| p.* = value;
}

pub fn configReadExt(bus: u8, dev: u8, func: u8, offset: u16) u32 {
    const flags = pci_lock.acquireIrqSave();
    defer pci_lock.releaseIrqRestore(flags);
    return configReadExtUnlocked(bus, dev, func, offset);
}

pub fn configWriteExt(bus: u8, dev: u8, func: u8, offset: u16, value: u32) void {
    const flags = pci_lock.acquireIrqSave();
    defer pci_lock.releaseIrqRestore(flags);
    configWriteExtUnlocked(bus, dev, func, offset, value);
}

// --- Device scanning ---

// PCI config register layouts per PCI Local Bus Spec 3.0 §6.1.
const IdReg = packed struct(u32) {
    vendor_id: u16,
    device_id: u16,
};
const ClassReg = packed struct(u32) {
    revision_id: u8,
    prog_if: u8,
    subclass: u8,
    class_code: u8,
};
const HdrReg = packed struct(u32) {
    cache_line_size: u8,
    latency_timer: u8,
    header_type: u8,
    bist: u8,
};

fn readDevice(bus: u8, dev: u8, func: u8) ?PciDevice {
    const id: IdReg = @bitCast(configRead(bus, dev, func, 0x00));
    if (id.vendor_id == 0xFFFF) return null;
    const class_reg: ClassReg = @bitCast(configRead(bus, dev, func, 0x08));
    const hdr_reg: HdrReg = @bitCast(configRead(bus, dev, func, 0x0C));

    const irq = configRead(bus, dev, func, 0x3C);

    // Read all 6 BARs. 64-bit memory BARs straddle two slots: the lo half
    // holds the type bits, the hi half is data-only. Putting the combined
    // value into the lo slot and zeroing the hi slot mirrors how Linux
    // exposes BARs through sysfs — drivers want a "BAR N's address" view,
    // not "raw 32-bit dwords".
    var bars: [6]usize = .{ 0, 0, 0, 0, 0, 0 };
    var i: u8 = 0;
    while (i < 6) : (i += 1) {
        const off: u8 = 0x10 + i * 4;
        const lo = configRead(bus, dev, func, off);
        if (lo == 0) continue;
        if (lo & 1 != 0) {
            // I/O BAR — 32-bit only, address in bits 31:2.
            bars[i] = lo & 0xFFFFFFFC;
            continue;
        }
        const bar_type = (lo >> 1) & 3;
        const base_lo: usize = lo & 0xFFFFFFF0;
        if (bar_type == 2 and i < 5) {
            // 64-bit memory BAR: pair (i, i+1) collapses into bars[i].
            const hi: usize = configRead(bus, dev, func, off + 4);
            bars[i] = base_lo | (hi << 32);
            i += 1; // bars[i+1] stays 0; spec says the high slot has no
            // independent meaning once paired.
            continue;
        }
        bars[i] = base_lo;
    }

    return .{
        .bus = bus,
        .dev = dev,
        .func = func,
        .vendor_id = id.vendor_id,
        .device_id = id.device_id,
        .class_code = class_reg.class_code,
        .subclass = class_reg.subclass,
        .prog_if = class_reg.prog_if,
        .header_type = hdr_reg.header_type,
        .bars = bars,
        .irq_line = @truncate(irq),
    };
}

/// Read a BAR by config-space offset, handling 64-bit BARs (type 2 in
/// bits 2:1). Kept for callers with a dynamic BAR offset (virtio SHM
/// caps, MSI-X table BIR). Most drivers should prefer `dev.bars[i]` /
/// `dev.bar(i)` since enumeration already cached every BAR.
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
/// Held under pci_lock for the entire sequence so concurrent readers on
/// other CPUs don't observe the decode-disabled / half-written state.
pub fn assignBar64(bus: u8, dev: u8, func: u8, bar_idx: u8, base: u64) void {
    const flags = pci_lock.acquireIrqSave();
    defer pci_lock.releaseIrqRestore(flags);

    const cmd_off: u8 = 0x04;
    const orig_cmd = configRead16Unlocked(bus, dev, func, cmd_off);

    // Clear MEM decode (bit 1) during BAR write
    configWrite16Unlocked(bus, dev, func, cmd_off, orig_cmd & ~@as(u16, 0x02));

    const bar_off: u8 = 0x10 + bar_idx * 4;
    const orig_lo = configReadUnlocked(bus, dev, func, bar_off);
    const new_lo: u32 = (@as(u32, @truncate(base)) & 0xFFFFFFF0) | (orig_lo & 0x0F);
    const new_hi: u32 = @truncate(base >> 32);
    configWriteUnlocked(bus, dev, func, bar_off, new_lo);
    configWriteUnlocked(bus, dev, func, bar_off + 4, new_hi);

    // Re-enable MEM decode + bus master + I/O space (preserve original other bits)
    configWrite16Unlocked(bus, dev, func, cmd_off, orig_cmd | 0x07);
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

/// Get the size of a BAR by writing all-ones and reading back. The probe
/// momentarily writes 0xFFFFFFFF into the BAR — on real hardware that can
/// cause spurious decode hits during the window, so we disable MEM-decode
/// (bit 1 of command register) across the whole sequence the way Linux's
/// __pci_read_base does. The entire probe runs under pci_lock so a
/// concurrent reader on another CPU can't observe the all-FFs state.
pub fn getBarSize(dev: PciDevice, bar_idx: u8) u32 {
    const flags = pci_lock.acquireIrqSave();
    defer pci_lock.releaseIrqRestore(flags);

    const cmd_off: u8 = 0x04;
    const orig_cmd = configRead16Unlocked(dev.bus, dev.dev, dev.func, cmd_off);
    configWrite16Unlocked(dev.bus, dev.dev, dev.func, cmd_off, orig_cmd & ~@as(u16, 0x02));

    const offset: u8 = 0x10 + bar_idx * 4;
    const original = configReadUnlocked(dev.bus, dev.dev, dev.func, offset);
    configWriteUnlocked(dev.bus, dev.dev, dev.func, offset, 0xFFFFFFFF);
    const size_mask = configReadUnlocked(dev.bus, dev.dev, dev.func, offset);
    configWriteUnlocked(dev.bus, dev.dev, dev.func, offset, original); // Restore

    configWrite16Unlocked(dev.bus, dev.dev, dev.func, cmd_off, orig_cmd);

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
    // bars[] caches both I/O and memory BARs with the type bit stripped.
    // We still need the raw lo dword to tell them apart: I/O BARs can't
    // be mapped through the physmap.
    const bar_off: u8 = 0x10 + bar_idx * 4;
    const bar_lo = configRead(dev.bus, dev.dev, dev.func, bar_off);
    if (bar_lo & 1 != 0) return null; // I/O space
    const phys = dev.bars[bar_idx];
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

// --- PCIe extended capability walk (config offsets ≥ 0x100) ----------------
//
// PCIe extended caps live in extended config space (only reachable via
// ECAM). The header is 32-bit:
//   bits  0..15 = ext_cap_id (AER=0x0001, SR-IOV=0x0010, ARI=0x000E, ATS=0x000F, ...)
//   bits 16..19 = capability version
//   bits 20..31 = next-cap offset (0 ends the chain)
// A blank chain reads as all-zero or all-ones; both terminate the walk.

const EXT_CAP_START: u16 = 0x100;
const EXT_CAP_END: u16 = 0xFFC;

/// Find a PCIe extended capability by 16-bit id. Returns the config-space
/// offset of the cap header, or null. Requires ECAM (returns null silently
/// if absent).
pub fn findExtCap(dev: PciDevice, ext_cap_id: u16) ?u16 {
    if (ecam_base == 0) return null;
    var off: u16 = EXT_CAP_START;
    var hops: u8 = 0;
    while (off >= EXT_CAP_START and off <= EXT_CAP_END and hops < 64) : (hops += 1) {
        const hdr = configReadExt(dev.bus, dev.dev, dev.func, off);
        if (hdr == 0 or hdr == 0xFFFFFFFF) return null;
        const id: u16 = @truncate(hdr);
        if (id == ext_cap_id) return off;
        const next: u16 = @truncate(hdr >> 20);
        if (next == 0) return null;
        off = next;
    }
    return null;
}

// --- Power management cap (cap_id 0x01) ------------------------------------
//
// Layout per PCI Power Management Spec rev 1.2:
//   off+0  cap_id (1B) | next_ptr (1B) | PMC (2B, capabilities)
//   off+4  PMCSR (PMC State Register, 16-bit). Bits 0..1 = current state:
//          00 = D0 (active), 01 = D1, 10 = D2, 11 = D3hot.
//          Writing the bits transitions the device.
//   off+6  PMCSR_BSE (PCI bridge support extensions, irrelevant here)
//   off+7  Data (capability-specific)

const PM_CAP_ID: u8 = 0x01;
const PM_PMCSR_OFF: u8 = 4;
const PM_STATE_MASK: u16 = 0x0003;

pub const PowerState = enum(u2) { d0 = 0, d1 = 1, d2 = 2, d3hot = 3 };

/// Read the device's current PM state. Null if the device exposes no PM
/// cap — common on the host bridge / older virtio.
pub fn pmGetState(dev: PciDevice) ?PowerState {
    const off = findCapability(dev, PM_CAP_ID) orelse return null;
    const pmcsr = configRead16(dev.bus, dev.dev, dev.func, off + PM_PMCSR_OFF);
    return @enumFromInt(@as(u2, @truncate(pmcsr & PM_STATE_MASK)));
}

/// Transition the device to `state`. Per spec, a D3hot→D0 transition
/// requires at least 10 ms before the device responds; we sleep
/// unconditionally on any state change to keep the helper foolproof.
pub fn pmSetState(dev: PciDevice, state: PowerState) bool {
    const off = findCapability(dev, PM_CAP_ID) orelse return false;
    var pmcsr = configRead16(dev.bus, dev.dev, dev.func, off + PM_PMCSR_OFF);
    const cur = pmcsr & PM_STATE_MASK;
    const want: u16 = @intFromEnum(state);
    if (cur == want) return true;
    pmcsr = (pmcsr & ~PM_STATE_MASK) | want;
    configWrite16(dev.bus, dev.dev, dev.func, off + PM_PMCSR_OFF, pmcsr);
    // Per spec: D3hot→D0 requires Trestore >= 10 ms before any other config
    // access. We don't know the previous state-pair precisely (the device
    // may stale-cache), so always wait. Reads after this should hit a
    // responsive device.
    busyWaitMillis(10);
    return true;
}

/// `bindDevice` calls this so devices firmware left in D3hot wake up
/// automatically. Silent no-op when the device has no PM cap (we have
/// no business "waking" something that doesn't sleep) or is already D0.
fn pmWakeToD0(dev: PciDevice) void {
    const cur = pmGetState(dev) orelse return;
    if (cur == .d0) return;
    _ = pmSetState(dev, .d0);
}

// --- PCIe capability (cap_id 0x10) -----------------------------------------
//
// Layout per PCIe Base Spec rev 3.0+. Only the fields we use are named:
//   off+0   cap_id (1B) | next_ptr (1B) | PCIe Caps (2B)
//   off+4   Device Capabilities (4B). Bit 28 = Function-Level Reset capable.
//   off+8   Device Control (2B). Bit 15 = Initiate FLR (auto-clears).
//   off+0xA Device Status (2B). Bit 5 = TransactionsPending — must clear
//           before initiating FLR.
//   off+0xC Link Capabilities (4B). Bits 0..3 = max speed, 4..9 = max width.
//   off+0x10 Link Control (2B). Bits 0..1 = ASPM control (0=disabled).
//   off+0x12 Link Status (2B). Bits 0..3 = cur speed, 4..9 = cur width.

const PCIE_CAP_ID: u8 = 0x10;
const PCIE_DEVCAP_OFF: u8 = 4;
const PCIE_DEVCTL_OFF: u8 = 8;
const PCIE_DEVSTA_OFF: u8 = 0xA;
const PCIE_LINKCAP_OFF: u8 = 0xC;
const PCIE_LINKCTL_OFF: u8 = 0x10;
const PCIE_LINKSTA_OFF: u8 = 0x12;
const PCIE_DEVCAP_FLR: u32 = 1 << 28;
const PCIE_DEVCTL_INITIATE_FLR: u16 = 1 << 15;
const PCIE_DEVSTA_TRANS_PENDING: u16 = 1 << 5;

pub const PcieLinkInfo = struct {
    cur_speed: u4, // 1 = 2.5 GT/s, 2 = 5, 3 = 8, 4 = 16, 5 = 32
    cur_width: u6,
    max_speed: u4,
    max_width: u6,
};

// PCIe LinkCap (32b) and LinkSta (16b) low halves share the same speed[3:0],
// width[9:4] layout. Per PCIe Base Spec § 7.5.3.
const LinkSpeedWidth = packed struct(u16) {
    speed: u4,
    width: u6,
    _r: u6,
};

/// Read current + max link speed/width. Null on devices without PCIe cap
/// (legacy PCI, or some virtio-pci-modern in older QEMU).
pub fn pcieLinkInfo(dev: PciDevice) ?PcieLinkInfo {
    const off = findCapability(dev, PCIE_CAP_ID) orelse return null;
    const linkcap = configRead(dev.bus, dev.dev, dev.func, off + PCIE_LINKCAP_OFF);
    const linksta = configRead16(dev.bus, dev.dev, dev.func, off + PCIE_LINKSTA_OFF);
    const cap: LinkSpeedWidth = @bitCast(@as(u16, @truncate(linkcap)));
    const sta: LinkSpeedWidth = @bitCast(linksta);
    return .{
        .max_speed = cap.speed,
        .max_width = cap.width,
        .cur_speed = sta.speed,
        .cur_width = sta.width,
    };
}

/// Disable Active State Power Management on the device's PCIe link.
/// On real hardware ASPM L1 entry between an MSI-X posted write and the
/// CPU's dispatch can manifest as "interrupt arrived but driver never ran"
/// — disabling ASPM is the canonical fix when investigating these. No-op
/// when the device has no PCIe cap. Returns true if ASPM bits were
/// touched, false if the cap was absent.
pub fn disableAspm(dev: PciDevice) bool {
    const off = findCapability(dev, PCIE_CAP_ID) orelse return false;
    var lc = configRead16(dev.bus, dev.dev, dev.func, off + PCIE_LINKCTL_OFF);
    if ((lc & 0x3) == 0) return true; // already disabled
    lc &= ~@as(u16, 0x3);
    configWrite16(dev.bus, dev.dev, dev.func, off + PCIE_LINKCTL_OFF, lc);
    return true;
}

/// Function-Level Reset. Sequence per PCIe Base Spec § 6.6.2:
///   1. Confirm DevCap.FLR_Capable.
///   2. Quiesce: wait for DevSta.TransactionsPending == 0 (best effort).
///   3. Write DevCtl.InitiateFLR.
///   4. Wait at least 100 ms before any other config access.
///   5. Drivers are responsible for re-initializing device state.
/// Returns true if a reset was issued, false if the device has no PCIe
/// cap or isn't FLR-capable.
pub fn flr(dev: PciDevice) bool {
    const off = findCapability(dev, PCIE_CAP_ID) orelse return false;
    const devcap = configRead(dev.bus, dev.dev, dev.func, off + PCIE_DEVCAP_OFF);
    if (devcap & PCIE_DEVCAP_FLR == 0) return false;

    // Best-effort quiesce; loop bounded so a stuck device doesn't wedge.
    var quiesce: u32 = 0;
    while (quiesce < 1000) : (quiesce += 1) {
        const sta = configRead16(dev.bus, dev.dev, dev.func, off + PCIE_DEVSTA_OFF);
        if (sta & PCIE_DEVSTA_TRANS_PENDING == 0) break;
        busyWaitMillis(1);
    }

    var ctl = configRead16(dev.bus, dev.dev, dev.func, off + PCIE_DEVCTL_OFF);
    ctl |= PCIE_DEVCTL_INITIATE_FLR;
    configWrite16(dev.bus, dev.dev, dev.func, off + PCIE_DEVCTL_OFF, ctl);
    // Spec mandates ≥100 ms recovery before subsequent config access.
    busyWaitMillis(100);
    return true;
}

fn speedString(s: u4) []const u8 {
    return switch (s) {
        1 => "2.5GT",
        2 => "5GT",
        3 => "8GT",
        4 => "16GT",
        5 => "32GT",
        6 => "64GT",
        else => "?GT",
    };
}

/// Millisecond busy-wait used by PM/FLR helpers — they run on the boot
/// CPU before IRQs are fully live, so any sleep that yields would deadlock
/// the kernel timer init. Uses HPET via `time.monotonicNanos()`; before
/// the time module is initialized (theoretically possible if a driver
/// calls bindDevice that early), falls back to a port-80 spin which is
/// rough but always available.
fn busyWaitMillis(ms: u32) void {
    if (ms == 0) return;
    const start = time.monotonicNanos();
    if (start != 0) {
        const target: u64 = start + @as(u64, ms) * 1_000_000;
        while (time.monotonicNanos() < target) {
            asm volatile ("pause");
        }
        return;
    }
    // Pre-HPET fallback: 1µs ≈ 1 inb(0x80) on most chipsets, much faster
    // on QEMU. Conservative — over-waiting here is harmless.
    var i: u32 = 0;
    while (i < ms) : (i += 1) {
        var j: u32 = 0;
        while (j < 1000) : (j += 1) {
            _ = io.inb(0x80);
        }
    }
}

// --- Forensic config-space dump --------------------------------------------
//
// Prints the device's first 256 bytes (legacy config region) as a hex
// dump with row offsets. Mostly useful when a driver is misbehaving on
// hardware we can't easily reproduce — call `pci.dumpConfig(dev)` from
// the failing driver and the boot log will show every header field,
// command/status, BARs, and the legacy cap list raw.
pub fn dumpConfig(dev: PciDevice) void {
    debug.klog("[pci] config dump {x:0>2}:{x:0>2}.{d} (0x{x:0>4}:0x{x:0>4})\n", .{
        dev.bus, dev.dev, dev.func, dev.vendor_id, dev.device_id,
    });
    var off: u8 = 0;
    while (off < 0xF0) : (off += 0x10) {
        const a = configRead(dev.bus, dev.dev, dev.func, off);
        const b = configRead(dev.bus, dev.dev, dev.func, off + 4);
        const c = configRead(dev.bus, dev.dev, dev.func, off + 8);
        const d = configRead(dev.bus, dev.dev, dev.func, off + 12);
        debug.klog("[pci]   0x{x:0>2}: {x:0>8} {x:0>8} {x:0>8} {x:0>8}\n", .{ off, a, b, c, d });
        if (off == 0xE0) break;
    }
}

/// Same as `dumpConfig` but also walks the extended config space (offsets
/// 0x100..0xFFC) when ECAM is available. Bigger boot-log impact; only call
/// when actually debugging an extended-cap issue.
pub fn dumpConfigFull(dev: PciDevice) void {
    dumpConfig(dev);
    if (ecam_base == 0) return;
    debug.klog("[pci] extended config:\n", .{});
    var off: u16 = 0x100;
    while (off < 0xFF0) : (off += 0x10) {
        const a = configReadExt(dev.bus, dev.dev, dev.func, off);
        // Skip empty 16-byte rows to keep the dump short on devices with
        // few extended caps (the common case).
        const b = configReadExt(dev.bus, dev.dev, dev.func, off + 4);
        const c = configReadExt(dev.bus, dev.dev, dev.func, off + 8);
        const d = configReadExt(dev.bus, dev.dev, dev.func, off + 12);
        if (a == 0 and b == 0 and c == 0 and d == 0) continue;
        if (a == 0xFFFFFFFF and b == 0xFFFFFFFF and c == 0xFFFFFFFF and d == 0xFFFFFFFF) continue;
        debug.klog("[pci]   0x{x:0>3}: {x:0>8} {x:0>8} {x:0>8} {x:0>8}\n", .{ off, a, b, c, d });
    }
}
