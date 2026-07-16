//! GPU detection kit — read-only identification of display controllers on
//! the PCI bus.
//!
//! This NAMES what graphics hardware is installed (vendor, GPU
//! family/generation, discrete vs integrated vs virtual) and reports the
//! resources a real driver would later claim (BAR apertures, PCIe link
//! width/speed, MSI capability, option ROM) — but it never programs the
//! device. It is the "what GPUs are here?" layer; actually driving one
//! (modeset, command rings, VRAM management) is a separate, far-future job.
//!
//! Detection runs ONCE at boot (kernelMain, right after pci.enumerate) into
//! a cached inventory. Consumers: the desktop's display bring-up ladder
//! (mayHaveVirtioGpu — skip the virtio probe on hardware that can't have
//! one), the `gpu` CLI command (report), and any future driver picker
//! (inventory/primary). A native GPU driver would start from this cache:
//! match on (vendor, family), claim the BARs the inventory already sized.
//!
//! Zig-to-the-max / low boilerplate: all vendor and architecture knowledge
//! lives in two flat comptime tables (`vendor_table`, `family_table`).
//! Teaching the kit a new GPU generation is a one-line table row, not code.
//! `classify` is a pure function over (vendor_id, device_id) with no
//! hardware dependency, so the decode logic is trivially reviewable and the
//! detection path reuses the existing, battle-tested pci.zig primitives
//! rather than re-walking config space.

const std = @import("std");
const pci = @import("pci.zig");
const debug = @import("../debug/debug.zig");

// BAR sizing uses the standard write-all-ones / read-back / restore probe
// (PCI Local Bus Spec §6.2.5.1) with memory decode disabled for the window
// — exactly what Linux's __pci_read_base does at boot, and what pci.zig's
// getBarSize already implements safely. It is the ONLY non-read operation
// this kit performs, and it restores the BAR + command register exactly.
// Set false for a strictly read-only kit (apertures then report as unknown).
const SIZE_BARS = true;

/// Where a GPU keeps its memory / how it is presented to us.
pub const Kind = enum {
    integrated, // shares system RAM (iGPU / APU)
    discrete, // dedicated VRAM on an add-in board
    virtual, // hypervisor-presented (QEMU / VMware / virtio / Hyper-V)
    unknown,

    pub fn label(self: Kind) []const u8 {
        return switch (self) {
            .integrated => "integrated",
            .discrete => "discrete",
            .virtual => "virtual",
            .unknown => "unknown",
        };
    }
};

const VendorDef = struct { id: u16, name: []const u8, kind: Kind };

// PCI-SIG vendor IDs that ship display controllers. `kind` is the *default*
// assumption for a GPU from this vendor; a family_table row can override it
// per-device-range (Intel Arc is discrete though Intel is iGPU-by-default;
// AMD APUs are integrated though AMD is dGPU-by-default).
const vendor_table = [_]VendorDef{
    .{ .id = 0x10DE, .name = "NVIDIA", .kind = .discrete },
    .{ .id = 0x1002, .name = "AMD/ATI", .kind = .discrete },
    .{ .id = 0x8086, .name = "Intel", .kind = .integrated },
    .{ .id = 0x102B, .name = "Matrox", .kind = .discrete },
    .{ .id = 0x5333, .name = "S3 Graphics", .kind = .discrete },
    .{ .id = 0x1A03, .name = "ASPEED", .kind = .integrated }, // server BMC VGA
    // Virtual / paravirtual display adapters — what we actually see in QEMU.
    .{ .id = 0x1234, .name = "QEMU stdvga (Bochs)", .kind = .virtual },
    .{ .id = 0x1AF4, .name = "VirtIO GPU", .kind = .virtual },
    .{ .id = 0x1B36, .name = "Red Hat QXL", .kind = .virtual },
    .{ .id = 0x15AD, .name = "VMware SVGA", .kind = .virtual },
    .{ .id = 0x1013, .name = "Cirrus Logic", .kind = .virtual },
    .{ .id = 0x1414, .name = "Microsoft Hyper-V", .kind = .virtual },
};

const FamilyDef = struct {
    vendor: u16,
    lo: u16,
    hi: u16,
    name: []const u8,
    // .unknown = inherit the vendor's default Kind; set explicitly only
    // where a device-ID range contradicts the vendor default.
    kind: Kind = .unknown,
};

// Best-effort GPU generation map. Real GPU device IDs are NOT perfectly
// contiguous per architecture, so these are coarse generation buckets, not
// exact SKU tables — enough to say "an Ampere-class NVIDIA" or "a Gen12
// Intel iGPU" at a glance. Extend freely; a wrong/missing row only drops the
// family label to "" (vendor + class + resources are still reported).
const family_table = [_]FamilyDef{
    // --- NVIDIA (discrete) -------------------------------------------------
    .{ .vendor = 0x10DE, .lo = 0x1340, .hi = 0x13FF, .name = "Maxwell (GM10x)" },
    .{ .vendor = 0x10DE, .lo = 0x1400, .hi = 0x14FF, .name = "Maxwell (GM20x)" },
    .{ .vendor = 0x10DE, .lo = 0x15F0, .hi = 0x15FF, .name = "Pascal (GP100)" },
    .{ .vendor = 0x10DE, .lo = 0x1B00, .hi = 0x1D7F, .name = "Pascal (GP10x)" },
    .{ .vendor = 0x10DE, .lo = 0x1D80, .hi = 0x1DFF, .name = "Volta (GV100)" },
    .{ .vendor = 0x10DE, .lo = 0x1E00, .hi = 0x1FFF, .name = "Turing (TU10x)" },
    .{ .vendor = 0x10DE, .lo = 0x2180, .hi = 0x21FF, .name = "Turing (TU11x)" },
    .{ .vendor = 0x10DE, .lo = 0x2200, .hi = 0x25FF, .name = "Ampere (GA10x)" },
    .{ .vendor = 0x10DE, .lo = 0x2600, .hi = 0x28FF, .name = "Ada Lovelace (AD10x)" },
    .{ .vendor = 0x10DE, .lo = 0x2900, .hi = 0x2BFF, .name = "Blackwell (GB20x)" },
    // --- Intel (integrated by default; Arc ranges flip to discrete) --------
    .{ .vendor = 0x8086, .lo = 0x0100, .hi = 0x016F, .name = "Gen6/7 (Sandy/Ivy Bridge)" },
    .{ .vendor = 0x8086, .lo = 0x0400, .hi = 0x0D2F, .name = "Gen7.5 (Haswell)" },
    .{ .vendor = 0x8086, .lo = 0x1600, .hi = 0x163F, .name = "Gen8 (Broadwell)" },
    .{ .vendor = 0x8086, .lo = 0x1900, .hi = 0x193F, .name = "Gen9 (Skylake)" },
    .{ .vendor = 0x8086, .lo = 0x5900, .hi = 0x593F, .name = "Gen9.5 (Kaby Lake)" },
    .{ .vendor = 0x8086, .lo = 0x3E90, .hi = 0x3EFF, .name = "Gen9.5 (Coffee Lake)" },
    .{ .vendor = 0x8086, .lo = 0x8A50, .hi = 0x8A5F, .name = "Gen11 (Ice Lake)" },
    .{ .vendor = 0x8086, .lo = 0x9A40, .hi = 0x9AFF, .name = "Gen12 (Tiger Lake)" },
    .{ .vendor = 0x8086, .lo = 0x4680, .hi = 0x46FF, .name = "Gen12.2 (Alder Lake)" },
    .{ .vendor = 0x8086, .lo = 0xA780, .hi = 0xA7FF, .name = "Gen13 (Raptor Lake)" },
    .{ .vendor = 0x8086, .lo = 0x4F80, .hi = 0x4FFF, .name = "Arc Alchemist (DG2)", .kind = .discrete },
    .{ .vendor = 0x8086, .lo = 0x5690, .hi = 0x56BF, .name = "Arc Alchemist (A-series)", .kind = .discrete },
    .{ .vendor = 0x8086, .lo = 0xE200, .hi = 0xE2FF, .name = "Arc Battlemage (BMG)", .kind = .discrete },
    // --- AMD/ATI (discrete by default; APU iGPU ranges flip to integrated) -
    .{ .vendor = 0x1002, .lo = 0x6600, .hi = 0x669F, .name = "GCN (Sea/Volcanic Islands)" },
    .{ .vendor = 0x1002, .lo = 0x66A0, .hi = 0x66AF, .name = "Vega 20 (GCN5)" },
    .{ .vendor = 0x1002, .lo = 0x67C0, .hi = 0x67FF, .name = "Polaris (RX 400/500)" },
    .{ .vendor = 0x1002, .lo = 0x6860, .hi = 0x687F, .name = "Vega 10" },
    .{ .vendor = 0x1002, .lo = 0x7310, .hi = 0x73FF, .name = "RDNA/RDNA2 (Navi 1x/2x)" },
    .{ .vendor = 0x1002, .lo = 0x7440, .hi = 0x747F, .name = "RDNA3 (Navi 3x)" },
    .{ .vendor = 0x1002, .lo = 0x1500, .hi = 0x15FF, .name = "Radeon Vega/RDNA (APU)", .kind = .integrated },
    .{ .vendor = 0x1002, .lo = 0x1636, .hi = 0x167F, .name = "Radeon (APU)", .kind = .integrated },
    // --- Virtual adapters (exact device IDs — the model name beats a range) -
    .{ .vendor = 0x1234, .lo = 0x1111, .hi = 0x1111, .name = "stdvga (Bochs VBE)" },
    .{ .vendor = 0x1AF4, .lo = 0x1050, .hi = 0x1050, .name = "virtio-gpu (modern)" },
    .{ .vendor = 0x1AF4, .lo = 0x1010, .hi = 0x1010, .name = "virtio-gpu (transitional)" },
    .{ .vendor = 0x1B36, .lo = 0x0100, .hi = 0x0100, .name = "QXL paravirtual" },
    .{ .vendor = 0x15AD, .lo = 0x0405, .hi = 0x0405, .name = "SVGA II" },
    .{ .vendor = 0x1013, .lo = 0x00B8, .hi = 0x00B8, .name = "GD5446" },
    .{ .vendor = 0x1414, .lo = 0x5353, .hi = 0x5353, .name = "synthetic video" },
};

/// Pure decode result for a (vendor, device) pair. No hardware access.
pub const Class = struct {
    vendor_name: []const u8,
    family: []const u8, // "" when no family row matched
    kind: Kind,
};

/// Map a (vendor_id, device_id) to a human-readable vendor, GPU family, and
/// Kind. Pure function — the heart of the kit, driven entirely by the two
/// comptime tables above.
pub fn classify(vendor_id: u16, device_id: u16) Class {
    var vendor_name: []const u8 = "unknown vendor";
    var kind: Kind = .unknown;
    for (vendor_table) |v| {
        if (v.id == vendor_id) {
            vendor_name = v.name;
            kind = v.kind;
            break;
        }
    }
    var family: []const u8 = "";
    for (family_table) |f| {
        if (f.vendor == vendor_id and device_id >= f.lo and device_id <= f.hi) {
            family = f.name;
            if (f.kind != .unknown) kind = f.kind; // range overrides vendor default
            break;
        }
    }
    return .{ .vendor_name = vendor_name, .family = family, .kind = kind };
}

pub const BarKind = enum { io, mem32, mem64, none };

pub const BarInfo = struct {
    idx: u8,
    kind: BarKind,
    prefetch: bool,
    base: u64,
    size: u64, // 0 = unknown (sizing disabled, or the device ignored the probe)
};

/// Everything the kit learns about one display controller. Self-contained
/// (owns no pointers into PCI state) so callers can copy it freely.
pub const GpuInfo = struct {
    bus: u8,
    dev: u8,
    func: u8,
    vendor_id: u16,
    device_id: u16,
    subsystem_vendor: u16,
    subsystem_id: u16,
    revision: u8,
    class_code: u8,
    subclass: u8,
    prog_if: u8,
    vendor_name: []const u8,
    family: []const u8,
    kind: Kind,
    vga_compatible: bool, // claims legacy VGA decode (0x3B0-0x3DF, 0xA0000)
    has_rom: bool, // option ROM (video BIOS / UEFI GOP) present
    msi: bool,
    msix: bool,
    pcie: ?pci.PcieLinkInfo,
    aperture_bytes: u64, // largest prefetchable mem BAR = VRAM-window guess
    bars: [6]BarInfo,
    nbars: u8,
};

/// A display controller is PCI class 0x03 (any subclass: VGA / XGA / 3D /
/// other), plus the pre-2.0 "VGA-compatible" encoding (class 0x00, subclass
/// 0x01) that some old/quirky devices still report.
fn isGpu(d: pci.PciDevice) bool {
    return d.class_code == 0x03 or (d.class_code == 0x00 and d.subclass == 0x01);
}

/// Inspect one PCI device and build its GpuInfo. Reads config space and (if
/// SIZE_BARS) runs the restore-safe BAR size probe.
fn inspect(d: pci.PciDevice) GpuInfo {
    const cls = classify(d.vendor_id, d.device_id);
    const ss = pci.subsystemIds(d);
    // Revision is byte 0 of the class register (offset 0x08).
    const revision: u8 = @truncate(pci.configRead(d.bus, d.dev, d.func, 0x08));
    // Expansion ROM BAR (offset 0x30): a non-zero base address means firmware
    // assigned an option ROM window (legacy VGA BIOS or a UEFI GOP driver).
    // The enable bit (bit 0) is deliberately ignored — firmware routinely
    // leaves the ROM mapped but disabled. Pure read; the register is never
    // written, so this can't perturb the device.
    const rom_raw = pci.configRead(d.bus, d.dev, d.func, 0x30);
    const has_rom = (rom_raw & 0xFFFFF800) != 0;

    var info = GpuInfo{
        .bus = d.bus,
        .dev = d.dev,
        .func = d.func,
        .vendor_id = d.vendor_id,
        .device_id = d.device_id,
        .subsystem_vendor = ss.svid,
        .subsystem_id = ss.sid,
        .revision = revision,
        .class_code = d.class_code,
        .subclass = d.subclass,
        .prog_if = d.prog_if,
        .vendor_name = cls.vendor_name,
        .family = cls.family,
        .kind = cls.kind,
        .vga_compatible = (d.class_code == 0x03 and d.subclass == 0x00) or
            (d.class_code == 0x00 and d.subclass == 0x01),
        .has_rom = has_rom,
        .msi = pci.findCapability(d, 0x05) != null, // MSI cap id
        .msix = pci.findCapability(d, 0x11) != null, // MSI-X cap id
        .pcie = pci.pcieLinkInfo(d),
        .aperture_bytes = 0,
        .bars = undefined,
        .nbars = 0,
    };

    // Decode each BAR from its raw low dword (the cached dev.bars[] strips the
    // type bits, so re-read to learn I/O-vs-mem / 32-vs-64 / prefetchable).
    var n: u8 = 0;
    var i: u8 = 0;
    while (i < 6) : (i += 1) {
        const off: u8 = 0x10 + i * 4;
        const lo = pci.configRead(d.bus, d.dev, d.func, off);
        if (lo == 0) continue;
        var bi = BarInfo{ .idx = i, .kind = .none, .prefetch = false, .base = d.bars[i], .size = 0 };
        if (lo & 1 != 0) {
            bi.kind = .io;
        } else {
            const bar_type = (lo >> 1) & 3; // 0 = 32-bit, 2 = 64-bit
            bi.prefetch = (lo & 0x8) != 0;
            bi.kind = if (bar_type == 2) .mem64 else .mem32;
            // mem64 needs the 64-bit probe: a ≥4 GiB aperture (resizable-BAR
            // dGPU) has ALL its size bits in the high dword — the 32-bit
            // probe reads back 0 there and calls the VRAM window "size n/a".
            if (SIZE_BARS) bi.size = if (bi.kind == .mem64)
                pci.getBarSize64(d, i)
            else
                pci.getBarSize(d, i);
            // The framebuffer/VRAM window is conventionally the prefetchable
            // BAR; track the largest as the aperture guess.
            if (bi.prefetch and bi.size > info.aperture_bytes) info.aperture_bytes = bi.size;
        }
        info.bars[n] = bi;
        n += 1;
        if (bi.kind == .mem64) i += 1; // a 64-bit BAR consumes the next slot
    }
    info.nbars = n;
    // No prefetchable BAR? fall back to the largest plain memory BAR.
    if (info.aperture_bytes == 0) {
        for (info.bars[0..info.nbars]) |b| {
            if ((b.kind == .mem32 or b.kind == .mem64) and b.size > info.aperture_bytes)
                info.aperture_bytes = b.size;
        }
    }
    return info;
}

/// Fill `out` with every detected display controller; returns the count
/// written. Internal walker — external code reads the boot inventory below.
fn detectAll(out: []GpuInfo) usize {
    var n: usize = 0;
    for (pci.allDevices()) |d| {
        if (!isGpu(d)) continue;
        if (n >= out.len) break;
        out[n] = inspect(d);
        n += 1;
    }
    return n;
}

// --- Boot inventory ---------------------------------------------------------
// Detected ONCE from kernelMain right after pci.enumerate — before any
// display driver binds — and cached for the kernel's lifetime. Not
// detect-on-demand for a reason: BAR sizing flips the device's memory-decode
// bit for a few config cycles. At boot (pre-driver, exactly where Linux runs
// __pci_read_base) that's routine; from the `gpu` CLI against a BAR the
// compositor is actively scanning out of, it's a self-inflicted display
// glitch. So the probe happens here once and the CLI reads the cache.

pub const MAX_GPUS = 4;

var inventory_buf: [MAX_GPUS]GpuInfo = undefined;
var inventory_n: usize = 0;
var inventory_ready: bool = false;

/// Boot hook: walk the bus, cache every display controller, log a one-line
/// headline each. Returns the count for kernelMain's boot-log note.
pub fn init() usize {
    inventory_n = detectAll(inventory_buf[0..]);
    inventory_ready = true;
    if (inventory_n == 0) {
        debug.klog("[gpu] no display controller on the PCI bus\n", .{});
        return 0;
    }
    for (inventory_buf[0..inventory_n]) |*g| logHeadline(g);
    return inventory_n;
}

/// Every display controller found at boot. Empty slice before init().
pub fn inventory() []const GpuInfo {
    return inventory_buf[0..inventory_n];
}

/// The controller most likely to be scanning out: the VGA-compatible one
/// (at most one device owns legacy VGA decode per bus in practice), else
/// the first found. null = headless, or init() hasn't run.
pub fn primary() ?*const GpuInfo {
    for (inventory()) |*g| {
        if (g.vga_compatible) return g;
    }
    return if (inventory_n != 0) &inventory_buf[0] else null;
}

/// Gate for the desktop's virtio-gpu attempt: false only when the boot
/// inventory ran and saw no virtio display function — real hardware, where
/// that probe is a guaranteed miss. Conservative true before init() so any
/// caller ahead of pci.enumerate keeps the old probe-and-see behavior.
pub fn mayHaveVirtioGpu() bool {
    if (!inventory_ready) return true;
    // A full inventory may have truncated the virtio function out of the
    // cache — absence is only provable from a complete walk.
    if (inventory_n == MAX_GPUS) return true;
    for (inventory()) |*g| {
        if (g.vendor_id == 0x1AF4) return true;
    }
    return false;
}

// --- Reporting (the `gpu` CLI command) -------------------------------------

/// Log a readable report of every display controller. klog tees to the VGA
/// console, so this prints to the screen when run from the shell. Reads the
/// boot inventory; detects live only if the boot hook never ran.
pub fn report() void {
    if (!inventory_ready) _ = init();
    if (inventory_n == 0) {
        debug.klog("[gpu] no display controller found on the PCI bus\n", .{});
        return;
    }
    for (inventory_buf[0..inventory_n]) |*g| logOne(g);
    debug.klog("[gpu] {d} display controller(s) (inventoried at boot)\n", .{inventory_n});
}

/// Headline: location, vendor, family (if known), kind. The boot summary
/// line, and the first line of the CLI report's per-GPU block.
fn logHeadline(g: *const GpuInfo) void {
    debug.klog("[gpu] {x:0>2}:{x:0>2}.{d}  {s}{s}{s}  [{s}]\n", .{
        g.bus, g.dev, g.func,
        g.vendor_name,
        if (g.family.len != 0) " " else "",
        g.family,
        g.kind.label(),
    });
}

fn logOne(g: *const GpuInfo) void {
    logHeadline(g);
    // IDs + class line.
    debug.klog("[gpu]   id {x:0>4}:{x:0>4} rev {x:0>2}  subsys {x:0>4}:{x:0>4}  {s} (class {x:0>2}.{x:0>2}.{x:0>2})\n", .{
        g.vendor_id, g.device_id, g.revision,
        g.subsystem_vendor, g.subsystem_id,
        displayKind(g.class_code, g.subclass),
        g.class_code, g.subclass, g.prog_if,
    });
    // BARs.
    for (g.bars[0..g.nbars]) |b| {
        switch (b.kind) {
            .io => debug.klog("[gpu]   BAR{d}: I/O   port 0x{x}\n", .{ b.idx, b.base }),
            .mem32, .mem64 => debug.klog("[gpu]   BAR{d}: {s}{s} 0x{x:0>8}  {s}\n", .{
                b.idx,
                if (b.kind == .mem64) "mem64" else "mem32",
                if (b.prefetch) " pf" else "   ",
                b.base,
                humanSize(b.size),
            }),
            .none => {},
        }
    }
    if (g.aperture_bytes != 0)
        debug.klog("[gpu]   aperture (VRAM window guess): {s}\n", .{humanSize(g.aperture_bytes)});
    // Capabilities — one line, then PCIe link if present.
    debug.klog("[gpu]   caps: rom={s} msi={s} msix={s} vga={s}", .{
        yn(g.has_rom), yn(g.msi), yn(g.msix), yn(g.vga_compatible),
    });
    if (g.pcie) |li| {
        debug.klog("  pcie: {s} x{d} (max {s} x{d})\n", .{
            speedStr(li.cur_speed), li.cur_width, speedStr(li.max_speed), li.max_width,
        });
    } else {
        debug.klog("  pcie: n/a\n", .{});
    }
}

/// Subclass label within the display class (PCI Local Bus Spec §D).
fn displayKind(class: u8, subclass: u8) []const u8 {
    if (class == 0x00 and subclass == 0x01) return "VGA-compatible (legacy)";
    if (class != 0x03) return "non-display";
    return switch (subclass) {
        0x00 => "VGA controller",
        0x01 => "XGA controller",
        0x02 => "3D controller",
        0x80 => "display controller",
        else => "display",
    };
}

/// PCIe link speed code → GT/s string (PCIe Base Spec link-status encoding).
fn speedStr(code: u4) []const u8 {
    return switch (code) {
        1 => "2.5GT/s",
        2 => "5GT/s",
        3 => "8GT/s",
        4 => "16GT/s",
        5 => "32GT/s",
        6 => "64GT/s",
        else => "?",
    };
}

fn yn(b: bool) []const u8 {
    return if (b) "yes" else "no";
}

// Shared scratch for humanSize. Single-threaded CLI/boot use only; each
// call's result must be consumed (passed to klog) before the next call.
var size_buf: [24]u8 = undefined;

fn humanSize(bytes: u64) []const u8 {
    const gib: u64 = 1024 * 1024 * 1024;
    const mib: u64 = 1024 * 1024;
    if (bytes == 0) return "size n/a";
    if (bytes >= gib and bytes % gib == 0)
        return std.fmt.bufPrint(&size_buf, "{d} GiB", .{bytes / gib}) catch "?";
    if (bytes >= mib)
        return std.fmt.bufPrint(&size_buf, "{d} MiB", .{bytes / mib}) catch "?";
    if (bytes >= 1024)
        return std.fmt.bufPrint(&size_buf, "{d} KiB", .{bytes / 1024}) catch "?";
    return std.fmt.bufPrint(&size_buf, "{d} B", .{bytes}) catch "?";
}

// --- Pure-logic sanity checks ----------------------------------------------
// classify() has no hardware dependency, so its decode rules can be pinned
// here. (These compile under the kernel build; they document the contract
// even where a host `zig test` would pull in the freestanding PCI graph.)

test "classify maps known vendors and families" {
    const t = std.testing;
    const nv = classify(0x10DE, 0x2204); // Ampere GA102 (RTX 3090)
    try t.expectEqualStrings("NVIDIA", nv.vendor_name);
    try t.expectEqualStrings("Ampere (GA10x)", nv.family);
    try t.expectEqual(Kind.discrete, nv.kind);

    const arc = classify(0x8086, 0x56A0); // Intel Arc A770 — dGPU override
    try t.expectEqualStrings("Intel", arc.vendor_name);
    try t.expectEqual(Kind.discrete, arc.kind);

    const apu = classify(0x1002, 0x15DD); // Raven Ridge iGPU — integrated override
    try t.expectEqual(Kind.integrated, apu.kind);

    const std_vga = classify(0x1234, 0x1111); // QEMU stdvga
    try t.expectEqual(Kind.virtual, std_vga.kind);

    const unkn = classify(0xDEAD, 0x0001);
    try t.expectEqualStrings("unknown vendor", unkn.vendor_name);
    try t.expectEqual(Kind.unknown, unkn.kind);
}
