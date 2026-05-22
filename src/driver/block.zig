// block — single dispatch point for the storage filesystems (tarfs,
// fat32, fat16, cli debug commands) to talk to whatever disk controller
// the kernel found.
//
// Backends today:
//   - AHCI  (modern SATA, real hardware + QEMU `-device ahci`)
//   - ATA   (legacy IDE/PIIX, the existing in-tree driver)
//
// The "primary" / "secondary" naming is inherited from the IDE channel
// model: tarfs lives on the primary disk (disk.tar), fat32 lives on the
// secondary disk (disk.img). On AHCI we map those to the first two
// ports that have actual SATA disks attached.
//
// AHCI is probed first; if the controller isn't there we fall back to
// the legacy IDE driver. Existing QEMU runs with `-drive if=ide` keep
// using ATA exactly as before — no behavior change without explicitly
// switching to `-device ahci` in the QEMU args.

const ata = @import("ata.zig");
const ahci = @import("ahci.zig");
const nvme = @import("nvme.zig");
const debug = @import("../debug/debug.zig");

const Backend = enum { none, ata, ahci, nvme };
var backend: Backend = .none;

pub fn init() void {
    if (nvme.init()) {
        backend = .nvme;
        debug.klog("[block] using NVMe\n", .{});
        // Swap backing store lives on a dedicated NVMe disk (controller #2);
        // no-op if that device isn't present. Must run after nvme.init().
        @import("../mm/swap.zig").init();
        return;
    }
    if (ahci.init()) {
        backend = .ahci;
        debug.klog("[block] using AHCI\n", .{});
        return;
    }
    // ATA's init was historically called from main.zig directly; keep
    // that call here so block.init() is the single entry point now.
    ata.initDMA();
    backend = .ata;
    debug.klog("[block] using IDE/ATA\n", .{});
}

pub fn readSector(lba: u32, dest: [*]u8) void {
    switch (backend) {
        .none => {},
        .ata => ata.readSector(lba, dest),
        .ahci => ahci.readSectorPrimary(lba, dest),
        .nvme => nvme.readSectorPrimary(lba, dest),
    }
}

pub fn readSectors(lba: u32, count: u8, dest: [*]u8) void {
    switch (backend) {
        .none => {},
        .ata => ata.readSectors(lba, count, dest),
        .ahci => ahci.readSectorsPrimary(lba, count, dest),
        .nvme => nvme.readSectorsPrimary(lba, count, dest),
    }
}

pub fn readSectorSecondary(lba: u32, dest: [*]u8) void {
    switch (backend) {
        .none => {},
        .ata => ata.readSectorSecondary(lba, dest),
        .ahci => ahci.readSectorSecondary(lba, dest),
        .nvme => nvme.readSectorSecondary(lba, dest),
    }
}

pub fn readSectorsSecondary(lba: u32, count: u8, dest: [*]u8) void {
    switch (backend) {
        .none => {},
        .ata => ata.readSectorsSecondary(lba, count, dest),
        .ahci => ahci.readSectorsSecondary(lba, count, dest),
        .nvme => nvme.readSectorsSecondary(lba, count, dest),
    }
}

pub fn writeSectorSecondary(lba: u32, src: [*]const u8) void {
    switch (backend) {
        .none => {},
        .ata => ata.writeSectorSecondary(lba, src),
        .ahci => ahci.writeSectorSecondary(lba, src),
        .nvme => nvme.writeSectorSecondary(lba, src),
    }
}

/// Used by ata.zig for cross-CPU serialisation of legacy port I/O.
/// AHCI is per-port and doesn't need a global lock; the call is a no-op
/// in that backend so callers can use it unconditionally.
pub fn acquireLock() void {
    if (backend == .ata) ata.acquireLock();
}
pub fn releaseLock() void {
    if (backend == .ata) ata.releaseLock();
}
