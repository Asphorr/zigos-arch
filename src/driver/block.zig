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

// Returns false on a propagated read error — primary-disk twin of the
// readSectorsSecondary BUG 2 contract below. Only NVMe reports failures;
// ata/ahci stay void-returning and are wrapped as `true`. tarfs's bulk file
// loads (the primary disk's only multi-sector reader) check this so a failed
// read surfaces as a clean load failure instead of stale bytes served as
// file content.
pub fn readSectors(lba: u32, count: u16, dest: [*]u8) bool {
    return switch (backend) {
        .none => false,
        .ata => blk: {
            ata.readSectors(lba, count, dest);
            break :blk true;
        },
        .ahci => blk: {
            ahci.readSectorsPrimary(lba, count, dest);
            break :blk true;
        },
        .nvme => nvme.readSectorsPrimary(lba, count, dest),
    };
}

pub fn readSectorSecondary(lba: u32, dest: [*]u8) void {
    switch (backend) {
        .none => {},
        .ata => ata.readSectorSecondary(lba, dest),
        .ahci => ahci.readSectorSecondary(lba, dest),
        .nvme => nvme.readSectorSecondary(lba, dest),
    }
}

// Returns false on a propagated read error (BUG 2 fix, 2026-06-04). Only the
// NVMe backend reports failures today (ext2 lives on NVMe controller #1); the
// ata/ahci backends are still void-returning, so they're wrapped as `true` —
// no behavior change for them, and the ext2 path now surfaces real I/O errors
// instead of serving stale buffer bytes as a valid read.
pub fn readSectorsSecondary(lba: u32, count: u16, dest: [*]u8) bool {
    return switch (backend) {
        .none => false,
        .ata => blk: {
            ata.readSectorsSecondary(lba, count, dest);
            break :blk true;
        },
        .ahci => blk: {
            ahci.readSectorsSecondary(lba, count, dest);
            break :blk true;
        },
        .nvme => nvme.readSectorsSecondary(lba, count, dest),
    };
}

pub fn writeSectorSecondary(lba: u32, src: [*]const u8) void {
    elfWriteTripwire(lba, src, @returnAddress());
    switch (backend) {
        .none => {},
        .ata => ata.writeSectorSecondary(lba, src),
        .ahci => ahci.writeSectorSecondary(lba, src),
        .nvme => nvme.writeSectorSecondary(lba, src),
    }
}

/// Multi-sector write to the secondary disk. Returns false on a propagated
/// write error — only the NVMe backend reports failures (ext2 lives on NVMe
/// controller #1); ata/ahci loop per-sector and are wrapped as `true`, same
/// contract as readSectorsSecondary above.
pub fn writeSectorsSecondary(lba: u32, count: u16, src: [*]const u8) bool {
    {
        // Tripwire scans each 512-byte sector independently — same
        // per-sector semantics as the single-sector entry above.
        var s: u32 = 0;
        while (s < count) : (s += 1) {
            elfWriteTripwire(lba + s, src + s * 512, @returnAddress());
        }
    }
    return switch (backend) {
        .none => false,
        .ata => blk: {
            var i: u32 = 0;
            while (i < count) : (i += 1) ata.writeSectorSecondary(lba + i, src + i * 512);
            break :blk true;
        },
        .ahci => blk: {
            var i: u32 = 0;
            while (i < count) : (i += 1) ahci.writeSectorSecondary(lba + i, src + i * 512);
            break :blk true;
        },
        .nvme => nvme.writeSectorsSecondary(lba, count, src),
    };
}

/// [write-tripwire] (2026-06-04) — catch the ext2 on-disk corruptor in the act.
/// A 512-byte sector carrying a 7-byte ELF header (`7F 45 4C 46 02 01 01`) at a
/// NON-ZERO offset is a misplaced header: the exact signature of the unsynced
/// SMP ext2 cache race writing a shifted slice of one file over another's block
/// (observed on redteam.elf at sector-offset 0xB9). A legit ELF sector-0 write
/// has the magic at offset 0 (skipped). `ra` is writeSectorSecondary's caller —
/// resolves (via KERNEL.SYM) to the ext2 write path that did it (writeBlock /
/// writeBlockBytes / mmap writeback). Remove once the corruption is fixed.
fn elfWriteTripwire(lba: u32, src: [*]const u8, ra: usize) void {
    var i: usize = 1;
    while (i + 7 <= 512) : (i += 1) {
        if (src[i] == 0x7F and src[i + 1] == 0x45 and src[i + 2] == 0x4C and src[i + 3] == 0x46 and
            src[i + 4] == 0x02 and src[i + 5] == 0x01 and src[i + 6] == 0x01)
        {
            debug.klog("[write-tripwire] misplaced ELF magic @ sector-off={d} -> ext2 LBA {d} ra=0x{X}\n", .{ i, lba, ra });
            return;
        }
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
