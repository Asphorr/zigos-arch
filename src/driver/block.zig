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

/// NVMe controller index the ext2 root rides on. 1 in the classic 4-disk
/// dev topology (0=tarfs, 1=ext2 root, 2=swap, 3=install target). An
/// INSTALLED system boots from one disk carrying GPT with the root inside
/// it — ext2's mount discovery repoints this before mounting. NVMe only;
/// the ata/ahci arms keep their fixed secondary channel.
var root_ctrl_idx: usize = 1;

/// Repoint the "secondary" (ext2-root) entry points at NVMe controller
/// `ctrl`. Called by ext2's GPT discovery when the classic topology
/// (whole-disk ext2 on controller 1) isn't what the machine has.
pub fn setRootDisk(ctrl: usize) void {
    root_ctrl_idx = ctrl;
    debug.klog("[block] ext2 root routed to nvme{d}\n", .{ctrl});
}

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
        .nvme => _ = nvme.readSectorsOn(root_ctrl_idx, lba, 1, dest),
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
        .nvme => nvme.readSectorsOn(root_ctrl_idx, lba, count, dest),
    };
}

pub fn writeSectorSecondary(lba: u32, src: [*]const u8) void {
    elfWriteTripwire(lba, src, @returnAddress());
    switch (backend) {
        .none => {},
        .ata => ata.writeSectorSecondary(lba, src),
        .ahci => ahci.writeSectorSecondary(lba, src),
        .nvme => _ = nvme.writeSectorsOn(root_ctrl_idx, lba, 1, src),
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
        .nvme => nvme.writeSectorsOn(root_ctrl_idx, lba, count, src),
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

// =============================================================================
// Install target disk
// =============================================================================
//
// A dedicated scratch disk that the partitioning and mkfs code writes to. It
// exists as a separate device on purpose: `writeSectorsSecondary` addresses the
// live ext2 root, so a mkfs aimed there would destroy the running system on its
// first sector. Keeping the target a distinct index makes "format the wrong
// disk" a compile-site choice rather than an off-by-one in an LBA.
//
// Only the NVMe backend carries one (the run scripts attach it as a fourth
// controller). Under ata/ahci there is no fourth disk and `targetSectors()`
// reports 0, which callers surface as "no install target present" — see
// cli.zig's mkdisk command.

/// NVMe controller index of the install target. 0 = tarfs, 1 = ext2 root,
/// 2 = swap, 3 = target — the same ordering the run scripts attach.
const TARGET_CTRL_IDX: usize = 3;

/// A block device as a handle: how to reach its sectors, plus how many there
/// are. Lives here rather than in a filesystem because "what a block device
/// is" is this layer's question — `fs/gpt.zig` and `fs/ext2/mkfs.zig` both
/// take one, and neither should have to depend on the other to say so.
///
/// `writeSectors` is optional: null means a read-only view, and the writers
/// refuse such a device rather than trusting callers to keep track. That is
/// the difference between a partition table you can inspect and one you can
/// destroy, made visible in the type.
pub const Device = struct {
    readSectors: *const fn (lba: u32, count: u32, dest: [*]u8) bool,
    writeSectors: ?*const fn (lba: u32, count: u32, src: [*]const u8) bool,
    /// Capacity in 512-byte sectors.
    sectors: u64,
};

/// Sectors per zero-fill command. Formatters zero large regions — a FAT copy
/// is ~1000 sectors, an ext2 inode table 512 — and doing that one sector at a
/// time means thousands of separate NVMe commands.
///
/// History: mkfs.fat32 originally wrote its FATs a sector at a time, 2032
/// commands for the pair. That was slow, and on 2026-07-26 it also tripped
/// `[nvme] waitCompletion timeout (qid=1 head=14 csts=0x1)` partway through —
/// a completion the driver never reaped under sustained single-sector load.
/// Batching cuts the command count ~32x and has been stable since. NOTE that
/// this makes the driver issue worth investigating separately: fewer commands
/// is a better shape, not a fix for whatever dropped that completion.
pub const ZERO_CHUNK_SECTORS: u32 = 32;

/// A run of zero bytes long enough for one batched command. `const` so it
/// lives in rodata rather than costing .bss, and shared so the two formatters
/// don't each carry a copy.
const zero_chunk: [ZERO_CHUNK_SECTORS * 512]u8 = .{0} ** (ZERO_CHUNK_SECTORS * 512);

/// Writes `count` zero sectors starting at `lba`, batching into multi-sector
/// commands. Returns false on the first failed write.
pub fn writeZeroRun(dev: Device, lba: u32, count: u32) bool {
    const write = dev.writeSectors orelse return false;
    var done: u32 = 0;
    while (done < count) {
        const chunk = @min(count - done, ZERO_CHUNK_SECTORS);
        if (!write(lba + done, chunk, &zero_chunk)) return false;
        done += chunk;
    }
    return true;
}

/// The install target as a writable Device, or null when no target disk is
/// attached. The only constructor callers need today; the primary/secondary
/// disks keep their direct entry points because their users predate this type.
pub fn targetDevice() ?Device {
    const n = targetSectors();
    if (n == 0) return null;
    return .{
        .readSectors = readSectorsTarget,
        .writeSectors = writeSectorsTarget,
        .sectors = n,
    };
}

/// Capacity of the install target in 512-byte sectors, or 0 when no target
/// disk is attached. Callers must check this before issuing target I/O; it is
/// the presence test, and 0 is the only "not here" signal (the read/write
/// entry points below return false for real I/O errors, not for absence).
pub fn targetSectors() u64 {
    if (backend != .nvme) return 0;
    return nvme.namespaceSectors(TARGET_CTRL_IDX);
}

/// Read from the install target. Returns false on a propagated I/O error or
/// if no target disk is attached. Deliberately has no primary/secondary twin:
/// the target is addressed only by the partitioning and mkfs paths.
pub fn readSectorsTarget(lba: u32, count: u32, dest: [*]u8) bool {
    if (backend != .nvme) return false;
    return nvme.readSectorsOn(TARGET_CTRL_IDX, lba, count, dest);
}

/// Write to the install target. Returns false on a propagated I/O error or if
/// no target disk is attached.
///
/// Unlike `writeSectorsSecondary` this path runs no ELF write-tripwire. That
/// tripwire hunts a specific ext2-root corruptor by pattern-matching sector
/// content, and mkfs legitimately writes bitmaps and zero-fill that would trip
/// it; the target disk is also not the corruptor's victim by construction.
pub fn writeSectorsTarget(lba: u32, count: u32, src: [*]const u8) bool {
    if (backend != .nvme) return false;
    return nvme.writeSectorsOn(TARGET_CTRL_IDX, lba, count, src);
}

// =============================================================================
// Per-controller read-only views — GPT discovery
// =============================================================================

// Named per-index readers rather than a comptime generator: a Device holds
// bare function pointers (no context word), and Zig 0.15.2's LLVM backend
// has bitten us on anonymous struct types before — four explicit functions
// cost twelve lines and zero surprises. Indexed by NVMe controller.
fn readSectorsCtrl0(lba: u32, count: u32, dest: [*]u8) bool {
    return nvme.readSectorsOn(0, lba, count, dest);
}
fn readSectorsCtrl1(lba: u32, count: u32, dest: [*]u8) bool {
    return nvme.readSectorsOn(1, lba, count, dest);
}
fn readSectorsCtrl2(lba: u32, count: u32, dest: [*]u8) bool {
    return nvme.readSectorsOn(2, lba, count, dest);
}
fn readSectorsCtrl3(lba: u32, count: u32, dest: [*]u8) bool {
    return nvme.readSectorsOn(3, lba, count, dest);
}
const CTRL_READERS = [_]*const fn (lba: u32, count: u32, dest: [*]u8) bool{
    readSectorsCtrl0, readSectorsCtrl1, readSectorsCtrl2, readSectorsCtrl3,
};

/// Number of NVMe controllers found, 0 under the other backends. The index
/// domain of `ctrlDevice`.
pub fn controllerCount() usize {
    return if (backend == .nvme) nvme.controllerCount() else 0;
}

/// Read-only Device view of NVMe controller `idx`, for partition-table
/// scans (ext2 root discovery). Null when the backend isn't NVMe, the index
/// is out of range, or the namespace reports zero sectors.
pub fn ctrlDevice(idx: usize) ?Device {
    if (backend != .nvme) return null;
    if (idx >= CTRL_READERS.len) return null;
    const n = nvme.namespaceSectors(idx);
    if (n == 0) return null;
    return .{ .readSectors = CTRL_READERS[idx], .writeSectors = null, .sectors = n };
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
