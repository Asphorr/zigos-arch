// mkfs.fat32 — create an empty FAT32 filesystem, for use as an EFI System
// Partition.
//
// Firmware finds a bootloader by looking for a FAT filesystem in a partition
// of type EFI System and opening \EFI\BOOT\BOOTX64.EFI inside it. Until now
// that partition was always built on the host (`mkfs.fat -F 32 disk.img` in
// build.zig, or QEMU's synthetic `fat:rw:` device), so the kernel could read
// an ESP but never produce one.
//
// The BPB layout comes from fat32.zig — the driver's own declaration, reused
// rather than redeclared, so the reader and the writer cannot drift apart.
//
// THE CLUSTER-COUNT TRAP: a volume is FAT32 only if it has at least 65525
// clusters. Below that threshold the format is FAT16 by definition, no matter
// what the BPB claims, and tools that follow the spec will read the volume as
// FAT16 and find garbage. It is entirely possible to write a self-consistent
// "FAT32" that every checker rejects for this reason alone, so the count is
// computed and verified here before anything is written.

const std = @import("std");

const block = @import("../driver/block.zig");
const fat32 = @import("fat32.zig");
const random = @import("../crypto/random.zig");

const debug = @import("../debug/debug.zig");

// =============================================================================
// Constants
// =============================================================================

const SECTOR_SIZE: u32 = 512;

/// FAT32's defining minimum. See the banner — this is a format boundary, not
/// a tunable.
const MIN_FAT32_CLUSTERS: u32 = 65525;

/// Standard FAT32 reserved region: boot sector, FSInfo, backup copies at 6/7,
/// and slack. Every implementation uses 32.
///
/// These are u32 because they are almost always arithmetic operands against
/// sector counts; the narrower on-disk field types are applied at the single
/// point each is stored into the BPB.
const RESERVED_SECTORS: u32 = 32;
const NUM_FATS: u32 = 2;
const FSINFO_SECTOR: u32 = 1;
const BACKUP_BOOT_SECTOR: u32 = 6;

/// Cluster 2 is the first addressable data cluster and by convention holds the
/// root directory.
const ROOT_CLUSTER: u32 = 2;

/// Fixed-disk media descriptor, mirrored into FAT entry 0's low byte.
const MEDIA_FIXED: u8 = 0xF8;

/// End-of-chain marker. The top 4 bits of a FAT32 entry are reserved and read
/// as zero, so the marker is 0x0FFFFFFF rather than 0xFFFFFFFF.
const FAT_EOC: u32 = 0x0FFF_FFFF;

const ATTR_VOLUME_ID: u8 = 0x08;

// FSInfo signatures (fatgen103 §5).
const FSINFO_LEAD_SIG: u32 = 0x4161_5252;
const FSINFO_STRUCT_SIG: u32 = 0x6141_7272;
const FSINFO_TRAIL_SIG: u32 = 0xAA55_0000;
const FSINFO_STRUCT_SIG_OFFSET: usize = 484;
const FSINFO_FREE_COUNT_OFFSET: usize = 488;
const FSINFO_NEXT_FREE_OFFSET: usize = 492;
const FSINFO_TRAIL_SIG_OFFSET: usize = 508;

const BOOT_SIGNATURE_OFFSET: usize = 510;

/// A partition to format, in 512-byte sectors.
pub const Target = struct {
    dev: block.Device,
    part_lba: u32,
    part_sectors: u32,
};

// =============================================================================
// Geometry
// =============================================================================

const Geometry = struct {
    sectors_per_cluster: u32,
    fat_sectors: u32,
    data_start_sector: u32,
    cluster_count: u32,
};

/// Microsoft's fatgen103 FAT-size approximation, then a check that the result
/// actually holds the cluster count it implies. The approximation can only err
/// on the generous side, so verifying rather than iterating is sufficient —
/// but it IS verified, because a FAT one sector short corrupts the tail of the
/// volume in a way nothing notices until the disk is nearly full.
fn computeGeometry(part_sectors: u32) ?Geometry {
    // One sector per cluster keeps the cluster count high, which is what
    // clears the FAT32 minimum on a partition as small as an ESP. Larger
    // clusters would be more space-efficient on a big volume and are exactly
    // wrong here.
    const spc: u32 = 1;

    if (part_sectors <= RESERVED_SECTORS) {
        debug.klog("[mkfs.fat32] partition of {d} sectors is smaller than the reserved region\n", .{part_sectors});
        return null;
    }

    const usable = part_sectors - RESERVED_SECTORS;
    // (256 * SecPerClus + NumFATs) / 2 — the divisor from the spec's sizing
    // formula, which folds "4 bytes per FAT entry, NumFATs copies" into one
    // term.
    const divisor: u32 = (256 * spc + NUM_FATS) / 2;
    const fat_sectors = (usable + divisor - 1) / divisor;

    const data_sectors = part_sectors - RESERVED_SECTORS - NUM_FATS * fat_sectors;
    const cluster_count = data_sectors / spc;

    // Entries 0 and 1 are reserved, so the table must hold cluster_count + 2.
    const entries_needed = cluster_count + 2;
    const fat_bytes_needed = entries_needed * 4;
    const fat_sectors_needed = (fat_bytes_needed + SECTOR_SIZE - 1) / SECTOR_SIZE;
    if (fat_sectors < fat_sectors_needed) {
        debug.klog("[mkfs.fat32] FAT sizing short: {d} sectors for {d} entries (need {d})\n", .{ fat_sectors, entries_needed, fat_sectors_needed });
        return null;
    }

    if (cluster_count < MIN_FAT32_CLUSTERS) {
        debug.klog("[mkfs.fat32] {d} clusters is below the FAT32 minimum {d} — partition too small\n", .{ cluster_count, MIN_FAT32_CLUSTERS });
        return null;
    }

    return .{
        .sectors_per_cluster = spc,
        .fat_sectors = fat_sectors,
        .data_start_sector = RESERVED_SECTORS + NUM_FATS * fat_sectors,
        .cluster_count = cluster_count,
    };
}

// =============================================================================
// Sector writes
// =============================================================================

fn writeSector(t: Target, write: *const fn (u32, u32, [*]const u8) bool, sector: u32, buf: *const [SECTOR_SIZE]u8) bool {
    if (!write(t.part_lba + sector, 1, buf)) {
        debug.klog("[mkfs.fat32] write failed at partition sector {d}\n", .{sector});
        return false;
    }
    return true;
}

fn put32(buf: []u8, off: usize, v: u32) void {
    buf[off] = @truncate(v);
    buf[off + 1] = @truncate(v >> 8);
    buf[off + 2] = @truncate(v >> 16);
    buf[off + 3] = @truncate(v >> 24);
}

// =============================================================================
// Entry point
// =============================================================================

/// Formats `t` as an empty FAT32 volume. Existing contents are lost.
///
/// Returns false, having logged why, on a read-only device, a partition that
/// cannot hold a legal FAT32 (see the cluster-count trap in the banner), or
/// any failed write. Geometry is settled before the first write.
///
/// Caller context: process context only — issues many blocking sector writes.
pub fn format(t: Target, volume_label: []const u8) bool {
    const write = t.dev.writeSectors orelse {
        debug.klog("[mkfs.fat32] device is read-only\n", .{});
        return false;
    };

    const geo = computeGeometry(t.part_sectors) orelse return false;

    debug.klog("[mkfs.fat32] {d} sectors, {d} clusters, FAT {d} sectors x{d}, data at {d}\n", .{ t.part_sectors, geo.cluster_count, geo.fat_sectors, NUM_FATS, geo.data_start_sector });

    var volume_id: [4]u8 = undefined;
    if (!random.fillRandom(&volume_id)) {
        debug.klog("[mkfs.fat32] volume ID from degraded entropy source\n", .{});
    }

    // --- Boot sector, written to sector 0 and to the backup at sector 6. The
    //     backup is what firmware falls back on when sector 0 is unreadable;
    //     an ESP without one is accepted by most implementations and repaired
    //     by none.
    {
        var buf: [SECTOR_SIZE]u8 = .{0} ** SECTOR_SIZE;
        const bpb: *fat32.BPB = @ptrCast(@alignCast(&buf));
        bpb.* = .{
            // Short jump over the BPB then a NOP — the shape every FAT
            // implementation expects to find, even with no boot code behind it.
            .jmp_boot = .{ 0xEB, 0x58, 0x90 },
            .oem_name = .{ 'M', 'S', 'W', 'I', 'N', '4', '.', '1' },
            .bytes_per_sector = @intCast(SECTOR_SIZE),
            .sectors_per_cluster = @intCast(geo.sectors_per_cluster),
            .reserved_sectors = @intCast(RESERVED_SECTORS),
            .num_fats = @intCast(NUM_FATS),
            // Both zero on FAT32: the root directory is a normal cluster
            // chain, and the sector count lives in the 32-bit field.
            .root_entry_count = 0,
            .total_sectors_16 = 0,
            .media = MEDIA_FIXED,
            .fat_size_16 = 0,
            // Legacy CHS geometry. Nothing reads these on an LBA volume, but
            // the conventional values keep old tools from complaining.
            .sectors_per_track = 63,
            .num_heads = 255,
            .hidden_sectors = t.part_lba,
            .total_sectors_32 = t.part_sectors,
            .fat_size_32 = geo.fat_sectors,
            .ext_flags = 0, // both FATs live, mirrored
            .fs_ver = 0,
            .root_cluster = ROOT_CLUSTER,
            .fs_info = @intCast(FSINFO_SECTOR),
            .bk_boot_sec = @intCast(BACKUP_BOOT_SECTOR),
            .reserved = [_]u8{0} ** 12,
            .drive_number = 0x80,
            .reserved1 = 0,
            .boot_sig = 0x29, // extended boot signature: volume_id/label valid
            .volume_id = @bitCast(volume_id),
            .volume_label = padName(volume_label),
            .fs_type = .{ 'F', 'A', 'T', '3', '2', ' ', ' ', ' ' },
        };
        buf[BOOT_SIGNATURE_OFFSET] = 0x55;
        buf[BOOT_SIGNATURE_OFFSET + 1] = 0xAA;

        if (!writeSector(t, write, 0, &buf)) return false;
        if (!writeSector(t, write, BACKUP_BOOT_SECTOR, &buf)) return false;
    }

    // --- FSInfo, likewise mirrored behind the backup boot sector.
    {
        var buf: [SECTOR_SIZE]u8 = .{0} ** SECTOR_SIZE;
        put32(&buf, 0, FSINFO_LEAD_SIG);
        put32(&buf, FSINFO_STRUCT_SIG_OFFSET, FSINFO_STRUCT_SIG);
        // Cluster 2 is taken by the root directory; everything above is free.
        put32(&buf, FSINFO_FREE_COUNT_OFFSET, geo.cluster_count - 1);
        put32(&buf, FSINFO_NEXT_FREE_OFFSET, ROOT_CLUSTER + 1);
        put32(&buf, FSINFO_TRAIL_SIG_OFFSET, FSINFO_TRAIL_SIG);

        if (!writeSector(t, write, FSINFO_SECTOR, &buf)) return false;
        if (!writeSector(t, write, BACKUP_BOOT_SECTOR + FSINFO_SECTOR, &buf)) return false;
    }

    // --- Both FAT copies. Only the first sector carries anything; the rest
    //     must read as zero, which is what "free cluster" means.
    {
        var first: [SECTOR_SIZE]u8 = .{0} ** SECTOR_SIZE;
        // Entry 0: media descriptor in the low byte, the rest set.
        put32(&first, 0, 0x0FFF_FF00 | @as(u32, MEDIA_FIXED));
        // Entry 1: end-of-chain, historically also carrying dirty flags we
        // leave clear.
        put32(&first, 4, FAT_EOC);
        // Entry 2: the root directory is one cluster and ends immediately.
        put32(&first, 8, FAT_EOC);

        var fat: u32 = 0;
        while (fat < NUM_FATS) : (fat += 1) {
            const base = RESERVED_SECTORS + fat * geo.fat_sectors;
            if (!writeSector(t, write, base, &first)) return false;
            // The rest of the table is zero — batched, not per sector. See
            // block.ZERO_CHUNK_SECTORS for what per-sector cost us.
            if (!block.writeZeroRun(t.dev, t.part_lba + base + 1, geo.fat_sectors - 1)) {
                debug.klog("[mkfs.fat32] FAT {d} zero-fill failed\n", .{fat});
                return false;
            }
        }
    }

    // --- Root directory cluster: zeroed, with a volume-label entry so the
    //     volume reports its name the way a host-formatted one does.
    {
        var buf: [SECTOR_SIZE]u8 = .{0} ** SECTOR_SIZE;
        const e: *fat32.DirEntry = @ptrCast(@alignCast(&buf));
        e.* = std.mem.zeroes(fat32.DirEntry);
        e.name = padName(volume_label);
        e.attr = ATTR_VOLUME_ID;

        if (!writeSector(t, write, geo.data_start_sector, &buf)) return false;

        // Remaining sectors of the root cluster must be zero so directory
        // scanning stops at the first empty entry.
        if (geo.sectors_per_cluster > 1) {
            if (!block.writeZeroRun(t.dev, t.part_lba + geo.data_start_sector + 1, geo.sectors_per_cluster - 1)) {
                debug.klog("[mkfs.fat32] root cluster zero-fill failed\n", .{});
                return false;
            }
        }
    }

    debug.klog("[mkfs.fat32] done: {d} free clusters\n", .{geo.cluster_count - 1});
    return true;
}

/// FAT names are space-padded, not NUL-terminated, and upper-case by
/// convention. Longer input is truncated — the 11-byte field has no escape.
fn padName(name: []const u8) [11]u8 {
    var out: [11]u8 = .{' '} ** 11;
    const n = @min(name.len, out.len);
    for (name[0..n], 0..) |c, i| {
        out[i] = if (c >= 'a' and c <= 'z') c - 32 else c;
    }
    return out;
}
