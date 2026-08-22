// fat32_populate — write files into a FRESHLY-FORMATTED FAT32 volume.
//
// The installer's "install the bootloader" step: after fat32_mkfs.format has
// laid down an empty ESP on the target disk, this puts \EFI\BOOT\BOOTX64.EFI
// and \kernel.elf inside it. Deliberately NOT a general FAT32 writer (the
// driver in fat32.zig is one, but it is welded to the live root's disk with
// no partition offset — see its banner):
//
//   - clusters are allocated LINEARLY from the volume's first free cluster;
//     nothing is ever freed, so the allocator is a counter;
//   - every file's cluster run is contiguous, so a FAT chain is entry(c) =
//     c+1 with one end-of-chain — written in bulk after the data;
//   - directories are one cluster and never extended: this tree needs three
//     entries per directory and a cluster holds spc*16;
//   - 8.3 names only, uppercase, no LFN. UEFI's FAT driver matches
//     case-insensitively, which is why \EFI\BOOT\BOOTX64.EFI and
//     \kernel.elf both fit the scheme.
//
// The volume geometry is re-read from the BPB rather than assumed, so this
// stays correct if mkfs's parameters (spc, reserved count) ever change.

const std = @import("std");
const block = @import("../driver/block.zig");
const fat32 = @import("fat32.zig");
const debug = @import("../debug/debug.zig");

const SECTOR_SIZE: u32 = 512;
const FAT_EOC: u32 = 0x0FFF_FFFF;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const DIRENTS_PER_SECTOR: u32 = SECTOR_SIZE / @sizeOf(fat32.DirEntry);

// FSInfo offsets — mirrors fat32_mkfs.zig.
const FSINFO_FREE_COUNT_OFFSET: usize = 488;
const FSINFO_NEXT_FREE_OFFSET: usize = 492;

/// An open freshly-formatted volume plus its linear allocation state.
pub const Esp = struct {
    dev: block.Device,
    part_lba: u32,
    reserved: u32,
    num_fats: u32,
    fat_sectors: u32,
    spc: u32,
    /// Partition-relative sector where cluster 2 begins.
    data_start: u32,
    cluster_count: u32,
    root_cluster: u32,
    fsinfo_sector: u32,
    backup_boot: u32,
    /// The linear allocator: next never-used cluster.
    next_free: u32,
};

/// Chunked-I/O staging. 16 KiB = 32 sectors per command, the same batch
/// shape block.writeZeroRun uses.
const CHUNK_SECTORS: u32 = 32;
var chunk_buf: [CHUNK_SECTORS * SECTOR_SIZE]u8 align(8) = undefined;
var sector_buf: [SECTOR_SIZE]u8 align(8) = undefined;

/// Read the BPB and derive geometry. Returns null when the partition does
/// not carry the FAT32 this module expects to have just been written.
pub fn open(dev: block.Device, part_lba: u32) ?Esp {
    if (!dev.readSectors(part_lba, 1, &sector_buf)) return null;
    const bpb: *const fat32.BPB = @ptrCast(@alignCast(&sector_buf));
    if (bpb.bytes_per_sector != SECTOR_SIZE or bpb.fat_size_32 == 0 or
        bpb.num_fats == 0 or bpb.sectors_per_cluster == 0 or bpb.root_cluster < 2)
    {
        debug.klog("[esp-populate] partition at lba {d} is not the FAT32 we just wrote\n", .{part_lba});
        return null;
    }
    const reserved: u32 = bpb.reserved_sectors;
    const num_fats: u32 = bpb.num_fats;
    const fat_sectors: u32 = bpb.fat_size_32;
    const spc: u32 = bpb.sectors_per_cluster;
    const data_start = reserved + num_fats * fat_sectors;
    const cluster_count = (bpb.total_sectors_32 - data_start) / spc;
    return .{
        .dev = dev,
        .part_lba = part_lba,
        .reserved = reserved,
        .num_fats = num_fats,
        .fat_sectors = fat_sectors,
        .spc = spc,
        .data_start = data_start,
        .cluster_count = cluster_count,
        .root_cluster = bpb.root_cluster,
        .fsinfo_sector = bpb.fs_info,
        .backup_boot = bpb.bk_boot_sec,
        .next_free = bpb.root_cluster + 1,
    };
}

/// Partition-relative first sector of `cluster`.
inline fn clusterSector(e: *const Esp, cluster: u32) u32 {
    return e.data_start + (cluster - 2) * e.spc;
}

/// Build an 8.3 name field from "NAME.EXT" input (uppercase already —
/// callers pass literals). No dots in the result; both halves space-padded.
pub fn name83(name: []const u8) [11]u8 {
    var out: [11]u8 = .{' '} ** 11;
    var i: usize = 0;
    var o: usize = 0;
    while (i < name.len and name[i] != '.' and o < 8) : (i += 1) {
        out[o] = upper(name[i]);
        o += 1;
    }
    if (std.mem.lastIndexOfScalar(u8, name, '.')) |d| {
        var x: usize = d + 1;
        var xo: usize = 8;
        while (x < name.len and xo < 11) : (x += 1) {
            out[xo] = upper(name[x]);
            xo += 1;
        }
    }
    return out;
}

inline fn upper(c: u8) u8 {
    return if (c >= 'a' and c <= 'z') c - 32 else c;
}

/// Write the FAT chain for the contiguous run [first, first+count): each
/// entry points at the next cluster, the last is end-of-chain. Both FAT
/// copies. Sector-granular read-modify-write, batched CHUNK_SECTORS at a
/// time — a 20 MB kernel.elf is ~40K entries = ~320 FAT sectors per copy.
fn writeChain(e: *Esp, first: u32, count: u32) bool {
    if (count == 0) return true;
    const write = e.dev.writeSectors orelse return false;
    const last = first + count - 1;
    const s_first = (first * 4) / SECTOR_SIZE;
    const s_last = (last * 4) / SECTOR_SIZE;

    var fat: u32 = 0;
    while (fat < e.num_fats) : (fat += 1) {
        const fat_base = e.part_lba + e.reserved + fat * e.fat_sectors;
        var s = s_first;
        while (s <= s_last) {
            const chunk = @min(s_last - s + 1, CHUNK_SECTORS);
            if (!e.dev.readSectors(fat_base + s, chunk, &chunk_buf)) return false;
            // Patch every run entry that lands inside [s, s+chunk).
            const lo_byte: u64 = @as(u64, s) * SECTOR_SIZE;
            const hi_byte: u64 = lo_byte + @as(u64, chunk) * SECTOR_SIZE;
            var c = @max(first, @as(u32, @intCast(lo_byte / 4)));
            while (c <= last and @as(u64, c) * 4 < hi_byte) : (c += 1) {
                const v: u32 = if (c == last) FAT_EOC else c + 1;
                const off: usize = @intCast(@as(u64, c) * 4 - lo_byte);
                std.mem.writeInt(u32, chunk_buf[off..][0..4], v, .little);
            }
            if (!write(fat_base + s, chunk, &chunk_buf)) return false;
            s += chunk;
        }
    }
    return true;
}

/// Insert `ent` into the first free 32-byte slot of `dir_cluster` (one
/// cluster scanned — this writer never grows a directory). Free = never
/// used (0x00) or deleted (0xE5).
fn insertDirent(e: *Esp, dir_cluster: u32, ent: *const fat32.DirEntry) bool {
    const write = e.dev.writeSectors orelse return false;
    var s: u32 = 0;
    while (s < e.spc) : (s += 1) {
        const lba = e.part_lba + clusterSector(e, dir_cluster) + s;
        if (!e.dev.readSectors(lba, 1, &sector_buf)) return false;
        var i: u32 = 0;
        while (i < DIRENTS_PER_SECTOR) : (i += 1) {
            const off = i * @sizeOf(fat32.DirEntry);
            if (sector_buf[off] == 0x00 or sector_buf[off] == 0xE5) {
                @memcpy(sector_buf[off..][0..@sizeOf(fat32.DirEntry)], std.mem.asBytes(ent));
                return write(lba, 1, &sector_buf);
            }
        }
    }
    debug.klog("[esp-populate] directory cluster {d} is full\n", .{dir_cluster});
    return false;
}

const DOT_NAME: [11]u8 = .{ '.', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ' };
const DOTDOT_NAME: [11]u8 = .{ '.', '.', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ' };

fn makeDirent(nm: *const [11]u8, attr: u8, cluster: u32, size: u32) fat32.DirEntry {
    var ent = std.mem.zeroes(fat32.DirEntry);
    ent.name = nm.*;
    ent.attr = attr;
    ent.fst_clus_hi = @intCast(cluster >> 16);
    ent.fst_clus_lo = @intCast(cluster & 0xFFFF);
    ent.file_size = size;
    return ent;
}

/// Create subdirectory `nm` inside `parent_cluster`. Returns the new
/// directory's cluster. The ".." entry stores cluster 0 when the parent is
/// the root — FAT's spec-mandated special case.
pub fn addDir(e: *Esp, parent_cluster: u32, nm: *const [11]u8) ?u32 {
    const write = e.dev.writeSectors orelse return null;
    if (e.next_free >= e.cluster_count + 2) return null;
    const c = e.next_free;
    e.next_free += 1;
    if (!writeChain(e, c, 1)) return null;

    // First sector: "." and ".."; rest of the cluster: zeroed.
    @memset(&sector_buf, 0);
    const dot = makeDirent(&DOT_NAME, ATTR_DIRECTORY, c, 0);
    const dotdot_cluster: u32 = if (parent_cluster == e.root_cluster) 0 else parent_cluster;
    const dotdot = makeDirent(&DOTDOT_NAME, ATTR_DIRECTORY, dotdot_cluster, 0);
    @memcpy(sector_buf[0..32], std.mem.asBytes(&dot));
    @memcpy(sector_buf[32..64], std.mem.asBytes(&dotdot));
    const first_lba = e.part_lba + clusterSector(e, c);
    if (!write(first_lba, 1, &sector_buf)) return null;
    if (e.spc > 1) {
        if (!block.writeZeroRun(e.dev, first_lba + 1, e.spc - 1)) return null;
    }

    const ent = makeDirent(nm, ATTR_DIRECTORY, c, 0);
    if (!insertDirent(e, parent_cluster, &ent)) return null;
    return c;
}

/// In-progress file: clusters stream to disk as data arrives; the FAT chain
/// and directory entry land at endFile.
pub const FileWriter = struct {
    first_cluster: u32,
    size: u64 = 0,
    /// Partition-relative sector the next append writes to.
    cur_sector: u32,
    /// A partial-sector append is only legal as the LAST one.
    sealed: bool = false,
};

pub fn beginFile(e: *Esp) FileWriter {
    return .{
        .first_cluster = e.next_free,
        .cur_sector = clusterSector(e, e.next_free),
    };
}

/// Append `data` to the file's linear cluster run. Any append whose length
/// is not sector-aligned zero-pads its final sector and must be the last.
pub fn appendData(e: *Esp, w: *FileWriter, data: []const u8) bool {
    const write = e.dev.writeSectors orelse return false;
    if (w.sealed) {
        debug.klog("[esp-populate] append after a partial-sector append\n", .{});
        return false;
    }
    // Bound the stream to the data region — the chain isn't committed until
    // endFile, so this is the only thing standing between a too-big file and
    // the backup GPT past the partition's end.
    const data_end = e.data_start + e.cluster_count * e.spc;
    const sectors_needed: u32 = @intCast((data.len + SECTOR_SIZE - 1) / SECTOR_SIZE);
    if (w.cur_sector + sectors_needed > data_end) {
        debug.klog("[esp-populate] volume full mid-stream at sector {d}\n", .{w.cur_sector});
        return false;
    }
    var done: usize = 0;
    while (done + SECTOR_SIZE <= data.len) {
        const sectors: u32 = @intCast(@min((data.len - done) / SECTOR_SIZE, CHUNK_SECTORS));
        if (!write(e.part_lba + w.cur_sector, sectors, data.ptr + done)) return false;
        w.cur_sector += sectors;
        done += sectors * SECTOR_SIZE;
    }
    if (done < data.len) {
        @memset(&sector_buf, 0);
        @memcpy(sector_buf[0 .. data.len - done], data[done..]);
        if (!write(e.part_lba + w.cur_sector, 1, &sector_buf)) return false;
        w.cur_sector += 1;
        w.sealed = true;
    }
    w.size += data.len;
    return true;
}

/// Commit the file: mark its clusters in both FATs and give it a directory
/// entry in `dir_cluster`. A zero-byte file gets cluster 0 and no chain.
pub fn endFile(e: *Esp, w: *FileWriter, dir_cluster: u32, nm: *const [11]u8) bool {
    const bytes_per_cluster: u64 = @as(u64, e.spc) * SECTOR_SIZE;
    const clusters: u32 = @intCast((w.size + bytes_per_cluster - 1) / bytes_per_cluster);
    if (w.size > std.math.maxInt(u32)) {
        debug.klog("[esp-populate] {d} bytes exceeds FAT32's 4 GiB file cap\n", .{w.size});
        return false;
    }
    if (e.next_free + clusters > e.cluster_count + 2) {
        debug.klog("[esp-populate] volume full: need {d} clusters\n", .{clusters});
        return false;
    }
    if (clusters > 0) {
        if (!writeChain(e, w.first_cluster, clusters)) return false;
        e.next_free += clusters;
    }
    const first: u32 = if (clusters > 0) w.first_cluster else 0;
    const ent = makeDirent(nm, ATTR_ARCHIVE, first, @intCast(w.size));
    return insertDirent(e, dir_cluster, &ent);
}

/// Refresh both FSInfo copies with the linear allocator's final state so
/// fsck.fat's free-count check matches reality.
pub fn finalize(e: *Esp) bool {
    const write = e.dev.writeSectors orelse return false;
    const used = e.next_free - 2;
    const free_count = e.cluster_count - used;
    const copies = [2]u32{ e.fsinfo_sector, e.backup_boot + e.fsinfo_sector };
    for (copies) |s| {
        if (!e.dev.readSectors(e.part_lba + s, 1, &sector_buf)) return false;
        std.mem.writeInt(u32, sector_buf[FSINFO_FREE_COUNT_OFFSET..][0..4], free_count, .little);
        std.mem.writeInt(u32, sector_buf[FSINFO_NEXT_FREE_OFFSET..][0..4], e.next_free, .little);
        if (!write(e.part_lba + s, 1, &sector_buf)) return false;
    }
    debug.klog("[esp-populate] {d} clusters used, {d} free\n", .{ used, free_count });
    return true;
}
