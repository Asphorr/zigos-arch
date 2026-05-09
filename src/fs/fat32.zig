const std = @import("std");
const ata = @import("../driver/block.zig");
const debug = @import("../debug/debug.zig");
const vga = @import("../ui/vga.zig");
const path_cache = @import("path_cache.zig");

// FAT32 constants
const SECTOR_SIZE = 512;
const DIR_ENTRY_SIZE = 32;
const FAT_ENTRY_SIZE = 4;
const ATTR_READ_ONLY: u8 = 0x01;
const ATTR_HIDDEN: u8 = 0x02;
const ATTR_SYSTEM: u8 = 0x04;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

const FAT32_EOC: u32 = 0x0FFFFFF8; // End of chain marker (>=0x0FFFFFF8)
const FAT32_FREE: u32 = 0x00000000;
const FAT32_MASK: u32 = 0x0FFFFFFF; // Only 28 bits used
const LFN_LAST_ENTRY: u8 = 0x40; // Flag on last LFN sequence entry
const LFN_SEQ_MASK: u8 = 0x1F; // Sequence number mask (1-20)
const MAX_LFN_LEN: usize = 255; // Max long filename length

// BPB (BIOS Parameter Block) — FAT32 extended
const BPB = extern struct {
    jmp_boot: [3]u8,
    oem_name: [8]u8,
    bytes_per_sector: u16 align(1),
    sectors_per_cluster: u8,
    reserved_sectors: u16 align(1),
    num_fats: u8,
    root_entry_count: u16 align(1), // 0 for FAT32
    total_sectors_16: u16 align(1),
    media: u8,
    fat_size_16: u16 align(1), // 0 for FAT32
    sectors_per_track: u16 align(1),
    num_heads: u16 align(1),
    hidden_sectors: u32 align(1),
    total_sectors_32: u32 align(1),
    // FAT32-specific fields (offset 36)
    fat_size_32: u32 align(1),
    ext_flags: u16 align(1),
    fs_ver: u16 align(1),
    root_cluster: u32 align(1),
    fs_info: u16 align(1),
    bk_boot_sec: u16 align(1),
    reserved: [12]u8,
    drive_number: u8,
    reserved1: u8,
    boot_sig: u8,
    volume_id: u32 align(1),
    volume_label: [11]u8,
    fs_type: [8]u8,
};

// Directory entry (32 bytes)
pub const DirEntry = extern struct {
    name: [11]u8,
    attr: u8,
    nt_res: u8,
    crt_time_tenth: u8,
    crt_time: u16 align(1),
    crt_date: u16 align(1),
    lst_acc_date: u16 align(1),
    fst_clus_hi: u16 align(1),
    wrt_time: u16 align(1),
    wrt_date: u16 align(1),
    fst_clus_lo: u16 align(1),
    file_size: u32 align(1),
};

pub const Handle = struct {
    dir_cluster: u32, // cluster of the directory containing this file
    dir_index: u32, // index within that directory
    first_cluster: u32,
    file_size: u32,
    current_offset: u32,
};

// Cached layout info
var fat_start: u32 = 0;
var data_start: u32 = 0;
var sectors_per_cluster: u32 = 0;
pub var root_cluster: u32 = 0;
var fat_size: u32 = 0;
var total_clusters: u32 = 0;
var initialized: bool = false;

pub fn isInitialized() bool {
    return initialized;
}

// Cached FAT sectors (8-sector window = 4KB, covers 1024 FAT entries)
const FAT_CACHE_SECTORS = 8;
var cached_fat_base: u32 = 0xFFFFFFFF; // first sector of cached window
var fat_cache: [SECTOR_SIZE * FAT_CACHE_SECTORS]u8 = undefined;
var fat_cache_dirty: bool = false;
var fat_cache_dirty_mask: u8 = 0; // which sectors within window are dirty

// Directory entry cache (4 sectors = 2KB, covers 64 directory entries)
const DIR_CACHE_SECTORS = 4;
var cached_dir_cluster: u32 = 0xFFFFFFFF;
var cached_dir_sector: u32 = 0xFFFFFFFF;
var dir_cache: [SECTOR_SIZE * DIR_CACHE_SECTORS]u8 = undefined;
var dir_cache_dirty: bool = false;
var dir_cache_dirty_mask: u8 = 0;

fn readDiskSector(lba: u32, dest: [*]u8) void {
    ata.readSectorSecondary(lba, dest);
}

fn writeDiskSector(lba: u32, src: [*]const u8) void {
    ata.writeSectorSecondary(lba, src);
}

pub fn init() void {
    var boot_sector: [SECTOR_SIZE]u8 = undefined;
    readDiskSector(0, &boot_sector);

    const bpb: *const BPB = @ptrCast(@alignCast(&boot_sector));

    if (bpb.bytes_per_sector != 512) {
        debug.klog("[fat32] Invalid bytes_per_sector: {d}\n", .{bpb.bytes_per_sector});
        return;
    }

    sectors_per_cluster = bpb.sectors_per_cluster;

    // Determine FAT size (FAT32 uses fat_size_32)
    if (bpb.fat_size_16 != 0) {
        fat_size = bpb.fat_size_16;
    } else {
        fat_size = bpb.fat_size_32;
    }

    fat_start = bpb.reserved_sectors;
    root_cluster = bpb.root_cluster;

    // FAT32: no fixed root directory area
    // data_start = after reserved sectors + FATs
    const root_dir_sectors: u32 = (@as(u32, bpb.root_entry_count) * DIR_ENTRY_SIZE + SECTOR_SIZE - 1) / SECTOR_SIZE;
    data_start = fat_start + @as(u32, bpb.num_fats) * fat_size + root_dir_sectors;

    // Calculate total clusters for allocCluster bounds
    const total_sectors = if (bpb.total_sectors_16 != 0) @as(u32, bpb.total_sectors_16) else bpb.total_sectors_32;
    total_clusters = (total_sectors - data_start) / sectors_per_cluster + 2;

    initialized = true;
    debug.klog("[fat32] Initialized: fat@{d} data@{d} spc={d} rootclus={d} total_clus={d}\n", .{ fat_start, data_start, sectors_per_cluster, root_cluster, total_clusters });
}

fn clusterToLBA(cluster: u32) u32 {
    return data_start + (cluster - 2) * sectors_per_cluster;
}

fn getEntryCluster(entry: DirEntry) u32 {
    return (@as(u32, entry.fst_clus_hi) << 16) | @as(u32, entry.fst_clus_lo);
}

/// Read a FAT entry for the given cluster.
fn readFATEntry(cluster: u32) u32 {
    const fat_offset = cluster * FAT_ENTRY_SIZE;
    const sector = fat_start + fat_offset / SECTOR_SIZE;

    ensureFATCached(sector);

    // Offset within the multi-sector cache
    const cache_off = (sector - cached_fat_base) * SECTOR_SIZE + fat_offset % SECTOR_SIZE;

    // Read 4 bytes little-endian, mask to 28 bits
    const val = @as(u32, fat_cache[cache_off]) |
        (@as(u32, fat_cache[cache_off + 1]) << 8) |
        (@as(u32, fat_cache[cache_off + 2]) << 16) |
        (@as(u32, fat_cache[cache_off + 3]) << 24);
    return val & FAT32_MASK;
}

/// Write a FAT entry, preserving top 4 bits.
fn writeFATEntry(cluster: u32, value: u32) void {
    const fat_offset = cluster * FAT_ENTRY_SIZE;
    const sector = fat_start + fat_offset / SECTOR_SIZE;

    ensureFATCached(sector);

    const cache_off = (sector - cached_fat_base) * SECTOR_SIZE + fat_offset % SECTOR_SIZE;
    const sector_idx: u3 = @truncate(sector - cached_fat_base);

    // Preserve top 4 bits of existing entry
    const old_top = @as(u32, fat_cache[cache_off + 3]) & 0xF0;
    const new_val = (value & FAT32_MASK) | (@as(u32, old_top) << 24);

    fat_cache[cache_off] = @truncate(new_val);
    fat_cache[cache_off + 1] = @truncate(new_val >> 8);
    fat_cache[cache_off + 2] = @truncate(new_val >> 16);
    fat_cache[cache_off + 3] = @truncate(new_val >> 24);
    fat_cache_dirty = true;
    fat_cache_dirty_mask |= @as(u8, 1) << sector_idx;
}

fn ensureFATCached(sector: u32) void {
    const base = sector & ~@as(u32, FAT_CACHE_SECTORS - 1); // align to 8-sector boundary
    if (cached_fat_base == base) return;
    flushFATCache();
    ata.readSectorsSecondary(base, FAT_CACHE_SECTORS, &fat_cache);
    cached_fat_base = base;
}

fn flushFATCache() void {
    if (fat_cache_dirty and cached_fat_base != 0xFFFFFFFF) {
        // Only write back dirty sectors
        var mask = fat_cache_dirty_mask;
        var i: u3 = 0;
        while (mask != 0) : (i += 1) {
            if (mask & 1 != 0) {
                writeDiskSector(cached_fat_base + i, fat_cache[@as(u32, i) * SECTOR_SIZE ..][0..SECTOR_SIZE]);
            }
            mask >>= 1;
        }
        fat_cache_dirty = false;
        fat_cache_dirty_mask = 0;
    }
}

fn ensureDirCached(dir_cluster: u32, sector_in_cluster: u32) void {
    const base_sector = sector_in_cluster & ~@as(u32, DIR_CACHE_SECTORS - 1);
    if (cached_dir_cluster == dir_cluster and cached_dir_sector == base_sector) return;

    flushDirCache();

    const lba = clusterToLBA(dir_cluster) + base_sector;
    const sectors_to_read = @min(DIR_CACHE_SECTORS, sectors_per_cluster - base_sector);
    ata.readSectorsSecondary(lba, @intCast(sectors_to_read), &dir_cache);

    cached_dir_cluster = dir_cluster;
    cached_dir_sector = base_sector;
}

fn flushDirCache() void {
    if (dir_cache_dirty and cached_dir_cluster != 0xFFFFFFFF) {
        const lba = clusterToLBA(cached_dir_cluster) + cached_dir_sector;
        var mask = dir_cache_dirty_mask;
        var i: u2 = 0;
        while (mask != 0) : (i += 1) {
            if (mask & 1 != 0) {
                writeDiskSector(lba + i, dir_cache[@as(u32, i) * SECTOR_SIZE ..][0..SECTOR_SIZE]);
            }
            mask >>= 1;
        }
        dir_cache_dirty = false;
        dir_cache_dirty_mask = 0;
    }
}

pub fn flushAll() void {
    flushFATCache();
    flushDirCache();
}

fn isEOC(cluster: u32) bool {
    return cluster >= FAT32_EOC;
}

// --- Directory entry helpers (cluster-based) ---

/// Read a directory entry from a directory cluster chain.
fn readDirEntry(dir_cluster: u32, index: u32) ?DirEntry {
    const entries_per_cluster = sectors_per_cluster * SECTOR_SIZE / DIR_ENTRY_SIZE;

    var cluster = dir_cluster;
    var remaining = index;

    // Follow chain to the right cluster
    while (remaining >= entries_per_cluster) {
        if (isEOC(cluster) or cluster < 2) return null;
        cluster = readFATEntry(cluster);
        remaining -= entries_per_cluster;
    }

    if (isEOC(cluster) or cluster < 2) return null;

    // Read the sector containing this entry using cache
    const entries_per_sector = SECTOR_SIZE / DIR_ENTRY_SIZE;
    const sector_in_cluster = remaining / entries_per_sector;
    const offset = (remaining % entries_per_sector) * DIR_ENTRY_SIZE;

    ensureDirCached(cluster, sector_in_cluster);

    const cache_sector = sector_in_cluster - cached_dir_sector;
    const cache_offset = cache_sector * SECTOR_SIZE + offset;

    return @as(*const DirEntry, @ptrCast(@alignCast(&dir_cache[cache_offset]))).*;
}

/// Read raw 32 bytes of a directory entry (for LFN parsing).
pub fn readRootDirEntryRaw(index: u32) ?[32]u8 {
    return readDirEntryRaw(root_cluster, index);
}

/// Path-aware version of readRootDirEntryRaw. Used by syscall layer's
/// readdir to walk arbitrary directories. dir_cluster comes from
/// resolveDirCluster().
pub fn readDirEntryRawAt(dir_cluster: u32, index: u32) ?[32]u8 {
    return readDirEntryRaw(dir_cluster, index);
}

fn readDirEntryRaw(dir_cluster: u32, index: u32) ?[32]u8 {
    const entries_per_cluster = sectors_per_cluster * SECTOR_SIZE / DIR_ENTRY_SIZE;
    var cluster = dir_cluster;
    var remaining = index;
    while (remaining >= entries_per_cluster) {
        if (isEOC(cluster) or cluster < 2) return null;
        cluster = readFATEntry(cluster);
        remaining -= entries_per_cluster;
    }
    if (isEOC(cluster) or cluster < 2) return null;
    const entries_per_sector = SECTOR_SIZE / DIR_ENTRY_SIZE;
    const sector_in_cluster = remaining / entries_per_sector;
    const offset = (remaining % entries_per_sector) * DIR_ENTRY_SIZE;

    ensureDirCached(cluster, sector_in_cluster);

    const cache_sector = sector_in_cluster - cached_dir_sector;
    const cache_offset = cache_sector * SECTOR_SIZE + offset;

    return dir_cache[cache_offset..][0..32].*;
}

/// Write a directory entry to a directory cluster chain.
fn writeDirEntry(dir_cluster: u32, index: u32, entry: DirEntry) void {
    const entries_per_cluster = sectors_per_cluster * SECTOR_SIZE / DIR_ENTRY_SIZE;

    var cluster = dir_cluster;
    var remaining = index;

    while (remaining >= entries_per_cluster) {
        if (isEOC(cluster) or cluster < 2) return;
        cluster = readFATEntry(cluster);
        remaining -= entries_per_cluster;
    }

    if (isEOC(cluster) or cluster < 2) return;

    const entries_per_sector = SECTOR_SIZE / DIR_ENTRY_SIZE;
    const sector_in_cluster = remaining / entries_per_sector;
    const offset = (remaining % entries_per_sector) * DIR_ENTRY_SIZE;

    ensureDirCached(cluster, sector_in_cluster);

    const cache_sector = sector_in_cluster - cached_dir_sector;
    const cache_offset = cache_sector * SECTOR_SIZE + offset;
    const sector_idx: u2 = @truncate(cache_sector);

    const dest: *DirEntry = @ptrCast(@alignCast(&dir_cache[cache_offset]));
    dest.* = entry;

    dir_cache_dirty = true;
    dir_cache_dirty_mask |= @as(u8, 1) << sector_idx;
}

// --- Public compatibility wrappers (for VFS/syscall) ---

/// Read a root directory entry by index (compatibility with FAT16 API).
pub fn readRootDirEntry(index: u32) ?DirEntry {
    return readDirEntry(root_cluster, index);
}

/// Approximate root entry count for listing (scan until 0x00).
pub var root_entry_count: u32 = 0;

fn countRootEntries() void {
    var i: u32 = 0;
    while (i < 4096) : (i += 1) { // reasonable max
        const entry = readDirEntry(root_cluster, i) orelse break;
        if (entry.name[0] == 0) break;
        i += 1;
    }
    root_entry_count = i;
}

// --- 8.3 filename helpers ---

fn toFAT83(name: []const u8) [11]u8 {
    var result: [11]u8 = [_]u8{' '} ** 11;

    var dot_pos: ?usize = null;
    for (name, 0..) |c, idx| {
        if (c == '.') {
            dot_pos = idx;
            break;
        }
    }

    const base_end = dot_pos orelse name.len;
    const base_len = if (base_end > 8) 8 else base_end;
    for (0..base_len) |i| {
        result[i] = toUpper(name[i]);
    }

    if (dot_pos) |dp| {
        const ext_start = dp + 1;
        const ext_len = if (name.len - ext_start > 3) 3 else name.len - ext_start;
        for (0..ext_len) |i| {
            result[8 + i] = toUpper(name[ext_start + i]);
        }
    }

    return result;
}

fn toUpper(c: u8) u8 {
    if (c >= 'a' and c <= 'z') return c - 32;
    return c;
}

fn fat83Equal(a: [11]u8, b: [11]u8) bool {
    for (0..11) |i| {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// --- Long File Name (LFN) support ---

/// Extract characters from a VFAT LFN directory entry (raw 32 bytes).
/// Each LFN entry stores up to 13 UCS-2 characters at fixed offsets.
/// Returns the number of ASCII chars extracted.
fn extractLFNChars(raw: *const [32]u8, out: []u8) usize {
    // LFN character offsets within the 32-byte entry (UCS-2 little-endian):
    // name1: bytes 1,3,5,7,9 (5 chars)
    // name2: bytes 14,16,18,20,22,24 (6 chars)
    // name3: bytes 28,30 (2 chars)
    const offsets = [13]u8{ 1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30 };
    var count: usize = 0;
    for (offsets) |off| {
        if (count >= out.len) break;
        const lo = raw[off];
        const hi = raw[off + 1];
        if (lo == 0x00 and hi == 0x00) break; // null terminator
        if (lo == 0xFF and hi == 0xFF) break; // padding
        // Convert UCS-2 to ASCII (drop high byte for basic Latin)
        out[count] = if (hi == 0) lo else '?';
        count += 1;
    }
    return count;
}

/// Accumulator for assembling long filenames from LFN entries.
const LFNAccum = struct {
    buf: [MAX_LFN_LEN]u8 = undefined,
    len: usize = 0,
    active: bool = false,

    fn reset(self: *LFNAccum) void {
        self.len = 0;
        self.active = false;
    }

    /// Add an LFN entry. Entries arrive in reverse order (highest sequence first).
    fn addEntry(self: *LFNAccum, raw: *const [32]u8) void {
        const seq = raw[0] & LFN_SEQ_MASK;
        if (seq == 0 or seq > 20) {
            self.reset();
            return;
        }
        if (raw[0] & LFN_LAST_ENTRY != 0) {
            // First LFN entry we see (highest sequence number)
            self.len = 0;
            self.active = true;
        }
        if (!self.active) return;

        // Position in the assembled name: (seq-1) * 13
        const pos = (@as(usize, seq) - 1) * 13;
        var tmp: [13]u8 = undefined;
        const n = extractLFNChars(raw, &tmp);
        for (0..n) |j| {
            if (pos + j < MAX_LFN_LEN) {
                self.buf[pos + j] = tmp[j];
                if (pos + j + 1 > self.len) self.len = pos + j + 1;
            }
        }
    }

    fn name(self: *const LFNAccum) []const u8 {
        return self.buf[0..self.len];
    }
};

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (toUpper(ca) != toUpper(cb)) return false;
    }
    return true;
}

// === Directory walking ===
//
// FAT32 was originally root-only — every public function scanned root_cluster
// directly. The helpers below let arbitrary `foo/bar/baz` paths resolve by
// walking down through ATTR_DIRECTORY entries. They factor out the LFN scan
// loop that used to be duplicated in openFile/createFile/deleteFile/etc.

/// Where in a directory cluster chain a particular entry lives. `dir_index`
/// is the start of the LFN sequence (or the 8.3 entry itself if no LFN);
/// `short_index` is always the 8.3 entry. Both are needed by deleteFile to
/// blank out all the LFN fragments alongside the main entry.
pub const DirLocation = struct {
    dir_cluster: u32,
    dir_index: u32,
    short_index: u32,
    entry: DirEntry,
};

/// Search a single directory chain for `name` (case-insensitive, LFN-aware).
fn findInDir(dir_cluster: u32, name: []const u8) ?DirLocation {
    const fat_name = toFAT83(name);
    var lfn = LFNAccum{};
    var lfn_start: u32 = 0;

    for (0..4096) |i| {
        const raw = readDirEntryRaw(dir_cluster, @intCast(i)) orelse return null;
        if (raw[0] == 0) return null;
        if (raw[0] == 0xE5) {
            lfn.reset();
            continue;
        }

        if (raw[11] & ATTR_LONG_NAME == ATTR_LONG_NAME) {
            if (!lfn.active) lfn_start = @intCast(i);
            lfn.addEntry(&raw);
            continue;
        }

        const entry: *const DirEntry = @ptrCast(@alignCast(&raw));
        if (entry.attr & ATTR_VOLUME_ID != 0) {
            lfn.reset();
            continue;
        }

        const matched = (lfn.active and eqlIgnoreCase(lfn.name(), name)) or
            fat83Equal(entry.name, fat_name);

        if (matched) {
            return .{
                .dir_cluster = dir_cluster,
                .dir_index = if (lfn.active) lfn_start else @intCast(i),
                .short_index = @intCast(i),
                .entry = entry.*,
            };
        }
        lfn.reset();
    }
    return null;
}

/// Find the first deleted-or-end-of-list slot in `dir_cluster`. If the
/// existing cluster chain is full (readDirEntryRaw returns null at some
/// index), allocate a new cluster, link it onto the chain, zero it, and
/// return that index — the caller can then write into slot 0 of the new
/// cluster transparently. Returns null only on PMM exhaustion or after
/// the hard 4096-entry scan ceiling.
fn findFreeSlotInDir(dir_cluster: u32) ?u32 {
    var i: u32 = 0;
    while (i < 4096) : (i += 1) {
        if (readDirEntryRaw(dir_cluster, i)) |raw| {
            if (raw[0] == 0 or raw[0] == 0xE5) return i;
        } else {
            // Chain exhausted at index i. Extend it and the same i now
            // maps to slot 0 of the freshly-zeroed cluster.
            return extendDirChain(dir_cluster, i);
        }
    }
    return null;
}

/// Append a fresh, zeroed cluster onto the end of the directory cluster
/// chain rooted at `dir_cluster`, then return `target_index`. The index
/// must be the next-after-last entry in the existing chain, so that the
/// caller's subsequent writeDirEntry to (dir_cluster, target_index)
/// resolves into the new cluster.
fn extendDirChain(dir_cluster: u32, target_index: u32) ?u32 {
    var cluster = dir_cluster;
    while (true) {
        const next = readFATEntry(cluster);
        if (isEOC(next) or next < 2) break;
        cluster = next;
    }
    const new_cluster = allocCluster() orelse return null;
    writeFATEntry(cluster, new_cluster);
    writeFATEntry(new_cluster, FAT32_EOC);
    flushFATCache();

    const lba = clusterToLBA(new_cluster);
    var zero_buf: [SECTOR_SIZE]u8 = [_]u8{0} ** SECTOR_SIZE;
    for (0..sectors_per_cluster) |s| {
        writeDiskSector(lba + @as(u32, @intCast(s)), &zero_buf);
    }
    return target_index;
}

/// Walk `path` (slash-separated, no leading '/', trailing '/' tolerated)
/// down from root_cluster. Returns the location of the final component.
/// Empty path returns null — callers special-case "root" themselves.
pub fn walkPath(path: []const u8) ?DirLocation {
    if (!initialized) return null;
    var p = path;
    if (p.len > 0 and p[p.len - 1] == '/') p = p[0 .. p.len - 1];
    if (p.len == 0) return null;

    var cur_cluster = root_cluster;
    var rest = p;
    while (true) {
        const slash = std.mem.indexOfScalar(u8, rest, '/');
        const comp = if (slash) |s| rest[0..s] else rest;
        if (comp.len == 0) return null;

        const loc = findInDir(cur_cluster, comp) orelse return null;
        if (slash == null) return loc;

        if (loc.entry.attr & ATTR_DIRECTORY == 0) return null;
        cur_cluster = getEntryCluster(loc.entry);
        rest = rest[slash.? + 1 ..];
    }
}

/// Like walkPath but stops one component short. Used by mutating ops
/// that need to write into the parent directory.
pub const ParentLookup = struct {
    parent_cluster: u32,
    name: []const u8,
};

pub fn walkParent(path: []const u8) ?ParentLookup {
    if (!initialized) return null;
    var p = path;
    if (p.len > 0 and p[p.len - 1] == '/') p = p[0 .. p.len - 1];
    if (p.len == 0) return null;

    if (std.mem.lastIndexOfScalar(u8, p, '/')) |last| {
        const parent_path = p[0..last];
        const name = p[last + 1 ..];
        if (name.len == 0) return null;
        if (parent_path.len == 0) {
            return .{ .parent_cluster = root_cluster, .name = name };
        }
        const par_loc = walkPath(parent_path) orelse return null;
        if (par_loc.entry.attr & ATTR_DIRECTORY == 0) return null;
        return .{ .parent_cluster = getEntryCluster(par_loc.entry), .name = name };
    }
    return .{ .parent_cluster = root_cluster, .name = p };
}

/// Resolve a path to the cluster of the directory it names. Used by
/// readdir to locate the directory whose contents to list.
///   "" or "/" → root_cluster
///   "foo/"    → foo's cluster (must have ATTR_DIRECTORY)
///   "foo/bar" → bar's cluster (must have ATTR_DIRECTORY)
pub fn resolveDirCluster(path: []const u8) ?u32 {
    if (!initialized) return null;
    var p = path;
    if (p.len > 0 and p[p.len - 1] == '/') p = p[0 .. p.len - 1];
    if (p.len == 0) return root_cluster;

    const loc = walkPath(p) orelse return null;
    if (loc.entry.attr & ATTR_DIRECTORY == 0) return null;
    return getEntryCluster(loc.entry);
}

// === Public API ===

/// Open a file by path. Supports both 8.3 and VFAT long filenames, and
/// nested directories like `foo/bar/baz.txt`. Refuses to open a directory.
///
/// Path-cached: a hit lets us skip the entire `walkPath` (root → leaf
/// directory traversal, multiple disk reads). Cache is invalidated on
/// every mutating op (createFile/writeFile/deleteFile/renameFile/
/// createDirectory/removeDirectory) since fat32 caches file_size +
/// first_cluster + dir_index, all of which can change under those.
pub fn openFile(path: []const u8) ?Handle {
    if (path_cache.lookupFat32(path)) |hit| {
        return Handle{
            .dir_cluster = hit.dir_cluster,
            .dir_index = hit.dir_index,
            .first_cluster = hit.first_cluster,
            .file_size = hit.file_size,
            .current_offset = 0,
        };
    }
    const loc = walkPath(path) orelse return null;
    if (loc.entry.attr & ATTR_DIRECTORY != 0) return null;
    const first_cluster = getEntryCluster(loc.entry);
    path_cache.insertFat32(path, .{
        .dir_cluster = loc.dir_cluster,
        .dir_index = loc.short_index,
        .first_cluster = first_cluster,
        .file_size = loc.entry.file_size,
    });
    return Handle{
        .dir_cluster = loc.dir_cluster,
        .dir_index = loc.short_index,
        .first_cluster = first_cluster,
        .file_size = loc.entry.file_size,
        .current_offset = 0,
    };
}

/// Read from a file with cluster caching for sequential reads.
pub fn readFileAt(handle: Handle, buf: [*]u8, count: u32, cached_cluster: u32, cached_off: u32, out_cluster: *u32, out_off: *u32) usize {
    if (!initialized) return 0;
    if (handle.current_offset >= handle.file_size) return 0;

    const bytes_left = handle.file_size - handle.current_offset;
    const to_read = if (count > bytes_left) bytes_left else count;
    if (to_read == 0) return 0;

    var bytes_read: u32 = 0;
    var cluster: u32 = undefined;
    var offset: u32 = undefined;
    const cluster_size = sectors_per_cluster * SECTOR_SIZE;

    if (cached_cluster >= 2 and cached_off <= handle.current_offset) {
        cluster = cached_cluster;
        offset = handle.current_offset - cached_off;
    } else {
        cluster = handle.first_cluster;
        offset = handle.current_offset;
    }

    var cluster_base = handle.current_offset - offset;

    while (offset >= cluster_size) {
        if (isEOC(cluster) or cluster < 2) return 0;
        cluster = readFATEntry(cluster);
        offset -= cluster_size;
        cluster_base += cluster_size;
    }

    var sector_buf: [SECTOR_SIZE]u8 = undefined;
    while (bytes_read < to_read) {
        if (isEOC(cluster) or cluster < 2) break;

        const lba = clusterToLBA(cluster);
        const byte_in_sector = offset % SECTOR_SIZE;

        // Fast path: aligned bulk read across one or more physically-contiguous
        // clusters. We walk the FAT chain (cache-resident) to detect runs of
        // adjacent clusters and issue ONE underlying disk command per run, up
        // to the u8 sector-count ceiling that readSectorsSecondary takes.
        // For non-fragmented files this collapses N per-cluster commands into
        // one — same magnitude of win as the NVMe 8-sector batching that took
        // app loads from 13s → 1.77s.
        if (byte_in_sector == 0 and offset == 0 and to_read - bytes_read >= cluster_size) {
            const max_clusters_per_batch: u32 = @max(1, 255 / sectors_per_cluster);
            var run_clusters: u32 = 1;
            var run_tail = cluster;
            while (run_clusters < max_clusters_per_batch and
                (run_clusters + 1) * cluster_size <= to_read - bytes_read)
            {
                const next = readFATEntry(run_tail);
                if (isEOC(next) or next != run_tail + 1) break;
                run_tail = next;
                run_clusters += 1;
            }

            const total_sectors: u8 = @intCast(run_clusters * sectors_per_cluster);
            ata.readSectorsSecondary(lba, total_sectors, buf + bytes_read);
            bytes_read += run_clusters * cluster_size;
            cluster = readFATEntry(run_tail);
            cluster_base += run_clusters * cluster_size;
            continue;
        }

        const sector_in_cluster = offset / SECTOR_SIZE;
        readDiskSector(lba + sector_in_cluster, &sector_buf);

        const available = SECTOR_SIZE - byte_in_sector;
        const remaining = to_read - bytes_read;
        const chunk = if (available < remaining) available else remaining;

        @memcpy(buf[bytes_read..][0..chunk], sector_buf[byte_in_sector..][0..chunk]);
        bytes_read += chunk;
        offset += chunk;

        if (offset >= cluster_size) {
            cluster = readFATEntry(cluster);
            offset = 0;
            cluster_base += cluster_size;
        }
    }

    out_cluster.* = cluster;
    out_off.* = cluster_base;
    return bytes_read;
}

pub fn readFile(handle: Handle, buf: [*]u8, count: u32) usize {
    var c: u32 = 0;
    var o: u32 = 0;
    return readFileAt(handle, buf, count, 0, 0, &c, &o);
}

/// Create a new file. Returns handle or null.
pub fn createFile(path: []const u8) ?Handle {
    if (!initialized) return null;
    path_cache.invalidateAll();
    _ = deleteFile(path);

    const par = walkParent(path) orelse return null;
    const idx = findFreeSlotInDir(par.parent_cluster) orelse return null;

    const cluster = allocCluster() orelse return null;
    writeFATEntry(cluster, 0x0FFFFFFF);
    flushFATCache();

    var new_entry: DirEntry = undefined;
    new_entry.name = toFAT83(par.name);
    new_entry.attr = ATTR_ARCHIVE;
    new_entry.nt_res = 0;
    new_entry.crt_time_tenth = 0;
    new_entry.crt_time = 0;
    new_entry.crt_date = 0;
    new_entry.lst_acc_date = 0;
    new_entry.fst_clus_hi = @truncate(cluster >> 16);
    new_entry.wrt_time = 0;
    new_entry.wrt_date = 0;
    new_entry.fst_clus_lo = @truncate(cluster);
    new_entry.file_size = 0;
    writeDirEntry(par.parent_cluster, idx, new_entry);

    return Handle{
        .dir_cluster = par.parent_cluster,
        .dir_index = idx,
        .first_cluster = cluster,
        .file_size = 0,
        .current_offset = 0,
    };
}

/// Write data to a file handle. Returns bytes written.
pub fn writeFile(handle: *Handle, buf: [*]const u8, count: u32) usize {
    if (!initialized) return 0;
    if (count == 0) return 0;
    path_cache.invalidateAll();

    var bytes_written: u32 = 0;
    var cluster = handle.first_cluster;
    var offset = handle.current_offset;
    const cluster_size = sectors_per_cluster * SECTOR_SIZE;

    while (offset >= cluster_size) {
        const next = readFATEntry(cluster);
        if (isEOC(next) or next < 2) {
            const new_cluster = allocCluster() orelse return bytes_written;
            writeFATEntry(cluster, new_cluster);
            writeFATEntry(new_cluster, 0x0FFFFFFF);
            flushFATCache();
            cluster = new_cluster;
        } else {
            cluster = next;
        }
        offset -= cluster_size;
    }

    var sector_buf: [SECTOR_SIZE]u8 = undefined;
    while (bytes_written < count) {
        if (cluster < 2) break;

        const lba = clusterToLBA(cluster);
        const sector_in_cluster = offset / SECTOR_SIZE;
        const byte_in_sector = offset % SECTOR_SIZE;

        readDiskSector(lba + sector_in_cluster, &sector_buf);

        const available = SECTOR_SIZE - byte_in_sector;
        const remaining = count - bytes_written;
        const chunk = if (available < remaining) available else remaining;

        @memcpy(sector_buf[byte_in_sector..][0..chunk], buf[bytes_written..][0..chunk]);
        writeDiskSector(lba + sector_in_cluster, &sector_buf);

        bytes_written += chunk;
        offset += chunk;

        if (offset >= cluster_size) {
            const next = readFATEntry(cluster);
            if (isEOC(next) or next < 2) {
                if (bytes_written < count) {
                    const new_cluster = allocCluster() orelse break;
                    writeFATEntry(cluster, new_cluster);
                    writeFATEntry(new_cluster, 0x0FFFFFFF);
                    flushFATCache();
                    cluster = new_cluster;
                }
            } else {
                cluster = next;
            }
            offset = 0;
        }
    }

    handle.current_offset += bytes_written;
    if (handle.current_offset > handle.file_size) {
        handle.file_size = handle.current_offset;
    }
    updateDirEntrySize(handle.dir_cluster, handle.dir_index, handle.file_size);
    flushFATCache();

    return bytes_written;
}

/// Close a file handle, flush FAT.
pub fn closeFile(handle: Handle) void {
    _ = handle;
    flushFATCache();
}

/// List all files in root directory.
pub fn listFiles() void {
    if (!initialized) {
        vga.fg = .LightRed;
        vga.print("FAT32 not initialized\n", .{});
        vga.fg = .LightGray;
        return;
    }

    vga.fg = .Yellow;
    vga.print("FAT32 Files:\n", .{});
    vga.fg = .LightGray;

    var count: u32 = 0;
    var lfn = LFNAccum{};
    for (0..4096) |i| {
        const raw = readDirEntryRaw(root_cluster, @intCast(i)) orelse break;
        if (raw[0] == 0) break;
        if (raw[0] == 0xE5) { lfn.reset(); continue; }

        if (raw[11] & ATTR_LONG_NAME == ATTR_LONG_NAME) {
            lfn.addEntry(&raw);
            continue;
        }

        const entry: *const DirEntry = @ptrCast(@alignCast(&raw));
        if (entry.attr & ATTR_VOLUME_ID != 0) { lfn.reset(); continue; }

        // Use LFN if available, otherwise format 8.3
        if (lfn.active and lfn.len > 0) {
            const type_str: []const u8 = if (entry.attr & ATTR_DIRECTORY != 0) "<DIR>" else "     ";
            vga.print(" {s} {s} {d} bytes\n", .{ lfn.name(), type_str, entry.file_size });
        } else {
            var display_name: [12]u8 = [_]u8{' '} ** 12;
            var pos: usize = 0;
            var base_len: usize = 8;
            while (base_len > 0 and entry.name[base_len - 1] == ' ') base_len -= 1;
            for (0..base_len) |j| {
                display_name[pos] = entry.name[j];
                pos += 1;
            }
            var ext_len: usize = 3;
            while (ext_len > 0 and entry.name[8 + ext_len - 1] == ' ') ext_len -= 1;
            if (ext_len > 0) {
                display_name[pos] = '.';
                pos += 1;
                for (0..ext_len) |j| {
                    display_name[pos] = entry.name[8 + j];
                    pos += 1;
                }
            }
            const type_str: []const u8 = if (entry.attr & ATTR_DIRECTORY != 0) "<DIR>" else "     ";
            vga.print(" {s} {s} {d} bytes\n", .{ display_name[0..pos], type_str, entry.file_size });
        }
        count += 1;
        lfn.reset();
    }
    if (count == 0) {
        vga.print(" (empty)\n", .{});
    }
}

/// Find a free cluster in the FAT.
fn allocCluster() ?u32 {
    var c: u32 = 2;
    while (c < total_clusters) : (c += 1) {
        if (readFATEntry(c) == FAT32_FREE) {
            return c;
        }
    }
    return null;
}

fn updateDirEntrySize(dir_cluster: u32, dir_index: u32, new_size: u32) void {
    var entry = readDirEntry(dir_cluster, dir_index) orelse return;
    entry.file_size = new_size;
    writeDirEntry(dir_cluster, dir_index, entry);
}

/// Helper for the VFS layer: read first cluster + file size from the
/// directory entry at (dir_cluster, dir_index). Pass `dir_cluster=0` to
/// fall back to root (for fds opened before subdir support landed and
/// for the legacy callers that still hardcode root).
pub fn getFirstClusterAt(dir_cluster: u32, dir_index: u32) u32 {
    const dc = if (dir_cluster == 0) root_cluster else dir_cluster;
    const entry = readDirEntry(dc, dir_index) orelse return 0;
    return getEntryCluster(entry);
}

pub fn getFileSizeAt(dir_cluster: u32, dir_index: u32) u32 {
    const dc = if (dir_cluster == 0) root_cluster else dir_cluster;
    const entry = readDirEntry(dc, dir_index) orelse return 0;
    return entry.file_size;
}

/// Back-compat shims — keep old call sites compiling. New code should
/// use the explicit `*At` variants and the FdEntry's fat_dir_cluster.
pub fn getFirstCluster(dir_index: u16) u32 {
    return getFirstClusterAt(0, dir_index);
}

pub fn getFileSize(dir_index: u16) u32 {
    return getFileSizeAt(0, dir_index);
}

/// Free a cluster chain starting from the given cluster.
fn freeClusterChain(start_cluster: u32) void {
    if (start_cluster < 2 or isEOC(start_cluster)) return;

    var cluster = start_cluster;
    while (cluster >= 2 and !isEOC(cluster)) {
        const next = readFATEntry(cluster);
        writeFATEntry(cluster, FAT32_FREE);
        cluster = next;
    }
    flushFATCache();
}

/// Delete a file at `path` by marking its dirent (and any LFN entries
/// that precede it) deleted, then freeing the data cluster chain.
pub fn deleteFile(path: []const u8) bool {
    if (!initialized) return false;
    path_cache.invalidateAll();
    const par = walkParent(path) orelse return false;
    const loc = findInDir(par.parent_cluster, par.name) orelse return false;
    if (loc.entry.attr & ATTR_DIRECTORY != 0) return false;

    const first_cluster = getEntryCluster(loc.entry);
    if (first_cluster >= 2) freeClusterChain(first_cluster);

    // Wipe LFN fragments and the 8.3 entry by stamping 0xE5 on byte 0.
    var i = loc.dir_index;
    while (i <= loc.short_index) : (i += 1) {
        var raw = readDirEntryRaw(par.parent_cluster, i) orelse break;
        raw[0] = 0xE5;
        writeDirEntryRaw(par.parent_cluster, i, raw);
    }
    return true;
}

/// Write raw 32 bytes to a directory entry.
fn writeDirEntryRaw(dir_cluster: u32, index: u32, raw: [32]u8) void {
    const entries_per_cluster = sectors_per_cluster * SECTOR_SIZE / DIR_ENTRY_SIZE;

    var cluster = dir_cluster;
    var remaining = index;

    while (remaining >= entries_per_cluster) {
        if (isEOC(cluster) or cluster < 2) return;
        cluster = readFATEntry(cluster);
        remaining -= entries_per_cluster;
    }

    if (isEOC(cluster) or cluster < 2) return;

    const entries_per_sector = SECTOR_SIZE / DIR_ENTRY_SIZE;
    const sector_in_cluster = remaining / entries_per_sector;
    const offset = (remaining % entries_per_sector) * DIR_ENTRY_SIZE;

    ensureDirCached(cluster, sector_in_cluster);

    const cache_sector = sector_in_cluster - cached_dir_sector;
    const cache_offset = cache_sector * SECTOR_SIZE + offset;
    const sector_idx: u2 = @truncate(cache_sector);

    @memcpy(dir_cache[cache_offset..][0..32], &raw);

    dir_cache_dirty = true;
    dir_cache_dirty_mask |= @as(u8, 1) << sector_idx;
}

/// Get file statistics for a file in FAT32. Path is resolved through
/// walkPath so subdirectory paths like `foo/bar/baz.txt` work.
pub fn getFileStat(path: []const u8, stat_buf: *anyopaque) bool {
    const FileStat = extern struct {
        file_size: u32,
        is_directory: u32,
        create_time: u32,
        modify_time: u32,
    };

    const stat: *FileStat = @ptrCast(@alignCast(stat_buf));
    if (!initialized) return false;

    // Trailing-slash form (`foo/`) — caller is asking about a directory.
    var p = path;
    if (p.len > 0 and p[p.len - 1] == '/') p = p[0 .. p.len - 1];
    if (p.len == 0) {
        // Path is "/" or empty — describe the root directory.
        stat.* = .{ .file_size = 0, .is_directory = 1, .create_time = 0, .modify_time = 0 };
        return true;
    }

    const loc = walkPath(p) orelse return false;
    const entry = loc.entry;

    stat.file_size = entry.file_size;
    stat.is_directory = if (entry.attr & ATTR_DIRECTORY != 0) 1 else 0;

    // FAT timestamps: date bits = year-1980, month, day; time bits = hour, min, sec/2.
    // Pack a display-friendly value (year/month/day/hour); not real Unix time.
    const date = entry.crt_date;
    const time = entry.crt_time;
    const year: u32 = 1980 + (date >> 9);
    const month: u32 = (date >> 5) & 0xF;
    const day: u32 = date & 0x1F;
    const hour: u32 = time >> 11;
    stat.create_time = (year << 16) | (month << 12) | (day << 7) | hour;

    const wrt_date = entry.wrt_date;
    const wrt_time = entry.wrt_time;
    const wrt_year: u32 = 1980 + (wrt_date >> 9);
    const wrt_month: u32 = (wrt_date >> 5) & 0xF;
    const wrt_day: u32 = wrt_date & 0x1F;
    const wrt_hour: u32 = wrt_time >> 11;
    stat.modify_time = (wrt_year << 16) | (wrt_month << 12) | (wrt_day << 7) | wrt_hour;
    return true;
}

/// Rename a file. Both `old_path` and `new_path` must resolve to the same
/// parent directory — moving across directories isn't implemented yet.
/// Only the 8.3 short name is updated; LFN fragments are left alone, so a
/// file with a long name will keep that long name displayed (rename only
/// affects the canonical short name).
pub fn renameFile(old_path: []const u8, new_path: []const u8) bool {
    if (!initialized) return false;
    path_cache.invalidateAll();

    const old_par = walkParent(old_path) orelse return false;
    const new_par = walkParent(new_path) orelse return false;
    if (old_par.parent_cluster != new_par.parent_cluster) return false;

    const loc = findInDir(old_par.parent_cluster, old_par.name) orelse return false;
    var entry = loc.entry;
    entry.name = toFAT83(new_par.name);
    writeDirEntry(loc.dir_cluster, loc.short_index, entry);
    return true;
}

/// Create a directory at `path`. The parent must already exist (no -p
/// behavior). Refuses if anything already lives at that path.
pub fn createDirectory(path: []const u8) bool {
    if (!initialized) return false;
    path_cache.invalidateAll();
    const par = walkParent(path) orelse return false;
    if (findInDir(par.parent_cluster, par.name) != null) return false;

    // Allocate a cluster for the new directory and zero it.
    const dir_cluster = allocCluster() orelse return false;
    writeFATEntry(dir_cluster, FAT32_EOC);
    flushFATCache();

    const lba = clusterToLBA(dir_cluster);
    var zero_buf: [SECTOR_SIZE]u8 = [_]u8{0} ** SECTOR_SIZE;
    for (0..sectors_per_cluster) |i| {
        writeDiskSector(lba + @as(u32, @intCast(i)), &zero_buf);
    }

    // `.` → self
    var dot_entry: DirEntry = std.mem.zeroes(DirEntry);
    @memcpy(dot_entry.name[0..11], ".          ");
    dot_entry.attr = ATTR_DIRECTORY;
    dot_entry.fst_clus_lo = @truncate(dir_cluster);
    dot_entry.fst_clus_hi = @truncate(dir_cluster >> 16);
    writeDirEntry(dir_cluster, 0, dot_entry);

    // `..` → parent (root_cluster IS allowed even though FAT32 spec wants
    // 0 for parent==root; readers we care about treat both consistently).
    var dotdot_entry: DirEntry = std.mem.zeroes(DirEntry);
    @memcpy(dotdot_entry.name[0..11], "..         ");
    dotdot_entry.attr = ATTR_DIRECTORY;
    dotdot_entry.fst_clus_lo = @truncate(par.parent_cluster);
    dotdot_entry.fst_clus_hi = @truncate(par.parent_cluster >> 16);
    writeDirEntry(dir_cluster, 1, dotdot_entry);

    // Stitch the new dirent into the parent.
    const free_index = findFreeSlotInDir(par.parent_cluster) orelse {
        writeFATEntry(dir_cluster, FAT32_FREE);
        flushFATCache();
        return false;
    };

    var new_entry: DirEntry = std.mem.zeroes(DirEntry);
    new_entry.name = toFAT83(par.name);
    new_entry.attr = ATTR_DIRECTORY;
    new_entry.fst_clus_lo = @truncate(dir_cluster);
    new_entry.fst_clus_hi = @truncate(dir_cluster >> 16);
    new_entry.file_size = 0;
    writeDirEntry(par.parent_cluster, free_index, new_entry);
    return true;
}

/// Remove an empty directory at `path`. Refuses if it isn't a directory
/// or contains anything beyond `.` / `..`.
pub fn removeDirectory(path: []const u8) bool {
    if (!initialized) return false;
    path_cache.invalidateAll();
    const par = walkParent(path) orelse return false;
    const loc = findInDir(par.parent_cluster, par.name) orelse return false;
    if (loc.entry.attr & ATTR_DIRECTORY == 0) return false;

    const dir_cluster = getEntryCluster(loc.entry);

    // Empty? Skip `.` (".          ") and `..` ("..         ") and any deleted slots.
    for (0..4096) |i| {
        const raw = readDirEntryRaw(dir_cluster, @intCast(i)) orelse break;
        if (raw[0] == 0) break;
        if (raw[0] == 0xE5) continue;
        const entry: *const DirEntry = @ptrCast(@alignCast(&raw));
        if (entry.name[0] == '.' and (entry.name[1] == ' ' or entry.name[1] == '.')) continue;
        return false;
    }

    if (dir_cluster >= 2) freeClusterChain(dir_cluster);

    // Wipe the dirent (and any LFN fragments preceding it).
    var i = loc.dir_index;
    while (i <= loc.short_index) : (i += 1) {
        var raw = readDirEntryRaw(par.parent_cluster, i) orelse break;
        raw[0] = 0xE5;
        writeDirEntryRaw(par.parent_cluster, i, raw);
    }
    return true;
}
