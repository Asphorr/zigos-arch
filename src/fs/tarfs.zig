const std = @import("std");
const ata = @import("../driver/block.zig");
const vga = @import("../ui/vga.zig");
const debug = @import("../debug/debug.zig");

pub fn parseOctal(bytes: []const u8) usize {
    var res: usize = 0;
    for (bytes) |b| {
        if (b >= '0' and b <= '7') res = res * 8 + (b - '0') else break;
    }
    return res;
}

// --- In-memory TAR index (built once at boot) ---

const MAX_INDEX_ENTRIES = 128;

const IndexEntry = struct {
    name: [100]u8 = [_]u8{0} ** 100,
    name_len: u8 = 0,
    data_lba: u32 = 0,
    file_size: u32 = 0,
};

var index: [MAX_INDEX_ENTRIES]IndexEntry = [_]IndexEntry{.{}} ** MAX_INDEX_ENTRIES;
var index_count: u32 = 0;
var indexed: bool = false;

/// Build the TAR index at boot. Scans disk once, caches all file metadata.
pub fn buildIndex() void {
    var lba: u32 = 0;
    var buf: [512]u8 = undefined;
    index_count = 0;

    while (lba < 65536 and index_count < MAX_INDEX_ENTRIES) {
        ata.readSector(lba, &buf);
        if (buf[0] == 0) break;

        const name_len = std.mem.indexOfScalar(u8, buf[0..100], 0) orelse 100;
        const size = parseOctal(buf[124..136]);
        const sectors: u32 = @intCast((size + 511) / 512);

        var entry = &index[index_count];
        @memcpy(entry.name[0..name_len], buf[0..name_len]);
        entry.name_len = @intCast(name_len);
        entry.data_lba = lba + 1;
        entry.file_size = @intCast(size);
        index_count += 1;

        lba += 1 + sectors;
    }

    indexed = true;
    debug.klog("[tarfs] Indexed {d} files\n", .{index_count});

    // Sort index by filename for binary search
    sortIndex();
}

/// Sort index entries by filename (insertion sort - small N)
fn sortIndex() void {
    if (index_count <= 1) return;

    for (1..index_count) |i| {
        const key = index[i];
        var j: i32 = @as(i32, @intCast(i)) - 1;

        while (j >= 0) {
            const cmp = compareNames(index[@intCast(j)].name[0..index[@intCast(j)].name_len], key.name[0..key.name_len]);
            if (cmp <= 0) break;
            index[@intCast(j + 1)] = index[@intCast(j)];
            j -= 1;
        }
        index[@intCast(j + 1)] = key;
    }
}

/// Compare two filenames lexicographically
fn compareNames(a: []const u8, b: []const u8) i32 {
    const min_len = @min(a.len, b.len);
    for (0..min_len) |i| {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    if (a.len < b.len) return -1;
    if (a.len > b.len) return 1;
    return 0;
}

/// Find a file in the index. O(log N) binary search over cached entries, no disk I/O.
fn findInIndex(name: []const u8) ?*const IndexEntry {
    if (index_count == 0) return null;

    var left: u32 = 0;
    var right: u32 = index_count;

    while (left < right) {
        const mid = left + (right - left) / 2;
        const entry = &index[mid];
        const cmp = compareNames(entry.name[0..entry.name_len], name);

        if (cmp == 0) {
            return entry;
        } else if (cmp < 0) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    return null;
}

pub fn ls() void {
    vga.fg = .Yellow;
    vga.print("Files on IDE HDD:\n", .{});
    vga.fg = .LightGray;

    if (indexed) {
        for (0..index_count) |i| {
            const entry = &index[i];
            vga.print(" - {s} ({d} bytes)\n", .{ entry.name[0..entry.name_len], entry.file_size });
        }
    } else {
        // Fallback to disk scan if index not built
        var lba: u32 = 0;
        var buf: [512]u8 = undefined;
        while (lba < 8000) {
            ata.readSector(lba, &buf);
            if (buf[0] == 0) break;
            const name_len = std.mem.indexOfScalar(u8, buf[0..100], 0) orelse 100;
            const size = parseOctal(buf[124..136]);
            vga.print(" - {s} ({d} bytes)\n", .{ buf[0..name_len], size });
            lba += 1 + @as(u32, @intCast((size + 511) / 512));
        }
    }
}

// Handle-based API for VFS

pub const Handle = struct {
    data_lba: u32,
    file_size: u32,
    current_offset: u32,
};

var tar_handles: [8]?Handle = [_]?Handle{null} ** 8;

/// O(1) file-size lookup via the prebuilt index. Used by vfs.loadFileFresh
/// to size a PMM allocation before opening the file.
pub fn fileSize(name: []const u8) ?usize {
    if (indexed) {
        const entry = findInIndex(name) orelse return null;
        return entry.file_size;
    }
    return null;
}

pub fn openFile(name: []const u8) ?u16 {
    // Use index for O(1) lookup (no disk I/O)
    if (indexed) {
        const entry = findInIndex(name) orelse return null;
        for (0..8) |i| {
            if (tar_handles[i] == null) {
                tar_handles[i] = .{
                    .data_lba = entry.data_lba,
                    .file_size = entry.file_size,
                    .current_offset = 0,
                };
                return @intCast(i);
            }
        }
        return null; // no free handle
    }

    // Fallback: disk scan (before index is built)
    var lba: u32 = 0;
    var buf: [512]u8 = undefined;
    while (lba < 8000) {
        ata.readSector(lba, &buf);
        if (buf[0] == 0) break;
        const name_len = std.mem.indexOfScalar(u8, buf[0..100], 0) orelse 100;
        const size = parseOctal(buf[124..136]);
        const sectors: u32 = @intCast((size + 511) / 512);
        if (std.mem.eql(u8, buf[0..name_len], name)) {
            for (0..8) |i| {
                if (tar_handles[i] == null) {
                    tar_handles[i] = .{
                        .data_lba = lba + 1,
                        .file_size = @intCast(size),
                        .current_offset = 0,
                    };
                    return @intCast(i);
                }
            }
            return null;
        }
        lba += 1 + sectors;
    }
    return null;
}

pub fn readFile(handle_idx: u16, buf: [*]u8, count: u32) usize {
    if (handle_idx >= 8) return 0;
    var handle = tar_handles[handle_idx] orelse return 0;
    if (handle.current_offset >= handle.file_size) return 0;

    const bytes_left = handle.file_size - handle.current_offset;
    const to_read: u32 = if (count > bytes_left) bytes_left else count;
    if (to_read == 0) return 0;

    var bytes_read: u32 = 0;
    var sector_buf: [512]u8 = undefined;
    while (bytes_read < to_read) {
        const sector_offset = handle.current_offset / 512;
        const byte_in_sector = handle.current_offset % 512;
        ata.readSector(handle.data_lba + sector_offset, &sector_buf);

        const available = 512 - byte_in_sector;
        const remaining = to_read - bytes_read;
        const chunk = if (available < remaining) available else remaining;
        @memcpy(buf[bytes_read..][0..chunk], sector_buf[byte_in_sector..][0..chunk]);
        bytes_read += chunk;
        handle.current_offset += chunk;
    }

    tar_handles[handle_idx] = handle;
    return bytes_read;
}

pub fn closeFile(handle_idx: u16) void {
    if (handle_idx < 8) {
        tar_handles[handle_idx] = null;
    }
}

/// Collect tarfs filenames matching a prefix. Returns number of matches (max 8).
pub fn matchPrefix(prefix: []const u8, names: *[8][32]u8, name_lens: *[8]u8) u8 {
    if (indexed) {
        var count: u8 = 0;
        for (0..index_count) |i| {
            const entry = &index[i];
            const nl = entry.name_len;
            if (nl >= prefix.len and (prefix.len == 0 or std.mem.eql(u8, entry.name[0..prefix.len], prefix))) {
                if (count < 8) {
                    const copy_len = @min(nl, 32);
                    @memcpy(names[count][0..copy_len], entry.name[0..copy_len]);
                    name_lens[count] = @intCast(copy_len);
                    count += 1;
                }
            }
        }
        return count;
    }

    // Fallback: disk scan
    var lba: u32 = 0;
    var buf: [512]u8 = undefined;
    var count: u8 = 0;
    while (lba < 8000) {
        ata.readSector(lba, &buf);
        if (buf[0] == 0) break;
        const name_len = std.mem.indexOfScalar(u8, buf[0..100], 0) orelse 100;
        const size = parseOctal(buf[124..136]);
        const sectors: u32 = @intCast((size + 511) / 512);
        if (name_len >= prefix.len and (prefix.len == 0 or std.mem.eql(u8, buf[0..prefix.len], prefix))) {
            if (count < 8) {
                const copy_len = @min(name_len, 32);
                @memcpy(names[count][0..copy_len], buf[0..copy_len]);
                name_lens[count] = @intCast(copy_len);
                count += 1;
            }
        }
        lba += 1 + sectors;
    }
    return count;
}

pub fn loadFile(filename: []const u8, load_addr: []align(4) u8) ?usize {
    // Use index for instant lookup
    if (indexed) {
        const entry = findInIndex(filename) orelse return null;
        const sectors = (entry.file_size + 511) / 512;
        // Whole-sector reads land directly in load_addr — refuse if the
        // rounded-up size wouldn't fit (the caller's buffer is the bound).
        if (@as(u64, sectors) * 512 > load_addr.len) return null;
        var s: u32 = 0;
        while (s < sectors) {
            const batch: u8 = @intCast(@min(sectors - s, 128));
            const dest_ptr: [*]u8 = @ptrFromInt(@intFromPtr(load_addr.ptr) + s * 512);
            // Propagate read failure (BUG 2 class): serving the unwritten
            // load_addr bytes as file content is silent corruption.
            if (!ata.readSectors(entry.data_lba + s, batch, dest_ptr)) return null;
            s += batch;
        }
        return entry.file_size;
    }

    // Fallback: disk scan
    var lba: u32 = 0;
    var buf: [512]u8 = undefined;
    while (lba < 8000) {
        ata.readSector(lba, &buf);
        if (buf[0] == 0) return null;
        const name_len = std.mem.indexOfScalar(u8, buf[0..100], 0) orelse 100;
        const size = parseOctal(buf[124..136]);
        const sectors = @as(u32, @intCast((size + 511) / 512));
        if (std.mem.eql(u8, buf[0..name_len], filename)) {
            if (@as(u64, sectors) * 512 > load_addr.len) return null;
            var s: u32 = 0;
            while (s < sectors) {
                const batch: u8 = @intCast(@min(sectors - s, 128));
                const dest_ptr: [*]u8 = @ptrFromInt(@intFromPtr(load_addr.ptr) + s * 512);
                if (!ata.readSectors(lba + 1 + s, batch, dest_ptr)) return null;
                s += batch;
            }
            return size;
        }
        lba += 1 + sectors;
    }
    return null;
}

/// List all indexed files into a buffer (for readdir syscall)
pub fn listToBuffer(entries: [*]extern struct {
    name: [32]u8,
    name_len: u8,
    file_size: u32 align(1),
    flags: u8,
    _pad: [10]u8,
}, max_entries: u32) u32 {
    const count = @min(index_count, max_entries);
    for (0..count) |i| {
        const idx_entry = &index[i];
        var entry = &entries[i];
        @memset(&entry.name, 0);
        @memset(&entry._pad, 0);

        const copy_len = @min(idx_entry.name_len, 32);
        @memcpy(entry.name[0..copy_len], idx_entry.name[0..copy_len]);
        entry.name_len = @intCast(copy_len);
        entry.file_size = idx_entry.file_size;
        // Unified flag bits — see lib/libc.zig FE_FLAG_*.
        // tarfs is flat (no dirs) and read-only, so we only set is_elf
        // and from_tarfs (bit 4) for consumer-side filtering.
        var f: u8 = 0x10; // from_tarfs
        if (isElfName(idx_entry.name[0..idx_entry.name_len])) f |= 0x01;
        entry.flags = f;
    }
    return @intCast(count);
}

fn isElfName(name: []const u8) bool {
    return name.len >= 4 and std.mem.eql(u8, name[name.len - 4 ..], ".elf");
}

/// Get file statistics for a file in the tarfs index.
pub fn getFileStat(filename: []const u8, stat_buf: *anyopaque) bool {
    const FileStat = extern struct {
        file_size: u32,
        is_directory: u32,
        create_time: u32,
        modify_time: u32,
    };

    const stat: *FileStat = @ptrCast(@alignCast(stat_buf));

    if (indexed) {
        const entry = findInIndex(filename) orelse return false;
        stat.file_size = entry.file_size;
        stat.is_directory = 0; // tarfs has no directories
        stat.create_time = 0; // tar format doesn't store timestamps in our simple implementation
        stat.modify_time = 0;
        return true;
    }

    return false;
}
