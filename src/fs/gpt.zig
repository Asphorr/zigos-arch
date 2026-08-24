// gpt — GUID Partition Table: read an existing table, or lay down a new one.
//
// UEFI 2.10 §5.3. Until now nothing in the tree could answer "where does a
// filesystem start on this disk": `ext2/block.zig`'s `mount(partition_lba)`
// takes an LBA that every caller passed as 0, meaning "the whole device is one
// bare filesystem". That works for a raw image handed to QEMU and for nothing
// else — a disk the firmware can boot needs a partition table with an EFI
// System Partition in it.
//
// On-disk geometry this module reads and writes (N = disk size in sectors):
//
//   LBA 0                protective MBR — one 0xEE record spanning the disk,
//                        so a legacy tool sees "occupied, unknown" instead of
//                        "empty, please initialize"
//   LBA 1                primary header
//   LBA 2 … 33           primary entry array (128 entries × 128 B = 32 sectors)
//   LBA 34 … N-34        usable space
//   LBA N-33 … N-2       backup entry array
//   LBA N-1              backup header
//
// Both headers and both array copies are written by `create`, and either
// header is accepted by `parse` — a torn write that leaves the primary
// unreadable is recoverable from the tail of the disk, which is the entire
// reason the format is mirrored.
//
// TWO checksums guard the structure and they cover different things: the
// header CRC is computed over `header_size` bytes with the CRC field itself
// zeroed, and the array CRC is computed over the whole declared entry array
// (128 × 128 B) including the empty entries. Getting either wrong produces a
// table that our own parse accepts and every host tool rejects, so both are
// verified on read rather than trusted.

const std = @import("std");

const block = @import("../driver/block.zig");
const crc32 = @import("../util/crc32.zig");
const endian = @import("../util/endian.zig");
const random = @import("../crypto/random.zig");
const fail = @import("../util/fail.zig").fail;

const debug = @import("../debug/debug.zig");

// =============================================================================
// Constants
// =============================================================================

pub const SECTOR_SIZE: u32 = 512;

/// "EFI PART" as a little-endian u64 — the header signature.
const SIGNATURE: u64 = 0x5452415020494645;

/// Revision 1.0 in the spec's packed form (major 1, minor 0).
const REVISION_1_0: u32 = 0x00010000;

/// The spec fixes the header at 92 bytes for revision 1.0. Anything larger is
/// a future revision we refuse rather than half-parse.
const HEADER_BYTES: u32 = 92;

/// Spec minimum reserved space for the entry array: 16 KiB, which at the
/// standard 128-byte entry is 128 entries across 32 sectors. Every real tool
/// assumes exactly this, so we neither shrink it (breaking them) nor grow it.
pub const ENTRY_COUNT: u32 = 128;
pub const ENTRY_BYTES: u32 = 128;
pub const ENTRY_ARRAY_SECTORS: u32 = ENTRY_COUNT * ENTRY_BYTES / SECTOR_SIZE;

/// First LBA a partition may claim: MBR + header + array.
pub const FIRST_USABLE_LBA: u64 = 2 + ENTRY_ARRAY_SECTORS;

/// Partition alignment, in sectors: 1 MiB, the universal convention since
/// Vista/parted 2.1. It exists because flash erase blocks and RAID stripes are
/// far larger than a 512-byte sector — a partition starting at LBA 34 puts
/// every filesystem structure inside it 17 KiB out of phase with the physical
/// erase block, so a single logical write dirties two of them forever after.
/// Costs under a MiB per partition; `sgdisk` reports the alignment it infers,
/// which is how a table that skips this gets noticed.
pub const ALIGN_SECTORS: u64 = 2048;

/// Rounds `lba` up to the next `ALIGN_SECTORS` boundary.
pub fn alignUp(lba: u64) u64 {
    return (lba + ALIGN_SECTORS - 1) / ALIGN_SECTORS * ALIGN_SECTORS;
}

/// Rounds `lba` down so that `lba + 1` lands on an alignment boundary — the
/// right transform for an INCLUSIVE end LBA, so the next partition after it
/// would start aligned.
pub fn alignEndDown(lba: u64) u64 {
    return (lba + 1) / ALIGN_SECTORS * ALIGN_SECTORS - 1;
}

/// Sectors reserved at each end of the disk. A disk smaller than twice this
/// has no usable space at all and is refused up front.
const RESERVED_SECTORS: u64 = FIRST_USABLE_LBA + ENTRY_ARRAY_SECTORS + 1;

/// Entries surfaced by `parse`. The on-disk array holds 128, but a partition
/// count that large is not a shape this kernel has any use for; overflow is
/// reported (see `Table.truncated`) rather than silently dropped.
pub const MAX_PARSED: usize = 8;

/// Partition name length in UTF-16 code units (72 bytes / 2).
const NAME_UTF16_LEN: usize = 36;

/// Largest disk we address. Every block-layer entry point takes a u32 LBA, so
/// a namespace above this cannot be fully addressed and is refused rather than
/// silently truncated at the 2 TiB mark.
const MAX_DISK_SECTORS: u64 = 0xFFFF_FFFF;

// =============================================================================
// Partition type GUIDs
// =============================================================================
//
// GUIDs are stored mixed-endian: the first three fields (u32, u16, u16) are
// little-endian, the trailing two (u16 + 6 bytes) are big-endian. So the
// rendered form C12A7328-F81F-11D2-BA4B-00A0C93EC93B is the byte sequence
// 28 73 2A C1 1F F8 D2 11 BA 4B 00 A0 C9 3E C9 3B. Writing these as literal
// byte arrays rather than parsing a string keeps the conversion in one place —
// here — where it can be checked against the spec by eye.

/// EFI System Partition — C12A7328-F81F-11D2-BA4B-00A0C93EC93B. Firmware
/// looks for this type when hunting for \EFI\BOOT\BOOTX64.EFI.
pub const TYPE_ESP: [16]u8 = .{
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
    0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
};

/// Linux filesystem data — 0FC63DAF-8483-4772-8E79-3D69D8477DE4. The type
/// e2fsck and every Linux tool expects to find an ext2/3/4 volume behind.
pub const TYPE_LINUX_DATA: [16]u8 = .{
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
    0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
};

/// An all-zero type GUID marks an unused entry slot.
const TYPE_UNUSED: [16]u8 = .{0} ** 16;

// =============================================================================
// On-disk structures
// =============================================================================

/// LBA 1 (primary) and LBA N-1 (backup). Only the first 92 bytes are defined;
/// the rest of the containing sector must be zero, and IS included in no
/// checksum — the header CRC covers exactly `header_size` bytes.
const Header = extern struct {
    signature: endian.LE(u64),
    revision: endian.LE(u32),
    header_size: endian.LE(u32),
    /// CRC-32 of the first `header_size` bytes computed with this field set
    /// to zero. Self-referential, so it must be zeroed before computing and
    /// filled in afterwards — the single most common way to get GPT wrong.
    header_crc32: endian.LE(u32),
    _reserved: endian.LE(u32),
    /// LBA of *this* header. Differs between the primary and backup copies,
    /// which is why the two copies have different CRCs.
    my_lba: endian.LE(u64),
    alternate_lba: endian.LE(u64),
    first_usable_lba: endian.LE(u64),
    /// Inclusive — the last LBA a partition may claim.
    last_usable_lba: endian.LE(u64),
    disk_guid: [16]u8,
    partition_entry_lba: endian.LE(u64),
    num_partition_entries: endian.LE(u32),
    sizeof_partition_entry: endian.LE(u32),
    partition_entry_array_crc32: endian.LE(u32),
};
comptime {
    // UEFI 2.10 Table 5-5. Header is 92 bytes for revision 1.0.
    const a = std.debug.assert;
    a(@sizeOf(Header) == 92);
    a(@offsetOf(Header, "signature") == 0);
    a(@offsetOf(Header, "revision") == 8);
    a(@offsetOf(Header, "header_size") == 12);
    a(@offsetOf(Header, "header_crc32") == 16);
    a(@offsetOf(Header, "my_lba") == 24);
    a(@offsetOf(Header, "alternate_lba") == 32);
    a(@offsetOf(Header, "first_usable_lba") == 40);
    a(@offsetOf(Header, "last_usable_lba") == 48);
    a(@offsetOf(Header, "disk_guid") == 56);
    a(@offsetOf(Header, "partition_entry_lba") == 72);
    a(@offsetOf(Header, "num_partition_entries") == 80);
    a(@offsetOf(Header, "sizeof_partition_entry") == 84);
    a(@offsetOf(Header, "partition_entry_array_crc32") == 88);
    a(@sizeOf(Header) == HEADER_BYTES);
}

/// One 128-byte slot in the entry array.
const Entry = extern struct {
    type_guid: [16]u8,
    unique_guid: [16]u8,
    starting_lba: endian.LE(u64),
    /// Inclusive. A one-sector partition has ending_lba == starting_lba.
    ending_lba: endian.LE(u64),
    attributes: endian.LE(u64),
    /// UTF-16LE, NUL-padded. 36 code units.
    name: [72]u8,
};
comptime {
    // UEFI 2.10 Table 5-6.
    const a = std.debug.assert;
    a(@sizeOf(Entry) == 128);
    a(@offsetOf(Entry, "type_guid") == 0);
    a(@offsetOf(Entry, "unique_guid") == 16);
    a(@offsetOf(Entry, "starting_lba") == 32);
    a(@offsetOf(Entry, "ending_lba") == 40);
    a(@offsetOf(Entry, "attributes") == 48);
    a(@offsetOf(Entry, "name") == 56);
    a(@sizeOf(Entry) == ENTRY_BYTES);
    a(SECTOR_SIZE % ENTRY_BYTES == 0); // entries never straddle a sector
}

/// One of the four 16-byte records at offset 446 of the protective MBR.
const MbrRecord = extern struct {
    boot_indicator: u8,
    starting_chs: [3]u8,
    os_type: u8,
    ending_chs: [3]u8,
    starting_lba: endian.LE(u32),
    size_in_lba: endian.LE(u32),
};
comptime {
    const a = std.debug.assert;
    a(@sizeOf(MbrRecord) == 16);
    a(@offsetOf(MbrRecord, "os_type") == 4);
    a(@offsetOf(MbrRecord, "starting_lba") == 8);
    a(@offsetOf(MbrRecord, "size_in_lba") == 12);
}

/// Partition type of the single protective record: "GPT protective".
const MBR_TYPE_PROTECTIVE: u8 = 0xEE;
const MBR_RECORD_OFFSET: usize = 446;
const MBR_SIGNATURE_OFFSET: usize = 510;

// =============================================================================
// Device
// =============================================================================

/// The block layer owns the device handle type; re-exported here so callers
/// that only talk partitions don't need a second import.
pub const Device = block.Device;

/// The install target disk as a writable Device, or null when no target is
/// attached. Callers report the null case; this module never assumes a
/// target exists.
pub const targetDevice = block.targetDevice;

// =============================================================================
// Parsed view
// =============================================================================

pub const Partition = struct {
    /// Slot index in the on-disk array — a partition's stable identity, and
    /// what tools call "partition number" (1-based when displayed).
    index: u32,
    type_guid: [16]u8,
    unique_guid: [16]u8,
    start_lba: u64,
    /// Inclusive.
    end_lba: u64,
    /// Name transliterated to ASCII, NUL-padded. Non-ASCII code units become
    /// '?' — this is a display convenience, not a round-trip encoding.
    name: [NAME_UTF16_LEN]u8,
    name_len: usize,

    pub fn sectorCount(self: Partition) u64 {
        return self.end_lba - self.start_lba + 1;
    }

    pub fn isEsp(self: Partition) bool {
        return std.mem.eql(u8, &self.type_guid, &TYPE_ESP);
    }
};

pub const Table = struct {
    disk_guid: [16]u8,
    first_usable_lba: u64,
    last_usable_lba: u64,
    /// True when the header CRC matched on the primary; false means the table
    /// was recovered from the backup copy at the end of the disk. Surfaced so
    /// a caller can report the repair rather than silently paper over it.
    from_backup: bool,
    /// True when the disk carries more used entries than `MAX_PARSED`. The
    /// extra partitions are absent from `parts`, not merged into it.
    truncated: bool,
    count: usize,
    parts: [MAX_PARSED]Partition,

    /// First partition of the given type, or null. The lookup the boot path
    /// wants: "which partition is the ESP".
    pub fn findByType(self: *const Table, type_guid: [16]u8) ?Partition {
        for (self.parts[0..self.count]) |p| {
            if (std.mem.eql(u8, &p.type_guid, &type_guid)) return p;
        }
        return null;
    }
};

// =============================================================================
// Creation
// =============================================================================

/// What the caller wants laid down. `end_lba` is inclusive, matching the
/// on-disk field, because converting between inclusive and exclusive at an
/// API boundary is where off-by-one partition overlaps come from.
pub const PartSpec = struct {
    type_guid: [16]u8,
    start_lba: u64,
    end_lba: u64,
    /// ASCII; transliterated to UTF-16LE on write. Truncated at 36 code
    /// units with a warning rather than silently.
    name: []const u8,
};

/// Writes a complete GPT — protective MBR, both headers, both entry array
/// copies — describing `specs`. Every prior content of those sectors is lost.
///
/// Returns false, having logged the reason, if: the device is read-only, the
/// disk is too small or too large to address, or any spec is out of the usable
/// range, inverted, or overlaps another. Validation happens in full BEFORE the
/// first sector is written, so a rejected layout leaves the disk untouched
/// rather than half-partitioned.
///
/// Caller context: process context only. This issues many blocking sector
/// writes and must not run from an IRQ handler or under a spinlock.
pub fn create(dev: Device, specs: []const PartSpec) bool {
    const write = dev.writeSectors orelse {
        debug.klog("[gpt] create: device is read-only\n", .{});
        return false;
    };

    if (dev.sectors > MAX_DISK_SECTORS) {
        debug.klog("[gpt] create: disk {d} sectors exceeds the u32 LBA limit {d}\n", .{ dev.sectors, MAX_DISK_SECTORS });
        return false;
    }
    if (dev.sectors < RESERVED_SECTORS + 1) {
        debug.klog("[gpt] create: disk {d} sectors too small (need > {d})\n", .{ dev.sectors, RESERVED_SECTORS });
        return false;
    }
    if (specs.len > ENTRY_COUNT) {
        debug.klog("[gpt] create: {d} partitions exceeds the {d}-entry array\n", .{ specs.len, ENTRY_COUNT });
        return false;
    }

    const backup_header_lba = dev.sectors - 1;
    const backup_array_lba = backup_header_lba - ENTRY_ARRAY_SECTORS;
    const last_usable = backup_array_lba - 1;

    // Validate every spec before touching the disk.
    for (specs, 0..) |s, i| {
        if (s.end_lba < s.start_lba) {
            debug.klog("[gpt] create: part {d} inverted ({d}..{d})\n", .{ i, s.start_lba, s.end_lba });
            return false;
        }
        if (s.start_lba < FIRST_USABLE_LBA or s.end_lba > last_usable) {
            debug.klog("[gpt] create: part {d} range {d}..{d} outside usable {d}..{d}\n", .{ i, s.start_lba, s.end_lba, FIRST_USABLE_LBA, last_usable });
            return false;
        }
        for (specs[0..i], 0..) |prev, j| {
            if (s.start_lba <= prev.end_lba and prev.start_lba <= s.end_lba) {
                debug.klog("[gpt] create: part {d} ({d}..{d}) overlaps part {d} ({d}..{d})\n", .{ i, s.start_lba, s.end_lba, j, prev.start_lba, prev.end_lba });
                return false;
            }
        }
    }

    var disk_guid: [16]u8 = undefined;
    makeGuid(&disk_guid);

    if (!writeProtectiveMbr(write, dev.sectors)) return false;

    // Entry array: built and written one sector at a time, feeding the rolling
    // CRC as we go. The alternative — materialising all 16 KiB to checksum it
    // — would be the largest single buffer in the kernel outside the block
    // cache, for no gain: the CRC is defined over the byte stream in order,
    // which is exactly the order we emit it.
    var array_crc = crc32.start();
    {
        const per_sector: usize = SECTOR_SIZE / ENTRY_BYTES;
        const entry_bytes: usize = ENTRY_BYTES;
        var sector: usize = 0;
        while (sector < ENTRY_ARRAY_SECTORS) : (sector += 1) {
            var buf: [SECTOR_SIZE]u8 = .{0} ** SECTOR_SIZE;
            var slot: usize = 0;
            while (slot < per_sector) : (slot += 1) {
                const idx = sector * per_sector + slot;
                if (idx >= specs.len) break;
                const e = buildEntry(specs[idx]);
                @memcpy(buf[slot * entry_bytes ..][0..entry_bytes], std.mem.asBytes(&e));
            }
            array_crc = crc32.feed(array_crc, &buf);

            if (!write(@intCast(2 + sector), 1, &buf)) {
                debug.klog("[gpt] create: primary entry array write failed at sector {d}\n", .{sector});
                return false;
            }
            if (!write(@intCast(backup_array_lba + sector), 1, &buf)) {
                debug.klog("[gpt] create: backup entry array write failed at sector {d}\n", .{sector});
                return false;
            }
        }
    }
    const entries_crc = crc32.end(array_crc);

    // Primary header at LBA 1 pointing forward at LBA 2; backup at the last
    // LBA pointing back at its own copy. Everything else is identical, which
    // is why they are built by the same helper.
    if (!writeHeader(write, .{
        .my_lba = 1,
        .alternate_lba = backup_header_lba,
        .entry_lba = 2,
        .first_usable = FIRST_USABLE_LBA,
        .last_usable = last_usable,
        .disk_guid = disk_guid,
        .entries_crc = entries_crc,
    })) return false;

    if (!writeHeader(write, .{
        .my_lba = backup_header_lba,
        .alternate_lba = 1,
        .entry_lba = backup_array_lba,
        .first_usable = FIRST_USABLE_LBA,
        .last_usable = last_usable,
        .disk_guid = disk_guid,
        .entries_crc = entries_crc,
    })) return false;

    debug.klog("[gpt] wrote table: {d} partitions, usable {d}..{d}, backup header at {d}\n", .{ specs.len, FIRST_USABLE_LBA, last_usable, backup_header_lba });
    return true;
}

const HeaderSpec = struct {
    my_lba: u64,
    alternate_lba: u64,
    entry_lba: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: [16]u8,
    entries_crc: u32,
};

fn writeHeader(write: *const fn (u32, u32, [*]const u8) bool, spec: HeaderSpec) bool {
    var buf: [SECTOR_SIZE]u8 = .{0} ** SECTOR_SIZE;
    const h: *Header = @ptrCast(@alignCast(&buf));
    h.* = .{
        .signature = endian.LE(u64).init(SIGNATURE),
        .revision = endian.LE(u32).init(REVISION_1_0),
        .header_size = endian.LE(u32).init(HEADER_BYTES),
        // Zero while checksumming — filled in below.
        .header_crc32 = endian.LE(u32).init(0),
        ._reserved = endian.LE(u32).init(0),
        .my_lba = endian.LE(u64).init(spec.my_lba),
        .alternate_lba = endian.LE(u64).init(spec.alternate_lba),
        .first_usable_lba = endian.LE(u64).init(spec.first_usable),
        .last_usable_lba = endian.LE(u64).init(spec.last_usable),
        .disk_guid = spec.disk_guid,
        .partition_entry_lba = endian.LE(u64).init(spec.entry_lba),
        .num_partition_entries = endian.LE(u32).init(ENTRY_COUNT),
        .sizeof_partition_entry = endian.LE(u32).init(ENTRY_BYTES),
        .partition_entry_array_crc32 = endian.LE(u32).init(spec.entries_crc),
    };
    h.header_crc32.set(crc32.oneShot(buf[0..HEADER_BYTES]));

    if (!write(@intCast(spec.my_lba), 1, &buf)) {
        debug.klog("[gpt] header write failed at LBA {d}\n", .{spec.my_lba});
        return false;
    }
    return true;
}

fn buildEntry(spec: PartSpec) Entry {
    var e: Entry = .{
        .type_guid = spec.type_guid,
        .unique_guid = undefined,
        .starting_lba = endian.LE(u64).init(spec.start_lba),
        .ending_lba = endian.LE(u64).init(spec.end_lba),
        .attributes = endian.LE(u64).init(0),
        .name = .{0} ** 72,
    };
    makeGuid(&e.unique_guid);

    if (spec.name.len > NAME_UTF16_LEN) {
        debug.klog("[gpt] partition name '{s}' truncated to {d} chars\n", .{ spec.name, NAME_UTF16_LEN });
    }
    const n = @min(spec.name.len, NAME_UTF16_LEN);
    for (spec.name[0..n], 0..) |c, i| {
        // ASCII widens to UTF-16LE by zero-extension; anything above 0x7F
        // would need real transcoding, so it becomes '?' rather than a
        // mis-encoded code unit.
        e.name[i * 2] = if (c < 0x80) c else '?';
        e.name[i * 2 + 1] = 0;
    }
    return e;
}

fn writeProtectiveMbr(write: *const fn (u32, u32, [*]const u8) bool, disk_sectors: u64) bool {
    var buf: [SECTOR_SIZE]u8 = .{0} ** SECTOR_SIZE;
    const rec: *MbrRecord = @ptrCast(@alignCast(&buf[MBR_RECORD_OFFSET]));
    rec.* = .{
        .boot_indicator = 0,
        // CHS 0/0/2 — the spec's literal value for "LBA 1", kept as the magic
        // triple every other implementation writes rather than computed.
        .starting_chs = .{ 0x00, 0x02, 0x00 },
        .os_type = MBR_TYPE_PROTECTIVE,
        // CHS 0xFFFFFF is the spec's "too big for CHS" sentinel.
        .ending_chs = .{ 0xFF, 0xFF, 0xFF },
        .starting_lba = endian.LE(u32).init(1),
        // Spans the rest of the disk, saturating at u32 for disks over 2 TiB
        // — the spec's prescribed behavior, not a truncation bug.
        .size_in_lba = endian.LE(u32).init(@intCast(@min(disk_sectors - 1, 0xFFFF_FFFF))),
    };
    buf[MBR_SIGNATURE_OFFSET] = 0x55;
    buf[MBR_SIGNATURE_OFFSET + 1] = 0xAA;

    if (!write(0, 1, &buf)) {
        debug.klog("[gpt] protective MBR write failed\n", .{});
        return false;
    }
    return true;
}

/// RFC 4122 version 4 (random) UUID in GPT's mixed-endian byte order. The
/// version and variant nibbles are stamped over random bytes; which byte
/// carries which is fixed by the rendered form, not by the storage order.
fn makeGuid(out: *[16]u8) void {
    if (!random.fillRandom(out)) {
        // fillRandom fell back to its xorshift PRNG and said so. A GUID from
        // a weak source is a uniqueness risk, not a correctness one, so this
        // proceeds — but the log records which disks got weak GUIDs.
        debug.klog("[gpt] GUID from degraded entropy source\n", .{});
    }
    out[7] = (out[7] & 0x0F) | 0x40; // version 4
    out[8] = (out[8] & 0x3F) | 0x80; // RFC 4122 variant
}

// =============================================================================
// Parsing
// =============================================================================

/// Reads the table off `dev`. Tries the primary header at LBA 1 first and
/// falls back to the backup at the last LBA; the result records which one
/// answered. Returns null (having logged why) if neither copy has a valid
/// signature and header CRC.
///
/// Caller context: process context only — issues blocking reads.
/// Everything `parse` can reject a disk for. `NotGpt` is the common,
/// EXPECTED case (probe loops hit it all day); the rest mean "GPT here
/// but damaged" — a different situation for the caller, and the reason
/// this is an error set rather than a bool: the class travels with the
/// return, the detail (which LBA, which CRC pair) sits in the fail ring.
pub const ParseError = error{
    DiskTooSmall,
    DiskTooBig,
    ReadFailed,
    NotGpt,
    BadRevision,
    BadHeaderSize,
    BadEntrySize,
    TooManyEntries,
    BadHeaderCrc,
    ArrayPastDisk,
    BadArrayCrc,
};

pub fn parse(dev: Device) ParseError!Table {
    if (dev.sectors < RESERVED_SECTORS + 1) {
        return fail(error.DiskTooSmall, "parse: {d} sectors", .{dev.sectors});
    }
    if (dev.sectors > MAX_DISK_SECTORS) {
        return fail(error.DiskTooBig, "parse: {d} sectors > u32 LBA limit", .{dev.sectors});
    }

    const primary_err: ParseError = blk: {
        const h = readHeader(dev, 1) catch |e| break :blk e;
        return buildTable(dev, h, false);
    };
    // A wiped/corrupt primary with a healthy backup is still a GPT disk —
    // always try LBA N-1. Narrate on serial only when the primary looked
    // DAMAGED; a plain non-GPT disk (NotGpt) stays quiet here, its detail
    // already in the fail ring.
    if (primary_err != error.NotGpt) {
        debug.klog("[gpt] parse: primary header {s}, trying backup at LBA {d}\n", .{ @errorName(primary_err), dev.sectors - 1 });
    }
    const h = readHeader(dev, dev.sectors - 1) catch |backup_err| {
        if (primary_err != error.NotGpt or backup_err != error.NotGpt) {
            debug.klog("[gpt] parse: no valid GPT header on either copy ({s}/{s})\n", .{ @errorName(primary_err), @errorName(backup_err) });
        }
        return backup_err;
    };
    return buildTable(dev, h, true);
}

/// Reads and validates one header copy. Each rejection is a distinct
/// error with its detail (LBA, offending value) recorded via fail() —
/// "no GPT here" and "GPT here but corrupt" need different responses
/// from a caller.
fn readHeader(dev: Device, lba: u64) ParseError!Header {
    var buf: [SECTOR_SIZE]u8 = undefined;
    if (!dev.readSectors(@intCast(lba), 1, &buf)) {
        return fail(error.ReadFailed, "header read at lba={d}", .{lba});
    }

    var h: Header = undefined;
    @memcpy(std.mem.asBytes(&h), buf[0..@sizeOf(Header)]);

    if (h.signature.get() != SIGNATURE) {
        return fail(error.NotGpt, "lba={d} sig=0x{X}", .{ lba, h.signature.get() });
    }
    if (h.revision.get() != REVISION_1_0) {
        return fail(error.BadRevision, "lba={d} rev=0x{X}", .{ lba, h.revision.get() });
    }
    const hsize = h.header_size.get();
    if (hsize < HEADER_BYTES or hsize > SECTOR_SIZE) {
        return fail(error.BadHeaderSize, "lba={d} header_size={d}", .{ lba, hsize });
    }
    if (h.sizeof_partition_entry.get() != ENTRY_BYTES) {
        return fail(error.BadEntrySize, "lba={d} entry size {d} != {d}", .{ lba, h.sizeof_partition_entry.get(), ENTRY_BYTES });
    }
    if (h.num_partition_entries.get() > ENTRY_COUNT) {
        return fail(error.TooManyEntries, "lba={d}: {d} entries > the {d} we read", .{ lba, h.num_partition_entries.get(), ENTRY_COUNT });
    }

    // CRC over header_size bytes with the CRC field zeroed. Zero it in the
    // sector buffer, not in `h`, so the trailing bytes between @sizeOf(Header)
    // and header_size are included exactly as they are on disk.
    const stored = h.header_crc32.get();
    @memset(buf[@offsetOf(Header, "header_crc32")..][0..4], 0);
    const computed = crc32.oneShot(buf[0..hsize]);
    if (computed != stored) {
        return fail(error.BadHeaderCrc, "lba={d} crc 0x{X} != stored 0x{X}", .{ lba, computed, stored });
    }
    return h;
}

fn buildTable(dev: Device, h: Header, from_backup: bool) ParseError!Table {
    const entry_lba = h.partition_entry_lba.get();
    const declared = h.num_partition_entries.get();
    const array_bytes: u64 = @as(u64, declared) * @as(u64, ENTRY_BYTES);
    const sector_bytes: u64 = SECTOR_SIZE;
    const array_sectors: u64 = (array_bytes + sector_bytes - 1) / sector_bytes;

    if (entry_lba + array_sectors > dev.sectors) {
        return fail(error.ArrayPastDisk, "entry array lba={d} +{d} sectors, disk={d}", .{ entry_lba, array_sectors, dev.sectors });
    }

    var t: Table = .{
        .disk_guid = h.disk_guid,
        .first_usable_lba = h.first_usable_lba.get(),
        .last_usable_lba = h.last_usable_lba.get(),
        .from_backup = from_backup,
        .truncated = false,
        .count = 0,
        .parts = undefined,
    };

    // One pass: checksum the declared array while collecting used entries.
    // Sector-at-a-time for the same reason `create` emits it that way.
    const entry_bytes: usize = ENTRY_BYTES;
    const per_sector: usize = SECTOR_SIZE / ENTRY_BYTES;

    var array_crc = crc32.start();
    var remaining = array_bytes;
    var sector: u64 = 0;
    while (sector < array_sectors) : (sector += 1) {
        var buf: [SECTOR_SIZE]u8 = undefined;
        if (!dev.readSectors(@intCast(entry_lba + sector), 1, &buf)) {
            return fail(error.ReadFailed, "entry array sector {d} (lba={d})", .{ sector, entry_lba + sector });
        }
        // The final sector may be partially covered when `declared` is not a
        // multiple of 4; the CRC is defined over exactly declared*128 bytes.
        const take: usize = @intCast(@min(remaining, sector_bytes));
        array_crc = crc32.feed(array_crc, buf[0..take]);
        remaining -= take;

        var slot: usize = 0;
        while (slot * entry_bytes < take) : (slot += 1) {
            var e: Entry = undefined;
            @memcpy(std.mem.asBytes(&e), buf[slot * entry_bytes ..][0..entry_bytes]);
            if (std.mem.eql(u8, &e.type_guid, &TYPE_UNUSED)) continue;

            if (t.count >= MAX_PARSED) {
                t.truncated = true;
                continue;
            }
            const index: u32 = @intCast(sector * per_sector + slot);
            t.parts[t.count] = decodeEntry(e, index);
            t.count += 1;
        }
    }

    const computed = crc32.end(array_crc);
    const stored = h.partition_entry_array_crc32.get();
    if (computed != stored) {
        return fail(error.BadArrayCrc, "entry array crc 0x{X} != stored 0x{X}", .{ computed, stored });
    }
    if (t.truncated) {
        debug.kwarn(@src(), "[gpt] more than {d} partitions on disk; only the first {d} surfaced\n", .{ MAX_PARSED, MAX_PARSED });
    }
    return t;
}

fn decodeEntry(e: Entry, index: u32) Partition {
    var p: Partition = .{
        .index = index,
        .type_guid = e.type_guid,
        .unique_guid = e.unique_guid,
        .start_lba = e.starting_lba.get(),
        .end_lba = e.ending_lba.get(),
        .name = .{0} ** NAME_UTF16_LEN,
        .name_len = 0,
    };
    var i: usize = 0;
    while (i < NAME_UTF16_LEN) : (i += 1) {
        const lo = e.name[i * 2];
        const hi = e.name[i * 2 + 1];
        if (lo == 0 and hi == 0) break;
        p.name[i] = if (hi == 0 and lo < 0x80) lo else '?';
        p.name_len = i + 1;
    }
    return p;
}
