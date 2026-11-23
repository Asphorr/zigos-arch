//! The host-visible shared memory window (shm id 1). The host maps a blob
//! there (RESOURCE_MAP_BLOB) at an offset the driver picks; this hands out
//! those page ranges, first fit, and remembers whose blob each one holds.

const std = @import("std");
const SpinLock = @import("../../../proc/spinlock.zig").SpinLock;
const pmm = @import("../../../mm/pmm.zig");

/// Whose blob a range holds.
pub const Owner = enum(u32) {
    /// The kernel's own (the compositor's).
    kernel = 0,
    /// A range whose unmap failed: the host may still map a blob there, so
    /// it is never handed out again.
    orphan = 0xFFFF_FFFF,
    /// A process, by its thread group.
    _,

    pub fn process(tgid: u8) Owner {
        return @enumFromInt(@as(u32, tgid) + 1);
    }

    fn isProcess(self: Owner) bool {
        return self != .kernel and self != .orphan;
    }
};

const PAGE: u64 = 4096;

pub const Range = struct {
    offset: u64 = 0,
    size: u64 = 0,
    resource_id: u32 = 0,
    owner: Owner = .kernel,
};

/// The ranges in use, sorted by offset. Not locked.
pub const Table = struct {
    pub const MAX_RANGES = 256;

    length: u64 = 0,
    ranges: [MAX_RANGES]Range = [_]Range{.{}} ** MAX_RANGES,
    count: usize = 0,
    used: u64 = 0,
    peak: u64 = 0,
    /// Requests turned down for the reserve.
    refused: u32 = 0,

    /// A free range of `size` bytes, rounded up to pages, that leaves at
    /// least `reserve` bytes of the window free. Returns its offset.
    pub fn alloc(self: *Table, size: u64, reserve: u64, resource_id: u32, owner: Owner) ?u64 {
        if (size == 0 or size > self.length or self.count == MAX_RANGES) return null;
        const bytes = (size + PAGE - 1) & ~(PAGE - 1);
        if (reserve != 0 and self.used + bytes + reserve > self.length) {
            self.refused += 1;
            return null;
        }

        var at: u64 = 0;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (self.ranges[i].offset - at >= bytes) break;
            at = self.ranges[i].offset + self.ranges[i].size;
        }
        if (at + bytes > self.length) return null;

        std.mem.copyBackwards(Range, self.ranges[i + 1 .. self.count + 1], self.ranges[i..self.count]);
        self.ranges[i] = .{ .offset = at, .size = bytes, .resource_id = resource_id, .owner = owner };
        self.count += 1;
        self.used += bytes;
        self.peak = @max(self.peak, self.used);
        return at;
    }

    fn indexOf(self: *const Table, offset: u64) ?usize {
        for (self.ranges[0..self.count], 0..) |r, i| {
            if (r.offset == offset) return i;
        }
        return null;
    }

    /// Gives the range at `offset` back; null if there is none.
    pub fn free(self: *Table, offset: u64) ?Range {
        const i = self.indexOf(offset) orelse return null;
        const r = self.ranges[i];
        std.mem.copyForwards(Range, self.ranges[i .. self.count - 1], self.ranges[i + 1 .. self.count]);
        self.count -= 1;
        self.used -= r.size;
        return r;
    }

    /// Changes the owner of the range at `offset`; returns the old one.
    pub fn setOwner(self: *Table, offset: u64, owner: Owner) ?Owner {
        const i = self.indexOf(offset) orelse return null;
        const old = self.ranges[i].owner;
        self.ranges[i].owner = owner;
        return old;
    }

    pub fn find(self: *const Table, resource_id: u32, owner: Owner) ?Range {
        for (self.ranges[0..self.count]) |r| {
            if (r.resource_id == resource_id and r.owner == owner) return r;
        }
        return null;
    }

    pub fn firstOwnedBy(self: *const Table, owner: Owner) ?Range {
        for (self.ranges[0..self.count]) |r| {
            if (r.owner == owner) return r;
        }
        return null;
    }
};

comptime {
    @setEvalBranchQuota(20_000);
    const a = std.debug.assert;
    const p = Owner.process(6);
    var t: Table = .{ .length = 16 * PAGE };
    // Sizes round up to pages; ranges pack from the start.
    a(t.alloc(1, 0, 1, .kernel).? == 0);
    a(t.alloc(3 * PAGE, 0, 2, p).? == PAGE);
    a(t.alloc(PAGE + 1, 0, 3, p).? == 4 * PAGE);
    a(t.used == 6 * PAGE and t.count == 3);
    // First fit: a hole too small is passed over, then filled.
    a(t.free(PAGE).?.resource_id == 2);
    a(t.alloc(4 * PAGE, 0, 4, .kernel).? == 6 * PAGE);
    a(t.alloc(2 * PAGE, 0, 5, .kernel).? == PAGE);
    a(t.ranges[1].resource_id == 5 and t.ranges[2].resource_id == 3 and t.ranges[3].resource_id == 4);
    // 9 pages used of 16: the reserve refuses, the window's end refuses.
    a(t.alloc(PAGE, 8 * PAGE, 6, p) == null and t.refused == 1);
    a(t.alloc(8 * PAGE, 0, 6, .kernel) == null and t.refused == 1);
    a(t.alloc(6 * PAGE, 0, 6, .kernel).? == 10 * PAGE and t.alloc(PAGE, 0, 7, .kernel).? == 3 * PAGE);
    a(t.used == 16 * PAGE and t.peak == 16 * PAGE and t.alloc(PAGE, 0, 8, .kernel) == null);
    // Lookups go by owner; an orphan keeps its range and nothing else.
    a(t.find(3, p).?.offset == 4 * PAGE and t.find(3, .kernel) == null and t.firstOwnedBy(p).?.resource_id == 3);
    a(t.setOwner(4 * PAGE, .orphan).? == p and t.find(3, p) == null and t.firstOwnedBy(p) == null);
    a(t.free(123) == null and t.used == 16 * PAGE);
}

var lock: SpinLock = .{};
var table: Table = .{};

/// Physical base of the window; 0 = the device has none.
pub var phys: usize = 0;

/// Ranges held for processes, so that one with none exits without taking
/// the lock.
var process_ranges: u32 = 0;
var orphaned: u32 = 0;

/// At device bring-up, before anything maps a blob.
pub fn setWindow(base: usize, length: u64) void {
    phys = base;
    table.length = length;
    // Blobs get mapped into user address spaces; their pages are the
    // host's, not frames an address-space teardown may free.
    pmm.registerDeviceRange(pmm.Phys.of(base), @intCast(length));
}

/// A range for `resource_id`. A process's blobs leave a quarter of the
/// window to the kernel's: the display must not run out because of them.
pub fn alloc(size: u64, resource_id: u32, owner: Owner) ?u64 {
    lock.acquire();
    defer lock.release();
    const reserve = if (owner == .kernel) 0 else table.length / 4;
    const at = table.alloc(size, reserve, resource_id, owner) orelse return null;
    if (owner.isProcess()) _ = @atomicRmw(u32, &process_ranges, .Add, 1, .release);
    return at;
}

/// The host no longer maps anything at `offset`.
pub fn free(offset: u64) void {
    lock.acquire();
    defer lock.release();
    const r = table.free(offset) orelse return;
    if (r.owner.isProcess()) _ = @atomicRmw(u32, &process_ranges, .Sub, 1, .release);
    if (r.owner == .orphan) orphaned -= 1;
}

/// The host could not be made to unmap `offset`: keep it out of use.
pub fn orphan(offset: u64) void {
    lock.acquire();
    defer lock.release();
    const old = table.setOwner(offset, .orphan) orelse return;
    if (old == .orphan) return;
    if (old.isProcess()) _ = @atomicRmw(u32, &process_ranges, .Sub, 1, .release);
    orphaned += 1;
}

/// The range `owner` holds for `resource_id`.
pub fn rangeOf(resource_id: u32, owner: Owner) ?Range {
    lock.acquire();
    defer lock.release();
    return table.find(resource_id, owner);
}

/// One of a process's ranges, for releasing them one by one.
pub fn ownedBy(owner: Owner) ?Range {
    if (@atomicLoad(u32, &process_ranges, .acquire) == 0) return null;
    lock.acquire();
    defer lock.release();
    return table.firstOwnedBy(owner);
}

pub const Stats = struct { size: u64, used: u64, peak: u64, ranges: usize, refused: u32, orphaned: u32 };

pub fn stats() Stats {
    lock.acquire();
    defer lock.release();
    return .{
        .size = table.length,
        .used = table.used,
        .peak = table.peak,
        .ranges = table.count,
        .refused = table.refused,
        .orphaned = orphaned,
    };
}
