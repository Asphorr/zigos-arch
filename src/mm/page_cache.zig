// Unified page cache — a global (file identity, page offset) -> physical frame
// map behind both read() and file-backed mmap, so a page read by one process
// and mapped by another is the same frame.
//
// ============================== STRUCTURE ====================================
// A pool of entries, sized from RAM at the first init() and taken from PMM,
// indexed two ways: a chained hash by (file_id, page_off) for lookups, and a
// chained hash by file_id for the per-file walks (truncate, unlink). A page
// can always be added while the pool has a free entry or a clean cache-only
// page to evict, however the keys hash. A MAP_SHARED mapping depends on that:
// its writes reach the file only through a cached frame, so its fault fails
// rather than map a frame the cache does not track.
//
// ============================ REFCOUNT DISCIPLINE ============================
// Leans entirely on pmm's per-frame u8 refcount (pmm.acquireFrame/releaseFrame/
// frameRefCount), the same mechanism COW and shared-anon already use:
//
//   insertFilled      -> the caller's frame: 1 = the CACHE's ref, +1 the mapper's
//   pin               -> pmm.acquireFrame() -> >= 2           = a MAPPER's ref
//   (mapper unmaps)   -> pmm.releaseFrame() -> back to 1        (cache still holds)
//   evict             -> only when refcount == 1: releaseFrame -> 0, frame freed
//
// THE KEY INVARIANT: refcount == 1  <=>  cache-only, and evictable <=>
// (cache-only AND not dirty). A dirty cache-only page — a MAP_SHARED write whose
// mapper has gone but whose bytes aren't on disk yet — is held until
// syncCacheFile or pgflushd writes it and clears the flag. The invariant holds
// because a cache frame's physical address is PRIVATE to the cache until pin()
// hands it out, and pin() runs under the cache lock. So a refcount-1 frame can
// only go to 2 via the lock held during an eviction scan — eviction can never
// pull a frame out from under a live mapping. (Concurrent unmap can only drop a
// refcount toward 1, which merely makes a page MORE evictable: safe.)
//
// ============================== LOCKING ======================================
// One leaf-ish SpinLock; all cached state lives behind it in a Guarded blob
// (util/guarded.zig). Lock order is page_cache lock -> pmm locks (allocFrame /
// releaseFrame run under it; acquireFrame is a lock-free CAS). Nothing takes
// this lock from an IRQ handler, so a plain (non-IrqSave) acquire is correct.
// No hold walks more than SCAN_CHUNK entries or one file's pages.

const pmm = @import("pmm.zig");
const Phys = @import("../util/addr.zig").Phys;
const spinlock = @import("../proc/spinlock.zig");
const Guarded = @import("../util/guarded.zig").Guarded;

pub const PAGE_SIZE: usize = 4096;

// Pool size: a quarter of the frames free at boot, within these bounds — the
// most RAM cached pages can hold. Only a page fault that runs out of frames
// reclaims them, so the cache must leave room for everything else (large
// contiguous allocations included). An entry is 48 bytes: about 0.3% of RAM.
const MIN_ENTRIES: u32 = 2048;
const MAX_ENTRIES: u32 = 1 << 20;

/// Entries one lock hold may walk in a sweep (eviction, dirty scan, reclaim).
const SCAN_CHUNK: u32 = 4096;
/// A range of more pages than this is handled by walking the file's pages
/// instead of probing every offset.
const PROBE_MAX: u64 = 256;
/// Pages one reclaim call frees at least, so memory pressure doesn't come
/// back to it on every fault.
const RECLAIM_BATCH: u32 = 256;

const NIL: u32 = 0xFFFF_FFFF;

// pmm's per-frame refcount is a u8 and acquireFrame PANICS at 255. The pin /
// insert paths refuse a new mapper reference once a frame reaches this and
// serve the caller an UNCACHED private copy instead. The margin covers the
// window between the under-lock refcount check and acquireFrame:
// cloneAddressSpace's acquireFrame (vmm.zig) is lock-free, so up to
// MAX_CPUS-1 concurrent forks of the same frame can bump it meanwhile.
pub const PIN_SATURATION: u8 = 223;

// File-identity namespace tags occupy the high bits of a cache key's file_id,
// so one filesystem's inode keyspace can't collide with another's.
pub const FILE_ID_EXT2: u64 = 1 << 63;
pub fn ext2FileId(inum: u32) u64 {
    return FILE_ID_EXT2 | @as(u64, inum);
}

/// One cached page, or a free pool slot. Behind the cache lock.
const Entry = struct {
    file_id: u64 = 0,
    page_off: u64 = 0, // page-aligned byte offset within the file
    frame: Phys = Phys.of(0),
    /// Next in its key bucket while valid, in the free list otherwise.
    next: u32 = NIL,
    /// Neighbours in its file bucket's list (valid entries only).
    file_next: u32 = NIL,
    file_prev: u32 = NIL,
    valid: bool = false,
    /// A writable shared mapping has (or may have) modified this page since
    /// the last disk write. Never evicted; cleared by clearDirty* once no
    /// writable mapper remains.
    dirty: bool = false,
    /// `sum` is the page's content checksum from when it was published;
    /// cleared once the page may legitimately change (markDirty).
    summed: bool = false,
    sum: u64 = 0,
};

/// Check clean pages against their publish-time checksum: on every hit and
/// in pgflushd's sweep. A mismatch is a write that bypassed the cache.
pub const VERIFY = true;

fn pageSum(frame: Phys) u64 {
    const q = frame.toVirt().ptr([*]const u64);
    var a: u64 = 0x9E3779B97F4A7C15;
    var b: u64 = 0;
    for (0..512) |i| {
        a = (a ^ q[i]) *% 0xFF51AFD7ED558CCD;
        b +%= q[i] ^ @as(u64, i);
    }
    return a ^ b;
}

/// A cached page found changed, pinned for vfs.reportCacheCorruption.
pub const Corrupt = struct {
    file_id: u64,
    page_off: u64,
    frame: Phys,
    pinned: bool,
};

fn mix(x: u64) u64 {
    var h = x;
    h ^= h >> 33;
    h *%= 0xFF51AFD7ED558CCD;
    h ^= h >> 33;
    return h;
}

/// Everything the cache lock protects (util/guarded.zig).
const CacheState = struct {
    /// The pool and the two bucket-head tables: one PMM block, taken at the
    /// first init(). Head tables are powers of two long.
    entries: []Entry = &.{},
    key_heads: []u32 = &.{},
    file_heads: []u32 = &.{},
    free_head: u32 = NIL,
    /// Eviction and reclaim cursor over `entries`.
    hand: u32 = 0,
    /// No entry at or above this index has been used since init().
    high: u32 = 0,
    resident: u32 = 0,
    /// Most pages resident at once: entries.len, less in the self-test.
    limit: u32 = 0,
    registered: bool = false,

    // Diagnostic counters, read out via statsSnapshot.
    hits: u64 = 0,
    misses: u64 = 0,
    inserts: u64 = 0,
    evictions: u64 = 0,
    full_skips: u64 = 0, // a page could not be cached: no entry free or evictable
    reclaimed: u64 = 0, // clean cache-only pages dropped under PMM pressure
    verified: u64 = 0,
    corrupt_seen: u64 = 0,
    corrupt: [8]Corrupt = undefined,
    n_corrupt: u32 = 0,

    /// Report a clean page whose bytes no longer match its checksum, once.
    fn verify(self: *CacheState, e: *Entry) void {
        if (!VERIFY or !e.summed or e.dirty) return;
        self.verified += 1;
        if (pageSum(e.frame) == e.sum) return;
        e.summed = false;
        self.corrupt_seen += 1;
        const refs = pmm.frameRefCount(e.frame);
        const pid = @import("../cpu/smp.zig").currentPid() orelse 0;
        @import("../debug/serial.zig").print("[pc-verify] !!! cached page changed: inode {d} off 0x{X} frame 0x{X} refs {d} (noticed by pid {d})\n", .{
            e.file_id & 0xFFFF_FFFF, e.page_off, e.frame.raw(), refs, pid,
        });
        if (self.n_corrupt >= self.corrupt.len) return;
        const pinned = refs >= 1 and refs < PIN_SATURATION;
        if (pinned) pmm.acquireFrame(e.frame);
        self.corrupt[self.n_corrupt] = .{ .file_id = e.file_id, .page_off = e.page_off, .frame = e.frame, .pinned = pinned };
        self.n_corrupt += 1;
    }

    fn keyHead(self: *CacheState, file_id: u64, page_off: u64) *u32 {
        const h = mix(file_id *% 0x9E3779B97F4A7C15 +% (page_off >> 12));
        return &self.key_heads[h & (self.key_heads.len - 1)];
    }

    fn fileHead(self: *CacheState, file_id: u64) *u32 {
        return &self.file_heads[mix(file_id) & (self.file_heads.len - 1)];
    }

    fn find(self: *CacheState, file_id: u64, page_off: u64) ?*Entry {
        var i = self.keyHead(file_id, page_off).*;
        while (i != NIL) : (i = self.entries[i].next) {
            const e = &self.entries[i];
            if (e.file_id == file_id and e.page_off == page_off) return e;
        }
        return null;
    }

    /// A free entry's index: off the free list, or by evicting when `limit`
    /// pages are resident. Null if nothing in reach can go.
    fn takeFree(self: *CacheState) ?u32 {
        if (self.resident >= self.limit and !self.evictOne()) return null;
        const idx = self.free_head;
        self.free_head = self.entries[idx].next;
        if (idx >= self.high) self.high = idx + 1;
        return idx;
    }

    /// Cache `frame` as (file_id, page_off); the cache's reference is the one
    /// the caller hands over. Null if no entry could be had.
    fn insert(self: *CacheState, file_id: u64, page_off: u64, frame: Phys) ?*Entry {
        const idx = self.takeFree() orelse return null;
        const kh = self.keyHead(file_id, page_off);
        const fh = self.fileHead(file_id);
        self.entries[idx] = .{
            .file_id = file_id,
            .page_off = page_off,
            .frame = frame,
            .next = kh.*,
            .file_next = fh.*,
            .valid = true,
        };
        if (fh.* != NIL) self.entries[fh.*].file_prev = idx;
        kh.* = idx;
        fh.* = idx;
        self.resident += 1;
        self.inserts += 1;
        return &self.entries[idx];
    }

    /// Take `e` out of both indexes, onto the free list. Its frame reference
    /// is the caller's to drop.
    fn remove(self: *CacheState, e: *Entry) void {
        const idx: u32 = @intCast((@intFromPtr(e) - @intFromPtr(self.entries.ptr)) / @sizeOf(Entry));
        var link = self.keyHead(e.file_id, e.page_off);
        while (link.* != idx) link = &self.entries[link.*].next;
        link.* = e.next;
        if (e.file_prev != NIL) {
            self.entries[e.file_prev].file_next = e.file_next;
        } else {
            self.fileHead(e.file_id).* = e.file_next;
        }
        if (e.file_next != NIL) self.entries[e.file_next].file_prev = e.file_prev;
        e.* = .{ .next = self.free_head };
        self.free_head = idx;
        self.resident -= 1;
    }

    /// Clean and mapped nowhere (see the header invariant).
    fn evictable(e: *const Entry) bool {
        return e.valid and !e.dirty and pmm.frameRefCount(e.frame) == 1;
    }

    /// Drop one evictable page, sweeping at most SCAN_CHUNK entries from the
    /// hand.
    fn evictOne(self: *CacheState) bool {
        const span = @min(self.high, SCAN_CHUNK);
        var scanned: u32 = 0;
        while (scanned < span) : (scanned += 1) {
            if (self.hand >= self.high) self.hand = 0;
            const e = &self.entries[self.hand];
            self.hand += 1;
            if (!evictable(e)) continue;
            pmm.releaseFrame(e.frame); // 1 -> 0: frame returns to the pool
            self.remove(e);
            self.evictions += 1;
            return true;
        }
        return false;
    }
};

var cache: Guarded(CacheState) = .init(.{});

/// Lock-held snapshot of the diagnostic counters.
pub const Stats = struct {
    hits: u64,
    misses: u64,
    inserts: u64,
    evictions: u64,
    full_skips: u64,
    reclaimed: u64,
    verified: u64,
    corrupt_seen: u64,
};

pub fn statsSnapshot() Stats {
    const h = cache.acquire();
    defer h.release();
    return .{
        .hits = h.ptr.hits,
        .misses = h.ptr.misses,
        .inserts = h.ptr.inserts,
        .evictions = h.ptr.evictions,
        .full_skips = h.ptr.full_skips,
        .reclaimed = h.ptr.reclaimed,
        .verified = h.ptr.verified,
        .corrupt_seen = h.ptr.corrupt_seen,
    };
}

fn ceilPowerOfTwo(n: u32) u32 {
    var p: u32 = 1;
    while (p < n) p <<= 1;
    return p;
}

/// Take the pool and head tables from PMM. Boot-time, before any page is
/// cached; a smaller pool if RAM is that fragmented.
fn allocTables(s: *CacheState) void {
    var want: u32 = @min(@max(pmm.freeFrameCount() / 4, MIN_ENTRIES), MAX_ENTRIES);
    while (true) : (want /= 2) {
        const keys = ceilPowerOfTwo(want);
        const files = @max(keys / 16, 64);
        const bytes: usize = @as(usize, want) * @sizeOf(Entry) + (@as(usize, keys) + files) * @sizeOf(u32);
        const frames: u32 = @intCast((bytes + PAGE_SIZE - 1) / PAGE_SIZE);
        const block = pmm.allocContiguous(frames) orelse {
            if (want <= MIN_ENTRIES) @panic("page cache: no memory for its index");
            continue;
        };
        const base = block.toVirt().raw();
        s.entries = @as([*]Entry, @ptrFromInt(base))[0..want];
        const heads: [*]u32 = @ptrFromInt(base + @as(usize, want) * @sizeOf(Entry));
        s.key_heads = heads[0..keys];
        s.file_heads = heads[keys .. keys + files];
        return;
    }
}

/// Empty the cache and reset the stats: at boot (main.zig) and before each
/// self-test. A frame a mapper still holds survives until that mapper lets
/// go; the cache's own reference is dropped either way.
pub fn init() void {
    const h = cache.acquire();
    defer h.release();
    const s = h.ptr;
    if (s.entries.len == 0) allocTables(s);
    for (s.entries[0..s.high]) |*e| {
        if (e.valid) pmm.releaseFrame(e.frame);
    }
    // The free list in index order, so the first pages cached take the first
    // entries: the eviction sweep then meets them oldest first.
    for (s.entries, 0..) |*e, i| e.* = .{ .next = if (i + 1 < s.entries.len) @intCast(i + 1) else NIL };
    @memset(s.key_heads, NIL);
    @memset(s.file_heads, NIL);
    s.free_head = 0;
    s.hand = 0;
    s.high = 0;
    s.resident = 0;
    s.limit = @intCast(s.entries.len);
    s.hits = 0;
    s.misses = 0;
    s.inserts = 0;
    s.evictions = 0;
    s.full_skips = 0;
    s.reclaimed = 0;
    if (!s.registered) {
        spinlock.registerLock("page_cache.lock", &cache.lock);
        // PMM calls reclaim() when an allocation fails. registerReclaim takes
        // no lock, so it is safe under ours.
        pmm.registerReclaim(reclaim);
        s.registered = true;
    }
}

/// SELF-TEST ONLY. Let at most `pages` be resident, so a test reaches
/// eviction with a handful of pages. The next init() lifts it.
pub fn limitForTest(pages: u32) void {
    const h = cache.acquire();
    defer h.release();
    h.ptr.limit = @min(pages, @as(u32, @intCast(h.ptr.entries.len)));
}

/// SELF-TEST ONLY. Find a resident page WITHOUT pinning it: the frame is
/// unprotected the moment the lock drops. Production readers use `pin`.
pub fn lookup(file_id: u64, page_off: u64) ?Phys {
    const h = cache.acquire();
    defer h.release();
    if (h.ptr.find(file_id, page_off)) |e| {
        h.ptr.hits += 1;
        return e.frame;
    }
    h.ptr.misses += 1;
    return null;
}

/// Look up and PIN for mapping: atomically (under the lock) bumps the frame's
/// refcount so eviction cannot free it. The caller MUST pmm.releaseFrame when
/// the mapping is torn down (vmm.unmapUserRange already does this). Null on a
/// miss — the caller then reads the page into a private frame and publishes
/// it with `insertFilled` — and also when the resident frame is at
/// PIN_SATURATION.
pub fn pin(file_id: u64, page_off: u64) ?Phys {
    const h = cache.acquire();
    defer h.release();
    if (h.ptr.find(file_id, page_off)) |e| {
        if (pmm.frameRefCount(e.frame) >= PIN_SATURATION) {
            h.ptr.misses += 1;
            return null;
        }
        h.ptr.verify(e);
        pmm.acquireFrame(e.frame); // 1 -> 2 (or N -> N+1); now un-evictable
        h.ptr.hits += 1;
        return e.frame;
    }
    h.ptr.misses += 1;
    return null;
}

pub const GetResult = struct {
    frame: Phys,
    fresh: bool, // true: freshly allocated, the caller fills it; false: a hit
};

/// SELF-TEST ONLY. The frame for (file_id, page_off), allocated and inserted
/// on a miss. Production paths must not use it: the miss PUBLISHES the frame
/// before the caller fills it, at refcount 1, so a concurrent pin() would map
/// garbage and eviction could free it mid-fill. Real code uses pin +
/// insertFilled. Null if the page can't be cached or no frame is free.
pub fn getOrAlloc(file_id: u64, page_off: u64) ?GetResult {
    const h = cache.acquire();
    defer h.release();

    if (h.ptr.find(file_id, page_off)) |e| {
        h.ptr.hits += 1;
        return .{ .frame = e.frame, .fresh = false };
    }
    h.ptr.misses += 1;

    const phys = pmm.allocFrame() orelse {
        h.ptr.full_skips += 1;
        return null;
    };
    _ = h.ptr.insert(file_id, page_off, phys) orelse {
        pmm.releaseFrame(phys);
        h.ptr.full_skips += 1;
        return null;
    };
    return .{ .frame = phys, .fresh = true };
}

pub const Inserted = struct {
    /// The frame to map or read; the caller holds one reference on it.
    frame: Phys,
    /// False: `frame` is the caller's own, unknown to the cache.
    cached: bool,
    /// Not cached because the resident page is at PIN_SATURATION: freeing
    /// memory will not change that.
    saturated: bool = false,
};

/// Publish a caller-filled private frame as (file_id, page_off). The caller
/// allocates the frame, fills it from disk with NO lock held (so nobody can
/// see a half-filled page), then calls this.
///
/// `frame` MUST be a freshly allocated page (refcount 1) the caller owns.
/// Three outcomes:
///   - published — the frame is cached (refcount 2 = cache + caller).
///   - lost the race — another CPU cached this page meanwhile; the input
///     frame is dropped and the resident one returned, with a reference.
///   - not cached — no entry could be had, or the resident page is at
///     PIN_SATURATION; the input frame stays the caller's alone. Fine for a
///     read or a private mapping, not for a shared one (see the header).
pub fn insertFilled(file_id: u64, page_off: u64, frame: Phys) Inserted {
    const h = cache.acquire();
    defer h.release();

    if (h.ptr.find(file_id, page_off)) |e| {
        if (pmm.frameRefCount(e.frame) < PIN_SATURATION) {
            h.ptr.verify(e);
            pmm.releaseFrame(frame); // discard our wasted fill (1 -> 0, freed)
            pmm.acquireFrame(e.frame);
            h.ptr.hits += 1;
            return .{ .frame = e.frame, .cached = true };
        }
        h.ptr.full_skips += 1;
        return .{ .frame = frame, .cached = false, .saturated = true };
    }

    const e = h.ptr.insert(file_id, page_off, frame) orelse {
        h.ptr.full_skips += 1;
        return .{ .frame = frame, .cached = false };
    };
    if (VERIFY) {
        e.sum = pageSum(frame);
        e.summed = true;
    }
    pmm.acquireFrame(frame); // 1 (cache's ref) -> 2 (+ the caller's)
    return .{ .frame = frame, .cached = true };
}

/// Drop one page. The cache's reference is released; a frame a mapper still
/// holds survives until they release. True if the page was resident.
pub fn invalidate(file_id: u64, page_off: u64) bool {
    const h = cache.acquire();
    defer h.release();
    const e = h.ptr.find(file_id, page_off) orelse return false;
    pmm.releaseFrame(e.frame);
    h.ptr.remove(e);
    return true;
}

/// Visit the resident pages of `file_id` in [first, end): by probing each
/// offset for a short range, by walking the file's list otherwise. `f` may
/// remove the entry it is given.
fn forRange(s: *CacheState, file_id: u64, first: u64, end: u64, ctx: anytype) void {
    if ((end - first) / PAGE_SIZE <= PROBE_MAX) {
        var off = first;
        while (off < end) : (off += PAGE_SIZE) {
            if (s.find(file_id, off)) |e| ctx.visit(s, e);
        }
        return;
    }
    var i = s.fileHead(file_id).*;
    while (i != NIL) {
        const e = &s.entries[i];
        i = e.file_next;
        if (e.file_id == file_id and e.page_off >= first and e.page_off < end) ctx.visit(s, e);
    }
}

/// Page-aligned [first, end) covering the byte range; end saturates.
fn pageSpan(start_off: u64, len: u64) struct { first: u64, end: u64 } {
    const mask: u64 = PAGE_SIZE - 1;
    const end = (start_off +| len +| mask) & ~mask;
    return .{ .first = start_off & ~mask, .end = end };
}

/// Drop every cached page overlapping [start_off, start_off+len) of
/// `file_id`, after a file write, so a later fault or cached read re-fills
/// from disk. A frame a private mapper still holds survives, stale, until
/// that mapping goes — POSIX leaves that unspecified.
///
/// Dirty pages are kept: a dirty page is a live MAP_SHARED mapping's, and
/// dropping it would let a second frame be cached for the same file page and
/// lose the mapping's writes. The mapping is authoritative; its writeback
/// overwrites what this write() put on disk. Returns pages dropped.
pub fn invalidateRange(file_id: u64, start_off: u64, len: u64) u32 {
    if (len == 0) return 0;
    const span = pageSpan(start_off, len);
    const Drop = struct {
        dropped: u32 = 0,
        fn visit(self: *@This(), s: *CacheState, e: *Entry) void {
            if (e.dirty) return;
            pmm.releaseFrame(e.frame);
            s.remove(e);
            self.dropped += 1;
        }
    };
    var drop: Drop = .{};
    const h = cache.acquire();
    defer h.release();
    forRange(h.ptr, file_id, span.first, span.end, &drop);
    return drop.dropped;
}

/// Drop EVERY cached page of `file_id`, dirty ones too: the file is being
/// truncated or its inode freed. The freed-inode case is a SECURITY boundary:
/// a reused inode must not serve the deleted file's pages. Returns pages
/// dropped.
pub fn invalidateFile(file_id: u64) u32 {
    const h = cache.acquire();
    defer h.release();
    const s = h.ptr;
    var dropped: u32 = 0;
    var i = s.fileHead(file_id).*;
    while (i != NIL) {
        const e = &s.entries[i];
        i = e.file_next;
        if (e.file_id != file_id) continue;
        pmm.releaseFrame(e.frame);
        s.remove(e);
        dropped += 1;
    }
    return dropped;
}

// ============================== DIRTY TRACKING ===============================
// A MAP_SHARED file mapping maps the cache frame WRITABLE; the page-fault path
// flags the page dirty when it does so. msync/munmap and pgflushd write dirty
// pages back and, once no writable mapper remains, clear the flag. The cache
// frame is the single source of truth — every writable mapper writes the SAME
// frame — so a flush can persist the latest bytes at any time. Marking is
// coarse (a page faulted writable counts as dirty even if only read): the
// cost is re-persisting unchanged pages, never data loss.

/// Mark a resident page dirty, right after it was mapped writable for a
/// shared mapping.
pub fn markDirty(file_id: u64, page_off: u64) void {
    const h = cache.acquire();
    defer h.release();
    if (h.ptr.find(file_id, page_off)) |e| {
        e.dirty = true;
        e.summed = false;
    }
}

pub const DirtyPage = struct {
    page_off: u64,
    frame: Phys, // pinned (acquireFrame'd) — caller MUST pmm.releaseFrame after writeback
};

/// Pages one takeDirtyBatch call is asked for.
pub const DIRTY_BATCH: usize = 32;

/// Dirty and short of PIN_SATURATION: a flush can pin it.
fn flushable(e: *const Entry) bool {
    return e.dirty and pmm.frameRefCount(e.frame) < PIN_SATURATION;
}

/// The lowest dirty pages of `file_id` at or after `from_off`, ascending, up
/// to out.len of them: each PINNED (so the writeback I/O can't race eviction
/// or an unmap freeing the frame) and with its dirty flag left set. Returns
/// how many; 0 when none is left.
///
/// The caller (vfs.syncCacheFile) goes on from the last page_off + PAGE, so
/// the cursor strictly increases. The flag stays because msync must keep it:
/// the still-writable PTE means later writes won't fault to re-mark the
/// page. A page at PIN_SATURATION is skipped, left for a later flush.
///
/// The offsets right after `from_off` are probed first, so a run of dirty
/// pages never walks the list; the file's list then gives the lowest of the
/// rest. The cost follows the pages cached, never the file's size.
pub fn takeDirtyBatch(file_id: u64, from_off: u64, out: []DirtyPage) usize {
    if (out.len == 0) return 0;
    const h = cache.acquire();
    defer h.release();
    const s = h.ptr;

    var n: usize = 0;
    var off = from_off & ~@as(u64, PAGE_SIZE - 1);
    var probes: u64 = 0;
    while (probes < PROBE_MAX and n < out.len) : ({
        probes += 1;
        off +|= PAGE_SIZE;
    }) {
        const e = s.find(file_id, off) orelse continue;
        if (!flushable(e)) continue;
        out[n] = .{ .page_off = off, .frame = e.frame };
        n += 1;
    }

    if (n < out.len) {
        // Everything probed lies below `off`: out[first..] takes the lowest
        // of what the list holds from there on, kept in order.
        const first = n;
        var i = s.fileHead(file_id).*;
        while (i != NIL) : (i = s.entries[i].file_next) {
            const e = &s.entries[i];
            if (e.file_id != file_id or e.page_off < off or !flushable(e)) continue;
            if (n == out.len and e.page_off > out[n - 1].page_off) continue;
            if (n < out.len) n += 1; // else the highest falls off the end
            var j = n - 1;
            while (j > first and out[j - 1].page_off > e.page_off) : (j -= 1) out[j] = out[j - 1];
            out[j] = .{ .page_off = e.page_off, .frame = e.frame };
        }
    }

    for (out[0..n]) |dp| pmm.acquireFrame(dp.frame);
    return n;
}

pub const GlobalDirtyPage = struct {
    file_id: u64,
    page_off: u64,
    frame: Phys, // pinned (acquireFrame'd) — caller MUST pmm.releaseFrame after writeback
    next_idx: u32, // pool cursor to resume the scan from on the next call
};

/// The first dirty page at or after pool index `from_idx`, for the flush
/// daemon: PINNED, flag left set, with the index to resume from. Null once
/// the pass is complete. Order is arbitrary; the strictly advancing cursor
/// ends the daemon's loop. A page at PIN_SATURATION is skipped.
pub fn takeNextDirtyGlobal(from_idx: u32) ?GlobalDirtyPage {
    var idx = from_idx;
    while (true) {
        const h = cache.acquire();
        defer h.release();
        if (idx >= h.ptr.high) return null;
        const stop = @min(h.ptr.high, idx +| SCAN_CHUNK);
        while (idx < stop) : (idx += 1) {
            const e = &h.ptr.entries[idx];
            if (!e.valid or !e.dirty) continue;
            if (pmm.frameRefCount(e.frame) >= PIN_SATURATION) continue;
            pmm.acquireFrame(e.frame);
            return .{ .file_id = e.file_id, .page_off = e.page_off, .frame = e.frame, .next_idx = idx + 1 };
        }
    }
}

/// Clear the dirty flag on a page IFF it's now cache-only (refcount == 1),
/// i.e. no writable mapper remains that could store new bytes without
/// re-faulting. Called AFTER the region's PTEs are torn down and the page's
/// final bytes have been flushed. True if the flag was cleared.
pub fn clearDirtyIfCacheOnly(file_id: u64, page_off: u64) bool {
    const h = cache.acquire();
    defer h.release();
    if (h.ptr.find(file_id, page_off)) |e| {
        if (e.dirty and pmm.frameRefCount(e.frame) == 1) {
            e.dirty = false;
            return true;
        }
    }
    return false;
}

/// Whether `frame` is still what the cache holds for (file_id, page_off).
/// For a writeback that pinned the frame earlier: asked under the
/// filesystem's lock, yes means the file was neither truncated nor freed
/// (and its inode handed to another file) in between — both drop the page
/// under that lock.
pub fn holds(file_id: u64, page_off: u64, frame: Phys) bool {
    const h = cache.acquire();
    defer h.release();
    const e = h.ptr.find(file_id, page_off) orelse return false;
    return e.frame == frame;
}

/// Drop a page IFF it is cache-only, dirty or not: for a page wholly past
/// EOF once its last mapping is gone — nothing of it can be persisted, and it
/// must not be served if the file later grows over it. True if dropped.
pub fn dropIfCacheOnly(file_id: u64, page_off: u64) bool {
    const h = cache.acquire();
    defer h.release();
    const e = h.ptr.find(file_id, page_off) orelse return false;
    if (pmm.frameRefCount(e.frame) != 1) return false;
    pmm.releaseFrame(e.frame);
    h.ptr.remove(e);
    return true;
}

/// Clear the dirty flag on every cache-only page of `file_id` in
/// [start_off, start_off+len): at process teardown, so a MAP_SHARED region's
/// pages rejoin the evictable pool. A page another address space still maps
/// (refcount > 1) stays dirty — that mapping owns its writeback.
///
/// Does NOT write back: teardown is I/O-free by design (the OOM-kill path
/// reaches it under memory pressure). Returns pages cleared.
pub fn clearDirtyRangeCacheOnly(file_id: u64, start_off: u64, len: u64) u32 {
    if (len == 0) return 0;
    const span = pageSpan(start_off, len);
    const Clear = struct {
        cleared: u32 = 0,
        fn visit(self: *@This(), _: *CacheState, e: *Entry) void {
            if (e.dirty and pmm.frameRefCount(e.frame) == 1) {
                e.dirty = false;
                self.cleared += 1;
            }
        }
    };
    var clear: Clear = .{};
    const h = cache.acquire();
    defer h.release();
    forRange(h.ptr, file_id, span.first, span.end, &clear);
    return clear.cleared;
}

/// Where the background sweep goes on from. (p:cache)
var sweep_at: u32 = 0;

/// Check the next `pages` clean resident pages against their checksums,
/// going round the table from call to call: a sweep the size of the cache
/// at once costs a CPU's worth of memory reads. Returns pages found changed
/// so far (since boot).
pub fn verifySome(pages: u32) u64 {
    if (!VERIFY) return 0;
    var left = pages;
    var steps: u32 = 0;
    while (true) {
        // 64 pages per lock hold: each check reads a whole page.
        const h = cache.acquire();
        defer h.release();
        const s = h.ptr;
        const limit = @min(s.high, SCAN_CHUNK);
        var batch: u32 = 64;
        while (left > 0 and batch > 0 and steps < limit) : (steps += 1) {
            if (sweep_at >= s.high) sweep_at = 0;
            const e = &s.entries[sweep_at];
            sweep_at += 1;
            if (!e.valid or !e.summed or e.dirty) continue;
            s.verify(e);
            left -= 1;
            batch -= 1;
        }
        if (left == 0 or steps >= limit) return s.corrupt_seen;
    }
}

/// The next changed page verify() queued; its pin, if `pinned`, is the
/// caller's to release.
pub fn takeCorrupt() ?Corrupt {
    const h = cache.acquire();
    defer h.release();
    const s = h.ptr;
    if (s.n_corrupt == 0) return null;
    s.n_corrupt -= 1;
    return s.corrupt[s.n_corrupt];
}

/// Number of currently-resident pages.
pub fn residentCount() u32 {
    const h = cache.acquire();
    defer h.release();
    return h.ptr.resident;
}

/// PMM reclaim callback (registered from init()): pmm.tryReclaim calls it
/// when an allocation fails, to hand frames back by dropping evictable pages
/// — pure read cache, a future refill from disk at worst. Dirty pages wait
/// for pgflushd. Frees at least a batch when it can, so pressure doesn't
/// return on the very next fault; returns the count freed.
///
/// NON-BLOCKING by contract — it runs from a page fault, possibly under the
/// caller's as_lock — so no I/O. One sweep of the pool from the hand, in
/// SCAN_CHUNK holds.
pub fn reclaim(needed: u32) u32 {
    if (needed == 0) return 0;
    const want = @max(needed, RECLAIM_BATCH);
    var freed: u32 = 0;
    var swept: u32 = 0;
    while (true) {
        const h = cache.acquire();
        defer h.release();
        const s = h.ptr;
        if (swept >= s.high) return freed;
        var held: u32 = 0;
        while (held < SCAN_CHUNK and swept < s.high) : ({
            held += 1;
            swept += 1;
        }) {
            if (s.hand >= s.high) s.hand = 0;
            const e = &s.entries[s.hand];
            s.hand += 1;
            if (!CacheState.evictable(e)) continue;
            pmm.releaseFrame(e.frame);
            s.remove(e);
            s.reclaimed += 1;
            freed += 1;
            if (freed >= want) return freed;
        }
    }
}
