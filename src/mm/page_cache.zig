// Unified page cache — a global (file-identity, page-offset) -> physical frame
// map. This is the unifying layer ZigOS lacked: one refcounted cache of file
// pages that — once fully wired in — backs BOTH the read() path and file-backed
// mmap, so a page read by one process and mmap'd by another is the SAME
// physical frame instead of independent copies.
//
// Today each filesystem keeps a private block cache (ext2's CACHE_SECTORS
// window) and file-backed mmap eagerly copies every touched page into a private
// frame. This module is the replacement: its frames can be MAPPED (shared,
// refcounted) rather than copied.
//
// ============================ MVP STATUS (Slice 1) ===========================
// Data structure + lifetime discipline ONLY. There is no fault-handler or
// read() integration yet (slices 2 and 3). The point of this slice is to build
// and PROVE the core in isolation — see src/test/page_cache_selftest.zig
// (boot_mode = 14), which exercises hit/miss, set-eviction, refcount pinning,
// and leak-freedom before any high-blast-radius fault-path surgery.
//
// ============================== STRUCTURE ====================================
// Set-associative, exactly like a TLB or a CPU cache. A key hashes to ONE set;
// within the set we linear-scan WAYS entries. A miss evicts a victim WITHIN
// that set. This deliberately avoids open-addressing probe chains and tombstone
// bookkeeping (the classic source of cache-deletion bugs) — a set is a tiny
// fixed array and eviction just overwrites one way.
//
// ============================ REFCOUNT DISCIPLINE ============================
// Leans entirely on pmm's per-frame u8 refcount (pmm.acquireFrame/releaseFrame/
// frameRefCount), the same mechanism COW and shared-anon already use:
//
//   getOrAlloc (miss) -> pmm.allocFrame()   gives refcount 1  = the CACHE's ref
//   pin               -> pmm.acquireFrame() -> >= 2           = a MAPPER's ref
//   (mapper unmaps)   -> pmm.releaseFrame() -> back to 1        (cache still holds)
//   evict             -> only when refcount == 1: releaseFrame -> 0, frame freed
//
// THE KEY INVARIANT: refcount == 1  <=>  cache-only, and evictable <=>
// (cache-only AND not dirty). A dirty cache-only page — a MAP_SHARED write whose
// mapper has gone but whose bytes aren't on disk yet (Slice 3c) — is held until
// syncCacheFile flushes + clears it; chooseSlot skips it. For non-dirty pages
// (every page before Slice 3c, and all read()/RO-mmap pages) evictable still
// reduces to refcount == 1. It holds
// because a cache frame's physical address is PRIVATE to the cache until pin()
// hands it out, and pin() runs under the cache lock. So a refcount-1 frame can only
// transition to 2 via the lock we hold during an eviction scan — eviction can
// never pull a frame out from under a live mapping. (Concurrent unmap can only
// drop a refcount toward 1, which merely makes a page MORE evictable: safe.)
//
// ============================== LOCKING ======================================
// One leaf-ish SpinLock; all cached state lives behind it in a Guarded blob
// (util/guarded.zig), so touching an Entry without the lock is not a race but
// a different-looking piece of code. Lock order is page_cache lock -> pmm
// locks (we call allocFrame/freeFrame while holding it; acquireFrame is a
// lock-free CAS so it adds no edge). Nothing acquires this lock from an IRQ
// handler, so a plain (non-IrqSave) acquire is correct.

const pmm = @import("pmm.zig");
const Phys = @import("../util/addr.zig").Phys;
const spinlock = @import("../proc/spinlock.zig");
const Guarded = @import("../util/guarded.zig").Guarded;

pub const PAGE_SIZE: usize = 4096;

// 8 ways x 256 sets = 2048 cached pages = 8 MiB max resident (allocated lazily,
// only as pages are inserted). Entry table is ~64 KiB of BSS. NUM_SETS must be
// a power of two (setIndex masks with NUM_SETS-1).
pub const WAYS: u32 = 8;
pub const NUM_SETS: u32 = 256;
pub const CAPACITY: u32 = WAYS * NUM_SETS;

comptime {
    if (NUM_SETS & (NUM_SETS - 1) != 0) @compileError("NUM_SETS must be a power of two");
}

const SET_MASK: u64 = NUM_SETS - 1;

// pmm's per-frame refcount is a u8 and acquireFrame PANICS at 255. A single
// file page shared by very many mappings could approach that ceiling, so the
// pin / insert paths refuse to take a new mapper reference once a frame reaches
// this and serve the caller an UNCACHED private copy instead — correct, just
// unshared. The margin must cover the window between our under-lock refcount
// check and acquireFrame: cloneAddressSpace's acquireFrame (vmm.zig) is
// LOCK-FREE and runs without page_cache.lock, so up to MAX_CPUS-1 concurrent
// forks of the same frame can bump it after we pass the check. 255 - MAX_CPUS
// (32) = 223 keeps the worst-case fork storm strictly under 255. In practice no
// page is mapped by ~220 tasks at once, so the uncached fallback never fires.
pub const PIN_SATURATION: u8 = 223;

// File-identity namespace tags occupy the high bits of a cache key's file_id,
// so one filesystem's inode keyspace can't collide with another's. Slices 2/3
// use only ext2; a future filesystem takes a different high tag. Shared by the
// mmap fault path (fault.zig) and the write/truncate/free invalidation (ext2).
pub const FILE_ID_EXT2: u64 = 1 << 63;
pub fn ext2FileId(inum: u32) u64 {
    return FILE_ID_EXT2 | @as(u64, inum);
}

/// One cached page. Lives inside `CacheState`, i.e. behind the cache lock —
/// an `*Entry` is reachable only through a held token, so every field is
/// lock-protected by construction.
const Entry = struct {
    file_id: u64 = 0, // unique file identity, e.g. (mount_id << 32) | inode_num
    page_off: u64 = 0, // page-aligned byte offset within the file
    frame: Phys = Phys.of(0), // physical frame backing this page
    valid: bool = false, // slot occupied
    // MAP_SHARED writeback (Slice 3c): set when a writable shared file
    // mapping has (or may have) modified this page since the last disk write.
    // A dirty page is NEVER evicted (chooseSlot skips it) — that would discard
    // unflushed data. vfs.syncCacheFile writes dirty pages back on msync/munmap;
    // clearDirtyIfCacheOnly clears the bit once no writable mapper remains.
    dirty: bool = false,
};

const Set = struct {
    ways: [WAYS]Entry = [_]Entry{.{}} ** WAYS,
    hand: u32 = 0, // round-robin eviction cursor (FIFO-ish, skips pinned ways)
};

/// Everything the cache lock protects, behind the lock (util/guarded.zig).
/// findWay/chooseSlot are methods here: their old "runs with `lock` already
/// held" comment-contract is now the receiver type — a `*CacheState` exists
/// only inside a token window.
const CacheState = struct {
    sets: [NUM_SETS]Set = [_]Set{.{}} ** NUM_SETS,
    registered: bool = false,

    // Diagnostic counters — read out via statsSnapshot (self-test, a future
    // /proc/meminfo).
    hits: u64 = 0,
    misses: u64 = 0,
    inserts: u64 = 0,
    evictions: u64 = 0,
    full_skips: u64 = 0, // insert found every way of the set pinned -> couldn't cache
    reclaimed: u64 = 0, // clean cache-only pages dropped by reclaim() under PMM pressure (3d-1)

    fn findWay(self: *CacheState, file_id: u64, page_off: u64) ?*Entry {
        const set = &self.sets[setIndexFor(file_id, page_off)];
        for (&set.ways) |*e| {
            if (e.valid and e.file_id == file_id and e.page_off == page_off) return e;
        }
        return null;
    }

    /// Pick a slot in `set_idx` for a new entry: first any empty way, else
    /// evict an unpinned (refcount==1) way chosen round-robin via the set's
    /// hand. Returns null if every way is valid AND pinned (refcount > 1) —
    /// the set is fully in use by live mappings and cannot accept a new page
    /// right now.
    fn chooseSlot(self: *CacheState, set_idx: u32) ?*Entry {
        const set = &self.sets[set_idx];

        // Prefer an empty way.
        for (&set.ways) |*e| {
            if (!e.valid) return e;
        }

        // All valid: sweep from the hand for the first evictable (unpinned,
        // clean) way.
        var i: u32 = 0;
        while (i < WAYS) : (i += 1) {
            const idx = (set.hand + i) % WAYS;
            const e = &set.ways[idx];
            // refcount == 1 means cache-only (see header invariant): safe to
            // evict — UNLESS it's dirty (unflushed MAP_SHARED write), which
            // must not be discarded. Dirty pages are released by
            // syncCacheFile, not eviction; a set full of dirty pages just
            // falls back to an uncached insert (rare; dirty pages are flushed
            // at msync/munmap and the bit cleared).
            if (pmm.frameRefCount(e.frame) == 1 and !e.dirty) {
                pmm.releaseFrame(e.frame); // 1 -> 0: frame returns to the pool
                e.* = .{};
                set.hand = (idx + 1) % WAYS;
                self.evictions += 1;
                return e;
            }
        }

        // Every way pinned by a live mapping — caller proceeds uncached.
        return null;
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
    };
}

/// Clear the cache and reset stats. For the MVP this is called by the self-test
/// task; the eventual read()/mmap integration will call it once from mm init.
/// Idempotent. Frees any frames still resident (refcount-1 ones); a frame a
/// mapper still holds survives the reset until the mapper releases it.
pub fn init() void {
    const h = cache.acquire();
    defer h.release();
    for (&h.ptr.sets) |*set| {
        for (&set.ways) |*e| {
            // Drop the CACHE's reference unconditionally (mirrors invalidate):
            // refcount 1 → frame freed here; refcount > 1 → a mapper still
            // holds it and it's freed by that mapper's own release. Gating
            // this on refcount == 1 (the original code) ORPHANED the cache's
            // ref for still-mapped frames: the mapper's later release parked
            // the count at 1 forever — a permanent frame leak.
            if (e.valid) pmm.releaseFrame(e.frame);
            e.* = .{};
        }
        set.hand = 0;
    }
    h.ptr.hits = 0;
    h.ptr.misses = 0;
    h.ptr.inserts = 0;
    h.ptr.evictions = 0;
    h.ptr.full_skips = 0;
    h.ptr.reclaimed = 0;
    if (!h.ptr.registered) {
        spinlock.registerLock("page_cache.lock", &cache.lock);
        // PMM invokes reclaim() under memory pressure to shed clean cache pages
        // (Slice 3d-1). One-shot: init() runs at boot (main.zig) and again per
        // self-test, so the guard keeps a single registration. registerReclaim
        // takes no lock (plain array append, boot-time/single-threaded), so it's
        // safe to call here while `lock` is held.
        pmm.registerReclaim(reclaim);
        h.ptr.registered = true;
    }
}

/// Which set a key lands in. Public so the self-test (and a future introspection
/// tool) can reason about collisions; harmless to expose.
pub fn setIndexFor(file_id: u64, page_off: u64) u32 {
    // Mix both halves with distinct odd multipliers (fibonacci-hash constants);
    // page_off carries the entropy for sequential reads, file_id separates files.
    const h = (file_id *% 0x9E3779B97F4A7C15) ^ (page_off *% 0xC2B2AE3D27D4EB4F);
    return @intCast((h >> 17) & SET_MASK);
}

/// ⚠️ SELF-TEST ONLY. Find a resident page WITHOUT pinning it. The frame is
/// unprotected the moment the cache lock drops at return — concurrent eviction /
/// invalidation can free it before the caller dereferences (UAF). That is
/// tolerable only in the single-threaded self-test. Production readers use
/// `pin` (see vfs.readThroughCache): copy under the pin, then releaseFrame.
pub fn lookup(file_id: u64, page_off: u64) ?Phys {
    const h = cache.acquire();
    defer h.release();
    if (h.ptr.findWay(file_id, page_off)) |e| {
        h.ptr.hits += 1;
        return e.frame;
    }
    h.ptr.misses += 1;
    return null;
}

/// Look up and PIN for mapping: atomically (under `lock`) bumps the frame's
/// refcount so eviction cannot free it. The caller MUST pmm.releaseFrame when
/// the mapping is torn down (vmm.unmapUserRange already does this). Returns null
/// on miss — the caller then reads the page into a private frame and publishes
/// it with `insertFilled`. Also returns null (treated as a miss) when the
/// resident frame is at PIN_SATURATION, so the caller serves an uncached copy
/// rather than tripping pmm.acquireFrame's 255 ceiling.
pub fn pin(file_id: u64, page_off: u64) ?Phys {
    const h = cache.acquire();
    defer h.release();
    if (h.ptr.findWay(file_id, page_off)) |e| {
        if (pmm.frameRefCount(e.frame) >= PIN_SATURATION) {
            h.ptr.misses += 1; // refuse to saturate; caller maps an uncached copy
            return null;
        }
        pmm.acquireFrame(e.frame); // 1 -> 2 (or N -> N+1); now un-evictable
        h.ptr.hits += 1;
        return e.frame;
    }
    h.ptr.misses += 1;
    return null;
}

pub const GetResult = struct {
    frame: Phys, // physical frame for the page
    fresh: bool, // true: freshly allocated, caller must fill it from disk; false: cache hit, already filled
};

/// ⚠️ SELF-TEST ONLY. Get the frame for (file_id, page_off), allocating +
/// inserting a fresh frame on miss. On a hit returns {frame, fresh=false}
/// (already populated). On a miss allocates a zeroed-by-pmm frame, inserts it,
/// and returns {frame, fresh=true} for the caller to fill. Returns null only
/// if the set is entirely pinned AND no fresh frame is available.
///
/// Why production paths must NOT use this: the miss path PUBLISHES the frame
/// before the caller fills it — a concurrent pin() would map a garbage page —
/// and the published frame is refcount-1 (cache-only), i.e. EVICTABLE while
/// the caller's fill I/O is still writing into it (write-into-freed-frame).
/// Both hazards vanish in the single-threaded self-test, which is what this
/// predates-insertFilled API is kept for. Real code uses pin + insertFilled
/// (fill a private frame with no lock held, publish atomically) — see
/// vfs.readThroughCache and fault.faultInCachePage.
pub fn getOrAlloc(file_id: u64, page_off: u64) ?GetResult {
    const h = cache.acquire();
    defer h.release();

    if (h.ptr.findWay(file_id, page_off)) |e| {
        h.ptr.hits += 1;
        return .{ .frame = e.frame, .fresh = false };
    }
    h.ptr.misses += 1;

    const slot = h.ptr.chooseSlot(setIndexFor(file_id, page_off)) orelse {
        h.ptr.full_skips += 1;
        return null;
    };
    const phys = pmm.allocFrame() orelse {
        h.ptr.full_skips += 1;
        return null;
    };
    slot.* = .{ .file_id = file_id, .page_off = page_off, .frame = phys, .valid = true };
    h.ptr.inserts += 1;
    return .{ .frame = phys, .fresh = true };
}

/// Publish a caller-filled private frame into the cache for (file_id, page_off)
/// and return the frame the caller should MAP (read-only + COW). This is the
/// race-free fault-path insert: the caller allocates a private frame, fills it
/// from disk with NO lock held (so no other mapper can ever observe a
/// half-filled page), then calls this to publish it atomically.
///
/// `frame` MUST be a freshly pmm.allocFrame'd page (refcount 1) the caller owns.
/// On return the caller holds exactly ONE mapper reference on the returned frame
/// (to be balanced by freeFrame at unmap). Three outcomes:
///   - published — the input frame is now cached (refcount 2 = cache + caller);
///     returns the input frame.
///   - lost the race — another CPU cached this page while we read; we drop the
///     input frame and adopt the resident one (acquireFrame); returns IT.
///   - uncached — the set is fully pinned, or the resident page is at
///     PIN_SATURATION; the input frame stays private (refcount 1, NOT cached);
///     returns the input frame. The caller maps it privately: correct, unshared.
pub fn insertFilled(file_id: u64, page_off: u64, frame: Phys) Phys {
    const h = cache.acquire();
    defer h.release();

    if (h.ptr.findWay(file_id, page_off)) |e| {
        // Another CPU published this page first. Prefer the shared resident copy
        // unless it's near the pmm refcount ceiling (acquireFrame panics at 255);
        // in that pathological case keep our own frame private.
        if (pmm.frameRefCount(e.frame) < PIN_SATURATION) {
            pmm.releaseFrame(frame); // discard our wasted fill (1 -> 0, freed)
            pmm.acquireFrame(e.frame); // take a mapper ref on the resident copy
            h.ptr.hits += 1;
            return e.frame;
        }
        h.ptr.full_skips += 1;
        return frame; // saturated: stay private (refcount 1, uncached)
    }

    const slot = h.ptr.chooseSlot(setIndexFor(file_id, page_off)) orelse {
        // Every way pinned by a live mapping — can't cache. Map privately.
        h.ptr.full_skips += 1;
        return frame; // refcount 1, uncached
    };
    slot.* = .{ .file_id = file_id, .page_off = page_off, .frame = frame, .valid = true };
    pmm.acquireFrame(frame); // 1 (cache's ref) -> 2 (+ this mapper's ref)
    h.ptr.inserts += 1;
    return frame;
}

/// Drop a specific page from the cache (e.g. the file was truncated or written
/// through a non-mmap path). Releases the cache's reference; if a mapper still
/// holds the frame it survives until they release. NOTE: this does not yet keep
/// existing mappers coherent with a subsequent re-read — read()/mmap coherence
/// is slice 3. Returns true if the page was resident.
pub fn invalidate(file_id: u64, page_off: u64) bool {
    const h = cache.acquire();
    defer h.release();
    if (h.ptr.findWay(file_id, page_off)) |e| {
        pmm.releaseFrame(e.frame); // drop the cache's reference
        e.* = .{};
        return true;
    }
    return false;
}

/// Drop every cached page overlapping the byte range [start_off, start_off+len)
/// of `file_id`. Called after a file write so a later mmap fault / cached read
/// re-fills from disk instead of serving the pre-write bytes. The cache's
/// reference is released; a frame an mmap mapper still holds survives (with
/// now-stale contents) until that mapping is torn down — acceptable for
/// MAP_PRIVATE, whose write()-coherence POSIX leaves unspecified. One lock hold
/// for the whole range (its pages scatter across sets). Returns pages dropped.
pub fn invalidateRange(file_id: u64, start_off: u64, len: u64) u32 {
    if (len == 0) return 0;
    const PG: u64 = PAGE_SIZE;
    const first = start_off & ~(PG - 1); // floor to page boundary
    const end = start_off +| len; // exclusive; saturating so a corrupt offset
    // can't overflow-panic (ReleaseSafe) the spinlocked path. first <= end always.
    const h = cache.acquire();
    defer h.release();
    var dropped: u32 = 0;
    // Two ways to cover the range, both O(CAPACITY)-bounded so no held-lock
    // runaway on a hostile/huge len: probe each page offset (cost ~ range), or
    // scan the whole cache once (cost ~ CAPACITY). Probing wins for a normal
    // small write; the scan wins — and stays bounded — once the range spans more
    // pages than the cache can possibly hold.
    const span_pages = (end -| first +| (PG - 1)) / PG;
    if (span_pages > CAPACITY) {
        for (&h.ptr.sets) |*set| {
            for (&set.ways) |*e| {
                // !e.dirty: keep a MAP_SHARED-written page (see the probe branch).
                if (e.valid and !e.dirty and e.file_id == file_id and e.page_off >= first and e.page_off < end) {
                    pmm.releaseFrame(e.frame);
                    e.* = .{};
                    dropped += 1;
                }
            }
        }
        return dropped;
    }
    var off = first;
    while (off < end) : (off += PG) {
        if (h.ptr.findWay(file_id, off)) |e| {
            // A dirty page is a live MAP_SHARED mapping that has been written but
            // not yet flushed. Dropping it here (write() invalidating an mmap'd
            // file) would (1) orphan the mapper's frame so a later read()/mmap
            // MISSES and inserts a SECOND physical frame for the same file page —
            // divergence, breaking the cache's single-source invariant — and
            // (2) discard the dirty bit so the mapping's writes are never written
            // back. So keep it: the shared mapping is authoritative; this write()'s
            // bytes reached disk but are shadowed by, and will be overwritten by,
            // the mapping's eventual writeback. (write()-vs-active-MAP_SHARED
            // ordering is POSIX-unspecified; write-through coherence is future work.)
            if (e.dirty) continue;
            pmm.releaseFrame(e.frame);
            e.* = .{};
            dropped += 1;
        }
    }
    return dropped;
}

/// Drop EVERY cached page of `file_id` (any offset). Called when a file is
/// truncated or its inode is freed. The freed-inode case is also a SECURITY
/// boundary: a reused inode must not serve the deleted file's pages (same
/// file_id = inode). Walks all sets under the lock; cheap relative to the rare
/// truncate/unlink that triggers it. Returns pages dropped.
pub fn invalidateFile(file_id: u64) u32 {
    const h = cache.acquire();
    defer h.release();
    var dropped: u32 = 0;
    for (&h.ptr.sets) |*set| {
        for (&set.ways) |*e| {
            if (e.valid and e.file_id == file_id) {
                pmm.releaseFrame(e.frame);
                e.* = .{};
                dropped += 1;
            }
        }
    }
    return dropped;
}

// ============================ DIRTY TRACKING (Slice 3c) ======================
// A MAP_SHARED file mapping maps the cache frame WRITABLE; the page-fault path
// flags the page dirty when it does so. msync/munmap then write dirty pages back
// to disk and (when no writable mapper remains) clear the flag. The cache frame
// is the single source of truth — every writable mapper of a page writes the
// SAME frame — so a flush can read it back at any time and persist the latest
// bytes. Dirty marking here is coarse (a faulted-writable page is treated as
// dirty even if only read); the cost is re-persisting unchanged pages, never
// data loss. (A precise mkwrite scheme — map RO, mark dirty on the write fault —
// is a future optimization.)

/// Mark a resident page dirty. Called by the fault path right after it maps a
/// page writable for a shared mapping. No-op if the page isn't resident — which
/// only happens for the uncached fallback (set fully pinned): such a page is
/// private + unshared + untracked, and is NOT written back (documented edge).
pub fn markDirty(file_id: u64, page_off: u64) void {
    const h = cache.acquire();
    defer h.release();
    if (h.ptr.findWay(file_id, page_off)) |e| e.dirty = true;
}

pub const DirtyPage = struct {
    page_off: u64,
    frame: Phys, // pinned (acquireFrame'd) — caller MUST pmm.releaseFrame after writeback
};

/// Find the LOWEST-offset dirty page of `file_id` with page_off >= `from_off`,
/// PIN it (acquireFrame, so writeback I/O can't race eviction or a concurrent
/// unmap freeing the frame), and return it WITHOUT clearing the dirty flag.
/// Returns null when no dirty page remains at/above `from_off`.
///
/// The caller (vfs.syncCacheFile) loops with `from_off = result.page_off + PAGE`
/// so the cursor strictly increases — termination is guaranteed even though the
/// flag is left set (msync must keep it set: the still-writable PTE means future
/// writes won't re-fault to re-mark it, so clearing now would lose them). The
/// dirty bit is cleared separately by clearDirtyIfCacheOnly once the last
/// writable mapper is gone. A page at PIN_SATURATION is skipped (left for a later
/// flush) rather than tripping acquireFrame's 255 ceiling.
pub fn takeNextDirty(file_id: u64, from_off: u64) ?DirtyPage {
    const h = cache.acquire();
    defer h.release();
    var best: ?*Entry = null;
    for (&h.ptr.sets) |*set| {
        for (&set.ways) |*e| {
            if (e.valid and e.dirty and e.file_id == file_id and e.page_off >= from_off) {
                if (pmm.frameRefCount(e.frame) >= PIN_SATURATION) continue; // skip; flush later
                if (best == null or e.page_off < best.?.page_off) best = e;
            }
        }
    }
    const e = best orelse return null;
    pmm.acquireFrame(e.frame); // pin across the (lockless) writeback I/O
    return .{ .page_off = e.page_off, .frame = e.frame };
}

pub const GlobalDirtyPage = struct {
    file_id: u64,
    page_off: u64,
    frame: Phys, // pinned (acquireFrame'd) — caller MUST pmm.releaseFrame after writeback
    next_idx: u32, // flat way cursor to resume the scan from on the next call
};

/// Global dirty enumeration for the background flush daemon (Slice 3d-2) — the
/// cross-file analogue of takeNextDirty. Scans the cache linearly from flat way
/// index `from_idx` (= set*WAYS + way) and returns the FIRST dirty page found,
/// PINNED (acquireFrame, so the lockless writeback I/O can't race eviction or an
/// unmap freeing the frame) and WITHOUT clearing the flag, plus `next_idx` to
/// resume from. Returns null once no dirty page remains at/after `from_idx` (the
/// pass is complete). Order within a pass is arbitrary — every dirty page is
/// flushed regardless — and the strictly-advancing cursor guarantees the daemon's
/// loop terminates. A page at PIN_SATURATION is skipped (flushed a later pass)
/// rather than tripping acquireFrame's 255 ceiling.
pub fn takeNextDirtyGlobal(from_idx: u32) ?GlobalDirtyPage {
    const h = cache.acquire();
    defer h.release();
    var idx = from_idx;
    while (idx < CAPACITY) : (idx += 1) {
        const e = &h.ptr.sets[idx / WAYS].ways[idx % WAYS];
        if (e.valid and e.dirty) {
            if (pmm.frameRefCount(e.frame) >= PIN_SATURATION) continue; // skip; flush a later pass
            pmm.acquireFrame(e.frame); // pin across the lockless writeback I/O
            return .{ .file_id = e.file_id, .page_off = e.page_off, .frame = e.frame, .next_idx = idx + 1 };
        }
    }
    return null;
}

/// Clear the dirty flag on a page IFF it's now cache-only (refcount == 1), i.e.
/// no writable mapper remains that could store new bytes without re-faulting.
/// Called by munmap/teardown AFTER the region's PTEs are torn down and the
/// page's final bytes have been flushed. If another mapper still holds the page
/// (refcount > 1) the flag is left set — that mapper keeps it dirty until its own
/// teardown flushes + clears it. Returns true if the flag was cleared.
pub fn clearDirtyIfCacheOnly(file_id: u64, page_off: u64) bool {
    const h = cache.acquire();
    defer h.release();
    if (h.ptr.findWay(file_id, page_off)) |e| {
        if (e.dirty and pmm.frameRefCount(e.frame) == 1) {
            e.dirty = false;
            return true;
        }
    }
    return false;
}

/// Clear the dirty flag on every cache-only (refcount==1) page of `file_id` in
/// [start_off, start_off+len). Used at process teardown so a MAP_SHARED region's
/// pages — now that this address space's PTEs are gone (destroyAddressSpace ran
/// first) — rejoin the evictable pool instead of lingering dirty-and-unevictable
/// forever (chooseSlot skips dirty pages). refcount-gated, so a page another AS
/// still maps (refcount > 1) stays dirty — that AS owns its own writeback.
///
/// Deliberately does NOT write back: teardown is I/O-free by design (the OOM-kill
/// path reaches it under memory pressure and must stay light). Persistence is via
/// msync()/munmap() before exit; a bare exit discards unflushed shared writes.
/// Same bounded dual-strategy (probe vs full scan) as invalidateRange. Returns
/// the number of pages cleared.
pub fn clearDirtyRangeCacheOnly(file_id: u64, start_off: u64, len: u64) u32 {
    if (len == 0) return 0;
    const PG: u64 = PAGE_SIZE;
    const first = start_off & ~(PG - 1);
    const end = start_off +| len; // saturating (corrupt offset can't overflow-panic)
    const h = cache.acquire();
    defer h.release();
    var cleared: u32 = 0;
    const span_pages = (end -| first +| (PG - 1)) / PG;
    if (span_pages > CAPACITY) {
        for (&h.ptr.sets) |*set| {
            for (&set.ways) |*e| {
                if (e.valid and e.dirty and e.file_id == file_id and
                    e.page_off >= first and e.page_off < end and
                    pmm.frameRefCount(e.frame) == 1)
                {
                    e.dirty = false;
                    cleared += 1;
                }
            }
        }
        return cleared;
    }
    var off = first;
    while (off < end) : (off += PG) {
        if (h.ptr.findWay(file_id, off)) |e| {
            if (e.dirty and pmm.frameRefCount(e.frame) == 1) {
                e.dirty = false;
                cleared += 1;
            }
        }
    }
    return cleared;
}

/// Number of currently-resident pages. Diagnostic (walks all sets under lock).
pub fn residentCount() u32 {
    const h = cache.acquire();
    defer h.release();
    var n: u32 = 0;
    for (&h.ptr.sets) |*set| {
        for (&set.ways) |*e| {
            if (e.valid) n += 1;
        }
    }
    return n;
}

/// PMM reclaim callback (registered once from init(); see pmm.registerReclaim).
/// pmm.tryReclaim invokes this when an allocation fails — currently only the
/// fault-handler OOM path — to hand frames back by discarding CLEAN cache-only
/// pages: refcount == 1 (no live mapper) AND !dirty (no unflushed MAP_SHARED
/// write). Such a page is pure read-cache; dropping it costs only a future refill
/// from disk, never data. DIRTY pages are skipped here — their writeback needs a
/// blocking context (a flush daemon cleans them first, Slice 3d-2). Stops once
/// `needed` frames are freed; returns the count actually freed.
///
/// NON-BLOCKING by contract — tryReclaim runs from a page fault (possibly under a
/// caller's as_lock), so this does no I/O. It holds the cache lock and calls
/// releaseFrame under it: the same `page_cache lock -> pmm` order, and the same refcount==1
/// stability argument, as chooseSlot's eviction. A refcount-1 frame is mapped
/// nowhere, and the only way to raise it to 2 is pin()'s acquireFrame, which runs
/// under this same lock — so the count cannot rise under us between the check and
/// releaseFrame. A concurrent unmap can only drop a count toward 1 (more
/// evictable: safe). Linear scan is fine: every clean page refills identically,
/// so which ones we drop doesn't matter for correctness.
pub fn reclaim(needed: u32) u32 {
    if (needed == 0) return 0;
    const h = cache.acquire();
    defer h.release();
    var freed: u32 = 0;
    for (&h.ptr.sets) |*set| {
        for (&set.ways) |*e| {
            if (freed >= needed) return freed;
            if (!e.valid or e.dirty) continue;
            if (pmm.frameRefCount(e.frame) != 1) continue;
            pmm.releaseFrame(e.frame); // 1 -> 0: frame returns to the pool
            e.* = .{};
            freed += 1;
            h.ptr.reclaimed += 1;
        }
    }
    return freed;
}

