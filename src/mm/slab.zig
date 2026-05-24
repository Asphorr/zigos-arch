// Slab allocator — fixed-size object cache on top of PMM.
//
// Each Cache holds objects of one fixed `obj_size + obj_align`. A Slab is one
// PMM page: a small header at offset 0 followed by N objects. Free objects
// are threaded into a singly-linked freelist using their own first 8 bytes
// (overwritten on alloc, so the user sees uninitialized memory).
//
// Why bother when we already have heap.kmalloc?
//   - O(1) alloc/free common path. heap.kmalloc walks the global free list.
//   - No fragmentation. Every object in a cache is the same size; freed objects
//     are always perfectly reusable for the next alloc of the same type.
//   - Per-cache stats (live, peak, total allocs, slab count). Tells you which
//     subsystem is leaking before the global heap shows pressure.
//   - Cache-line locality. Objects of one type cluster within a 4 KB page
//     instead of being scattered across the heap.
//
// The slab page itself is 4 KB (one PMM frame). We don't use multi-page slabs
// — the per-object overhead from a tiny header (~32 bytes) is negligible.
//
// Slab page layout:
//   [Slab header]  [pad to alignUp(sizeof(header), obj_align)]  [obj0]...[objN-1]
//
// Slab pointer recovery from any object pointer uses SLAB_MASK (mask off the
// low 12 bits to land on the page base). That works regardless of header
// size — the only constraint is that the slab page itself is 4 KB-aligned,
// which pmm.allocFrame guarantees.

const std = @import("std");
const pmm = @import("pmm.zig");
const paging = @import("paging.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const debug = @import("../debug/debug.zig");
const heap = @import("heap.zig");
const kasan = @import("../debug/kasan.zig");

const SLAB_BYTES: usize = 4096;
const SLAB_MASK: usize = ~(SLAB_BYTES - 1);
const SLAB_MAGIC: u32 = 0x51AB7AC0; // "SlabTaco" — distinctive in dumps

/// One-byte tag at offset 4 of the slab header. Differentiates valid slab
/// pages from random PMM pages so corrupted free()s panic instead of
/// scribbling on a random PMM frame.
const SLAB_TYPE_TAG: u8 = 0xCA;

const FreeObj = extern struct {
    next: ?*FreeObj,
};

/// Per-slab metadata at offset 0 of the page. Limited to ≤64 bytes — see
/// alignment requirement above.
const Slab = extern struct {
    magic: u32, // 0x51AB7AC0
    type_tag: u8, // SLAB_TYPE_TAG
    _pad0: [3]u8 = .{ 0, 0, 0 },
    cache: *Cache, // 8 bytes
    free_list: ?*FreeObj, // 8 bytes
    next: ?*Slab, // 8 bytes
    prev: ?*Slab, // 8 bytes
    free_count: u16, // 2 bytes
    used_count: u16, // 2 bytes
    list_kind: u8, // 0=partial, 1=full, 2=empty (cheap O(1) move)
    _pad1: [3]u8 = .{ 0, 0, 0 },
    // total: 4+1+3+8+8+8+8+2+2+1+3 = 48 bytes
};

const LIST_PARTIAL: u8 = 0;
const LIST_FULL: u8 = 1;
const LIST_EMPTY: u8 = 2;

pub const NAME_BUF: usize = 24;

pub const Cache = struct {
    name_buf: [NAME_BUF]u8 = [_]u8{0} ** NAME_BUF,
    name_len: u8 = 0,
    obj_size: u32,
    obj_align: u32,
    objs_per_slab: u16,
    obj_offset: u16, // byte offset from Slab* to first object

    // Slab lists. Doubly-linked so we can move slabs between lists in O(1).
    partial_head: ?*Slab = null,
    full_head: ?*Slab = null,
    empty_head: ?*Slab = null,

    // Stats
    total_allocs: u64 = 0,
    total_frees: u64 = 0,
    live_objs: u32 = 0,
    peak_live_objs: u32 = 0,
    slab_count: u32 = 0,
    slab_high_water: u32 = 0,

    // How many empty slabs to keep around before returning them to PMM.
    // Default 1 — one full empty page worth of breathing room before the
    // next alloc churns PMM. Set with `setEmptyKeep`.
    empty_keep: u16 = 1,
    empty_count: u16 = 0,

    lock: SpinLock = .{},
    next_cache: ?*Cache = null,
};

var cache_list_head: ?*Cache = null;
var cache_list_lock: SpinLock = .{};

fn alignUp(v: usize, a: usize) usize {
    return (v + a - 1) & ~(a - 1);
}

/// Create a new slab cache for objects of the given size + alignment.
/// `name` is copied into the Cache (truncated to NAME_BUF-1 bytes), so the
/// caller doesn't need to keep the source memory live.
/// Returns null if the heap can't allocate the Cache struct or if the
/// requested size is too large for a 4 KB slab to hold even one object.
pub fn createCache(name: []const u8, obj_size: u32, obj_align: u32) ?*Cache {
    // Min object size is 8 (size of FreeObj.next pointer). Sub-8 objects
    // would have nowhere to thread the freelist.
    var size = obj_size;
    if (size < @sizeOf(FreeObj)) size = @sizeOf(FreeObj);
    var alignment = obj_align;
    if (alignment < @alignOf(FreeObj)) alignment = @alignOf(FreeObj);

    const obj_offset = alignUp(@sizeOf(Slab), alignment);
    if (obj_offset >= SLAB_BYTES) return null;
    const objs_per_slab = (SLAB_BYTES - obj_offset) / size;
    if (objs_per_slab == 0) return null;

    const buf = heap.kmallocAligned(@sizeOf(Cache), @alignOf(Cache)) orelse return null;
    const cache: *Cache = @ptrCast(@alignCast(buf));
    cache.* = .{
        .obj_size = size,
        .obj_align = alignment,
        .objs_per_slab = @intCast(objs_per_slab),
        .obj_offset = @intCast(obj_offset),
    };
    const copy_len = @min(name.len, NAME_BUF - 1);
    @memcpy(cache.name_buf[0..copy_len], name[0..copy_len]);
    cache.name_len = @intCast(copy_len);

    const f = cache_list_lock.acquireIrqSave();
    defer cache_list_lock.releaseIrqRestore(f);
    cache.next_cache = cache_list_head;
    cache_list_head = cache;
    return cache;
}

/// Borrowed view of the cache name. Lifetime is the cache itself (caches
/// are never destroyed at runtime, so always safe to hold).
pub fn cacheName(cache: *const Cache) []const u8 {
    return cache.name_buf[0..cache.name_len];
}

/// Address-classification query for `debug.addrinfo`. Returns null if `addr`
/// doesn't land on a valid slab page (magic + type_tag mismatch or unmapped).
/// Caller must validate the address is in a memory region the kernel can
/// safely deref before calling — we use the 4 KB page mask to find the slab
/// header, which would fault on unmapped pages.
pub const SlabAddrInfo = struct {
    cache_name: []const u8,
    is_header: bool,
    obj_index: u16 = 0,
    obj_byte_off: u32 = 0,
};

pub fn querySlabAddr(addr: usize) ?SlabAddrInfo {
    const slab_addr = addr & SLAB_MASK;
    // PT-walk gate. Called by addrinfo / autopsy with arbitrary RIPs and
    // pointers; dereffing s.magic on an unmapped page would double-fault
    // INSIDE the autopsy path — the same class as the 2026-05-11 IDT
    // code-dump bug ([[idt-code-dump-unmapped-rip]]). Bail cleanly if the
    // slab base isn't mapped before any deref.
    if (!@import("paging.zig").isMapped(slab_addr)) return null;
    const s: *const Slab = @ptrFromInt(slab_addr);
    if (s.magic != SLAB_MAGIC or s.type_tag != SLAB_TYPE_TAG) return null;
    const cache = s.cache;
    const objs_lo = slab_addr + cache.obj_offset;
    if (addr < objs_lo) {
        return .{ .cache_name = cacheName(cache), .is_header = true };
    }
    const off = addr - objs_lo;
    const idx = off / cache.obj_size;
    if (idx >= cache.objs_per_slab) return null; // past last object — gap
    return .{
        .cache_name = cacheName(cache),
        .is_header = false,
        .obj_index = @intCast(idx),
        .obj_byte_off = @intCast(off % cache.obj_size),
    };
}

/// Allocate one object from the cache. Returns a raw byte pointer — caller
/// casts to the appropriate type. The object's memory is uninitialized
/// (whatever the freelist next pointer left in the first 8 bytes).
pub fn alloc(cache: *Cache) ?[*]u8 {
    const flags = cache.lock.acquireIrqSave();
    defer cache.lock.releaseIrqRestore(flags);

    // 1. Prefer partial — those have free objects without touching empty/PMM.
    var slab = cache.partial_head;

    // 2. Fall back to empty — promote one to partial.
    if (slab == null) {
        if (cache.empty_head) |s| {
            removeFromList(cache, s);
            insertHead(cache, s, LIST_PARTIAL);
            slab = s;
        }
    }

    // 3. Last resort: allocate a fresh slab from PMM.
    if (slab == null) {
        const new_slab = newSlab(cache) orelse return null;
        insertHead(cache, new_slab, LIST_PARTIAL);
        slab = new_slab;
    }

    const s = slab.?;
    const obj = s.free_list orelse {
        // Should never happen — partial implies free_count > 0 implies free_list != null.
        @import("../debug/serial.zig").print("[slab/{s}] BUG: partial slab has no free_list\n", .{cacheName(cache)});
        @panic("slab corruption");
    };
    // Unpoison BEFORE reading obj.next — newSlab and free() leave the object
    // poisoned-as-FREED for KASAN's use-after-free detection.
    kasan.unpoison(@intFromPtr(obj), cache.obj_size);
    s.free_list = obj.next;
    s.free_count -= 1;
    s.used_count += 1;

    // If we just consumed the last free object, move slab to the full list.
    if (s.free_count == 0) {
        removeFromList(cache, s);
        insertHead(cache, s, LIST_FULL);
    }

    cache.total_allocs += 1;
    cache.live_objs += 1;
    if (cache.live_objs > cache.peak_live_objs) cache.peak_live_objs = cache.live_objs;

    return @ptrCast(obj);
}

/// Free an object back to the cache. Validates that `ptr` looks like it
/// belongs to this cache — panics otherwise (catches double-frees, type
/// confusion, and freeing into the wrong cache).
pub fn free(cache: *Cache, ptr: [*]u8) void {
    const obj_addr = @intFromPtr(ptr);
    const slab_addr = obj_addr & SLAB_MASK;
    const s: *Slab = @ptrFromInt(slab_addr);

    const cname = cacheName(cache);
    if (s.magic != SLAB_MAGIC or s.type_tag != SLAB_TYPE_TAG or s.cache != cache) {
        @import("../debug/serial.zig").print(
            "[slab/{s}] BAD FREE: ptr=0x{X} slab=0x{X} magic=0x{X} tag=0x{X} expect_cache={s}\n",
            .{ cname, obj_addr, slab_addr, s.magic, s.type_tag, cname },
        );
        @panic("slab: invalid free (wrong cache, double-free, or non-slab ptr)");
    }

    // Bounds check: object must lie inside slab's object array.
    const objs_lo = slab_addr + cache.obj_offset;
    const objs_hi = objs_lo + @as(usize, cache.obj_size) * cache.objs_per_slab;
    if (obj_addr < objs_lo or obj_addr >= objs_hi) {
        @import("../debug/serial.zig").print("[slab/{s}] BAD FREE: ptr=0x{X} outside obj range [0x{X}..0x{X})\n", .{ cname, obj_addr, objs_lo, objs_hi });
        @panic("slab: free of misaligned object pointer");
    }
    // Alignment check
    if ((obj_addr - objs_lo) % cache.obj_size != 0) {
        @import("../debug/serial.zig").print("[slab/{s}] BAD FREE: ptr=0x{X} not aligned to obj_size {d}\n", .{ cname, obj_addr, cache.obj_size });
        @panic("slab: free of misaligned object pointer");
    }

    const flags = cache.lock.acquireIrqSave();
    defer cache.lock.releaseIrqRestore(flags);

    const obj: *FreeObj = @ptrCast(@alignCast(ptr));
    obj.next = s.free_list;
    s.free_list = obj;
    s.used_count -= 1;
    s.free_count += 1;
    // Poison after the freelist write — alloc() unpoisons before reading .next.
    kasan.poison(obj_addr, cache.obj_size, kasan.SHADOW_FREED);

    cache.total_frees += 1;
    // Underflow here means a stray free or double-free slipped past the
    // magic/tag/cache validation above. That's a bug we want to see, not
    // saturate silently.
    std.debug.assert(cache.live_objs > 0);
    cache.live_objs -= 1;

    // List transitions:
    //   full     -> partial   (used_count was max, now max-1)
    //   partial  -> empty     (free_count == objs_per_slab)
    if (s.list_kind == LIST_FULL) {
        removeFromList(cache, s);
        insertHead(cache, s, LIST_PARTIAL);
    }
    if (s.free_count == cache.objs_per_slab) {
        removeFromList(cache, s);
        // Either keep on empty list, or release straight to PMM if we already
        // have empty_keep slabs cached.
        if (cache.empty_count >= cache.empty_keep) {
            releaseSlabToPmm(cache, s);
        } else {
            insertHead(cache, s, LIST_EMPTY);
        }
    }
}

/// Drop all empty slabs back to PMM. Useful under memory pressure or on
/// long-lived caches that just had a burst of frees. Returns the number
/// of frames returned.
pub fn shrink(cache: *Cache) u32 {
    const flags = cache.lock.acquireIrqSave();
    defer cache.lock.releaseIrqRestore(flags);
    var freed: u32 = 0;
    while (cache.empty_head) |s| {
        removeFromList(cache, s);
        releaseSlabToPmm(cache, s);
        freed += 1;
    }
    return freed;
}

pub const Stats = struct {
    name: []const u8,
    obj_size: u32,
    objs_per_slab: u16,
    live_objs: u32,
    peak_live_objs: u32,
    total_allocs: u64,
    total_frees: u64,
    slab_count: u32,
    slab_high_water: u32,
    empty_count: u16,
    bytes_in_use: u64, // live_objs * obj_size
    bytes_committed: u64, // slab_count * SLAB_BYTES
};

pub fn snapshot(cache: *Cache) Stats {
    const flags = cache.lock.acquireIrqSave();
    defer cache.lock.releaseIrqRestore(flags);
    return .{
        .name = cacheName(cache),
        .obj_size = cache.obj_size,
        .objs_per_slab = cache.objs_per_slab,
        .live_objs = cache.live_objs,
        .peak_live_objs = cache.peak_live_objs,
        .total_allocs = cache.total_allocs,
        .total_frees = cache.total_frees,
        .slab_count = cache.slab_count,
        .slab_high_water = cache.slab_high_water,
        .empty_count = cache.empty_count,
        .bytes_in_use = @as(u64, cache.live_objs) * cache.obj_size,
        .bytes_committed = @as(u64, cache.slab_count) * SLAB_BYTES,
    };
}

/// Iterate caches without holding the global cache list lock during the body.
/// Returns the next cache after `prev`, or null at the end. Pass null for the
/// first call. Caches are never destroyed at runtime so it's race-free against
/// list mutation.
pub fn iterCaches(prev: ?*Cache) ?*Cache {
    if (prev) |p| return p.next_cache;
    return cache_list_head;
}

/// Print a one-line summary for every cache. Cheap; suitable for an
/// occasional dmesg dump, panic forensics, or sysmon panel. No-op if no
/// caches have been created (panic-time call before slab is wired).
pub fn printAllCaches() void {
    if (cache_list_head == null) return;
    const serial = @import("../debug/serial.zig");
    serial.print("[slab] caches:\n", .{});
    var c = iterCaches(null);
    while (c) |cache| : (c = iterCaches(cache)) {
        const s = snapshot(cache);
        serial.print(
            "  {s:<16} obj={d:>5}B/slab={d:>3} live={d:>5}/peak={d:>5} slabs={d:>3}/hi={d:>3} alloc={d} free={d} bytes_used={d}/committed={d}\n",
            .{ s.name, s.obj_size, s.objs_per_slab, s.live_objs, s.peak_live_objs, s.slab_count, s.slab_high_water, s.total_allocs, s.total_frees, s.bytes_in_use, s.bytes_committed },
        );
    }
}

// ----- Internals -----

fn newSlab(cache: *Cache) ?*Slab {
    const phys = pmm.allocFrame() orelse return null;
    // Phase 3: reach the slab page through the kernel physmap. Direct
    // `@ptrFromInt(phys)` only worked while PML4[0] held the legacy low
    // identity. With it dropped, the kernel's view of any PMM frame is
    // PHYSMAP_BASE + phys.
    const virt = paging.physToVirt(phys);
    const s: *Slab = @ptrFromInt(virt);
    s.* = .{
        .magic = SLAB_MAGIC,
        .type_tag = SLAB_TYPE_TAG,
        .cache = cache,
        .free_list = null,
        .next = null,
        .prev = null,
        .free_count = cache.objs_per_slab,
        .used_count = 0,
        .list_kind = 0xFF, // not on any list yet — caller will insert
    };

    // Build freelist: thread through objects in reverse so head is at idx=0.
    // Object addresses are computed off the *virtual* slab base so callers
    // see kernel-pointer-shaped pointers; the slab itself remembers its
    // phys via `physFromSlabPtr` (caller-derivable) when DMA needs it.
    var idx: u16 = cache.objs_per_slab;
    while (idx > 0) {
        idx -= 1;
        const obj_addr = virt + cache.obj_offset + @as(usize, idx) * cache.obj_size;
        const obj: *FreeObj = @ptrFromInt(obj_addr);
        obj.next = s.free_list;
        s.free_list = obj;
    }

    // Poison the object area as FREED — every object starts on the freelist.
    // alloc() unpoisons before reading .next; the slab header stays VALID so
    // free() can read magic/type_tag/cache without tripping the shadow.
    const obj_array_bytes = @as(usize, cache.obj_size) * cache.objs_per_slab;
    kasan.poison(virt + cache.obj_offset, obj_array_bytes, kasan.SHADOW_FREED);

    cache.slab_count += 1;
    if (cache.slab_count > cache.slab_high_water) cache.slab_high_water = cache.slab_count;
    return s;
}

fn releaseSlabToPmm(cache: *Cache, s: *Slab) void {
    // Wipe magic so any stale pointer that finds its way back to free()
    // panics distinctly ("non-slab ptr") instead of silently freeing.
    s.magic = 0xDEADDEAD;
    pmm.freeFrame(@intFromPtr(s));
    if (cache.slab_count > 0) cache.slab_count -= 1;
}

inline fn listHeadPtr(cache: *Cache, kind: u8) *?*Slab {
    return switch (kind) {
        LIST_PARTIAL => &cache.partial_head,
        LIST_FULL => &cache.full_head,
        LIST_EMPTY => &cache.empty_head,
        else => unreachable,
    };
}

fn insertHead(cache: *Cache, s: *Slab, kind: u8) void {
    const head = listHeadPtr(cache, kind);
    s.next = head.*;
    s.prev = null;
    if (head.*) |old| old.prev = s;
    head.* = s;
    s.list_kind = kind;
    if (kind == LIST_EMPTY) cache.empty_count += 1;
}

fn removeFromList(cache: *Cache, s: *Slab) void {
    if (s.prev) |p| p.next = s.next;
    if (s.next) |n| n.prev = s.prev;
    const head = listHeadPtr(cache, s.list_kind);
    if (head.* == s) head.* = s.next;
    if (s.list_kind == LIST_EMPTY and cache.empty_count > 0) cache.empty_count -= 1;
    s.prev = null;
    s.next = null;
    s.list_kind = 0xFF;
}
