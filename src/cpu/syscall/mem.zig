//! Syscall handlers (mem) — split out of syscall.zig (#797).
//! Dispatched from cpu/syscall.zig doSyscallInner; named in SYSCALLS.

const std = @import("std");
const vga = @import("../../ui/vga.zig");
const elf_loader = @import("../../proc/elf_loader.zig");
const keyboard = @import("../../driver/keyboard.zig");
const process = @import("../../proc/process.zig");
const vmm = @import("../../mm/vmm.zig");
const pmm = @import("../../mm/pmm.zig");
const paging = @import("../../mm/paging.zig");
const Phys = @import("../../util/addr.zig").Phys;
const bga = @import("../../ui/bga.zig");
const vfs = @import("../../fs/vfs.zig");
const desktop = @import("../../ui/desktop.zig");
const xhci = @import("../../driver/xhci.zig");
const debug = @import("../../debug/debug.zig");
const perf = @import("../../debug/perf.zig");
const pipe = @import("../../proc/pipe.zig");
const memmap = @import("../../mm/memmap.zig");
const config = @import("../../config.zig");
const smp = @import("../smp.zig");
const signals = @import("../../proc/signals.zig");
const errno = @import("../../proc/errno.zig");
const sched_asm = @import("../../proc/sched_asm.zig");
const apic = @import("../../time/apic.zig");

const common = @import("common.zig");
const validateUserPtr = common.validateUserPtr;
const validateUserPtrAligned = common.validateUserPtrAligned;
const USER_SPACE_START = common.USER_SPACE_START;
const NATIVE_SPACE_END: usize = memmap.NATIVE_SPACE_END;
const E_INVAL = common.E_INVAL;
const E_NOENT = common.E_NOENT;
const E_FAULT = common.E_FAULT;
const E_BADF = common.E_BADF;
const E_NOMEM = common.E_NOMEM;
const E_AGAIN = common.E_AGAIN;
const E_BUSY = common.E_BUSY;
const E_NAMETOOLONG = common.E_NAMETOOLONG;
const E_PIPE = common.E_PIPE;
const E_SRCH = common.E_SRCH;
const E_NOSYS = common.E_NOSYS;
const E_PERM = common.E_PERM;
const E_CHILD = common.E_CHILD;
const E_INTR = common.E_INTR;

/// Region-set `remove` context for ranges whose pages the caller already
/// released.
const Discard = struct {
    pub fn removed(_: Discard, _: process.LazyRegion) void {}
};

pub fn sysSbrk(increment: u32) u32 {
    const pcb = process.currentPCB() orelse return E_FAULT;
    _ = pcb.page_directory orelse return E_FAULT;
    // sbrk and the heap lazy region are per-process — sysClone members
    // grow the same heap. Same indirection pattern as sysMmap.
    const lead = process.leader(pcb);

    // AS-stability lock. Serializes against the io_uring worker (running
    // on a different pid + CPU) doing memcpy into this AS — without this
    // the worker could be mid-bounce-copy when sbrk's lazy-region mutation
    // changes the region table mid-walk. See PCB.as_lock doc.
    lead.as_lock.acquire();
    defer lead.as_lock.release();

    const old_brk = lead.user_brk;
    if (increment == 0) return @intCast(old_brk);

    // Shrink path: when the caller passes a negative i32 (reinterpreted as
    // u32 with bit 31 set), trim the heap. Returns `old_brk` on success or
    // E_INVAL if the requested shrink would drop below the heap origin or
    // there is no heap region to trim. Pages between [new_brk, old_brk)
    // are unmapped and their PMM frames freed; the tail of the heap lazy
    // region is shortened. One TLB shootdown covers the whole batch.
    const inc_signed: i32 = @bitCast(increment);
    if (inc_signed < 0) {
        // Widen to i64 BEFORE negating: inc_signed can be i32 INT_MIN
        // (increment == 0x80000000), and -INT_MIN overflows i32 → a ReleaseSafe
        // "integer overflow" panic = userspace-reachable kernel DoS (found by
        // redteam: sbrk(0x80000000)). i64 holds the 2^31 magnitude; the bounds
        // check just below then rejects the absurd shrink as E_INVAL.
        const decrement: usize = @intCast(-@as(i64, inc_signed));
        if (decrement > old_brk - lead.brk_base) return E_INVAL;
        const new_brk_shrink = old_brk - decrement;
        if (lead.heap_start == 0) return E_INVAL;
        const hr = lead.regions.find(lead.heap_start) orelse return E_INVAL;
        if (hr.start != lead.heap_start or hr.end != old_brk) return E_INVAL;
        if (new_brk_shrink < hr.start) return E_INVAL;

        debug.klog("[sbrk-shrink] pid={d} name='{s}' dec={d}KB old=0x{X} new=0x{X}\n", .{
            process.getCurrentPid(), pcb.name[0..pcb.name_len],
            decrement / 1024, old_brk, new_brk_shrink,
        });

        const pml4: [*]align(4096) u64 = @ptrCast(@alignCast(lead.page_directory.?));
        var rc: vmm.Reclaim = .{ .pcid = lead.pcid };
        _ = vmm.unmapUserRange(pml4, new_brk_shrink, old_brk, &rc);
        const first_page = new_brk_shrink & ~@as(usize, 0xFFF);
        const end_page = (old_brk + 0xFFF) & ~@as(usize, 0xFFF);
        @import("../mmu/tlb.zig").shootdownRange(lead.pcid, first_page, (end_page - first_page) / 0x1000);
        rc.release();

        // A heap shrunk to nothing leaves the set; the next grow starts a
        // new heap region at the break.
        if (new_brk_shrink == hr.start) {
            lead.regions.remove(hr.start, old_brk, Discard{}) catch unreachable; // whole region: no split
            lead.heap_start = 0;
        } else {
            _ = lead.regions.resizeEnd(lead.heap_start, new_brk_shrink);
        }
        lead.user_brk = new_brk_shrink;
        return @intCast(old_brk);
    }

    const new_brk = old_brk + increment;
    if (new_brk > NATIVE_SPACE_END or new_brk < old_brk) return E_INVAL;

    // Diagnostic: log every grow > 1 MB so we can attribute big user-heap
    // jumps to a specific app call. Filter small grows to avoid spam.
    if (increment >= 1024 * 1024) {
        debug.klog("[sbrk] pid={d} name='{s}' inc={d}KB old=0x{X} new=0x{X}\n", .{
            process.getCurrentPid(), pcb.name[0..pcb.name_len],
            increment / 1024, old_brk, new_brk,
        });
    }

    // Lazy heap: register (or extend) a lazy region instead of eagerly mapping
    // every page. The page-fault handler allocates+zeros pages on first touch.
    // Grow the heap region if it still ends at old_brk; otherwise (first
    // sbrk, or gpu_map_blob bumped user_brk past it) register a new one.
    const reuse = if (lead.heap_start != 0) blk: {
        const hr = lead.regions.find(lead.heap_start) orelse break :blk false;
        break :blk hr.start == lead.heap_start and hr.end == old_brk;
    } else false;

    if (reuse) {
        if (!lead.regions.resizeEnd(lead.heap_start, new_brk)) return E_INVAL;
    } else {
        if (!process.addLazyRegion(@intCast(lead.tgid), old_brk, new_brk, 0)) return E_INVAL;
        lead.heap_start = old_brk;
    }

    lead.user_brk = new_brk;
    return @intCast(old_brk);
}

/// mmap a region of user VA. Demand-paged in either flavor — the page-fault
/// handler resolves the registered LazyRegion on first touch, allocating one
/// 4KB user page at a time.
///
/// Anonymous (`fd == 0xFFFFFFFF`):
///   Zero-filled. Same machinery sbrk uses; ~free given the existing lazy-
///   region path.
///
/// File-backed (valid `fd`):
///   The kernel reads `len` bytes starting at `offset` from the file into a
///   PMM-allocated contiguous buffer. The lazy region's `source` points at
///   that buffer; on page fault, `handleUserPageFault` copies the relevant
///   slice into the freshly-mapped user page (so each user page is an
///   independent copy, not a shared mapping — true MAP_SHARED requires a
///   page-cache and is a v2 problem). Bytes past EOF stay zero.
///
///   The fd's offset is saved/restored across the read so the caller's
///   sequential file-position state isn't disturbed. FAT cluster cache is
///   reset because changing offset invalidates it.
///
/// VAs grow downward from `pcb.mmap_top` (initially NATIVE_SPACE_END) so they
/// stay clear of upward-growing sbrk and the ELF load area.
pub fn sysMmap(len: u32, fd: u32, offset: u32) u32 {
    if (len == 0) return E_INVAL;
    const pcb = process.currentPCB() orelse return E_FAULT;
    _ = pcb.page_directory orelse return E_FAULT;
    const lead = process.leader(pcb);

    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    const anon = fd == 0xFFFFFFFF;
    if (!anon) {
        if (fd >= config.MAX_FDS) return E_INVAL;
        if (!pcb.fd_table[fd].in_use) return E_INVAL;
    }
    // Cache-backed fast path (ext2 only): a demand-paged region keyed on the
    // file's inode — NO eager read, NO private buffer. Pages fault in through
    // the unified page cache, shared across mappers and filled lazily
    // (fault.zig faultInCachePage).
    const cached = !anon and pcb.fd_table[fd].fs_type == .ext2;

    // Any other file is copied into a private buffer, BEFORE the lock: the
    // read may block (a pipe, a long disk read), and with the write side held
    // every fault of every thread would wait on it.
    const Copy = struct { phys: Phys, ptr: [*]u8, pages: u32 };
    var copy: ?Copy = null;
    if (!anon and !cached) {
        const num_pages: u32 = @intCast(len_pg / 0x1000);
        // User-driven fd-backed mmap — respect the PMM reserve so a
        // big mmap can't deplete the kernel emergency pool.
        const buf_phys = pmm.allocContiguousUser(num_pages) orelse return E_NOMEM;
        const buf_ptr = buf_phys.toVirt().ptr([*]u8);

        const saved_off = pcb.fd_table[fd].offset;
        pcb.fd_table[fd].offset = offset;
        pcb.fd_table[fd].fat_cluster = 0;
        pcb.fd_table[fd].fat_cluster_off = 0;
        const n = vfs.read(pcb, fd, buf_ptr, len);
        pcb.fd_table[fd].offset = saved_off;
        pcb.fd_table[fd].fat_cluster = 0;
        pcb.fd_table[fd].fat_cluster_off = 0;

        if (n == 0xFFFFFFFF) {
            pmm.freeContiguous(buf_phys, @intCast(num_pages));
            return E_INVAL;
        }
        if (n < len_pg) {
            const tail = buf_phys.add(n).toVirt().ptr([*]u8);
            @memset(tail[0 .. len_pg - n], 0);
        }
        copy = .{ .phys = buf_phys, .ptr = buf_ptr, .pages = num_pages };
    }

    // AS-stability lock (see PCB.as_lock), write side: placement reads
    // mmap_top/user_brk and the new region goes into the set.
    lead.as_lock.acquire();
    defer lead.as_lock.release();

    const placed: ?usize = if (len_pg <= lead.mmap_top and lead.mmap_top - len_pg >= lead.user_brk) lead.mmap_top - len_pg else null;
    var region: process.LazyRegion = .{ .end = lead.mmap_top, .prot = process.PROT_RW };
    if (placed) |new_top| {
        region.start = new_top;
        if (cached) {
            region.cache_inode = @intCast(pcb.fd_table[fd].inode);
            region.cache_off = offset;
        }
        if (copy) |c| {
            region.source = c.ptr;
            region.src_va_base = new_top;
            region.src_size = len_pg;
            region.buf_owned = true;
            region.buf_pages = @intCast(c.pages);
        }
    }
    if (placed == null or !process.addRegion(lead.tgid, region)) {
        if (copy) |c| pmm.freeContiguous(c.phys, @intCast(c.pages));
        return E_INVAL;
    }
    lead.mmap_top = region.start;
    return @intCast(region.start);
}

/// MAP_SHARED file mapping (Slice 3c). Like the ext2 fast path of sysMmap, but
/// the region is flagged `cache_shared`: its pages map the shared page-cache
/// frame WRITABLE, so writes land in the shared page — visible to every other
/// mapper of the file and to read() — and are written back to disk on msync()
/// (sysMsync) / munmap() (sysMunmap). Demand-paged: no eager read.
///
/// ext2 regular-file fds only; any other fd / fs type is rejected (E_INVAL) so
/// the caller falls back to the private mmapFile path. Returns the VA on success,
/// E_INVAL on bad fd / table-full / VA exhaustion. VAs grow downward from
/// mmap_top exactly like sysMmap.
pub fn sysMmapFileShared(len: u32, fd: u32, offset: u32) u32 {
    if (len == 0) return E_INVAL;
    const pcb = process.currentPCB() orelse return E_FAULT;
    _ = pcb.page_directory orelse return E_FAULT;
    const lead = process.leader(pcb);

    lead.as_lock.acquire();
    defer lead.as_lock.release();

    if (fd >= config.MAX_FDS) return E_INVAL;
    if (!pcb.fd_table[fd].in_use) return E_INVAL;
    // Shared writeback only exists for the ext2 page cache. Other fs types have
    // no cache frame to share, so reject rather than silently giving private
    // semantics under a MAP_SHARED name.
    if (pcb.fd_table[fd].fs_type != .ext2) return E_INVAL;

    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    if (len_pg > lead.mmap_top) return E_INVAL;
    const new_top = lead.mmap_top - len_pg;
    if (new_top < lead.user_brk) return E_INVAL;

    if (!process.addRegion(lead.tgid, .{
        .start = new_top,
        .end = lead.mmap_top,
        .prot = process.PROT_RW,
        .cache_inode = @intCast(pcb.fd_table[fd].inode),
        .cache_off = offset,
        .cache_shared = true,
    })) return E_INVAL;
    lead.mmap_top = new_top;
    return @intCast(new_top);
}

/// msync(addr, len): write a MAP_SHARED file mapping's dirty pages back to disk.
/// Finds the cache-shared region covering `va` and flushes the WHOLE file's dirty
/// pages (a correct superset of [va, va+len) — every dirty page of the file needs
/// persisting eventually). The dirty flag is left set (the mapping stays live), so
/// a later write re-dirties and a later msync re-flushes. Blocking NVMe I/O runs
/// OUTSIDE as_lock. Returns 0 on success, E_INVAL if no shared region covers `va`.
pub fn sysMsync(va: u32, len: u32) u32 {
    _ = len; // whole-file flush (MVP) — range is advisory; see doc above
    const pcb = process.currentPCB() orelse return E_FAULT;
    _ = pcb.page_directory orelse return E_FAULT;
    const lead = process.leader(pcb);
    const start: usize = @as(usize, va) & ~@as(usize, 0xFFF);

    // Resolve the region under the lock (the table can be mutated by a concurrent
    // mmap/munmap on another thread), capture the inode, then release before I/O.
    lead.as_lock.acquireRead();
    const inum: ?u32 = blk: {
        defer lead.as_lock.releaseRead();
        const r = lead.regions.find(start) orelse break :blk null;
        if (r.cache_inode != 0 and r.cache_shared) break :blk r.cache_inode;
        break :blk null;
    };
    const i = inum orelse return E_INVAL;
    _ = vfs.syncCacheFile(i, false); // clear=false: mapping stays live, keep dirty
    return 0;
}

/// MAP_SHARED|MAP_ANONYMOUS mmap (POSIX-style). Creates a new shared-anon
/// region of `len` bytes (page-rounded), eagerly allocates and zeros all
/// frames, and maps the caller's lazy region against it. Subsequent fork()s
/// inherit the region as truly shared (not COW); munmap / exit decrement
/// the refcount; frames are freed when the last attacher releases.
///
/// Returns the VA on success, 0 on E_NOMEM / E_INVAL. (We can't use E_NOMEM
/// here because the mmap ABI uses 0 as "failure" — same convention as
/// sysMmap above.)
pub fn sysMmapSharedAnon(len: u32) u32 {
    if (len == 0) return 0;
    const pcb = process.currentPCB() orelse return 0;
    _ = pcb.page_directory orelse return 0;
    const lead = process.leader(pcb);

    lead.as_lock.acquire();
    defer lead.as_lock.release();

    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    if (len_pg > lead.mmap_top) return 0;
    const new_top = lead.mmap_top - len_pg;
    if (new_top < lead.user_brk) return 0;

    const shm = @import("../../mm/shm.zig");
    const num_pages: u32 = @intCast(len_pg / 0x1000);
    const shm_id = shm.create(num_pages) orelse return 0;

    if (!process.addRegion(lead.tgid, .{ .start = new_top, .end = lead.mmap_top, .prot = process.PROT_RW, .shm_id = shm_id })) {
        shm.release(shm_id);
        return 0;
    }
    lead.mmap_top = new_top;
    return @intCast(new_top);
}

/// DAX mmap of /dev/pmem0 (sys mmap_pmem, #121). Maps a page-aligned window of
/// the NVDIMM persistent-memory region DIRECTLY into the caller's address space:
/// each user page points at the pmem physical frame itself, so loads/stores hit
/// persistent memory with NO page-cache copy (the defining property of DAX). This
/// is unlike every other mmap flavor here, which either zero-fill, snapshot, or
/// route through the page cache.
///
/// `fd` must be an open /dev/pmem0; `offset` must be page-aligned and the whole
/// [offset, offset+len) window must lie inside the region. Pages are mapped
/// eagerly (the frames are fixed and known — no demand faulting needed) RW|USER,
/// write-back cacheable so CLWB/CLFLUSHOPT persistence works. The frames are
/// device memory registered with the PMM as a no-free range (pmem.init →
/// pmm.registerDeviceRange), so munmap / process-exit teardown freeFrame's them
/// as silent no-ops — they are never recycled into the RAM allocator.
///
/// Returns the mapped VA, or E_INVAL / E_NOMEM. (Like sysMmap, VAs grow down
/// from mmap_top.) NOTE: a DAX region is effectively MAP_SHARED — fork-COW of it
/// is not modeled (it would try to copy device frames); no current caller forks
/// across one. Same eager-device-mapping shape as the GPU blob path.
pub fn sysMmapPmem(len: u32, fd: u32, offset: u32) u32 {
    if (len == 0) return E_INVAL;
    const pcb = process.currentPCB() orelse return E_FAULT;
    const pd = pcb.page_directory orelse return E_FAULT;
    const lead = process.leader(pcb);

    // The fd must really be /dev/pmem0 — DAX semantics only make sense there.
    if (fd >= config.MAX_FDS) return E_INVAL;
    if (!pcb.fd_table[fd].in_use) return E_INVAL;
    if (pcb.fd_table[fd].fs_type != .devfs) return E_INVAL;
    const devfs = @import("../../fs/devfs.zig");
    if (devfs.kindOf(pcb.fd_table[fd].inode) != .pmem0) return E_INVAL;

    const pmem = @import("../../mm/pmem.zig");
    if (!pmem.isPresent()) return E_INVAL;

    // Page-align: we map whole frames, and the pmem offset must be a frame
    // boundary so user VA page N maps pmem frame (offset/4096 + N).
    if (offset & 0xFFF != 0) return E_INVAL;
    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    if (@as(u64, offset) + len_pg > pmem.size()) return E_INVAL; // window must fit the region

    lead.as_lock.acquire();
    defer lead.as_lock.release();

    if (len_pg > lead.mmap_top) return E_INVAL;
    const new_top = lead.mmap_top - len_pg;
    if (new_top < lead.user_brk) return E_INVAL;

    // Eagerly install the direct mappings. base_phys + offset is the first
    // frame; map consecutive frames to consecutive user pages.
    const first_phys = Phys.of(pmem.basePhys() + offset);
    const num_pages = len_pg / 0x1000;
    var i: usize = 0;
    while (i < num_pages) : (i += 1) {
        const virt = new_top + i * 0x1000;
        const phys = first_phys.add(i * 0x1000);
        vmm.mapUserPage(pd, virt, phys, paging.PRESENT | paging.READ_WRITE | paging.USER) catch {
            // Roll back the pages mapped so far. These are device frames, so
            // unmapUserPage's returned phys is discarded (nothing to free).
            var j: usize = 0;
            while (j < i) : (j += 1) _ = vmm.unmapUserPage(pd, new_top + j * 0x1000);
            return E_NOMEM;
        };
    }

    // Track the VA range so munmap/teardown account for it. No buf_owned /
    // cache_inode / shm_id: the frames are device memory, freed as no-ops.
    if (!process.addRegion(lead.tgid, .{ .start = new_top, .end = lead.mmap_top, .prot = process.PROT_RW })) {
        var j: usize = 0;
        while (j < num_pages) : (j += 1) _ = vmm.unmapUserPage(pd, new_top + j * 0x1000);
        return E_INVAL;
    }
    lead.mmap_top = new_top;
    return @intCast(new_top);
}

/// Free a previously-mmapped region. `va` must match the start of a registered
/// region exactly and `len` must match its length (rounded up to page) — partial
/// unmaps are rejected. Walks the page table releasing each present 4KB frame
/// back to the PMM, then removes the region.
///
/// VA recovery: when the freed region is the lowest mmap (its start equals
/// the current mmap_top), mmap_top is advanced upward to the next mmap's
/// start — this also reclaims any contiguous holes below that were freed
/// earlier in non-stack order. Middle holes between still-allocated regions
/// are not reused by this bump allocator (the Linux mmap searches gaps).
pub fn sysMunmap(va: u32, len: u32) u32 {
    if (len == 0) return E_INVAL;
    const pcb = process.currentPCB() orelse return E_FAULT;
    const pd = pcb.page_directory orelse return E_FAULT;
    const lead = process.leader(pcb);

    // AS-stability lock — serializes vs io_uring worker memcpy into AS. Released
    // EXPLICITLY (not deferred) before the shared-region writeback at the end:
    // that does blocking NVMe I/O and so must run with this spinlock dropped.
    // Each early error return below releases it first.
    lead.as_lock.acquire();

    const start: usize = @as(usize, va) & ~@as(usize, 0xFFF);
    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    const end = start + len_pg;
    if (end <= start) {
        lead.as_lock.release();
        return E_INVAL;
    }

    const found = lead.regions.find(start) orelse {
        lead.as_lock.release();
        return E_INVAL;
    };
    if (found.start != start or found.end != end) {
        lead.as_lock.release();
        return E_INVAL;
    }
    // A copy: regions.remove below shifts the array under `found`. Keep this
    // a plain `const = ptr.*` — Zig 0.15.2 ReleaseSafe turns a const struct
    // initialized by a block, if or switch that yields `ptr.*` into an alias
    // of *ptr, and this one would then read the region shifted into its slot.
    const removed = found.*;

    // Gap #7+#8 (2026-05-20): batched walk that shares the PT pointer
    // across each 2 MB span AND reclaims empty intermediate tables. The
    // previous loop did a full PML4→PT walk per page (~100× more
    // indirections on a 64 MB munmap) and never freed empty PTs.
    var rc: vmm.Reclaim = .{ .pcid = lead.pcid };
    _ = vmm.unmapUserRange(pd, start, end, &rc);

    // Single cross-CPU TLB shootdown for the whole range. unmapUserRange
    // does no per-page invlpg; until this call, other CPUs may still cache
    // the unmapped pages' translations, which is why their frames are freed
    // only after it. Doing it once at batch end rather than inside the
    // unmap loop cuts the IPI count by len/4096×. Small ranges go page by
    // page (INVPCID type-0 plus the INVLPG backstop that reliably clears
    // this CPU's entry under nested virt), so peers keep the rest of the
    // AS's entries; large ones flush the whole PCID.
    @import("../mmu/tlb.zig").shootdownRange(lead.pcid, start, (end - start) / 0x1000);
    rc.release();

    lead.regions.remove(start, end, Discard{}) catch unreachable; // whole region: no split
    if (removed.start == lead.heap_start) lead.heap_start = 0;

    // VA reclaim: if we just freed the lowest mmap region, slide mmap_top up
    // to the next one's start (or NATIVE_SPACE_END). Regions above mmap_top are
    // all mmaps — the heap sits far below.
    if (removed.start == lead.mmap_top) {
        lead.mmap_top = if (lead.regions.atOrAbove(lead.mmap_top)) |next| next.start else NATIVE_SPACE_END;
    }

    // File-backed mmap allocates a per-region kernel buffer; drop this
    // process's ownership after the user-side teardown so a fault hitting the
    // just-removed region (e.g. a stale TLB entry) can't read freed memory.
    // A fork peer may still own it. `source` is a physmap virt pointer.
    if (removed.buf_owned) {
        if (removed.source) |src| {
            const phys = paging.virtToPhys(@intFromPtr(src)).?;
            pmm.releaseContiguous(Phys.of(phys), removed.buf_pages);
        }
    }

    // Shared-anon: drop this attacher's ref on the shm region. At refcount==0
    // the shm registry freeFrame's every page; until then peers keep using
    // them. The PMM refcount per frame (bumped by every fault-in via
    // acquireFrame) gets dropped by unmapUserRange above when it freeFrame's
    // present pages — so the only thing remaining here is the shm-side ref.
    {
        const shm = @import("../../mm/shm.zig");
        if (removed.shm_id != shm.SHM_INVALID) shm.release(removed.shm_id);
    }

    // Capture before releasing: a MAP_SHARED file region needs its dirty pages
    // flushed to disk. unmapUserRange above already dropped this mapping's PTE
    // refs, so by the time syncCacheFile(clear=true) runs, clearDirtyIfCacheOnly
    // sees the true remaining-mapper count (refcount==1 ⇒ no other mapper ⇒ clear
    // ⇒ the page rejoins the evictable pool).
    const shared_inode: ?u32 =
        if (removed.cache_inode != 0 and removed.cache_shared) removed.cache_inode else null;
    lead.as_lock.release();

    // Writeback runs OUTSIDE as_lock — writebackPage blocks on NVMe I/O.
    if (shared_inode) |inum| _ = vfs.syncCacheFile(inum, true);
    return 0;
}

/// Change page-protection on an existing mmap region. The range must match
/// a registered region exactly — partial mprotect (split a region in two on
/// a sub-range) is a v2 problem; for now the simpler all-or-nothing semantic
/// is enough for the W^X baseline and JIT-style use.
///
/// Updates the lazy region's `prot` (so future first-touch fault-ins use the
/// new bits) AND walks the existing PTEs in the range, rewriting flags on
/// any present pages. Pages that haven't faulted in yet are no-ops here —
/// they pick up the new prot when handleUserPageFault eventually runs.
pub fn sysMprotect(va: u32, len: u32, prot: u32) u32 {
    if (len == 0) return E_INVAL;
    const pcb = process.currentPCB() orelse return E_FAULT;
    const pd = pcb.page_directory orelse return E_FAULT;

    // AS-stability lock — serializes vs io_uring worker memcpy into AS.
    const lead = process.leader(pcb);
    lead.as_lock.acquire();
    defer lead.as_lock.release();

    const start: usize = @as(usize, va) & ~@as(usize, 0xFFF);
    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    const end = start + len_pg;
    if (end <= start) return E_INVAL;

    // Regions live on the lead thread (per-process), like every other
    // mmap-family syscall — a cloned (non-lead) thread's mprotect must see the
    // shared table, not its own empty one.
    const lr = lead.regions.find(start) orelse return E_INVAL;
    if (lr.start != start or lr.end != end) return E_INVAL;

    // Mask off non-prot bits the user might have passed; we own the encoding.
    const new_prot: u8 = @as(u8, @truncate(prot)) & process.PROT_RWX;
    lr.prot = new_prot;

    // A PRIVATE cache-backed region's present pages are mapped read-only + COW
    // over a SHARED frame; protToMapFlags(PROT_RW) would strip COW and set W,
    // letting a write scribble the shared page (and every other mapper's view).
    // cacheMapFlags keeps them RO+COW (writable prot) or plain RO (read-only prot)
    // so the COW divergence — and PROT_READ enforcement — stay intact.
    // A SHARED cache region (cache_shared, Slice 3c) is the opposite: writes are
    // SUPPOSED to hit the shared frame, so it takes the plain prot bits like anon.
    const new_flags = if (lr.cache_inode != 0 and !lr.cache_shared)
        vmm.cacheMapFlags(new_prot)
    else
        vmm.protToMapFlags(new_prot);
    var page = start;
    while (page < end) : (page += 0x1000) {
        // changePageProt returns false for not-yet-faulted-in pages — that's
        // fine, the region's prot field is updated so the eventual fault-in
        // sees the new bits.
        _ = vmm.changePageProt(pd, page, new_flags);
    }

    // Cross-CPU TLB shootdown. changePageProt only does a local invlpg per
    // page; without this, another CPU's TLB still caches the OLD prot bits
    // and an mprotect(RW→RO) wouldn't actually block writes from that CPU
    // until its TLB happens to evict the entry. Page by page for small
    // ranges (see sysMunmap), the whole PCID for large ones.
    @import("../mmu/tlb.zig").shootdownRange(lead.pcid, start, len_pg / 0x1000);
    return 0;
}

