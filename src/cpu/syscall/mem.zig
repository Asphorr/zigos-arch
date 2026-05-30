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
const USER_SPACE_END = common.USER_SPACE_END;
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
        const decrement: usize = @intCast(-inc_signed);
        if (decrement > old_brk - memmap.USER_BRK_INITIAL) return E_INVAL;
        const new_brk_shrink = old_brk - decrement;
        if (lead.heap_lazy_idx < 0) return E_INVAL;
        const hr = &lead.lazy_regions[@intCast(lead.heap_lazy_idx)];
        if (hr.end != old_brk) return E_INVAL;
        if (new_brk_shrink < hr.start) return E_INVAL;

        debug.klog("[sbrk-shrink] pid={d} name='{s}' dec={d}KB old=0x{X} new=0x{X}\n", .{
            process.getCurrentPid(), pcb.name[0..pcb.name_len],
            decrement / 1024, old_brk, new_brk_shrink,
        });

        const pml4: [*]align(4096) u64 = @ptrCast(@alignCast(lead.page_directory.?));
        _ = vmm.unmapUserRange(pml4, new_brk_shrink, old_brk);
        @import("../mmu/tlb.zig").shootdownAll(lead.pcid);

        hr.end = new_brk_shrink;
        lead.user_brk = new_brk_shrink;
        return @intCast(old_brk);
    }

    const new_brk = old_brk + increment;
    if (new_brk > USER_SPACE_END or new_brk < old_brk) return E_INVAL;

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
    // Reuse the existing heap region if it still ends at old_brk; otherwise
    // (first sbrk, or gpu_map_blob bumped user_brk past it) register a new one.
    const reuse = lead.heap_lazy_idx >= 0 and
        lead.lazy_regions[@intCast(lead.heap_lazy_idx)].end == old_brk;

    if (reuse) {
        lead.lazy_regions[@intCast(lead.heap_lazy_idx)].end = new_brk;
    } else {
        if (!process.addLazyRegion(@intCast(lead.tgid), old_brk, new_brk, 0)) return E_INVAL;
        lead.heap_lazy_idx = @intCast(lead.lazy_count - 1);
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
/// VAs grow downward from `pcb.mmap_top` (initially USER_SPACE_END) so they
/// stay clear of upward-growing sbrk and the ELF load area.
pub fn sysMmap(len: u32, fd: u32, offset: u32) u32 {
    if (len == 0) return E_INVAL;
    const pcb = process.currentPCB() orelse return E_FAULT;
    _ = pcb.page_directory orelse return E_FAULT;
    const lead = process.leader(pcb);

    // AS-stability lock (see PCB.as_lock). Acquired before any AS-state
    // read to avoid races with the io_uring worker.
    lead.as_lock.acquire();
    defer lead.as_lock.release();

    if (lead.lazy_count >= process.MAX_LAZY_REGIONS) return E_INVAL;

    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    if (len_pg > lead.mmap_top) return E_INVAL;
    const new_top = lead.mmap_top - len_pg;
    if (new_top < lead.user_brk) return E_INVAL;

    const lead_pid: u32 = lead.tgid;

    if (fd == 0xFFFFFFFF) {
        if (!process.addLazyRegion(lead_pid, new_top, lead.mmap_top, 0)) return E_INVAL;
        lead.lazy_regions[lead.lazy_count - 1].prot = process.PROT_RW;
    } else {
        if (fd >= config.MAX_FDS) return E_INVAL;
        if (!pcb.fd_table[fd].in_use) return E_INVAL;

        // Cache-backed fast path (ext2 only): register a demand-paged region
        // keyed on the file's inode and return immediately — NO eager read, NO
        // private buffer. Pages fault in through the unified page cache, shared
        // across mappers and filled lazily (fault.zig faultInCachePage). Other
        // filesystems fall through to the eager copy-into-buffer path below.
        if (pcb.fd_table[fd].fs_type == .ext2) {
            if (!process.addLazyRegion(lead_pid, new_top, lead.mmap_top, 0)) return E_INVAL;
            const ridx = lead.lazy_count - 1;
            lead.lazy_regions[ridx].prot = process.PROT_RW;
            lead.lazy_regions[ridx].cache_inode = @intCast(pcb.fd_table[fd].inode);
            lead.lazy_regions[ridx].cache_off = offset;
            lead.mmap_top = new_top;
            return @intCast(new_top);
        }

        const num_pages: u32 = @intCast(len_pg / 0x1000);
        // User-driven fd-backed mmap — respect the PMM reserve so a
        // big mmap can't deplete the kernel emergency pool.
        const buf_phys = pmm.allocContiguousUser(num_pages) orelse return E_NOMEM;
        const buf_ptr: [*]u8 = @ptrFromInt(paging.physToVirt(buf_phys));

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
            const tail: [*]u8 = @ptrFromInt(paging.physToVirt(buf_phys + n));
            @memset(tail[0 .. len_pg - n], 0);
        }

        if (!process.addLazyRegionWithSource(
            lead_pid,
            new_top,
            lead.mmap_top,
            0,
            buf_ptr,
            new_top,
            len_pg,
            0,
        )) {
            pmm.freeContiguous(buf_phys, @intCast(num_pages));
            return E_INVAL;
        }
        const ridx = lead.lazy_count - 1;
        lead.lazy_regions[ridx].buf_owned = true;
        lead.lazy_regions[ridx].buf_pages = @intCast(num_pages);
        lead.lazy_regions[ridx].prot = process.PROT_RW;
    }

    lead.mmap_top = new_top;
    return @intCast(new_top);
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

    if (lead.lazy_count >= process.MAX_LAZY_REGIONS) return E_INVAL;
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

    if (!process.addLazyRegion(lead.tgid, new_top, lead.mmap_top, 0)) return E_INVAL;
    const ridx = lead.lazy_count - 1;
    lead.lazy_regions[ridx].prot = process.PROT_RW;
    lead.lazy_regions[ridx].cache_inode = @intCast(pcb.fd_table[fd].inode);
    lead.lazy_regions[ridx].cache_off = offset;
    lead.lazy_regions[ridx].cache_shared = true;
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
    lead.as_lock.acquire();
    const inum: ?u32 = blk: {
        defer lead.as_lock.release();
        for (lead.lazy_regions[0..lead.lazy_count]) |r| {
            if (r.cache_inode != 0 and r.cache_shared and start >= r.start and start < r.end) {
                break :blk r.cache_inode;
            }
        }
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

    if (lead.lazy_count >= process.MAX_LAZY_REGIONS) return 0;

    const len_pg: usize = (@as(usize, len) + 0xFFF) & ~@as(usize, 0xFFF);
    if (len_pg > lead.mmap_top) return 0;
    const new_top = lead.mmap_top - len_pg;
    if (new_top < lead.user_brk) return 0;

    const shm = @import("../../mm/shm.zig");
    const num_pages: u32 = @intCast(len_pg / 0x1000);
    const shm_id = shm.create(num_pages) orelse return 0;

    if (!process.addLazyRegion(lead.tgid, new_top, lead.mmap_top, 0)) {
        shm.release(shm_id);
        return 0;
    }
    const ridx = lead.lazy_count - 1;
    lead.lazy_regions[ridx].prot = process.PROT_RW;
    lead.lazy_regions[ridx].shm_id = shm_id;
    lead.mmap_top = new_top;
    return @intCast(new_top);
}

/// Free a previously-mmapped region. `va` must match the start of a registered
/// region exactly and `len` must match its length (rounded up to page) — partial
/// unmaps are rejected. Walks the page table releasing each present 4KB frame
/// back to the PMM, then removes the lazy-region entry.
///
/// VA recovery: when the freed region is the topmost (its start equals the
/// current mmap_top), mmap_top is advanced upward to the next existing mmap
/// region's start — this also reclaims any contiguous holes below that were
/// freed earlier in non-stack order. Middle holes between still-allocated
/// regions are NOT reclaimed; that needs a real free-range list and is
/// deferred until the lazy_count cap (16) actually starts hurting.
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

    var found_idx: ?usize = null;
    for (lead.lazy_regions[0..lead.lazy_count], 0..) |r, i| {
        if (r.start == start and r.end == end) {
            found_idx = i;
            break;
        }
    }
    const idx = found_idx orelse {
        lead.as_lock.release();
        return E_INVAL;
    };
    const removed = lead.lazy_regions[idx];

    // Gap #7+#8 (2026-05-20): batched walk that shares the PT pointer
    // across each 2 MB span AND reclaims empty intermediate tables. The
    // previous loop did a full PML4→PT walk per page (~100× more
    // indirections on a 64 MB munmap) and never freed empty PTs.
    _ = vmm.unmapUserRange(pd, start, end);

    // Single cross-CPU TLB shootdown for the whole range. unmapUserRange
    // does no per-page invlpg; without this call, other CPUs would still
    // cache the freed pages' translations and could read / write into
    // now-recycled PMM frames. Doing it once at batch end rather than
    // inside the unmap loop cuts the IPI count by len/4096×.
    // For range==1 page, use INVPCID type-0 (single-page) so peer CPUs
    // only lose that one TLB entry; for larger ranges, use type-1
    // (whole-PCID flush) which is cheaper than emitting N type-0 calls.
    const tlb = @import("../mmu/tlb.zig");
    if ((end - start) == 0x1000) {
        // Single page: surgical INVPCID type-0 on peers. shootdownPage's local
        // flush (flushLocalForMode) carries an INVLPG backstop that reliably
        // clears THIS CPU's entry under nested virt — where type-0 under-
        // invalidates and could leave a stale entry into the just-freed frame —
        // so no separate local flush is needed here.
        tlb.shootdownPage(lead.pcid, start);
    } else {
        tlb.shootdownAll(lead.pcid);
    }

    // Compact the lazy_regions array. heap_lazy_idx is sbrk's pointer; if it
    // happens to be above the removed slot, shift it down by one to keep
    // pointing at the same region.
    for (idx + 1..lead.lazy_count) |j| lead.lazy_regions[j - 1] = lead.lazy_regions[j];
    lead.lazy_count -= 1;
    lead.lazy_regions[lead.lazy_count] = .{};
    if (lead.heap_lazy_idx >= 0 and @as(usize, @intCast(lead.heap_lazy_idx)) > idx) {
        lead.heap_lazy_idx -= 1;
    }

    // VA reclaim: if we just freed the topmost mmap region, slide mmap_top up
    // to the next still-allocated mmap region's start (or USER_SPACE_END).
    // Filter `r.start > lead.mmap_top` excludes the heap region (which sits
    // far below in user space) and naturally picks only mmap-managed regions.
    if (removed.start == lead.mmap_top) {
        var new_top: usize = memmap.USER_SPACE_END;
        for (lead.lazy_regions[0..lead.lazy_count]) |r| {
            if (r.start > lead.mmap_top and r.start < new_top) new_top = r.start;
        }
        lead.mmap_top = new_top;
    }

    // File-backed mmap allocates a per-region kernel buffer; release it after
    // the user-side teardown so a fault hitting the just-removed region (e.g.
    // a stale TLB entry) can't read freed memory. `source` is a physmap virt
    // pointer (see sysMmap line 942) — translate back to phys for PMM.
    if (removed.buf_owned) {
        if (removed.source) |src| {
            const phys = paging.virtToPhys(@intFromPtr(src)).?;
            pmm.freeContiguous(phys, removed.buf_pages);
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

    // Lazy regions live on the lead thread (per-process), like every other
    // mmap-family syscall — a cloned (non-lead) thread's mprotect must see the
    // shared table, not its own empty one.
    var found_idx: ?usize = null;
    for (lead.lazy_regions[0..lead.lazy_count], 0..) |r, i| {
        if (r.start == start and r.end == end) {
            found_idx = i;
            break;
        }
    }
    const idx = found_idx orelse return E_INVAL;

    // Mask off non-prot bits the user might have passed; we own the encoding.
    const new_prot: u8 = @as(u8, @truncate(prot)) & process.PROT_RWX;
    lead.lazy_regions[idx].prot = new_prot;

    // A PRIVATE cache-backed region's present pages are mapped read-only + COW
    // over a SHARED frame; protToMapFlags(PROT_RW) would strip COW and set W,
    // letting a write scribble the shared page (and every other mapper's view).
    // cacheMapFlags keeps them RO+COW (writable prot) or plain RO (read-only prot)
    // so the COW divergence — and PROT_READ enforcement — stay intact.
    // A SHARED cache region (cache_shared, Slice 3c) is the opposite: writes are
    // SUPPOSED to hit the shared frame, so it takes the plain prot bits like anon.
    const lr = &lead.lazy_regions[idx];
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
    // until its TLB happens to evict the entry.
    // Single-page case uses type-0 INVPCID (surgical, leaves the rest of
    // the PCID's TLB intact); ranges fall through to the whole-PCID type-1
    // flush.
    const tlb = @import("../mmu/tlb.zig");
    if (len_pg == 0x1000) {
        // Single page: see sysMunmap — shootdownPage's flushLocalForMode INVLPG
        // backstop reliably clears THIS CPU's stale entry under nested virt (the
        // W^X-narrowing hazard); peers are covered by the .single_page gen-bump.
        tlb.shootdownPage(pcb.pcid, start);
    } else {
        tlb.shootdownAll(pcb.pcid);
    }
    return 0;
}

