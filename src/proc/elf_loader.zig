const std = @import("std");
const vga = @import("../ui/vga.zig");
const process = @import("process.zig");
const gdt = @import("../cpu/arch/gdt.zig");
const debug = @import("../debug/debug.zig");
const vmm = @import("../mm/vmm.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const symbols = @import("../debug/symbols.zig");
const memmap = @import("../mm/memmap.zig");

const Header = extern struct {
    ident: [16]u8,
    type: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
};

// ELF64 program header: note p_flags is second field (after p_type)
const ProgramHeader = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

const PAGE_SIZE: usize = 4096;

// User-space VA range. Apps link at USER_VA_FLOOR (app/linker.ld); any ELF
// segment below that is suspicious — almost always means someone tried to
// launch kernel.elf or a UEFI binary from the file browser.
const USER_VA_MIN: usize = memmap.USER_VA_FLOOR;
const USER_VA_MAX: usize = memmap.USER_VA_MAX;

fn isUserVA(addr: usize, size: usize) bool {
    if (addr < USER_VA_MIN) return false;
    const end = addr +| size;
    return end <= USER_VA_MAX;
}

// (PerCpuRspSlot + per_cpu_rsp_save removed. The Linux-style switchTo
// primitive saves each task's RSP into its own pcb.kernel_esp; dying-task
// callers go to a per-CPU dead_letter_kesp. No shared longjmp anchor.)

/// Allocate a per-process kernel-side ELF buffer (PMM-allocated contiguous
/// frames in the lower-4GB identity-mapped range) and copy `file_size` bytes
/// from `staging` into it. Returns null if PMM has no contiguous chunk that
/// big. Caller stores the pointer in pcb.elf_buf for later free.
fn allocAndCopyElfBuf(staging: [*]const u8, file_size: usize) ?struct { buf: [*]u8, pages: u32 } {
    const pages: u32 = @intCast((file_size + PAGE_SIZE - 1) / PAGE_SIZE);
    const phys = pmm.allocContiguous(pages) orelse {
        debug.klog("[elf] allocContiguous({d} pages) failed\n", .{pages});
        return null;
    };
    // Reach the PMM frame through the kernel physmap.
    const buf: [*]u8 = @ptrFromInt(paging.physToVirt(phys));
    @memcpy(buf[0..file_size], staging[0..file_size]);
    return .{ .buf = buf, .pages = pages };
}

fn freePmmRange(base_va: usize, pages: u32) void {
    // Callers pass @intFromPtr(elf_buf) — a kernel physmap VA (elf_buf is the
    // physToVirt of a PMM frame; see allocAndCopyElfBuf / vfs.loadFileFresh).
    // freeContiguous speaks phys, so translate — exactly as lifecycle.freeElfBuf
    // does. (Pre-3e this passed the VA straight through; only rare error paths
    // ever hit it, so freeContiguous's bad-range reject silently leaked. Slice
    // 3e's success-path elf_buf drop fires it on every DROPPED load and surfaced
    // it: a [pmm] WARNING + ~1 MB leaked per exec.)
    const phys = paging.virtToPhys(base_va) orelse {
        debug.klog("[elf] freePmmRange: virtToPhys(0x{X:0>16}) failed — leaking {d} pages\n", .{ base_va, pages });
        return;
    };
    pmm.freeContiguous(phys, pages);
}

/// Register a lazy region for a single PT_LOAD segment, sourced from elf_buf.
/// Pages in [seg_start_aligned, seg_end_aligned) get allocated on first touch;
/// the page-fault handler copies file-backed bytes from elf_buf and zero-fills
/// the rest (BSS portion + alignment padding).
fn registerSegmentLazy(
    pid: usize,
    elf_buf: [*]const u8,
    p_vaddr: usize,
    p_memsz: usize,
    p_filesz: usize,
    p_offset: usize,
) bool {
    const seg_start = p_vaddr & ~@as(usize, PAGE_SIZE - 1);
    const seg_end = (p_vaddr + p_memsz + PAGE_SIZE - 1) & ~@as(usize, PAGE_SIZE - 1);
    return process.addLazyRegionWithSource(
        pid,
        seg_start,
        seg_end,
        0,
        elf_buf,
        p_vaddr,
        p_filesz,
        p_offset,
    );
}

// ELF program-header flag bits.
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
// PF_R = 0x4 — always set for loadable segments; PROT_READ has no PTE bit.

/// Translate a PT_LOAD's p_flags into our PROT_* bitmask (always readable;
/// writable iff PF_W; executable iff PF_X). Used for cache-shared segments so
/// `cacheMapFlags` produces the right RO / RX / NX mapping.
fn segProt(p_flags: u32) u8 {
    var prot: u8 = process.PROT_READ;
    if (p_flags & PF_W != 0) prot |= process.PROT_WRITE;
    if (p_flags & PF_X != 0) prot |= process.PROT_EXEC;
    return prot;
}

/// Register every PT_LOAD segment's lazy region (Slice 3e), choosing per segment:
///   * pure BSS (p_filesz==0)           → anonymous zero-fill (no source), the
///                                         same path the stack uses.
///   * read-only, file==mem, page-      → the unified page cache: the segment's
///     congruent, on ext2 (inode!=0)      frames are SHARED across every process
///                                         running this binary; a stray write
///                                         COW-diverges into a private copy.
///   * everything else (RW init data,   → a private copy demand-paged from
///     or a non-qualifying RO segment)    elf_buf (the legacy path).
/// Returns whether ANY segment still needs elf_buf (so the caller knows whether
/// to retain it or free it after symbol parsing), or null if a region couldn't
/// be registered or a segment's VA is out of user range (caller kills the proc).
fn registerSegments(pid: usize, elf_buf: [*]const u8, phoff: usize, phnum: u16, inode: u32) ?bool {
    const pcb = process.getPCB(pid);
    const phdrs: [*]align(1) const ProgramHeader = @ptrCast(elf_buf + phoff);
    var needs_elf_buf = false;
    var n_cache: u32 = 0;
    var n_anon: u32 = 0;
    var n_priv: u32 = 0;
    for (0..phnum) |i| {
        if (phdrs[i].p_type != 1) continue; // PT_LOAD
        const p_vaddr: usize = @intCast(phdrs[i].p_vaddr);
        const p_memsz: usize = @intCast(phdrs[i].p_memsz);
        const p_filesz: usize = @intCast(phdrs[i].p_filesz);
        const p_offset: usize = @intCast(phdrs[i].p_offset);
        const p_flags = phdrs[i].p_flags;
        if (!isUserVA(p_vaddr, p_memsz)) {
            debug.klog("[elf] segment 0x{X}+{d} outside user VA\n", .{ p_vaddr, p_memsz });
            return null;
        }
        const seg_start = p_vaddr & ~@as(usize, PAGE_SIZE - 1);
        const seg_end = (p_vaddr + p_memsz + PAGE_SIZE - 1) & ~@as(usize, PAGE_SIZE - 1);

        if (p_filesz == 0) {
            // Pure BSS: anonymous zero-fill — no file content, never needs elf_buf.
            if (!process.addLazyRegion(pid, seg_start, seg_end, 0)) return null;
            n_anon += 1;
        } else if (inode != 0 and (p_flags & PF_W) == 0 and p_filesz == p_memsz and
            (p_offset & (PAGE_SIZE - 1)) == (p_vaddr & (PAGE_SIZE - 1)))
        {
            // Read-only, fully file-backed, page-congruent, on ext2: share via
            // the unified page cache. cache_off is the file offset of the page-
            // aligned segment start (congruence guarantees off & ~0xFFF lines up
            // with vaddr & ~0xFFF). Maps RO, executable iff PF_X; a write
            // COW-diverges (the cache's own ref keeps refcount>=2, so the shared
            // frame is copied, never stolen).
            if (!process.addLazyRegion(pid, seg_start, seg_end, 0)) return null;
            const ridx = pcb.lazy_count - 1;
            pcb.lazy_regions[ridx].cache_inode = inode;
            pcb.lazy_regions[ridx].cache_off = p_offset & ~@as(usize, PAGE_SIZE - 1);
            pcb.lazy_regions[ridx].prot = segProt(p_flags);
            n_cache += 1;
        } else {
            // RW initialized data (+maybe a BSS tail), or a non-qualifying RO
            // segment (filesz!=memsz, not page-congruent, or non-ext2 boot):
            // keep the private elf_buf-sourced copy.
            if (!registerSegmentLazy(pid, elf_buf, p_vaddr, p_memsz, p_filesz, p_offset)) return null;
            needs_elf_buf = true;
            n_priv += 1;
        }
    }
    debug.klog("[elf] pid={d} inode={d}: segs cache={d} anon={d} priv={d} elf_buf={s}\n", .{
        pid, inode, n_cache, n_anon, n_priv, if (needs_elf_buf) "kept" else "DROPPED",
    });
    return needs_elf_buf;
}

/// Load an ELF and create the process, but don't enter user mode.
/// Returns PID or null. Used by the desktop for multitasking.
///
/// `elf_buf` ownership is transferred to this function. On success, the
/// buffer is stashed in `pcb.elf_buf` and freed when the process exits.
/// On any failure path, this function frees `elf_buf` itself — the caller
/// must NOT touch it after the call.
pub fn loadAndStart(elf_buf: [*]align(4) u8, file_size: usize, elf_buf_pages: u32, inode: u32) ?usize {
    debug.klog("[elf] Loading ELF64 binary...\n", .{});
    const header = @as([*]align(1) const Header, @ptrCast(elf_buf))[0];
    if (!std.mem.eql(u8, header.ident[0..4], "\x7fELF") or header.ident[4] != 2 or header.machine != 0x3E) {
        // Diagnostic: dump first 32 bytes + parsed fields. The "Invalid"
        // condition is hit when DMA returned garbage (race on PRDT) — the
        // bytes show whether the buffer is zeros (DMA never wrote), stale
        // (cache coherence miss), or scrambled (interleaved with another
        // transfer).
        debug.klog("[elf] Invalid ELF64 header — file_size={d} elf_buf=0x{X:0>16}\n", .{ file_size, @intFromPtr(elf_buf) });
        debug.klog("[elf]   ident[0..4]: {X:0>2} {X:0>2} {X:0>2} {X:0>2}  (want: 7F 45 4C 46)\n", .{ header.ident[0], header.ident[1], header.ident[2], header.ident[3] });
        debug.klog("[elf]   ident[4]={d} (want 2 = ELF64), machine=0x{X} (want 0x3E = AMD64)\n", .{ header.ident[4], header.machine });
        debug.klog("[elf]   First 32 bytes:", .{});
        for (0..@min(32, file_size)) |i| debug.klog(" {X:0>2}", .{elf_buf[i]});
        debug.klog("\n", .{});
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return null;
    }

    const entry_addr: usize = @intCast(header.entry);
    if (!isUserVA(entry_addr, 1)) {
        debug.klog("[elf] Rejected: entry 0x{X} outside user VA range\n", .{entry_addr});
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return null;
    }

    var pd_phys: usize = 0;
    const pd = vmm.createAddressSpace(&pd_phys) orelse {
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return null;
    };

    // Validate every PT_LOAD's VA range fits in user space before doing
    // any per-segment work — bail early without partial state.
    const phoff: usize = @intCast(header.phoff);
    const phdrs: [*]align(1) const ProgramHeader = @ptrCast(elf_buf + phoff);
    for (0..header.phnum) |i| {
        if (phdrs[i].p_type != 1) continue;
        const p_vaddr: usize = @intCast(phdrs[i].p_vaddr);
        const p_memsz: usize = @intCast(phdrs[i].p_memsz);
        if (!isUserVA(p_vaddr, p_memsz)) {
            debug.klog("[elf] Rejected: segment 0x{X}+{d} outside user VA\n", .{ p_vaddr, p_memsz });
            vmm.destroyAddressSpace(pd, pd_phys);
            freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
            return null;
        }
    }

    // User stack: lazily allocated via the page-fault handler. Pages back
    // on first touch so unused stack costs 0 RSS. Top stays at
    // USER_VA_FLOOR so process.create's initial RSP is just below it; the
    // first push triggers fault-in for the top page.
    //
    // SIZE is derived from memmap.USER_STACK_RESERVE — must match exactly,
    // otherwise mapUserPage silently rejects stack faults below
    // USER_SPACE_START (=USER_VA_FLOOR - USER_STACK_RESERVE) and the app
    // burns frames forever in a re-fault loop (caught 2026-05-20 on Q1
    // after the stack was bumped to 64 pages but USER_STACK_RESERVE
    // stayed at 16 pages = 64 KB → 200 MB leak before OOM).
    const stack_top: usize = memmap.USER_VA_FLOOR;
    const stack_pages: usize = memmap.USER_STACK_RESERVE / PAGE_SIZE;
    const stack_base: usize = stack_top - stack_pages * PAGE_SIZE;
    comptime {
        if (stack_pages * PAGE_SIZE > memmap.USER_STACK_RESERVE) {
            @compileError("stack_pages exceeds USER_STACK_RESERVE — mapUserPage will reject low stack faults");
        }
    }

    const entry: usize = @intCast(header.entry);
    const pid = process.create(entry, stack_top - 8) orelse {
        vmm.destroyAddressSpace(pd, pd_phys);
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return null;
    };
    debug.klog("[elf] Process created PID={d} entry=0x{X:0>16}\n", .{ pid, header.entry });

    const pcb = process.getPCB(pid);
    pcb.page_directory = pd;
    pcb.page_dir_phys = pd_phys;
    pcb.pcid = @import("../cpu/mmu/pcid.zig").alloc();
    pcb.elf_buf = elf_buf;
    pcb.elf_buf_pages = elf_buf_pages;
    pcb.stack_base = stack_base;

    // Register lazy regions: stack first (region 0), then each PT_LOAD segment
    // (regions 1..N). Heap is registered later by sysSbrk.
    if (!process.addLazyRegion(pid, stack_base, stack_top, 0)) {
        debug.klog("[elf] Failed to register lazy stack region for PID {d}\n", .{pid});
        process.killProcess(@intCast(pid));
        return null;
    }
    const needs_elf_buf = registerSegments(pid, elf_buf, phoff, header.phnum, inode) orelse {
        debug.klog("[elf] segment registration failed for PID {d}\n", .{pid});
        process.killProcess(@intCast(pid));
        return null;
    };

    // Parse debug symbols from ELF section headers (use kernel-side ELF buffer).
    pcb.sym_table = symbols.parseElfSymbols(elf_buf, file_size);

    // Slice 3e: if no segment is demand-paged from elf_buf (all are cache-shared
    // or pure-BSS anon), the per-process whole-file copy is dead weight — free it
    // now instead of holding it until exit. freeElfBuf is null-safe, so teardown
    // simply no-ops. Symbol parsing above already copied what it needs.
    if (!needs_elf_buf) {
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        pcb.elf_buf = null;
        pcb.elf_buf_pages = 0;
    }

    // Init complete — transition .loading → .ready. Until this store, an AP
    // sees the PCB as not-runnable. After this, pickNext can dispatch it
    // and the iretq will land on a fully-initialized address space + lazy
    // region table. assignInitialCpu BEFORE the state flip so the rqEnter
    // setState triggers lands on the right per-CPU runqueue.
    process.assignInitialCpu(pid);
    process.setState(pid, .ready);

    return pid;
}

pub fn loadAndExecute(elf_buf: [*]align(4) u8, file_size: usize, elf_buf_pages: u32, inode: u32) void {
    debug.klog("[elf] Loading ELF64 binary...\n", .{});
    const header = @as([*]align(1) const Header, @ptrCast(elf_buf))[0];
    if (!std.mem.eql(u8, header.ident[0..4], "\x7fELF") or header.ident[4] != 2 or header.machine != 0x3E) {
        vga.fg = .LightRed;
        vga.print("ELF Error!\n", .{});
        debug.klog("[elf] Invalid ELF64 header\n", .{});
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return;
    }

    // Create per-process address space
    var pd_phys: usize = 0;
    const pd = vmm.createAddressSpace(&pd_phys) orelse {
        vga.fg = .LightRed;
        vga.print("Error: cannot create address space!\n", .{});
        debug.klog("[elf] Failed to create address space\n", .{});
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return;
    };

    // User stack: derived from memmap.USER_STACK_RESERVE — see loadAndStart
    // for the silent-rejection bug class this matching prevents.
    const stack_top: usize = memmap.USER_VA_FLOOR;
    const stack_pages: usize = memmap.USER_STACK_RESERVE / PAGE_SIZE;
    const stack_base: usize = stack_top - stack_pages * PAGE_SIZE;

    // Create process with fake interrupt frame
    const entry: usize = @intCast(header.entry);
    const pid = process.create(entry, stack_top - 8) orelse {
        vga.fg = .LightRed;
        vga.print("Error: process table full!\n", .{});
        debug.klog("[elf] Process table full\n", .{});
        vmm.destroyAddressSpace(pd, pd_phys);
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        return;
    };
    debug.klog("[elf] Process created PID={d} entry=0x{X:0>16}\n", .{ pid, header.entry });

    // Store address space + ELF buffer in PCB
    const pcb = process.getPCB(pid);
    pcb.page_directory = pd;
    pcb.page_dir_phys = pd_phys;
    pcb.pcid = @import("../cpu/mmu/pcid.zig").alloc();
    pcb.elf_buf = elf_buf;
    pcb.elf_buf_pages = elf_buf_pages;
    pcb.stack_base = stack_base;

    if (!process.addLazyRegion(pid, stack_base, stack_top, 0)) {
        vga.fg = .LightRed;
        vga.print("Error: lazy stack region full!\n", .{});
        process.killProcess(@intCast(pid));
        return;
    }

    const phoff: usize = @intCast(header.phoff);
    const needs_elf_buf = registerSegments(pid, elf_buf, phoff, header.phnum, inode) orelse {
        vga.fg = .LightRed;
        vga.print("Error: segment registration failed!\n", .{});
        process.killProcess(@intCast(pid));
        return;
    };

    // Parse debug symbols from ELF section headers (use kernel-side ELF buffer).
    pcb.sym_table = symbols.parseElfSymbols(elf_buf, file_size);

    // Slice 3e: drop the per-process whole-file copy if nothing sources from it
    // (all segments cache-shared or pure-BSS anon). See loadAndStart.
    if (!needs_elf_buf) {
        freePmmRange(@intFromPtr(elf_buf), elf_buf_pages);
        pcb.elf_buf = null;
        pcb.elf_buf_pages = 0;
    }

    // Init complete — flip .loading → .ready so an AP's pickNext can see it
    // (and so this CPU's later preemption-resume cycles work). loadAndExecute
    // dispatches synchronously below, but state must be at least .ready for
    // the post-preemption schedule path. assignInitialCpu first so the
    // setState rqEnter lands on the right rq.
    process.assignInitialCpu(pid);
    process.setState(pid, .ready);

    // Mark process as running and set TSS for initial launch
    process.setCurrent(pid);
    const proc_info = process.getProcessInfo(pid);
    gdt.setTssRsp0(pid, proc_info.kernel_stack_top);

    // Switch to the new address space (PCID-tagged so subsequent reloads
    // can preserve this process's TLB across context switches).
    @import("../cpu/mmu/pcid.zig").loadCr3(pd_phys, pcb.pcid, @import("../cpu/smp.zig").myCpu().cpu_id);

    debug.klog("[elf] Entering Ring 3\n", .{});
    // Synchronously wait for the loaded process to exit. schedule() may pick
    // OTHER tasks first; we loop until the one we just loaded actually dies.
    // (The legacy enterUserMode/returnToKernel pair returned at any sysExit
    // on this CPU's dispatch path, which had the same loose semantics; this
    // makes the wait explicit.)
    while (process.procs[pid].state != .zombie and process.procs[pid].state != .unused) {
        process.schedule();
        asm volatile ("sti");
    }
}

/// Copy data to pages mapped in a page directory.
/// Since physical frames are in identity-mapped PMM range, we write to physical addresses directly.
fn copyToMappedPages(pd: [*]align(4096) u64, virt_start: usize, src: [*]const u8, len: usize) void {
    var offset: usize = 0;
    while (offset < len) {
        const virt = virt_start + offset;
        const phys = resolvePhys(pd, virt) orelse return;
        const page_offset = virt & (PAGE_SIZE - 1);
        const chunk = @min(PAGE_SIZE - page_offset, len - offset);
        const dest: [*]u8 = @ptrFromInt(paging.physToVirt(phys + page_offset));
        @memcpy(dest[0..chunk], src[offset..][0..chunk]);
        offset += chunk;
    }
}

/// Zero pages mapped in a page directory.
fn zeroMappedPages(pd: [*]align(4096) u64, virt_start: usize, len: usize) void {
    var offset: usize = 0;
    while (offset < len) {
        const virt = virt_start + offset;
        const phys = resolvePhys(pd, virt) orelse return;
        const page_offset = virt & (PAGE_SIZE - 1);
        const chunk = @min(PAGE_SIZE - page_offset, len - offset);
        const dest: [*]u8 = @ptrFromInt(paging.physToVirt(phys + page_offset));
        @memset(dest[0..chunk], 0);
        offset += chunk;
    }
}

/// Resolve virtual address to physical address using 4-level page tables (PML4→PDPT→PD→PT).
pub fn resolvePhys(pml4: [*]align(4096) u64, virt: usize) ?usize {
    const MASK: u64 = 0x000FFFFFFFFFF000;
    const v: u64 = @intCast(virt);

    // PML4 → PDPT
    const pml4_idx = (v >> 39) & 0x1FF;
    const pml4e = pml4[pml4_idx];
    if (pml4e & 1 == 0) return null;
    const pdpt: [*]const u64 = @ptrFromInt(paging.physToVirt(pml4e & MASK));

    // PDPT → PD
    const pdpt_idx = (v >> 30) & 0x1FF;
    const pdpte = pdpt[pdpt_idx];
    if (pdpte & 1 == 0) return null;
    const pd: [*]const u64 = @ptrFromInt(paging.physToVirt(pdpte & MASK));

    // PD → PT (check for 2MB page)
    const pd_idx = (v >> 21) & 0x1FF;
    const pde = pd[pd_idx];
    if (pde & 1 == 0) return null;
    if (pde & 0x80 != 0) {
        // 2MB page
        return @intCast((pde & MASK) + (v & 0x1FFFFF));
    }
    const pt: [*]const u64 = @ptrFromInt(paging.physToVirt(pde & MASK));

    // PT → physical page
    const pt_idx = (v >> 12) & 0x1FF;
    const pte = pt[pt_idx];
    if (pte & 1 == 0) return null;
    return @intCast(pte & MASK);
}

// (enterUserMode / returnToKernel / returnToKernelHere removed.
// Replaced by sched_asm.zig's switchTo (kernel↔kernel context switch)
// and retToUserStub (single iretq site for new tasks). Dispatch sites
// now call process.schedule() directly.)
