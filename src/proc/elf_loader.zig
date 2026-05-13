const std = @import("std");
const vga = @import("../ui/vga.zig");
const process = @import("process.zig");
const gdt = @import("../cpu/gdt.zig");
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

fn freePmmRange(base: usize, pages: u32) void {
    pmm.freeContiguous(base, pages);
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

/// Load an ELF and create the process, but don't enter user mode.
/// Returns PID or null. Used by the desktop for multitasking.
///
/// `elf_buf` ownership is transferred to this function. On success, the
/// buffer is stashed in `pcb.elf_buf` and freed when the process exits.
/// On any failure path, this function frees `elf_buf` itself — the caller
/// must NOT touch it after the call.
pub fn loadAndStart(elf_buf: [*]align(4) u8, file_size: usize, elf_buf_pages: u32) ?usize {
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

    // User stack: 64KB (16 pages) lazily allocated via the page-fault handler.
    // Pages get backed on first touch, so 64KB stacks cost 0 RSS until used.
    // Top stays at 0x500000 so process.create's initial RSP (0x4FFFF8) is
    // just below it; first push triggers fault-in for the top page.
    const stack_top: usize = 0x500000;
    const stack_pages: usize = 16;
    const stack_base: usize = stack_top - stack_pages * PAGE_SIZE;

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
    pcb.pcid = @import("../cpu/pcid.zig").alloc();
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
    for (0..header.phnum) |i| {
        if (phdrs[i].p_type != 1) continue;
        const p_vaddr: usize = @intCast(phdrs[i].p_vaddr);
        const p_memsz: usize = @intCast(phdrs[i].p_memsz);
        const p_filesz: usize = @intCast(phdrs[i].p_filesz);
        const p_offset: usize = @intCast(phdrs[i].p_offset);
        if (!registerSegmentLazy(pid, elf_buf, p_vaddr, p_memsz, p_filesz, p_offset)) {
            debug.klog("[elf] Lazy regions full registering segment 0x{X}\n", .{p_vaddr});
            process.killProcess(@intCast(pid));
            return null;
        }
    }

    // Parse debug symbols from ELF section headers (use kernel-side ELF buffer).
    pcb.sym_table = symbols.parseElfSymbols(elf_buf, file_size);

    // Init complete — transition .loading → .ready. Until this store, an AP
    // sees the PCB as not-runnable. After this, pickNext can dispatch it
    // and the iretq will land on a fully-initialized address space + lazy
    // region table. assignInitialCpu BEFORE the state flip so the rqEnter
    // setState triggers lands on the right per-CPU runqueue.
    process.assignInitialCpu(pid);
    process.setState(pid, .ready);

    return pid;
}

pub fn loadAndExecute(elf_buf: [*]align(4) u8, file_size: usize, elf_buf_pages: u32) void {
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

    // User stack: 64KB lazy (see loadAndStart for rationale).
    const stack_top: usize = 0x500000;
    const stack_pages: usize = 16;
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
    pcb.pcid = @import("../cpu/pcid.zig").alloc();
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
    const phdrs: [*]align(1) const ProgramHeader = @ptrCast(elf_buf + phoff);
    for (0..header.phnum) |i| {
        if (phdrs[i].p_type != 1) continue;
        const p_vaddr: usize = @intCast(phdrs[i].p_vaddr);
        const p_memsz: usize = @intCast(phdrs[i].p_memsz);
        const p_filesz: usize = @intCast(phdrs[i].p_filesz);
        const p_offset: usize = @intCast(phdrs[i].p_offset);
        if (!isUserVA(p_vaddr, p_memsz)) {
            vga.fg = .LightRed;
            vga.print("Error: segment outside user VA!\n", .{});
            process.killProcess(@intCast(pid));
            return;
        }
        if (!registerSegmentLazy(pid, elf_buf, p_vaddr, p_memsz, p_filesz, p_offset)) {
            vga.fg = .LightRed;
            vga.print("Error: lazy regions full!\n", .{});
            process.killProcess(@intCast(pid));
            return;
        }
    }

    // Parse debug symbols from ELF section headers (use kernel-side ELF buffer).
    pcb.sym_table = symbols.parseElfSymbols(elf_buf, file_size);

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
    @import("../cpu/pcid.zig").loadCr3(pd_phys, pcb.pcid, @import("../cpu/smp.zig").myCpu().cpu_id);

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
