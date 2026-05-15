// x86_64 long mode virtual memory manager
// 4-level paging: PML4 → PDPT → PD → PT
// Each table has 512 entries of u64 (8 bytes each, 4096 bytes per table)

const pmm = @import("pmm.zig");
const paging = @import("paging.zig");
const debug = @import("../debug/debug.zig");
const heap = @import("heap.zig");
const memmap = @import("memmap.zig");

const PRESENT: u64 = paging.PRESENT;
const READ_WRITE: u64 = paging.READ_WRITE;
const USER: u64 = paging.USER;
const PAGE_SIZE_FLAG: u64 = paging.PAGE_SIZE_FLAG;
const PAGE_MASK: u64 = paging.PAGE_MASK;

const PAGE_SIZE: u64 = 4096;
pub const USER_SPACE_START: u64 = memmap.USER_SPACE_START;
pub const USER_SPACE_END: u64 = memmap.USER_SPACE_END;

/// Extract the physical address from a page table entry.
inline fn entryPhys(entry: u64) usize {
    return @intCast(entry & PAGE_MASK);
}

/// Convert a physical address to a page table pointer through the kernel
/// physmap (high-half VA, kernel-only). Replaces the old phys==virt
/// identity reliance — works regardless of whether PML4[0] is still alive.
inline fn tableFromEntry(entry: u64) [*]u64 {
    return @ptrFromInt(paging.physToVirt(entryPhys(entry)));
}

/// Allocate a zeroed page frame and return it as a table pointer (via the
/// physmap so the kernel can write zeros without depending on PML4[0]).
fn allocZeroedTable() ?struct { ptr: [*]u64, phys: usize } {
    const phys = pmm.allocFrame() orelse return null;
    const ptr: [*]u64 = @ptrFromInt(paging.physToVirt(phys));
    @memset(ptr[0..512], 0);
    return .{ .ptr = ptr, .phys = phys };
}

/// Build a page table entry from physical address and flags.
inline fn makeEntry(phys: usize, flags: u64) u64 {
    return @as(u64, @intCast(phys)) | flags;
}

/// Create a new per-process address space (PML4).
///
/// Phase 2d simplified layout:
///   PML4[0]    fresh empty PDPT — user owns the entire low half. mapUserPage
///              fills entries lazily as the process faults pages in. The kernel
///              never accesses low VAs from user CR3 (post-Phase-2c sweep —
///              see paging.physToVirt callers); inheriting kernel low-identity
///              entries here used to be necessary but now is dead weight.
///   PML4[256]  inherited from kernel master — physmap (kernel-only).
///              Required because the kernel's page-table walkers and DMA
///              accesses run under whatever CR3 happens to be loaded.
///   PML4[511]  inherited from kernel master — kernel image at -2 GB.
///              LSTAR / IDT / .text live here, so syscall/IRQ entry needs it.
pub fn createAddressSpace(phys_out: *usize) ?[*]align(4096) u64 {
    const alloc = allocZeroedTable() orelse return null;
    const pml4: [*]align(4096) u64 = @alignCast(alloc.ptr);

    // PML4[0]: fresh empty PDPT. User-owned; mapUserPage will populate as
    // the process touches pages. USER bit on the pointer so user-mode walks
    // can traverse it.
    const pdpt_alloc = allocZeroedTable() orelse {
        pmm.freeFrame(alloc.phys);
        return null;
    };
    pml4[0] = makeEntry(pdpt_alloc.phys, PRESENT | READ_WRITE | USER);

    // Inherit the kernel high-half mappings by reference. Any kernel-side
    // change (e.g., installWriteWatch splitting a 1 GB page) propagates to
    // every process automatically because we share the underlying PDPT pages.
    // [256] = physmap, [258] = vmalloc arena, [511] = kernel image.
    const kernel_pml4: [*]const u64 = @ptrFromInt(paging.physToVirt(paging.getKernelPML4Phys()));
    pml4[256] = kernel_pml4[256];
    pml4[258] = kernel_pml4[258];
    pml4[511] = kernel_pml4[511];

    phys_out.* = alloc.phys;
    return pml4;
}

/// Switch to a different address space by loading CR3.
pub fn switchAddressSpace(phys_pml4: usize) void {
    asm volatile ("movq %[pml4], %%cr3"
        :
        : [pml4] "r" (phys_pml4),
    );
}

/// Map a 4KB user page at the given virtual address in the given PML4.
/// Walks PML4→PDPT→PD→PT, allocating intermediate tables as needed.
/// Handles splitting 1GB pages (UEFI bootloader) at the PDPT level and 2MB
/// pages at the PD level into smaller pages on first user write.
pub fn mapUserPage(pml4: [*]align(4096) u64, virt: usize, phys: usize, flags: u64) void {
    if (virt < USER_SPACE_START or virt >= USER_SPACE_END) return;
    // Protect kernel heap range from user mappings. The check is on the
    // user *virtual* address — user pages can never be mapped at the same
    // VA the kernel has reserved, even though the kernel itself addresses
    // its heap through the physmap (PHYSMAP_BASE + KERNEL_HEAP_BASE). The
    // raw KERNEL_HEAP_BASE constant is the right thing to compare against
    // because USER_SPACE_START..USER_SPACE_END is a low-VA range.
    if (virt >= memmap.KERNEL_HEAP_BASE and virt < memmap.KERNEL_HEAP_BASE + memmap.KERNEL_HEAP_SIZE) return;

    const vaddr: u64 = @intCast(virt);
    const paddr: u64 = @intCast(phys);

    // Extract indices for each level
    const pml4_idx = (vaddr >> 39) & 0x1FF;
    const pdpt_idx = (vaddr >> 30) & 0x1FF;
    const pd_idx = (vaddr >> 21) & 0x1FF;
    const pt_idx = (vaddr >> 12) & 0x1FF;

    // --- Level 1: PML4 → PDPT (always private per-process) ---
    const pdpt = tableFromEntry(pml4[pml4_idx]);

    // --- Level 1.5: split 1GB huge page if present ---
    // The UEFI bootloader maps memory with 1GB huge pages in the PDPT
    // (PAGE_SIZE_FLAG set). Multiboot uses regular PDPT entries. Either
    // way, by the time we're mapping a user page, we need a real PD —
    // so split the 1GB page into 512×2MB entries pointing into the same
    // 1GB region.
    if (pdpt[pdpt_idx] & PRESENT != 0 and pdpt[pdpt_idx] & PAGE_SIZE_FLAG != 0) {
        const gb_phys = pdpt[pdpt_idx] & PAGE_MASK;
        const new_pd = allocZeroedTable() orelse return;
        for (0..512) |i| {
            new_pd.ptr[i] = (gb_phys + @as(u64, @intCast(i)) * 0x200000) |
                PRESENT | READ_WRITE | USER | PAGE_SIZE_FLAG;
        }
        pdpt[pdpt_idx] = makeEntry(new_pd.phys, PRESENT | READ_WRITE | USER);
    }

    // --- Level 2: PDPT → PD ---
    // Phase 3: per-process PML4[0]'s PDPT is fully user-owned (created
    // empty by createAddressSpace; kernel master's PML4[0] is zero). No
    // aliasing of kernel low-half tables, so no COW comparison needed.
    const pd = resolveOrAlloc(pdpt, pdpt_idx) orelse return;

    // --- Level 3: PD → PT ---
    var pt: [*]u64 = undefined;
    if (pd[pd_idx] & PRESENT != 0 and pd[pd_idx] & PAGE_SIZE_FLAG != 0) {
        // Split the 2MB page into 512 × 4KB pages. The original 2MB entry
        // came from the kernel identity map and is now kernel-only (no USER)
        // thanks to createAddressSpace stripping it. Preserve that — only
        // the specific PTE we're about to write below should be USER.
        const large_page_phys = pd[pd_idx] & PAGE_MASK;
        const alloc = allocZeroedTable() orelse return;
        for (0..512) |i| {
            alloc.ptr[i] = (large_page_phys + @as(u64, @intCast(i)) * 4096) | PRESENT | READ_WRITE;
        }
        pd[pd_idx] = makeEntry(alloc.phys, PRESENT | READ_WRITE | USER);
        pt = alloc.ptr;
    } else if (pd[pd_idx] & PRESENT != 0) {
        pt = tableFromEntry(pd[pd_idx]);
    } else {
        const alloc = allocZeroedTable() orelse return;
        pd[pd_idx] = makeEntry(alloc.phys, PRESENT | READ_WRITE | USER);
        pt = alloc.ptr;
    }

    // --- Level 4: Write the 4KB PTE ---
    pt[pt_idx] = (paddr & PAGE_MASK) | flags | PRESENT;

    // kdbg: record the install so post-mortem can answer "who mapped CR2?".
    // Cheap (a struct copy + atomic increment); only the last 64 entries
    // per process are kept.
    const cur_pid: u8 = blk: {
        const cpu = @import("../cpu/smp.zig").myCpu();
        if (cpu.current_pid) |p| break :blk @intCast(p);
        break :blk 0xFF;
    };
    @import("../debug/kdbg.zig").mmapEvent(cur_pid, virt, paddr & PAGE_MASK, flags);
}

/// Resolve an existing table entry or allocate a new one.
///
/// Phase 3: the COW-from-kernel-master path is gone. User PML4[0] is
/// fully private (createAddressSpace allocates a fresh PDPT); no kernel
/// table is ever aliased into the user low half, so there's nothing to
/// copy-on-write. If the entry is present we hand back the existing
/// table; if not we alloc a fresh one.
fn resolveOrAlloc(table: [*]u64, idx: u64) ?[*]u64 {
    if (table[idx] & PRESENT != 0) {
        return tableFromEntry(table[idx]);
    }
    const alloc = allocZeroedTable() orelse return null;
    table[idx] = makeEntry(alloc.phys, PRESENT | READ_WRITE | USER);
    return alloc.ptr;
}

/// Bit 63 of a 64-bit PTE — when set (and EFER.NXE=1), executing from this
/// page traps as a page fault. We enable NXE in `syscall_entry.init` so this
/// bit takes effect.
pub const NX: u64 = @as(u64, 1) << 63;

/// Translate a Linux-style prot bitmask (bit 0 = PROT_READ, bit 1 = PROT_WRITE,
/// bit 2 = PROT_EXEC) into the PTE-flag bits to OR with `PRESENT` when mapping
/// a user page. PROT_READ has no representation — pages are readable as soon
/// as PRESENT is set; PROT_NONE = 0 produces a USER + NX page that traps on
/// any access. Zero-cost for the common RWX case.
pub fn protToMapFlags(prot: u8) u64 {
    var f: u64 = USER;
    if ((prot & 0x02) != 0) f |= READ_WRITE;
    if ((prot & 0x04) == 0) f |= NX;
    return f;
}

/// Allocate a physical frame, map it at the given virtual address with the
/// supplied flags, and zero it. `flags` is the OR of the bits the page-fault
/// resolution path wants — typically `protToMapFlags(region.prot)`. PRESENT
/// is set inside `mapUserPage`; callers don't need to include it.
pub fn allocAndMapUserPage(pml4: [*]align(4096) u64, virt: usize, flags: u64) ?usize {
    const frame = pmm.allocFrame() orelse return null;
    mapUserPage(pml4, virt, frame, flags);
    const ptr: [*]u8 = @ptrFromInt(paging.physToVirt(frame));
    @memset(ptr[0..4096], 0);
    return frame;
}

/// Update the access-control bits on an already-mapped 4KB user page. The
/// physical frame is left untouched; only the PTE flags change. Returns false
/// if the page isn't currently mapped (e.g. a lazy region whose first touch
/// hasn't faulted yet) — the caller (sysMprotect) handles that by updating
/// the lazy region's prot field, so subsequent fault-ins pick up the new
/// flags. Walks read-only — no table allocation.
pub fn changePageProt(pml4: [*]align(4096) u64, virt: usize, flags: u64) bool {
    if (virt < USER_SPACE_START or virt >= USER_SPACE_END) return false;
    const vaddr: u64 = @intCast(virt);
    const pml4_idx = (vaddr >> 39) & 0x1FF;
    const pdpt_idx = (vaddr >> 30) & 0x1FF;
    const pd_idx = (vaddr >> 21) & 0x1FF;
    const pt_idx = (vaddr >> 12) & 0x1FF;

    if (pml4[pml4_idx] & PRESENT == 0) return false;
    const pdpt = tableFromEntry(pml4[pml4_idx]);
    if (pdpt[pdpt_idx] & PRESENT == 0 or pdpt[pdpt_idx] & PAGE_SIZE_FLAG != 0) return false;
    const pd = tableFromEntry(pdpt[pdpt_idx]);
    if (pd[pd_idx] & PRESENT == 0 or pd[pd_idx] & PAGE_SIZE_FLAG != 0) return false;
    const pt = tableFromEntry(pd[pd_idx]);
    if (pt[pt_idx] & PRESENT == 0) return false;

    const phys = pt[pt_idx] & PAGE_MASK;
    pt[pt_idx] = phys | flags | PRESENT;

    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (virt),
        : .{ .memory = true }
    );
    return true;
}

/// Unmap a 4KB user page. Returns the previously-mapped physical frame so the
/// caller can `pmm.freeFrame` it; null if the page wasn't present (e.g. a lazy
/// region that never faulted in). Walks read-only — no table allocation, no
/// huge-page splits. Used by `sysMunmap`.
pub fn unmapUserPage(pml4: [*]align(4096) u64, virt: usize) ?usize {
    if (virt < USER_SPACE_START or virt >= USER_SPACE_END) return null;

    const vaddr: u64 = @intCast(virt);
    const pml4_idx = (vaddr >> 39) & 0x1FF;
    const pdpt_idx = (vaddr >> 30) & 0x1FF;
    const pd_idx = (vaddr >> 21) & 0x1FF;
    const pt_idx = (vaddr >> 12) & 0x1FF;

    if (pml4[pml4_idx] & PRESENT == 0) return null;
    const pdpt = tableFromEntry(pml4[pml4_idx]);
    // 1GB huge page (UEFI bootloader) — we don't unmap into one of those.
    if (pdpt[pdpt_idx] & PRESENT == 0 or pdpt[pdpt_idx] & PAGE_SIZE_FLAG != 0) return null;
    const pd = tableFromEntry(pdpt[pdpt_idx]);
    // 2MB huge page (kernel identity map) — same; only 4KB PTEs are unmappable.
    if (pd[pd_idx] & PRESENT == 0 or pd[pd_idx] & PAGE_SIZE_FLAG != 0) return null;
    const pt = tableFromEntry(pd[pd_idx]);
    if (pt[pt_idx] & PRESENT == 0) return null;

    const frame = pt[pt_idx] & PAGE_MASK;
    pt[pt_idx] = 0;

    // Local-only invalidate. Callers that unmap a batch of pages should
    // issue ONE `tlb.shootdownAll()` after the whole batch — broadcasting
    // per-page would multiply IPI cost N× for the same effect. Single-
    // page callers must still call shootdownAll themselves (this routine
    // doesn't know batch boundaries).
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (virt),
        : .{ .memory = true }
    );

    return @intCast(frame);
}

/// Destroy a per-process address space.
/// Frees user-mapped frames and all private page tables.
///
/// Phase 3 layout: PML4[0] is fully user-owned — `createAddressSpace`
/// allocates a fresh empty PDPT for every new process, and the kernel
/// master's own PML4[0] is zero. There's no aliasing of kernel low-half
/// tables in user space, so the old COW comparison against
/// `kernel_pml4[0]` is dead weight (and after Phase 3 it's actively
/// harmful: `physToVirt(0)` lands on the BIOS area; if a stray bit-51
/// in the BIOS data sneaks through `entryPhys` the next `physToVirt`
/// overflows u64 and ReleaseSafe panics on integer overflow). We simply
/// walk and free everything under PML4[0].
///
/// PML4[256] (physmap) and PML4[511] (kernel image) are inherited by
/// reference and never freed here — the kernel master owns them.
pub fn destroyAddressSpace(pml4: [*]align(4096) u64, pml4_phys: usize) void {
    if (pml4[0] & PRESENT == 0) {
        pmm.freeFrame(pml4_phys);
        return;
    }

    // Walk the private PDPT
    const pdpt: [*]u64 = tableFromEntry(pml4[0]);

    for (0..512) |pdpt_i| {
        if (pdpt[pdpt_i] & PRESENT == 0) continue;
        if (pdpt[pdpt_i] & PAGE_SIZE_FLAG != 0) continue; // 1GB huge — never installed by user

        const pd: [*]u64 = tableFromEntry(pdpt[pdpt_i]);

        for (0..512) |pd_i| {
            if (pd[pd_i] & PRESENT == 0 or pd[pd_i] & PAGE_SIZE_FLAG != 0) continue;

            const pt: [*]u64 = tableFromEntry(pd[pd_i]);

            // Drop one reference per user-mapped 4 KB frame. For non-shared
            // (refcount==1) pages this triggers the actual bitmap free; for
            // COW-shared pages (refcount>1, e.g. parent and child after fork)
            // the surviving address space keeps the frame mapped until its
            // own teardown drops the last reference.
            for (0..512) |pt_i| {
                if (pt[pt_i] & PRESENT != 0 and pt[pt_i] & USER != 0) {
                    const phys = entryPhys(pt[pt_i]);
                    pmm.releaseFrame(phys);
                }
            }

            // Free the page table itself
            pmm.freeFrame(entryPhys(pd[pd_i]));
        }

        // Free the private PD
        pmm.freeFrame(entryPhys(pdpt[pdpt_i]));
    }

    // Free the private PDPT and PML4
    pmm.freeFrame(entryPhys(pml4[0]));
    pmm.freeFrame(pml4_phys);
}

/// Clone an address space for fork(). Walks parent's PML4[0] tree, allocates
/// fresh PDPT/PD/PT pages for the child, and shares each user 4 KB data frame
/// between parent and child via copy-on-write: both PTEs marked R/O + COW, and
/// the PMM refcount bumped so the frame stays alive until both sides release.
///
/// Kernel half (PML4[256] = physmap, PML4[511] = kernel image) is inherited by
/// reference — same as createAddressSpace.
///
/// On OOM partway through, returns null with `phys_out` set to the partial
/// child PML4's phys. The caller MUST then call destroyAddressSpace on the
/// partial child — that path drops every refcount we bumped (releaseFrame on
/// each present user PTE) and frees every child page-table page we allocated.
/// Parent's already-marked-COW PTEs stay COW; the next parent write will
/// fault, see refcount==1, and resolve cleanly via the COW handler.
///
/// After a successful clone, this function flushes the local TLB by reloading
/// CR3 — parent's old R/W TLB entries would otherwise let writes bypass the
/// new R/O+COW marking. Caller is presumed to be running on parent's CR3
/// (sysFork's natural context). Other CPUs are safe by inspection: no thread
/// model yet means no other CPU runs in the parent's address space.
pub fn cloneAddressSpace(parent_pml4: [*]align(4096) u64, phys_out: *usize) ?[*]align(4096) u64 {
    const pml4_alloc = allocZeroedTable() orelse return null;
    const child_pml4: [*]align(4096) u64 = @alignCast(pml4_alloc.ptr);
    phys_out.* = pml4_alloc.phys;

    // Kernel-half by-reference inheritance (same as createAddressSpace).
    // [256] = physmap, [258] = vmalloc arena, [511] = kernel image.
    const kernel_pml4: [*]const u64 = @ptrFromInt(paging.physToVirt(paging.getKernelPML4Phys()));
    child_pml4[256] = kernel_pml4[256];
    child_pml4[258] = kernel_pml4[258];
    child_pml4[511] = kernel_pml4[511];

    // PML4[0]: child gets a private PDPT. Two cases:
    //  - parent has no user mappings (PML4[0] absent): give child an empty PDPT
    //    and we're done.
    //  - parent has mappings: walk parent's PDPT and clone each present entry.
    if (parent_pml4[0] & PRESENT == 0) {
        const child_pdpt_alloc = allocZeroedTable() orelse return null;
        child_pml4[0] = makeEntry(child_pdpt_alloc.phys, PRESENT | READ_WRITE | USER);
        return child_pml4;
    }

    const parent_pdpt: [*]u64 = tableFromEntry(parent_pml4[0]);
    const child_pdpt_alloc = allocZeroedTable() orelse return null;
    const child_pdpt: [*]u64 = child_pdpt_alloc.ptr;
    child_pml4[0] = makeEntry(child_pdpt_alloc.phys, PRESENT | READ_WRITE | USER);

    for (0..512) |pdpt_i| {
        const parent_pdpte = parent_pdpt[pdpt_i];
        if (parent_pdpte & PRESENT == 0) continue;
        if (parent_pdpte & PAGE_SIZE_FLAG != 0) continue; // 1 GB huge — never under user

        const parent_pd: [*]u64 = tableFromEntry(parent_pdpte);
        const child_pd_alloc = allocZeroedTable() orelse return null;
        const child_pd: [*]u64 = child_pd_alloc.ptr;
        child_pdpt[pdpt_i] = makeEntry(child_pd_alloc.phys, parent_pdpte & 0xFFF);

        for (0..512) |pd_i| {
            const parent_pde = parent_pd[pd_i];
            if (parent_pde & PRESENT == 0) continue;
            if (parent_pde & PAGE_SIZE_FLAG != 0) continue; // 2 MB huge — kernel identity, not user

            const parent_pt: [*]u64 = tableFromEntry(parent_pde);
            const child_pt_alloc = allocZeroedTable() orelse return null;
            const child_pt: [*]u64 = child_pt_alloc.ptr;
            child_pd[pd_i] = makeEntry(child_pt_alloc.phys, parent_pde & 0xFFF);

            for (0..512) |pt_i| {
                const parent_pte = parent_pt[pt_i];
                if (parent_pte & PRESENT == 0) continue;
                if (parent_pte & USER == 0) continue; // skip non-user (shouldn't appear under PML4[0] anyway)

                const phys = entryPhys(parent_pte);
                pmm.acquireFrame(phys);

                if (parent_pte & READ_WRITE != 0) {
                    // Writable page: mark BOTH sides R/O+COW. First write on
                    // either side faults into the COW handler, which alloc's
                    // a private copy and clears COW for that side.
                    const cow_pte = (parent_pte & ~READ_WRITE) | paging.COW;
                    parent_pt[pt_i] = cow_pte;
                    child_pt[pt_i] = cow_pte;
                } else {
                    // Already read-only (text/rodata or PROT_READ mmap): no
                    // need to mark COW — a write was illegal before fork and
                    // stays illegal after. Share the PTE as-is.
                    child_pt[pt_i] = parent_pte;
                }
            }
        }
    }

    // Flush parent's stale R/W TLB entries. Full CR3 reload is the cheapest
    // way for any non-trivial process — invlpg per page would loop thousands
    // of times for a healthy address space.
    asm volatile (
        \\movq %%cr3, %%rax
        \\movq %%rax, %%cr3
        :
        :
        : .{ .rax = true, .memory = true }
    );

    return child_pml4;
}
