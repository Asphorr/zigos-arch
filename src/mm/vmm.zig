// x86_64 long mode virtual memory manager
// 4-level paging: PML4 → PDPT → PD → PT
// Each table has 512 entries of u64 (8 bytes each, 4096 bytes per table)

const pmm = @import("pmm.zig");
const paging = @import("paging.zig");
const debug = @import("../debug/debug.zig");
const heap = @import("heap.zig");
const memmap = @import("memmap.zig");
const swap = @import("swap.zig");

const PRESENT: u64 = paging.PRESENT;
const READ_WRITE: u64 = paging.READ_WRITE;
const USER: u64 = paging.USER;
const PAGE_SIZE_FLAG: u64 = paging.PAGE_SIZE_FLAG;
const PAGE_MASK: u64 = paging.PAGE_MASK;

// Gap #14 (2026-05-20): the local `const PAGE_SIZE: u64 = 4096;` was
// dead code — never referenced anywhere in this file. Deleted.
pub const USER_SPACE_START: u64 = memmap.USER_SPACE_START;
pub const USER_SPACE_END: u64 = memmap.USER_SPACE_END;

/// Errors `mapUserPage` can return. Replacing the previous `void` signature
/// is a load-bearing change: silent rejection was the bug class behind the
/// 2026-05-20 Q1 lazy-fault leak (the PF handler called mapUserPage,
/// assumed success, fault re-fired forever — leaking 200 MB of frames
/// before OOM). Each variant names a distinct caller-policy outcome:
///   BadVA         — virt outside USER_SPACE_START..USER_SPACE_END.
///                   Programmer bug or malicious user-VA in syscall arg.
///                   Caller should fail the syscall with E_FAULT / SIGSEGV.
///   KernelHeap    — virt collides with the kernel heap reservation.
///                   Same response as BadVA.
///   Oom           — PT/PD/PDPT alloc failed under PMM pressure. Caller
///                   should run reclaim + retry, then OOM-kill if still
///                   short. Not a programmer bug.
///   AlreadyMapped — virt already has a *different* physical frame
///                   installed. Either a race (two CPUs faulting on the
///                   same page) or a caller bug (double-mmap without
///                   unmap). `allocAndMapUserPage` treats this as a race
///                   and returns the winning frame; explicit syscall
///                   paths should roll back and return E_BUSY / E_INVAL.
pub const MapError = error{ BadVA, Oom, AlreadyMapped };

/// Invalidate the TLB entry for a single virtual address on the local
/// CPU only. Used inside vmm by single-page mutators; batch callers
/// (sysMunmap range) should still do ONE tlb.shootdownAll() after the
/// whole batch — invlpg per page would multiply IPI cost N×.
inline fn invlpg(virt: usize) void {
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (virt),
        : .{ .memory = true });
}

/// Extract the physical address from a page table entry.
inline fn entryPhys(entry: u64) usize {
    return @intCast(entry & PAGE_MASK);
}

/// Convert a physical address to a page table pointer through the kernel
/// physmap (high-half VA, kernel-only). Replaces the old phys==virt
/// identity reliance — works regardless of whether PML4[0] is still alive.
///
/// Gap #9 (2026-05-20): panic if PRESENT is clear. Every current caller
/// already checks PRESENT first; the panic catches future callers that
/// forget. Without it, a `tableFromEntry(non_present)` returns
/// `physToVirt(0)` — which lands on the BIOS area, and a stray non-zero
/// bit in the BIOS data could overflow u64 inside the next physToVirt
/// (ReleaseSafe panics on integer overflow, masking the real cause).
inline fn tableFromEntry(entry: u64) [*]u64 {
    if (entry & PRESENT == 0) @panic("tableFromEntry: entry not present");
    const phys = entryPhys(entry);
    // Validate phys is within physmap-covered range. A garbage PD entry
    // (corrupted table page) can have bit 51 set in the phys field; the
    // next `physToVirt(phys) = PHYSMAP_BASE + phys` then overflows u64
    // and ReleaseSafe panics on integer overflow without telling us the
    // original PTE was the problem. With this guard, the panic message
    // points at the corrupt PTE directly so the autopsy ring lookup in
    // pmm.freeFrame's underflow path lines up with the right phys.
    if (phys >= paging.PHYSMAP_SIZE) {
        @import("../debug/serial.zig").print(
            "[vmm] tableFromEntry: out-of-physmap PTE=0x{X} phys=0x{X} — table page is corrupt\n",
            .{ entry, phys },
        );
        @panic("tableFromEntry: phys outside physmap (corrupt PTE)");
    }
    return @ptrFromInt(paging.physToVirt(phys));
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

// Gap #6 (2026-05-20): vmm.switchAddressSpace was removed in favor of
// the PCID-aware cpu/pcid.zig:loadCr3(pml4_phys, pcid, cpu_id). All four
// previous callers (desktop, process, two stress tests) were switching
// TO the kernel PML4 — they now call pcid.loadCr3(kernel_pml4, 0, cpu_id)
// directly. pcid=0 falls through to a plain CR3 write in loadCr3, so
// behavior is identical; the win is structural — pcid.zig's invariant
// "all CR3 writes go through loadCr3" is no longer false.

/// Map a 4KB user page at the given virtual address in the given PML4.
/// Walks PML4→PDPT→PD→PT, allocating intermediate tables as needed.
/// Handles splitting 1GB pages (UEFI bootloader) at the PDPT level and 2MB
/// pages at the PD level into smaller pages on first user write.
///
/// Returns `MapError` on rejection (see the enum doc-comment for the policy
/// each variant implies). The previous `void` signature swallowed every
/// failure mode silently — see the 2026-05-20 Q1 lazy-fault-leak post-mortem.
/// Callers MUST handle the error union; the PF handler in particular needs
/// `BadVA` / `KernelHeap` to deliver SIGSEGV instead of looping.
///
/// `AlreadyMapped` is returned ONLY when the PTE points at a different phys
/// than the one being installed. Same-phys + new-flags is a no-op (we'd be
/// installing the same mapping) and is reported as success after a local
/// invlpg to make sure the flag change is visible. This keeps the contract
/// idempotent under multi-CPU lazy-fault races.
pub fn mapUserPage(pml4: [*]align(4096) u64, virt: usize, phys: usize, flags: u64) MapError!void {
    if (virt < USER_SPACE_START or virt >= USER_SPACE_END) return error.BadVA;
    // Historical note: this used to also reject any user VA falling inside
    // [KERNEL_HEAP_BASE, KERNEL_HEAP_BASE+KERNEL_HEAP_SIZE) as a defense
    // against user/kernel low-half aliasing. That check was vestigial
    // post-Phase-3 (kernel master PML4[0] is dropped to 0 — kernel reaches
    // every low-PA frame through the high-half physmap, never through
    // a low-half VA, so a user mapping at user-VA 0xA00000 in a per-process
    // PT cannot collide with the kernel's heap PHYS at the same number).
    // It crashed Quake1 (region[3] spans 0x56E000..0x1622000, straddling
    // the heap range) on its first BSS page-fault inside the forbidden
    // window. Removed 2026-05-20.

    const vaddr: u64 = @intCast(virt);
    const paddr: u64 = @intCast(phys);

    // Extract indices for each level
    const pml4_idx = (vaddr >> 39) & 0x1FF;
    const pdpt_idx = (vaddr >> 30) & 0x1FF;
    const pd_idx = (vaddr >> 21) & 0x1FF;
    const pt_idx = (vaddr >> 12) & 0x1FF;

    // --- Level 1: PML4 → PDPT (always private per-process) ---
    const pdpt = tableFromEntry(pml4[pml4_idx]);

    // --- Level 1.5: 1 GB huge-page split (Phase 3 unreachable) ---
    // Gap #11 (2026-05-20): under Phase 3 the kernel master PML4[0] is
    // zero (see paging.dropKernelLowHalf), and `createAddressSpace` gives
    // every process a fresh empty PDPT. There's no inheritance path that
    // could put a 1 GB huge in user PDPT[*]. Pre-Phase 3 this branch
    // existed to handle UEFI's 1 GB identity map leaking into the user
    // PDPT by reference; that vector is closed. If we ever hit this
    // panic, the boot-time PML4 layout has regressed — we'd rather know
    // than silently split kernel-owned memory into user-accessible pages.
    if (pdpt[pdpt_idx] & PRESENT != 0 and pdpt[pdpt_idx] & PAGE_SIZE_FLAG != 0) {
        @panic("mapUserPage: 1 GB huge in user PDPT — Phase 3 invariant violated");
    }

    // --- Level 2: PDPT → PD ---
    // Phase 3: per-process PML4[0]'s PDPT is fully user-owned (created
    // empty by createAddressSpace; kernel master's PML4[0] is zero). No
    // aliasing of kernel low-half tables, so no COW comparison needed.
    const pd = try resolveOrAlloc(pdpt, pdpt_idx);

    // --- Level 3: PD → PT ---
    // Gap #11 (2026-05-20): same Phase 3 reasoning as the 1 GB branch
    // above — a 2 MB huge under user PD can only exist if a 1 GB split
    // installed it, and the 1 GB split is now unreachable. Panic if it
    // fires; we'd rather catch the regression than silently install
    // 511 kernel-only sibling PTEs that the user then re-faults through
    // one at a time (and which would also collide with the new
    // gap #2 AlreadyMapped check, producing spurious lazy-fault rejects).
    var pt: [*]u64 = undefined;
    if (pd[pd_idx] & PRESENT != 0 and pd[pd_idx] & PAGE_SIZE_FLAG != 0) {
        @panic("mapUserPage: 2 MB huge in user PD — Phase 3 invariant violated");
    } else if (pd[pd_idx] & PRESENT != 0) {
        pt = tableFromEntry(pd[pd_idx]);
    } else {
        const alloc = allocZeroedTable() orelse return error.Oom;
        pd[pd_idx] = makeEntry(alloc.phys, PRESENT | READ_WRITE | USER);
        pt = alloc.ptr;
    }

    // --- Level 4: Check the 4KB PTE, then write ---
    // Gap #2 fix: detect double-install. The previous `pt[pt_idx] = ...`
    // unconditionally overwrote any prior frame, leaking it. The kdbg
    // mmap-ring's "same virt twice with different phys" autopsy was
    // pointing at THIS line.
    //
    // Multi-CPU lazy-fault race policy:
    //   - Same phys, same flags: idempotent. Treat as success.
    //   - Same phys, different flags: flag update (mprotect-via-remap).
    //     Write the new flags + local invlpg so the CPU sees them.
    //   - Different phys: error.AlreadyMapped. Caller (typically
    //     allocAndMapUserPage) frees its newly-allocated frame and
    //     uses the winner's mapping.
    const new_pte: u64 = (paddr & PAGE_MASK) | flags | PRESENT;
    const old_pte = pt[pt_idx];
    if (old_pte & PRESENT != 0) {
        // Compare phys in u64 form on both sides to dodge usize/u64
        // mismatch (paddr is u64 since line 109's @intCast, old_pte is
        // u64 from pt[*u64]). Same-phys → flag update or no-op; different
        // phys → AlreadyMapped.
        if ((old_pte & PAGE_MASK) != (paddr & PAGE_MASK)) return error.AlreadyMapped;
        if (old_pte == new_pte) return; // already exactly what we want
        pt[pt_idx] = new_pte;
        invlpg(virt);
    } else {
        pt[pt_idx] = new_pte;
    }

    // kdbg: record the install so post-mortem can answer "who mapped CR2?".
    // Only the success path lands here — the error returns above don't
    // pollute the ring with would-be-installs that bounced.
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
fn resolveOrAlloc(table: [*]u64, idx: u64) MapError![*]u64 {
    if (table[idx] & PRESENT != 0) {
        return tableFromEntry(table[idx]);
    }
    const alloc = allocZeroedTable() orelse return error.Oom;
    table[idx] = makeEntry(alloc.phys, PRESENT | READ_WRITE | USER);
    return alloc.ptr;
}

/// Read-only walk: return the physical frame currently mapped at `virt`,
/// or null if not present / outside the user range / under a huge page.
/// Does NOT allocate intermediate tables — purely diagnostic / race-resolution
/// (`allocAndMapUserPage` calls this on the `AlreadyMapped` branch to
/// recover the winner's phys so the caller can still memcpy file-backed
/// content into it).
pub fn resolveUserPhys(pml4: [*]align(4096) u64, virt: usize) ?usize {
    if (virt < USER_SPACE_START or virt >= USER_SPACE_END) return null;
    const vaddr: u64 = @intCast(virt);
    const pml4_idx = (vaddr >> 39) & 0x1FF;
    const pdpt_idx = (vaddr >> 30) & 0x1FF;
    const pd_idx = (vaddr >> 21) & 0x1FF;
    const pt_idx = (vaddr >> 12) & 0x1FF;

    if (pml4[pml4_idx] & PRESENT == 0) return null;
    const pdpt = tableFromEntry(pml4[pml4_idx]);
    if (pdpt[pdpt_idx] & PRESENT == 0 or pdpt[pdpt_idx] & PAGE_SIZE_FLAG != 0) return null;
    const pd = tableFromEntry(pdpt[pdpt_idx]);
    if (pd[pd_idx] & PRESENT == 0 or pd[pd_idx] & PAGE_SIZE_FLAG != 0) return null;
    const pt = tableFromEntry(pd[pd_idx]);
    if (pt[pt_idx] & PRESENT == 0) return null;
    return entryPhys(pt[pt_idx]);
}

/// Pointer to the leaf PTE for `virt` in `pml4`, or null if the page tables
/// down to the PT don't exist (an upper level not present, or a huge page).
/// Unlike resolveUserPhys, this returns the pointer EVEN when the leaf itself
/// is not present — so the swap subsystem can read/rewrite a swapped-out
/// (not-present) entry, and the page-fault handler can test for one.
pub fn userPtePtr(pml4: [*]align(4096) u64, virt: usize) ?*u64 {
    if (virt < USER_SPACE_START or virt >= USER_SPACE_END) return null;
    const vaddr: u64 = @intCast(virt);
    const pml4_idx = (vaddr >> 39) & 0x1FF;
    const pdpt_idx = (vaddr >> 30) & 0x1FF;
    const pd_idx = (vaddr >> 21) & 0x1FF;
    const pt_idx = (vaddr >> 12) & 0x1FF;

    if (pml4[pml4_idx] & PRESENT == 0) return null;
    const pdpt = tableFromEntry(pml4[pml4_idx]);
    if (pdpt[pdpt_idx] & PRESENT == 0 or pdpt[pdpt_idx] & PAGE_SIZE_FLAG != 0) return null;
    const pd = tableFromEntry(pdpt[pdpt_idx]);
    if (pd[pd_idx] & PRESENT == 0 or pd[pd_idx] & PAGE_SIZE_FLAG != 0) return null;
    const pt = tableFromEntry(pd[pd_idx]);
    return &pt[pt_idx];
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
///
/// Returns the physical frame the caller should write into. Under the
/// multi-CPU lazy-fault race (two CPUs page-fault on the same virt at the
/// same time), the loser sees `AlreadyMapped` from mapUserPage, frees its
/// own freshly-allocated frame, walks for the winner's phys, and returns
/// THAT — so the caller's subsequent memcpy lands on the same physical
/// page the winner installed. Idempotent for read-only ELF file-backed
/// content; harmless for BSS / anonymous (both sides zero the same page).
///
/// Errors:
///   Oom           — pmm has no free user frame, OR a page-table alloc failed
///                   while walking down. Caller should run reclaim + retry.
///   BadVA/KernelHeap — virt is not a valid user-mappable address. Caller
///                      should SIGSEGV.
///   (AlreadyMapped is NOT propagated — it's resolved internally.)
pub fn allocAndMapUserPage(pml4: [*]align(4096) u64, virt: usize, flags: u64) MapError!usize {
    // User-data frame: respects the PMM reserve so a user-driven lazy
    // fault can't eat into the kernel emergency pool.
    const frame = pmm.allocFrameUser() orelse return error.Oom;
    mapUserPage(pml4, virt, frame, flags) catch |e| switch (e) {
        // Race resolved — another CPU faulted in this page while we were
        // allocating. Give our frame back; tell the caller to use the
        // existing one. resolveUserPhys can only fail here if the
        // winner's mapping got torn down between mapUserPage's PRESENT
        // check and our walk — vanishingly rare, but possible during
        // teardown; surface as Oom so the fault handler kills the proc.
        error.AlreadyMapped => {
            pmm.freeFrame(frame);
            return resolveUserPhys(pml4, virt) orelse error.Oom;
        },
        // Genuine failures — give the frame back, propagate the cause.
        // (Including Oom-from-PT-alloc-deep-in-mapUserPage: our user
        // frame is fine but a page-table page wasn't, so the address
        // space couldn't grow to hold the PTE.)
        else => {
            pmm.freeFrame(frame);
            return e;
        },
    };
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
    // Gap #10 (2026-05-20): defensively OR-in USER. The only current caller
    // (sysMprotect via protToMapFlags) already sets USER, but bit-OR can't
    // clear bits — adding it here means a future caller forgetting to
    // include USER can't accidentally turn a user page kernel-only. Cheap
    // belt-and-suspenders for a function whose contract is "change PROT
    // bits on an existing USER mapping."
    pt[pt_idx] = phys | flags | PRESENT | USER;

    invlpg(virt);
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
    // use `unmapUserRange` (gap #7) — it shares the PT pointer across
    // the whole batch and reclaims empty intermediate tables (gap #8).
    // Single-page callers must still issue tlb.shootdownAll themselves
    // (this routine doesn't know batch boundaries).
    invlpg(virt);

    return @intCast(frame);
}

/// Unmap every present 4 KB user PTE in `[start, end)`. Calls
/// `pmm.freeFrame` on each released phys; returns the count freed.
///
/// Gap #7 (2026-05-20): replacement for the sysMunmap pattern
///     `while (...) if (unmapUserPage(...)) |f| pmm.freeFrame(f);`
/// which did a full PML4→PT walk per page. Here we walk to the PT once
/// per 2 MB span and iterate the per-PT slice inline — ~100× fewer
/// indirections on a 64 MB munmap.
///
/// Gap #8 (2026-05-20): when a PT becomes empty after our unmap pass
/// (no present entries from anyone, not just our range), we free the
/// PT page and clear the PD entry; if the PD goes empty, free it and
/// clear the PDPT entry. The cascade stops at PDPT — the per-process
/// PML4[0]'s PDPT is owned by `createAddressSpace` and reclaimed only
/// by `destroyAddressSpace`. Without this, a long-running process that
/// allocates and frees large heap regions keeps every page-table page
/// it ever touched, fragmenting the user-half page-table tree forever.
///
/// Does NOT do per-page invlpg or any TLB invalidation — the caller
/// (typically `sysMunmap`) is expected to issue one `tlb.shootdownAll`
/// after the whole batch.
pub fn unmapUserRange(pml4: [*]align(4096) u64, start: usize, end: usize) usize {
    if (start >= end) return 0;
    const range_start = start & ~@as(usize, 0xFFF);
    const range_end = (end + 0xFFF) & ~@as(usize, 0xFFF);
    if (range_start < USER_SPACE_START or range_end > USER_SPACE_END) return 0;

    var freed: usize = 0;
    var span = range_start & ~@as(usize, 0x1FFFFF); // 2 MB aligned

    while (span < range_end) : (span += 0x200000) {
        const pml4_idx = (span >> 39) & 0x1FF;
        const pdpt_idx = (span >> 30) & 0x1FF;
        const pd_idx = (span >> 21) & 0x1FF;

        // Skip 2 MB spans whose tables aren't allocated. Huge-page spans
        // (1 GB at PDPT or 2 MB at PD) are also skipped — sysMunmap can't
        // legitimately unmap into one since they're either kernel
        // identity or UEFI bootloader leftovers.
        if (pml4[pml4_idx] & PRESENT == 0) continue;
        const pdpt = tableFromEntry(pml4[pml4_idx]);
        if (pdpt[pdpt_idx] & PRESENT == 0 or pdpt[pdpt_idx] & PAGE_SIZE_FLAG != 0) continue;
        const pd = tableFromEntry(pdpt[pdpt_idx]);
        if (pd[pd_idx] & PRESENT == 0 or pd[pd_idx] & PAGE_SIZE_FLAG != 0) continue;
        const pt = tableFromEntry(pd[pd_idx]);

        // Clamp the range to the intersection of [span, span+2M) and
        // [range_start, range_end). For the middle of a large munmap
        // this is the full 512 PTEs; for the head/tail span it's a
        // partial slice.
        const lo = @max(span, range_start);
        const hi = @min(span + 0x200000, range_end);
        const pt_idx_lo: usize = (lo >> 12) & 0x1FF;
        const pt_idx_hi_excl: usize = pt_idx_lo + ((hi - lo) >> 12);

        var i: usize = pt_idx_lo;
        while (i < pt_idx_hi_excl) : (i += 1) {
            const pte = pt[i];
            if (pte & PRESENT != 0 and pte & USER != 0) {
                pt[i] = 0;
                pmm.freeFrame(@intCast(pte & PAGE_MASK));
                freed += 1;
            } else {
                // Non-PRESENT: may be SWAPPED, SWAP_INFLIGHT (mid-eviction on
                // another thread), or 0. teardownNonPresent CAS-claims the PTE
                // and releases the right resource (slot or pinned frame). The
                // CAS is needed because a concurrent evictor may flip
                // SWAP_INFLIGHT → SWAPPED at any moment; without CAS we'd
                // race and either double-free or leak.
                _ = swap.teardownNonPresent(&pt[i]);
            }
        }

        // Gap #8: empty-PT reclamation. Scan all 512 slots — if none
        // remain present, free the PT and clear the parent PD entry.
        // Then cascade: if the PD itself is now empty, free it and
        // clear the parent PDPT entry. Don't touch the PDPT — it's
        // the per-process root that destroyAddressSpace owns.
        var pt_used = false;
        for (0..512) |j| {
            if (pt[j] & PRESENT != 0) { pt_used = true; break; }
        }
        if (!pt_used) {
            pmm.freeFrame(entryPhys(pd[pd_idx]));
            pd[pd_idx] = 0;

            var pd_used = false;
            for (0..512) |j| {
                if (pd[j] & PRESENT != 0) { pd_used = true; break; }
            }
            if (!pd_used) {
                pmm.freeFrame(entryPhys(pdpt[pdpt_idx]));
                pdpt[pdpt_idx] = 0;
            }
        }
    }
    return freed;
}

/// Gap #12 (2026-05-20): public iterator over every present 4 KB user PTE
/// under `pml4`. Calls `callback(ctx, virt, phys, flags)` per page. Skips
/// huge pages (none should exist in user space under Phase 3 — see gap
/// #11 — but we defensively skip rather than panic so iteration is safe
/// to call from autopsy paths). Read-only: never mutates the tree.
///
/// Two use cases this unlocks without duplicating the descent loop:
///   - "count user-mapped pages of pid N" for RSS reporting
///   - "find all writable mappings in range" for security audits
/// Existing single-VA walker `kdbg.walkUserPT` is unaffected; this is the
/// all-pages variant.
pub fn forEachUserPage(
    pml4: [*]align(4096) u64,
    ctx: anytype,
    comptime callback: anytype,
) void {
    if (pml4[0] & PRESENT == 0) return;
    const pdpt = tableFromEntry(pml4[0]);
    for (0..512) |pdpt_i| {
        const pdpte = pdpt[pdpt_i];
        if (pdpte & PRESENT == 0) continue;
        if (pdpte & PAGE_SIZE_FLAG != 0) continue;
        const pd = tableFromEntry(pdpte);
        for (0..512) |pd_i| {
            const pde = pd[pd_i];
            if (pde & PRESENT == 0) continue;
            if (pde & PAGE_SIZE_FLAG != 0) continue;
            const pt = tableFromEntry(pde);
            for (0..512) |pt_i| {
                const pte = pt[pt_i];
                if (pte & PRESENT == 0) continue;
                if (pte & USER == 0) continue;
                // pml4_i is always 0 for user space (PML4[0]'s subtree).
                const virt: usize = (pdpt_i << 30) | (pd_i << 21) | (pt_i << 12);
                callback(ctx, virt, entryPhys(pte), pte & 0xFFF);
            }
        }
    }
}

/// Convenience built on `forEachUserPage`: count present 4 KB user PTEs.
/// O(populated entries), not O(262144) — short-circuits at every level.
pub fn countUserPages(pml4: [*]align(4096) u64) usize {
    const Counter = struct {
        n: usize = 0,
        fn cb(self: *@This(), _: usize, _: usize, _: u64) void {
            self.n += 1;
        }
    };
    var c: Counter = .{};
    forEachUserPage(pml4, &c, Counter.cb);
    return c.n;
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

    // Walk the private PDPT.
    //
    // Gap #16 (2026-05-20): the walk is O(populated entries) because each
    // level short-circuits on `PRESENT == 0`. A process that did proper
    // munmap before exit has already triggered gap #8's empty-PT/PD
    // reclamation, so most of the tree is already gone — destroy just
    // sweeps the kernel-half-inherited skeleton plus whatever pages were
    // still live at exit. Sparse-bitmap optimization (track populated
    // PDPT entries to skip whole 512-byte subtrees) would speed up
    // pathological cases but adds memory + complexity for negligible
    // wins on the realistic workload.
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
                const pte = pt[pt_i];
                if (pte & PRESENT != 0 and pte & USER != 0) {
                    pmm.releaseFrame(entryPhys(pte));
                } else {
                    // Evicted page (SWAPPED) or in-flight eviction
                    // (SWAP_INFLIGHT) held by this dying address space: release
                    // the slot OR the pinned frame respectively. teardownNonPresent
                    // CAS-claims the PTE so it can't race with a concurrent
                    // evictor finishing on another CPU. PT is freed right after,
                    // so the CAS-to-0 side effect is harmless.
                    _ = swap.teardownNonPresent(&pt[pt_i]);
                }
            }

            // Free the page table itself
            pmm.freeFrame(entryPhys(pd[pd_i]));
        }

        // Free the private PD
        pmm.freeFrame(entryPhys(pdpt[pdpt_i]));
    }

    // Free the private PDPT
    pmm.freeFrame(entryPhys(pml4[0]));

    // Gap #4 (2026-05-20): TLB hygiene at teardown. We just freed every
    // user-mapped frame and every private page-table page. If anything
    // in the kernel touches a user VA between now and the caller's next
    // CR3 load (context switch), the TLB still holds the old translations
    // → it reaches into now-recycled PMM frames. A full CR3 reload flushes
    // the entire user half cheaply; invlpg per freed page would loop tens
    // of thousands of times for a healthy process. PCID-preserve bit 63 is
    // deliberately NOT set: we WANT every user-VA TLB entry gone.
    //
    // Order matters: the reload re-walks the pml4 (still mapped at
    // pml4_phys) to refresh the kernel-half entries it inherits. If we
    // freed pml4_phys first, the reload would walk a possibly-recycled
    // frame. Reloading BEFORE the freeFrame keeps the walk safe; by the
    // time the caller (destroyCurrent) switches CR3 to the next process,
    // the kernel-half walks are TLB-cached and no longer need pml4_phys.
    asm volatile (
        \\movq %%cr3, %%rax
        \\movq %%rax, %%cr3
        :
        :
        : .{ .rax = true, .memory = true });

    // Free the PML4 itself
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
///
/// Gap #13 (2026-05-20, deferred): the all-R/O PT case (text segments,
/// PROT_READ mmaps) currently allocates a fresh child PT and copies entries
/// individually even though every entry is identical. A real "PT-sharing"
/// optimization would point child's PD[pd_i] at the parent's PT directly
/// (with a PT-page refcount); first child write that touches an R/O page
/// in such a shared PT would also trigger a PT-page-break before installing
/// the writable copy. Real saving: ~4 KB per shared PT (~32 KB per fork of
/// a 16 MB text mapping). Implementation requires per-page-table-page
/// refcounting + a "shared PT" PTE bit, plus matching unmap-side awareness.
/// Worth doing if/when fork-heavy workloads appear (none today — Doom and
/// Quake load via exec, not fork). Documented here as the architectural
/// next step.
///
/// SWAPPED PAGES: a parent PTE that is out on swap (PRESENT=0 + SWAPPED marker)
/// is SKIPPED by the present-check below — the child does NOT inherit it. So a
/// fork-without-exec child that reads a page the parent had swapped before the
/// fork sees a fresh zero page (anon) or a re-read of `source` (file-backed),
/// not the parent's copy. Harmless in practice (fork is ~always followed by
/// exec, which tears down PML4[0]); a complete fix would swap the parent's
/// pages in before cloning. Tracked as a swap follow-up.
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
