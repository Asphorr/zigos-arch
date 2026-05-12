// x86_64 long mode paging — 4-level page tables (PML4→PDPT→PD→PT)
// Both bootloaders identity-map the first 64 GB with 1 GB huge pages
// (boot.asm: PML4→PDPT[0..63] PS=1; uefi/uefi_boot.zig does the same).
// The kernel paging module is minimal: most mappings are already done by boot.
//
// Kernel: identity-mapped at physical addresses (0–64 GB via 1 GB pages)
// User: 0x400000-0x0FFFFFFF (GUI FB at 0x08000000, up to 16MB)

const pmm = @import("pmm.zig");
const memmap = @import("memmap.zig");

// Page table entry flags (same bit positions in x86_64)
pub const PRESENT: u64 = 1 << 0;
pub const READ_WRITE: u64 = 1 << 1;
pub const USER: u64 = 1 << 2;
pub const WRITE_THROUGH: u64 = 1 << 3; // PWT — write-through caching
pub const CACHE_DISABLE: u64 = 1 << 4; // PCD — uncached (set for MMIO)
// Multi-level: at PDPT entry = 1GB page, at PD entry = 2MB page. Never set
// at PML4 in our setup (would mean 512GB pages, no boot path uses them).
pub const PAGE_SIZE_FLAG: u64 = 1 << 7;
// Software-available bit 9 — set on PTEs that are copy-on-write. Combined
// with cleared READ_WRITE, the page-fault handler distinguishes COW pages
// (alloc + copy + remap R/W on write fault) from genuine read-only pages
// (segfault on write). Bits 10/11 remain free for future flags.
pub const COW: u64 = 1 << 9;

// PAT bit positions — different for 4KB vs huge pages. Combined with
// PCD/PWT, the 3 bits index into IA32_PAT MSR's 8 type slots.
pub const PAT_BIT_4K: u64 = 1 << 7; // 4KB PTE
pub const PAT_BIT_HUGE: u64 = 1 << 12; // 2MB PDE / 1GB PDPTE (PS=1)

// Bit 63 — No-Execute. Requires EFER.NXE=1 (paging requires this on x86_64
// with our setup; cpuid_info.requireFeatures rejects boot if NX is missing).
pub const NX: u64 = 1 << 63;

// Phys-address mask depends on the leaf size. PTE/PDE/PDPTE all reserve
// bits 12..51 conceptually, but huge-page leaves zero out the low bits
// covered by the page itself (bits 12..20 reserved on 2MB PDE, 12..29
// reserved on 1GB PDPTE). Splitting code MUST use the matching mask or
// it will copy garbage in those reserved bits — currently zero in our
// boot map but firmware-dependent on real HW.
pub const PAGE_MASK: u64 = 0x000FFFFFFFFFF000; // 4KB PTE phys (bits 12..51)
pub const PAGE_MASK_2M: u64 = 0x000FFFFFFFE00000; // 2MB PDE phys (bits 21..51)
pub const PAGE_MASK_1G: u64 = 0x000FFFFFC0000000; // 1GB PDPTE phys (bits 30..51)

// When splitting a huge-page leaf into a pointer entry, only the
// access-control bits transfer — cache bits (PCD/PWT/PAT) on a pointer
// entry govern the *table page itself*, which is normal kernel memory and
// wants WB (= zeros). Leaf flags (cache type, COW, GLOBAL, ...) get
// re-applied per-leaf below the new pointer.
pub const PTR_FLAGS_MASK: u64 = PRESENT | READ_WRITE | USER | NX;

// Higher-half kernel translation.
//
// Three kernel windows (boot.asm sets them up; src/linker.ld places the
// kernel image at the high one):
//
//   PHYSMAP_BASE   = 0xFFFF800000000000  PML4[256], 64 GB → phys 0..64 GB.
//                                        Kernel-only. The canonical "kernel
//                                        can reach any phys frame" view.
//   KERNEL_VIRT_BASE = 0xFFFFFFFF80000000 PML4[511]+PDPT[510], 1 GB →
//                                        phys 0..1 GB. Kernel image (.text,
//                                        .rodata, .data, .bss) lives here.
//
// During Phase 2 the legacy low identity (PML4[0]) is *also* live so callers
// that haven't migrated keep working. Phase 2d drops it.
//
// physToVirt:  phys → high-half pointer-as-int (via physmap)
// virtToPhys:  any kernel VA → phys, regardless of which window it lives in
//
// The constants live in memmap.zig (single-source-of-truth for the static
// memory map). Re-aliased here as compile-time u64s so this module's call
// sites stay terse.
pub const KERNEL_VIRT_BASE: u64 = memmap.KERNEL_VIRT_BASE;
pub const PHYSMAP_BASE: u64 = memmap.PHYSMAP_BASE;
pub const PHYSMAP_SIZE: u64 = memmap.PHYSMAP_SIZE;

pub inline fn physToVirt(phys: u64) u64 {
    return PHYSMAP_BASE + phys;
}

/// Translate a kernel VA to its physical address. Recognized windows:
///   - kernel image (-2 GB, KERNEL_VIRT_BASE..)        → virt - KERNEL_VIRT_BASE
///   - physmap (PHYSMAP_BASE..+PHYSMAP_SIZE)            → virt - PHYSMAP_BASE
///   - low identity (virt < 4 GB)                       → virt (boot 1 GB
///     pages identity-map 0..64 GB; under Phase 3 only PML4[0] is dropped,
///     not the boot map at high half — but in practice low-VA callers are
///     early-boot ATA/AHCI buffers that pre-date the physmap convention)
///
/// Returns null otherwise — a non-canonical or out-of-window VA, almost
/// always a caller bug. Calling code typically unwraps with `.?`; the
/// resulting panic message localizes the bug instantly.
pub inline fn virtToPhys(virt: u64) ?u64 {
    if (virt >= KERNEL_VIRT_BASE) {
        return virt - KERNEL_VIRT_BASE;
    }
    if (virt >= PHYSMAP_BASE and virt < PHYSMAP_BASE + PHYSMAP_SIZE) {
        return virt - PHYSMAP_BASE;
    }
    // Boot-time low-identity (capped at 4 GB so genuine wild VAs in the
    // [4 GB, PHYSMAP_BASE) gap still return null).
    if (virt < 0x100000000) {
        return virt;
    }
    return null;
}

/// Convenience: take a physical address, return a kernel pointer that
/// reads/writes the same memory through the high-half physmap. Replacement
/// for the old `@ptrFromInt(phys)` pattern that depended on PML4[0].
pub inline fn physPtr(comptime T: type, phys: u64) T {
    return @ptrFromInt(PHYSMAP_BASE + phys);
}

/// True if `addr` is mapped in the current address space (current CR3). Walks
/// the page tables by hand — used by debug paths (gdb stub, kdbg) that need to
/// validate a pointer before dereferencing it. Treats huge-page (PS=1) entries
/// at any level as covering the rest of the walk.
///
/// Caveats:
///   - Reads intermediate page-table addresses through the kernel physmap
///     (PHYSMAP_BASE + phys). PMM only hands out frames below 64 GB, so the
///     physmap covers every valid PT page. If PMM ever allocates above 64 GB
///     this needs revisiting.
///   - Doesn't validate canonical-form. Caller should do that first.
pub fn isMapped(addr: u64) bool {
    const cr3 = asm volatile ("movq %%cr3, %[ret]"
        : [ret] "=r" (-> u64),
    );
    const pml4: [*]const u64 = @ptrFromInt(physToVirt(cr3 & PAGE_MASK));
    const pml4e = pml4[(addr >> 39) & 0x1FF];
    if (pml4e & PRESENT == 0) return false;
    if (pml4e & PAGE_SIZE_FLAG != 0) return true; // unusual: 512GB huge

    const pdpt: [*]const u64 = @ptrFromInt(physToVirt(pml4e & PAGE_MASK));
    const pdpte = pdpt[(addr >> 30) & 0x1FF];
    if (pdpte & PRESENT == 0) return false;
    if (pdpte & PAGE_SIZE_FLAG != 0) return true; // 1GB page

    const pd: [*]const u64 = @ptrFromInt(physToVirt(pdpte & PAGE_MASK));
    const pde = pd[(addr >> 21) & 0x1FF];
    if (pde & PRESENT == 0) return false;
    if (pde & PAGE_SIZE_FLAG != 0) return true; // 2MB page

    const pt: [*]const u64 = @ptrFromInt(physToVirt(pde & PAGE_MASK));
    const pte = pt[(addr >> 12) & 0x1FF];
    return pte & PRESENT != 0;
}

// --- PML4 address ---
// Set during boot from either Multiboot (boot.asm's extern symbol) or UEFI (BootInfo).
var pml4_addr: usize = 0;

/// Return the physical address of the kernel PML4.
/// (Identity-mapped, so virtual address == physical address.)
pub fn getKernelPML4Phys() usize {
    return pml4_addr;
}

/// Legacy name kept for compatibility with process.zig / desktop.zig / syscall.zig.
pub fn getKernelPageDirPhys() usize {
    return pml4_addr;
}

/// Initialize from BootInfo (works for both Multiboot and UEFI).
pub fn init(boot_info: *const @import("../boot/boot_info.zig").BootInfo) void {
    pml4_addr = @intCast(boot_info.pml4_phys);
}

// --- MMIO mapping ---
// Addresses within the boot identity map (0-64 GB on both Multiboot and
// UEFI) are already mapped via 1 GB PDPT huge pages. For addresses above
// 64 GB (rare; would need >64 GB of physical RAM or BARs assigned that
// high), `ensureMapped` dynamically adds 2 MB page entries with PCD set
// so writes aren't reordered through the cache.
//
// Caveat: in-range MMIO (< 64 GB) inherits the boot map's caching policy,
// which is currently the default (write-back). On QEMU/KVM this is fine —
// MMIO writes to virtio/PCI BARs work correctly under WB. On real hardware
// or with strict-ordering devices, we'd need to split the boot 1 GB page
// down to 2 MB pages and re-mark the relevant slot with PCD. Deferred.
//
// The "PDPT entry has PS=1, skip" branch (`continue` below) covers every
// in-range MMIO address in steady state — the boot map already has it.

const debug = @import("../debug/debug.zig");

pub fn mapMMIO(phys: usize, size: usize) void {
    ensureMapped(phys, size, CACHE_DISABLE);
}

/// Same as mapMMIO but Write-Back cacheable. Use for shared host/guest
/// DRAM regions exposed via PCI BARs (e.g. virtio-gpu BLOB / SHM BAR)
/// — those are real DRAM, not registers, and reading them via UC PTEs
/// (1) thrashes performance to ~1.5 GB/s, and (2) breaks x86 cache
/// coherency with the host's WB mapping of the same dma-buf, so the
/// guest sees stale DRAM until the host flushes its own caches. WB on
/// both sides lets MESI snoop across the KVM boundary.
pub fn mapWBRange(phys: usize, size: usize) void {
    ensureMapped(phys, size, 0);
}

pub fn mapAPIC() void {
    // The boot identity map covers IOAPIC at 0xFEC00000 and LAPIC at
    // 0xFEE00000 via 1GB huge pages defaulting to WB. APIC registers
    // require strict UC: WB-cached writes can be reordered or coalesced,
    // breaking EOI delivery and IOAPIC programming. (On QEMU/KVM the
    // hypervisor traps regardless, and MTRR var[0] forces UC over the
    // 0x80000000–0xFFFFFFFF range, so the symptom is invisible. On real
    // HW with no MTRR override the PAT must enforce UC, otherwise APIC
    // silently misbehaves.)
    //
    // Previous implementation called ensureMapped() which short-circuits
    // for any phys < PHYSMAP_SIZE — silently discarding the cache flag.
    // This version walks the kernel master through the physmap (where
    // apic.zig stores lapic_base / ioapic_base) and ORs PCD onto each
    // 4KB leaf PTE. With PCD=1, PWT=0, PAT=0 → IA32_PAT slot 2 (UC-),
    // strict enough for APIC use.
    const apic_pages = [_]u64{
        PHYSMAP_BASE + 0xFEC00000, // IOAPIC base
        PHYSMAP_BASE + 0xFEC01000, // IOAPIC + 4KB (mapAPIC's old size was 0x2000)
        PHYSMAP_BASE + 0xFEE00000, // LAPIC base
        PHYSMAP_BASE + 0xFEE01000, // LAPIC + 4KB
    };
    for (apic_pages) |va| {
        if (splitToPte(va)) |pte| {
            pte.* |= CACHE_DISABLE;
        }
    }
    flushTLB();
}

// --- PAT (Page Attribute Table) ---------------------------------------
//
// Default IA32_PAT after CPU reset:
//   PA0=WB, PA1=WT, PA2=UC-, PA3=UC, PA4=WB, PA5=WT, PA6=UC-, PA7=UC
//
// We override PA4 to Write-Combining. Pages set with PAT=1, PCD=0, PWT=0
// (= index 4) become WC. PA0..PA3 stay at defaults so existing
// CACHE_DISABLE-based MMIO mappings work unchanged.
//
// Why: real-HW UEFI GOP framebuffers default to UC if no MTRR upgrades
// them. UC FB writes go through the BIU one transaction at a time —
// 1080p desktop draws drop to ~10 fps. WC coalesces them into burst
// transactions; the OS sees full memory bandwidth on the FB.
//
// PAT is per-CPU. setupPat() must be called on the BSP and on every AP
// (apEntry calls it) so the PA4=WC slot is consistent everywhere.
//
// PAT was added in Pentium III (2000); CPUID.01H:EDX[16] reports support.
// Every x86_64 CPU has it, but we probe defensively.

const PAT_MSR: u32 = 0x277;
// PA0=WB(0x06)  PA1=WT(0x04)  PA2=UC-(0x07)  PA3=UC(0x00)
// PA4=WC(0x01)  PA5=WT(0x04)  PA6=UC-(0x07)  PA7=UC(0x00)
//
// Encoded little-endian, byte 0 = PA0. Reset default is
// 0x0007040600070406 (PA4=WB); we change byte 4 from 0x06 to 0x01 so
// PAT_BIT_HUGE on a PDE selects WC.
//
// History: previous value 0x0007040600070106 had bytes 1 and 4 swapped
// (PA1=WC, PA4=WB), so setRangeWriteCombining sets PAT_BIT_HUGE → PA4 →
// got WB instead of WC. Symptom invisible on QEMU because MTRR forces
// UC on the BAR range; on real-HW UEFI with no MTRR override the FB
// stayed cached (no burst combining). Comptime assert below pins the
// byte order so a future typo trips the build instead of running silently.
const PAT_VALUE_WITH_WC4: u64 = 0x0007040100070406;

comptime {
    if ((PAT_VALUE_WITH_WC4 >> (4 * 8)) & 0xFF != 0x01) {
        @compileError("PA4 must be WC (0x01) — setRangeWriteCombining selects this slot");
    }
    if (PAT_VALUE_WITH_WC4 & 0xFF != 0x06) {
        @compileError("PA0 must remain WB (0x06)");
    }
}

fn writeMsr(msr: u32, value: u64) void {
    const lo: u32 = @truncate(value);
    const hi: u32 = @truncate(value >> 32);
    asm volatile ("wrmsr"
        :
        : [_] "{ecx}" (msr),
          [_] "{eax}" (lo),
          [_] "{edx}" (hi),
    );
}

/// Configure PAT slot 4 = WC on the calling CPU. Idempotent. Per-CPU —
/// caller must invoke from BSP startup AND from every AP entry.
pub fn setupPat() void {
    // Probe CPUID.01H:EDX bit 16 (PAT). Mandatory on x86_64; check anyway.
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={edx}" (edx),
        : [_] "{eax}" (@as(u32, 1)),
        : .{ .ebx = true, .ecx = true });
    if (edx & (1 << 16) == 0) return;
    writeMsr(PAT_MSR, PAT_VALUE_WITH_WC4);
    flushTLB();
}

/// Mark a physical address range as Write-Combining via PAT, viewed
/// through the kernel physmap (PML4[256]). Splits any 1GB huge page in
/// the way down to 2MB pages, then sets PAT_BIT_HUGE on each 2MB page
/// covering [phys, phys+size).
///
/// Caller contract: setupPat() already ran on this CPU. Range must be
/// page-aligned (we round outward to 2MB boundaries; the FB phys range
/// is always 4KB-aligned, and bumping a couple of edge pages to WC is
/// harmless — they're either FB padding or unrelated phys that happens
/// to share a 2MB chunk with the FB and is unused at runtime).
///
/// Cost: 1 PD page allocation per 1GB region split, plus the 4KB PD
/// itself. For a single 8MB FB inside one 1GB region: 1 alloc, 4 PDEs
/// modified.
///
/// SMP: only flushes the calling CPU's TLB. Boot ordering today calls
/// this before APs come up, so APs naturally see the new mapping when
/// their cr3 load picks up the modified PD entries via the shared PML4.
pub fn setRangeWriteCombining(phys: u64, size: u64) void {
    if (pml4_addr == 0 or size == 0) return;
    const pml4: [*]volatile u64 = @ptrFromInt(physToVirt(pml4_addr));
    const physmap_pml4_idx: usize = (PHYSMAP_BASE >> 39) & 0x1FF;
    if (pml4[physmap_pml4_idx] & PRESENT == 0) return;
    const pdpt: [*]volatile u64 = @ptrFromInt(physToVirt(pml4[physmap_pml4_idx] & PAGE_MASK));

    var p = phys & ~@as(u64, 0x1FFFFF);
    const end = (phys + size + 0x1FFFFF) & ~@as(u64, 0x1FFFFF);

    while (p < end) {
        const pdpt_idx = (p >> 30) & 0x1FF;
        var pdpte = pdpt[pdpt_idx];
        if (pdpte & PRESENT == 0) {
            // Phys outside the physmap — skip the whole 1GB and move on.
            p = (p + 0x40000000) & ~@as(u64, 0x3FFFFFFF);
            continue;
        }
        // Split 1GB → 2MB if the physmap entry is still a huge page.
        // Phys field is bits 30..51 (PAGE_MASK_1G), not 12..51 — the wrong
        // mask would copy any bits set in 12..29 (notably PAT at bit 12)
        // into gb_phys, throwing off the per-2MB phys arithmetic.
        if (pdpte & PAGE_SIZE_FLAG != 0) {
            const gb_phys = pdpte & PAGE_MASK_1G;
            // Preserve every leaf flag from the original (cache type, USER,
            // NX, PAT, AVL, GLOBAL, ...). PAT stays at bit 12 in both 1GB
            // and 2MB encodings, so no bit movement is required. PS stays
            // set since the new 2MB PDEs are also leaves.
            const leaf_template = pdpte & ~PAGE_MASK_1G;
            const new_pd_phys = pmm.allocFrame() orelse return;
            const new_pd: [*]u64 = @ptrFromInt(physToVirt(new_pd_phys));
            for (0..512) |i| {
                new_pd[i] = (gb_phys + @as(u64, @intCast(i)) * 0x200000) | leaf_template;
            }
            pdpt[pdpt_idx] = @as(u64, new_pd_phys) | (pdpte & PTR_FLAGS_MASK);
            pdpte = pdpt[pdpt_idx];
        }
        const pd: [*]volatile u64 = @ptrFromInt(physToVirt(pdpte & PAGE_MASK));
        const pd_idx = (p >> 21) & 0x1FF;
        if (pd[pd_idx] & PRESENT != 0 and pd[pd_idx] & PAGE_SIZE_FLAG != 0) {
            // PAT_BIT_HUGE = bit 12; combined with PCD=PWT=0 → PA4 = WC.
            pd[pd_idx] |= PAT_BIT_HUGE;
        }
        p += 0x200000;
    }
    flushTLB();
}

/// Ensure a physical address range is identity-mapped via 2MB pages.
/// If already covered by the boot map, this is a no-op.
///
/// Phase 3: phys < 64 GB is reached through the kernel physmap (PML4[256]),
/// so callers that take the result of `paging.physToVirt(phys)` already have
/// a valid kernel pointer. ensureMapped used to also write into pml4[0]'s
/// low-identity entries — that path would re-create the dropped low identity
/// every time a driver brought up MMIO, defeating Phase 3. Skip the work.
/// For phys >= 64 GB (genuinely outside the physmap window) we still walk
/// pml4[0]; bumping PHYSMAP_SIZE is the long-term fix once we hit hardware
/// that needs it.
///
/// SMP: this mutates the kernel master PML4 (shared across all CPUs) but
/// only flushes the calling CPU's TLB. APs may still have stale cached
/// entries until they invalidate naturally. All current callers are at
/// boot (driver init) where APs aren't running yet — that's why we get
/// away with it. ANY post-boot caller needs an IPI-broadcast TLB
/// shootdown; the simplest is `smp.broadcastSync(remoteFlushTLB)`.
///
/// Lifetime: any PMM-allocated PD/PT pages are permanently consumed; we
/// don't track them for teardown. Currently fine (we never unmap MMIO);
/// any future `unmapMMIO` would need to release them.
fn ensureMapped(phys: usize, size: usize, cache_flag: u64) void {
    if (pml4_addr == 0) return;
    if (phys + size <= PHYSMAP_SIZE) return; // covered by physmap
    // Slow path: phys is above the 512 GB physmap window. Drivers calling
    // mapMMIO/mapDataMMIO then dereferencing physToVirt(phys) WILL #PF —
    // the slow path writes pml4[0] (low identity) which Phase 3 has
    // dropped, and physToVirt() targets PML4[256] which we don't extend.
    // Fix when this fires: bump PHYSMAP_SIZE + extend pdpt_physmap, or
    // teach this path to write into the physmap range properly.
    debug.klog("[paging] WARN: ensureMapped phys=0x{X} size=0x{X} above PHYSMAP_SIZE=0x{X} — caller will #PF on physToVirt\n", .{ phys, size, PHYSMAP_SIZE });
    const pml4: [*]volatile u64 = @ptrFromInt(physToVirt(pml4_addr));

    var addr = phys & ~@as(usize, 0x1FFFFF); // Align down to 2MB
    const end = (phys + size + 0x1FFFFF) & ~@as(usize, 0x1FFFFF); // Align up

    while (addr < end) : (addr += 0x200000) {
        const pml4_idx = (addr >> 39) & 0x1FF;
        const pdpt_idx = (addr >> 30) & 0x1FF;
        const pd_idx = (addr >> 21) & 0x1FF;

        const TBL_FLAGS = PRESENT | READ_WRITE | USER;

        // Check/create PDPT
        if (pml4[pml4_idx] & PRESENT == 0) {
            // Need a new PDPT page — allocate from PMM
            const page = @import("pmm.zig").allocFrame() orelse return;
            const p: [*]u8 = @ptrFromInt(physToVirt(page));
            @memset(p[0..4096], 0);
            pml4[pml4_idx] = @as(u64, page) | TBL_FLAGS;
        }

        const pdpt_phys = pml4[pml4_idx] & PAGE_MASK;
        const pdpt: [*]volatile u64 = @ptrFromInt(physToVirt(@as(usize, @intCast(pdpt_phys))));

        // Check/create PD
        if (pdpt[pdpt_idx] & PRESENT == 0) {
            const page = @import("pmm.zig").allocFrame() orelse return;
            const p: [*]u8 = @ptrFromInt(physToVirt(page));
            @memset(p[0..4096], 0);
            pdpt[pdpt_idx] = @as(u64, page) | TBL_FLAGS;
        }

        // Check if PDPT entry is a 1GB page (shouldn't be for our setup)
        if (pdpt[pdpt_idx] & PAGE_SIZE_FLAG != 0) continue;

        const pd_phys = pdpt[pdpt_idx] & PAGE_MASK;
        const pd: [*]volatile u64 = @ptrFromInt(physToVirt(@as(usize, @intCast(pd_phys))));

        // Map 2MB page if not already present. cache_flag is CACHE_DISABLE
        // for true MMIO (registers) and 0 (= WB) for SHM/data ranges where
        // host & guest both need cache coherency.
        if (pd[pd_idx] & PRESENT == 0) {
            pd[pd_idx] = @as(u64, addr) | TBL_FLAGS | PAGE_SIZE_FLAG | cache_flag;
            debug.klog("[paging]   Mapped 2MB page at 0x{X} -> PD[{d}]\n", .{ addr, pd_idx });
        } else {
            debug.klog("[paging]   Already mapped at 0x{X}\n", .{addr});
        }
    }
    flushTLB();
}

// --- Per-process GUI framebuffer kernel mappings ---
// PMM-per-window: kernel reads/writes the FB through the physmap window
// (`physToVirt(phys)`), no per-process page-table work needed. We just
// remember the phys base so unmap can free the contiguous frames back.

pub const GUI_FB_USER_BASE: usize = 0x08000000; // user-space GUI FB virtual address

const MAX_PROCS = @import("../config.zig").MAX_PROCS;

// Track per-PID GUI FB phys base. Index = pid; entry = 0 means "no FB".
var gui_fb_phys_base: [MAX_PROCS]usize = [_]usize{0} ** MAX_PROCS;

/// Record the base physical address of a process's GUI framebuffer so
/// `unmapGuiFB` can release it later.
pub fn registerGuiFB(pid: u8, phys_base: usize) void {
    if (pid < MAX_PROCS) gui_fb_phys_base[pid] = phys_base;
}

/// Free a process's GUI FB back to the PMM. The first `num_user_pages` are
/// front-buffer pages mapped in the user PML4 — they're dual-owned (user PML4
/// holds one ref bumped at sysCreateWindow time, kernel desktop holds the
/// other), so we drop the kernel ref via per-frame releaseFrame; the user
/// ref drops when destroyAddressSpace walks the PML4 on process exit.
/// The remainder (`total_pages - num_user_pages`) are kernel-only back
/// buffers, single-owner — bulk freeContiguous reclaims them in one go.
pub fn unmapGuiFB(pid: u8, num_user_pages: u32, total_pages: u32) void {
    if (pid >= MAX_PROCS or gui_fb_phys_base[pid] == 0) return;
    const phys_base = gui_fb_phys_base[pid];
    var i: u32 = 0;
    while (i < num_user_pages) : (i += 1) {
        pmm.releaseFrame(phys_base + i * 4096);
    }
    if (total_pages > num_user_pages) {
        pmm.freeContiguous(phys_base + num_user_pages * 4096, total_pages - num_user_pages);
    }
    gui_fb_phys_base[pid] = 0;
}

// --- Back buffer ---
// Fixed contiguous region after the guest framebuffer. The kernel pointer
// goes through the physmap; the BB_BASE constant itself is the *physical*
// address (used by allocBackBuffer to mark the region used in PMM).
//   kernel_heap → guest_fb → back_buffer → gui_fb_reserve.
const BB_BASE: usize = memmap.BACK_BUFFER_BASE;

pub fn allocBackBuffer(num_pages: u32) ?[*]u32 {
    pmm.markRegionUsed(BB_BASE, @as(usize, num_pages) * 4096);
    return @ptrFromInt(physToVirt(BB_BASE));
}

pub fn getBackBufferAddr() usize {
    return BB_BASE;
}

pub fn freeBackBuffer(num_pages: u32) void {
    pmm.markRegionFree(BB_BASE, @as(usize, num_pages) * 4096);
}

// --- Guest FB (virtio-gpu) ---
// Fixed contiguous region. Needs contiguous physical memory for DMA. Kernel
// writes go through the physmap; the device sees the entries in `phys_out`
// (still the raw phys addresses, what virtio-gpu's resource_create expects).
const GFB_BASE: usize = memmap.GUEST_FB_BASE;

pub fn allocGuestFB(num_pages: u32, phys_out: [*]usize) ?[*]volatile u32 {
    pmm.markRegionUsed(GFB_BASE, @as(usize, num_pages) * 4096);
    for (0..num_pages) |i| {
        phys_out[i] = GFB_BASE + i * 4096;
    }
    return @ptrFromInt(physToVirt(GFB_BASE));
}

pub fn getGuestFBAddr() usize {
    return GFB_BASE;
}

pub fn freeGuestFB(num_pages: u32) void {
    pmm.markRegionFree(GFB_BASE, @as(usize, num_pages) * 4096);
}

// --- Helpers ---

pub fn flushTLB() void {
    asm volatile (
        \\ movq %%cr3, %%rax
        \\ movq %%rax, %%cr3
        ::: .{ .rax = true });
}

/// Phase 3: clear the low-identity slot (PML4[0]) in the kernel master.
/// After this call, kernel-mode code can no longer dereference low VAs
/// through this PML4 — every kernel access must go through the physmap
/// (PHYSMAP_BASE + phys, via `paging.physToVirt`) or the kernel image
/// window at -2 GB.
///
/// Caller contract:
///   - Must run on a kstack at HIGH VA (kstack_pool in kernel BSS, or a
///     heap-allocated kstack which sits in the physmap window). The boot
///     stack lives in `.bss.boot` at low phys = low VA — running this from
///     the boot stack would unmap the very stack we're standing on. The
///     intended call site is the desktop kernel task's entry, which gets
///     dispatched onto a high-VA kstack by `enterFirstTask`.
///   - Per-process page tables are unaffected (each process owns its own
///     PML4[0]). Kernel tasks share the kernel master CR3, so they see
///     this change immediately on TLB flush. APs are already running on
///     their own high-VA kstacks (apEntry → enterFirstTaskAp).
///
/// Idempotent: harmless to call twice (the slot just stays zero).
pub fn dropLowIdentity() void {
    if (pml4_addr == 0) return;
    const pml4: [*]volatile u64 = @ptrFromInt(physToVirt(pml4_addr));
    pml4[0] = 0;
    flushTLB();
}

/// Walk the kernel master PML4 and count how many leaf pages exist at each
/// granularity (1 GB / 2 MB / 4 KB) across the kernel's high-half range
/// (PML4[256] physmap + PML4[511] kernel image). Each unique leaf consumes
/// one TLB entry — smaller numbers = smaller TLB working set.
///
/// Per-slot output:
///   `[paging] kernel TLB map: PML4[256] physmap=A×1GB+B×2MB+C×4KB
///             PML4[511] image=A×1GB+B×2MB+C×4KB`
///
/// Healthy boot baseline (no splits yet):
///   physmap=64×1GB (or up to 512 if physmap is fully populated, kernel-only)
///   image=1×1GB
/// After typical kernel init (guard pages, kdata RO, write-watches), expect
/// a handful of 2 MB and 4 KB pages — anything >100 4KB pages suggests
/// unnecessary splits worth investigating.
const MapStats = struct {
    pages_1g: u32 = 0,
    pages_2m: u32 = 0,
    pages_4k: u32 = 0,
};

fn auditSlot(pml4_entry: u64, stats: *MapStats) void {
    if (pml4_entry & PRESENT == 0) return;
    const pdpt_phys = pml4_entry & PAGE_MASK;
    const pdpt: [*]const u64 = @ptrFromInt(physToVirt(pdpt_phys));
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const e = pdpt[i];
        if (e & PRESENT == 0) continue;
        if (e & PAGE_SIZE_FLAG != 0) {
            stats.pages_1g += 1;
            continue;
        }
        const pd: [*]const u64 = @ptrFromInt(physToVirt(e & PAGE_MASK));
        var j: usize = 0;
        while (j < 512) : (j += 1) {
            const pde = pd[j];
            if (pde & PRESENT == 0) continue;
            if (pde & PAGE_SIZE_FLAG != 0) {
                stats.pages_2m += 1;
                continue;
            }
            const pt: [*]const u64 = @ptrFromInt(physToVirt(pde & PAGE_MASK));
            var k: usize = 0;
            while (k < 512) : (k += 1) {
                if (pt[k] & PRESENT != 0) stats.pages_4k += 1;
            }
        }
    }
}

pub fn dumpKernelMappingStats() void {
    if (pml4_addr == 0) return;
    const pml4: [*]const u64 = @ptrFromInt(physToVirt(pml4_addr));
    var physmap_stats: MapStats = .{};
    var image_stats: MapStats = .{};
    auditSlot(pml4[256], &physmap_stats);
    auditSlot(pml4[511], &image_stats);
    const serial = @import("../debug/serial.zig");
    serial.print(
        "[paging] kernel TLB map: PML4[256] physmap={d}x1GB+{d}x2MB+{d}x4KB PML4[511] image={d}x1GB+{d}x2MB+{d}x4KB\n",
        .{
            physmap_stats.pages_1g, physmap_stats.pages_2m, physmap_stats.pages_4k,
            image_stats.pages_1g,   image_stats.pages_2m,   image_stats.pages_4k,
        },
    );
}

// --- 4KB-granular page protection ---
//
// `splitToPte` walks the kernel master PML4 down to the 4KB leaf PTE for
// `virt`, splitting 1GB or 2MB huge pages along the way as needed. Returns
// a pointer to the PTE so the caller can mutate any bit (PRESENT for guard
// pages, READ_WRITE for write-watches, etc.).
//
// Idempotent: if the page is already 4KB-granular, no allocation happens
// and we just walk down to the existing PT.
//
// Returns null if:
//   - paging not initialized (pml4_addr == 0)
//   - any walked entry has PRESENT=0 (no mapping to split)
//   - PMM allocation fails when a new PD or PT is needed
//
// Caller must `flushTLB()` after mutating the returned PTE.
fn splitToPte(virt: usize) ?*u64 {
    if (pml4_addr == 0) return null;
    const pml4: [*]u64 = @ptrFromInt(physToVirt(pml4_addr));
    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;

    if (pml4[pml4_idx] & PRESENT == 0) return null;
    const pdpt: [*]u64 = @ptrFromInt(physToVirt(pml4[pml4_idx] & PAGE_MASK));
    if (pdpt[pdpt_idx] & PRESENT == 0) return null;

    // 1GB → 2MB split (UEFI firmware uses 1GB huge pages at the PDPT level).
    // Preserves every leaf flag (USER, NX, PAT, PCD, PWT, GLOBAL, ...) so
    // a USER or MMIO huge page survives the split with the same semantics.
    // The previous version hardcoded `PRESENT | READ_WRITE` and silently
    // dropped everything else — fine while the only callers were kernel-
    // only WB pages (kdata watch, kstack guard), latent the moment anyone
    // splits a USER, COW, or MMIO page.
    if (pdpt[pdpt_idx] & PAGE_SIZE_FLAG != 0) {
        const orig = pdpt[pdpt_idx];
        const gb_phys = orig & PAGE_MASK_1G;
        // PAT stays at bit 12 in both 1GB and 2MB pages; PS stays set since
        // the new 2MB PDEs are also leaves.
        const leaf_template = orig & ~PAGE_MASK_1G;
        const new_pd_phys = pmm.allocFrame() orelse return null;
        const new_pd: [*]u64 = @ptrFromInt(physToVirt(new_pd_phys));
        for (0..512) |i| {
            new_pd[i] = (gb_phys + @as(u64, @intCast(i)) * 0x200000) | leaf_template;
        }
        pdpt[pdpt_idx] = @as(u64, new_pd_phys) | (orig & PTR_FLAGS_MASK);
    }

    const pd: [*]u64 = @ptrFromInt(physToVirt(pdpt[pdpt_idx] & PAGE_MASK));
    if (pd[pd_idx] & PRESENT == 0) return null;

    // 2MB → 4KB split (default boot mapping uses 2MB huge pages in the PD).
    // Same flag preservation as above, plus one wrinkle: PAT moves from
    // bit 12 (2MB PDE encoding) to bit 7 (4KB PTE encoding). Extract and
    // re-place explicitly. Without this, splitting a WC 2MB page produces
    // 4KB PTEs that select the wrong PA slot (likely PA0 = WB).
    if (pd[pd_idx] & PAGE_SIZE_FLAG != 0) {
        const orig = pd[pd_idx];
        const huge_phys = orig & PAGE_MASK_2M;
        const huge_pat = (orig >> 12) & 1;
        const leaf_template = (orig & ~PAGE_MASK_2M & ~PAGE_SIZE_FLAG & ~PAT_BIT_HUGE) | (huge_pat << 7);
        const new_pt_phys = pmm.allocFrame() orelse return null;
        const new_pt: [*]u64 = @ptrFromInt(physToVirt(new_pt_phys));
        for (0..512) |i| {
            new_pt[i] = (huge_phys + @as(u64, @intCast(i)) * 4096) | leaf_template;
        }
        pd[pd_idx] = @as(u64, new_pt_phys) | (orig & PTR_FLAGS_MASK);
    }

    const pt: [*]u64 = @ptrFromInt(physToVirt(pd[pd_idx] & PAGE_MASK));
    return &pt[pt_idx];
}

// --- Guard pages ---
// Plant a not-present guard page below each per-process kernel stack so an
// overflow becomes a clean #PF instead of silent heap corruption.
//
// Must run BEFORE any per-process address space is created. createAddressSpace
// copies the master kernel PD entries by value, so all later processes inherit
// the post-split PT pointers (which are themselves shared with the master) and
// see the not-present PTE automatically. Splitting after a process exists
// would leave that process with a stale 2MB huge-page entry.
//
// SMP: also requires "before APs are up", same reason as ensureMapped — only
// flushes the calling CPU's TLB. Boot ordering currently guarantees this.
pub fn installGuardPage(virt: usize) bool {
    const pte = splitToPte(virt) orelse return false;
    pte.* &= ~PRESENT;
    flushTLB();
    return true;
}

// --- MMU write-watch (RO page protection) -----------
//
// Mark a 4KB page as R/W=0 so any kernel-mode write to it traps as #PF (with
// CR0.WP=1). Used today by `protectKdataInit` to lock down the hardened-data
// section after boot.
//
// Returns the 4KB-aligned VA of the protected page, or null on failure.
pub fn installWriteWatch(virt: usize) ?usize {
    const pte = splitToPte(virt) orelse return null;
    pte.* &= ~READ_WRITE;
    flushTLB();
    return virt & ~@as(usize, 0xFFF);
}

/// Toggle the R/W bit for a previously-split page. The split is permanent;
/// only the R/W bit flips. Used by the trap handler to step past the
/// legitimate writer (count++) without disarming the watch.
pub fn setWriteWatchRW(virt: usize, allow_write: bool) void {
    if (pml4_addr == 0) return;
    const pml4: [*]u64 = @ptrFromInt(physToVirt(pml4_addr));
    const pml4_idx = (virt >> 39) & 0x1FF;
    const pdpt_idx = (virt >> 30) & 0x1FF;
    const pd_idx = (virt >> 21) & 0x1FF;
    const pt_idx = (virt >> 12) & 0x1FF;
    if (pml4[pml4_idx] & PRESENT == 0) return;
    const pdpt: [*]u64 = @ptrFromInt(physToVirt(pml4[pml4_idx] & PAGE_MASK));
    if (pdpt[pdpt_idx] & PRESENT == 0 or pdpt[pdpt_idx] & PAGE_SIZE_FLAG != 0) return;
    const pd: [*]u64 = @ptrFromInt(physToVirt(pdpt[pdpt_idx] & PAGE_MASK));
    if (pd[pd_idx] & PRESENT == 0 or pd[pd_idx] & PAGE_SIZE_FLAG != 0) return;
    const pt: [*]u64 = @ptrFromInt(physToVirt(pd[pd_idx] & PAGE_MASK));
    if (allow_write) {
        pt[pt_idx] |= READ_WRITE;
    } else {
        pt[pt_idx] &= ~READ_WRITE;
    }
    asm volatile ("invlpg (%[a])"
        :
        : [a] "r" (virt),
        : .{ .memory = true });
}

// --- Hardened-data section (.kdata_protected) page-protection ---
//
// per_cpu_asm and (future) other fragile structs live in a page-aligned
// linker section whose pages are marked RO after boot. Wild writes (PMM
// double-allocation aliasing, ELF-buffer overrun, wild kernel pointer)
// hit #PF cleanly with the writer's RIP captured in the saved frame.
// Legitimate writers (gdt.setTssRsp0) bracket their writes with
// `unlockKdata` / `lockKdata`; CR0.WP=1 ensures the toggle is honored.

extern var __kdata_protected_start: u8;
extern var __kdata_protected_end: u8;

/// Boot-time: after pmm + kernel-mapping splits are set up, walk the
/// hardened-data pages and clear their R/W bit. Each page is split from
/// 2MB → 4KB if needed (installWriteWatch handles that, sets RO + flushes
/// TLB). After this, any kernel write to that section traps unless the
/// caller temporarily unlocks via `unlockKdata`.
pub fn protectKdataInit() void {
    var page = @intFromPtr(&__kdata_protected_start);
    const end = @intFromPtr(&__kdata_protected_end);
    while (page < end) : (page += 4096) {
        _ = installWriteWatch(page);
    }
}

/// Re-enable writes to the hardened-data pages on the CALLING CPU only,
/// by clearing CR0.WP. Per-CPU semantics — SMP-race-free; the page's
/// PTE keeps W=0, so other CPUs (with WP=1) still trap on writes.
/// Cost: ~30 cycles for the cr0 round-trip vs ~140 for PTE+invlpg.
/// Must be paired with `lockKdata` immediately after the store.
pub fn unlockKdata() void {
    asm volatile (
        \\ movq %%cr0, %%rax
        \\ btrq $16, %%rax
        \\ movq %%rax, %%cr0
        ::: .{ .rax = true });
}

/// Re-set CR0.WP on the CALLING CPU. Pair with `unlockKdata`.
pub fn lockKdata() void {
    asm volatile (
        \\ movq %%cr0, %%rax
        \\ btsq $16, %%rax
        \\ movq %%rax, %%cr0
        ::: .{ .rax = true });
}

/// Set CR0.WP=1 so kernel-mode writes respect R/W=0 PTEs. Without this,
/// supervisor writes ignore the R/W bit and the watch never trips.
pub fn enableCR0WriteProtect() void {
    var cr0 = asm volatile ("mov %%cr0, %[ret]"
        : [ret] "=r" (-> u64),
    );
    cr0 |= 1 << 16;
    asm volatile ("mov %[v], %%cr0"
        :
        : [v] "r" (cr0),
    );
}
