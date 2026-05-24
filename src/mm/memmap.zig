// Single source of truth for ZigOS's static memory map. Every fixed virtual
// address the kernel hands out — kernel image, heap, framebuffer, GUI windows
// — comes from here. Pairwise comptime overlap asserts at the bottom catch a
// future hand-picked VA that lands inside an existing region: it becomes a
// build error rather than the kind of cross-region triple fault we hunted in
// the early days.
//
// Layout (low to high, all phys-identity below 4 GB / kernel-physmap above):
//
//   0x000000..0x0FFFFF   reserved (BIOS, IVT, Multiboot data)
//   0x100000..kernel_end kernel image (.text, .rodata, .data, .bss).
//                        kernel_end is runtime-derived from `_kernel_end` —
//                        the linker sets it; nothing in the static map cares
//                        where exactly it lands as long as it's < KERNEL_HEAP_BASE.
//   kernel_end..0x7FFFFF free RAM (PMM hands these frames out on demand).
//                        Historically reserved as USER_LOAD; the reservation
//                        was fossilized protection for a Phase-2 lazy-fault
//                        bug class that's gone since PML4[0] was dropped.
//   0xA00000..0xDFFFFF   kernel dynamic heap (KERNEL_HEAP, 4 MB)
//   0xE00000..0x15FFFFF  guest GPU framebuffer (GUEST_FB, 8 MB)
//   0x1600000..0x1DFFFFF CPU back buffer for compositing (BACK_BUFFER, 8 MB)
//   0x1E00000..0x1E3FFFF UEFI page tables (reserved on UEFI builds only)
//
// User space (per-process page tables): each process gets its own PML4[0]
// from createAddressSpace; user-app .text loads at USER_VA_FLOOR (matches
// app/linker.ld). user_brk starts at USER_BRK_INITIAL and grows to
// USER_SPACE_END. Two distinct floors apply: CODE/RIP validators (kdbg
// ripIsValidUser, elf_loader segments, sysClone entry) floor at USER_VA_FLOOR
// because code never lives below the load base; STACK/DATA validators
// (validateUserPtr, vmm.mapUserPage, signals frame validation) MUST floor at
// USER_SPACE_START, since the user stack lives in [USER_SPACE_START,
// USER_VA_FLOOR). Conflating the two is the class of bug that broke Ctrl+C.

const std = @import("std");

// --- Kernel image (linker-defined; runtime values) ---
pub const KERNEL_PHYS_START: usize = 0x100000;

/// Higher-half kernel base — must match `KERNEL_VIRT_BASE` in src/linker.ld.
/// Kernel symbols (kmain, _kernel_end, &__kdata_protected_start, etc.) link
/// at `phys + KERNEL_VIRT_BASE`, so any check that compares a kernel VA
/// against a low-half constant has to translate first.
pub const KERNEL_VIRT_BASE: usize = 0xFFFFFFFF80000000;

/// Physmap base — must match `pdpt_physmap` slot in boot.asm. Maps phys
/// 0..PHYSMAP_SIZE at VA `PHYSMAP_BASE..PHYSMAP_BASE+PHYSMAP_SIZE`. The
/// canonical "kernel can read/write any phys frame" view in Phase 2+. Use
/// `paging.physToVirt(p)` rather than the bare constant whenever possible.
///
/// Sized to cover the full 512 GB span addressable by one PML4 slot (one
/// 4 KB PDPT page = 512 × 1 GB entries). Smaller windows leave high-phys
/// MMIO BARs unmapped (e.g. xHCI BAR at ~481 GB under `-cpu host` with
/// 39-bit maxphyaddr) and the bare physToVirt() result page-faults.
/// `pdpt_physmap` in src/boot/boot.asm and uefi/uefi_boot.zig must fill
/// all 512 entries to match.
pub const PHYSMAP_BASE: usize = 0xFFFF800000000000;
pub const PHYSMAP_SIZE: usize = 0x8000000000; // 512 GB (full PML4 slot)

extern var _kernel_end: u8;

/// Virtual end of the kernel image (high half, what Zig sees).
pub fn kernelEnd() usize {
    return @intFromPtr(&_kernel_end);
}

/// Physical end of the kernel image — what Multiboot loaded the last byte
/// into. Used by PMM to reserve the kernel image's frames. Runtime-derived,
/// so kernel growth (more code, bigger BSS) is automatic; no manual bumps.
pub fn kernelEndPhys() usize {
    return kernelEnd() - KERNEL_VIRT_BASE;
}

// --- Validator constant (matches user-app linker convention) ---
// The lowest legitimate user-mode VA. app/linker.ld pins user-app .text
// at 0x500000, so any saved RIP below this on iretq-to-user is wild
// (kdbg.validateUserReturnIretq), as is any sysExec entry below this
// (syscall.zig). USER_SPACE_START sits 64 KB lower to make room for the
// downward-growing user stack.
//
// Independent of kernel image size — the kernel image lives at high-half
// VAs; the only thing that has to fit at low PAs is "kernel image must
// end before KERNEL_HEAP_BASE" (assertKernelImageFits). Bumping this
// constant requires re-linking all user apps and is rarely the right move.
pub const USER_VA_FLOOR: usize = 0x500000;

// --- Static kernel-side regions (low PA, post-kernel-image) ---
//
// Bumped 2026-05-20 from 0x800000 → 0xA00000. The kernel image (incl.
// BSS) grew past 0x800000 once ext2's per-mount cache_buf went from
// 4 KB → 32 KB (gap perf-#1) — the kernel-image-fits check tripped.
// 2 MB of headroom now between _kernel_end and KERNEL_HEAP_BASE so
// future BSS growth doesn't require chasing this constant again.
// Downstream regions are *derived* so a future bump only touches
// KERNEL_HEAP_BASE here.
pub const KERNEL_HEAP_BASE: usize = 0xA00000;
pub const KERNEL_HEAP_SIZE: usize = 0x1000000; // 16 MB (TLSF: bumped from 4 MB 2026-05-24)

pub const GUEST_FB_BASE: usize = KERNEL_HEAP_BASE + KERNEL_HEAP_SIZE; // 0xE00000
pub const GUEST_FB_SIZE: usize = 0x800000; // 8 MB

pub const BACK_BUFFER_BASE: usize = GUEST_FB_BASE + GUEST_FB_SIZE; // 0x1600000
pub const BACK_BUFFER_SIZE: usize = 0x800000; // 8 MB

// UEFI page tables (PML4/PDPT/PDs that map our 64 GB identity range with
// 1 GB pages). Set up by uefi/uefi_boot.zig before kmain_uefi runs and
// kept live for the whole boot — kernel CR3 points at this PML4. PMM
// reserves it under UEFI ONLY; under Multiboot the page tables live in
// the kernel image (boot.asm's BSS) so this region is plain free RAM.
// Without the reservation, kasan.init's 32 MB shadow allocContiguous
// happily lands here, the @memset overwrites the page tables, the next
// memory access hits a wild CR3, and the kernel halts silently.
pub const UEFI_PT_BASE: usize = BACK_BUFFER_BASE + BACK_BUFFER_SIZE; // 0x1E00000
pub const UEFI_PT_SIZE: usize = 0x40000; // 256 KB

// GUI framebuffers are PMM-allocated per window now (sysCreateWindow).
// Only the per-window size cap remains.
// 10 MB max per window. Initial allocations stay small (apps request their
// window size, still bounded by GUI_MAX_SIZE = 8 MB in sysCreateWindow); the
// extra headroom is for F10 grow-on-maximize (desktop.growGuiFb), which only
// the maximized window pays — a full 1920×1080 RGBA buffer is ~8.3 MB.
pub const GUI_FB_PER_PID_SIZE: usize = 0xA00000;

// --- User-space layout (per-process) ---
// USER_SPACE_START sits N pages below USER_VA_FLOOR so the user stack
// (just under the load base) is mappable. Without this margin,
// mapUserPage silently rejects stack faults (virt < USER_SPACE_START), the
// PF handler thinks the lazy fault-in succeeded (mapUserPage is void), and
// the app spins re-faulting until OOM kills it (caught 2026-05-20 on
// Q1 with its 64-page stack — leaked 200 MB before OOM).
// MUST be >= elf_loader's `stack_pages * PAGE_SIZE`. The comptime
// assert in src/proc/elf_loader.zig keeps this in sync.
//
// 1 MB / 256 pages (2026-05-20): Quake1's R_EdgeDrawing overflowed the
// prior 64-page reservation by ~7 KB. Lazy-fault means unused pages
// cost zero PMM, so the reserve sets only the VA ceiling. Going higher
// (e.g. 4 MB) would push USER_SPACE_START into the kernel image's low
// PA range — stay at 1 MB until an app needs more and we restructure
// the low-VA layout.
pub const USER_STACK_RESERVE: u64 = 0x100000; // 256 pages = 1 MB
pub const USER_SPACE_START: u64 = USER_VA_FLOOR - USER_STACK_RESERVE;
pub const USER_SPACE_END: u64 = 0x10000000; // 256 MB
// Initial sbrk position (per-process VA). Lives in user low-half VA
// space, fully independent of kernel low-PA layout — kernel reaches its
// own heap through the high-half physmap (Phase 3 dropped PML4[0]), so
// a numeric collision between user-VA and kernel-PHYS is harmless.
// 0x2000000 (32 MB) gives apps a fresh upward range from a round
// boundary; well below USER_SPACE_END (0x10000000 = 256 MB).
pub const USER_BRK_INITIAL: usize = 0x2000000;
pub const USER_VA_MAX: usize = 0x40000000; // ELF segment validity ceiling

// --- Comptime overlap asserts ---
//
// Pairwise check that the kernel-side static regions don't overlap. If a
// future change makes two regions collide (e.g. doubling KERNEL_HEAP_SIZE
// without bumping GUEST_FB_BASE), this fails at build time. The kernel
// image's runtime extent is checked separately in `assertKernelImageFits`.
comptime {
    const Region = struct { name: []const u8, base: usize, size: usize };
    const regions = [_]Region{
        .{ .name = "kernel_heap", .base = KERNEL_HEAP_BASE, .size = KERNEL_HEAP_SIZE },
        .{ .name = "guest_fb", .base = GUEST_FB_BASE, .size = GUEST_FB_SIZE },
        .{ .name = "back_buffer", .base = BACK_BUFFER_BASE, .size = BACK_BUFFER_SIZE },
    };
    var i: usize = 0;
    while (i < regions.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < regions.len) : (j += 1) {
            const a = regions[i];
            const b = regions[j];
            const a_end = a.base + a.size;
            const b_end = b.base + b.size;
            if (a.base < b_end and b.base < a_end) {
                @compileError("memmap: regions overlap — " ++ a.name ++ " vs " ++ b.name);
            }
        }
    }

    // USER_VA_FLOOR sanity (matches app/linker.ld; comptime catch if someone
    // moves it below the kernel-image base).
    if (USER_VA_FLOOR <= KERNEL_PHYS_START) {
        @compileError("USER_VA_FLOOR must be above KERNEL_PHYS_START");
    }

    // User-space sanity.
    if (USER_BRK_INITIAL >= USER_SPACE_END) {
        @compileError("USER_BRK_INITIAL beyond USER_SPACE_END");
    }
    if (USER_BRK_INITIAL < USER_VA_FLOOR) {
        @compileError("USER_BRK_INITIAL must be at or above USER_VA_FLOOR");
    }
}

/// Runtime check that the kernel image fits below KERNEL_HEAP_BASE. Call once
/// during boot. If this fires, the kernel grew into the heap region — heap
/// allocations would corrupt kernel BSS / .data. Either trim the kernel or
/// bump KERNEL_HEAP_BASE (and the dependent regions stacked above it).
///
/// Note: this is the ONLY runtime constraint on kernel image size — user-app
/// load VA is a separate concept (USER_VA_FLOOR, fixed by app/linker.ld) and
/// has no relationship to kernel growth.
pub fn assertKernelImageFits() void {
    const end = kernelEndPhys();
    if (end > KERNEL_HEAP_BASE) {
        @import("../debug/debug.zig").klog(
            "[memmap] FATAL: kernel image extends to 0x{X}, past KERNEL_HEAP_BASE 0x{X}\n",
            .{ end, KERNEL_HEAP_BASE },
        );
        @panic("kernel image grew into kernel heap region");
    }
}
