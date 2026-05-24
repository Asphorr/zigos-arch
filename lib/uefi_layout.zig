// Single source of truth for addresses that BOTH the UEFI bootloader and
// the kernel must agree on. Before this file existed, uefi/uefi_boot.zig
// had `PAGE_TABLES_ADDR = 0x1C00000` hardcoded, and src/mm/memmap.zig
// derived `UEFI_PT_BASE` from a chain of kernel-side region sizes. The
// two drifted silently — PMM reserved one region while the bootloader
// wrote page tables to a different one. The mismatch was latent at 4 MB
// heap (the actual page tables happened to land inside BACK_BUFFER,
// which isn't bulk-zeroed), then bit catastrophically when heap was
// bumped to 16 MB: GUEST_FB shifted over the page tables and a 4 MB FB
// zero-fill destroyed the live PML4, freezing the kernel during
// virtio-gpu init with no panic and no autopsy.
//
// Now: both files import this module. Memory layout changes require
// updating this file, which causes the `comptime` agreement assertion
// in src/mm/memmap.zig to either pass or fail loudly at build time.
//
// Order of dependence: kernel-side memmap regions (HEAP, GFB, BB) are
// arithmetic on KERNEL_HEAP_BASE + sizes; UEFI_PT_BASE is the address
// at the end of that chain; PAGE_TABLES_ADDR + siblings must equal
// UEFI_PT_BASE.

// === Kernel-side region addresses (mirror of memmap.zig) ===
pub const KERNEL_HEAP_BASE: usize = 0xA00000;
pub const KERNEL_HEAP_SIZE: usize = 0x1000000; // 16 MB

pub const GUEST_FB_BASE: usize = KERNEL_HEAP_BASE + KERNEL_HEAP_SIZE;
pub const GUEST_FB_SIZE: usize = 0x800000; // 8 MB

pub const BACK_BUFFER_BASE: usize = GUEST_FB_BASE + GUEST_FB_SIZE;
pub const BACK_BUFFER_SIZE: usize = 0x800000; // 8 MB

pub const UEFI_PT_BASE: usize = BACK_BUFFER_BASE + BACK_BUFFER_SIZE;
pub const UEFI_PT_SIZE: usize = 0x40000; // 256 KB

// === Bootloader fixed addresses (must live inside UEFI_PT_BASE..+SIZE) ===
//
// All four MUST sit inside the kernel's reserved UEFI_PT region — the
// comptime block at the bottom enforces it.

pub const PAGE_TABLES_ADDR: u64 = UEFI_PT_BASE; // PML4+PDPT+8xPD = 10 pages
pub const BOOT_INFO_ADDR: u64 = UEFI_PT_BASE + 0x30000;
pub const MMAP_REGIONS_ADDR: u64 = UEFI_PT_BASE + 0x31000;
pub const BOOT_STACK_TOP: u64 = UEFI_PT_BASE + 0x40000;

comptime {
    if (PAGE_TABLES_ADDR != UEFI_PT_BASE) {
        @compileError("PAGE_TABLES_ADDR must equal UEFI_PT_BASE");
    }
    if (BOOT_STACK_TOP > UEFI_PT_BASE + UEFI_PT_SIZE) {
        @compileError("UEFI bootloader fixed addresses overflow the reserved UEFI_PT region — bump UEFI_PT_SIZE or relocate.");
    }
    if (PAGE_TABLES_ADDR + 10 * 4096 > BOOT_INFO_ADDR) {
        @compileError("PAGE_TABLES_ADDR's 10 pages overlap BOOT_INFO_ADDR");
    }
}
