//! What a boot loader hands the kernel. uefi/uefi_boot.zig fills it for the
//! UEFI path, src/boot/boot_info.zig for Multiboot; the kernel reads it in
//! src/main.zig. Both sides import this file, so the layout cannot drift.
//!
//! A loader owes the kernel, beyond the struct:
//!   - long mode, interrupts off, on page tables rooted at `pml4_phys` with
//!     the three windows below: the low identity, the physmap and the image;
//!   - the image's segments at `p_paddr + kernel_phys_offset`;
//!   - pointers in the struct that are valid on those tables.
//! The stack is the kernel's own business: it moves to its own at entry.

const std = @import("std");

/// Everything this file promises, as a number: raise it with any change a
/// loader or a kernel built from the old file would get wrong. (1 was the
/// layout that had no version in it.)
pub const VERSION: u32 = 2;

/// The kernel exports its UEFI entry under this name and the loader looks
/// for no other, so a pair built from different versions stops at the
/// loader's error screen.
pub const ENTRY_SYMBOL = std.fmt.comptimePrint("zigos_uefi_entry_v{d}", .{VERSION});

/// "ZBIv": the first word of BootInfo.
pub const MAGIC: u32 = 0x7649_425A;

/// The windows of the address space the kernel is entered in. A loader
/// builds them; src/mm/memmap.zig asserts the kernel's layout is the same.
pub const IDENTITY_SIZE: u64 = 64 << 30;
pub const PHYSMAP_BASE: u64 = 0xFFFF_8000_0000_0000;
pub const PHYSMAP_SIZE: u64 = 512 << 30;
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;
/// The image window: link addresses (`p_paddr`) below this, mapped at
/// `KERNEL_VIRT_BASE + p_paddr`.
pub const IMAGE_WINDOW_SIZE: u64 = 1 << 30;

pub const MemoryRegion = extern struct {
    base: u64,
    length: u64,
    kind: Kind,

    /// The kernel takes `usable` and leaves every other kind alone.
    pub const Kind = enum(u32) {
        usable = 1,
        reserved = 2,
        acpi_reclaimable = 3,
        acpi_nvs = 4,
        bad_memory = 5,
        uefi_runtime = 6,
        _,
    };
};

/// The largest framebuffer the kernel has a back buffer for: a loader picks
/// its video mode within this.
pub const MAX_FRAMEBUFFER_BYTES: usize = 0x800000;

pub const FramebufferInfo = extern struct {
    base: u64,
    width: u32,
    height: u32,
    stride: u32,
    format: Format,

    pub const Format = enum(u32) { bgra = 0, rgba = 1, unknown = 2, _ };
};

pub const BootInfo = extern struct {
    /// Checked by the kernel before it takes anything else from here.
    magic: u32 = MAGIC,
    version: u32 = VERSION,
    memory_map: [*]const MemoryRegion,
    memory_map_count: u32,
    has_framebuffer: u32,
    framebuffer: FramebufferInfo,
    /// The kernel keeps these tables: they must lie below 4 GiB (an AP
    /// loads CR3 in 32-bit mode) in memory the map does not call usable,
    /// or inside `boot_data`.
    pml4_phys: u64,
    rsdp_addr: u64,
    /// The menu's choice: 0 normal, 1 verbose, 2 safe, 3.. tests. 0 on
    /// Multiboot unless the command line says `boot_mode=N`.
    boot_mode: u32,
    _reserved: u32 = 0,
    /// The UEFI RuntimeServices table, 0 on Multiboot.
    runtime_services_addr: u64 = 0,
    /// The loader's build id, 0 on Multiboot. The kernel warns when it is
    /// not its own: one of BOOTX64.efi and kernel.elf is stale.
    bootloader_build_id: u64 = 0,
    cmdline: [256]u8 = [_]u8{0} ** 256,
    cmdline_len: u32 = 0,
    _reserved2: u32 = 0,
    /// How far above its link addresses (`p_paddr`) the image lies. A
    /// multiple of 2 MiB; 0 when the loader could not choose (Multiboot).
    kernel_phys_offset: u64 = 0,
    /// Memory the loader took for what outlives it (page tables, this
    /// struct, the memory map). The map calls it usable; the kernel must
    /// not hand it out. Size 0 when there is none.
    boot_data_base: u64 = 0,
    boot_data_size: u64 = 0,
};
