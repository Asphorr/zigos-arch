// Boot-protocol-agnostic boot information.
// Shared layout between UEFI bootloader and kernel.
// All structs are extern for C ABI compatibility.

const multiboot = @import("multiboot.zig");

pub const MemoryRegion = extern struct {
    base: u64,
    length: u64,
    kind: u32, // Kind enum value

    pub const Kind = enum(u32) {
        usable = 1,
        reserved = 2,
        acpi_reclaimable = 3,
        acpi_nvs = 4,
        bad_memory = 5,
        uefi_runtime = 6,
    };
};

pub const FramebufferInfo = extern struct {
    base: u64,
    width: u32,
    height: u32,
    stride: u32,
    format: u32, // 0=bgra, 1=rgba, 2=unknown
};

pub const BootInfo = extern struct {
    memory_map: [*]const MemoryRegion,
    memory_map_count: u32,
    has_framebuffer: u32,
    framebuffer: FramebufferInfo,
    pml4_phys: u64,
    rsdp_addr: u64,
    /// 0 = normal, 1 = verbose, 2 = safe (no SMP). Set by the UEFI menu;
    /// always 0 on the Multiboot path (no menu there).
    boot_mode: u32,
    _reserved: u32 = 0,
    /// Address of the UEFI RuntimeServices table, or 0 on Multiboot path.
    /// The kernel uses this to call SetVariable post-handoff for things
    /// like writing LastBootStatus = success / crashed back to NVRAM.
    /// Stored as u64 to avoid pulling std.os.uefi types into the kernel
    /// freestanding target (the kernel-side wrapper at
    /// `boot/uefi_nvram.zig` casts it to its own minimal mirror struct).
    runtime_services_addr: u64 = 0,
    /// Bootloader's compile-time build_id. UEFI path: filled from
    /// bootloader's `build_options.build_id`. Multiboot path: 0.
    /// Kernel compares to its own compile-time build_id at startup and
    /// klogs a loud warning if they diverge — catches "rebuilt kernel
    /// but old BOOTX64.efi on ESP" (or vice versa) without needing the
    /// klog pattern recognition that would otherwise reveal it minutes later.
    bootloader_build_id: u64 = 0,
    /// Kernel cmdline string (ASCII). Bootloader populates from NVRAM
    /// var `ZigOSCmdline`; Multiboot path leaves it empty. Cap is 256 B
    /// because UEFI variables incur metadata overhead per byte and 256
    /// is plenty for `init=foo klog=verbose nosmp` style flags.
    cmdline: [256]u8 = [_]u8{0} ** 256,
    cmdline_len: u32 = 0,
    _reserved2: u32 = 0,
};

/// True if the kernel was entered via the UEFI bootloader, false for Multiboot.
/// Set by `kmain_uefi` before `kernelMain`. Use sparingly — prefer one code path
/// that handles both. Mostly useful for diagnostic prefixes and BAR fixup hints.
pub var is_uefi: bool = false;

/// Selected boot mode from the UEFI menu (0=normal, 1=verbose, 2=safe).
/// Multiboot path leaves this as 0. Read by smp.init() etc. to gate behavior.
pub var boot_mode: u32 = 0;

// Static storage for converted memory regions. 256 matches the UEFI path's
// max_regions; real HW emits 80-200 descriptors typically. Multiboot
// usually has 10-20, so most slots stay unused on that path.
var regions: [256]MemoryRegion = undefined;

/// Convert a Multiboot1 memory map to a BootInfo struct.
pub fn fromMultiboot(info: *multiboot.MultibootInfo) BootInfo {
    var count: u32 = 0;

    if (info.flags & (1 << 6) != 0) {
        var offset: u32 = 0;
        while (offset < info.mmap_length and count < 256) {
            const paging = @import("../mm/paging.zig");
            const entry: *const multiboot.MultibootMmapEntry = @ptrFromInt(paging.physToVirt(@as(u64, info.mmap_addr) + offset));
            regions[count] = .{
                .base = @as(u64, entry.addr_high) << 32 | entry.addr_low,
                .length = @as(u64, entry.len_high) << 32 | entry.len_low,
                .kind = switch (entry.type) {
                    1 => 1, // usable
                    3 => 3, // acpi_reclaimable
                    4 => 4, // acpi_nvs
                    5 => 5, // bad_memory
                    else => 2, // reserved
                },
            };
            count += 1;
            offset += entry.size + 4;
        }
    }

    // Get current PML4 from CR3
    const cr3 = asm volatile ("movq %%cr3, %[ret]"
        : [ret] "=r" (-> u64),
    );

    // Multiboot1 cmdline: bit 2 of flags set => info.cmdline is the
    // physical address of a NUL-terminated string. We honour
    // `boot_mode=N` so QEMU `-append "boot_mode=8"` can pick stress
    // harnesses without re-editing source. Out-of-range / absent →
    // default 0 (normal desktop).
    var parsed_mode: u32 = 0;
    if ((info.flags & (1 << 2)) != 0 and info.cmdline != 0) {
        const paging = @import("../mm/paging.zig");
        const cmdline_va: [*]const u8 = @ptrFromInt(paging.physToVirt(@as(u64, info.cmdline)));
        parsed_mode = parseBootModeArg(cmdline_va);
    }

    return .{
        .memory_map = &regions,
        .memory_map_count = count,
        .has_framebuffer = 0,
        .framebuffer = .{ .base = 0, .width = 0, .height = 0, .stride = 0, .format = 2 },
        .pml4_phys = cr3 & 0xFFFFFFFFF000,
        .rsdp_addr = 0,
        .boot_mode = parsed_mode,
    };
}

/// Find `boot_mode=N` in a NUL-terminated cmdline (max 256 bytes scanned)
/// and return N. Returns 0 if absent or unparseable. Tiny & free of any
/// allocator dependency so it's safe to call this early in boot.
fn parseBootModeArg(s: [*]const u8) u32 {
    const key = "boot_mode=";
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        if (s[i] == 0) return 0;
        // Match `key` at position i.
        var j: usize = 0;
        while (j < key.len) : (j += 1) {
            if (s[i + j] != key[j]) break;
        }
        if (j == key.len) {
            var v: u32 = 0;
            var k: usize = i + key.len;
            var any: bool = false;
            while (k < i + key.len + 4) : (k += 1) {
                const c = s[k];
                if (c < '0' or c > '9') break;
                v = v * 10 + @as(u32, c - '0');
                any = true;
            }
            return if (any) v else 0;
        }
    }
    return 0;
}
