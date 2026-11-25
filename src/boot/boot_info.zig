//! The kernel's view of the boot handoff. The struct itself is
//! lib/boot_protocol.zig, shared with the UEFI loader; this file adds the
//! Multiboot conversion and what the kernel remembers of the handoff.

const multiboot = @import("multiboot.zig");
const protocol = @import("boot_protocol");

pub const MemoryRegion = protocol.MemoryRegion;
pub const FramebufferInfo = protocol.FramebufferInfo;
pub const BootInfo = protocol.BootInfo;

/// True if the kernel was entered via the UEFI bootloader, false for Multiboot.
/// Set by `uefiMain` before `kernelMain`. Use sparingly — prefer one code path
/// that handles both. Mostly useful for diagnostic prefixes and BAR fixup hints.
pub var is_uefi: bool = false;

/// Selected boot mode from the UEFI menu (0=normal, 1=verbose, 2=safe).
/// Multiboot path leaves this as 0. Read by smp.init() etc. to gate behavior.
pub var boot_mode: u32 = 0;

// Static storage for converted memory regions. 512 matches the UEFI path's
// max_regions; real HW emits 80-200 descriptors typically (more on fragmented
// boards). Multiboot usually has 10-20, so most slots stay unused on that path.
var regions: [512]MemoryRegion = undefined;

/// Convert a Multiboot1 memory map to a BootInfo struct.
pub fn fromMultiboot(info: *multiboot.MultibootInfo) BootInfo {
    var count: u32 = 0;

    if (info.flags & (1 << 6) != 0) {
        var offset: u32 = 0;
        while (offset < info.mmap_length and count < regions.len) {
            const paging = @import("../mm/paging.zig");
            const entry: *const multiboot.MultibootMmapEntry = @ptrFromInt(paging.physToVirt(@as(u64, info.mmap_addr) + offset));
            regions[count] = .{
                .base = @as(u64, entry.addr_high) << 32 | entry.addr_low,
                .length = @as(u64, entry.len_high) << 32 | entry.len_low,
                .kind = switch (entry.type) {
                    1 => .usable,
                    3 => .acpi_reclaimable,
                    4 => .acpi_nvs,
                    5 => .bad_memory,
                    else => .reserved,
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
        .framebuffer = .{ .base = 0, .width = 0, .height = 0, .stride = 0, .format = .unknown },
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
