//! The handoff to the kernel (lib/boot_protocol.zig): its page tables, a GDT,
//! BootInfo and the memory map in one block the firmware gives us, then the
//! jump. The kernel is told where the block is and keeps it for good.

const std = @import("std");
const uefi = std.os.uefi;
const protocol = @import("boot_protocol");
const kernel_image = @import("kernel_image.zig");

const BootServices = uefi.tables.BootServices;
const MemoryMapSlice = uefi.tables.MemoryMapSlice;
const MemoryType = uefi.tables.MemoryType;
const BootInfo = protocol.BootInfo;
const MemoryRegion = protocol.MemoryRegion;

const PAGE: usize = 4096;
const GIB: u64 = 1 << 30;

/// Real firmware hands out 80..200 descriptors and neighbours of one kind
/// merge, so this is room to spare. A dropped one is lost RAM.
pub const MAX_REGIONS = 512;

/// The block: a page each, the memory map to the end.
const Part = enum(usize) { pml4, pdpt_identity, pdpt_physmap, pdpt_image, pd_image, gdt, boot_info, regions };
const BLOCK_PAGES = @intFromEnum(Part.regions) + std.mem.alignForward(usize, MAX_REGIONS * @sizeOf(MemoryRegion), PAGE) / PAGE;

const Pte = struct {
    const present: u64 = 1 << 0;
    const writable: u64 = 1 << 1;
    const user: u64 = 1 << 2;
    const huge: u64 = 1 << 7;
    const global: u64 = 1 << 8;
    const rw = present | writable;
};

const PML4_SHIFT = 39;
const PDPT_SHIFT = 30;

fn tableIndex(virt: u64, comptime shift: u6) usize {
    return @intCast((virt >> shift) & 0x1FF);
}

const KERNEL_CODE_SELECTOR = 0x08;
const KERNEL_DATA_SELECTOR = 0x10;

/// Null, kernel code, kernel data, user code, user data: boot.asm's order.
/// The kernel loads its own GDT; until then it runs on the first three.
const GDT = [_]u64{
    0,
    flatSegment(.code, 0),
    flatSegment(.data, 0),
    flatSegment(.code, 3),
    flatSegment(.data, 3),
};

const Gdtr = extern struct {
    limit: u16 align(1),
    base: u64 align(1),
};

fn flatSegment(comptime kind: enum { code, data }, comptime dpl: u2) u64 {
    const present = 0x80;
    const code_or_data = 0x10;
    const executable_readable = 0x0A;
    const writable = 0x02;
    const access: u64 = present | code_or_data | (@as(u64, dpl) << 5) |
        switch (kind) {
            .code => executable_readable,
            .data => writable,
        };

    const limit_high = 0x0F;
    const page_granular = 0x80;
    const long_mode = 0x20;
    const operand_32bit = 0x40;
    const flags: u64 = limit_high | page_granular | switch (kind) {
        .code => long_mode,
        .data => operand_32bit,
    };

    const limit_low = 0xFFFF;
    return limit_low | (access << 40) | (flags << 48);
}

comptime {
    // The descriptors boot.asm and the old loader spelled as numbers.
    std.debug.assert(GDT[1] == 0x00AF9A000000FFFF and GDT[2] == 0x00CF92000000FFFF);
    std.debug.assert(GDT[3] == 0x00AFFA000000FFFF and GDT[4] == 0x00CFF2000000FFFF);
}

pub const MapSummary = struct {
    descriptors: u32 = 0,
    regions: u32 = 0,
    dropped: u32 = 0,
    usable_bytes: u64 = 0,
    acpi_nvs_bytes: u64 = 0,
};

pub const BootData = struct {
    base: usize,

    pub const SIZE: usize = BLOCK_PAGES * PAGE;

    /// Below 4 GiB: an AP loads these tables' address into CR3 from 32-bit
    /// mode, and the kernel's PMM manages nothing above.
    pub fn allocate(boot_services: *BootServices) error{OutOfMemory}!BootData {
        const pages = boot_services.allocatePages(
            .{ .max_address = @ptrFromInt(kernel_image.LAST_PAGE_BELOW_4G) },
            .loader_data,
            BLOCK_PAGES,
        ) catch return error.OutOfMemory;
        @memset(std.mem.sliceAsBytes(pages), 0);
        return .{ .base = @intFromPtr(pages.ptr) };
    }

    fn at(self: BootData, part: Part) usize {
        return self.base + @intFromEnum(part) * PAGE;
    }

    fn table(self: BootData, part: Part) *[512]u64 {
        return @ptrFromInt(self.at(part));
    }

    pub fn info(self: BootData) *BootInfo {
        return @ptrFromInt(self.at(.boot_info));
    }

    pub fn regions(self: BootData) *[MAX_REGIONS]MemoryRegion {
        return @ptrFromInt(self.at(.regions));
    }

    pub fn pml4Phys(self: BootData) u64 {
        return self.at(.pml4);
    }

    /// The three windows of boot_protocol.zig. The identity and the physmap
    /// are 1 GiB pages; the image is 2 MiB pages onto wherever it was put.
    pub fn mapAddressSpace(self: BootData, image: kernel_image.Image) void {
        const pml4 = self.table(.pml4);
        // USER on the identity: a process inherits it for the lazy-fault
        // paths of early boot.
        pml4[0] = self.at(.pdpt_identity) | Pte.rw | Pte.user;
        pml4[tableIndex(protocol.PHYSMAP_BASE, PML4_SHIFT)] = self.at(.pdpt_physmap) | Pte.rw;
        pml4[tableIndex(protocol.KERNEL_VIRT_BASE, PML4_SHIFT)] = self.at(.pdpt_image) | Pte.rw;

        const identity = self.table(.pdpt_identity);
        for (0..protocol.IDENTITY_SIZE / GIB) |i| {
            identity[i] = i * GIB | Pte.rw | Pte.user | Pte.huge;
        }

        // GLOBAL: the kernel's mappings outlive a CR3 reload once it sets
        // CR4.PGE.
        const physmap = self.table(.pdpt_physmap);
        for (0..protocol.PHYSMAP_SIZE / GIB) |i| {
            physmap[i] = i * GIB | Pte.rw | Pte.huge | Pte.global;
        }

        self.table(.pdpt_image)[tableIndex(protocol.KERNEL_VIRT_BASE, PDPT_SHIFT)] = self.at(.pd_image) | Pte.rw;
        const image_pd = self.table(.pd_image);
        var link = image.link_base;
        while (link < image.link_base + image.span) : (link += kernel_image.HUGE_PAGE) {
            image_pd[@intCast(link / kernel_image.HUGE_PAGE)] = (link +% image.phys_offset) | Pte.rw | Pte.huge | Pte.global;
        }
    }

    /// Turns the firmware's map into the kernel's and records its length in
    /// BootInfo. Needs no boot service: call it after ExitBootServices, on
    /// the map whose key got through.
    pub fn adoptMemoryMap(self: BootData, map: MemoryMapSlice) MapSummary {
        const out = self.regions();
        var summary: MapSummary = .{};
        var count: u32 = 0;
        var descriptors = map.iterator();
        while (descriptors.next()) |descriptor| {
            const region: MemoryRegion = .{
                .base = descriptor.physical_start,
                .length = descriptor.number_of_pages * PAGE,
                .kind = kindOf(descriptor.type),
            };
            summary.descriptors += 1;
            switch (region.kind) {
                .usable => summary.usable_bytes += region.length,
                .acpi_nvs => summary.acpi_nvs_bytes += region.length,
                else => {},
            }

            if (count > 0 and continues(out[count - 1], region)) {
                out[count - 1].length += region.length;
            } else if (count < MAX_REGIONS) {
                out[count] = region;
                count += 1;
            } else {
                summary.dropped += 1;
            }
        }
        summary.regions = count;
        self.info().memory_map_count = count;
        return summary;
    }

    /// Does not return: onto the kernel's tables and GDT, then its entry
    /// with BootInfo in rdi. The stack stays the firmware's; the kernel
    /// leaves it at once.
    pub fn enterKernel(self: BootData, entry: u64) noreturn {
        const gdt: *[GDT.len]u64 = @ptrFromInt(self.at(.gdt));
        gdt.* = GDT;
        const gdtr: *Gdtr = @ptrFromInt(self.at(.gdt) + @sizeOf(@TypeOf(GDT)));
        gdtr.* = .{ .limit = @sizeOf(@TypeOf(GDT)) - 1, .base = @intFromPtr(gdt) };

        const code = std.fmt.comptimePrint("{d}", .{KERNEL_CODE_SELECTOR});
        const data = std.fmt.comptimePrint("{d}", .{KERNEL_DATA_SELECTOR});
        asm volatile ("cli\n" ++
                "movq %%rsi, %%cr3\n" ++
                "lgdt (%%rcx)\n" ++
                "pushq $" ++ code ++ "\n" ++
                "leaq 1f(%%rip), %%rax\n" ++
                "pushq %%rax\n" ++
                "lretq\n" ++
                "1:\n" ++
                "movw $" ++ data ++ ", %%ax\n" ++
                \\ movw %%ax, %%ds
                \\ movw %%ax, %%es
                \\ movw %%ax, %%fs
                \\ movw %%ax, %%gs
                \\ movw %%ax, %%ss
                \\ jmpq *%%rdx
            :
            : [tables] "{rsi}" (self.pml4Phys()),
              [gdtr] "{rcx}" (@intFromPtr(gdtr)),
              [entry] "{rdx}" (entry),
              [boot_info] "{rdi}" (@intFromPtr(self.info())),
        );
        unreachable;
    }
};

/// What the firmware's memory types are to the kernel. Boot-services memory
/// is free once they have exited; the loader's own is free once it has
/// jumped, but for the image and the boot data, which BootInfo names.
fn kindOf(memory_type: MemoryType) MemoryRegion.Kind {
    return switch (memory_type) {
        .conventional_memory,
        .loader_code,
        .loader_data,
        .boot_services_code,
        .boot_services_data,
        => .usable,
        .runtime_services_code, .runtime_services_data => .uefi_runtime,
        .acpi_reclaim_memory => .acpi_reclaimable,
        .acpi_memory_nvs => .acpi_nvs,
        .unusable_memory => .bad_memory,
        else => .reserved,
    };
}

fn continues(previous: MemoryRegion, next: MemoryRegion) bool {
    return previous.kind == next.kind and previous.base + previous.length == next.base;
}

pub const ExitError = error{ MemoryMap, Refused };

/// Leaves boot services and returns the map that was current when they went.
/// After a refusal the firmware allows nothing but another try, so the
/// caller must not touch boot services on `Refused` either.
pub fn exitBootServices(boot_services: *BootServices, image_handle: uefi.Handle, map_buffer: []align(@alignOf(uefi.tables.MemoryDescriptor)) u8) ExitError!MemoryMapSlice {
    // The key is the latest map's. The firmware may change the map inside
    // ExitBootServices itself: then it wants the new key.
    var attempts_left: u32 = 3;
    while (attempts_left > 0) : (attempts_left -= 1) {
        const map = boot_services.getMemoryMap(map_buffer) catch return error.MemoryMap;
        boot_services.exitBootServices(image_handle, map.info.key) catch continue;
        return map;
    }
    return error.Refused;
}

/// A buffer for `exitBootServices`, with room for the descriptors this very
/// allocation adds.
pub fn allocateMapBuffer(boot_services: *BootServices) error{ MemoryMap, OutOfMemory }![]align(@alignOf(uefi.tables.MemoryDescriptor)) u8 {
    const SPARE_DESCRIPTORS = 16;
    const size = boot_services.getMemoryMapInfo() catch return error.MemoryMap;
    const bytes = (size.len + SPARE_DESCRIPTORS) * size.descriptor_size;
    return boot_services.allocatePool(.loader_data, bytes) catch return error.OutOfMemory;
}
