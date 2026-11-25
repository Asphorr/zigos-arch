//! kernel.elf, read from the boot volume into memory the firmware gives us.
//!
//! The image does not go to the physical addresses it was linked for: those
//! can be the firmware's own (OVMF keeps what S3 resume needs at 8..9 MiB,
//! as ACPI NVS). It goes wherever AllocatePages has room, a whole number of
//! 2 MiB pages away from its link addresses, and the kernel is told how far.

const std = @import("std");
const uefi = std.os.uefi;
const protocol = @import("boot_protocol");
const BootServices = uefi.tables.BootServices;
const File = uefi.protocol.File;

pub const Error = error{
    Missing,
    ShortRead,
    NotElf,
    WrongClass,
    BadSegments,
    OutOfMemory,
    NoEntrySymbol,
};

pub const Image = struct {
    /// Virtual address of `protocol.ENTRY_SYMBOL`, inside the mapped span.
    entry: u64,
    /// What the image window has to map: the link-time physical span of the
    /// segments, widened to 2 MiB pages.
    link_base: u64,
    span: u64,
    /// The span lies at `link_base + phys_offset`.
    phys_offset: u64,
};

pub const HUGE_PAGE: u64 = 0x200000;
/// AllocatePages takes the highest address allowed, a page pointer.
pub const LAST_PAGE_BELOW_4G: usize = 0xFFFF_F000;

const MAX_SEGMENTS = 16;

const Elf64Header = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

const Elf64Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

const Elf64Shdr = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

const Elf64Sym = extern struct {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
};

const EI_CLASS = 4;
const EI_DATA = 5;
const ELFCLASS64 = 2;
const ELFDATA2LSB = 1;
const EM_X86_64 = 62;
const PT_LOAD = 1;
const SHT_SYMTAB = 2;

/// Reads /kernel.elf from `root` into allocated memory. The pages stay
/// allocated: the memory map calls them usable, the kernel keeps its own.
pub fn load(boot_services: *BootServices, root: *const File) Error!Image {
    const file = root.open(std.unicode.utf8ToUtf16LeStringLiteral("kernel.elf"), .read, .{}) catch return error.Missing;
    defer file.close() catch {};

    var header: Elf64Header = undefined;
    try readAt(file, 0, std.mem.asBytes(&header));
    if (!std.mem.eql(u8, header.e_ident[0..4], "\x7FELF")) return error.NotElf;
    if (header.e_ident[EI_CLASS] != ELFCLASS64 or header.e_ident[EI_DATA] != ELFDATA2LSB or
        header.e_machine != EM_X86_64) return error.WrongClass;

    var storage: [MAX_SEGMENTS]Elf64Phdr = undefined;
    const segments = try readLoadSegments(file, &header, &storage);

    var image = try place(boot_services, segments);
    for (segments) |segment| {
        const dest: [*]u8 = @ptrFromInt(@as(usize, @intCast(segment.p_paddr +% image.phys_offset)));
        try readAt(file, segment.p_offset, dest[0..@intCast(segment.p_filesz)]);
    }
    // No such symbol: the kernel was built for another protocol version.
    image.entry = try findSymbol(boot_services, file, &header, protocol.ENTRY_SYMBOL);
    const window_start = protocol.KERNEL_VIRT_BASE + image.link_base;
    if (image.entry < window_start or image.entry - window_start >= image.span) return error.NoEntrySymbol;
    return image;
}

fn readAt(file: *File, offset: u64, dest: []u8) Error!void {
    file.setPosition(offset) catch return error.ShortRead;
    var done: usize = 0;
    while (done < dest.len) {
        const got = file.read(dest[done..]) catch return error.ShortRead;
        if (got == 0) return error.ShortRead;
        done += got;
    }
}

fn readLoadSegments(file: *File, header: *const Elf64Header, storage: *[MAX_SEGMENTS]Elf64Phdr) Error![]const Elf64Phdr {
    if (header.e_phentsize != @sizeOf(Elf64Phdr)) return error.BadSegments;
    var count: usize = 0;
    for (0..header.e_phnum) |index| {
        var segment: Elf64Phdr = undefined;
        try readAt(file, header.e_phoff + index * @sizeOf(Elf64Phdr), std.mem.asBytes(&segment));
        if (segment.p_type != PT_LOAD or segment.p_memsz == 0) continue;
        if (segment.p_filesz > segment.p_memsz or count == storage.len) return error.BadSegments;
        storage[count] = segment;
        count += 1;
    }
    if (count == 0) return error.BadSegments;
    return storage[0..count];
}

/// Allocates zeroed memory for the segments' span and settles the offset.
fn place(boot_services: *BootServices, segments: []const Elf64Phdr) Error!Image {
    var lowest: u64 = std.math.maxInt(u64);
    var highest: u64 = 0;
    for (segments) |segment| {
        lowest = @min(lowest, segment.p_paddr);
        highest = @max(highest, segment.p_paddr +| segment.p_memsz);
    }
    if (highest > protocol.IMAGE_WINDOW_SIZE) return error.BadSegments;

    const link_base = std.mem.alignBackward(u64, lowest, HUGE_PAGE);
    const span = std.mem.alignForward(u64, highest, HUGE_PAGE) - link_base;
    // One huge page more than the span: wherever these pages land, they hold
    // a 2 MiB-aligned run of `span` bytes.
    const pages = boot_services.allocatePages(
        .{ .max_address = @ptrFromInt(LAST_PAGE_BELOW_4G) },
        .loader_data,
        @intCast((span + HUGE_PAGE) / 4096),
    ) catch return error.OutOfMemory;
    const phys_base = std.mem.alignForward(u64, @intFromPtr(pages.ptr), HUGE_PAGE);
    @memset(@as([*]u8, @ptrFromInt(@as(usize, @intCast(phys_base))))[0..@intCast(span)], 0);

    return .{ .entry = 0, .link_base = link_base, .span = span, .phys_offset = phys_base -% link_base };
}

fn findSymbol(boot_services: *BootServices, file: *File, header: *const Elf64Header, name: []const u8) Error!u64 {
    if (header.e_shentsize != @sizeOf(Elf64Shdr)) return error.NoEntrySymbol;
    const symtab = try findSymbolTable(file, header);
    var strtab: Elf64Shdr = undefined;
    try readAt(file, header.e_shoff + @as(u64, symtab.sh_link) * @sizeOf(Elf64Shdr), std.mem.asBytes(&strtab));
    if (symtab.sh_entsize != @sizeOf(Elf64Sym)) return error.NoEntrySymbol;

    const symbols = try readSection(boot_services, file, &symtab);
    defer boot_services.freePool(symbols.ptr) catch {};
    const names = try readSection(boot_services, file, &strtab);
    defer boot_services.freePool(names.ptr) catch {};

    var offset: usize = 0;
    while (offset + @sizeOf(Elf64Sym) <= symbols.len) : (offset += @sizeOf(Elf64Sym)) {
        const symbol = std.mem.bytesToValue(Elf64Sym, symbols[offset..][0..@sizeOf(Elf64Sym)]);
        if (symbol.st_value == 0 or symbol.st_name >= names.len) continue;
        const symbol_name = std.mem.sliceTo(names[symbol.st_name..], 0);
        if (std.mem.eql(u8, symbol_name, name)) return symbol.st_value;
    }
    return error.NoEntrySymbol;
}

fn findSymbolTable(file: *File, header: *const Elf64Header) Error!Elf64Shdr {
    for (0..header.e_shnum) |index| {
        var section: Elf64Shdr = undefined;
        try readAt(file, header.e_shoff + index * @sizeOf(Elf64Shdr), std.mem.asBytes(&section));
        if (section.sh_type == SHT_SYMTAB and section.sh_link < header.e_shnum) return section;
    }
    return error.NoEntrySymbol;
}

fn readSection(boot_services: *BootServices, file: *File, section: *const Elf64Shdr) Error![]align(8) u8 {
    const bytes = boot_services.allocatePool(.loader_data, @intCast(section.sh_size)) catch return error.OutOfMemory;
    errdefer boot_services.freePool(bytes.ptr) catch {};
    try readAt(file, section.sh_offset, bytes);
    return bytes;
}
