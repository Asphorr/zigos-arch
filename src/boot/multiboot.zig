pub const MultibootInfo = extern struct {
    flags: u32,
    mem_lower: u32,
    mem_upper: u32,
    boot_device: u32,
    cmdline: u32,
    mods_count: u32,
    mods_addr: u32,
    syms: [4]u32,
    mmap_length: u32,
    mmap_addr: u32,
};

pub const MultibootMmapEntry = extern struct {
    size: u32,
    addr_low: u32,
    addr_high: u32,
    len_low: u32,
    len_high: u32,
    @"type": u32,
};
