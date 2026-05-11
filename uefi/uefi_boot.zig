// ZigOS UEFI Bootloader
// Loads kernel.elf from the ESP, sets up page tables + GDT, jumps to kernel.
// Built with .uefi target → produces PE/COFF BOOTX64.EFI

const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const BootServices = uefi.tables.BootServices;
const ConfigurationTable = uefi.tables.ConfigurationTable;
const GraphicsOutput = uefi.protocol.GraphicsOutput;
const SimpleFileSystem = uefi.protocol.SimpleFileSystem;
const File = uefi.protocol.File;
const MemoryType = uefi.tables.MemoryType;
const MemoryDescriptor = uefi.tables.MemoryDescriptor;
const menu = @import("menu.zig");
const nvram = @import("nvram.zig");
const error_screen = @import("error_screen.zig");

// BootInfo struct — must match src/boot_info.zig exactly
const MemoryRegion = extern struct {
    base: u64,
    length: u64,
    kind: u32, // matches boot_info.zig MemoryRegion.Kind enum
};

const FramebufferInfo = extern struct {
    base: u64,
    width: u32,
    height: u32,
    stride: u32,
    format: u32, // 0=bgra, 1=rgba, 2=unknown
};

// MUST match `src/boot/boot_info.zig:BootInfo` exactly — this is the
// duplicated definition the bootloader uses (UEFI target can't pull in
// the freestanding kernel module). If you add a field here, add it
// there too.
const BootInfo = extern struct {
    memory_map: [*]const MemoryRegion,
    memory_map_count: u32,
    has_framebuffer: u32,
    framebuffer: FramebufferInfo,
    pml4_phys: u64,
    rsdp_addr: u64,
    boot_mode: u32, // 0=normal, 1=verbose, 2=safe — picked by menu
    _reserved: u32 = 0,
    runtime_services_addr: u64 = 0,
    bootloader_build_id: u64 = 0,
    cmdline: [256]u8 = [_]u8{0} ** 256,
    cmdline_len: u32 = 0,
    _reserved2: u32 = 0,
};

// ELF64 header structures
const ELF_MAGIC = [4]u8{ 0x7F, 'E', 'L', 'F' };

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

const PT_LOAD: u32 = 1;

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

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;

// Fixed addresses for bootloader data (after kernel's back buffer region)
const PAGE_TABLES_ADDR: u64 = 0x1C00000; // 28MB — PML4+PDPT+8xPD = 10 pages (0x1C00000-0x1C09FFF)
const BOOT_INFO_ADDR: u64 = 0x1C30000; // After page tables (PML4+PDPT+34 PDs end at 0x1C24000)
const MMAP_REGIONS_ADDR: u64 = 0x1C31000; // MemoryRegion array (64 entries × 20 bytes < 4KB)
const BOOT_STACK_TOP: u64 = 0x1C40000; // Stack (pages below this, after BootInfo+mmap)

// Output to serial COM1 (0x3F8) for debug — works before and after ExitBootServices
fn serialPut(c: u8) void {
    // Wait for transmit buffer empty
    while (asm volatile ("inb %[port], %[ret]"
        : [ret] "={al}" (-> u8),
        : [port] "N{dx}" (@as(u16, 0x3FD)),
    ) & 0x20 == 0) {}
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (c),
          [port] "N{dx}" (@as(u16, 0x3F8)),
    );
}

fn serialPrint(msg: []const u8) void {
    for (msg) |c| serialPut(c);
}

fn serialHex(val: u64) void {
    const hex = "0123456789ABCDEF";
    serialPrint("0x");
    var i: u6 = 60;
    var started = false;
    while (true) : (i -= 4) {
        const nibble: u4 = @truncate(val >> i);
        if (nibble != 0) started = true;
        if (started or i == 0) serialPut(hex[nibble]);
        if (i == 0) break;
    }
}

pub fn main() uefi.Status {
    const system_table = uefi.system_table;
    const image_handle = uefi.handle;
    // Init serial for debug output
    // Set 38400 baud, 8N1
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x00)),
          [port] "N{dx}" (@as(u16, 0x3F9)),
    ); // Disable interrupts
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x80)),
          [port] "N{dx}" (@as(u16, 0x3FB)),
    ); // DLAB on
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x03)),
          [port] "N{dx}" (@as(u16, 0x3F8)),
    ); // Divisor low (38400)
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x00)),
          [port] "N{dx}" (@as(u16, 0x3F9)),
    ); // Divisor high
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x03)),
          [port] "N{dx}" (@as(u16, 0x3FB)),
    ); // 8N1
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0xC7)),
          [port] "N{dx}" (@as(u16, 0x3FA)),
    ); // FIFO
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x0B)),
          [port] "N{dx}" (@as(u16, 0x3FC)),
    ); // RTS/DSR

    serialPrint("[uefi] ZigOS UEFI bootloader\n");

    const boot_services = system_table.boot_services orelse {
        serialPrint("[uefi] No boot services!\n");
        return .aborted;
    };

    // --- 1. Locate GOP ---
    serialPrint("[uefi] Locating GOP...\n");
    var fb_info = FramebufferInfo{
        .base = 0,
        .width = 0,
        .height = 0,
        .stride = 0,
        .format = 2,
    };
    var has_fb: u32 = 0;

    const gop_result = boot_services.locateProtocol(GraphicsOutput, null) catch null;
    if (gop_result) |gop| {
        const mode = gop.mode;
        const info = mode.info;
        fb_info.base = mode.frame_buffer_base;
        fb_info.width = info.horizontal_resolution;
        fb_info.height = info.vertical_resolution;
        fb_info.stride = info.pixels_per_scan_line;
        fb_info.format = switch (info.pixel_format) {
            .blue_green_red_reserved_8_bit_per_color => 0, // bgra
            .red_green_blue_reserved_8_bit_per_color => 1, // rgba
            else => 2, // unknown
        };
        has_fb = 1;
        serialPrint("[uefi] GOP: ");
        serialHex(fb_info.width);
        serialPut('x');
        serialHex(fb_info.height);
        serialPrint(" fb=");
        serialHex(fb_info.base);
        serialPut('\n');
    } else {
        serialPrint("[uefi] No GOP found\n");
    }

    // --- 1.5. Boot menu (only if GOP + keyboard available) ---
    // menu.show() handles "About" entry internally and never returns 0xFF —
    // it always returns a real boot mode (0/1/2). Esc returns 0 (default).
    //
    // Default-selection comes from NVRAM:
    //   - LastBootMode (0/1/2)        → which entry is highlighted
    //   - LastBootStatus == .crashed → force Safe (entry 2) regardless of mode
    //
    // The status check covers the recovery loop: a kernel that consistently
    // panics in CPU bring-up would otherwise need manual intervention every
    // boot. With this, the second consecutive boot lands in Safe mode.
    // RuntimeServices is mandatory in the UEFI spec — present on every
    // standards-compliant firmware. Type is non-nullable so no orelse here.
    const runtime_services = system_table.runtime_services;

    // Cmdline read once here so it's available when filling BootInfo
    // post-handoff. Persists across reboots via NVRAM.
    var cmdline_buf: [256]u8 = [_]u8{0} ** 256;
    const cmdline_len: usize = nvram.getCmdline(runtime_services, &cmdline_buf);
    if (cmdline_len > 0) {
        serialPrint("[nvram] cmdline=");
        var ci: usize = 0;
        while (ci < cmdline_len and ci < cmdline_buf.len) : (ci += 1) {
            if (cmdline_buf[ci] >= 0x20 and cmdline_buf[ci] < 0x7F) serialPut(cmdline_buf[ci]);
        }
        serialPut('\n');
    }

    // Read the boot history ring and decide:
    //   - which menu entry to highlight by default
    //   - whether to show the crash fingerprint banner
    //   - whether to escalate to Safe after a string of same-mode crashes
    //
    // The ring is the canonical source of truth post-Phase-2. Singletons
    // (LastBootMode/Status/CrashFp) are still written by the existing
    // kernel-side code so a brand-new kernel against an old NVRAM (or
    // vice-versa) keeps working — `historyMaybeFromSingletons` synthesizes
    // a one-entry ring on first read if the ring var is missing.
    var default_selection: u32 = 0;
    var crash_fp_buf: [256]u8 = undefined;
    var crash_fp_len: usize = 0;
    const ring_opt = nvram.historyRead(runtime_services);
    if (ring_opt) |ring| {
        const last_idx_opt = nvram.historyLastSlotIdx(&ring);
        if (last_idx_opt) |last_idx| {
            const last = ring.entries[last_idx];
            const last_status = std.enums.fromInt(nvram.BootStatus, last.outcome) orelse .unknown;
            serialPrint("[nvram] ring next=");
            serialHex(ring.next);
            serialPrint(" last_mode=");
            serialHex(last.mode);
            serialPrint(" last_status=");
            serialHex(@intFromEnum(last_status));
            serialPut('\n');

            // Recovery escalation: walk the most-recent entries; if 3 in a
            // row are crashed AND from the same mode, that mode is broken
            // — force Safe regardless of what the user picked last. One
            // crash is bad luck; three is a pattern.
            var consecutive: u32 = 0;
            const consec_mode: u32 = last.mode;
            const window: u32 = @min(@as(u32, @intCast(ring.next)), nvram.HISTORY_DEPTH);
            var w: u32 = 0;
            while (w < window) : (w += 1) {
                const slot: usize = @intCast((@as(u64, ring.next) -% (1 + w)) % nvram.HISTORY_DEPTH);
                const e = ring.entries[slot];
                if (e.outcome == @intFromEnum(nvram.BootStatus.crashed) and e.mode == consec_mode) {
                    consecutive += 1;
                } else break;
            }

            if (last_status == .crashed or last_status == .in_progress) {
                // Tiered fallback policy:
                //   GPU compositor (mode 9) crash → Normal (menu idx 0). The
                //   GPU path is opt-in; a CPU compositor desktop is the
                //   right next step, not Safe-no-SMP.
                //   Anything else → Safe (menu idx 2).
                //   3+ same-mode crashes → always Safe regardless of mode.
                if (consecutive >= 3) {
                    default_selection = 2; // Safe
                    serialPrint("[nvram] 3+ same-mode crashes in a row — locked to Safe\n");
                } else if (last.mode == 9) {
                    default_selection = 0; // Normal
                    serialPrint("[nvram] GPU compositor (mode 9) crashed — defaulting to Normal\n");
                } else {
                    default_selection = 2; // Safe
                    serialPrint("[nvram] previous boot didn't complete — defaulting to Safe\n");
                }
                if (last.crash_fp_len > 0) {
                    const n = @min(@as(usize, last.crash_fp_len), crash_fp_buf.len);
                    @memcpy(crash_fp_buf[0..n], last.crash_fp[0..n]);
                    crash_fp_len = n;
                } else {
                    // Fall back to the legacy singleton if the ring entry's
                    // fp slot is empty (kernel-side didn't push to ring yet).
                    crash_fp_len = nvram.getCrashFp(runtime_services, &crash_fp_buf);
                }
            } else {
                // Last boot succeeded — highlight that mode if it still
                // exists in the menu (mode→entry walk covers Tests-submenu
                // modes 3..7 which never appear in the main menu).
                for (menu.ENTRIES, 0..) |e, ei| {
                    if (e.boot_mode == last.mode) {
                        default_selection = @intCast(ei);
                        break;
                    }
                }
            }
        }
    } else {
        // No ring yet — first boot or NVRAM was reset. Fall back to the
        // singleton vars so behavior matches pre-Phase-2 builds during
        // the migration.
        const last_mode = nvram.getBootMode(runtime_services);
        const last_status = nvram.getBootStatus(runtime_services);
        serialPrint("[nvram] no ring; falling back to singletons last_mode=");
        serialHex(last_mode);
        serialPrint(" last_status=");
        serialHex(@intFromEnum(last_status));
        serialPut('\n');
        if (last_status == .crashed or last_status == .in_progress) {
            // Same tiered fallback as the ring path: GPU mode → Normal,
            // anything else → Safe. (No 3-in-a-row escalation here because
            // singletons don't carry that history.)
            if (last_mode == 9) {
                default_selection = 0;
                serialPrint("[nvram] mode 9 crashed (singleton) — defaulting to Normal\n");
            } else {
                default_selection = 2;
            }
            crash_fp_len = nvram.getCrashFp(runtime_services, &crash_fp_buf);
        } else {
            for (menu.ENTRIES, 0..) |e, ei| {
                if (e.boot_mode == last_mode) {
                    default_selection = @intCast(ei);
                    break;
                }
            }
        }
    }

    var boot_mode: u32 = 0;
    if (gop_result) |gop_for_menu| {
        if (system_table.con_in) |stin| {
            serialPrint("[uefi] Showing boot menu...\n");
            // menu.show returns the chosen boot_mode directly. Sentinel values
            // (Tests/About/Back) are resolved internally; only real boot-modes
            // (0..127) leak out. Tests-submenu boot-modes (3,4,...) ride the
            // same channel — kernel's boot_mode dispatch knows how to map them.
            const ring_ref: ?*const nvram.BootHistoryRing = if (ring_opt) |*r| r else null;
            boot_mode = menu.show(gop_for_menu, stin, boot_services, runtime_services, default_selection, crash_fp_buf[0..crash_fp_len], ring_ref);
            serialPrint("[uefi] boot_mode=");
            serialHex(boot_mode);
            serialPut('\n');
        } else {
            serialPrint("[uefi] No con_in — skipping menu\n");
        }
    }

    // Persist the user's choice + mark "in_progress". The kernel will flip
    // this to `success` after it reaches its "boot complete" milestone
    // (Phase 2). If we ever boot and find this still set to `in_progress`,
    // it means the previous kernel either crashed or wedged — we'll fall
    // back to Safe mode next time (logic above).
    nvram.setBootMode(runtime_services, boot_mode);
    nvram.setBootStatus(runtime_services, .in_progress);

    // Push a fresh entry to the boot history ring. Kernel will mutate this
    // slot in-place to record success / crash. We stamp the bootloader's
    // build_id now; kernel will stamp `kernel_build_id` later. Mismatch
    // between the two on a single entry surfaces in About as build skew.
    {
        const bo = @import("build_options");
        nvram.historyPush(runtime_services, boot_mode, bo.build_id);
    }

    // --- 2. Load kernel.elf from ESP ---
    serialPrint("[uefi] Loading kernel.elf...\n");
    var kernel_entry: u64 = 0;

    const fs_result = boot_services.locateProtocol(SimpleFileSystem, null) catch null;
    if (fs_result) |filesystem| {
        const root = filesystem.openVolume() catch null;
        if (root) |root_dir| {
            // Open kernel.elf
            const kernel_file = root_dir.open(
                &[_:0]u16{ 'k', 'e', 'r', 'n', 'e', 'l', '.', 'e', 'l', 'f' },
                .read,
                .{},
            ) catch null;

            if (kernel_file) |file| {
                // Read ELF header
                var ehdr: Elf64Header = undefined;
                const ehdr_bytes: *[@sizeOf(Elf64Header)]u8 = @ptrCast(&ehdr);
                _ = file.read(ehdr_bytes) catch 0;

                if (ehdr.e_ident[0] == 0x7F and ehdr.e_ident[1] == 'E' and
                    ehdr.e_ident[2] == 'L' and ehdr.e_ident[3] == 'F')
                {
                    serialPrint("[uefi] ELF valid, entry=");
                    serialHex(ehdr.e_entry);
                    serialPrint(" phnum=");
                    serialHex(ehdr.e_phnum);
                    serialPut('\n');
                    kernel_entry = ehdr.e_entry;

                    // Load PT_LOAD segments
                    for (0..ehdr.e_phnum) |pi| {
                        file.setPosition(ehdr.e_phoff + pi * @sizeOf(Elf64Phdr)) catch continue;
                        var phdr: Elf64Phdr = undefined;
                        const phdr_bytes: *[@sizeOf(Elf64Phdr)]u8 = @ptrCast(&phdr);
                        _ = file.read(phdr_bytes) catch continue;

                        if (phdr.p_type != PT_LOAD) continue;
                        if (phdr.p_memsz == 0) continue;

                        serialPrint("[uefi]   LOAD ");
                        serialHex(phdr.p_paddr);
                        serialPrint(" filesz=");
                        serialHex(phdr.p_filesz);
                        serialPrint(" memsz=");
                        serialHex(phdr.p_memsz);
                        serialPut('\n');

                        // Zero the target region
                        const dest: [*]u8 = @ptrFromInt(@as(usize, @intCast(phdr.p_paddr)));
                        for (0..@intCast(phdr.p_memsz)) |i| dest[i] = 0;

                        // Copy file data
                        file.setPosition(phdr.p_offset) catch continue;
                        const copy_len: usize = @intCast(phdr.p_filesz);
                        _ = file.read(dest[0..copy_len]) catch {};
                    }

                    // Find kmain_uefi symbol in ELF symbol table
                    var symtab_off: u64 = 0;
                    var symtab_size: u64 = 0;
                    var symtab_entsize: u64 = 0;
                    var strtab_off: u64 = 0;
                    var symtab_link: u32 = 0;

                    // Scan section headers to find .symtab
                    for (0..ehdr.e_shnum) |si| {
                        file.setPosition(ehdr.e_shoff + si * @sizeOf(Elf64Shdr)) catch continue;
                        var shdr: Elf64Shdr = undefined;
                        const shdr_bytes: *[@sizeOf(Elf64Shdr)]u8 = @ptrCast(&shdr);
                        _ = file.read(shdr_bytes) catch continue;

                        if (shdr.sh_type == SHT_SYMTAB) {
                            symtab_off = shdr.sh_offset;
                            symtab_size = shdr.sh_size;
                            symtab_entsize = if (shdr.sh_entsize > 0) shdr.sh_entsize else @sizeOf(Elf64Sym);
                            symtab_link = shdr.sh_link; // index of associated strtab
                        }
                    }

                    // Get strtab offset
                    if (symtab_link > 0) {
                        file.setPosition(ehdr.e_shoff + @as(u64, symtab_link) * @sizeOf(Elf64Shdr)) catch {};
                        var strtab_shdr: Elf64Shdr = undefined;
                        const strtab_bytes: *[@sizeOf(Elf64Shdr)]u8 = @ptrCast(&strtab_shdr);
                        _ = file.read(strtab_bytes) catch {};
                        strtab_off = strtab_shdr.sh_offset;
                    }

                    // Search symbols for "kmain_uefi"
                    if (symtab_off > 0 and strtab_off > 0) {
                        const target_name = "kmain_uefi";
                        const num_syms = symtab_size / symtab_entsize;
                        for (0..@intCast(num_syms)) |si| {
                            file.setPosition(symtab_off + si * symtab_entsize) catch continue;
                            var sym: Elf64Sym = undefined;
                            const sym_bytes: *[@sizeOf(Elf64Sym)]u8 = @ptrCast(&sym);
                            _ = file.read(sym_bytes) catch continue;

                            if (sym.st_name == 0 or sym.st_value == 0) continue;

                            // Read symbol name from strtab
                            file.setPosition(strtab_off + sym.st_name) catch continue;
                            var name_buf: [32]u8 = undefined;
                            const name_len = file.read(&name_buf) catch 0;
                            if (name_len >= target_name.len) {
                                if (std.mem.eql(u8, name_buf[0..target_name.len], target_name)) {
                                    kernel_entry = sym.st_value;
                                    serialPrint("[uefi] Found kmain_uefi at ");
                                    serialHex(kernel_entry);
                                    serialPut('\n');
                                    break;
                                }
                            }
                        }
                    }

                    serialPrint("[uefi] Kernel loaded\n");
                } else {
                    serialPrint("[uefi] Invalid ELF!\n");
                    error_screen.show(gop_result, system_table.con_in, runtime_services, .invalid_elf_magic, "");
                }
                file.close() catch {};
            } else {
                serialPrint("[uefi] kernel.elf not found!\n");
                error_screen.show(gop_result, system_table.con_in, runtime_services, .open_kernel_file, "");
            }
            root_dir.close() catch {};
        } else {
            serialPrint("[uefi] openVolume failed!\n");
            error_screen.show(gop_result, system_table.con_in, runtime_services, .open_volume, "");
        }
    } else {
        serialPrint("[uefi] No filesystem!\n");
        error_screen.show(gop_result, system_table.con_in, runtime_services, .no_filesystem, "");
    }

    // --- 3. Find RSDP from configuration table ---
    var rsdp_addr: u64 = 0;
    for (0..system_table.number_of_table_entries) |i| {
        const entry = system_table.configuration_table[i];
        if (std.mem.eql(u8, std.mem.asBytes(&entry.vendor_guid), std.mem.asBytes(&ConfigurationTable.acpi_20_table_guid))) {
            rsdp_addr = @intFromPtr(entry.vendor_table);
            serialPrint("[uefi] RSDP at ");
            serialHex(rsdp_addr);
            serialPut('\n');
            break;
        }
    }

    // --- 4. Get memory map + ExitBootServices ---
    serialPrint("[uefi] Getting memory map...\n");

    // Get memory map size first
    const mmap_info = boot_services.getMemoryMapInfo() catch {
        serialPrint("[uefi] getMemoryMapInfo failed!\n");
        return .aborted;
    };

    // Allocate buffer (add extra space for the allocation itself changing the map)
    const mmap_buf_size = (mmap_info.len + 4) * mmap_info.descriptor_size;
    const mmap_buf = boot_services.allocatePool(.loader_data, mmap_buf_size) catch {
        serialPrint("[uefi] allocatePool failed!\n");
        return .aborted;
    };

    // Get the actual memory map
    var mmap_size: usize = mmap_buf_size;
    var map_key: uefi.tables.MemoryMapKey = undefined;
    var desc_size: usize = undefined;
    var desc_version: u32 = undefined;

    switch (boot_services._getMemoryMap(
        &mmap_size,
        @alignCast(mmap_buf.ptr),
        &map_key,
        &desc_size,
        &desc_version,
    )) {
        .success => {},
        else => {
            serialPrint("[uefi] getMemoryMap failed!\n");
            return .aborted;
        },
    }

    const num_descs = mmap_size / desc_size;
    serialPrint("[uefi] Memory map: ");
    serialHex(num_descs);
    serialPrint(" entries\n");

    // Convert UEFI memory map to BootInfo MemoryRegion array BEFORE ExitBootServices
    // (We write to fixed physical addresses that are in conventional memory).
    // 256 × 24 B = 6 KB, fits in MMAP_REGIONS_ADDR..0x1C40000 (60 KB room).
    // Real-HW UEFI emits 80-200 descriptors typically; QEMU emits ~10.
    const regions: [*]MemoryRegion = @ptrFromInt(@as(usize, @intCast(MMAP_REGIONS_ADDR)));
    var region_count: u32 = 0;
    const max_regions: u32 = 256;

    // Per-type histogram for first-real-HW-boot diagnostics. The first time
    // something feels off on a new machine, the serial log already has the
    // breakdown; we don't have to re-flash to add prints.
    var hist_conv: u32 = 0;
    var hist_loader: u32 = 0;
    var hist_bs: u32 = 0;
    var hist_rs: u32 = 0;
    var hist_acpi_r: u32 = 0;
    var hist_acpi_nvs: u32 = 0;
    var hist_unusable: u32 = 0;
    var hist_other: u32 = 0;
    var total_usable_pages: u64 = 0;
    var truncated: u32 = 0;

    for (0..num_descs) |i| {
        const desc: *MemoryDescriptor = @ptrCast(@alignCast(mmap_buf.ptr + i * desc_size));
        const pages = desc.number_of_pages;
        const kind: u32 = switch (desc.type) {
            .conventional_memory => blk: {
                hist_conv += 1;
                total_usable_pages += pages;
                break :blk 1;
            },
            .loader_code, .loader_data => blk: {
                hist_loader += 1;
                total_usable_pages += pages;
                break :blk 1;
            },
            .boot_services_code, .boot_services_data => blk: {
                hist_bs += 1;
                total_usable_pages += pages;
                break :blk 1;
            },
            .runtime_services_code, .runtime_services_data => blk: {
                hist_rs += 1;
                break :blk 6;
            },
            .acpi_reclaim_memory => blk: {
                hist_acpi_r += 1;
                break :blk 3;
            },
            .acpi_memory_nvs => blk: {
                hist_acpi_nvs += 1;
                break :blk 4;
            },
            .unusable_memory => blk: {
                hist_unusable += 1;
                break :blk 5;
            },
            else => blk: {
                hist_other += 1;
                break :blk 2;
            },
        };
        if (region_count >= max_regions) {
            truncated += 1;
            continue;
        }
        regions[region_count] = .{
            .base = desc.physical_start,
            .length = pages * 4096,
            .kind = kind,
        };
        region_count += 1;
    }

    serialPrint("[uefi] memmap hist: conv=");
    serialHex(hist_conv);
    serialPrint(" loader=");
    serialHex(hist_loader);
    serialPrint(" bs=");
    serialHex(hist_bs);
    serialPrint(" rs=");
    serialHex(hist_rs);
    serialPrint(" acpi_r=");
    serialHex(hist_acpi_r);
    serialPrint(" acpi_nvs=");
    serialHex(hist_acpi_nvs);
    serialPrint(" unusable=");
    serialHex(hist_unusable);
    serialPrint(" other=");
    serialHex(hist_other);
    serialPrint("\n[uefi] memmap usable_pages=");
    serialHex(total_usable_pages);
    serialPrint(" (");
    serialHex(total_usable_pages * 4 / 1024);
    serialPrint(" MB) regions=");
    serialHex(region_count);
    serialPrint("\n");
    if (truncated > 0) {
        serialPrint("[uefi] WARNING: memory map truncated, ");
        serialHex(truncated);
        serialPrint(" entries dropped (bump max_regions)\n");
    }

    // --- ExitBootServices ---
    serialPrint("[uefi] ExitBootServices...\n");
    boot_services.exitBootServices(image_handle, map_key) catch {
        // Map key may have changed — retry with fresh map
        serialPrint("[uefi] Retry ExitBootServices...\n");
        var retry_size: usize = mmap_buf_size;
        var retry_key: uefi.tables.MemoryMapKey = undefined;
        switch (boot_services._getMemoryMap(
            &retry_size,
            @alignCast(mmap_buf.ptr),
            &retry_key,
            &desc_size,
            &desc_version,
        )) {
            .success => {},
            else => {
                serialPrint("[uefi] Retry getMemoryMap failed!\n");
                while (true) asm volatile ("hlt");
            },
        }
        boot_services.exitBootServices(image_handle, retry_key) catch {
            serialPrint("[uefi] ExitBootServices failed!\n");
            while (true) asm volatile ("hlt");
        };
    };

    // === NO MORE UEFI CALLS AFTER THIS POINT ===
    serialPrint("[uefi] Boot services exited\n");

    // --- 5. Set up page tables for the higher-half kernel ---
    //
    // Phase 1+2+3 of the higher-half migration moved the kernel image to
    // VA 0xFFFFFFFF80000000 and added a 64 GB physmap window at
    // 0xFFFF800000000000. boot.asm sets up a three-PDPT layout for the
    // Multiboot path; we mirror it here for UEFI:
    //
    //   PML4[0]    → pdpt_low      64×1GB identity (0..64GB) USER bit on.
    //   PML4[256]  → pdpt_physmap  64×1GB at VA 0xFFFF800000000000 →
    //                              phys 0..64GB. Kernel-only physmap.
    //   PML4[511]  → pdpt_high     1×1GB at slot 510 (VA -2GB) →
    //                              phys 0..1GB. Kernel image lives here.
    //
    // Without PML4[511], the kernel's first instruction fetch at the
    // high-half entry point (kmain_uefi at 0xFFFFFFFF801C....) faults
    // immediately on the iretq/lretq dispatch — no serial output, no
    // panic message, just a triple-fault back to firmware. Without
    // PML4[256], every kernel-side `paging.physToVirt(p)` access
    // (heap, kasan shadow, MMIO base translation, PT walks) hits an
    // unmapped VA. UEFI_PT_SIZE = 256 KB, the four pages used here
    // sit comfortably inside it.
    const pml4: [*]volatile u64 = @ptrFromInt(@as(usize, @intCast(PAGE_TABLES_ADDR)));
    const pdpt_low: [*]volatile u64 = @ptrFromInt(@as(usize, @intCast(PAGE_TABLES_ADDR + 0x1000)));
    const pdpt_physmap: [*]volatile u64 = @ptrFromInt(@as(usize, @intCast(PAGE_TABLES_ADDR + 0x2000)));
    const pdpt_high: [*]volatile u64 = @ptrFromInt(@as(usize, @intCast(PAGE_TABLES_ADDR + 0x3000)));

    // Zero PML4 + 3 PDPTs (4 pages).
    for (0..4 * 512) |i| pml4[i] = 0;

    // PML4[0] → pdpt_low (USER bit on so per-process inheritance still
    // works for the lazy-fault paths during early boot).
    pml4[0] = (PAGE_TABLES_ADDR + 0x1000) | 0x07; // Present + RW + USER

    // PML4[256] → pdpt_physmap (kernel-only).
    pml4[256] = (PAGE_TABLES_ADDR + 0x2000) | 0x03; // Present + RW (no USER)

    // PML4[511] → pdpt_high (kernel-only — kernel image at -2GB).
    pml4[511] = (PAGE_TABLES_ADDR + 0x3000) | 0x03; // Present + RW (no USER)

    // pdpt_low[0..63] → 1GB identity-mapped huge pages, USER on.
    for (0..64) |i| {
        pdpt_low[i] = @as(u64, i) * 0x40000000 | 0x87; // P + RW + USER + PS(1GB)
    }

    // pdpt_physmap[0..511] → 1GB pages identity-mapped within the PML4[256]
    // window, supervisor only. Fills the full 512 GB PML4 slot so any phys
    // address up to the architecture limit (maxphyaddr ≤ 39 bits = 512 GB on
    // current Hyper-V/KVM hosts) is reachable via paging.physToVirt(p).
    // Must match memmap.PHYSMAP_SIZE and src/boot/boot.asm fill loop.
    for (0..512) |i| {
        pdpt_physmap[i] = @as(u64, i) * 0x40000000 | 0x83; // P + RW + PS(1GB), no USER
    }

    // pdpt_high[510] = phys 0..1GB at VA 0xFFFFFFFF80000000.
    // Kernel image (linker.ld places it here) lives in this window.
    // Slot index: (0xFFFFFFFF80000000 >> 30) & 0x1FF = 510.
    pdpt_high[510] = 0x83; // P + RW + PS(1GB) at phys 0, supervisor only

    // Load new page tables
    asm volatile ("movq %[val], %%cr3"
        :
        : [val] "r" (PAGE_TABLES_ADDR),
    );
    serialPrint("[uefi] Page tables loaded\n");

    // --- 6. Set up GDT ---
    // Same layout as boot.asm: null, kcode64, kdata, ucode64, udata
    const gdt_base: [*]volatile u64 = @ptrFromInt(@as(usize, @intCast(PAGE_TABLES_ADDR - 0x100))); // Just before page tables
    gdt_base[0] = 0; // null
    gdt_base[1] = 0x00AF9A000000FFFF; // kernel code: L=1, D=0, DPL=0, type=0xA (exec/read)
    gdt_base[2] = 0x00CF92000000FFFF; // kernel data: DPL=0
    gdt_base[3] = 0x00AFFA000000FFFF; // user code: L=1, D=0, DPL=3
    gdt_base[4] = 0x00CFF2000000FFFF; // user data: DPL=3

    // GDT descriptor (10 bytes: 2-byte limit + 8-byte base)
    const gdtr: [*]volatile u8 = @ptrFromInt(@as(usize, @intCast(PAGE_TABLES_ADDR - 0x110)));
    const gdt_limit: u16 = 5 * 8 - 1;
    const gdt_addr: u64 = @intFromPtr(gdt_base);
    gdtr[0] = @truncate(gdt_limit);
    gdtr[1] = @truncate(gdt_limit >> 8);
    for (0..8) |i| {
        gdtr[2 + i] = @truncate(gdt_addr >> @intCast(i * 8));
    }

    // Load GDT and reload CS via far return
    asm volatile (
        \\ lgdt (%[gdtr])
        \\ pushq $0x08
        \\ leaq 1f(%%rip), %%rax
        \\ pushq %%rax
        \\ lretq
        \\ 1:
        \\ movw $0x10, %%ax
        \\ movw %%ax, %%ds
        \\ movw %%ax, %%es
        \\ movw %%ax, %%fs
        \\ movw %%ax, %%gs
        \\ movw %%ax, %%ss
        :
        : [gdtr] "r" (@as(usize, @intFromPtr(gdtr))),
        : .{ .rax = true }
    );
    serialPrint("[uefi] GDT loaded\n");

    // --- 7. Build BootInfo struct ---
    const boot_info: *volatile BootInfo = @ptrFromInt(@as(usize, @intCast(BOOT_INFO_ADDR)));
    boot_info.memory_map = regions;
    boot_info.memory_map_count = region_count;
    boot_info.has_framebuffer = has_fb;
    boot_info.framebuffer = fb_info;
    boot_info.pml4_phys = PAGE_TABLES_ADDR;
    boot_info.rsdp_addr = rsdp_addr;
    boot_info.boot_mode = boot_mode;
    boot_info._reserved = 0;
    boot_info.runtime_services_addr = @intFromPtr(runtime_services);
    // Phase 4: stamp our own build_id so kernel can check it matches its
    // own. Both come from the same build_options module; if they diverge
    // it means kernel.elf and BOOTX64.efi came from different `zig build`
    // invocations.
    const build_options = @import("build_options");
    boot_info.bootloader_build_id = build_options.build_id;
    // Phase 3: cmdline is opaque to the bootloader — just pass it through.
    boot_info.cmdline_len = @intCast(cmdline_len);
    if (cmdline_len > 0) {
        const n = @min(cmdline_len, boot_info.cmdline.len);
        var ci: usize = 0;
        while (ci < n) : (ci += 1) boot_info.cmdline[ci] = cmdline_buf[ci];
    }
    boot_info._reserved2 = 0;

    // --- 8. Jump to kernel ---
    serialPrint("[uefi] Jumping to kernel at ");
    serialHex(kernel_entry);
    serialPut('\n');

    // Set stack and call kmain_uefi(boot_info)
    const entry_fn: *const fn (*const BootInfo) callconv(.c) noreturn = @ptrFromInt(@as(usize, @intCast(kernel_entry)));
    asm volatile (
        \\ movq %[stack], %%rsp
        \\ movq %[arg], %%rdi
        \\ callq *%[entry]
        :
        : [stack] "r" (BOOT_STACK_TOP),
          [arg] "r" (@as(u64, BOOT_INFO_ADDR)),
          [entry] "r" (@as(u64, @intFromPtr(entry_fn))),
        : .{ .rsp = true, .rdi = true }
    );

    unreachable;
}
