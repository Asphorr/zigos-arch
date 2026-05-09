const serial = @import("serial.zig");
const debug = @import("debug.zig");
const heap = @import("../mm/heap.zig");
const slab = @import("../mm/slab.zig");
const vfs = @import("../fs/vfs.zig");
const vga = @import("../ui/vga.zig");

// Slab cache for the small SymTable header struct. Variable-size entries[]
// and names[] still go through kmalloc — slab can only handle fixed sizes.
var symtab_cache: ?*slab.Cache = null;

pub fn init() void {
    symtab_cache = slab.createCache("symtab", @sizeOf(SymTable), @alignOf(SymTable));
}

// --- Data structures ---

pub const SymEntry = struct {
    addr: u64,
    size: u64,
    name_off: u32,
};

pub const SymTable = struct {
    entries: [*]SymEntry,
    count: u32,
    names: [*]const u8,
    names_len: u32,
};

pub const ResolveResult = struct {
    name: []const u8,
    offset: u64,
};

const MAX_APP_SYMBOLS: u32 = 4096; // 32B per entry → 128KB max — way more than any real ELF
const MAX_NAME_POOL: u32 = 256 * 1024; // 256KB name pool — fits long mangled C++/Zig names

// ELF64 structures for section header parsing
const SHT_SYMTAB: u32 = 2;
const STT_FUNC: u8 = 2;

const SectionHeader = extern struct {
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

const ElfHeader = extern struct {
    ident: [16]u8,
    e_type: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
};

// --- Kernel symbol table (loaded from kernel.sym on disk) ---

var kernel_table: ?SymTable = null;

// --- Binary format for kernel.sym ---
// u32 magic (0x53594D42)
// u32 entry_count
// u32 name_pool_size
// [entry_count] x SymEntry { u64 addr, u64 size, u32 name_off }
// [name_pool_size] bytes of null-terminated strings

const SYM_MAGIC: u32 = 0x53594D42; // "SYMB"

/// Load kernel symbols from kernel.sym on FAT32 disk
pub fn loadKernelSymbols() void {
    // Use loadFileFresh so the disk DMA writes to a PMM-allocated buffer
    // outside the kernel image — never to a fixed BSS-aliased VA. Parse,
    // copy what we keep into the heap, then free the buffer.
    const fresh = vfs.loadFileFresh("KERNEL.SYM") orelse {
        debug.klog("[sym] kernel.sym not found on disk\n", .{});
        return;
    };
    const staging: [*]const u8 = fresh.buf;
    const file_size = fresh.size;
    defer {
        // fresh.buf is a kernel-side physmap VA (from vfs.loadFileFresh's
        // physToVirt). PMM expects physical addresses, so translate back.
        const paging = @import("../mm/paging.zig");
        const phys_base = paging.virtToPhys(@intFromPtr(fresh.buf)).?;
        for (0..fresh.pages) |p| @import("../mm/pmm.zig").freeFrame(phys_base + p * 4096);
    }

    if (file_size < 12) {
        debug.klog("[sym] kernel.sym too small ({d} bytes)\n", .{file_size});
        return;
    }

    // Parse header
    const header_ptr: [*]const u32 = @ptrCast(@alignCast(staging));
    const magic = header_ptr[0];
    const entry_count = header_ptr[1];
    const name_pool_size = header_ptr[2];

    if (magic != SYM_MAGIC) {
        debug.klog("[sym] Bad magic: 0x{X:0>8}\n", .{magic});
        return;
    }

    const entries_size = entry_count * @sizeOf(SymEntry);
    const expected_size = 12 + entries_size + name_pool_size;
    if (file_size < expected_size) {
        debug.klog("[sym] File too small: {d} < {d}\n", .{ file_size, expected_size });
        return;
    }

    // Allocate entries array (8-byte aligned for u64 fields)
    const entries_buf = heap.kmallocAligned(entries_size, 8) orelse {
        debug.klog("[sym] Failed to allocate {d} bytes for entries\n", .{entries_size});
        return;
    };
    const entries: [*]SymEntry = @ptrCast(@alignCast(entries_buf));

    // Copy entries from staging buffer
    const src_entries = staging + 12;
    @memcpy(entries_buf[0..entries_size], src_entries[0..entries_size]);

    // Allocate and copy name pool
    const names_buf = heap.kmalloc(name_pool_size) orelse {
        heap.kfree(entries_buf);
        debug.klog("[sym] Failed to allocate {d} bytes for names\n", .{name_pool_size});
        return;
    };
    const src_names = staging + 12 + entries_size;
    @memcpy(names_buf[0..name_pool_size], src_names[0..name_pool_size]);

    kernel_table = .{
        .entries = entries,
        .count = entry_count,
        .names = names_buf,
        .names_len = name_pool_size,
    };

    debug.klog("[sym] Loaded {d} kernel symbols ({d} bytes names)\n", .{ entry_count, name_pool_size });
}

/// Resolve a kernel address to function name + offset
pub fn resolveKernel(addr: u64) ?ResolveResult {
    const table = kernel_table orelse return null;
    return resolve(&table, addr);
}

/// Resolve a user address using a per-process symbol table
pub fn resolveUser(table: *const SymTable, addr: u64) ?ResolveResult {
    return resolve(table, addr);
}

/// Binary search: find the largest entry.addr <= target. Returns the result
// only if `addr` is actually inside the symbol's range (using `entry.size` if
// known, else the next symbol's address as upper bound). Returns null when
// `addr` falls in a gap between known symbols — saves us from confidently
// printing wrong labels.
fn resolve(table: *const SymTable, addr: u64) ?ResolveResult {
    if (table.count == 0) return null;

    const entries = table.entries[0..table.count];

    // Binary search for largest entry where entry.addr <= addr
    var lo: u32 = 0;
    var hi: u32 = table.count;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (entries[mid].addr <= addr) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    if (lo == 0) return null;
    const idx = lo - 1;
    const entry = entries[idx];

    // Effective end: trust `entry.size` when present, else fall back to the
    // next symbol's start, else cap at +64KB as a sane outer bound.
    const effective_end: u64 = if (entry.size > 0)
        entry.addr + entry.size
    else if (idx + 1 < table.count)
        entries[idx + 1].addr
    else
        entry.addr + 0x10000;

    if (addr >= effective_end) return null;

    const name = getName(table, entry.name_off);
    return .{
        .name = name,
        .offset = addr - entry.addr,
    };
}

/// Extract null-terminated string from name pool
fn getName(table: *const SymTable, off: u32) []const u8 {
    if (off >= table.names_len) return "???";
    const start = table.names + off;
    const remaining = table.names_len - off;
    var end: u32 = 0;
    while (end < remaining and start[end] != 0) : (end += 1) {}
    return start[0..end];
}

// --- ELF64 section header parsing for app symbols ---

/// Parse symbol table from an ELF64 file in memory (staging buffer)
pub fn parseElfSymbols(file_buf: [*]const u8, file_size: usize) ?*SymTable {
    if (file_size < @sizeOf(ElfHeader)) return null;

    const hdr: *align(1) const ElfHeader = @ptrCast(file_buf);

    // Validate ELF64
    if (hdr.ident[0] != 0x7F or hdr.ident[1] != 'E' or hdr.ident[2] != 'L' or hdr.ident[3] != 'F') return null;
    if (hdr.ident[4] != 2) return null; // Must be ELF64

    if (hdr.shnum == 0 or hdr.shoff == 0) return null;

    const shoff: usize = @intCast(hdr.shoff);
    const shentsize: usize = @intCast(hdr.shentsize);
    const shnum: usize = @intCast(hdr.shnum);

    if (shoff + shnum * shentsize > file_size) return null;

    // Find .symtab section
    var symtab_shdr: ?*align(1) const SectionHeader = null;
    for (0..shnum) |i| {
        const sh: *align(1) const SectionHeader = @ptrCast(file_buf + shoff + i * shentsize);
        if (sh.sh_type == SHT_SYMTAB) {
            symtab_shdr = sh;
            break;
        }
    }

    const symtab = symtab_shdr orelse return null;

    // Get linked .strtab
    const strtab_idx: usize = @intCast(symtab.sh_link);
    if (strtab_idx >= shnum) return null;
    const strtab_sh: *align(1) const SectionHeader = @ptrCast(file_buf + shoff + strtab_idx * shentsize);

    const sym_offset: usize = @intCast(symtab.sh_offset);
    const sym_size: usize = @intCast(symtab.sh_size);
    const sym_entsize: usize = @intCast(symtab.sh_entsize);
    if (sym_entsize == 0) return null;
    const sym_count = sym_size / sym_entsize;

    const str_offset: usize = @intCast(strtab_sh.sh_offset);
    const str_size: usize = @intCast(strtab_sh.sh_size);

    if (sym_offset + sym_size > file_size) return null;
    if (str_offset + str_size > file_size) return null;

    const strtab_ptr = file_buf + str_offset;

    // First pass: count function symbols
    var func_count: u32 = 0;
    var total_name_bytes: u32 = 0;
    for (0..sym_count) |i| {
        const sym: *align(1) const Elf64Sym = @ptrCast(file_buf + sym_offset + i * sym_entsize);
        if ((sym.st_info & 0xF) == STT_FUNC and sym.st_value != 0) {
            func_count += 1;
            // Calculate name length
            const name_start: usize = @intCast(sym.st_name);
            if (name_start < str_size) {
                var name_len: u32 = 0;
                while (name_start + name_len < str_size and strtab_ptr[name_start + name_len] != 0) : (name_len += 1) {
                    if (name_len >= 63) break; // truncate long names
                }
                total_name_bytes += name_len + 1; // +1 for null terminator
            }
            if (func_count >= MAX_APP_SYMBOLS) break;
        }
    }

    if (func_count == 0) return null;
    if (total_name_bytes > MAX_NAME_POOL) total_name_bytes = MAX_NAME_POOL;

    // Allocate SymTable struct + entries + names. The header lives in the
    // symtab slab cache (fixed size, per-process churn shows up in slab stats);
    // entries and names are variable-size and still go through kmalloc.
    const cache = symtab_cache orelse return null;
    const table_buf = slab.alloc(cache) orelse return null;
    const table: *SymTable = @ptrCast(@alignCast(table_buf));

    const entries_size = func_count * @sizeOf(SymEntry);
    const entries_buf = heap.kmallocAligned(entries_size, 8) orelse {
        slab.free(cache, table_buf);
        return null;
    };
    const entries: [*]SymEntry = @ptrCast(@alignCast(entries_buf));

    const names_buf = heap.kmalloc(total_name_bytes) orelse {
        heap.kfree(entries_buf);
        slab.free(cache, table_buf);
        return null;
    };

    // Second pass: populate entries and names
    var idx: u32 = 0;
    var name_off: u32 = 0;
    for (0..sym_count) |i| {
        const sym: *align(1) const Elf64Sym = @ptrCast(file_buf + sym_offset + i * sym_entsize);
        if ((sym.st_info & 0xF) == STT_FUNC and sym.st_value != 0) {
            if (idx >= func_count) break;

            entries[idx] = .{
                .addr = sym.st_value,
                .size = sym.st_size,
                .name_off = name_off,
            };

            // Copy name
            const name_start: usize = @intCast(sym.st_name);
            if (name_start < str_size and name_off < total_name_bytes) {
                var name_len: u32 = 0;
                while (name_start + name_len < str_size and strtab_ptr[name_start + name_len] != 0 and name_off + name_len < total_name_bytes - 1) : (name_len += 1) {
                    if (name_len >= 63) break;
                    names_buf[name_off + name_len] = strtab_ptr[name_start + name_len];
                }
                names_buf[name_off + name_len] = 0;
                name_off += name_len + 1;
            }

            idx += 1;
        }
    }

    // Sort entries by address (insertion sort — small arrays)
    for (1..idx) |ii| {
        const i: u32 = @intCast(ii);
        const key = entries[i];
        var j: i32 = @as(i32, @intCast(i)) - 1;
        while (j >= 0 and entries[@intCast(j)].addr > key.addr) : (j -= 1) {
            entries[@as(u32, @intCast(j + 1))] = entries[@intCast(j)];
        }
        entries[@as(u32, @intCast(j + 1))] = key;
    }

    table.* = .{
        .entries = entries,
        .count = idx,
        .names = names_buf,
        .names_len = name_off,
    };

    debug.klog("[sym] Loaded {d} app symbols\n", .{idx});
    return table;
}

/// Free a heap-allocated symbol table
pub fn freeSymTable(table: *SymTable) void {
    heap.kfree(@ptrCast(table.entries));
    heap.kfree(@ptrCast(@constCast(table.names)));
    if (symtab_cache) |cache| {
        slab.free(cache, @ptrCast(table));
    } else {
        heap.kfree(@ptrCast(table));
    }
}

// --- Backtrace printing with symbol resolution ---

/// Print a symbolicated backtrace to serial (and optionally VGA)
pub fn printBacktrace(initial_rbp: usize, rip: u64, is_kernel: bool, app_table: ?*const SymTable) void {
    // Print RIP first
    printResolvedAddr(rip, is_kernel, app_table, "  RIP");

    // Walk RBP chain
    var rbp = initial_rbp;
    var depth: u32 = 0;
    const range_lo: usize = if (is_kernel) 0x100000 else 0x400000;
    const range_hi: usize = if (is_kernel) 0x4000000 else 0x600000;

    while (rbp > range_lo and rbp < range_hi and depth < 16) : (depth += 1) {
        const frame: [*]const usize = @ptrFromInt(rbp);
        const ret_addr: u64 = @intCast(frame[1]);
        printResolvedAddr(ret_addr, is_kernel, app_table, null);
        rbp = frame[0];
    }
}

fn printResolvedAddr(addr: u64, is_kernel: bool, app_table: ?*const SymTable, label: ?[]const u8) void {
    const result = if (is_kernel)
        resolveKernel(addr)
    else if (app_table) |t|
        resolveUser(t, addr)
    else
        null;

    if (label) |l| {
        serial.print("  {s}: ", .{l});
    } else {
        serial.print("    ", .{});
    }

    if (result) |r| {
        serial.print("{s}+0x{X} (0x{X:0>16})\n", .{ r.name, r.offset, addr });
    } else {
        serial.print("0x{X:0>16}\n", .{addr});
    }
}

// --- CLI helpers ---

/// List symbols from a table (for CLI `symbols` command)
pub fn listSymbols(table: *const SymTable, filter: ?[]const u8, use_vga: bool) void {
    var shown: u32 = 0;
    for (0..table.count) |i| {
        const entry = table.entries[i];
        const name = getName(table, entry.name_off);

        // Apply filter if provided
        if (filter) |f| {
            if (!contains(name, f)) continue;
        }

        if (use_vga) {
            vga.fg = .LightGreen;
            vga.print("  0x{X:0>16}", .{entry.addr});
            vga.fg = .DarkGray;
            vga.print(" [{d:>6}] ", .{entry.size});
            vga.fg = .White;
            vga.print("{s}\n", .{name});
        } else {
            serial.print("  0x{X:0>16} [{d:>6}] {s}\n", .{ entry.addr, entry.size, name });
        }

        shown += 1;
        if (shown >= 50) {
            if (use_vga) {
                vga.fg = .DarkGray;
                vga.print("  ... ({d} more)\n", .{table.count - shown});
            }
            break;
        }
    }

    if (use_vga) {
        vga.fg = .DarkGray;
        vga.print("  Total: {d} symbols\n", .{table.count});
        vga.fg = .LightGray;
    }
}

/// List kernel symbols
pub fn listKernelSymbols(filter: ?[]const u8, use_vga: bool) void {
    if (kernel_table) |*table| {
        listSymbols(table, filter, use_vga);
    } else {
        if (use_vga) {
            vga.fg = .LightRed;
            vga.print("  No kernel symbols loaded\n", .{});
            vga.fg = .LightGray;
        }
    }
}

/// Simple substring search
fn contains(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    for (0..haystack.len - needle.len + 1) |i| {
        if (std.mem.eql(u8, haystack[i..][0..needle.len], needle)) return true;
    }
    return false;
}

const std = @import("std");
