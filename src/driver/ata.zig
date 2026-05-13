const io = @import("../io.zig");
const pci = @import("pci.zig");
const pmm = @import("../mm/pmm.zig");
const debug = @import("../debug/debug.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;

var ata_lock: SpinLock = .{};

pub fn acquireLock() void {
    ata_lock.acquire();
}

pub fn releaseLock() void {
    ata_lock.release();
}

const PRIMARY_PORT: u16 = 0x1F0;
const SECONDARY_PORT: u16 = 0x170;
const PRIMARY_CTRL: u16 = 0x3F6;
const SECONDARY_CTRL: u16 = 0x376;

// === DMA state ===

const PRDT = extern struct {
    phys_addr: u32,
    byte_count: u16, // 0 = 64KB
    flags: u16, // bit 15 = EOT
};

var bmide_base: u16 = 0; // BAR4 I/O port base
var prdt_phys: u32 = 0; // Physical address of PRDT page
var prdt_ptr: ?[*]volatile PRDT = null;
var dma_available: bool = false;

// === Read-ahead cache ===
const READAHEAD_SECTORS = 8; // Prefetch 8 sectors (4KB)
var readahead_cache: [READAHEAD_SECTORS * 512]u8 = undefined;
var readahead_start_lba: u32 = 0xFFFFFFFF; // Invalid LBA initially
var readahead_valid: bool = false;

/// Initialize ATA DMA by finding the IDE PCI controller and setting up BMIDE.
pub fn initDMA() void {
    const boot_info_mod = @import("../boot/boot_info.zig");
    const tag: []const u8 = if (boot_info_mod.is_uefi) "uefi" else "mb";

    // Try common IDE PCI prog_if values
    const ide_dev = pci.findByClass(0x01, 0x01, 0x80) orelse
        pci.findByClass(0x01, 0x01, 0x8A) orelse
        pci.findByClass(0x01, 0x01, 0x00) orelse {
        debug.klog("[ata/{s}] No IDE PCI controller found, DMA disabled\n", .{tag});
        return;
    };
    debug.klog("[ata/{s}] IDE PCI: {d}:{d}.{d} prog_if=0x{X:0>2}\n", .{
        tag, ide_dev.bus, ide_dev.dev, ide_dev.func, ide_dev.prog_if,
    });

    // Read BAR4 (BMIDE base) — offset 0x20 in PCI config
    const bar4_raw = pci.configRead(ide_dev.bus, ide_dev.dev, ide_dev.func, 0x20);
    debug.klog("[ata/{s}] BAR4 raw=0x{X:0>8}\n", .{ tag, bar4_raw });
    if (bar4_raw & 1 == 0) {
        debug.klog("[ata/{s}] BAR4 is not I/O space, DMA disabled\n", .{tag});
        return;
    }
    bmide_base = @truncate(bar4_raw & 0xFFFC);
    if (bmide_base == 0) {
        debug.klog("[ata/{s}] BAR4 is zero, DMA disabled\n", .{tag});
        return;
    }

    // Enable bus mastering + I/O space + SERR
    const cmd_before = pci.configRead16(ide_dev.bus, ide_dev.dev, ide_dev.func, 0x04);
    var cmd16 = cmd_before;
    cmd16 |= 0x0107; // I/O + Memory + BusMaster + SERR
    pci.configWrite16(ide_dev.bus, ide_dev.dev, ide_dev.func, 0x04, cmd16);
    const cmd_after = pci.configRead16(ide_dev.bus, ide_dev.dev, ide_dev.func, 0x04);
    debug.klog("[ata/{s}] CMD: before=0x{X:0>4} after=0x{X:0>4}\n", .{ tag, cmd_before, cmd_after });

    // Fix IRQ if OVMF left it unconfigured (0xFF)
    const irq_reg = pci.configRead(ide_dev.bus, ide_dev.dev, ide_dev.func, 0x3C);
    if ((irq_reg & 0xFF) == 0xFF) {
        pci.configWrite(ide_dev.bus, ide_dev.dev, ide_dev.func, 0x3C, (irq_reg & 0xFFFFFF00) | 14);
    }

    // Allocate a page for PRDT (must be below 4GB, physically contiguous)
    const prdt_page = pmm.allocContiguousBelow4G(1) orelse {
        debug.klog("[ata/{s}] Failed to allocate PRDT page\n", .{tag});
        return;
    };
    prdt_phys = @intCast(prdt_page);
    // Kernel access through the physmap; the device sees prdt_phys itself.
    prdt_ptr = @ptrFromInt(@import("../mm/paging.zig").physToVirt(prdt_page));

    // Reset BMIDE state (OVMF may leave stale bits)
    const bm_pri_status = io.inb(bmide_base + 2);
    const bm_sec_status = io.inb(bmide_base + 10);
    debug.klog("[ata/{s}] BMIDE pre-reset: pri_status=0x{X:0>2} sec_status=0x{X:0>2}\n", .{
        tag, bm_pri_status, bm_sec_status,
    });
    io.outb(bmide_base, 0x00); // stop primary
    io.outb(bmide_base + 2, 0x06); // clear primary interrupt+error
    io.outb(bmide_base + 8, 0x00); // stop secondary
    io.outb(bmide_base + 10, 0x06); // clear secondary interrupt+error

    // Software reset both IDE channels via SRST in device control register.
    // OVMF can leave the IDE controller in a state where the drive doesn't
    // ACK READ DMA commands; SRST forces a clean state.
    io.outb(PRIMARY_CTRL, 0x04); // SRST set on primary
    io.outb(SECONDARY_CTRL, 0x04); // SRST set on secondary
    // ~5us delay via 4 status reads (each ~1us on legacy IDE)
    inline for (0..4) |_| _ = io.inb(PRIMARY_CTRL);
    io.outb(PRIMARY_CTRL, 0x00); // Clear SRST
    io.outb(SECONDARY_CTRL, 0x00);
    // Wait for drives to clear BSY (up to ~500ms — generous for spinning rust)
    var settle: u32 = 0;
    while (settle < 1_000_000) : (settle += 1) {
        const pri_busy = io.inb(PRIMARY_PORT + 7) & 0x80;
        const sec_busy = io.inb(SECONDARY_PORT + 7) & 0x80;
        if (pri_busy == 0 and sec_busy == 0) break;
    }
    debug.klog("[ata/{s}] Post-SRST: settled after {d} reads\n", .{ tag, settle });

    // Functional DMA test: try a single-sector DMA read and check if it completes
    if (testDmaRead(SECONDARY_PORT, 0xE0, bmide_base + 0x08)) {
        dma_available = true;
        debug.klog("[ata/{s}] DMA initialized: BMIDE=0x{X:0>4} PRDT=0x{X:0>8}\n", .{
            tag, bmide_base, prdt_phys,
        });
    } else {
        dma_available = false;
        const final_status = io.inb(bmide_base + 10);
        debug.klog("[ata/{s}] DMA test failed: BMIDE=0x{X:0>4} sec_status=0x{X:0>2}, using PIO\n", .{
            tag, bmide_base, final_status,
        });
    }
}

/// Test if DMA actually works by reading sector 0 into the PRDT page itself.
fn testDmaRead(port: u16, drive_head: u8, bm_base: u16) bool {
    const prdt = prdt_ptr orelse return false;

    // Use the second half of the PRDT page as a test buffer
    const test_buf_phys: u32 = prdt_phys + 2048;

    // Set up PRDT: read 1 sector (512 bytes) into test buffer
    prdt[0] = .{
        .phys_addr = test_buf_phys,
        .byte_count = 512,
        .flags = 0x8000, // EOT
    };

    // Stop + clear
    io.outb(bm_base, 0x00);
    io.outb(bm_base + 2, io.inb(bm_base + 2) | 0x06);

    // Set PRDT address
    io.outl(bm_base + 4, prdt_phys);

    // Read direction
    io.outb(bm_base, 0x08);

    // Send READ DMA for LBA 0, count 1
    _ = waitBsy(port);
    io.outb(port + 6, drive_head);
    io.outb(port + 2, 1); // 1 sector
    io.outb(port + 3, 0); // LBA 0
    io.outb(port + 4, 0);
    io.outb(port + 5, 0);
    io.outb(port + 7, 0xC8); // READ DMA

    // Start DMA
    io.outb(bm_base, 0x09);

    // Poll with short timeout
    var timeout: u32 = 100_000;
    while (timeout > 0) : (timeout -= 1) {
        const status = io.inb(bm_base + 2);
        if (status & 0x02 != 0) {
            // Error
            debug.klog("[ata] DMA test: error status=0x{X:0>2} after {d} polls\n", .{
                status, 100_000 - timeout,
            });
            io.outb(bm_base, 0x00);
            io.outb(bm_base + 2, 0x06);
            return false;
        }
        if (status & 0x04 != 0) {
            // Success — DMA completed
            debug.klog("[ata] DMA test: success after {d} polls (status=0x{X:0>2})\n", .{
                100_000 - timeout, status,
            });
            io.outb(bm_base, 0x00);
            io.outb(bm_base + 2, io.inb(bm_base + 2) | 0x06);
            return true;
        }
    }

    // Timeout — DMA didn't complete
    const final_status = io.inb(bm_base + 2);
    debug.klog("[ata] DMA test: timeout, final status=0x{X:0>2}\n", .{final_status});
    io.outb(bm_base, 0x00);
    io.outb(bm_base + 2, 0x06);
    return false;
}

// === Public API ===

// --- Primary ATA (0x1F0) — used for tarfs ---

pub fn readSector(lba: u32, dest: [*]u8) void {
    ata_lock.acquire();
    defer ata_lock.release();
    readSectorPort(PRIMARY_PORT, 0xE0, lba, dest);
}

// --- Secondary ATA (0x170) — used for FAT32 disk ---

pub fn readSectorSecondary(lba: u32, dest: [*]u8) void {
    ata_lock.acquire();
    defer ata_lock.release();

    // Check if sector is in read-ahead cache
    if (readahead_valid and lba >= readahead_start_lba and lba < readahead_start_lba + READAHEAD_SECTORS) {
        const offset = (lba - readahead_start_lba) * 512;
        @memcpy(dest[0..512], readahead_cache[offset..][0..512]);
        return;
    }

    // Cache miss - read sector and prefetch next sectors
    readSectorPort(SECONDARY_PORT, 0xE0, lba, dest);

    // Prefetch next READAHEAD_SECTORS sectors into cache
    if (dma_available) {
        readSectorsDMA(SECONDARY_PORT, 0xE0, lba, READAHEAD_SECTORS, &readahead_cache, bmide_base + 0x08);
    } else {
        readSectorsPort(SECONDARY_PORT, 0xE0, lba, READAHEAD_SECTORS, &readahead_cache);
    }
    readahead_start_lba = lba;
    readahead_valid = true;
}

/// Read multiple contiguous sectors. Uses DMA if available, falls back to PIO.
/// Lock-acquired because PRDT + BMIDE registers are SHARED across both ATA
/// channels — without the lock, two CPUs reading concurrently race on PRDT
/// setup and produce garbage ELF buffers (`Invalid ELF64 header` on every
/// `cat foo | wc`-style pipeline where AP and BSP both touch ATA).
pub fn readSectorsSecondary(lba: u32, count: u8, dest: [*]u8) void {
    ata_lock.acquire();
    defer ata_lock.release();
    if (dma_available and count >= 2) {
        readSectorsDMA(SECONDARY_PORT, 0xE0, lba, count, dest, bmide_base + 0x08);
    } else {
        readSectorsPort(SECONDARY_PORT, 0xE0, lba, count, dest);
    }
}

pub fn readSectors(lba: u32, count: u8, dest: [*]u8) void {
    ata_lock.acquire();
    defer ata_lock.release();
    if (dma_available and count >= 2) {
        readSectorsDMA(PRIMARY_PORT, 0xE0, lba, count, dest, bmide_base);
    } else {
        readSectorsPort(PRIMARY_PORT, 0xE0, lba, count, dest);
    }
}

pub fn writeSectorSecondary(lba: u32, src: [*]const u8) void {
    ata_lock.acquire();
    defer ata_lock.release();
    writeSectorPort(SECONDARY_PORT, 0xE0, lba, src);
}

// === DMA read ===

// Aggregate counters for DMA performance investigation. Every readSectorsDMA
// call updates them; serial-spam cost is one print per load.
pub var dma_call_count: u64 = 0;
pub var dma_total_cycles: u64 = 0;
pub var dma_total_polls: u64 = 0;
pub var dma_total_sectors: u64 = 0;
pub var dma_max_cycles_per_call: u64 = 0;
pub var dma_max_polls_per_call: u64 = 0;
pub var dma_timeouts: u64 = 0;

pub fn resetDmaStats() void {
    dma_call_count = 0;
    dma_total_cycles = 0;
    dma_total_polls = 0;
    dma_total_sectors = 0;
    dma_max_cycles_per_call = 0;
    dma_max_polls_per_call = 0;
    dma_timeouts = 0;
}

fn readSectorsDMA(port: u16, drive_head: u8, lba: u32, count: u8, dest: [*]u8, bm_base: u16) void {
    const prdt = prdt_ptr orelse {
        readSectorsPort(port, drive_head, lba, count, dest);
        return;
    };
    const n: u32 = if (count == 0) 256 else @as(u32, count);
    const byte_count: u32 = n * 512;

    // Dest must be a 32-bit physical address for the BMIDE PRDT. Higher-half
    // kernel: a kernel-BSS pointer (e.g., readahead_cache) comes in as a
    // high VA; translate to LMA before truncating. virtToPhys handles both
    // high-half and low-identity inputs.
    const dest_phys: u32 = @intCast(@import("../mm/paging.zig").virtToPhys(@intFromPtr(dest)).?);

    // Set up PRDT: single entry pointing to dest buffer
    prdt[0] = .{
        .phys_addr = dest_phys,
        .byte_count = if (byte_count >= 0x10000) 0 else @intCast(byte_count),
        .flags = 0x8000, // EOT
    };

    const t_start = @import("../debug/perf.zig").rdtsc();

    // 1. Stop any previous DMA + clear status
    io.outb(bm_base, 0x00); // stop
    io.outb(bm_base + 2, io.inb(bm_base + 2) | 0x06); // clear interrupt + error

    // 2. Set PRDT address
    io.outl(bm_base + 4, prdt_phys);

    // 3. Set read direction (bit 3 = 0 for read)
    io.outb(bm_base, 0x08); // read direction

    // 4. Select drive + send ATA READ DMA command
    io.outb(port + 6, drive_head | @as(u8, @truncate((lba >> 24) & 0x0F)));
    io.outb(port + 2, count);
    io.outb(port + 3, @as(u8, @truncate(lba)));
    io.outb(port + 4, @as(u8, @truncate(lba >> 8)));
    io.outb(port + 5, @as(u8, @truncate(lba >> 16)));
    io.outb(port + 7, 0xC8); // READ DMA

    // 5. Start DMA (set bit 0, keep bit 3 for read direction)
    io.outb(bm_base, 0x09); // start + read

    // 6. Poll for completion
    var timeout: u32 = 1_000_000;
    var polls: u32 = 0;
    while (timeout > 0) : (timeout -= 1) {
        const status = io.inb(bm_base + 2);
        polls += 1;
        if (status & 0x02 != 0) {
            // Error — fall back to PIO
            io.outb(bm_base, 0x00); // stop
            io.outb(bm_base + 2, 0x06); // clear
            const t_end = @import("../debug/perf.zig").rdtsc();
            dma_call_count += 1;
            dma_total_cycles +%= t_end -% t_start;
            dma_total_polls += polls;
            dma_total_sectors += n;
            readSectorsPort(port, drive_head, lba, count, dest);
            return;
        }
        if (status & 0x04 != 0) {
            // Interrupt — DMA complete
            break;
        }
    }

    // 7. Stop DMA + clear status
    io.outb(bm_base, 0x00);
    io.outb(bm_base + 2, io.inb(bm_base + 2) | 0x06);

    const t_end = @import("../debug/perf.zig").rdtsc();
    const dt = t_end -% t_start;
    dma_call_count += 1;
    dma_total_cycles +%= dt;
    dma_total_polls += polls;
    dma_total_sectors += n;
    if (dt > dma_max_cycles_per_call) dma_max_cycles_per_call = dt;
    if (polls > dma_max_polls_per_call) dma_max_polls_per_call = polls;

    // If timeout, fall back to PIO
    if (timeout == 0) {
        dma_timeouts += 1;
        readSectorsPort(port, drive_head, lba, count, dest);
    }
}

// === PIO operations (kept as fallback) ===

// 1M port reads ≈ ~1s on legacy IDE bus (each inb is ~1µs). Anything past
// that and the drive is presumed dead — return false so callers bail
// instead of wedging cpu1 until the watchdog (~3s).
const ATA_WAIT_LIMIT: u32 = 1_000_000;

fn waitReady(port: u16) bool {
    var n: u32 = ATA_WAIT_LIMIT;
    while (n > 0) : (n -= 1) {
        if ((io.inb(port + 7) & 0x80) == 0) break;
    }
    if (n == 0) return false;
    n = ATA_WAIT_LIMIT;
    while (n > 0) : (n -= 1) {
        if ((io.inb(port + 7) & 0x08) != 0) return true;
    }
    return false;
}

fn waitBsy(port: u16) bool {
    var n: u32 = ATA_WAIT_LIMIT;
    while (n > 0) : (n -= 1) {
        if ((io.inb(port + 7) & 0x80) == 0) return true;
    }
    return false;
}

fn readSectorPort(port: u16, drive_head: u8, lba: u32, dest: [*]u8) void {
    io.outb(port + 6, drive_head | @as(u8, @truncate((lba >> 24) & 0x0F)));
    io.outb(port + 2, 1);
    io.outb(port + 3, @as(u8, @truncate(lba)));
    io.outb(port + 4, @as(u8, @truncate(lba >> 8)));
    io.outb(port + 5, @as(u8, @truncate(lba >> 16)));
    io.outb(port + 7, 0x20); // READ SECTORS
    if (!waitReady(port)) {
        @memset(dest[0..512], 0);
        return;
    }
    const dest_u16: [*]align(1) u16 = @ptrCast(dest);
    for (0..256) |i| dest_u16[i] = io.inw(port);
}

fn readSectorsPort(port: u16, drive_head: u8, lba: u32, count: u8, dest: [*]u8) void {
    const n = if (count == 0) 256 else @as(u32, count);
    io.outb(port + 6, drive_head | @as(u8, @truncate((lba >> 24) & 0x0F)));
    io.outb(port + 2, count);
    io.outb(port + 3, @as(u8, @truncate(lba)));
    io.outb(port + 4, @as(u8, @truncate(lba >> 8)));
    io.outb(port + 5, @as(u8, @truncate(lba >> 16)));
    io.outb(port + 7, 0x20); // READ SECTORS
    const dest_u16: [*]align(1) u16 = @ptrCast(dest);
    for (0..n) |s| {
        const off = s * 256;
        if (!waitReady(port)) {
            // Zero the remainder so callers see consistent (empty) data
            // rather than uninitialized memory from the previous sector.
            @memset(dest[off * 2 .. n * 512], 0);
            return;
        }
        for (0..256) |i| dest_u16[off + i] = io.inw(port);
    }
}

fn writeSectorPort(port: u16, drive_head: u8, lba: u32, src: [*]const u8) void {
    io.outb(port + 6, drive_head | @as(u8, @truncate((lba >> 24) & 0x0F)));
    io.outb(port + 2, 1);
    io.outb(port + 3, @as(u8, @truncate(lba)));
    io.outb(port + 4, @as(u8, @truncate(lba >> 8)));
    io.outb(port + 5, @as(u8, @truncate(lba >> 16)));
    io.outb(port + 7, 0x30); // WRITE SECTORS
    if (!waitReady(port)) return;
    const src_u16: [*]align(1) const u16 = @ptrCast(src);
    for (0..256) |i| io.outb16(port, src_u16[i]);
    // Flush cache
    io.outb(port + 7, 0xE7);
    _ = waitBsy(port);
}
