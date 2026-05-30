// AHCI (Advanced Host Controller Interface) — modern SATA driver.
//
// Replaces the legacy IDE/ATA path on any post-~2008 motherboard. QEMU
// exposes the same controller with `-device ahci`. The same code runs
// on real hardware: AHCI is the standard programming model for every
// Intel/AMD chipset SATA controller in the last 15+ years.
//
// Reference: Intel "Serial ATA Advanced Host Controller Interface
// Specification" (rev 1.3.1). We use only the basic command-issue path:
// no NCQ, no port multiplier, no port reset state machine, no error
// recovery. Polled completion (no interrupts), one in-flight command per
// port at a time. Plenty for booting and reading/writing a disk.
//
// Surface mirrors ata.zig — readSector/readSectors/writeSector — split
// into "primary" and "secondary" addressing the first two ports with
// attached disks. block.zig dispatches between this and ata.zig.

const io = @import("../io.zig");
const pci = @import("pci.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const msix = @import("../time/msix.zig");
const debug = @import("../debug/debug.zig");

// PCI class for "AHCI 1.0 compliant" SATA controller.
const PCI_CLASS_STORAGE: u8 = 0x01;
const PCI_SUBCLASS_SATA: u8 = 0x06;
const PCI_PROGIF_AHCI: u8 = 0x01;

// --- HBA (host bus adapter) registers, offsets from ABAR (BAR5) ---
const HBA_CAP: u32 = 0x00;
const HBA_GHC: u32 = 0x04;
const HBA_IS: u32 = 0x08;
const HBA_PI: u32 = 0x0C;
const HBA_VS: u32 = 0x10;
const HBA_BOHC: u32 = 0x28;

const GHC_HR: u32 = 1 << 0; // HBA Reset
const GHC_IE: u32 = 1 << 1; // Interrupt Enable (we disable it; we poll)
const GHC_AE: u32 = 1 << 31; // AHCI Enable

const BOHC_BOS: u32 = 1 << 0; // BIOS Owned Semaphore
const BOHC_OOS: u32 = 1 << 1; // OS Owned Semaphore

// --- Per-port registers, offsets from (ABAR + 0x100 + port*0x80) ---
const PORT_CLB: u32 = 0x00;
const PORT_CLBU: u32 = 0x04;
const PORT_FB: u32 = 0x08;
const PORT_FBU: u32 = 0x0C;
const PORT_IS: u32 = 0x10;
const PORT_IE: u32 = 0x14;
const PORT_CMD: u32 = 0x18;
const PORT_TFD: u32 = 0x20;
const PORT_SIG: u32 = 0x24;
const PORT_SSTS: u32 = 0x28;
const PORT_SCTL: u32 = 0x2C;
const PORT_SERR: u32 = 0x30;
const PORT_CI: u32 = 0x38;

const CMD_ST: u32 = 1 << 0; // Start
const CMD_FRE: u32 = 1 << 4; // FIS Receive Enable
const CMD_FR: u32 = 1 << 14; // FIS Receive Running
const CMD_CR: u32 = 1 << 15; // Command List Running

const TFD_BSY: u32 = 1 << 7;
const TFD_DRQ: u32 = 1 << 3;
const TFD_ERR: u32 = 1 << 0;

const SSTS_DET_MASK: u32 = 0x0F;
const SSTS_DET_PRESENT: u32 = 0x03;

// SATA device signature in PORT_SIG.
const SIG_ATA: u32 = 0x00000101;

// FIS types we issue/expect.
const FIS_TYPE_REG_H2D: u8 = 0x27;

// ATA commands we use.
const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
const ATA_CMD_IDENTIFY: u8 = 0xEC;

// --- AHCI structures ---
//
// One "command header" per slot in the command list (32 slots per port).
// `prdtl` says how many PRDT entries the command table has; `ctba`
// points to the command table.
const CommandHeader = extern struct {
    flags: u16 align(1), // bits 0..4 = CFIS DWORD count, bit 6 = write
    prdtl: u16 align(1), // PRDT entry count
    prdbc: u32 align(1), // bytes transferred (HBA writes back here)
    ctba: u32 align(1), // command table base, low
    ctbau: u32 align(1), // command table base, high
    _rsv: [4]u32 align(1),
};

// A command table holds the FIS for one command, plus a PRDT (scatter-
// gather list of physical buffers). We only use 1 PRDT entry per
// command (single contiguous buffer), which is plenty for sector-sized
// I/O.
const PrdtEntry = extern struct {
    dba: u32 align(1), // data base address (low)
    dbau: u32 align(1), // data base address (high)
    _rsv: u32 align(1),
    dbc: u32 align(1), // byte count - 1, top bit = interrupt-on-completion
};

const CommandTable = extern struct {
    cfis: [64]u8 align(1), // command FIS
    acmd: [16]u8 align(1), // ATAPI command (unused for SATA)
    _rsv: [48]u8 align(1),
    prdt: [1]PrdtEntry align(1), // we use exactly one entry
};

const Port = struct {
    idx: u8,
    cmd_list_phys: usize, // 1 KB (32 entries × 32 bytes)
    fis_phys: usize, // 256 bytes
    cmd_table_phys: usize, // 256 bytes (CFIS + ATAPI + rsv + 1 PRDT)
    active: bool = false,
};

var hba_base: usize = 0;
var ports: [32]Port = undefined;
var primary_port: u8 = 0xFF;
var secondary_port: u8 = 0xFF;
var initialized: bool = false;
var use_msix: bool = false;
pub var irq_count: u64 = 0;

// Per-port lock — `issueCommand` shared the per-port CFIS/PRDT slot 0 between
// CPUs. Two reads on the same port from different CPUs scrambled each other's
// command table before the doorbell. Same bug class as ata.readSectors that
// produced "Invalid ELF64 header" on `cat foo | wc`.
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
var port_locks: [32]SpinLock = [_]SpinLock{.{}} ** 32;

/// AHCI MSI-X handler: ack the HBA-level interrupt status and per-port
/// interrupt status (both write-1-to-clear), then bump a counter. The
/// real wait happens in `issueCommand`, where `sti; hlt` blocks until
/// either this handler fires or the LAPIC timer ticks.
fn ahciIrqHandler() callconv(.c) void {
    irq_count +%= 1;
    const is = hbaRead(HBA_IS);
    if (is == 0) return;
    var p: u8 = 0;
    while (p < 32) : (p += 1) {
        if ((is >> @intCast(p)) & 1 == 0) continue;
        const pis = portRead(p, PORT_IS);
        portWrite(p, PORT_IS, pis); // W1C
    }
    hbaWrite(HBA_IS, is); // W1C at HBA level
}

fn hbaRead(off: u32) u32 {
    const ptr: *volatile u32 = @ptrFromInt(hba_base + off);
    return ptr.*;
}

fn hbaWrite(off: u32, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(hba_base + off);
    ptr.* = val;
}

fn portRead(port: u8, off: u32) u32 {
    const ptr: *volatile u32 = @ptrFromInt(hba_base + 0x100 + @as(usize, port) * 0x80 + off);
    return ptr.*;
}

fn portWrite(port: u8, off: u32, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(hba_base + 0x100 + @as(usize, port) * 0x80 + off);
    ptr.* = val;
}

/// Stop a port: clear ST + FRE, wait for CR + FR to clear. Required
/// before reprogramming PxCLB / PxFB.
fn portStop(p: u8) void {
    var cmd = portRead(p, PORT_CMD);
    cmd &= ~(CMD_ST | CMD_FRE);
    portWrite(p, PORT_CMD, cmd);
    var spin: u32 = 0;
    while (true) {
        const c = portRead(p, PORT_CMD);
        if ((c & (CMD_CR | CMD_FR)) == 0) break;
        spin += 1;
        if (spin > 1_000_000) {
            debug.klog("[ahci] port {d} stop timeout\n", .{p});
            break;
        }
    }
}

/// Start a port. Set FRE first so the HBA begins accepting FISes from the
/// device — that's what triggers the device to send its initial D2H
/// Register FIS, which populates PxTFD and PxSIG. Then wait for BSY/DRQ
/// to clear (= device is idle and signature is valid), then set ST to
/// turn on the command engine.
fn portStart(p: u8) void {
    var cmd = portRead(p, PORT_CMD);
    cmd |= CMD_FRE;
    portWrite(p, PORT_CMD, cmd);

    var spin: u32 = 0;
    while ((portRead(p, PORT_TFD) & (TFD_BSY | TFD_DRQ)) != 0 and spin < 5_000_000) : (spin += 1) {}

    cmd |= CMD_ST;
    portWrite(p, PORT_CMD, cmd);
}

pub fn init() bool {
    const dev = pci.findByClass(PCI_CLASS_STORAGE, PCI_SUBCLASS_SATA, PCI_PROGIF_AHCI) orelse {
        return false;
    };
    debug.klog("[ahci] found at {x}:{x}.{x} vendor=0x{x} dev=0x{x}\n", .{ dev.bus, dev.dev, dev.func, dev.vendor_id, dev.device_id });

    // ABAR is BAR5. pci.zig caches all 6 BARs at enumeration so we
    // can index directly without re-walking config space.
    const abar = dev.bars[5];
    if (abar == 0) {
        debug.klog("[ahci] BAR5 unassigned\n", .{});
        return false;
    }
    // Store the kernel-side VA (physmap). Hardware itself never sees
    // hba_base; only CPU-side register reads/writes through it.
    hba_base = paging.physToVirt(abar);
    debug.klog("[ahci] hba_base=0x{x} (phys 0x{x})\n", .{ hba_base, abar });

    var bind = pci.bindDevice(dev);
    defer bind.deinit();

    // BIOS/OS handoff if the controller supports it (CAP2.BOH bit). We
    // don't bother reading CAP2 — just always try and bail quickly if
    // BOS doesn't clear (means firmware doesn't implement handoff).
    const bohc = hbaRead(HBA_BOHC);
    if (bohc & BOHC_BOS != 0) {
        hbaWrite(HBA_BOHC, bohc | BOHC_OOS);
        var spin: u32 = 0;
        while ((hbaRead(HBA_BOHC) & BOHC_BOS) != 0 and spin < 1_000_000) : (spin += 1) {}
    }

    // Enable AHCI mode + reset HBA.
    hbaWrite(HBA_GHC, GHC_AE);
    hbaWrite(HBA_GHC, GHC_AE | GHC_HR);
    var spin: u32 = 0;
    while ((hbaRead(HBA_GHC) & GHC_HR) != 0 and spin < 1_000_000) : (spin += 1) {}
    if (spin >= 1_000_000) {
        debug.klog("[ahci] HBA reset timeout\n", .{});
        return false;
    }
    hbaWrite(HBA_GHC, GHC_AE); // re-enable after reset

    // MSI-X probe — single vector for the whole HBA, so each issued
    // command's polling loop can sleep on `hlt` instead of busy-spinning.
    // The handler only acks IS/PxIS; the actual completion check is
    // re-done in `issueCommand` after wakeup.
    if (msix.armOne(dev, 0, ahciIrqHandler)) |armed| {
        use_msix = true;
        // Enable HBA-level interrupt generation.
        hbaWrite(HBA_GHC, GHC_AE | GHC_IE);
        debug.klog("[ahci] MSI-X armed: tbl_sz={d} IDT vec=0x{x} dest=0x{x}\n", .{
            armed.cap.table_size, armed.vector.irq_vector, armed.vector.addr,
        });
    } else {
        debug.klog("[ahci] no MSI-X cap, polled mode\n", .{});
    }

    const pi = hbaRead(HBA_PI);
    debug.klog("[ahci] ports implemented: 0x{x}\n", .{pi});

    // Initialize each implemented port that has a device attached.
    var p: u8 = 0;
    while (p < 32) : (p += 1) {
        ports[p] = .{ .idx = p, .cmd_list_phys = 0, .fis_phys = 0, .cmd_table_phys = 0, .active = false };
        if ((pi >> @intCast(p)) & 1 == 0) continue;

        const ssts = portRead(p, PORT_SSTS);
        if ((ssts & SSTS_DET_MASK) != SSTS_DET_PRESENT) continue;

        if (!setupPort(p)) {
            debug.klog("[ahci] port {d}: setup failed\n", .{p});
            continue;
        }

        // Signature is only valid after the device's initial D2H FIS has
        // arrived — which only happens once FRE is set in setupPort →
        // portStart. Hence the reorder.
        const sig = portRead(p, PORT_SIG);
        if (sig != SIG_ATA) {
            debug.klog("[ahci] port {d}: non-ATA device sig=0x{x} skipped\n", .{ p, sig });
            continue;
        }
        ports[p].active = true;
        debug.klog("[ahci] port {d}: SATA disk ready\n", .{p});

        if (primary_port == 0xFF) {
            primary_port = p;
        } else if (secondary_port == 0xFF) {
            secondary_port = p;
        }
    }

    if (primary_port == 0xFF) {
        debug.klog("[ahci] no SATA disks found\n", .{});
        return false;
    }

    initialized = true;
    debug.klog("[ahci] initialized: primary=port{d} secondary=port{?d}\n", .{
        primary_port,
        if (secondary_port == 0xFF) null else @as(u8, secondary_port),
    });
    bind.commit();
    return true;
}

fn setupPort(p: u8) bool {
    portStop(p);

    // One page per port for command list (1 KB) + FIS (256 B) + command
    // table (256 B). Layout:
    //   0x000-0x3FF: command list (32 × 32-byte CommandHeader)
    //   0x400-0x4FF: FIS receive area
    //   0x500-0x5FF: command table 0 (we only use slot 0)
    //   0x600-0xFFF: scratch / unused
    const phys = pmm.allocContiguous(1) orelse return false;
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(phys)))[0..4096], 0);
    ports[p].cmd_list_phys = phys;
    ports[p].fis_phys = phys + 0x400;
    ports[p].cmd_table_phys = phys + 0x500;

    // Wire slot 0's CommandHeader to point at our single command table.
    const cmd_list: [*]volatile CommandHeader = @ptrFromInt(paging.physToVirt(phys));
    cmd_list[0].ctba = @truncate(ports[p].cmd_table_phys);
    cmd_list[0].ctbau = @truncate(ports[p].cmd_table_phys >> 32);

    portWrite(p, PORT_CLB, @truncate(phys));
    portWrite(p, PORT_CLBU, @truncate(phys >> 32));
    portWrite(p, PORT_FB, @truncate(phys + 0x400));
    portWrite(p, PORT_FBU, @truncate((phys + 0x400) >> 32));

    // Clear pending error state from before our setup.
    portWrite(p, PORT_SERR, 0xFFFFFFFF);
    portWrite(p, PORT_IS, 0xFFFFFFFF);

    portStart(p);

    // Per-port interrupt enable. DHRE (bit 0) covers D2H Register FIS,
    // which fires on completion of READ/WRITE DMA EXT and IDENTIFY.
    // Only meaningful once the HBA-level IE was set during MSI-X bring-up.
    if (use_msix) portWrite(p, PORT_IE, 1);
    return true;
}

/// Issue one ATA command and poll to completion. `cmd` is the ATA opcode
/// (READ DMA EXT / WRITE DMA EXT). Buffer `buf_phys` must be a physical
/// address; size in bytes = sectors × 512. `is_write` controls the FIS
/// write bit. Returns true on success.
fn issueCommand(port: u8, cmd: u8, lba: u64, sectors: u16, buf_phys: usize, is_write: bool) bool {
    if (!ports[port].active) return false;
    // Per-port lock: CFIS + PRDT + command-list slot 0 + the doorbell are
    // SHARED per port. Without this, two CPUs reading the same port race
    // on the command table and produce garbage in their buffers.
    port_locks[port].acquire();
    defer port_locks[port].release();
    const tab_addr = ports[port].cmd_table_phys;
    const cmd_list_addr = ports[port].cmd_list_phys;

    // Wait until the engine is idle.
    var spin: u32 = 0;
    while (true) {
        const tfd = portRead(port, PORT_TFD);
        if ((tfd & (TFD_BSY | TFD_DRQ)) == 0) break;
        spin += 1;
        if (spin > 5_000_000) {
            debug.klog("[ahci] port {d} not idle (tfd=0x{x})\n", .{ port, tfd });
            return false;
        }
    }

    // Fill the command FIS (Register Host-to-Device).
    const cfis: [*]volatile u8 = @ptrFromInt(paging.physToVirt(tab_addr));
    var k: usize = 0;
    while (k < 64) : (k += 1) cfis[k] = 0;
    cfis[0] = FIS_TYPE_REG_H2D;
    cfis[1] = 0x80; // C bit set: this FIS is a command
    cfis[2] = cmd;
    cfis[3] = 0; // features

    cfis[4] = @truncate(lba);
    cfis[5] = @truncate(lba >> 8);
    cfis[6] = @truncate(lba >> 16);
    cfis[7] = 0x40; // device: LBA mode

    cfis[8] = @truncate(lba >> 24);
    cfis[9] = @truncate(lba >> 32);
    cfis[10] = @truncate(lba >> 40);
    cfis[11] = 0; // features (high)

    cfis[12] = @truncate(sectors);
    cfis[13] = @truncate(sectors >> 8);
    cfis[14] = 0; // ICC
    cfis[15] = 0; // control

    // Fill PRDT entry 0.
    const prdt_off: usize = 0x80; // CFIS(64) + ATAPI(16) + rsv(48) = 128
    const prdt: *volatile PrdtEntry = @ptrFromInt(paging.physToVirt(tab_addr + prdt_off));
    prdt.dba = @truncate(buf_phys);
    prdt.dbau = @truncate(buf_phys >> 32);
    prdt._rsv = 0;
    // dbc = byte_count - 1, low 22 bits. Top bit = interrupt-on-completion (we poll).
    const byte_count: u32 = @as(u32, sectors) * 512;
    prdt.dbc = byte_count - 1;

    // Fill the command list slot 0 header.
    const hdr: *volatile CommandHeader = @ptrFromInt(paging.physToVirt(cmd_list_addr));
    // flags: bits 0..4 = CFIS DWORD count (5 = 20 bytes / 4),
    //        bit 6 = write to device.
    hdr.flags = 5 | (if (is_write) @as(u16, 1) << 6 else 0);
    hdr.prdtl = 1;
    hdr.prdbc = 0;

    // Clear stale interrupt status for this port.
    portWrite(port, PORT_IS, 0xFFFFFFFF);

    // Issue command in slot 0.
    portWrite(port, PORT_CI, 1);

    // Poll until the slot bit clears or we hit a fatal task-file error.
    // With MSI-X the loop sleeps on `sti; hlt` between checks — woken by
    // either ahciIrqHandler (D2H FIS arrived) or the LAPIC timer.
    //
    // cli-around-check + atomic sti;hlt — without the cli, an IRQ arriving
    // between the ci-bit check and the sti;hlt is consumed by the dummy
    // ahciIrqHandler and we sleep until the next 10ms LAPIC tick. Same
    // pattern as nvme.waitCompletion / virtio_gpu.sendCmdViaPhys.
    spin = 0;
    while (true) {
        if (use_msix) asm volatile ("cli" ::: .{ .memory = true });
        const ci = portRead(port, PORT_CI);
        if ((ci & 1) == 0) {
            if (use_msix) asm volatile ("sti" ::: .{ .memory = true });
            break;
        }
        const tfd = portRead(port, PORT_TFD);
        if ((tfd & TFD_ERR) != 0) {
            if (use_msix) asm volatile ("sti" ::: .{ .memory = true });
            debug.klog("[ahci] port {d} command error tfd=0x{x}\n", .{ port, tfd });
            return false;
        }
        if (use_msix) {
            // sti+hlt is atomic via the sti shadow; pending IRQ from
            // before the cli wakes us after hlt commits.
            asm volatile ("sti; hlt" ::: .{ .memory = true });
        } else {
            spin += 1;
            if (spin > 10_000_000) {
                debug.klog("[ahci] port {d} command timeout\n", .{port});
                return false;
            }
        }
    }

    return true;
}

// === Public sector API (mirrors ata.zig) ===
// `issueCommand` takes a *physical* address — it goes straight into the
// PRDT (`prdt.dba`/`dbau`). After the higher-half kernel migration a kernel
// buffer like a FAT32 cache page is at a high VA, so we route every dest/src
// pointer through paging.virtToPhys before truncating. virtToPhys returns
// null on out-of-window VAs; we unwrap (.?) — a panic here means a caller
// passed a non-kernel pointer to AHCI, which is a real bug.

inline fn vp(p: anytype) usize {
    return @import("../mm/paging.zig").virtToPhys(@intFromPtr(p)).?;
}

pub fn readSectorPrimary(lba: u32, dest: [*]u8) void {
    if (primary_port == 0xFF) return;
    _ = issueCommand(primary_port, ATA_CMD_READ_DMA_EXT, lba, 1, vp(dest), false);
}

// count is u16 (ext2's cache fill can now be up to 256 sectors for QD4). No
// chunk loop needed: issueCommand's CFIS count is 16-bit (LBA48) and its single
// PRDT entry's dbc is 22-bit, so one command covers up to 4 MiB / 8192 sectors
// in one contiguous transfer — far past anything the FS cache asks for.
pub fn readSectorsPrimary(lba: u32, count: u16, dest: [*]u8) void {
    if (primary_port == 0xFF) return;
    _ = issueCommand(primary_port, ATA_CMD_READ_DMA_EXT, lba, count, vp(dest), false);
}

pub fn readSectorSecondary(lba: u32, dest: [*]u8) void {
    if (secondary_port == 0xFF) return;
    _ = issueCommand(secondary_port, ATA_CMD_READ_DMA_EXT, lba, 1, vp(dest), false);
}

pub fn readSectorsSecondary(lba: u32, count: u16, dest: [*]u8) void {
    if (secondary_port == 0xFF) return;
    _ = issueCommand(secondary_port, ATA_CMD_READ_DMA_EXT, lba, count, vp(dest), false);
}

pub fn writeSectorSecondary(lba: u32, src: [*]const u8) void {
    if (secondary_port == 0xFF) return;
    _ = issueCommand(secondary_port, ATA_CMD_WRITE_DMA_EXT, lba, 1, vp(src), true);
}

pub fn isReady() bool {
    return initialized;
}

pub fn hasSecondary() bool {
    return secondary_port != 0xFF;
}
