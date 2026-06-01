const pci = @import("pci.zig");
const paging = @import("../mm/paging.zig");
const pmm = @import("../mm/pmm.zig");
const debug = @import("../debug/debug.zig");
const process = @import("../proc/process.zig");
const keyboard = @import("keyboard.zig");
const mouse = @import("mouse.zig");
const msix = @import("../time/msix.zig");
const iommu = @import("../cpu/mmu/iommu.zig");

// PCI BDF captured at init for per-device-attach iommu.dmaMap calls.
var pci_bus: u8 = 0;
var pci_dev: u8 = 0;
var pci_func: u8 = 0;

// --- xHCI TRB Types ---
const TRB_NORMAL = 1;
const TRB_SETUP = 2;
const TRB_DATA = 3;
const TRB_STATUS = 4;
const TRB_LINK = 6;
const TRB_ENABLE_SLOT = 9;
const TRB_DISABLE_SLOT = 10;
const TRB_ADDRESS_DEVICE = 11;
const TRB_CONFIGURE_EP = 12;
const TRB_EVALUATE_CTX = 13;
const TRB_RESET_EP = 14;
const TRB_STOP_EP = 15;
const TRB_NOOP = 23;
const TRB_SET_TR_DEQUEUE = 16; // Was WRONG (10 = Disable Slot!)
const TRB_EVENT_TRANSFER = 32;
const TRB_EVENT_CMD_COMPLETE = 33;
const TRB_EVENT_PORT_CHANGE = 34;

// --- xHCI USB Speed ---
const SPEED_FULL = 1;
const SPEED_LOW = 2;
const SPEED_HIGH = 3;
const SPEED_SUPER = 4;

// --- TRB structure (16 bytes) ---
const TRB = extern struct {
    param_lo: u32,
    param_hi: u32,
    status: u32,
    control: u32,
};

// --- Ring buffer ---
const RING_SIZE: u32 = 256; // Transfer ring size (1 page = 4096 bytes, no fragmentation)
const EVT_RING_SIZE: u32 = 1024; // Event ring size (4 pages)

const Ring = struct {
    trbs: [*]volatile TRB,
    phys: usize,
    enqueue: u32,
    cycle: bool,
    link_pending: bool = false, // Deferred Link TRB cycle update
};

// --- USB descriptor types ---
const DESC_DEVICE = 1;
const DESC_CONFIGURATION = 2;
const DESC_INTERFACE = 4;
const DESC_ENDPOINT = 5;
const DESC_HID = 0x21;

// USB HID class
const USB_CLASS_HID = 3;
const HID_SUBCLASS_BOOT = 1;
const HID_PROTOCOL_KEYBOARD = 1;
const HID_PROTOCOL_MOUSE = 2;

// USB Mass Storage class
const USB_CLASS_MSC = 8;
const MSC_SUBCLASS_SCSI = 6;
const MSC_PROTOCOL_BOT = 0x50; // Bulk-Only Transport
const MSC_PROTOCOL_UAS = 0x62; // USB Attached SCSI

// UAS descriptors + pipe roles (UAS spec §4). Each UAS bulk endpoint is
// followed by a Pipe Usage Descriptor binding it to one of four logical
// pipes; on SuperSpeed a SuperSpeed Endpoint Companion descriptor carries
// bMaxStreams (the number of streams = 2^bMaxStreams).
const DESC_PIPE_USAGE = 0x24; // class-specific endpoint descriptor
const DESC_SS_EP_COMPANION = 0x30; // SuperSpeed endpoint companion
const UAS_PIPE_COMMAND = 1; // bulk OUT — Command IUs
const UAS_PIPE_STATUS = 2; // bulk IN  — Status/Sense IUs (streamed)
const UAS_PIPE_DATA_IN = 3; // bulk IN  — read data (streamed)
const UAS_PIPE_DATA_OUT = 4; // bulk OUT — write data (streamed)

// USB request types
const REQ_GET_DESCRIPTOR = 6;
const REQ_SET_CONFIGURATION = 9;
const REQ_SET_PROTOCOL = 0x0B;
const REQ_SET_IDLE = 0x0A;

// Context size (32 bytes when CSZ=0)
const CTX_SIZE: u32 = 32;
const MAX_DEVICES: u8 = 8;

// Per-device state
const NUM_INTR_TRBS: u32 = 127; // Half of usable ring (255/2)

const DeviceSlot = struct {
    slot_id: u8 = 0,
    port: u8 = 0,
    speed: u8 = 0,
    active: bool = false,
    is_keyboard: bool = false,
    is_mouse: bool = false,
    is_tablet: bool = false, // USB tablet (absolute coordinates)
    is_msc: bool = false, // Mass Storage Class
    dev_ctx_phys: usize = 0,
    tr_ring: ?Ring = null, // Interrupt IN ring (HID) or Bulk IN ring (MSC)
    ep_dci: u8 = 0, // IN endpoint DCI
    data_phys: usize = 0, // Per-device data buffer page
    // MSC-specific
    bulk_out_ring: ?Ring = null,
    bulk_out_dci: u8 = 0,
    msc_tag: u32 = 1, // CBW tag counter
    msc_block_size: u32 = 512,
    msc_block_count: u32 = 0,
    msc_max_packet: u16 = 512,
};

var devices: [MAX_DEVICES]DeviceSlot = [_]DeviceSlot{.{}} ** MAX_DEVICES;

// Single detected UAS device. UAS keeps its own state (4 logical pipes +
// stream count) separate from the BOT DeviceSlot path: a UAS device is NOT
// added to devices[] (it isn't HID and its bulk endpoints are streamed, so
// pollHID / mscScsiCommand must not touch it). Filled by enumerateDevice
// (Slice U1 = detection); the stream endpoints + transport land in U2/U3.
const UasInfo = struct {
    present: bool = false,
    slot_id: u8 = 0,
    port: u8 = 0,
    speed: u8 = 0,
    dev_ctx_phys: usize = 0,
    alt: u8 = 0, // UAS alternate interface setting
    cmd_ep: u8 = 0, // bulk OUT — command pipe (no streams)
    cmd_mp: u16 = 0,
    status_ep: u8 = 0, // bulk IN — status pipe (streamed)
    status_mp: u16 = 0,
    in_ep: u8 = 0, // bulk IN — data-in pipe (streamed)
    in_mp: u16 = 0,
    out_ep: u8 = 0, // bulk OUT — data-out pipe (streamed)
    out_mp: u16 = 0,
    max_streams: u8 = 0, // 2^bMaxStreams from the SS companion (0 = no streams)
};
var uas_dev: UasInfo = .{};

// Per-device lock for the MSC bulk-transport path. mscScsiCommand shares
// dev.data_phys (CBW@0/data@512/CSW@1024) + the device's bulk in/out rings,
// AND the global event ring with pollHID — two CPUs reading from a USB MSC
// disk via syscall would race on all three. pollHID itself is BSP-only so
// the IRQ producer side is safe; this lock just serializes consumers.
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
var msc_locks: [MAX_DEVICES]SpinLock = [_]SpinLock{.{}} ** MAX_DEVICES;
var device_count: u8 = 0;

// Separate ring storage — avoids Zig optional pointer semantics issues
var hid_rings: [MAX_DEVICES]Ring = undefined;
var hid_ring_active: [MAX_DEVICES]bool = [_]bool{false} ** MAX_DEVICES;

// Event ring dequeue tracking
pub var evt_dequeue: u32 = 0;
var evt_cycle: bool = true;

// Scratchpad for control transfers (one page)
var scratch_phys: usize = 0;

// --- Controller state ---
var mmio_base: usize = 0;
var op_base: usize = 0;
var rt_base: usize = 0;
var db_base: usize = 0;
var max_ports: u8 = 0;
var max_slots: u8 = 0;

var cmd_ring: Ring = undefined;
var evt_ring: Ring = undefined;
var dcbaa_phys: usize = 0;
var erst_phys: usize = 0;

var initialized: bool = false;
var enumeration_done: bool = false; // Set after all ports enumerated

// MSI-X / IRQ-driven completion state. When `use_msix` is true,
// `waitForEvent` blocks on `sti; hlt` instead of a busy-poll — woken by
// either the xHCI MSI-X handler or the LAPIC tick. Same shape as
// virtio_gpu's MSI-X plumbing.
var use_msix: bool = false;
/// Gate the sti+hlt path. Flips true after MSI-X is armed AND we're
/// post-Phase-5 sti. xhci.init() is called from Phase 6 so by the time
/// MSI-X arms successfully, both conditions hold and we set this immediately.
pub var msix_safe_to_use: bool = false;
pub var xhci_irq_count: u64 = 0;

/// True while a sendCommand/mscScsiCommand is mid-flight waiting for its
/// event. pollHID checks this at entry and bails — otherwise the timer-
/// driven HID drain would steal CMD_COMPLETE / MSC TRANSFER events from
/// waitForEvent and leave the caller spinning until timeout. Set BEFORE
/// the doorbell that triggers the awaited event so the timer-IRQ window
/// between doorbell and waitForEvent doesn't expose a race.
var event_drain_locked: bool = false;

/// Catch-all MSI-X handler. Just bumps a counter — the actual ring drain
/// happens in waitForEvent's next loop iteration after `hlt` returns.
/// Same design as nvmeIrqHandler / virtio_gpu's irq handler.
fn xhciIrqHandler() callconv(.c) void {
    xhci_irq_count +%= 1;
}

// --- MMIO register helpers ---
inline fn readReg(addr: usize) u32 {
    return @as(*volatile u32, @ptrFromInt(addr)).*;
}

inline fn writeReg(addr: usize, val: u32) void {
    @as(*volatile u32, @ptrFromInt(addr)).* = val;
}

inline fn readReg64(addr: usize) u64 {
    const lo = readReg(addr);
    const hi = readReg(addr + 4);
    return @as(u64, hi) << 32 | @as(u64, lo);
}

inline fn writeReg64(addr: usize, val: u64) void {
    writeReg(addr, @truncate(val));
    writeReg(addr + 4, @truncate(val >> 32));
}

// --- Operational register offsets ---
const USBCMD = 0x00;
const USBSTS = 0x04;
const PAGESIZE = 0x08;
const DNCTRL = 0x14;
const CRCR = 0x18;
const DCBAAP = 0x30;
const CONFIG = 0x38;
const PORTSC_BASE = 0x400;

// USBCMD bits
const CMD_RS = 1 << 0; // Run/Stop
const CMD_HCRST = 1 << 1; // Host Controller Reset
const CMD_INTE = 1 << 2; // Interrupter Enable

// USBSTS bits
const STS_HCH = 1 << 0; // HCHalted
const STS_CNR = 1 << 11; // Controller Not Ready
const STS_EINT = 1 << 3; // Event Interrupt

// PORTSC bits
const PORTSC_CCS = 1 << 0; // Current Connect Status
const PORTSC_PED = 1 << 1; // Port Enabled
const PORTSC_PR = 1 << 4; // Port Reset
const PORTSC_PLS_MASK: u32 = 0xF << 5; // Port Link State
const PORTSC_PP = 1 << 9; // Port Power
const PORTSC_SPEED_MASK: u32 = 0xF << 10; // Port Speed
const PORTSC_CSC = 1 << 17; // Connect Status Change
const PORTSC_PRC = 1 << 21; // Port Reset Change

fn portscAddr(port: u8) usize {
    return op_base + PORTSC_BASE + @as(usize, port) * 0x10;
}

// --- Ring buffer management ---

fn initRing() ?Ring {
    // Allocate one page for command/event rings
    const phys = pmm.allocFrame() orelse return null;
    const ptr: [*]u8 = @ptrFromInt(paging.physToVirt(phys));
    @memset(ptr[0..4096], 0);

    return .{
        .trbs = @ptrFromInt(paging.physToVirt(phys)),
        .phys = phys,
        .enqueue = 0,
        .cycle = true,
    };
}

fn initTransferRing() ?Ring {
    // 1 page = 256 TRBs (255 usable + Link TRB) — guaranteed contiguous physical memory
    const phys = pmm.allocFrame() orelse return null;
    const trbs: [*]volatile TRB = @ptrFromInt(paging.physToVirt(phys));
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(phys)))[0..4096], 0);

    // Link TRB at last position: TC is bit 1 (NOT bit 5 which is IOC!)
    trbs[RING_SIZE - 1] = TRB{
        .param_lo = @truncate(phys),
        .param_hi = @truncate(phys >> 32),
        .status = 0,
        .control = (TRB_LINK << 10) | (1 << 1) | 1, // Type=Link, TC=1(bit1), Cycle=1
    };

    return .{
        .trbs = trbs,
        .phys = phys,
        .enqueue = 0,
        .cycle = true,
    };
}

fn ringEnqueue(ring: *Ring, trb: TRB) void {
    if (ring.enqueue >= RING_SIZE - 1) return; // At Link TRB position

    // Write TRB data fields first, then control (with cycle) after sfence
    ring.trbs[ring.enqueue].param_lo = trb.param_lo;
    ring.trbs[ring.enqueue].param_hi = trb.param_hi;
    ring.trbs[ring.enqueue].status = trb.status;
    asm volatile ("sfence" ::: .{ .memory = true });
    ring.trbs[ring.enqueue].control = (trb.control & ~@as(u32, 1)) |
        (if (ring.cycle) @as(u32, 1) else @as(u32, 0));

    ring.enqueue += 1;

    // When we reach the Link TRB position, update it and wrap
    if (ring.enqueue >= RING_SIZE - 1) {
        // Write Link TRB with current cycle, TC=bit1
        asm volatile ("sfence" ::: .{ .memory = true });
        ring.trbs[RING_SIZE - 1].control = (TRB_LINK << 10) | (1 << 1) | // TC=bit1
            (if (ring.cycle) @as(u32, 1) else @as(u32, 0));
        ring.enqueue = 0;
        ring.cycle = !ring.cycle;
    }
}

fn ringDoorbell(slot: u8, target: u8) void {
    // Memory barrier: ensure all TRB/ring writes are visible before doorbell
    asm volatile ("mfence" ::: .{ .memory = true });
    const db_addr = db_base + @as(usize, slot) * 4;
    writeReg(db_addr, @as(u32, target));
}

// --- Controller initialization ---

pub fn init() bool {
    debug.klog("[xhci] Scanning for xHCI controller...\n", .{});

    // Find xHCI device: class=0x0C (Serial Bus), subclass=0x03 (USB), prog_if=0x30 (xHCI)
    const dev = pci.findByClass(0x0C, 0x03, 0x30) orelse {
        debug.klog("[xhci] No xHCI controller found\n", .{});
        return false;
    };

    debug.klog("[xhci] Found at bus={d} dev={d} func={d} vendor=0x{x} device=0x{x}\n", .{
        dev.bus, dev.dev, dev.func, dev.vendor_id, dev.device_id,
    });
    debug.klog("[xhci] BAR0=0x{x} IRQ={d}\n", .{ dev.bars[0], dev.irq_line });

    // Get BAR size
    const bar_size = pci.getBarSize(dev, 0);
    debug.klog("[xhci] BAR0 size={d} bytes\n", .{bar_size});

    if (dev.bars[0] == 0) {
        debug.klog("[xhci] BAR0 is zero, cannot map\n", .{});
        return false;
    }

    // Bus master + MEM/IO + INTx-disable (xHCI uses MSI-X for event ring).
    var bind = pci.bindDevice(dev);
    defer bind.deinit();
    pci_bus = dev.bus;
    pci_dev = dev.dev;
    pci_func = dev.func;

    // IOMMU Phase 3: flip onto own SL page table before any DMA setup.
    // The xHCI controller starts DMA on USBCMD.RS below — everything it
    // touches between here and that point must be dmaMap'd. Plus every
    // per-device structure allocated during enumeration.
    _ = iommu.enableIsolation(dev.bus, dev.dev, dev.func);

    // Map MMIO region. mmio_base stores the physmap-translated VA so
    // `mmio_base + off` is directly dereferenceable; hardware never sees
    // this value, only CPU register reads/writes.
    const map_size = if (bar_size > 0) bar_size else 0x10000; // Default 64KB
    paging.mapMMIO(dev.bars[0], map_size);
    mmio_base = paging.physToVirt(@intCast(dev.bars[0]));

    // Read capability registers
    const caplength: u8 = @truncate(readReg(mmio_base));
    const hciversion: u16 = @truncate(readReg(mmio_base) >> 16);
    const hcsparams1 = readReg(mmio_base + 0x04);
    const hccparams1 = readReg(mmio_base + 0x10);
    const dboff = readReg(mmio_base + 0x14);
    const rtsoff = readReg(mmio_base + 0x18);

    max_slots = @truncate(hcsparams1);
    max_ports = @truncate(hcsparams1 >> 24);
    const max_intrs: u16 = @truncate(hcsparams1 >> 8);

    op_base = mmio_base + caplength;
    rt_base = mmio_base + rtsoff;
    db_base = mmio_base + dboff;

    const ac64 = (hccparams1 & 1) != 0;
    const csz = (hccparams1 & (1 << 2)) != 0;

    debug.klog("[xhci] Version {d}.{d}, MaxPorts={d}, MaxSlots={d}, MaxIntrs={d}\n", .{
        hciversion >> 8, hciversion & 0xFF, max_ports, max_slots, max_intrs,
    });
    debug.klog("[xhci] AC64={d} CSZ={d} OpBase=0x{x}\n", .{ @as(u8, if (ac64) 1 else 0), @as(u8, if (csz) 1 else 0), op_base });

    // --- BIOS handoff (USBLEGSUP) ---
    //
    // Real-HW BIOSes commonly own the xHCI controller for PS/2 emulation
    // (BIOS reads USB-keyboard scancodes and mirrors them through 0x60/0x64).
    // Without this handoff, BIOS keeps owning the controller, every USB
    // transfer fires an SMI (5-50ms latency hit each), and on some chipsets
    // the BIOS reclaims the controller out from under us minutes later.
    //
    // Walk the extended-capability linked list. xECP is hccparams1[31:16]
    // expressed in 32-bit dwords from MMIO base. Cap ID 1 = USBLEGSUP.
    // QEMU has no such cap (BIOS doesn't pre-own); on QEMU this loop is
    // a no-op or terminates immediately.
    const xecp_off_dwords: u32 = (hccparams1 >> 16) & 0xFFFF;
    if (xecp_off_dwords != 0) {
        var cap_addr = mmio_base + @as(usize, xecp_off_dwords) * 4;
        var hops: u32 = 0;
        while (hops < 64) : (hops += 1) {
            const cap = readReg(cap_addr);
            const cap_id: u8 = @truncate(cap & 0xFF);
            const next_off: u8 = @truncate((cap >> 8) & 0xFF);
            if (cap_id == 1) {
                // USBLEGSUP at +0:  bit 16 = BIOS Owned, bit 24 = OS Owned
                // USBLEGCTLSTS at +4: SMI enables (low 16) + status (high 16, RW1C)
                if (cap & (1 << 16) != 0) {
                    debug.klog("[xhci] BIOS owns controller — requesting handoff\n", .{});
                    writeReg(cap_addr, cap | (1 << 24));
                    var ho_tries: u32 = 0;
                    while (ho_tries < 1_000_000) : (ho_tries += 1) {
                        if (readReg(cap_addr) & (1 << 16) == 0) break;
                    }
                    if (ho_tries >= 1_000_000) {
                        // BIOS refused to release. Force-clear per xHCI
                        // spec section 4.22.1: write OS-Owned, leave
                        // BIOS-Owned 0. Some buggy BIOSes wedge here.
                        debug.klog("[xhci] BIOS handoff TIMEOUT — forcing\n", .{});
                        writeReg(cap_addr, 1 << 24);
                    } else {
                        debug.klog("[xhci] BIOS handoff OK\n", .{});
                    }
                }
                // Disable SMI generation + ack any pending SMI status.
                // Low 16 bits → write 0 (clear enables); high 16 bits → write 1
                // to clear (RW1C). 0xE0000000 hits the three RW1C status
                // bits the spec defines (HSE, OS_OWNERSHIP_CHANGE, PCICOMMAND).
                writeReg(cap_addr + 4, 0xE0000000);
            }
            if (next_off == 0) break;
            cap_addr += @as(usize, next_off) * 4;
        }
    }

    // --- Reset controller ---
    // Stop first
    var cmd = readReg(op_base + USBCMD);
    cmd &= ~@as(u32, CMD_RS);
    writeReg(op_base + USBCMD, cmd);

    // Wait for halted
    var timeout: u32 = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if (readReg(op_base + USBSTS) & STS_HCH != 0) break;
    }
    if (timeout == 0) {
        debug.klog("[xhci] Timeout waiting for halt\n", .{});
        return false;
    }

    // Reset (HCRST). Real HW chipsets sometimes need a second attempt —
    // Intel xhci specifically can ignore the first HCRST if the controller
    // was mid-state when stopped. Retry once if the first try doesn't
    // self-clear within ~100ms.
    var reset_attempts: u32 = 0;
    while (reset_attempts < 2) : (reset_attempts += 1) {
        writeReg(op_base + USBCMD, CMD_HCRST);
        timeout = 100000;
        while (timeout > 0) : (timeout -= 1) {
            if (readReg(op_base + USBCMD) & CMD_HCRST == 0) break;
        }
        if (timeout > 0) break;
        debug.klog("[xhci] HCRST attempt {d} didn't clear, retrying\n", .{reset_attempts + 1});
    }
    if (reset_attempts >= 2) {
        debug.klog("[xhci] Timeout waiting for reset (after retry)\n", .{});
        return false;
    }

    // Wait for CNR to clear
    timeout = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if (readReg(op_base + USBSTS) & STS_CNR == 0) break;
    }
    if (timeout == 0) {
        debug.klog("[xhci] Timeout waiting for CNR clear\n", .{});
        return false;
    }
    debug.klog("[xhci] Controller reset OK\n", .{});

    // --- Set max slots ---
    writeReg(op_base + CONFIG, max_slots);

    // --- Allocate DCBAA ---
    // (max_slots + 1) * 8 bytes, must be 64-byte aligned. One page is fine.
    const dcbaa_page = pmm.allocFrame() orelse {
        debug.klog("[xhci] Failed to allocate DCBAA\n", .{});
        return false;
    };
    dcbaa_phys = dcbaa_page;
    const dcbaa_ptr: [*]u8 = @ptrFromInt(paging.physToVirt(dcbaa_page));
    @memset(dcbaa_ptr[0..4096], 0);
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, dcbaa_phys, 4096, .{});
    writeReg64(op_base + DCBAAP, dcbaa_phys);
    debug.klog("[xhci] DCBAA at 0x{x}\n", .{dcbaa_phys});

    // --- Allocate Command Ring ---
    cmd_ring = initRing() orelse {
        debug.klog("[xhci] Failed to allocate command ring\n", .{});
        return false;
    };
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, cmd_ring.phys, 4096, .{});
    // Write CRCR: physical address | cycle bit
    writeReg64(op_base + CRCR, cmd_ring.phys | 1);
    debug.klog("[xhci] Command ring at 0x{x}\n", .{cmd_ring.phys});

    // --- Allocate Event Ring (4 contiguous pages = 1024 TRBs) ---
    const evt_phys = pmm.allocContiguous(4) orelse return false;
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(evt_phys)))[0..4096 * 4], 0);
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, evt_phys, 4096 * 4, .{});
    evt_ring = .{
        .trbs = @ptrFromInt(paging.physToVirt(evt_phys)),
        .phys = evt_phys,
        .enqueue = 0,
        .cycle = true,
    };
    debug.klog("[xhci] Event ring at 0x{x} (4 pages)\n", .{evt_phys});

    // --- Set up Event Ring Segment Table ---
    // ERST: one entry = {base_addr_lo, base_addr_hi, ring_size, reserved}
    const erst_page = pmm.allocFrame() orelse {
        debug.klog("[xhci] Failed to allocate ERST\n", .{});
        return false;
    };
    erst_phys = erst_page;
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, erst_phys, 4096, .{});
    const erst: [*]volatile u32 = @ptrFromInt(paging.physToVirt(erst_page));
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(erst_page)))[0..4096], 0);
    erst[0] = @truncate(evt_ring.phys); // Base address low
    erst[1] = @truncate(evt_ring.phys >> 32); // Base address high
    erst[2] = EVT_RING_SIZE; // Ring segment size (1024 entries)
    erst[3] = 0; // Reserved

    // Interrupter 0 registers (runtime base + 0x20 + interrupter*32)
    const ir0_base = rt_base + 0x20;
    // Set ERSTSZ (Event Ring Segment Table Size)
    writeReg(ir0_base + 0x08, 1); // One segment
    // Set ERDP (Event Ring Dequeue Pointer)
    writeReg64(ir0_base + 0x18, evt_ring.phys);
    // Set ERSTBA (Event Ring Segment Table Base Address)
    writeReg64(ir0_base + 0x10, erst_phys);
    // Enable interrupter
    var iman = readReg(ir0_base + 0x00);
    iman |= 0x02; // IE (Interrupt Enable)
    writeReg(ir0_base + 0x00, iman);

    // --- Start controller ---
    cmd = readReg(op_base + USBCMD);
    cmd |= CMD_RS | CMD_INTE;
    writeReg(op_base + USBCMD, cmd);

    // Verify running
    timeout = 100000;
    while (timeout > 0) : (timeout -= 1) {
        if (readReg(op_base + USBSTS) & STS_HCH == 0) break;
    }
    if (timeout == 0) {
        debug.klog("[xhci] Controller failed to start\n", .{});
        return false;
    }

    initialized = true;
    debug.klog("[xhci] Controller running!\n", .{});

    // Arm MSI-X: table entry 0 → interrupter 0 by xHCI spec when MSI-X is
    // enabled. We already set IMAN.IE on interrupter 0 above and CMD_INTE
    // in USBCMD, so the device is ready to fire — `msix.armOne` just wires
    // up the IDT vector + LAPIC mailbox + flips the cap's MSI-X-Enable bit.
    // Failing arm leaves us on the busy-poll path; both work, MSI-X just
    // saves milliseconds of `pause` per USB transfer.
    //
    // xhci.init() runs in Phase 6, AFTER the global `sti` and AFTER
    // `virtio_gpu.msix_safe_to_use = true` were both flipped, so we can
    // safely use the sti+hlt path immediately — no two-phase setup needed.
    if (msix.armOne(dev, 0, xhciIrqHandler)) |armed| {
        use_msix = true;
        msix_safe_to_use = true;
        debug.klog("[xhci] MSI-X armed: IDT vec=0x{x}\n", .{armed.vector.irq_vector});
    } else {
        debug.klog("[xhci] MSI-X unavailable — busy-poll fallback\n", .{});
    }

    // Scan ports and enumerate connected devices
    scanAndEnumerate();
    enumeration_done = true;
    debug.klog("[xhci] Enumeration complete, {d} HID devices\n", .{device_count});

    bind.commit();
    return true;
}

fn scanAndEnumerate() void {
    // Allocate scratch buffer for control transfers
    scratch_phys = pmm.allocFrame() orelse {
        debug.klog("[xhci] Failed to allocate scratch buffer\n", .{});
        return;
    };
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(scratch_phys)))[0..4096], 0);
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, scratch_phys, 4096, .{});

    evt_dequeue = 0;
    evt_cycle = true;

    debug.klog("[xhci] Scanning {d} ports...\n", .{max_ports});
    var port: u8 = 0;
    while (port < max_ports) : (port += 1) {
        const portsc = readReg(portscAddr(port));
        if (portsc & PORTSC_CCS == 0) continue; // Not connected

        const speed = @as(u8, @truncate((portsc & PORTSC_SPEED_MASK) >> 10));
        debug.klog("[xhci] Port {d}: connected, speed={d}\n", .{ port + 1, speed });

        // Reset port
        if (!resetPort(port)) continue;

        // Enumerate device
        enumerateDevice(port, speed);
    }
}

fn resetPort(port: u8) bool {
    const addr = portscAddr(port);
    // Write PR (Port Reset) bit, preserve PP, clear status change bits
    var portsc = readReg(addr);
    portsc &= ~@as(u32, PORTSC_PED); // Don't accidentally disable
    portsc |= PORTSC_PR; // Set reset
    // Clear change bits by writing 1
    portsc |= PORTSC_CSC | PORTSC_PRC;
    writeReg(addr, portsc);

    // Wait for reset complete (PRC bit set)
    var timeout: u32 = 200000;
    while (timeout > 0) : (timeout -= 1) {
        const sc = readReg(addr);
        if (sc & PORTSC_PRC != 0) {
            // Clear PRC
            writeReg(addr, (sc & 0x0E01C3E0) | PORTSC_PRC);
            break;
        }
    }
    if (timeout == 0) {
        debug.klog("[xhci] Port {d} reset timeout\n", .{port + 1});
        return false;
    }

    // Check port is enabled
    const sc = readReg(addr);
    if (sc & PORTSC_PED == 0) {
        debug.klog("[xhci] Port {d} not enabled after reset\n", .{port + 1});
        return false;
    }

    debug.klog("[xhci] Port {d} reset OK, enabled\n", .{port + 1});
    return true;
}

// --- Command ring helpers ---

fn sendCommand(trb: TRB) ?TRB {
    // Lock the event-ring drain BEFORE the doorbell. The timer-driven
    // pollHID would otherwise be free to consume our CMD_COMPLETE event
    // in the window between doorbell and waitForEvent, leaving the
    // caller spinning to timeout. See `event_drain_locked` comment.
    event_drain_locked = true;
    defer event_drain_locked = false;
    ringEnqueue(&cmd_ring, trb);
    // Ring doorbell 0 (host controller) target 0
    ringDoorbell(0, 0);
    return waitForEvent(TRB_EVENT_CMD_COMPLETE, 500000);
}

fn waitForEvent(event_type: u8, max_polls: u32) ?TRB {
    // Two paths:
    //   * MSI-X armed (post-init): `sti; hlt` until either our handler
    //     fires or the LAPIC tick wakes us. Cheap — CPU is HLT-idle so
    //     it can serve other IRQs (timer, network, kbd) instead of
    //     burning ~0.5 ms of `pause` per USB transfer. 200 ticks ≈ 2 s
    //     timeout on the default 10 ms LAPIC period — comfortable for
    //     real-HW MSC reads which can take tens of ms.
    //   * Polled (init phase if MSI-X arm failed): legacy `pause` spin
    //     with the caller-supplied poll cap.
    if (use_msix and msix_safe_to_use) {
        // cli-around-check + atomic sti;hlt — without the cli, an MSI-X
        // arriving between the cycle-bit check and the sti;hlt is consumed
        // by the dummy xhciIrqHandler and we sleep until the next 10ms
        // LAPIC tick, inflating per-USB-op latency by 10×. Same pattern
        // as nvme.waitCompletion / virtio_gpu.sendCmdViaPhys.
        var hlt_count: u32 = 0;
        while (hlt_count < 200) {
            asm volatile ("cli" ::: .{ .memory = true });
            const evt_trb = evt_ring.trbs[evt_dequeue];
            const cycle_bit = (evt_trb.control & 1) != 0;
            if (cycle_bit == evt_cycle) {
                asm volatile ("sti" ::: .{ .memory = true });
                const trb_type = @as(u8, @truncate((evt_trb.control >> 10) & 0x3F));
                evt_dequeue += 1;
                if (evt_dequeue >= EVT_RING_SIZE) {
                    evt_dequeue = 0;
                    evt_cycle = !evt_cycle;
                }
                const erdp_phys = evt_ring.phys + evt_dequeue * 16;
                const ir0_base = rt_base + 0x20;
                writeReg64(ir0_base + 0x18, @as(u64, erdp_phys) | (1 << 3));
                if (trb_type == event_type) return evt_trb;
                continue; // different event type, look at the next slot
            }
            // No event yet; sleep with cli still active. sti+hlt is atomic,
            // pending IRQ from before cli wakes us after hlt commits.
            asm volatile ("sti; hlt" ::: .{ .memory = true });
            hlt_count += 1;
        }
        return null;
    }

    var polls: u32 = 0;
    while (polls < max_polls) : (polls += 1) {
        const evt_trb = evt_ring.trbs[evt_dequeue];
        const cycle_bit = (evt_trb.control & 1) != 0;
        if (cycle_bit != evt_cycle) {
            asm volatile ("pause");
            continue;
        }
        const trb_type = @as(u8, @truncate((evt_trb.control >> 10) & 0x3F));
        evt_dequeue += 1;
        if (evt_dequeue >= EVT_RING_SIZE) {
            evt_dequeue = 0;
            evt_cycle = !evt_cycle;
        }
        const erdp_phys = evt_ring.phys + evt_dequeue * 16;
        const ir0_base = rt_base + 0x20;
        writeReg64(ir0_base + 0x18, @as(u64, erdp_phys) | (1 << 3));
        if (trb_type == event_type) return evt_trb;
    }
    return null;
}

// --- USB Enumeration ---

fn enumerateDevice(port: u8, speed: u8) void {
    if (device_count >= MAX_DEVICES) return;

    // Step 1: Enable Slot
    const enable_slot_trb = TRB{
        .param_lo = 0,
        .param_hi = 0,
        .status = 0,
        .control = (TRB_ENABLE_SLOT << 10),
    };
    const evt = sendCommand(enable_slot_trb) orelse {
        debug.klog("[xhci] Enable Slot failed (no event)\n", .{});
        return;
    };

    const cc = @as(u8, @truncate(evt.status >> 24)); // Completion code
    if (cc != 1) { // 1 = Success
        debug.klog("[xhci] Enable Slot failed, cc={d}\n", .{cc});
        return;
    }
    const slot_id = @as(u8, @truncate(evt.control >> 24));
    debug.klog("[xhci] Slot {d} enabled for port {d}\n", .{ slot_id, port + 1 });

    // Step 2: Allocate Input Context + Device Context
    const input_ctx_phys = pmm.allocFrame() orelse return;
    const dev_ctx_phys = pmm.allocFrame() orelse return;
    const tr_phys = pmm.allocFrame() orelse return;
    // Map per-device DMA targets before the controller touches them.
    // input_ctx is read by ADDRESS_DEVICE / CONFIGURE_ENDPOINT; dev_ctx
    // and tr (transfer ring) are read/written on every URB.
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, input_ctx_phys, 4096, .{});
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, dev_ctx_phys, 4096, .{});
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, tr_phys, 4096, .{});

    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(input_ctx_phys)))[0..4096], 0);
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(dev_ctx_phys)))[0..4096], 0);
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(tr_phys)))[0..4096], 0);

    // Set DCBAA entry for this slot
    const dcbaa: [*]volatile u32 = @ptrFromInt(paging.physToVirt(dcbaa_phys));
    dcbaa[slot_id * 2] = @truncate(dev_ctx_phys); // Low 32 bits
    dcbaa[slot_id * 2 + 1] = @truncate(dev_ctx_phys >> 32); // High 32 bits

    // Fill Input Context
    const input_ctx: [*]volatile u32 = @ptrFromInt(paging.physToVirt(input_ctx_phys));

    // Input Control Context (first 32 bytes): Add flags for Slot (bit 0) and EP0 (bit 1)
    input_ctx[1] = 0x03; // Add Context flags: A0 (Slot) + A1 (EP0)

    // Slot Context (offset 32 bytes = 8 dwords)
    const slot_ctx = @as([*]volatile u32, @ptrFromInt(paging.physToVirt(input_ctx_phys + CTX_SIZE)));
    // Dword 0: Route String (0) | Speed | Context Entries (1 = just EP0)
    const speed_val: u32 = @as(u32, speed) << 20;
    slot_ctx[0] = speed_val | (1 << 27); // Context Entries = 1
    // Dword 1: Root Hub Port Number
    slot_ctx[1] = (@as(u32, port) + 1) << 16; // Root Hub Port Number (1-based)

    // EP0 Context (offset 64 bytes = 16 dwords)
    const ep0_ctx = @as([*]volatile u32, @ptrFromInt(paging.physToVirt(input_ctx_phys + CTX_SIZE * 2)));
    // Dword 1: EP Type (4=Control Bi), MaxPacketSize, CErr=3
    const max_packet: u32 = switch (speed) {
        SPEED_LOW => 8,
        SPEED_FULL => 64,
        SPEED_HIGH => 64,
        SPEED_SUPER => 512,
        else => 64,
    };
    ep0_ctx[1] = (4 << 3) | (3 << 1) | (max_packet << 16); // EP Type=Control, CErr=3
    // Dword 2-3: TR Dequeue Pointer (physical address of transfer ring | DCS=1)
    ep0_ctx[2] = @truncate(tr_phys | 1); // DCS = 1
    ep0_ctx[3] = @truncate(tr_phys >> 32);
    // Dword 4: Average TRB Length
    ep0_ctx[4] = 8; // Control transfers average 8 bytes

    // Step 3: Address Device command
    const addr_dev_trb = TRB{
        .param_lo = @truncate(input_ctx_phys),
        .param_hi = @truncate(input_ctx_phys >> 32),
        .status = 0,
        .control = (TRB_ADDRESS_DEVICE << 10) | (@as(u32, slot_id) << 24),
    };

    // Create EP0 transfer ring
    var ep0_ring = Ring{
        .trbs = @ptrFromInt(paging.physToVirt(tr_phys)),
        .phys = tr_phys,
        .enqueue = 0,
        .cycle = true,
    };

    const addr_evt = sendCommand(addr_dev_trb) orelse {
        debug.klog("[xhci] Address Device failed (no event)\n", .{});
        return;
    };
    const addr_cc = @as(u8, @truncate(addr_evt.status >> 24));
    if (addr_cc != 1) {
        debug.klog("[xhci] Address Device failed, cc={d}\n", .{addr_cc});
        return;
    }
    debug.klog("[xhci] Device addressed on slot {d}\n", .{slot_id});

    // Step 4: GET_DESCRIPTOR (Device Descriptor)
    var desc_buf: [18]u8 = [_]u8{0} ** 18;
    if (!controlTransfer(&ep0_ring, slot_id, 0x80, REQ_GET_DESCRIPTOR, (DESC_DEVICE << 8), 0, &desc_buf, 18)) {
        debug.klog("[xhci] GET_DESCRIPTOR (device) failed\n", .{});
        return;
    }

    const dev_class = desc_buf[4];
    const num_configs = desc_buf[17];
    debug.klog("[xhci] Device: class={d} configs={d}\n", .{ dev_class, num_configs });

    // Step 5: GET_DESCRIPTOR (Configuration Descriptor)
    var config_buf: [256]u8 = [_]u8{0} ** 256;
    if (!controlTransfer(&ep0_ring, slot_id, 0x80, REQ_GET_DESCRIPTOR, (DESC_CONFIGURATION << 8), 0, &config_buf, 256)) {
        debug.klog("[xhci] GET_DESCRIPTOR (config) failed\n", .{});
        return;
    }

    const config_val = config_buf[5];
    const total_len = @as(u16, config_buf[3]) << 8 | @as(u16, config_buf[2]);
    debug.klog("[xhci] Config: value={d} total_len={d}\n", .{ config_val, total_len });

    // Step 6: SET_CONFIGURATION
    if (!controlTransfer(&ep0_ring, slot_id, 0x00, REQ_SET_CONFIGURATION, config_val, 0, null, 0)) {
        debug.klog("[xhci] SET_CONFIGURATION failed\n", .{});
        return;
    }
    debug.klog("[xhci] Configuration {d} set\n", .{config_val});

    // Step 7: Parse config descriptor for HID interfaces
    var is_kbd = false;
    var is_mouse = false;
    var is_tablet = false;
    var is_msc = false;
    var intr_ep_addr: u8 = 0;
    var intr_ep_max_packet: u16 = 0;
    var intr_ep_interval: u8 = 0;
    var bulk_in_addr: u8 = 0;
    var bulk_in_max_packet: u16 = 0;
    var bulk_out_addr: u8 = 0;
    var bulk_out_max_packet: u16 = 0;

    // UAS (USB Attached SCSI) detection state. A UAS interface advertises
    // protocol 0x62; its four bulk endpoints are each bound to a logical
    // pipe by a following Pipe Usage Descriptor, and (on SuperSpeed) carry a
    // companion descriptor with the stream count.
    var is_uas = false;
    var cur_iface_uas = false; // are we inside the UAS interface right now?
    var uas_alt: u8 = 0;
    var uas_cmd_ep: u8 = 0;
    var uas_cmd_mp: u16 = 0;
    var uas_status_ep: u8 = 0;
    var uas_status_mp: u16 = 0;
    var uas_in_ep: u8 = 0;
    var uas_in_mp: u16 = 0;
    var uas_out_ep: u8 = 0;
    var uas_out_mp: u16 = 0;
    var uas_max_streams: u8 = 0;
    // The most recent endpoint seen inside the UAS interface, so the Pipe
    // Usage Descriptor that follows can bind it to a role.
    var last_ep_addr: u8 = 0;
    var last_ep_mp: u16 = 0;

    var offset: u16 = 0;
    const parse_len = @min(total_len, 256);
    while (offset + 2 <= parse_len) {
        const dlen = config_buf[offset];
        const dtype = config_buf[offset + 1];
        if (dlen == 0) break;

        if (dtype == DESC_INTERFACE and offset + 9 <= parse_len) {
            const ialt = config_buf[offset + 3];
            const iclass = config_buf[offset + 5];
            const isubclass = config_buf[offset + 6];
            const iprotocol = config_buf[offset + 7];
            // A new interface descriptor ends any prior interface's UAS scope.
            cur_iface_uas = false;
            if (iclass == USB_CLASS_HID) {
                if (isubclass == HID_SUBCLASS_BOOT and iprotocol == HID_PROTOCOL_KEYBOARD) {
                    is_kbd = true;
                    debug.klog("[xhci] Found HID Boot Keyboard\n", .{});
                } else if (isubclass == HID_SUBCLASS_BOOT and iprotocol == HID_PROTOCOL_MOUSE) {
                    is_mouse = true;
                    debug.klog("[xhci] Found HID Boot Mouse\n", .{});
                } else if (iprotocol == 0) {
                    // Non-boot HID device (e.g. USB tablet with absolute coordinates)
                    is_tablet = true;
                    debug.klog("[xhci] Found HID Tablet/Pointer\n", .{});
                }
            } else if (iclass == USB_CLASS_MSC and isubclass == MSC_SUBCLASS_SCSI) {
                if (iprotocol == MSC_PROTOCOL_BOT) {
                    is_msc = true;
                    debug.klog("[xhci] Found USB Mass Storage (SCSI BOT)\n", .{});
                } else if (iprotocol == MSC_PROTOCOL_UAS) {
                    is_uas = true;
                    cur_iface_uas = true;
                    uas_alt = ialt;
                    debug.klog("[xhci] Found USB Attached SCSI (UAS), alt={d}\n", .{ialt});
                }
            }
        }

        if (dtype == DESC_ENDPOINT and offset + 7 <= parse_len) {
            const ep_addr = config_buf[offset + 2];
            const ep_attr = config_buf[offset + 3];
            const ep_max = @as(u16, config_buf[offset + 5]) << 8 | @as(u16, config_buf[offset + 4]);
            const ep_type = ep_attr & 0x03;
            const ep_dir_in = (ep_addr & 0x80) != 0;

            if (cur_iface_uas) {
                // Inside the UAS interface: stash this endpoint so the Pipe
                // Usage Descriptor that follows binds it to a role. Don't
                // touch bulk_in/out — those drive the (separate) BOT path so
                // a UAS-only device never accidentally lights up is_msc.
                last_ep_addr = ep_addr;
                last_ep_mp = ep_max;
            } else if (ep_type == 0x03 and ep_dir_in) { // Interrupt IN
                intr_ep_addr = ep_addr;
                intr_ep_max_packet = ep_max;
                intr_ep_interval = config_buf[offset + 6];
                debug.klog("[xhci] Interrupt EP: addr=0x{x} maxpkt={d}\n", .{ ep_addr, ep_max });
            } else if (ep_type == 0x02) { // Bulk
                if (ep_dir_in) {
                    bulk_in_addr = ep_addr;
                    bulk_in_max_packet = ep_max;
                    debug.klog("[xhci] Bulk IN EP: addr=0x{x} maxpkt={d}\n", .{ ep_addr, ep_max });
                } else {
                    bulk_out_addr = ep_addr;
                    bulk_out_max_packet = ep_max;
                    debug.klog("[xhci] Bulk OUT EP: addr=0x{x} maxpkt={d}\n", .{ ep_addr, ep_max });
                }
            }
        }

        // UAS Pipe Usage Descriptor (follows each UAS endpoint): bPipeID at
        // +2 binds the most-recent endpoint to a logical pipe.
        if (cur_iface_uas and dtype == DESC_PIPE_USAGE and offset + 3 <= parse_len) {
            switch (config_buf[offset + 2]) {
                UAS_PIPE_COMMAND => {
                    uas_cmd_ep = last_ep_addr;
                    uas_cmd_mp = last_ep_mp;
                },
                UAS_PIPE_STATUS => {
                    uas_status_ep = last_ep_addr;
                    uas_status_mp = last_ep_mp;
                },
                UAS_PIPE_DATA_IN => {
                    uas_in_ep = last_ep_addr;
                    uas_in_mp = last_ep_mp;
                },
                UAS_PIPE_DATA_OUT => {
                    uas_out_ep = last_ep_addr;
                    uas_out_mp = last_ep_mp;
                },
                else => {},
            }
        }

        // SuperSpeed Endpoint Companion (follows each SS endpoint): bMaxStreams
        // in the low 5 bits of bmAttributes (+3) → stream count = 2^bMaxStreams.
        if (cur_iface_uas and dtype == DESC_SS_EP_COMPANION and offset + 4 <= parse_len) {
            const bmax = config_buf[offset + 3] & 0x1F;
            if (bmax > uas_max_streams) uas_max_streams = bmax;
        }

        offset += dlen;
    }

    if (!is_kbd and !is_mouse and !is_tablet and !is_msc and !is_uas) {
        debug.klog("[xhci] Unknown device class, skipping\n", .{});
        return;
    }

    // UAS detected (Slice U1 = detection only). Record the pipe map + stream
    // count for the stream setup + IU transport that land in U2/U3. The
    // device is NOT added to devices[] and its endpoints are NOT yet
    // configured, so it stays inert for now. We fall through rather than
    // return: a hybrid device that also exposes a BOT alt-setting still gets
    // its BOT endpoints configured below as a working fallback.
    if (is_uas) {
        uas_dev = .{
            .present = true,
            .slot_id = slot_id,
            .port = port,
            .speed = speed,
            .dev_ctx_phys = dev_ctx_phys,
            .alt = uas_alt,
            .cmd_ep = uas_cmd_ep,
            .cmd_mp = uas_cmd_mp,
            .status_ep = uas_status_ep,
            .status_mp = uas_status_mp,
            .in_ep = uas_in_ep,
            .in_mp = uas_in_mp,
            .out_ep = uas_out_ep,
            .out_mp = uas_out_mp,
            .max_streams = uas_max_streams,
        };
        const nstreams: u32 = if (uas_max_streams == 0)
            0
        else
            (@as(u32, 1) << @as(u5, @truncate(uas_max_streams)));
        debug.klog("[xhci] UAS pipes: cmd=0x{x} status=0x{x} data-in=0x{x} data-out=0x{x}\n", .{ uas_cmd_ep, uas_status_ep, uas_in_ep, uas_out_ep });
        debug.klog("[xhci] UAS streams: bMaxStreams={d} ({d} streams), speed={d}{s}, slot={d}\n", .{ uas_max_streams, nstreams, speed, if (speed == SPEED_SUPER) " SuperSpeed" else "", slot_id });
    }

    // HID-specific setup
    if (is_kbd or is_mouse) {
        // Boot protocol devices: force boot protocol + idle
        _ = controlTransfer(&ep0_ring, slot_id, 0x21, REQ_SET_PROTOCOL, 0, 0, null, 0);
        _ = controlTransfer(&ep0_ring, slot_id, 0x21, REQ_SET_IDLE, 0, 0, null, 0);
    }
    // Skip SET_IDLE for tablets — QEMU usb-tablet may STALL on it

    // Step 9: Configure Endpoint — set up interrupt endpoint
    if (intr_ep_addr != 0) {
        const ep_num = intr_ep_addr & 0x0F;
        const ep_dir: u8 = if (intr_ep_addr & 0x80 != 0) 1 else 0; // 1=IN
        const dci = ep_num * 2 + ep_dir; // Device Context Index

        // Allocate large interrupt transfer ring (16 pages, no Link TRB)
        const intr_ring = initTransferRing() orelse return;
        const intr_tr_phys = intr_ring.phys;
        _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, intr_tr_phys, 4096, .{});

        // Configure Endpoint Input Context
        @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(input_ctx_phys)))[0..4096], 0);
        // Add context flag for this EP + Slot
        const add_flags: u32 = (1 << 0) | (@as(u32, 1) << @as(u5, @truncate(dci)));
        input_ctx[1] = add_flags;

        // Slot context: update context entries
        slot_ctx[0] = speed_val | (@as(u32, dci) << 27); // Context Entries = dci

        // EP context at offset CTX_SIZE * (dci + 1) from input context start
        const ep_ctx = @as([*]volatile u32, @ptrFromInt(paging.physToVirt(input_ctx_phys + CTX_SIZE * (@as(u32, dci) + 1))));
        // EP Type: 7=Interrupt IN, CErr=3, MaxPacketSize, Interval
        const interval_val: u32 = if (speed == SPEED_HIGH or speed == SPEED_SUPER)
            @as(u32, intr_ep_interval) // Already encoded
        else
            intervalToExponent(intr_ep_interval); // Convert ms to exponent
        ep_ctx[0] = interval_val << 16; // Interval
        ep_ctx[1] = (7 << 3) | (3 << 1) | (@as(u32, intr_ep_max_packet) << 16); // EP Type=Interrupt IN, CErr=3
        ep_ctx[2] = @truncate(intr_tr_phys | 1); // TR Dequeue Pointer | DCS
        ep_ctx[3] = @truncate(intr_tr_phys >> 32);
        ep_ctx[4] = intr_ep_max_packet; // Average TRB Length

        // Send Configure Endpoint command
        const cfg_trb = TRB{
            .param_lo = @truncate(input_ctx_phys),
            .param_hi = @truncate(input_ctx_phys >> 32),
            .status = 0,
            .control = (TRB_CONFIGURE_EP << 10) | (@as(u32, slot_id) << 24),
        };
        const cfg_evt = sendCommand(cfg_trb) orelse {
            debug.klog("[xhci] Configure Endpoint failed (no event)\n", .{});
            return;
        };
        const cfg_cc = @as(u8, @truncate(cfg_evt.status >> 24));
        if (cfg_cc != 1) {
            debug.klog("[xhci] Configure Endpoint failed, cc={d}\n", .{cfg_cc});
            return;
        }
        debug.klog("[xhci] Endpoint configured, DCI={d}\n", .{dci});

        // Allocate per-device data buffer page
        const dev_data_phys = pmm.allocFrame() orelse return;
        @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(dev_data_phys)))[0..4096], 0);
        _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, dev_data_phys, 4096, .{});

        // Save device state
        const di = device_count;
        // Store ring in separate array to avoid optional pointer issues
        hid_rings[di] = Ring{
            .trbs = @ptrFromInt(paging.physToVirt(intr_tr_phys)),
            .phys = intr_tr_phys,
            .enqueue = 0,
            .cycle = true,
        };
        hid_ring_active[di] = true;
        devices[di] = .{
            .slot_id = slot_id,
            .port = port,
            .speed = speed,
            .active = true,
            .is_keyboard = is_kbd,
            .is_mouse = is_mouse,
            .is_tablet = is_tablet,
            .dev_ctx_phys = dev_ctx_phys,
            .tr_ring = null, // rings stored in hid_rings[] instead
            .ep_dci = dci,
            .data_phys = dev_data_phys,
        };
        device_count += 1;

        // Queue initial interrupt transfer TRBs
        queueInterruptTransfers(di);

        debug.klog("[xhci] HID device ready: {s}\n", .{if (is_kbd) "Keyboard" else "Mouse"});
    }

    // Step 10: Configure MSC bulk endpoints
    if (is_msc and bulk_in_addr != 0 and bulk_out_addr != 0) {
        const in_num = bulk_in_addr & 0x0F;
        const in_dci = in_num * 2 + 1; // IN
        const out_num = bulk_out_addr & 0x0F;
        const out_dci = out_num * 2; // OUT
        const max_dci = @max(in_dci, out_dci);

        // Allocate bulk transfer rings (16 pages each, linear)
        const bulk_in_ring = initTransferRing() orelse return;
        const bulk_out_ring_r = initTransferRing() orelse return;
        _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, bulk_in_ring.phys, 4096, .{});
        _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, bulk_out_ring_r.phys, 4096, .{});

        // Configure Endpoint Input Context for both bulk endpoints
        @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(input_ctx_phys)))[0..4096], 0);
        const add_flags: u32 = (1 << 0) | (@as(u32, 1) << @as(u5, @truncate(in_dci))) | (@as(u32, 1) << @as(u5, @truncate(out_dci)));
        input_ctx[1] = add_flags;

        // Slot context
        slot_ctx[0] = speed_val | (@as(u32, max_dci) << 27);

        // Bulk IN endpoint context
        const ep_in_ctx = @as([*]volatile u32, @ptrFromInt(paging.physToVirt(input_ctx_phys + CTX_SIZE * (@as(u32, in_dci) + 1))));
        ep_in_ctx[0] = 0; // No interval for bulk
        ep_in_ctx[1] = (6 << 3) | (3 << 1) | (@as(u32, bulk_in_max_packet) << 16); // EP Type=6 (Bulk IN), CErr=3
        ep_in_ctx[2] = @truncate(bulk_in_ring.phys | 1); // TR Dequeue | DCS
        ep_in_ctx[3] = @truncate(bulk_in_ring.phys >> 32);
        ep_in_ctx[4] = bulk_in_max_packet; // Average TRB Length

        // Bulk OUT endpoint context
        const ep_out_ctx = @as([*]volatile u32, @ptrFromInt(paging.physToVirt(input_ctx_phys + CTX_SIZE * (@as(u32, out_dci) + 1))));
        ep_out_ctx[0] = 0;
        ep_out_ctx[1] = (2 << 3) | (3 << 1) | (@as(u32, bulk_out_max_packet) << 16); // EP Type=2 (Bulk OUT), CErr=3
        ep_out_ctx[2] = @truncate(bulk_out_ring_r.phys | 1);
        ep_out_ctx[3] = @truncate(bulk_out_ring_r.phys >> 32);
        ep_out_ctx[4] = bulk_out_max_packet;

        // Send Configure Endpoint command
        const cfg_trb = TRB{
            .param_lo = @truncate(input_ctx_phys),
            .param_hi = @truncate(input_ctx_phys >> 32),
            .status = 0,
            .control = (TRB_CONFIGURE_EP << 10) | (@as(u32, slot_id) << 24),
        };
        const cfg_evt = sendCommand(cfg_trb) orelse {
            debug.klog("[xhci] MSC Configure Endpoint failed (no event)\n", .{});
            return;
        };
        const cfg_cc = @as(u8, @truncate(cfg_evt.status >> 24));
        if (cfg_cc != 1) {
            debug.klog("[xhci] MSC Configure Endpoint failed, cc={d}\n", .{cfg_cc});
            return;
        }
        debug.klog("[xhci] MSC endpoints configured: IN DCI={d} OUT DCI={d}\n", .{ in_dci, out_dci });

        // Allocate data buffer page for MSC
        const msc_data_phys = pmm.allocFrame() orelse return;
        @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(msc_data_phys)))[0..4096], 0);
        _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, msc_data_phys, 4096, .{});

        const di = device_count;
        devices[di] = .{
            .slot_id = slot_id,
            .port = port,
            .speed = speed,
            .active = true,
            .is_msc = true,
            .dev_ctx_phys = dev_ctx_phys,
            .tr_ring = bulk_in_ring,
            .ep_dci = in_dci,
            .data_phys = msc_data_phys,
            .bulk_out_ring = bulk_out_ring_r,
            .bulk_out_dci = out_dci,
            .msc_max_packet = bulk_in_max_packet,
        };
        device_count += 1;

        // Probe disk: INQUIRY + READ CAPACITY
        mscProbe(di);
    }
}

// --- USB Mass Storage (SCSI BOT) ---

const CBW_SIGNATURE: u32 = 0x43425355; // "USBC"
const CSW_SIGNATURE: u32 = 0x53425355; // "USBS"
const CBW_SIZE: u32 = 31;
const CSW_SIZE: u32 = 13;

fn mscProbe(dev_idx: u8) void {
    // SCSI INQUIRY
    var inquiry_buf: [36]u8 = [_]u8{0} ** 36;
    if (mscScsiCommand(dev_idx, &[_]u8{ 0x12, 0, 0, 0, 36, 0 }, 6, &inquiry_buf, 36, true)) {
        // Parse vendor/product from inquiry
        debug.klog("[xhci] MSC INQUIRY OK\n", .{});
    } else {
        debug.klog("[xhci] MSC INQUIRY failed\n", .{});
    }

    // SCSI TEST UNIT READY
    _ = mscScsiCommand(dev_idx, &[_]u8{ 0x00, 0, 0, 0, 0, 0 }, 6, null, 0, false);

    // SCSI READ CAPACITY(10)
    var cap_buf: [8]u8 = [_]u8{0} ** 8;
    if (mscScsiCommand(dev_idx, &[_]u8{ 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 10, &cap_buf, 8, true)) {
        const last_lba = @as(u32, cap_buf[0]) << 24 | @as(u32, cap_buf[1]) << 16 | @as(u32, cap_buf[2]) << 8 | @as(u32, cap_buf[3]);
        const block_size = @as(u32, cap_buf[4]) << 24 | @as(u32, cap_buf[5]) << 16 | @as(u32, cap_buf[6]) << 8 | @as(u32, cap_buf[7]);
        devices[dev_idx].msc_block_count = last_lba + 1;
        devices[dev_idx].msc_block_size = block_size;
        const size_mb = (last_lba + 1) / (1048576 / block_size);
        debug.klog("[xhci] MSC disk: {d} blocks x {d} bytes = {d} MB\n", .{ last_lba + 1, block_size, size_mb });
    } else {
        debug.klog("[xhci] MSC READ CAPACITY failed\n", .{});
    }
}

/// Send a SCSI command via Bulk-Only Transport (CBW/Data/CSW).
fn mscScsiCommand(dev_idx: u8, cdb: []const u8, cdb_len: u8, data: ?[*]u8, data_len: u32, data_in: bool) bool {
    msc_locks[dev_idx].acquire();
    defer msc_locks[dev_idx].release();
    // Block pollHID from draining MSC TRANSFER events before our
    // waitForEvent calls see them — set BEFORE the first doorbell.
    event_drain_locked = true;
    defer event_drain_locked = false;
    const dev = &devices[dev_idx];
    const data_phys = dev.data_phys;

    // Build CBW at data_phys offset 0
    const cbw: [*]volatile u8 = @ptrFromInt(paging.physToVirt(data_phys));
    @memset(cbw[0..CBW_SIZE], 0);

    // CBW Signature (little-endian)
    cbw[0] = @truncate(CBW_SIGNATURE);
    cbw[1] = @truncate(CBW_SIGNATURE >> 8);
    cbw[2] = @truncate(CBW_SIGNATURE >> 16);
    cbw[3] = @truncate(CBW_SIGNATURE >> 24);

    // Tag
    const tag = dev.msc_tag;
    dev.msc_tag +%= 1;
    cbw[4] = @truncate(tag);
    cbw[5] = @truncate(tag >> 8);
    cbw[6] = @truncate(tag >> 16);
    cbw[7] = @truncate(tag >> 24);

    // Data Transfer Length
    cbw[8] = @truncate(data_len);
    cbw[9] = @truncate(data_len >> 8);
    cbw[10] = @truncate(data_len >> 16);
    cbw[11] = @truncate(data_len >> 24);

    // Flags (bit 7: 0=OUT, 1=IN)
    cbw[12] = if (data_in) 0x80 else 0x00;

    // LUN = 0
    cbw[13] = 0;

    // CDB Length
    cbw[14] = cdb_len;

    // Copy CDB
    const cdb_n = @min(cdb.len, 16);
    @memcpy(cbw[15..][0..cdb_n], cdb[0..cdb_n]);

    // Send CBW via Bulk OUT
    const out_ring = &(dev.bulk_out_ring orelse return false);
    const cbw_trb = TRB{
        .param_lo = @truncate(data_phys), // CBW at offset 0
        .param_hi = @truncate(data_phys >> 32),
        .status = CBW_SIZE,
        .control = (TRB_NORMAL << 10) | (1 << 5), // IOC
    };
    ringEnqueue(out_ring, cbw_trb);
    ringDoorbell(dev.slot_id, dev.bulk_out_dci);

    // Wait for CBW transfer completion
    if (waitForEvent(TRB_EVENT_TRANSFER, 500000) == null) {
        debug.klog("[xhci] MSC CBW send timeout\n", .{});
        return false;
    }

    // Data phase (if any)
    if (data_len > 0) {
        const data_buf_phys = data_phys + 512; // Data at offset 512 in data page
        if (data_in) {
            // Bulk IN
            const in_ring = &(dev.tr_ring orelse return false);
            const data_trb = TRB{
                .param_lo = @truncate(data_buf_phys),
                .param_hi = @truncate(data_buf_phys >> 32),
                .status = data_len,
                .control = (TRB_NORMAL << 10) | (1 << 5),
            };
            ringEnqueue(in_ring, data_trb);
            ringDoorbell(dev.slot_id, dev.ep_dci);
        } else {
            // Bulk OUT — copy data to buffer first
            if (data) |src| {
                const dst: [*]u8 = @ptrFromInt(paging.physToVirt(data_buf_phys));
                @memcpy(dst[0..data_len], src[0..data_len]);
            }
            const data_trb = TRB{
                .param_lo = @truncate(data_buf_phys),
                .param_hi = @truncate(data_buf_phys >> 32),
                .status = data_len,
                .control = (TRB_NORMAL << 10) | (1 << 5),
            };
            ringEnqueue(out_ring, data_trb);
            ringDoorbell(dev.slot_id, dev.bulk_out_dci);
        }

        // Wait for data transfer completion
        if (waitForEvent(TRB_EVENT_TRANSFER, 500000) == null) {
            debug.klog("[xhci] MSC data transfer timeout\n", .{});
            return false;
        }

        // Copy IN data out
        if (data_in and data != null) {
            const src: [*]const u8 = @ptrFromInt(paging.physToVirt(data_buf_phys));
            const dst = data.?;
            @memcpy(dst[0..data_len], src[0..data_len]);
        }
    }

    // CSW phase — read via Bulk IN
    const csw_phys = data_phys + 1024; // CSW at offset 1024
    const in_ring = &(dev.tr_ring orelse return false);
    const csw_trb = TRB{
        .param_lo = @truncate(csw_phys),
        .param_hi = @truncate(csw_phys >> 32),
        .status = CSW_SIZE,
        .control = (TRB_NORMAL << 10) | (1 << 5),
    };
    ringEnqueue(in_ring, csw_trb);
    ringDoorbell(dev.slot_id, dev.ep_dci);

    if (waitForEvent(TRB_EVENT_TRANSFER, 500000) == null) {
        debug.klog("[xhci] MSC CSW timeout\n", .{});
        return false;
    }

    // Verify CSW
    const csw: [*]const volatile u8 = @ptrFromInt(paging.physToVirt(csw_phys));
    const csw_sig = @as(u32, csw[0]) | @as(u32, csw[1]) << 8 | @as(u32, csw[2]) << 16 | @as(u32, csw[3]) << 24;
    const csw_status = csw[12];
    if (csw_sig != CSW_SIGNATURE or csw_status != 0) {
        debug.klog("[xhci] MSC CSW error: sig=0x{x} status={d}\n", .{ csw_sig, csw_status });
        return false;
    }

    return true;
}

/// True if a UAS device was detected during enumeration.
pub fn uasPresent() bool {
    return uas_dev.present;
}

/// Report the detected UAS device (Slice U1 = detection). Pub so the `uas`
/// CLI command and later slices can query it. Logs the pipe map + stream
/// count; klog tees to the VGA console so this prints from the shell.
pub fn uasReport() void {
    if (!uas_dev.present) {
        debug.klog("[uas] no UAS device detected on the USB bus\n", .{});
        return;
    }
    const d = uas_dev;
    const nstreams: u32 = if (d.max_streams == 0)
        0
    else
        (@as(u32, 1) << @as(u5, @truncate(d.max_streams)));
    debug.klog("[uas] device: slot {d}, port {d}, speed {d}{s}, UAS alt-setting {d}\n", .{
        d.slot_id, d.port + 1, d.speed,
        if (d.speed == SPEED_SUPER) " (SuperSpeed)" else "",
        d.alt,
    });
    debug.klog("[uas]   pipes: cmd ep0x{x} | status ep0x{x} | data-in ep0x{x} | data-out ep0x{x}\n", .{
        d.cmd_ep, d.status_ep, d.in_ep, d.out_ep,
    });
    debug.klog("[uas]   streams: bMaxStreams={d} -> {d} stream(s){s}\n", .{
        d.max_streams, nstreams,
        if (nstreams == 0) "  (no streams — device not at SuperSpeed)" else "",
    });
    debug.klog("[uas]   transport: pending (U2 stream contexts / U3 IU flow not yet implemented)\n", .{});
}

/// Read `count` sectors starting at `lba` into `buf`. mscScsiCommand uses
/// a 512-byte staging area at offset 512..1024 of the per-device data page
/// (with CSW at 1024), so we issue one READ(10) per sector — anything more
/// would overflow the staging area into the CSW slot. Slow but correct;
/// can be sped up later by enlarging the data buffer to span more sectors.
pub fn mscReadSectors(lba: u32, count: u16, buf: [*]u8) bool {
    var dev_idx: ?u8 = null;
    for (0..device_count) |i| {
        if (devices[i].active and devices[i].is_msc) {
            dev_idx = @intCast(i);
            break;
        }
    }
    const di = dev_idx orelse return false;
    const block_size = devices[di].msc_block_size;

    var i: u16 = 0;
    while (i < count) : (i += 1) {
        const cur_lba = lba + i;
        var cdb: [10]u8 = [_]u8{0} ** 10;
        cdb[0] = 0x28; // READ(10)
        cdb[2] = @truncate(cur_lba >> 24);
        cdb[3] = @truncate(cur_lba >> 16);
        cdb[4] = @truncate(cur_lba >> 8);
        cdb[5] = @truncate(cur_lba);
        cdb[7] = 0;
        cdb[8] = 1; // single sector per call
        const off = @as(u32, i) * block_size;
        const dst: [*]u8 = buf + off;
        if (!mscScsiCommand(di, &cdb, 10, dst, block_size, true)) return false;
    }
    return true;
}

pub fn hasMscDevice() bool {
    for (0..device_count) |i| {
        if (devices[i].active and devices[i].is_msc) return true;
    }
    return false;
}

/// Write `count` blocks starting at `lba` from `buf`. Mirror of
/// mscReadSectors using SCSI WRITE(10) (opcode 0x2A) instead of READ(10).
/// Returns true on success.
pub fn mscWriteSectors(lba: u32, count: u16, buf: [*]const u8) bool {
    var dev_idx: ?u8 = null;
    for (0..device_count) |i| {
        if (devices[i].active and devices[i].is_msc) {
            dev_idx = @intCast(i);
            break;
        }
    }
    const di = dev_idx orelse return false;
    const block_size = devices[di].msc_block_size;
    const total_bytes = @as(u32, count) * block_size;

    var cdb: [10]u8 = [_]u8{0} ** 10;
    cdb[0] = 0x2A; // WRITE(10)
    cdb[2] = @truncate(lba >> 24);
    cdb[3] = @truncate(lba >> 16);
    cdb[4] = @truncate(lba >> 8);
    cdb[5] = @truncate(lba);
    cdb[7] = @truncate(count >> 8);
    cdb[8] = @truncate(count);

    // mscScsiCommand currently only reads through dev.data_phys. WRITE flow
    // needs a writable buffer-of-bytes, so we cast away const — the kernel
    // copies bytes out of it before issuing the bulk-out, never modifying it.
    const mut: [*]u8 = @constCast(buf);
    return mscScsiCommand(di, &cdb, 10, mut, total_bytes, false);
}

pub fn getMscBlockSize() u32 {
    for (0..device_count) |i| {
        if (devices[i].active and devices[i].is_msc) return devices[i].msc_block_size;
    }
    return 0;
}

pub fn getMscBlockCount() u32 {
    for (0..device_count) |i| {
        if (devices[i].active and devices[i].is_msc) return devices[i].msc_block_count;
    }
    return 0;
}

fn intervalToExponent(ms_interval: u8) u32 {
    // Convert milliseconds to xHCI interval exponent for Full/Low speed
    // xHCI uses 2^(interval-1) * 125us frames
    if (ms_interval <= 1) return 3; // 1ms
    if (ms_interval <= 2) return 4;
    if (ms_interval <= 4) return 5;
    if (ms_interval <= 8) return 6;
    if (ms_interval <= 16) return 7;
    return 8;
}

fn queueInterruptTransfers(dev_idx: u8) void {
    const slot = devices[dev_idx].slot_id;
    const dci = devices[dev_idx].ep_dci;
    const data_page = devices[dev_idx].data_phys;
    if (data_page == 0) return;
    if (!hid_ring_active[dev_idx]) return;
    const ring_ptr = &hid_rings[dev_idx];

    // Link TRB already written by initTransferRing()
    for (0..NUM_INTR_TRBS) |i| {
        const buf_offset = data_page + i * 16;
        const trb = TRB{
            .param_lo = @truncate(buf_offset),
            .param_hi = @truncate(buf_offset >> 32),
            .status = 8, // Always 8 bytes (prevents Babble Error on mice with extra buttons)
            .control = (TRB_NORMAL << 10) | (1 << 5), // IOC
        };
        ringEnqueue(ring_ptr, trb);
    }
    ringDoorbell(slot, dci);
}

// --- Control Transfer ---

fn controlTransfer(ring: *Ring, slot_id: u8, bmRequestType: u8, bRequest: u8, wValue: u16, wIndex: u16, data: ?[*]u8, wLength: u16) bool {
    // Setup TRB
    const setup_param: u32 = @as(u32, bmRequestType) |
        (@as(u32, bRequest) << 8) |
        (@as(u32, wValue) << 16);
    const setup_param_hi: u32 = @as(u32, wIndex) | (@as(u32, wLength) << 16);

    const trt: u32 = if (wLength > 0)
        (if (bmRequestType & 0x80 != 0) @as(u32, 3) else @as(u32, 2)) // 3=IN, 2=OUT
    else
        0; // No data stage

    const setup_trb = TRB{
        .param_lo = setup_param,
        .param_hi = setup_param_hi,
        .status = 8, // TRB transfer length = 8 for setup
        .control = (TRB_SETUP << 10) | (1 << 6) | (trt << 16), // IDT | TRT
    };
    ringEnqueue(ring, setup_trb);

    // Data TRB (if needed)
    if (wLength > 0) {
        // Use scratch buffer for data
        const data_dir: u32 = if (bmRequestType & 0x80 != 0) 1 else 0; // 1=IN
        const data_trb = TRB{
            .param_lo = @truncate(scratch_phys),
            .param_hi = @truncate(scratch_phys >> 32),
            .status = wLength,
            .control = (TRB_DATA << 10) | (data_dir << 16),
        };
        ringEnqueue(ring, data_trb);
    }

    // Status TRB
    const status_dir: u32 = if (wLength > 0 and bmRequestType & 0x80 != 0) 0 else 1; // Opposite of data
    const status_trb = TRB{
        .param_lo = 0,
        .param_hi = 0,
        .status = 0,
        .control = (TRB_STATUS << 10) | (status_dir << 16) | (1 << 5), // IOC
    };
    ringEnqueue(ring, status_trb);

    // Ring doorbell for EP0 (DCI=1)
    ringDoorbell(slot_id, 1);

    // Wait for transfer event
    const evt = waitForEvent(TRB_EVENT_TRANSFER, 500000) orelse return false;
    const cc = @as(u8, @truncate(evt.status >> 24));
    if (cc != 1 and cc != 13) { // 1=Success, 13=Short Packet (ok for descriptors)
        debug.klog("[xhci] Control transfer failed, cc={d}\n", .{cc});
        return false;
    }

    // Copy data out if IN transfer
    if (wLength > 0 and data != null and bmRequestType & 0x80 != 0) {
        const src: [*]const u8 = @ptrFromInt(paging.physToVirt(scratch_phys));
        const dst = data.?;
        @memcpy(dst[0..wLength], src[0..wLength]);
    }

    return true;
}

// --- HID Polling (called from desktop main loop) ---

// Diagnostic counters (readable from outside, no serial I/O in IRQ)
pub var poll_count: u32 = 0;
pub var event_count: u32 = 0;
pub var requeue_count: u32 = 0;
pub var wrap_count: u32 = 0;
var mouse_event_tick: u64 = 0;
var mouse_ever_worked: bool = false;
var mouse_requeue_count: u32 = 0;
var kbd_requeue_count: u32 = 0;
const MOUSE_WATCHDOG_TICKS: u64 = 500; // 5 seconds at 100Hz

pub fn pollHID() void {
    @import("../cpu/smp.zig").assertBSP("xhci.pollHID");
    // iretq-frame tripwire (task #230). pollHID runs every IRQ0 tick on
    // BSP and consumes user-mode pointers from completed transfer TRBs;
    // it's a prime candidate for wild writes during paint clicks. Check
    // at entry AND exit so we can distinguish "corrupted before pollHID"
    // from "corrupted by pollHID".
    @import("../debug/iretq_canary.zig").check(@src());
    defer @import("../debug/iretq_canary.zig").check(@src());
    if (!enumeration_done or device_count == 0) return;
    // sendCommand / mscScsiCommand are mid-flight on some CPU and have
    // claimed the event ring — deferring HID drain by one tick (10 ms)
    // is invisible to the user, while letting pollHID drain here would
    // race the awaited event out from under them.
    if (event_drain_locked) return;
    poll_count +%= 1;

    // Process all pending events from the event ring
    var processed: u32 = 0;
    while (processed < 128) : (processed += 1) {
        const evt_trb = evt_ring.trbs[evt_dequeue];
        const cycle_bit = (evt_trb.control & 1) != 0;
        if (cycle_bit != evt_cycle) break;

        const trb_type = @as(u8, @truncate((evt_trb.control >> 10) & 0x3F));
        const cc = @as(u8, @truncate(evt_trb.status >> 24));
        const slot_id = @as(u8, @truncate(evt_trb.control >> 24));

        evt_dequeue += 1;
        if (evt_dequeue >= EVT_RING_SIZE) {
            evt_dequeue = 0;
            evt_cycle = !evt_cycle;
            wrap_count +%= 1;
        }

        event_count +%= 1;
        if (trb_type != TRB_EVENT_TRANSFER) continue;

        var di: ?u8 = null;
        for (0..device_count) |i| {
            if (devices[i].slot_id == slot_id and devices[i].active) {
                di = @intCast(i);
                break;
            }
        }
        const dev_i = di orelse continue;

        const trb_ptr = evt_trb.param_lo;
        if (trb_ptr == 0) continue;
        // trb_ptr points at the data-stage TRB we issued — its phys was
        // written into the transfer ring; we read it back here. Map through
        // the physmap so kernel deref works without the legacy low identity.
        const completed_words: [*]volatile u32 = @ptrFromInt(paging.physToVirt(trb_ptr));
        const data_addr = completed_words[0];
        if (data_addr == 0) continue;

        // Only process data on success/short packet
        if (cc == 1 or cc == 13) {
            const data: [*]volatile const u8 = @ptrFromInt(paging.physToVirt(data_addr));
            if (devices[dev_i].is_keyboard) {
                processKeyboardReport(data);
            } else if (devices[dev_i].is_mouse or devices[dev_i].is_tablet) {
                if (devices[dev_i].is_tablet) {
                    processTabletReport(data);
                } else {
                    processMouseReport(data);
                }
                mouse_event_tick = process.tick_count;
                mouse_ever_worked = true;
            }
        }

        // ALWAYS re-queue TRB — even on errors! Otherwise the ring starves.
        if (hid_ring_active[dev_i]) {
            const ring = &hid_rings[dev_i];
            if (ring.enqueue < RING_SIZE - 1) {
                const idx = ring.enqueue;
                ring.trbs[idx].param_lo = data_addr;
                ring.trbs[idx].param_hi = 0;
                ring.trbs[idx].status = 8; // Always 8 bytes (prevents Babble Error)
                asm volatile ("sfence" ::: .{ .memory = true });
                ring.trbs[idx].control = (TRB_NORMAL << 10) | (1 << 5) |
                    (if (ring.cycle) @as(u32, 1) else @as(u32, 0));
                ring.enqueue = idx + 1;
                if (ring.enqueue >= RING_SIZE - 1) {
                    asm volatile ("sfence" ::: .{ .memory = true });
                    ring.trbs[RING_SIZE - 1].control = (TRB_LINK << 10) | (1 << 1) |
                        (if (ring.cycle) @as(u32, 1) else @as(u32, 0));
                    ring.enqueue = 0;
                    ring.cycle = !ring.cycle;
                }
            }
            requeue_count +%= 1;
            if (devices[dev_i].is_mouse or devices[dev_i].is_tablet) mouse_requeue_count +%= 1;
            if (devices[dev_i].is_keyboard) kbd_requeue_count +%= 1;
            // Doorbell immediately per event
            asm volatile ("sfence" ::: .{ .memory = true });
            ringDoorbell(devices[dev_i].slot_id, devices[dev_i].ep_dci);
        }
    }

    // Update ERDP once after processing all events
    if (processed > 0) {
        const erdp_phys = evt_ring.phys + @as(usize, evt_dequeue) * 16;
        const ir0_base = rt_base + 0x20;
        writeReg64(ir0_base + 0x18, erdp_phys | (1 << 3));
    }

    // Doorbells are rung per-event above (not batched).
    // No refill — each completed transfer is re-queued individually.
    // The ring self-sustains: 1 event in = 1 TRB re-queued.
    for (0..device_count) |i| {
        if (!devices[i].active) continue;
        if (devices[i].is_msc) continue;
        if (devices[i].tr_ring) |*ring| {
            _ = ring;
        }
    }

    // Watchdog: if mouse was working and stopped, flag for reset (done from main loop, not IRQ)
    // Skip watchdog for tablets — they only send events on actual movement
    if (mouse_ever_worked and !hasTabletDevice() and process.tick_count > mouse_event_tick + MOUSE_WATCHDOG_TICKS) {
        mouse_needs_reset = true;
        mouse_event_tick = process.tick_count;
        // Wake the event-driven compositor so the reset actually runs.
        // Without this, a wedged mouse would never recover because no
        // other input event can fire while the mouse is stuck.
        @import("../ui/desktop/wake.zig").requestWake();
    }
}

/// Flag: set by watchdog in IRQ context, consumed by desktop main loop
pub var mouse_needs_reset: bool = false;

/// Reset mouse transfer ring — MUST be called from main loop (not IRQ), needs interrupts enabled.
pub fn resetMouseRing() void {
    for (0..device_count) |i| {
        if ((!devices[i].is_mouse and !devices[i].is_tablet) or !devices[i].active) continue;

        const ring = &hid_rings[i];
        debug.klog("[xhci] Resetting mouse ring (enq={d})\n", .{ring.enqueue});

        // 1. Stop Endpoint
        const stop_result = sendCommand(TRB{
            .param_lo = 0, .param_hi = 0, .status = 0,
            .control = (TRB_STOP_EP << 10) | (@as(u32, devices[i].slot_id) << 24) | (@as(u32, devices[i].ep_dci) << 16),
        });
        debug.klog("[xhci] Stop EP: {s}\n", .{if (stop_result != null) "OK" else "FAIL"});

        // 2. Zero ring and reset state
        @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(ring.phys)))[0 .. RING_SIZE * 16], 0);
        // Rewrite Link TRB (zeroing destroyed it)
        ring.trbs[RING_SIZE - 1] = TRB{
            .param_lo = @truncate(ring.phys), .param_hi = @truncate(ring.phys >> 32), .status = 0,
            .control = (TRB_LINK << 10) | (1 << 1) | 1, // TC=bit1, Cycle=1
        };
        ring.enqueue = 0;
        ring.cycle = true;

        // 3. Set TR Dequeue Pointer
        const deq_result = sendCommand(TRB{
            .param_lo = @truncate(ring.phys | 1), .param_hi = @truncate(ring.phys >> 32), .status = 0,
            .control = (TRB_SET_TR_DEQUEUE << 10) | (@as(u32, devices[i].slot_id) << 24) | (@as(u32, devices[i].ep_dci) << 16),
        });
        debug.klog("[xhci] Set TR Dequeue: {s}\n", .{if (deq_result != null) "OK" else "FAIL"});

        // 4. Refill with unique buffers and correct size (8 bytes to avoid Babble Error)
        const data_page = devices[i].data_phys;
        if (data_page != 0) {
            var fill: u32 = 0;
            while (fill < NUM_INTR_TRBS) : (fill += 1) {
                const buf_offset = data_page + @as(usize, fill) * 16;
                ringEnqueue(ring, TRB{
                    .param_lo = @truncate(buf_offset), .param_hi = @truncate(buf_offset >> 32),
                    .status = 8,
                    .control = (TRB_NORMAL << 10) | (1 << 5),
                });
            }
        }

        // 5. Doorbell
        ringDoorbell(devices[i].slot_id, devices[i].ep_dci);
        mouse_needs_reset = false;
        mouse_event_tick = process.tick_count;
        debug.klog("[xhci] Mouse ring reset done, enq={d}\n", .{ring.enqueue});
    }
}

// --- HID Report Processing ---

// Boot keyboard report: [modifier, reserved, key1, key2, key3, key4, key5, key6]
var prev_keys: [6]u8 = [_]u8{0} ** 6;

fn processKeyboardReport(data: [*]volatile const u8) void {
    const modifiers = data[0];
    // Check modifier changes
    keyboard.shift_held = (modifiers & 0x22) != 0; // Left or Right Shift
    keyboard.ctrl_held = (modifiers & 0x11) != 0; // Left or Right Ctrl
    keyboard.alt_held = (modifiers & 0x44) != 0; // Left or Right Alt
    keyboard.mods.shift = keyboard.shift_held;
    keyboard.mods.ctrl = keyboard.ctrl_held;
    keyboard.mods.alt = keyboard.alt_held;

    // Set key_state for modifier keys so keyHeld() works for Ctrl/Shift/Alt
    keyboard.key_state[0x1D] = keyboard.ctrl_held; // Ctrl
    keyboard.key_state[0x2A] = (modifiers & 0x02) != 0; // LShift
    keyboard.key_state[0x36] = (modifiers & 0x20) != 0; // RShift
    keyboard.key_state[0x38] = keyboard.alt_held; // Alt

    // Process key presses (data[2..8])
    var ki: u8 = 0;
    while (ki < 6) : (ki += 1) {
        const key = data[2 + ki];
        if (key == 0) continue;

        // Check if this key was already pressed
        var was_pressed = false;
        for (&prev_keys) |pk| {
            if (pk == key) { was_pressed = true; break; }
        }

        if (!was_pressed) {
            var ch = hidUsageToAscii(key, keyboard.shift_held);
            if (ch != 0) {
                // Apply Ctrl modifier: Ctrl+A..Z → 0x01..0x1A
                if (keyboard.ctrl_held) {
                    if (ch >= 'a' and ch <= 'z') {
                        ch = ch - 'a' + 1;
                    } else if (ch >= 'A' and ch <= 'Z') {
                        ch = ch - 'A' + 1;
                    }
                }
                keyboard.push(ch);
                // Typematic repeat: track by PS/2 scancode (not HID usage)
                // because keyboard.pollRepeat indexes `key_state[]` and that
                // table is keyed by PS/2 scancode below. Passing the HID
                // value (e.g. 0x04 for 'a') collides with whatever PS/2
                // scancode happens to share that number (0x04 = '3' on
                // PS/2 set 1) and pollRepeat ends up watching the wrong
                // key — fast typing then leaves auto-repeat firing on a
                // key the user already released. Convert to PS/2 here.
                const repeat_sc = hidUsageToScancode(key);
                if (repeat_sc != 0) {
                    keyboard.beginRepeatTracking(repeat_sc, ch, @import("../proc/process.zig").tick_count);
                }
            }
        }
    }

    // Update key_state from current HID report for keyHeld() polling
    // First: clear all previously held keys
    for (&prev_keys) |pk| {
        if (pk != 0) {
            const sc = hidUsageToScancode(pk);
            if (sc != 0) keyboard.key_state[sc] = false;
        }
    }
    // Then: set currently held keys
    for (0..6) |i| {
        const key = data[2 + i];
        if (key != 0) {
            const sc = hidUsageToScancode(key);
            if (sc != 0) keyboard.key_state[sc] = true;
        }
    }

    // Save current keys
    @memcpy(prev_keys[0..6], data[2..8]);
}

fn processMouseReport(data: [*]volatile const u8) void {
    const buttons = data[0];
    const dx: i32 = @as(i32, @as(i8, @bitCast(data[1])));
    const dy: i32 = @as(i32, @as(i8, @bitCast(data[2])));

    const prev_buttons = mouse.buttons;
    mouse.buttons = buttons & 0x07;
    const buttons_changed = mouse.buttons != prev_buttons;

    if (dx != 0 or dy != 0) {
        // Apply speed
        var adx = dx;
        var ady = dy;
        if (mouse.speed == 0) {
            adx = @divTrunc(adx, 2);
            ady = @divTrunc(ady, 2);
        } else if (mouse.speed == 2) {
            adx *= 2;
            ady *= 2;
        }

        mouse.raw_dx +%= adx;
        mouse.raw_dy +%= ady;
        mouse.x += adx;
        mouse.y += ady;
        if (mouse.x < 0) mouse.x = 0;
        if (mouse.y < 0) mouse.y = 0;
        if (mouse.x >= mouse.screen_w) mouse.x = mouse.screen_w - 1;
        if (mouse.y >= mouse.screen_h) mouse.y = mouse.screen_h - 1;
        mouse.moved = true;
    } else if (buttons_changed) {
        // Click without motion — still needs to wake the event-driven
        // compositor so the click reaches the focused window.
        mouse.moved = true;
    }
}

fn processTabletReport(data: [*]volatile const u8) void {
    const buttons = data[0];
    const abs_x: u32 = @as(u32, data[1]) | (@as(u32, data[2]) << 8);
    const abs_y: u32 = @as(u32, data[3]) | (@as(u32, data[4]) << 8);
    // QEMU usb-tablet HID descriptor: byte 5 is signed -127..127 wheel delta.
    const wheel_delta: i32 = @as(i32, @as(i8, @bitCast(data[5])));

    const prev_buttons = mouse.buttons;
    const prev_x = mouse.x;
    const prev_y = mouse.y;

    mouse.buttons = buttons & 0x07;

    const sw: u32 = @intCast(mouse.screen_w);
    const sh: u32 = @intCast(mouse.screen_h);
    mouse.x = @intCast((abs_x * sw) / 32768);
    mouse.y = @intCast((abs_y * sh) / 32768);

    if (mouse.x >= mouse.screen_w) mouse.x = mouse.screen_w - 1;
    if (mouse.y >= mouse.screen_h) mouse.y = mouse.screen_h - 1;
    if (wheel_delta != 0) mouse.wheel +%= wheel_delta;
    // Only flag `moved` when state actually changed. QEMU's usb-tablet
    // emits a HID report at ~125 Hz regardless of motion; with the
    // event-driven compositor's wake floor removed, an unconditional
    // moved=true would resume the desktop on every tick (10 ms) and
    // negate the whole event-driven idle win.
    if (mouse.x != prev_x or mouse.y != prev_y or mouse.buttons != prev_buttons or wheel_delta != 0) {
        mouse.moved = true;
    }
}

// HID Usage ID to ASCII (simplified boot keyboard mapping)
fn hidUsageToAscii(usage: u8, shift: bool) u8 {
    return switch (usage) {
        0x04...0x1D => if (shift) usage - 0x04 + 'A' else usage - 0x04 + 'a', // a-z
        0x1E...0x26 => if (shift) "!@#$%^&*("[usage - 0x1E] else usage - 0x1E + '1', // 1-9
        0x27 => if (shift) ')' else '0', // 0
        0x28 => '\n', // Enter
        0x29 => 0x1B, // Escape
        0x2A => 0x08, // Backspace
        0x2B => '\t', // Tab
        0x2C => ' ', // Space
        0x2D => if (shift) '_' else '-',
        0x2E => if (shift) '+' else '=',
        0x2F => if (shift) '{' else '[',
        0x30 => if (shift) '}' else ']',
        0x31 => if (shift) '|' else '\\',
        0x33 => if (shift) ':' else ';',
        0x34 => if (shift) '"' else '\'',
        0x35 => if (shift) '~' else '`',
        0x36 => if (shift) '<' else ',',
        0x37 => if (shift) '>' else '.',
        0x38 => if (shift) '?' else '/',
        0x3A...0x45 => keyboard.KEY_F1 + (usage - 0x3A), // F1-F12
        0x4F => keyboard.KEY_RIGHT,
        0x50 => keyboard.KEY_LEFT,
        0x51 => keyboard.KEY_DOWN,
        0x52 => keyboard.KEY_UP,
        else => 0,
    };
}

/// Map USB HID usage code to PS/2 scancode (for key_state tracking)
fn hidUsageToScancode(usage: u8) u8 {
    return switch (usage) {
        0x04 => 0x1E, // A
        0x05 => 0x30, // B
        0x06 => 0x2E, // C
        0x07 => 0x20, // D
        0x08 => 0x12, // E
        0x09 => 0x21, // F
        0x0A => 0x22, // G
        0x0B => 0x23, // H
        0x0C => 0x17, // I
        0x0D => 0x24, // J
        0x0E => 0x25, // K
        0x0F => 0x26, // L
        0x10 => 0x32, // M
        0x11 => 0x31, // N
        0x12 => 0x18, // O
        0x13 => 0x19, // P
        0x14 => 0x10, // Q
        0x15 => 0x13, // R
        0x16 => 0x1F, // S
        0x17 => 0x14, // T
        0x18 => 0x16, // U
        0x19 => 0x2F, // V
        0x1A => 0x11, // W
        0x1B => 0x2D, // X
        0x1C => 0x15, // Y
        0x1D => 0x2C, // Z
        0x1E => 0x02, // 1
        0x1F => 0x03, // 2
        0x20 => 0x04, // 3
        0x21 => 0x05, // 4
        0x22 => 0x06, // 5
        0x23 => 0x07, // 6
        0x24 => 0x08, // 7
        0x25 => 0x09, // 8
        0x26 => 0x0A, // 9
        0x27 => 0x0B, // 0
        0x28 => 0x1C, // Enter
        0x29 => 0x01, // Escape
        0x2A => 0x0E, // Backspace
        0x2B => 0x0F, // Tab
        0x2C => 0x39, // Space
        0x3A => 0x3B, // F1
        0x3B => 0x3C, // F2
        0x3C => 0x3D, // F3
        0x3D => 0x3E, // F4
        0x3E => 0x3F, // F5
        0x3F => 0x40, // F6
        0x40 => 0x41, // F7
        0x41 => 0x42, // F8
        0x42 => 0x43, // F9
        0x43 => 0x44, // F10
        0x44 => 0x57, // F11
        0x45 => 0x58, // F12
        0x4F => 0x4D, // Right arrow
        0x50 => 0x4B, // Left arrow
        0x51 => 0x50, // Down arrow
        0x52 => 0x48, // Up arrow
        else => 0,
    };
}

// --- Public API ---

pub fn isInitialized() bool {
    return initialized;
}

pub fn getMaxPorts() u8 {
    return max_ports;
}

pub fn getMaxSlots() u8 {
    return max_slots;
}

pub fn getDeviceCount() u8 {
    return device_count;
}

pub fn getMmioBase() usize {
    return mmio_base;
}

pub fn hasUsbMouse() bool {
    for (0..device_count) |i| {
        if (devices[i].active and (devices[i].is_mouse or devices[i].is_tablet)) return true;
    }
    return false;
}

pub fn hasTabletDevice() bool {
    for (0..device_count) |i| {
        if (devices[i].active and devices[i].is_tablet) return true;
    }
    return false;
}

pub fn hasUsbKeyboard() bool {
    for (0..device_count) |i| {
        if (devices[i].active and devices[i].is_keyboard) return true;
    }
    return false;
}
