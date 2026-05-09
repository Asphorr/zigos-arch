// Intel 8254x Gigabit Ethernet driver — first real-hardware NIC driver.
//
// Targets the 82540EM (PCI 0x8086:0x100E), QEMU's default `-device e1000`
// emulation. Also recognises 82545EM (0x100F) and 82541PI (0x1076), which
// behave identically for the legacy register set we use. The same code
// path runs on real hardware: any motherboard with a built-in 82540 or a
// PCI card based on it.
//
// Reference: Intel "PCI/PCI-X Family of Gigabit Ethernet Controllers
// Software Developer's Manual" (rev 4.0, document 8254x_GBe_SDM.pdf).
// We use only the legacy descriptor format (chapter 3); MSI-X, advanced
// receive descriptors, and packet-split RX are all skipped.
//
// Operating mode: IRQ-driven RX (RXT0 via MSI-X / MSI), with a polled
// fallback if no message-signalled interrupt capability is available.
// The IRQ handler drains the RX ring and dispatches each frame to
// net.handleRxFrame — so net.poll() called from a syscall normally
// finds the ring empty and returns immediately. No checksum offload,
// no VLAN, no TSO. Plenty fast for 100 Mbps QEMU userspace networking.
//
// Module surface mirrors virtio_net.zig — init/isReady/send/recv/
// rxRelease/getMac — so nic.zig can switch between the two transparently.

const io = @import("../io.zig");
const pci = @import("pci.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const msix = @import("../time/msix.zig");
const debug = @import("../debug/debug.zig");
const net = @import("../net/net.zig");

const E1000_VENDOR: u16 = 0x8086;

// Legacy 82540/41/45 family — fully tested in QEMU.
const E1000_LEGACY = [_]u16{
    0x100E, // 82540EM (QEMU `-device e1000`)
    0x100F, // 82545EM
    0x1076, // 82541GI
};

// e1000e family (82574 + i217/i218/i219). Same descriptor format and the
// register layout we touch is mostly identical, but real silicon needs
// PHY-access tweaks (KMRN/MDIC sequencing) on first link bring-up. Bound
// here so a real ThinkPad's NIC binds the driver and we surface the gap
// in the boot log instead of silently leaving the card dead. Init logs a
// warning when matching one of these IDs.
const E1000_E_FAMILY = [_]u16{
    0x10D3, // 82574L (server / NUC)
    0x153A, // I217-LM (ThinkPad T440 et al)
    0x153B, // I217-V
    0x155A, // I218-LM (T450)
    0x1559, // I218-V
    0x15A2, // I219-LM (T460)
    0x15A3, // I219-V
    0x15B7, // I219-LM (T470)
    0x15B8, // I219-V
    0x1502, // 82579LM (T420/T430)
};

// --- Register offsets (subset; see SDM §13 for the full table) ---
const REG_CTRL: u32 = 0x00000;
const REG_STATUS: u32 = 0x00008;
const REG_ICR: u32 = 0x000C0;
const REG_IMS: u32 = 0x000D0;
const REG_IMC: u32 = 0x000D8;
const REG_RCTL: u32 = 0x00100;
const REG_TCTL: u32 = 0x00400;
const REG_TIPG: u32 = 0x00410;
const REG_RDBAL: u32 = 0x02800;
const REG_RDBAH: u32 = 0x02804;
const REG_RDLEN: u32 = 0x02808;
const REG_RDH: u32 = 0x02810;
const REG_RDT: u32 = 0x02818;
const REG_TDBAL: u32 = 0x03800;
const REG_TDBAH: u32 = 0x03804;
const REG_TDLEN: u32 = 0x03808;
const REG_TDH: u32 = 0x03810;
const REG_TDT: u32 = 0x03818;
const REG_MTA: u32 = 0x05200; // 128 entries × 4 bytes
const REG_RAL0: u32 = 0x05400;
const REG_RAH0: u32 = 0x05404;

// --- CTRL register bits ---
const CTRL_FD: u32 = 1 << 0;
const CTRL_ASDE: u32 = 1 << 5;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;

// --- RCTL bits ---
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_BSIZE_2048: u32 = 0;
const RCTL_SECRC: u32 = 1 << 26;

// --- TCTL bits ---
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;

// --- TX descriptor command/status bits ---
const TXD_CMD_EOP: u8 = 1 << 0;
const TXD_CMD_IFCS: u8 = 1 << 1;
const TXD_CMD_RS: u8 = 1 << 3;
const TXD_STAT_DD: u8 = 1 << 0;

// --- RX descriptor status bits ---
const RXD_STAT_DD: u8 = 1 << 0;

// --- Ring sizing ---
//
// 32 descriptors of 16 bytes = 512 bytes (fits easily in one 4 KB page,
// the smallest pmm.allocContiguous unit). Buffers are 2048 bytes apiece;
// 32 × 2048 = 64 KB = 16 contiguous pages.
const NUM_RX_DESC: u32 = 32;
const NUM_TX_DESC: u32 = 32;
const BUF_SIZE: u32 = 2048;
const BUF_PAGES: u32 = (NUM_RX_DESC * BUF_SIZE) / 4096; // 16

const RxDesc = extern struct {
    buffer_addr: u64 align(1),
    length: u16 align(1),
    checksum: u16 align(1),
    status: u8,
    errors: u8,
    special: u16 align(1),
};

const TxDesc = extern struct {
    buffer_addr: u64 align(1),
    length: u16 align(1),
    cso: u8,
    cmd: u8,
    sta: u8,
    css: u8,
    special: u16 align(1),
};

var mmio_base: usize = 0;
pub var mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
var initialized: bool = false;
pub var irq_count: u64 = 0;
/// True once an MSI-X / MSI vector is bound to e1000IrqHandler. recv()
/// becomes a no-op in this mode — the IRQ handler exclusively owns the
/// RX ring, so a stray syscall-side poll won't race with it.
var irq_driven: bool = false;

/// e1000 MSI-X / MSI handler. ICR is read-to-clear, so the read both
/// acks all pending causes and tells us which ones fired (we mostly
/// only enabled RXT0). Then we drain the RX ring inline:
///   - peek next descriptor; bail when DD=0 (no more packets pending)
///   - hand the frame to net.handleRxFrame (TCP/IP/ARP processing,
///     including any send() responses such as ARP reply or TCP ACK)
///   - clear the descriptor and bump RDT to give it back to hardware
///
/// We're called with IRQs disabled (IDT interrupt gate). nic send()/recv()
/// from syscall context use rx_lock/tx_lock IrqSave, so they can't have
/// the lock held when this fires on the same CPU. Cross-CPU contention
/// is a brief spin (≤ a TX descriptor copy).
fn e1000IrqHandler() callconv(.c) void {
    irq_count +%= 1;
    _ = mmioRead(REG_ICR);

    while (true) {
        const next = (rx_tail + 1) % NUM_RX_DESC;
        if ((rx_descs[next].status & RXD_STAT_DD) == 0) break;
        const len = rx_descs[next].length;
        const buf_ptr: [*]volatile u8 = @ptrFromInt(paging.physToVirt(@as(u64, rx_descs[next].buffer_addr)));
        net.handleRxFrame(buf_ptr[0..len]);
        rx_descs[next].status = 0;
        rx_descs[next].length = 0;
        rx_tail = next;
    }
    mmioWrite(REG_RDT, rx_tail);
}

var rx_descs: [*]volatile RxDesc = undefined;
var rx_buffers: usize = 0;
var rx_tail: u32 = 0;

var tx_descs: [*]volatile TxDesc = undefined;
var tx_buffers: usize = 0;
var tx_next: u32 = 0;

// Track the descriptor that recv() handed out so rxRelease() can mark
// it consumed without recv() needing to return that index too.
var pending_rx_idx: u32 = 0;
var pending_rx_active: bool = false;

// Separate tx/rx locks — TX serializes the "find free desc + bump tx_next +
// write TDT" sequence; RX serializes the "scan rx_descs + stash pending_rx_*"
// sequence. Without these, two CPUs sending concurrently grab the same tx_next
// slot and clobber each other's descriptor (same bug class as ata.readSectors
// missing the lock — produced corrupted DMA buffers).
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
var tx_lock: SpinLock = .{};
var rx_lock: SpinLock = .{};

fn mmioRead(off: u32) u32 {
    const ptr: *volatile u32 = @ptrFromInt(mmio_base + off);
    return ptr.*;
}

fn mmioWrite(off: u32, val: u32) void {
    const ptr: *volatile u32 = @ptrFromInt(mmio_base + off);
    ptr.* = val;
}

pub fn init() bool {
    var found: ?pci.PciDevice = null;
    var is_e1000e: bool = false;
    for (E1000_LEGACY) |did| {
        if (pci.findByVendorDevice(E1000_VENDOR, did)) |d| {
            found = d;
            break;
        }
    }
    if (found == null) {
        for (E1000_E_FAMILY) |did| {
            if (pci.findByVendorDevice(E1000_VENDOR, did)) |d| {
                found = d;
                is_e1000e = true;
                break;
            }
        }
    }
    const d = found orelse return false;
    debug.klog("[e1000] found at {x}:{x}.{x} id=0x{x}{s}\n", .{
        d.bus, d.dev, d.func, d.device_id,
        if (is_e1000e) " (e1000e family — experimental: link bring-up may need PHY tweaks)" else "",
    });

    if (d.bar0 == 0) {
        debug.klog("[e1000] BAR0 unassigned\n", .{});
        return false;
    }
    // Store the kernel-side VA (physmap) so `mmio_base + off` is directly
    // dereferenceable without depending on the legacy low identity map.
    // Hardware itself never sees `mmio_base` — only register reads/writes
    // through it, and those are CPU-side.
    mmio_base = paging.physToVirt(@intCast(d.bar0));
    debug.klog("[e1000] mmio_base=0x{x} (phys 0x{x})\n", .{ mmio_base, d.bar0 });

    pci.bindDevice(d);

    // Reset: pulse CTRL.RST. The device clears it once self-test finishes.
    mmioWrite(REG_CTRL, mmioRead(REG_CTRL) | CTRL_RST);
    var spin: u32 = 0;
    while ((mmioRead(REG_CTRL) & CTRL_RST) != 0 and spin < 100000) : (spin += 1) {}
    if (spin >= 100000) {
        debug.klog("[e1000] reset timeout\n", .{});
        return false;
    }

    // Silence all interrupt sources before deciding whether to opt into
    // MSI-X. We re-enable specific bits below if MSI-X comes up.
    mmioWrite(REG_IMC, 0xFFFFFFFF);
    _ = mmioRead(REG_ICR);

    // Try MSI-X first, then MSI as a fallback. We keep net.poll() as the
    // rx drain so the handler stays cheap; the IRQ mostly exists to wake
    // kernel `hlt` waiters when packets arrive. RXT0 (bit 7) is enabled
    // either way so the device generates events.
    const irq_armed: bool = blk: {
        if (msix.armOne(d, 0, e1000IrqHandler)) |armed| {
            debug.klog("[e1000] MSI-X armed: IDT vec=0x{x}\n", .{armed.vector.irq_vector});
            break :blk true;
        }
        // Fallback for chipsets without MSI-X (notably QEMU's 82540EM):
        // legacy MSI cap. Single vector, no per-entry table.
        if (msix.findMsiCap(d)) |cap| {
            if (msix.allocVector(e1000IrqHandler)) |v| {
                msix.enableMsi(d, cap, v.addr, v.data);
                debug.klog("[e1000] MSI armed (legacy): IDT vec=0x{x} 64bit={}\n", .{ v.irq_vector, cap.is_64bit });
                break :blk true;
            }
        }
        debug.klog("[e1000] no MSI/MSI-X cap, polled mode\n", .{});
        break :blk false;
    };
    if (irq_armed) {
        mmioWrite(REG_IMS, 1 << 7); // RXT0 — receive timer
        irq_driven = true;
    }

    // Read MAC out of the receive-address registers — QEMU populates these
    // from `-device e1000,mac=...` (or a stable random one). On real
    // hardware the firmware/EEPROM has done the same by power-on time.
    const ral = mmioRead(REG_RAL0);
    const rah = mmioRead(REG_RAH0);
    mac[0] = @truncate(ral);
    mac[1] = @truncate(ral >> 8);
    mac[2] = @truncate(ral >> 16);
    mac[3] = @truncate(ral >> 24);
    mac[4] = @truncate(rah);
    mac[5] = @truncate(rah >> 8);
    debug.klog("[e1000] MAC {x}:{x}:{x}:{x}:{x}:{x}\n", .{ mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] });

    // MTA = multicast hash table. Zero it so no multicasts match (we
    // accept broadcast via RCTL.BAM and don't care about multicast).
    var i: u32 = 0;
    while (i < 128) : (i += 1) mmioWrite(REG_MTA + i * 4, 0);

    // Bring the link up. ASDE asks the PHY to autonegotiate speed/duplex.
    mmioWrite(REG_CTRL, CTRL_SLU | CTRL_ASDE | CTRL_FD);

    // === RX ring setup ===
    const rx_desc_phys = pmm.allocContiguous(1) orelse {
        debug.klog("[e1000] RX desc alloc failed\n", .{});
        return false;
    };
    rx_descs = @ptrFromInt(paging.physToVirt(rx_desc_phys));
    rx_buffers = pmm.allocContiguous(BUF_PAGES) orelse {
        debug.klog("[e1000] RX buf alloc failed\n", .{});
        return false;
    };
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(rx_desc_phys)))[0 .. NUM_RX_DESC * @sizeOf(RxDesc)], 0);
    var di: u32 = 0;
    while (di < NUM_RX_DESC) : (di += 1) {
        rx_descs[di] = .{
            .buffer_addr = rx_buffers + di * BUF_SIZE,
            .length = 0,
            .checksum = 0,
            .status = 0,
            .errors = 0,
            .special = 0,
        };
    }
    mmioWrite(REG_RDBAL, @truncate(rx_desc_phys));
    mmioWrite(REG_RDBAH, @truncate(rx_desc_phys >> 32));
    mmioWrite(REG_RDLEN, NUM_RX_DESC * @sizeOf(RxDesc));
    mmioWrite(REG_RDH, 0);
    // Tail = NUM_RX_DESC - 1 means "all descriptors are HW-owned and ready
    // to receive into". RDH starts at 0 and chases RDT as packets arrive.
    mmioWrite(REG_RDT, NUM_RX_DESC - 1);
    rx_tail = NUM_RX_DESC - 1;
    mmioWrite(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC);

    // === TX ring setup ===
    const tx_desc_phys = pmm.allocContiguous(1) orelse return false;
    tx_descs = @ptrFromInt(paging.physToVirt(tx_desc_phys));
    tx_buffers = pmm.allocContiguous(BUF_PAGES) orelse return false;
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(tx_desc_phys)))[0 .. NUM_TX_DESC * @sizeOf(TxDesc)], 0);
    di = 0;
    while (di < NUM_TX_DESC) : (di += 1) {
        tx_descs[di] = .{
            .buffer_addr = tx_buffers + di * BUF_SIZE,
            .length = 0,
            .cso = 0,
            .cmd = 0,
            // Pre-mark every descriptor "done" so the first send() loop
            // through the ring sees a free slot without having to spin.
            .sta = TXD_STAT_DD,
            .css = 0,
            .special = 0,
        };
    }
    mmioWrite(REG_TDBAL, @truncate(tx_desc_phys));
    mmioWrite(REG_TDBAH, @truncate(tx_desc_phys >> 32));
    mmioWrite(REG_TDLEN, NUM_TX_DESC * @sizeOf(TxDesc));
    mmioWrite(REG_TDH, 0);
    mmioWrite(REG_TDT, 0);
    // TIPG: IPGT (bits 9:0) = 10, IPGR1 (19:10) = 8, IPGR2 (29:20) = 12.
    // These are the SDM-recommended values for full-duplex Gigabit.
    mmioWrite(REG_TIPG, 10 | (8 << 10) | (12 << 20));
    // TCTL: enable + pad short packets + collision threshold 0x10 + collision distance 0x40.
    mmioWrite(REG_TCTL, TCTL_EN | TCTL_PSP | (@as(u32, 0x10) << 4) | (@as(u32, 0x40) << 12));

    initialized = true;
    debug.klog("[e1000] initialized\n", .{});
    return true;
}

pub fn isReady() bool {
    return initialized;
}

pub fn getMac() [6]u8 {
    return mac;
}

/// Transmit a single Ethernet frame. The driver holds a per-descriptor
/// 2 KB buffer so the caller can free `data` immediately on return.
/// Spins briefly waiting for a descriptor to be free; gives up after a
/// generous bound rather than blocking the kernel forever (TX stalls
/// usually mean the ring is genuinely backed up — caller's problem).
pub fn send(data: []const u8) bool {
    if (!initialized) return false;
    if (data.len == 0 or data.len > BUF_SIZE) return false;

    // IrqSave: the IRQ handler may also call into send (ARP reply, TCP ACK).
    // Without disabling IF here, the same-CPU IRQ would deadlock on tx_lock.
    const flags = tx_lock.acquireIrqSave();
    defer tx_lock.releaseIrqRestore(flags);
    const idx = tx_next;
    var spin: u32 = 0;
    while ((tx_descs[idx].sta & TXD_STAT_DD) == 0 and spin < 1_000_000) : (spin += 1) {}
    if ((tx_descs[idx].sta & TXD_STAT_DD) == 0) {
        debug.klog("[e1000] tx ring stuck at idx={d}\n", .{idx});
        return false;
    }

    const buf_ptr: [*]u8 = @ptrFromInt(paging.physToVirt(tx_descs[idx].buffer_addr));
    @memcpy(buf_ptr[0..data.len], data);

    tx_descs[idx].length = @intCast(data.len);
    tx_descs[idx].cmd = TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS;
    // Clearing DD tells the hardware "this descriptor is mine again";
    // it sets DD again once the packet is on the wire.
    tx_descs[idx].sta = 0;

    tx_next = (idx + 1) % NUM_TX_DESC;
    mmioWrite(REG_TDT, tx_next);
    return true;
}

/// Return one received frame, or null if nothing pending. Caller must
/// invoke rxRelease() after consuming the slice — that hands the
/// descriptor back to hardware. The returned slice is only valid until
/// rxRelease() is called.
pub fn recv() ?[]volatile u8 {
    if (!initialized) return null;
    // IRQ-driven mode: the interrupt handler exclusively owns the RX ring.
    // net.poll() still calls into here from syscall context, but should
    // see "nothing pending" — returning null lets the loop exit cleanly.
    if (irq_driven) return null;
    const flags = rx_lock.acquireIrqSave();
    defer rx_lock.releaseIrqRestore(flags);
    const next = (rx_tail + 1) % NUM_RX_DESC;
    if ((rx_descs[next].status & RXD_STAT_DD) == 0) return null;

    const len = rx_descs[next].length;
    const buf_ptr: [*]volatile u8 = @ptrFromInt(paging.physToVirt(@as(u64, rx_descs[next].buffer_addr)));
    pending_rx_idx = next;
    pending_rx_active = true;
    return buf_ptr[0..len];
}

/// Hand the descriptor returned by recv() back to hardware. No-op if
/// recv() returned null since.
pub fn rxRelease() void {
    if (irq_driven) return;
    const flags = rx_lock.acquireIrqSave();
    defer rx_lock.releaseIrqRestore(flags);
    if (!pending_rx_active) return;
    rx_descs[pending_rx_idx].status = 0;
    rx_descs[pending_rx_idx].length = 0;
    rx_tail = pending_rx_idx;
    mmioWrite(REG_RDT, rx_tail);
    pending_rx_active = false;
}
