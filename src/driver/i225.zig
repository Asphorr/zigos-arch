// Intel I225 / I226 2.5 GbE driver — first modern NIC driver.
//
// Targets the Foxville family: I225-V (0x15F2), I225-LM (0x15F3), I225-IT
// (0x15F8), I225-K (0x3100/0x3101), I226-V (0x125B/0x125C), I226-LM (0x125D).
// Same software interface as I210/I211; the Linux igc driver covers the
// I225/I226 series. Common in 2020+ desktop and laptop motherboards
// (mostly via the I219 PHY + I225 MAC SKU split that Intel started doing).
//
// Why a new driver instead of extending e1000.zig:
//   - Register map shifts. EIMS/EICR/EIAM (extended) replace IMS/ICR. RX/TX
//     descriptor base addresses move from 0x2800 to 0xC000. SRRCTL adds
//     packet-buffer sizing. RXDCTL/TXDCTL gate queue start/stop instead of
//     RCTL.EN / TCTL.EN.
//   - Descriptor format changes. Legacy 16B descriptors with cmd/sta bytes
//     are replaced by "advanced" descriptors with different bit layouts.
//     I225 only accepts the advanced format.
//   - Multi-queue. The hardware exposes 4 RX + 4 TX rings and 5 MSI-X
//     vectors. We use one of each (queue 0) and steer all interrupts to
//     a single vector — same shape as e1000 from the kernel's view.
//   - MSI-X is mandatory. The I225 doesn't expose a legacy MSI cap; if
//     MSI-X allocation fails we fall back to polled mode (kept for
//     symmetry but unlikely on real HW).
//
// Reference: Intel "Ethernet Controller I225 Datasheet" (rev 2.30, doc
// 612212). Linux drivers/net/ethernet/intel/igc/ for cross-checking.
//
// Operating mode mirrors e1000.zig: IRQ-driven RX, drained inline by the
// MSI-X handler, dispatched to net.handleRxFrame. send() spins briefly
// for a free TX descriptor.

const io = @import("../io.zig");
const pci = @import("pci.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const msix = @import("../time/msix.zig");
const debug = @import("../debug/debug.zig");
const net = @import("../net/net.zig");

const I225_VENDOR: u16 = 0x8086;
// Most-common SKUs across I225 + I226 families. The driver doesn't care
// which one — register set is identical.
const I225_DEVICES = [_]u16{
    0x15F2, // I225-V
    0x15F3, // I225-LM
    0x15F8, // I225-IT
    0x3100, // I225-K
    0x3101, // I225-K2
    0x125B, // I226-V
    0x125C, // I226-LM
    0x125D, // I226-IT
};

// --- Register offsets ---
//
// I225 register layout follows I210/I211 exactly. Compare to e1000.zig: the
// general-purpose registers stayed at 0x0000-0x05FF, but per-queue rings
// moved to 0xC000 (RX) / 0xE000 (TX) so the spec could expose 4 queues per
// direction without colliding with general control.

// General control / status
const REG_CTRL: u32 = 0x00000;
const REG_STATUS: u32 = 0x00008;
const REG_CTRL_EXT: u32 = 0x00018;
const REG_MDIC: u32 = 0x00020; // PHY MDI access (not used here — autoneg is HW-managed)

// Extended interrupt registers (replace e1000 IMS/ICR/IMC)
const REG_EICR: u32 = 0x01580;
const REG_EICS: u32 = 0x01520;
const REG_EIMS: u32 = 0x01524;
const REG_EIMC: u32 = 0x01528;
const REG_EIAC: u32 = 0x0152C;
const REG_EIAM: u32 = 0x01530;
// IVAR0 is at 0x01700 + 4*(queue/2). We only use queue 0, so just IVAR0.
const REG_IVAR0: u32 = 0x01700;
const REG_IVAR_MISC: u32 = 0x01740; // For non-queue causes (link change etc.)
const REG_GPIE: u32 = 0x01514; // General Purpose Interrupt Enable

// Receive
const REG_RCTL: u32 = 0x00100;
const REG_RXPBSIZE: u32 = 0x02404;
const REG_RDBAL0: u32 = 0x0C000;
const REG_RDBAH0: u32 = 0x0C004;
const REG_RDLEN0: u32 = 0x0C008;
const REG_SRRCTL0: u32 = 0x0C00C;
const REG_RDH0: u32 = 0x0C010;
const REG_RDT0: u32 = 0x0C018;
const REG_RXDCTL0: u32 = 0x0C028;

// Transmit
const REG_TCTL: u32 = 0x00400;
const REG_TCTL_EXT: u32 = 0x00404;
const REG_TIPG: u32 = 0x00410;
const REG_TXPBSIZE: u32 = 0x03404;
const REG_TDBAL0: u32 = 0x0E000;
const REG_TDBAH0: u32 = 0x0E004;
const REG_TDLEN0: u32 = 0x0E008;
const REG_TDH0: u32 = 0x0E010;
const REG_TDT0: u32 = 0x0E018;
const REG_TXDCTL0: u32 = 0x0E028;

// MAC address registers (same as e1000)
const REG_MTA: u32 = 0x05200;
const REG_RAL0: u32 = 0x05400;
const REG_RAH0: u32 = 0x05404;

// --- CTRL bits ---
const CTRL_FD: u32 = 1 << 0;
const CTRL_ASDE: u32 = 1 << 5;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;

// --- STATUS bits ---
const STATUS_LU: u32 = 1 << 1; // Link Up

// --- RCTL bits ---
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_BSIZE_2048: u32 = 0;
const RCTL_SECRC: u32 = 1 << 26;

// --- TCTL bits ---
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;

// --- SRRCTL ---
// Split-Receive Control. Bits [4:0] = bsizepacket / 1024. Bit 25 = DESCTYPE
// (000 = legacy, 001 = advanced one-buffer, 010 = advanced header split).
// I225 requires advanced one-buffer for our usage.
const SRRCTL_BSIZEPKT_2KB: u32 = 2;
const SRRCTL_DESCTYPE_ADV: u32 = 1 << 25;
const SRRCTL_DROP_EN: u32 = 1 << 31;

// --- RXDCTL / TXDCTL bits ---
// Per-queue control. ENABLE bit gates the queue independently of RCTL/TCTL
// global enables — both must be set for the queue to actually run.
const QDCTL_ENABLE: u32 = 1 << 25;
const QDCTL_SWFLSH: u32 = 1 << 26; // SW flush (TX only)

// --- GPIE bits ---
// PBA_support: enables proper MSI-X PBA bit handling.
// MULTIPLE_MSIX: required when steering more than one cause to MSI-X.
// EIAME: auto-mask EIMS bits when their cause fires (we re-enable in handler).
const GPIE_NSICR: u32 = 1 << 0;
const GPIE_MULTIPLE_MSIX: u32 = 1 << 4;
const GPIE_EIAME: u32 = 1 << 30;
const GPIE_PBA_SUPPORT: u32 = 1 << 31;

// --- TX advanced descriptor bits (cmd_type_len field) ---
// Layout of cmd_type_len (32-bit value at bytes 12-15 of descriptor):
//   bits 0-15:  DTALEN (data length)
//   bit 20-23:  DTYP (descriptor type — 0x3 = data)
//   bit 24:     EOP (End Of Packet)
//   bit 25:     IFCS (Insert FCS)
//   bit 27:     RS (Report Status)
//   bit 29:     DEXT (Descriptor Extension — must be 1 for advanced)
const TXD_CMD_DEXT: u32 = 1 << 29;
const TXD_CMD_DTYP_DATA: u32 = 0x3 << 20;
const TXD_CMD_EOP: u32 = 1 << 24;
const TXD_CMD_IFCS: u32 = 1 << 25;
const TXD_CMD_RS: u32 = 1 << 27;

// --- TX advanced descriptor status (olinfo_status field, low byte after writeback) ---
const TXD_STAT_DD: u32 = 1 << 0;

// --- RX advanced descriptor writeback bits (extended_status field) ---
const RXD_STAT_DD: u32 = 1 << 0;
const RXD_STAT_EOP: u32 = 1 << 1;

// --- Ring sizing ---
// Same proportions as e1000.zig: 32 descriptors × 16 bytes = 512 B (fits in
// one 4 KB page); 32 × 2 KB packet buffers = 64 KB (16 pages contiguous).
// I225 supports up to 4096 descriptors per ring; 32 is plenty for our load.
const NUM_RX_DESC: u32 = 32;
const NUM_TX_DESC: u32 = 32;
const BUF_SIZE: u32 = 2048;
const BUF_PAGES: u32 = (NUM_RX_DESC * BUF_SIZE) / 4096; // 16

// --- Descriptor types ---
// 16 bytes each. We use raw u64 pairs and bit-twiddle the fields. A packed
// struct works but the read-format vs write-back-format split (the same
// 16 bytes mean different things before and after the HW touches them)
// makes that messier than just naming the slots after their write-back
// purpose.

const RxDesc = extern struct {
    /// Read format: packet buffer phys addr.
    /// Writeback format: bytes 0-3 RSS-info/packet-type, bytes 4-7
    /// extended_status[3:0]/extended_error[7:4]/etc.
    word0: u64 align(1),
    /// Read format: header buffer phys addr (we set 0 — no header split).
    /// Writeback format: bytes 8-9 length, bytes 10-11 vlan, bytes 12-15
    /// extras (rss_hash low half).
    word1: u64 align(1),
};
comptime {
    // i225 advanced RX descriptor — 16 bytes (datasheet §7.1.5).
    const a = @import("std").debug.assert;
    a(@sizeOf(RxDesc) == 16);
    a(@offsetOf(RxDesc, "word0") == 0);
    a(@offsetOf(RxDesc, "word1") == 8);
}

const TxDesc = extern struct {
    /// Read & writeback: buffer phys addr.
    buffer_addr: u64 align(1),
    /// Bytes 8-11: olinfo (paylen[31:14] | popts[13:10] | reserved | sta[3:0]).
    /// Writeback: HW sets DD in sta[0].
    olinfo_status: u32 align(1),
    /// Bytes 12-15: cmd_type_len (see TXD_CMD_* constants above).
    cmd_type_len: u32 align(1),
};
comptime {
    // i225 advanced TX descriptor — 16 bytes.
    const a = @import("std").debug.assert;
    a(@sizeOf(TxDesc) == 16);
    a(@offsetOf(TxDesc, "buffer_addr") == 0);
    a(@offsetOf(TxDesc, "olinfo_status") == 8);
    a(@offsetOf(TxDesc, "cmd_type_len") == 12);
}

// --- Module state ---
var mmio_base: usize = 0;
pub var mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
var initialized: bool = false;
pub var irq_count: u64 = 0;
var irq_driven: bool = false;
/// Bitmask of EIMS bits we configured. Re-armed inside the IRQ handler
/// because GPIE_EIAME auto-masks them on fire.
var our_eims_bits: u32 = 0;

var rx_descs: [*]volatile RxDesc = undefined;
var rx_buffers: usize = 0;
var rx_tail: u32 = 0;

var tx_descs: [*]volatile TxDesc = undefined;
var tx_buffers: usize = 0;
var tx_next: u32 = 0;

var pending_rx_idx: u32 = 0;
var pending_rx_active: bool = false;

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

/// MSI-X vector handler. We allocate a single vector and steer queue 0 RX
/// (and "misc" link-change events) to it. EIAME auto-clears EIMS when the
/// vector fires, so the cause is masked while we drain — re-arm at the end.
fn i225IrqHandler() callconv(.c) void {
    irq_count +%= 1;

    // Read+clear EICR. The bit assignment we set up via IVAR0 / IVAR_MISC
    // determines which bits fire here — we don't care which queue inside
    // the handler since we only have one.
    _ = mmioRead(REG_EICR);

    // Drain RX. Same shape as e1000: walk forward from rx_tail, hand each
    // packet to net.handleRxFrame, then bump RDT to give descriptors back.
    while (true) {
        const next = (rx_tail + 1) % NUM_RX_DESC;
        const ext_status: u32 = @truncate(rx_descs[next].word0 >> 32);
        if (ext_status & RXD_STAT_DD == 0) break;

        // Length lives in the low 16 bits of word1 (writeback format).
        const len: u16 = @truncate(rx_descs[next].word1);
        const buf_phys = rx_buffers + next * BUF_SIZE;
        const buf_ptr: [*]volatile u8 = @ptrFromInt(paging.physToVirt(buf_phys));
        net.handleRxFrame(buf_ptr[0..len]);

        // Re-arm the descriptor: HW expects the read-format buffer addr +
        // zero header addr. The read format uses the same bytes but the
        // word0 field is the packet buffer address now (no high-half bits
        // to clear since buf_phys is below 4 GB on QEMU; on real HW with
        // > 4 GB RAM the kernel physmap allocations could land high, but
        // the I225 supports 64-bit DMA addresses natively so it doesn't
        // matter — we just always write the full 64 bits).
        rx_descs[next].word0 = buf_phys;
        rx_descs[next].word1 = 0;

        rx_tail = next;
    }
    mmioWrite(REG_RDT0, rx_tail);

    // Re-arm the auto-cleared EIMS bits.
    mmioWrite(REG_EIMS, our_eims_bits);
}

pub fn init() bool {
    var found: ?pci.PciDevice = null;
    for (I225_DEVICES) |did| {
        if (pci.findByVendorDevice(I225_VENDOR, did)) |d| {
            found = d;
            break;
        }
    }
    const d = found orelse return false;
    debug.klog("[i225] found at {x}:{x}.{x} id=0x{x}\n", .{ d.bus, d.dev, d.func, d.device_id });

    if (d.bars[0] == 0) {
        debug.klog("[i225] BAR0 unassigned\n", .{});
        return false;
    }
    mmio_base = paging.physToVirt(@intCast(d.bars[0]));
    debug.klog("[i225] mmio_base=0x{x} (phys 0x{x})\n", .{ mmio_base, d.bars[0] });

    var bind = pci.bindDevice(d);
    defer bind.deinit();

    // --- Reset ---
    // CTRL.RST is self-clearing. Spec calls for a 1us delay after the write
    // before the first read; the busy-loop iterations cover this on any
    // CPU faster than ~1 GHz.
    mmioWrite(REG_CTRL, mmioRead(REG_CTRL) | CTRL_RST);
    var spin: u32 = 0;
    while ((mmioRead(REG_CTRL) & CTRL_RST) != 0 and spin < 100000) : (spin += 1) {}
    if (spin >= 100000) {
        debug.klog("[i225] reset timeout\n", .{});
        return false;
    }

    // --- Mask all interrupts during config ---
    // EIMC = 0xFFFFFFFF clears all bits in EIMS atomically (write-1-to-clear
    // semantics on the mask register). EICR is read-to-clear, so reading it
    // also acks any spurious events left over from before our reset.
    mmioWrite(REG_EIMC, 0xFFFFFFFF);
    _ = mmioRead(REG_EICR);

    // --- Read MAC ---
    // Firmware (or QEMU's PCI option ROM) populates RAH0/RAL0 at power-on
    // from the device's NVM image. We don't need to drive the EERD register
    // ourselves unless we want to read OTHER NVM contents.
    const ral = mmioRead(REG_RAL0);
    const rah = mmioRead(REG_RAH0);
    mac[0] = @truncate(ral);
    mac[1] = @truncate(ral >> 8);
    mac[2] = @truncate(ral >> 16);
    mac[3] = @truncate(ral >> 24);
    mac[4] = @truncate(rah);
    mac[5] = @truncate(rah >> 8);
    debug.klog("[i225] MAC {x}:{x}:{x}:{x}:{x}:{x}\n", .{ mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] });

    // Zero the multicast hash table — we accept broadcast via RCTL.BAM and
    // don't care about multicast.
    var i: u32 = 0;
    while (i < 128) : (i += 1) mmioWrite(REG_MTA + i * 4, 0);

    // --- Bring link up ---
    // SLU + ASDE + FD: tell HW to do PHY autoneg, set link up when complete.
    // I225 PHY autoneg can take up to 5 seconds on real HW because 2.5 GbE
    // negotiation has more handshake states than 1 GbE. We don't block on
    // it — RX/TX rings can be configured before link is up; packets just
    // queue until the PHY signals ready.
    mmioWrite(REG_CTRL, CTRL_SLU | CTRL_ASDE | CTRL_FD);

    // --- RX ring setup ---
    const rx_desc_phys = pmm.allocContiguous(1) orelse {
        debug.klog("[i225] RX desc alloc failed\n", .{});
        return false;
    };
    rx_descs = @ptrFromInt(paging.physToVirt(rx_desc_phys));
    rx_buffers = pmm.allocContiguous(BUF_PAGES) orelse {
        debug.klog("[i225] RX buf alloc failed\n", .{});
        return false;
    };
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(rx_desc_phys)))[0 .. NUM_RX_DESC * @sizeOf(RxDesc)], 0);
    var di: u32 = 0;
    while (di < NUM_RX_DESC) : (di += 1) {
        rx_descs[di] = .{
            .word0 = rx_buffers + di * BUF_SIZE, // packet buffer addr
            .word1 = 0, // no header split
        };
    }
    mmioWrite(REG_RDBAL0, @truncate(rx_desc_phys));
    mmioWrite(REG_RDBAH0, @truncate(rx_desc_phys >> 32));
    mmioWrite(REG_RDLEN0, NUM_RX_DESC * @sizeOf(RxDesc));
    mmioWrite(REG_RDH0, 0);
    mmioWrite(REG_RDT0, NUM_RX_DESC - 1);
    rx_tail = NUM_RX_DESC - 1;
    // SRRCTL: 2 KB packet buffers, advanced-one-buffer descriptor format,
    // drop packets when queue is full (instead of stalling the ring). The
    // DROP_EN bit makes the device discard incoming frames if no descriptor
    // is available — fail-fast behavior we want for a kernel that can't
    // afford backpressure stalls.
    mmioWrite(REG_SRRCTL0, SRRCTL_BSIZEPKT_2KB | SRRCTL_DESCTYPE_ADV | SRRCTL_DROP_EN);
    // Per-queue enable. The general RCTL.EN below is gated by this.
    mmioWrite(REG_RXDCTL0, QDCTL_ENABLE);
    mmioWrite(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC);

    // --- TX ring setup ---
    const tx_desc_phys = pmm.allocContiguous(1) orelse return false;
    tx_descs = @ptrFromInt(paging.physToVirt(tx_desc_phys));
    tx_buffers = pmm.allocContiguous(BUF_PAGES) orelse return false;
    @memset(@as([*]u8, @ptrFromInt(paging.physToVirt(tx_desc_phys)))[0 .. NUM_TX_DESC * @sizeOf(TxDesc)], 0);
    di = 0;
    while (di < NUM_TX_DESC) : (di += 1) {
        tx_descs[di] = .{
            .buffer_addr = tx_buffers + di * BUF_SIZE,
            // Pre-mark every TX descriptor "DD=1" so the first send() loop
            // through the ring sees a free slot without spinning on a stale
            // unwritten descriptor.
            .olinfo_status = TXD_STAT_DD,
            .cmd_type_len = 0,
        };
    }
    mmioWrite(REG_TDBAL0, @truncate(tx_desc_phys));
    mmioWrite(REG_TDBAH0, @truncate(tx_desc_phys >> 32));
    mmioWrite(REG_TDLEN0, NUM_TX_DESC * @sizeOf(TxDesc));
    mmioWrite(REG_TDH0, 0);
    mmioWrite(REG_TDT0, 0);
    mmioWrite(REG_TXDCTL0, QDCTL_ENABLE);
    // TIPG values from datasheet table for full-duplex 1G/2.5G: same as
    // e1000 actually (0x602008 = IPGT 8, IPGR1 8, IPGR2 6 in the new field
    // layout — the high-low ordering of the IPG fields differs across
    // generations but the wire-time math comes out the same).
    mmioWrite(REG_TIPG, 0x00602008);
    mmioWrite(REG_TCTL, TCTL_EN | TCTL_PSP | (@as(u32, 0x10) << 4) | (@as(u32, 0x40) << 12));

    // --- MSI-X allocation + IVAR steering ---
    //
    // I225 expects all interrupt causes to be steered through IVAR registers
    // before they can fire MSI-X vectors. IVAR0 lays out:
    //   bits  0- 6: RXQ0 vector index (bit 7 = valid)
    //   bits  8-14: TXQ0 vector index (bit 15 = valid)
    //   bits 16-22: RXQ1 vector index (bit 23 = valid)
    //   bits 24-30: TXQ1 vector index (bit 31 = valid)
    // We point RXQ0 at vector 0 (the one we'll allocate via msix.armOne),
    // and leave TXQ0 unsteered — TX completion just sets DD; we never
    // wait for a TX interrupt.
    //
    // GPIE setup: enable PBA support + MULTIPLE_MSIX + EIAME (auto-mask).
    // Without MULTIPLE_MSIX, the device stops at vector 0 even if we
    // configured separate vectors. Without EIAME, EIMS would have to be
    // toggled atomically on every IRQ, which is racy.
    const irq_armed: bool = blk: {
        // table_idx 0 — the only MSI-X entry we use. armOne() returns
        // ArmedVector { cap, vector, entry_addr } but not the index we
        // passed in; since we hardcode 0 we can keep using it directly.
        const ENTRY_IDX: u32 = 0;
        const armed = msix.armOne(d, @intCast(ENTRY_IDX), i225IrqHandler) orelse {
            debug.klog("[i225] MSI-X arm failed — polled mode\n", .{});
            break :blk false;
        };
        debug.klog("[i225] MSI-X armed: IDT vec=0x{x}\n", .{armed.vector.irq_vector});
        // Steer RXQ0 → MSI-X entry ENTRY_IDX, valid bit set.
        mmioWrite(REG_IVAR0, 0x80 | (ENTRY_IDX & 0x7F));
        // Misc/other-causes → same entry. (Link-change events go here.)
        mmioWrite(REG_IVAR_MISC, 0x80 | (ENTRY_IDX & 0x7F));
        mmioWrite(REG_GPIE, GPIE_PBA_SUPPORT | GPIE_MULTIPLE_MSIX | GPIE_EIAME | GPIE_NSICR);
        // Bit ENTRY_IDX of EIMS gates this vector. EIAC clears EICR bits
        // automatically when the vector fires (cleaner than read-to-clear
        // alone — avoids re-firing if we haven't fully drained yet).
        const bit: u32 = @as(u32, 1) << @intCast(ENTRY_IDX);
        our_eims_bits = bit;
        mmioWrite(REG_EIAC, bit);
        mmioWrite(REG_EIAM, bit);
        mmioWrite(REG_EIMS, bit);
        break :blk true;
    };
    irq_driven = irq_armed;

    initialized = true;
    debug.klog("[i225] initialized (irq_driven={})\n", .{irq_driven});
    bind.commit();
    return true;
}

pub fn isReady() bool {
    return initialized;
}

pub fn getMac() [6]u8 {
    return mac;
}

pub fn send(data: []const u8) bool {
    if (!initialized) return false;
    if (data.len == 0 or data.len > BUF_SIZE) return false;

    const flags = tx_lock.acquireIrqSave();
    defer tx_lock.releaseIrqRestore(flags);
    const idx = tx_next;
    var spin: u32 = 0;
    while ((tx_descs[idx].olinfo_status & TXD_STAT_DD) == 0 and spin < 1_000_000) : (spin += 1) {}
    if ((tx_descs[idx].olinfo_status & TXD_STAT_DD) == 0) {
        debug.klog("[i225] tx ring stuck at idx={d}\n", .{idx});
        return false;
    }

    const buf_ptr: [*]u8 = @ptrFromInt(paging.physToVirt(tx_descs[idx].buffer_addr));
    @memcpy(buf_ptr[0..data.len], data);

    // PAYLEN goes in the high 18 bits of olinfo_status. For a single-segment
    // packet PAYLEN = data length. Without this, HW computes 0 payload and
    // truncates the frame on the wire — looks correct in the descriptor
    // ring but never arrives at the destination.
    const len_u32: u32 = @intCast(data.len);
    tx_descs[idx].olinfo_status = len_u32 << 14;
    tx_descs[idx].cmd_type_len = TXD_CMD_DEXT | TXD_CMD_DTYP_DATA |
        TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS | (len_u32 & 0xFFFF);

    tx_next = (idx + 1) % NUM_TX_DESC;
    mmioWrite(REG_TDT0, tx_next);
    return true;
}

pub fn recv() ?[]volatile u8 {
    if (!initialized) return null;
    if (irq_driven) return null;
    const flags = rx_lock.acquireIrqSave();
    defer rx_lock.releaseIrqRestore(flags);
    const next = (rx_tail + 1) % NUM_RX_DESC;
    const ext_status: u32 = @truncate(rx_descs[next].word0 >> 32);
    if (ext_status & RXD_STAT_DD == 0) return null;

    const len: u16 = @truncate(rx_descs[next].word1);
    const buf_phys = rx_buffers + next * BUF_SIZE;
    const buf_ptr: [*]volatile u8 = @ptrFromInt(paging.physToVirt(buf_phys));
    pending_rx_idx = next;
    pending_rx_active = true;
    return buf_ptr[0..len];
}

pub fn rxRelease() void {
    if (irq_driven) return;
    const flags = rx_lock.acquireIrqSave();
    defer rx_lock.releaseIrqRestore(flags);
    if (!pending_rx_active) return;
    const idx = pending_rx_idx;
    rx_descs[idx].word0 = rx_buffers + idx * BUF_SIZE;
    rx_descs[idx].word1 = 0;
    rx_tail = idx;
    mmioWrite(REG_RDT0, rx_tail);
    pending_rx_active = false;
}
