// MSI-X (Message Signaled Interrupts, eXtended) — modern PCIe interrupt
// delivery. Each device has up to 2048 vectors, mapped via a per-device
// MSI-X table that lives inside one of the device's BARs. Each table
// entry has an LAPIC-mailbox address, a data word (the IDT vector), and
// a per-entry mask bit. When the device wants to signal, it writes its
// `data` word to its `address` — that write is intercepted by the LAPIC
// (any address matching `0xFEE00000 | (apic_id << 12)`) and turned into
// an interrupt at the specified vector.
//
// This module:
//   1. Walks PCI capabilities to find the MSI-X cap (cap_id 0x11).
//   2. Allocates an IDT vector from the dynamic-vector pool (idt.zig).
//   3. Computes the LAPIC mailbox address for the target CPU and the
//      data word for the chosen vector.
//   4. Writes the entry into the device's MSI-X table and unmasks it.
//   5. Flips the MSI-X enable bit in the cap header so the device
//      starts using the table.
//
// Reference: PCI Local Bus Spec rev 3.0 §6.8.2.

const std = @import("std");
const pci = @import("../driver/pci.zig");
const idt = @import("../cpu/idt.zig");
const apic = @import("apic.zig");
const debug = @import("../debug/debug.zig");

const CAP_ID_MSIX: u8 = 0x11;
const CAP_ID_MSI: u8 = 0x05;

/// Parsed view of a device's MSI-X capability. The two `(bir, offset)`
/// pairs describe where the table and the pending-bit array live —
/// usually both in the same BAR but the spec allows them to be split.
pub const Cap = struct {
    cfg_off: u8,
    table_size: u16,
    table_bir: u8,
    table_offset: u32,
    pba_bir: u8,
    pba_offset: u32,
};

/// One MSI-X table entry — 16 bytes, layout fixed by the PCI spec.
const TableEntry = extern struct {
    addr_lo: u32 align(1),
    addr_hi: u32 align(1),
    data: u32 align(1),
    vector_control: u32 align(1), // bit 0 = mask
};

/// One allocation: which IDT vector got assigned, plus the LAPIC
/// address+data the device must program into its MSI-X table entry.
pub const Vector = struct {
    irq_vector: u8, // IDT vector handleDynIrq dispatches from
    addr: u64, // value to write into TableEntry.addr_lo/hi
    data: u32, // value to write into TableEntry.data
};

/// Find the device's MSI-X capability and decode it. Returns null if the
/// device doesn't expose MSI-X.
pub fn findCap(dev: pci.PciDevice) ?Cap {
    const off = pci.findCapability(dev, CAP_ID_MSIX) orelse return null;

    // Cap layout (relative to off):
    //   +0: u8 cap_id (0x11)
    //   +1: u8 next_cap_ptr
    //   +2: u16 message_control (table_size-1 in bits 10:0)
    //   +4: u32 table_offset_bir   (BIR in bits 2:0, offset in bits 31:3)
    //   +8: u32 pba_offset_bir
    const msg_ctrl = pci.configRead16(dev.bus, dev.dev, dev.func, off + 2);
    const table_dw = pci.configRead(dev.bus, dev.dev, dev.func, off + 4);
    const pba_dw = pci.configRead(dev.bus, dev.dev, dev.func, off + 8);

    return .{
        .cfg_off = off,
        .table_size = (msg_ctrl & 0x07FF) + 1,
        .table_bir = @truncate(table_dw & 0x07),
        .table_offset = table_dw & 0xFFFFFFF8,
        .pba_bir = @truncate(pba_dw & 0x07),
        .pba_offset = pba_dw & 0xFFFFFFF8,
    };
}

/// Result of a successful `armOne`: cached cap (so the driver can later
/// re-write the entry on CPU migration), the IDT/LAPIC vector info, and
/// the kernel-pointer to the entry the driver picked. Drivers that don't
/// need to track these can ignore the fields.
pub const ArmedVector = struct {
    cap: Cap,
    vector: Vector,
    entry_addr: usize,
};

/// One-shot arm of a single MSI-X entry: find the cap, allocate an IDT
/// vector, mask all entries (defensive — some BIOSes leave stale bits),
/// write the chosen `table_idx` entry, enable the cap. Returns null if
/// the device has no MSI-X, the table is too small, or the dynamic IRQ
/// pool is exhausted.
///
/// Replaces 5 near-identical copies of the same dance across NVMe,
/// AHCI, e1000, virtio_gpu, virtio_net. Most drivers use `table_idx=0`;
/// NVMe picks 1 because the admin queue at entry 0 stays polled.
pub fn armOne(dev: pci.PciDevice, table_idx: u16, handler: idt.DynHandler) ?ArmedVector {
    const cap = findCap(dev) orelse return null;
    if (cap.table_size <= table_idx) return null;
    const v = allocVector(handler) orelse return null;
    var i: u16 = 0;
    while (i < cap.table_size) : (i += 1) {
        maskEntry(tableAddr(dev, cap, i), true);
    }
    const entry_addr = tableAddr(dev, cap, table_idx);
    writeEntry(entry_addr, v.addr, v.data, false);
    enable(dev, cap);
    return .{ .cap = cap, .vector = v, .entry_addr = entry_addr };
}

/// Compute the kernel-pointer (physmap VA) of MSI-X table entry `idx`.
/// The table BAR must already be mapped (it overlaps the device's main
/// MMIO region in every controller we touch — NVMe BAR0, e1000 BAR0,
/// AHCI BAR5).
///
/// Returns the physmap-translated VA so callers can dereference through
/// the kernel physmap. After Phase 3 dropped PML4[0], the raw phys form
/// (e.g. 0x80861000) is no longer valid in supervisor mode — every
/// writeEntry/maskEntry would #PF on the first vector_control store.
pub fn tableAddr(dev: pci.PciDevice, cap: Cap, idx: u16) usize {
    const bar_off: u8 = 0x10 + cap.table_bir * 4;
    const bar = pci.readBar64(dev.bus, dev.dev, dev.func, bar_off);
    const phys: usize = @as(usize, bar) + cap.table_offset + @as(usize, idx) * @sizeOf(TableEntry);
    const paging = @import("../mm/paging.zig");
    return paging.physToVirt(phys);
}

/// Write one MSI-X table entry and (optionally) unmask it. Caller must
/// have already issued `enable()` on the cap or the device will ignore
/// the entry until it is enabled.
pub fn writeEntry(entry_addr: usize, addr: u64, data: u32, masked: bool) void {
    const e: *volatile TableEntry = @ptrFromInt(entry_addr);
    // Spec requires masking before changing addr/data so a stale entry
    // can't fire mid-write. Set mask bit, write fields, optionally clear.
    e.vector_control = 1;
    e.addr_lo = @truncate(addr);
    e.addr_hi = @truncate(addr >> 32);
    e.data = data;
    e.vector_control = if (masked) 1 else 0;
}

/// Toggle the per-entry mask bit without touching addr/data.
pub fn maskEntry(entry_addr: usize, mask_it: bool) void {
    const e: *volatile TableEntry = @ptrFromInt(entry_addr);
    e.vector_control = if (mask_it) 1 else 0;
}

/// Flip the MSI-X enable bit (and clear function-level mask) in the cap
/// header so the device starts emitting MSI-X messages. Also clears
/// legacy INTx by setting bit 10 of PCI command register — without this,
/// a device that's wired to a shared legacy IRQ line will keep asserting
/// it and the IOAPIC will see ghost interrupts.
pub fn enable(dev: pci.PciDevice, cap: Cap) void {
    // Disable legacy INTx (PCI command register, bit 10 = Interrupt Disable).
    const cmd = pci.configRead16(dev.bus, dev.dev, dev.func, 0x04);
    pci.configWrite16(dev.bus, dev.dev, dev.func, 0x04, cmd | 0x0400);

    // Message Control: bit 15 = MSI-X Enable, bit 14 = Function Mask.
    var mc = pci.configRead16(dev.bus, dev.dev, dev.func, cap.cfg_off + 2);
    mc |= 0x8000; // enable
    mc &= ~@as(u16, 0x4000); // clear function mask
    pci.configWrite16(dev.bus, dev.dev, dev.func, cap.cfg_off + 2, mc);
}

// --- Legacy MSI fallback (cap_id 0x05) -------------------------------------
//
// Some older chipsets (notably QEMU's 82540EM e1000 and a handful of
// add-in cards) implement MSI but not MSI-X. The cap layout is similar
// — same LAPIC mailbox addressing — but the address/data live directly
// in PCI config space rather than a separate table, and the cap itself
// only carries one (or a small power-of-two) vector.

pub const MsiCap = struct {
    cfg_off: u8,
    is_64bit: bool, // bit 7 of message control
};

pub fn findMsiCap(dev: pci.PciDevice) ?MsiCap {
    const off = pci.findCapability(dev, CAP_ID_MSI) orelse return null;
    const mc = pci.configRead16(dev.bus, dev.dev, dev.func, off + 2);
    return .{ .cfg_off = off, .is_64bit = (mc & (1 << 7)) != 0 };
}

/// Program a single MSI vector: write addr/data into the cap's
/// config-space registers, then flip the MSI Enable bit (bit 0 of
/// message control) and silence legacy INTx (PCI command bit 10).
/// `multiple_message_enable` is forced to 0 (=1 vector); we don't use
/// MSI's burst-of-vectors feature.
pub fn enableMsi(dev: pci.PciDevice, cap: MsiCap, addr: u64, data: u32) void {
    pci.configWrite(dev.bus, dev.dev, dev.func, cap.cfg_off + 4, @truncate(addr));
    if (cap.is_64bit) {
        pci.configWrite(dev.bus, dev.dev, dev.func, cap.cfg_off + 8, @truncate(addr >> 32));
        pci.configWrite16(dev.bus, dev.dev, dev.func, cap.cfg_off + 12, @truncate(data));
    } else {
        pci.configWrite16(dev.bus, dev.dev, dev.func, cap.cfg_off + 8, @truncate(data));
    }
    var mc = pci.configRead16(dev.bus, dev.dev, dev.func, cap.cfg_off + 2);
    mc &= ~@as(u16, 0x0070); // MME = 0 (1 vector)
    mc |= 1; // MSI Enable
    pci.configWrite16(dev.bus, dev.dev, dev.func, cap.cfg_off + 2, mc);

    const cmd = pci.configRead16(dev.bus, dev.dev, dev.func, 0x04);
    pci.configWrite16(dev.bus, dev.dev, dev.func, 0x04, cmd | 0x0400);
}

/// One-shot: pick a free dynamic IDT vector, register `handler`, return
/// the LAPIC addr/data the device must use to deliver to it. Pinned to
/// CPU0 (the BSP) — we don't do per-CPU IRQ steering. If/when we want
/// to retarget interrupts at runtime, take a `dest_cpu` arg rather than
/// reading the caller's LAPIC ID (the latter would silently misroute an
/// IRQ if someone ever called this from an AP context, e.g. hot-pluggable
/// driver init).
pub fn allocVector(handler: idt.DynHandler) ?Vector {
    const vec = idt.allocDynVector() orelse {
        debug.klog("[msix] all dynamic IRQ slots in use\n", .{});
        return null;
    };
    idt.registerIrq(vec, handler);

    // LAPIC mailbox MSI message format (Intel SDM Vol 3 §10.11):
    //   Address [31:20] = 0xFEE
    //   Address [19:12] = destination APIC ID
    //   Address [11:4]  = reserved (0)
    //   Address [3]     = redirection hint (0 = directed)
    //   Address [2]     = destination mode (0 = physical)
    //   Data    [7:0]   = vector
    //   Data    [10:8]  = delivery mode (0 = fixed)
    //   Data    [14]    = level (0 = edge)
    //   Data    [15]    = trigger mode (0 = edge)
    const dest_id: u64 = 0; // BSP — see fn comment for rationale
    const addr: u64 = 0xFEE00000 | (dest_id << 12);
    const data: u32 = vec;

    return .{ .irq_vector = vec, .addr = addr, .data = data };
}
