// ACPI table parser — replaces the pile of hardcoded "well-known" magic
// (IOAPIC at 0xFEC00000, HPET at 0xFED00000, shutdown via outw 0x604,
// SMP enumerated by probing) with values pulled from firmware-provided
// tables. Real hardware doesn't honour the QEMU defaults; without this
// every modern board would need its own special case.
//
// Scope: enough ACPI to find and decode FADT, MADT, HPET, MCFG. We do
// NOT implement the AML interpreter — DSDT/SSDT bytecode parsing is a
// separate, much larger animal. Where AML would normally yield values
// (e.g. SLP_TYPa for sysShutdown), we use the spec-defined defaults
// that match every BIOS we've ever encountered (S5 = 5).
//
// Reference: ACPI 6.4 spec §5.2 (RSDP, XSDT, FADT) and §5.2.12 (MADT).
//
// Lifetime: `init(boot_info_rsdp)` runs once during boot, after paging
// is up. UEFI passes the RSDP via `BootInfo.rsdp_addr`; on Multiboot we
// scan the legacy BIOS regions (EBDA + 0xE0000..0xFFFFF). Cached table
// pointers live in module-level vars and are read for the rest of boot.

const std = @import("std");
const debug = @import("../debug/debug.zig");
const paging = @import("../mm/paging.zig");
const io = @import("../io.zig");

// --- Top-level ACPI structures ---------------------------------------------
//
// RSDP: the entry point. Found in firmware-controlled memory. ACPI 1.0
// version is 20 bytes (rsdt_address only); ACPI 2.0+ extended it to 36
// bytes (xsdt_address + extended_checksum). Identified by the "RSD PTR "
// signature. Both versions are valid — we prefer XSDT when revision >= 2
// because it gives us 64-bit table pointers (real machines map ACPI
// tables above 4 GiB sometimes).

pub const Rsdp = extern struct {
    signature: [8]u8,
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32,
    // ACPI 2.0+ extension — only present when revision >= 2:
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [3]u8,
};

/// 36-byte header that fronts every SDT (System Description Table). The
/// first 4 bytes (signature) tell us what kind of table follows; `length`
/// covers the header + the table body, so the next SDT in an XSDT walk
/// is at `header + length`.
pub const SdtHeader = extern struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: [4]u8,
    creator_revision: u32,
};

/// Generic Address Structure — used by FADT to describe register banks
/// that may live in either I/O space (System I/O) or MMIO (System Memory).
pub const Gas = extern struct {
    addr_space: u8, // 0 = System Memory, 1 = System I/O
    bit_width: u8,
    bit_offset: u8,
    access_size: u8,
    address: u64 align(1),
};

// --- FADT (signature "FACP") -----------------------------------------------
// Only the fields we actually use; the table is much larger. Layout
// matches ACPI 6.4 Table 5.34. Field offsets are spec-fixed so we keep
// extern struct ordering even where we don't use a value.

pub const Fadt = extern struct {
    header: SdtHeader,
    firmware_ctrl: u32,
    dsdt: u32,
    _reserved0: u8,
    preferred_pm_profile: u8,
    sci_int: u16 align(1),
    smi_cmd: u32 align(1),
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_req: u8,
    pstate_cnt: u8,
    pm1a_evt_blk: u32 align(1),
    pm1b_evt_blk: u32 align(1),
    pm1a_cnt_blk: u32 align(1),
    pm1b_cnt_blk: u32 align(1),
    pm2_cnt_blk: u32 align(1),
    pm_tmr_blk: u32 align(1),
    gpe0_blk: u32 align(1),
    gpe1_blk: u32 align(1),
    pm1_evt_len: u8,
    pm1_cnt_len: u8,
    pm2_cnt_len: u8,
    pm_tmr_len: u8,
    gpe0_blk_len: u8,
    gpe1_blk_len: u8,
    gpe1_base: u8,
    cst_cnt: u8,
    p_lvl2_lat: u16 align(1),
    p_lvl3_lat: u16 align(1),
    flush_size: u16 align(1),
    flush_stride: u16 align(1),
    duty_offset: u8,
    duty_width: u8,
    day_alarm: u8,
    mon_alarm: u8,
    century: u8,
    iapc_boot_arch: u16 align(1),
    _reserved1: u8,
    flags: u32 align(1),
    reset_reg: Gas align(1),
    reset_value: u8,
    arm_boot_arch: u16 align(1),
    fadt_minor_version: u8,
    x_firmware_ctrl: u64 align(1),
    x_dsdt: u64 align(1),
    x_pm1a_evt_blk: Gas align(1),
    x_pm1b_evt_blk: Gas align(1),
    x_pm1a_cnt_blk: Gas align(1),
    x_pm1b_cnt_blk: Gas align(1),
    // ... rest omitted; we don't need it.
};

comptime {
    // The fields tryReset reads sit at spec-fixed offsets (ACPI 6.4 Table
    // 5.34). They only stay put because every multi-byte field above carries
    // align(1) — drop one (e.g. iapc_boot_arch at the odd offset 109) and
    // everything below shifts a byte, so tryReset would poke the wrong
    // register. Fail the build instead of finding out at reboot time.
    std.debug.assert(@offsetOf(Fadt, "flags") == 112);
    std.debug.assert(@offsetOf(Fadt, "reset_reg") == 116);
    std.debug.assert(@offsetOf(Fadt, "reset_value") == 128);
}

// --- MADT (signature "APIC") -----------------------------------------------
// Header followed by a stream of variable-length sub-entries discriminated
// by an 8-bit type field. Walk by header.length; each sub-entry is at
// least `[type:u8][length:u8] ...`.

pub const Madt = extern struct {
    header: SdtHeader,
    lapic_addr: u32 align(1),
    flags: u32 align(1),
    // followed by interrupt controller structures
};

pub const MadtEntryHeader = extern struct {
    entry_type: u8,
    length: u8,
};

pub const MadtType = enum(u8) {
    processor_lapic = 0,
    ioapic = 1,
    interrupt_source_override = 2,
    nmi_source = 3,
    lapic_nmi = 4,
    lapic_addr_override = 5,
    processor_x2apic = 9,
};

pub const MadtLapic = extern struct {
    header: MadtEntryHeader,
    acpi_processor_id: u8,
    apic_id: u8,
    flags: u32 align(1), // bit 0 = enabled, bit 1 = online-capable
};

pub const MadtIoapic = extern struct {
    header: MadtEntryHeader,
    ioapic_id: u8,
    _reserved: u8,
    ioapic_addr: u32 align(1),
    gsi_base: u32 align(1),
};

pub const MadtIso = extern struct {
    header: MadtEntryHeader,
    bus: u8, // always 0 (ISA)
    source: u8, // legacy IRQ
    gsi: u32 align(1),
    flags: u16 align(1),
};

/// MADT type 9 — Processor x2APIC. Used on systems with x2APIC IDs
/// > 255 (real hardware with many cores). The 32-bit `x2apic_id` field
/// is the equivalent of MadtLapic.apic_id.
pub const MadtX2Apic = extern struct {
    header: MadtEntryHeader,
    _reserved: u16 align(1),
    x2apic_id: u32 align(1),
    flags: u32 align(1), // bit 0 = enabled
    acpi_uid: u32 align(1),
};

// --- HPET (signature "HPET") -----------------------------------------------

pub const Hpet = extern struct {
    header: SdtHeader,
    event_timer_block_id: u32 align(1),
    address: Gas align(1),
    hpet_number: u8,
    min_clock_tick: u16 align(1),
    page_protection: u8,
};

// --- MCFG (signature "MCFG") -----------------------------------------------
// PCIe ECAM segments. Each segment maps a chunk of PCI bus numbers to a
// memory-mapped configuration space window.

pub const Mcfg = extern struct {
    header: SdtHeader,
    _reserved: u64 align(1),
    // followed by McfgSegment entries until header.length is exhausted
};

pub const McfgSegment = extern struct {
    base: u64 align(1),
    segment_group: u16 align(1),
    start_bus: u8,
    end_bus: u8,
    _reserved: u32 align(1),
};

// --- DMAR (signature "DMAR") -----------------------------------------------
// DMA Remapping Reporting — describes the Intel VT-d remapping units in the
// system. The table header is followed by a 12-byte DMAR-specific header
// (host address width + flags) and then a stream of variable-length
// remapping structures (DRHD, RMRR, ATSR, RHSA, ANDD) each prefixed by
// `{type:u16, length:u16}`.
//
// Reference: Intel VT-d spec §8.

pub const Dmar = extern struct {
    header: SdtHeader,
    /// Bits[7:0] of MaxPhysAddrWidth minus 1. e.g. 47 = 48-bit phys.
    host_addr_width: u8,
    /// Bit 0 = INTR_REMAP (interrupt remapping supported), bit 1 = X2APIC_OPT_OUT.
    flags: u8,
    _reserved: [10]u8,
    // followed by DmarRemappingHeader entries until header.length is exhausted
};

pub const DmarRemappingHeader = extern struct {
    /// 0 = DRHD, 1 = RMRR, 2 = ATSR, 3 = RHSA, 4 = ANDD
    entry_type: u16 align(1),
    length: u16 align(1),
};

pub const DmarType = enum(u16) {
    drhd = 0,
    rmrr = 1,
    atsr = 2,
    rhsa = 3,
    andd = 4,
};

/// DRHD: DMA Remapping Hardware Definition — one VT-d unit's MMIO base +
/// the PCI device-scope list it covers. `flags` bit 0 = INCLUDE_PCI_ALL,
/// meaning this DRHD is the catch-all for every PCI device on `segment`
/// that isn't claimed by another DRHD.
pub const DmarDrhd = extern struct {
    header: DmarRemappingHeader,
    flags: u8,
    _reserved: u8,
    segment: u16 align(1),
    register_base: u64 align(1),
    // followed by variable-length device-scope entries
};

// --- NFIT (signature "NFIT") -----------------------------------------------
// NVDIMM Firmware Interface Table — describes persistent-memory regions. The
// table header is followed by a 4-byte reserved field, then a stream of
// variable-length sub-structures each prefixed by `{type:u16, length:u16}`
// (same shape as DMAR). We decode the System Physical Address (SPA) Range
// Structure (type 0), which carries one address range's guest-physical
// base + length + a GUID identifying the kind of range.
//
// Reference: ACPI 6.4 §5.2.25.

pub const Nfit = extern struct {
    header: SdtHeader,
    _reserved: u32 align(1),
    // followed by NfitStructHeader entries until header.length is exhausted
};

pub const NfitStructHeader = extern struct {
    /// 0 = SPA Range, 1 = NVDIMM Region Mapping, 2 = Interleave, 3 = SMBIOS,
    /// 4 = NVDIMM Control Region, 5 = Block Data Window, 6 = Flush Hint,
    /// 7 = Platform Capabilities.
    entry_type: u16 align(1),
    length: u16 align(1),
};

/// System Physical Address (SPA) Range Structure — NFIT type 0. base/length
/// give the guest-physical extent of one range; range_guid says what kind.
pub const NfitSpaRange = extern struct {
    header: NfitStructHeader,
    spa_index: u16 align(1),
    flags: u16 align(1),
    _reserved: u32 align(1),
    proximity_domain: u32 align(1),
    range_guid: [16]u8,
    base: u64 align(1),
    length: u64 align(1),
    memory_mapping_attribute: u64 align(1),
};

/// Address Range Type GUID for byte-addressable persistent memory
/// (66F0D379-B4F3-4074-AC43-0D3318B78CDC), in the mixed-endian GUID byte
/// order NFIT stores it (Data1/2/3 little-endian, Data4 as-is). This is the
/// spec-correct value real NVDIMM firmware emits.
pub const PM_SPA_GUID = [16]u8{
    0x79, 0xD3, 0xF0, 0x66, 0xF3, 0xB4, 0x74, 0x40,
    0xAC, 0x43, 0x0D, 0x33, 0x18, 0xB7, 0x8C, 0xDC,
};

/// QEMU's NVDIMM emits the PM range GUID with the last byte 0xDB instead of the
/// spec's 0xDC (hw/acpi/nvdimm.c: `nvdimm_nfit_spa_uuid` ends ...0x8c, 0xdb) —
/// a long-standing one-byte deviation from ACPI 6.x. Match it too so the same
/// parser works under QEMU and on real hardware.
pub const PM_SPA_GUID_QEMU = [16]u8{
    0x79, 0xD3, 0xF0, 0x66, 0xF3, 0xB4, 0x74, 0x40,
    0xAC, 0x43, 0x0D, 0x33, 0x18, 0xB7, 0x8C, 0xDB,
};

// --- Module state ----------------------------------------------------------

var fadt: ?*align(1) const Fadt = null;
var madt: ?*align(1) const Madt = null;
var hpet: ?*align(1) const Hpet = null;
var mcfg: ?*align(1) const Mcfg = null;
var dmar: ?*align(1) const Dmar = null;
var nfit: ?*align(1) const Nfit = null;
var dsdt: ?*align(1) const SdtHeader = null;

/// SSDTs (Secondary System Description Tables) found in the (X)SDT. Unlike the
/// DSDT there can be several — real firmware splits thermal zones, batteries,
/// CPU objects, etc. across SSDTs, and QEMU's `-acpitable sig=SSDT,...` injects
/// one here too. The AML interpreter loads each into the same namespace as the
/// DSDT (Slice D), so a thermal/battery method defined in any of them resolves.
const MAX_SSDT = 20;
var ssdts: [MAX_SSDT]*align(1) const SdtHeader = undefined;
var nssdt: usize = 0;

/// SLP_TYPa / SLP_TYPb values extracted from the DSDT's `\_S5_` package — the
/// 3-bit codes the firmware wants written into PM1a_CNT / PM1b_CNT (bits 12:10)
/// to enter S5 (soft off). Null until init parses them; sysShutdown falls back
/// to the spec-default 5 when null.
pub const SleepTypes = struct { a: u8, b: u8 };
var s5_slp_typ: ?SleepTypes = null;

/// FADT.flags bit 10 = RESET_REG_SUP. When set, FADT.reset_reg is a valid
/// Generic Address pointing at a register; writing FADT.reset_value to it
/// triggers a system reset.
const FADT_F_RESET_REG_SUP: u32 = 1 << 10;

/// Attempt to reset the system via the ACPI reset register. Best-first
/// reboot path on modern firmware: triple-fault and 0xCF9 don't always
/// recover cleanly when Intel ME / AMD PSP holds reset state, but the
/// ACPI reset register goes through firmware's preferred path.
///
/// Caller treats this as fire-and-forget — on success the system resets
/// and the function never returns. On failure (no FADT, flag clear, or
/// register write didn't take), control falls through and the caller
/// should try the next reboot mechanism (0xCF9, 8042, triple fault).
pub fn tryReset() void {
    const f = fadt orelse return;
    // ACPI 1.0 FADTs are only 116 bytes — shorter than reset_reg's offset
    // (116). Don't read reset_reg / reset_value unless the table is long
    // enough to contain them, or we'd interpret adjacent physmap bytes as a
    // GAS. (On a 1.0 FADT this returns here; the RESET_REG_SUP flag below
    // would also be clear, but this makes the bound explicit, not incidental.)
    if (f.header.length < @offsetOf(Fadt, "reset_value") + 1) return;
    if (f.flags & FADT_F_RESET_REG_SUP == 0) return;
    if (f.reset_reg.address == 0) return;
    switch (f.reset_reg.addr_space) {
        // System I/O space (most common — even modern systems use this for
        // reset-control registers because they predate MMIO config).
        1 => io.outb(@truncate(f.reset_reg.address), f.reset_value),
        // System Memory (MMIO). Some server boards use this; a single byte
        // write at the indicated address triggers reset.
        0 => {
            // Bound the firmware-supplied MMIO address to the physmap so a
            // corrupt FADT can't turn a reboot attempt into an unmapped-VA
            // #PF; fall through to the caller's next reboot mechanism instead.
            if (!physRangeMapped(f.reset_reg.address, 1)) return;
            const va = paging.physToVirt(f.reset_reg.address);
            const ptr: *volatile u8 = @ptrFromInt(va);
            ptr.* = f.reset_value;
        },
        else => {},
    }
}

pub fn getFadt() ?*align(1) const Fadt {
    return fadt;
}

pub fn getMadt() ?*align(1) const Madt {
    return madt;
}

pub fn getHpet() ?*align(1) const Hpet {
    return hpet;
}

pub fn getMcfg() ?*align(1) const Mcfg {
    return mcfg;
}

pub fn getDmar() ?*align(1) const Dmar {
    return dmar;
}

pub fn getDsdt() ?*align(1) const SdtHeader {
    return dsdt;
}

/// Number of SSDTs discovered in the (X)SDT (0 on QEMU's stock q35 unless one
/// was injected via `-acpitable`). The AML loader iterates [0, ssdtCount).
pub fn ssdtCount() usize {
    return nssdt;
}

/// The i-th SSDT header (already checksum-validated by the table walk), or null
/// if out of range. Its AML body begins at +sizeof(SdtHeader).
pub fn getSsdt(i: usize) ?*align(1) const SdtHeader {
    return if (i < nssdt) ssdts[i] else null;
}

/// The `\_S5_` SLP_TYPa/b codes parsed from the DSDT, or null if no DSDT /
/// no `_S5_` / unparseable. sysShutdown writes these into PM1a/PM1b_CNT.
pub fn getS5SleepTypes() ?SleepTypes {
    return s5_slp_typ;
}

/// Iterator over DMAR remapping structures (DRHD / RMRR / ...). Caller cases
/// on `entry_type` (see DmarType) and casts the header to the concrete struct:
///   var it = acpi.dmarEntries();
///   while (it.next()) |h| switch (@as(acpi.DmarType, @enumFromInt(h.entry_type))) { ... }
pub const DmarIterator = struct {
    p: usize,
    end: usize,

    pub fn next(self: *DmarIterator) ?*align(1) const DmarRemappingHeader {
        if (self.p + @sizeOf(DmarRemappingHeader) > self.end) return null;
        const h: *align(1) const DmarRemappingHeader = @ptrFromInt(self.p);
        // length must cover its own header (catches 0 and the 1-byte desync
        // that would walk misaligned garbage) and the whole entry must fit
        // before end, or the caller reads past the table.
        if (h.length < @sizeOf(DmarRemappingHeader) or self.p + h.length > self.end) return null;
        self.p += h.length;
        return h;
    }
};

/// DMAR remapping-structure iterator. Yields nothing when no DMAR was found.
pub fn dmarEntries() DmarIterator {
    const d = dmar orelse return .{ .p = 0, .end = 0 };
    return .{ .p = @intFromPtr(d) + @sizeOf(Dmar), .end = @intFromPtr(d) + d.header.length };
}

/// Iterator over NFIT sub-structures. Same `{type,length}`-prefixed walk as
/// DMAR; caller cases on `entry_type` and casts to the concrete struct.
pub const NfitIterator = struct {
    p: usize,
    end: usize,

    pub fn next(self: *NfitIterator) ?*align(1) const NfitStructHeader {
        if (self.p + @sizeOf(NfitStructHeader) > self.end) return null;
        const h: *align(1) const NfitStructHeader = @ptrFromInt(self.p);
        if (h.length < @sizeOf(NfitStructHeader) or self.p + h.length > self.end) return null;
        self.p += h.length;
        return h;
    }
};

/// NFIT sub-structure iterator. Yields nothing when no NFIT was found.
pub fn nfitEntries() NfitIterator {
    const n = nfit orelse return .{ .p = 0, .end = 0 };
    return .{ .p = @intFromPtr(n) + @sizeOf(Nfit), .end = @intFromPtr(n) + n.header.length };
}

/// True when an NFIT table was published (i.e. an NVDIMM is present).
pub fn hasNfit() bool {
    return nfit != null;
}

/// Walk the NFIT for the first persistent-memory SPA Range Structure (type 0
/// carrying the PM address-range GUID) and return its guest-physical base +
/// length. Null if there's no NFIT or no PM range. The iterator already
/// bounds every entry inside the table body, and the type-0 length check
/// guarantees the full NfitSpaRange is readable before we cast.
pub fn firstPmemRange() ?struct { base: u64, length: u64 } {
    var it = nfitEntries();
    while (it.next()) |h| {
        if (h.entry_type != 0) continue; // only SPA Range structures
        if (h.length < @sizeOf(NfitSpaRange)) continue;
        const spa: *align(1) const NfitSpaRange = @ptrCast(h);
        const is_pm = std.mem.eql(u8, &spa.range_guid, &PM_SPA_GUID) or
            std.mem.eql(u8, &spa.range_guid, &PM_SPA_GUID_QEMU);
        if (!is_pm) continue;
        return .{ .base = spa.base, .length = spa.length };
    }
    return null;
}

// --- Checksum + validation --------------------------------------------------

fn checksumOk(bytes: []const u8) bool {
    var sum: u8 = 0;
    for (bytes) |b| sum +%= b; // ACPI checksum is a mod-256 sum (+%= wraps)
    return sum == 0;
}

/// True if [phys, phys+len) lies entirely inside the mapped 512 GB physmap
/// window, so physToVirt over that range yields only mapped VAs. The
/// subtraction form (rather than `phys + len <= SIZE`) can't overflow on a
/// hostile phys/len. phys == 0 (null / real-mode IVT) and len == 0 are never
/// real table reads, so both are rejected. This is the single bound every
/// firmware-supplied physical address passes through before it reaches
/// physToVirt.
fn physRangeMapped(phys: u64, len: u64) bool {
    return phys != 0 and len != 0 and phys <= paging.PHYSMAP_SIZE and len <= paging.PHYSMAP_SIZE - phys;
}

/// Validate an SDT's checksum after sanity-checking its firmware-supplied
/// `length`: too-large would walk off the physmap, too-small (< header size)
/// would underflow the entry-count subtraction in walkSdt (a ReleaseSafe
/// trap). `phys` is the table's physical base — used to confirm the whole
/// length-byte body is mapped before checksumOk reads it. 1 MiB is far above
/// any real table yet finite.
fn sdtChecksumOk(phys: u64, hdr: *align(1) const SdtHeader) bool {
    if (hdr.length < @sizeOf(SdtHeader) or hdr.length > 1 << 20) return false;
    if (!physRangeMapped(phys, hdr.length)) return false;
    return checksumOk(@as([*]const u8, @ptrCast(hdr))[0..hdr.length]);
}

// --- RSDP discovery ---------------------------------------------------------

/// Validate the bytes at `addr` as an RSDP. The 1.0 checksum covers the
/// first 20 bytes; revision >= 2 also requires the extended checksum
/// over the full `length` field.
fn validateRsdp(addr: u64) ?*align(1) const Rsdp {
    // The 8-byte signature + 20-byte ACPI 1.0 checksum span must be mapped.
    if (!physRangeMapped(addr, 20)) return null;
    const r: *align(1) const Rsdp = @ptrFromInt(paging.physToVirt(addr));
    if (!std.mem.eql(u8, &r.signature, "RSD PTR ")) {
        // Diagnostic: dump the first 16 bytes at this address so we can
        // tell "wrong address" from "address was clobbered" failures.
        const bytes: [*]const u8 = @ptrCast(r);
        debug.klog(
            "[acpi]   RSDP@0x{x} sig mismatch; bytes={x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}\n",
            .{ addr, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7] },
        );
        return null;
    }
    if (!checksumOk(@as([*]const u8, @ptrCast(r))[0..20])) {
        debug.klog("[acpi]   RSDP@0x{x} 1.0 checksum failed (rev={d})\n", .{ addr, r.revision });
        return null;
    }
    if (r.revision >= 2) {
        // ACPI 2.0+ RSDP is exactly 36 bytes per spec. Don't use
        // @sizeOf(Rsdp) here — Zig rounds extern-struct size up to its
        // alignment (8 for the u64 xsdt_address), so @sizeOf == 40 and
        // would falsely reject the spec-correct length 36. i440fx OVMF
        // happens to report 40 (struct-aligned); q35 OVMF reports the
        // spec-correct 36.
        const RSDP_MIN_BYTES: u32 = 36;
        if (r.length < RSDP_MIN_BYTES or r.length > 256) {
            debug.klog("[acpi]   RSDP@0x{x} length {d} out of range\n", .{ addr, r.length });
            return null;
        }
        if (!physRangeMapped(addr, r.length)) return null; // extended body mapped
        if (!checksumOk(@as([*]const u8, @ptrCast(r))[0..r.length])) {
            debug.klog("[acpi]   RSDP@0x{x} extended checksum failed\n", .{addr});
            return null;
        }
    }
    return r;
}

/// Scan the BIOS-era RSDP windows. EBDA is pointed to by the BDA word at
/// 0x40E (segment, multiply by 16 for linear). The high BIOS area
/// 0xE0000..0xFFFFF is always scanned. RSDP is paragraph-aligned.
fn scanBiosRsdp() ?*align(1) const Rsdp {
    // EBDA segment lives in BDA[0x40E:0x410]; the EBDA itself is up to 1 KB.
    // BDA word at phys 0x40E (EBDA segment); read through the physmap so
    // this works without the legacy low identity map.
    const bda_ebda_seg: *const u16 = @ptrFromInt(paging.physToVirt(0x40E));
    const ebda_base: u64 = @as(u64, bda_ebda_seg.*) << 4;
    if (ebda_base != 0 and ebda_base < 0xA0000) {
        var addr: u64 = ebda_base;
        const ebda_end = @min(ebda_base + 1024, 0xA0000);
        while (addr + 20 <= ebda_end) : (addr += 16) {
            if (validateRsdp(addr)) |r| return r;
        }
    }
    var addr: u64 = 0xE0000;
    while (addr + 20 <= 0x100000) : (addr += 16) {
        if (validateRsdp(addr)) |r| return r;
    }
    return null;
}

// --- Table walk -------------------------------------------------------------

/// Cache the pointer to a known-signature table when the walk encounters it.
fn dispatchTable(hdr: *align(1) const SdtHeader) void {
    if (std.mem.eql(u8, &hdr.signature, "FACP")) {
        fadt = @ptrCast(hdr);
    } else if (std.mem.eql(u8, &hdr.signature, "APIC")) {
        madt = @ptrCast(hdr);
    } else if (std.mem.eql(u8, &hdr.signature, "HPET")) {
        hpet = @ptrCast(hdr);
    } else if (std.mem.eql(u8, &hdr.signature, "MCFG")) {
        mcfg = @ptrCast(hdr);
    } else if (std.mem.eql(u8, &hdr.signature, "DMAR")) {
        dmar = @ptrCast(hdr);
    } else if (std.mem.eql(u8, &hdr.signature, "NFIT")) {
        nfit = @ptrCast(hdr);
    } else if (std.mem.eql(u8, &hdr.signature, "SSDT")) {
        // Collect every SSDT; the AML interpreter walks them all into the one
        // namespace (Slice D). Cap silently — overflow just means the namespace
        // misses a late table, never a crash.
        if (nssdt < ssdts.len) {
            ssdts[nssdt] = hdr;
            nssdt += 1;
        }
    }
}

/// Walk an (X)SDT's entry array, dispatching each known-signature table.
/// `Ptr` is the entry-pointer width: `u64` for an XSDT, `u32` for a legacy
/// RSDT. Returns true if the root table's own header validated — the caller
/// uses that to fall back to the RSDT when firmware published a corrupt XSDT.
///
/// Each member table's checksum is verified before caching; a mismatched
/// table is logged and skipped rather than aborting boot, since one bad table
/// shouldn't disable shutdown / SMP / ECAM altogether. All ACPI structure
/// pointers use align(1) — ACPI tables are spec-aligned to 4, but the
/// @ptrFromInt safety check is annoying when firmware does anything unusual,
/// and extern struct accesses with align(1) just work.
///
/// Every firmware-supplied physical address+extent is checked with
/// physRangeMapped before physToVirt, so a wild or oversized pointer becomes a
/// skipped entry instead of an unmapped-VA #PF.
fn walkSdt(comptime Ptr: type, table_phys: u64) bool {
    // The header must be mapped before we can trust-read its length.
    if (!physRangeMapped(table_phys, @sizeOf(SdtHeader))) return false;
    const hdr: *align(1) const SdtHeader = @ptrFromInt(paging.physToVirt(table_phys));
    if (!sdtChecksumOk(table_phys, hdr)) {
        debug.klog("[acpi] root SDT checksum/length FAIL (len={d})\n", .{hdr.length});
        return false;
    }
    const entry_count = (hdr.length - @sizeOf(SdtHeader)) / @sizeOf(Ptr);
    const entries: [*]align(1) const Ptr = @ptrFromInt(paging.physToVirt(table_phys + @sizeOf(SdtHeader)));
    for (0..entry_count) |i| {
        const tbl_phys: u64 = entries[i];
        if (!physRangeMapped(tbl_phys, @sizeOf(SdtHeader))) continue;
        const tbl: *align(1) const SdtHeader = @ptrFromInt(paging.physToVirt(tbl_phys));
        if (!sdtChecksumOk(tbl_phys, tbl)) {
            debug.klog("[acpi] table {s} checksum/length FAIL\n", .{tbl.signature});
            continue;
        }
        debug.klog("[acpi] table {s} len={d} rev={d}\n", .{ tbl.signature, tbl.length, tbl.revision });
        dispatchTable(tbl);
    }
    return true;
}

/// One-time boot-side initialisation. Pass `boot_rsdp` as either the
/// UEFI-provided pointer (preferred) or 0 to fall back to a BIOS scan.
pub fn init(boot_rsdp: u64) void {
    const r = blk: {
        if (boot_rsdp != 0) {
            if (validateRsdp(boot_rsdp)) |x| {
                debug.klog("[acpi] RSDP from UEFI: 0x{x} rev={d}\n", .{ boot_rsdp, x.revision });
                break :blk x;
            }
            debug.klog("[acpi] UEFI RSDP at 0x{x} failed validation; falling back to scan\n", .{boot_rsdp});
        }
        if (scanBiosRsdp()) |x| {
            debug.klog("[acpi] RSDP from BIOS scan: 0x{x} rev={d}\n", .{ @intFromPtr(x), x.revision });
            break :blk x;
        }
        debug.klog("[acpi] no RSDP found — ACPI disabled\n", .{});
        return;
    };

    // Prefer the XSDT (64-bit entry pointers). If firmware published one but
    // it's corrupt, fall back to the RSDT rather than losing every table —
    // some firmware ships a good RSDT alongside a broken XSDT.
    var walked = false;
    if (r.revision >= 2 and r.xsdt_address != 0) {
        walked = walkSdt(u64, r.xsdt_address);
        if (!walked) debug.klog("[acpi] XSDT unusable; falling back to RSDT\n", .{});
    }
    if (!walked and r.rsdt_address != 0) {
        walked = walkSdt(u32, r.rsdt_address);
    }
    if (!walked) {
        debug.klog("[acpi] no usable XSDT or RSDT — ACPI disabled\n", .{});
        return;
    }

    // DSDT isn't an (X)SDT entry — it's reached via FADT. Cache it and extract
    // the `\_S5_` sleep codes so shutdown uses the firmware's real SLP_TYP
    // instead of the spec-default 5 (which only happens to work on QEMU).
    cacheDsdtAndParseS5();

    debug.klog("[acpi] ready: FADT={s} MADT={s} HPET={s} MCFG={s} DMAR={s} NFIT={s}\n", .{
        if (fadt != null) "yes" else "no",
        if (madt != null) "yes" else "no",
        if (hpet != null) "yes" else "no",
        if (mcfg != null) "yes" else "no",
        if (dmar != null) "yes" else "no",
        if (nfit != null) "yes" else "no",
    });

    // Dynamic ACPI (Slice B): decode the DSDT's AML into a namespace. Best-
    // effort + fully bounds-checked; a malformed DSDT yields a partial walk,
    // never a fault. For bring-up this dumps the discovered objects to serial.
    _ = @import("aml.zig").load();
}

// --- MADT iterator ----------------------------------------------------------

/// Iterator over MADT sub-entries. Caller cases on `entry_type` (see MadtType)
/// and casts the header to the concrete struct (MadtLapic/MadtIoapic/MadtIso/…):
///   var it = acpi.madtEntries();
///   while (it.next()) |h| switch (@as(acpi.MadtType, @enumFromInt(h.entry_type))) { ... }
pub const MadtIterator = struct {
    p: usize,
    end: usize,

    pub fn next(self: *MadtIterator) ?*align(1) const MadtEntryHeader {
        if (self.p + @sizeOf(MadtEntryHeader) > self.end) return null;
        const h: *align(1) const MadtEntryHeader = @ptrFromInt(self.p);
        // length must cover its own header (catches 0 and the 1-byte desync
        // that would walk misaligned garbage) and the whole sub-entry must fit
        // before end, or the caller reads past the table.
        if (h.length < @sizeOf(MadtEntryHeader) or self.p + h.length > self.end) return null;
        self.p += h.length;
        return h;
    }
};

/// MADT sub-entry iterator. Yields nothing when no MADT was found.
pub fn madtEntries() MadtIterator {
    const m = madt orelse return .{ .p = 0, .end = 0 };
    return .{ .p = @intFromPtr(m) + @sizeOf(Madt), .end = @intFromPtr(m) + m.header.length };
}

// --- DSDT + `\_S5_` (minimal AML) ------------------------------------------
//
// NOT an AML interpreter — just the one well-trodden pattern match every
// shutdown path needs. A real DSDT encodes S5 as:
//
//     NameOp(0x08) [ '\' 0x5C ]? "_S5_" PackageOp(0x12) PkgLength NumElements
//         <SLP_TYPa> <SLP_TYPb> <reserved> <reserved>
//
// We find `_S5_`, confirm the NameOp/PackageOp framing (so a stray "_S5_"
// inside some buffer can't masquerade as the object), step over the package
// header, and read the first two integer elements. Everything is a small
// integer op: ZeroOp/OneOp/OnesOp or BytePrefix(0x0A)+byte. The AML is
// untrusted firmware, so every index is bounds-checked: a malformed table
// degrades to "not found" (caller keeps the default SLP_TYP=5) instead of
// reading off the end of the DSDT.

/// Locate, validate, and cache the DSDT (reached via FADT, not the (X)SDT),
/// then parse `\_S5_`. Best-effort: any failure leaves s5_slp_typ null and
/// logs why, so shutdown falls back to the spec default.
fn cacheDsdtAndParseS5() void {
    const f = fadt orelse return;

    // Prefer the 64-bit X_DSDT, but only when the FADT is actually long enough
    // to contain it (ACPI 1.0 FADTs stop well before offset 140). Otherwise the
    // 32-bit DSDT pointer.
    var dsdt_phys: u64 = 0;
    if (f.header.length >= @offsetOf(Fadt, "x_dsdt") + @sizeOf(u64) and f.x_dsdt != 0) {
        dsdt_phys = f.x_dsdt;
    } else if (f.dsdt != 0) {
        dsdt_phys = f.dsdt;
    }
    if (dsdt_phys == 0) {
        debug.klog("[acpi] FADT has no DSDT pointer; shutdown uses default SLP_TYP=5\n", .{});
        return;
    }

    if (!physRangeMapped(dsdt_phys, @sizeOf(SdtHeader))) return;
    const hdr: *align(1) const SdtHeader = @ptrFromInt(paging.physToVirt(dsdt_phys));
    if (!std.mem.eql(u8, &hdr.signature, "DSDT")) {
        debug.klog("[acpi] DSDT signature mismatch ({s}); shutdown uses default\n", .{hdr.signature});
        return;
    }
    // 2 MiB cap: QEMU's DSDT is ~8 KiB; even large server DSDTs stay well under
    // this. The bound keeps a corrupt `length` from walking off the physmap.
    if (hdr.length < @sizeOf(SdtHeader) or hdr.length > 2 << 20 or !physRangeMapped(dsdt_phys, hdr.length)) {
        debug.klog("[acpi] DSDT length {d} unusable; shutdown uses default\n", .{hdr.length});
        return;
    }
    dsdt = hdr;
    // A bad DSDT checksum is common on real firmware and doesn't stop us — we
    // bounds-check the scan independently — but it's worth a breadcrumb.
    if (!checksumOk(@as([*]const u8, @ptrCast(hdr))[0..hdr.length]))
        debug.klog("[acpi] DSDT checksum bad (scanning _S5_ anyway)\n", .{});

    // AML proper begins after the 36-byte SDT header.
    const body = @as([*]const u8, @ptrCast(hdr))[@sizeOf(SdtHeader)..hdr.length];
    if (parseS5(body)) |st| {
        s5_slp_typ = st;
        debug.klog("[acpi] \\_S5_ SLP_TYPa={d} SLP_TYPb={d}\n", .{ st.a, st.b });
    } else {
        debug.klog("[acpi] \\_S5_ not found in DSDT; shutdown uses default SLP_TYP=5\n", .{});
    }
}

/// Scan an AML body for the `_S5_` name object and return its SLP_TYPa/b.
/// Keeps scanning past a coincidental `_S5_` byte run that fails the framing
/// check, so the real Name() object is still found.
fn parseS5(aml: []const u8) ?SleepTypes {
    if (aml.len < 4) return null;
    var i: usize = 0;
    while (i + 4 <= aml.len) : (i += 1) {
        if (aml[i] == '_' and aml[i + 1] == 'S' and aml[i + 2] == '5' and aml[i + 3] == '_') {
            if (parseS5At(aml, i)) |st| return st;
        }
    }
    return null;
}

/// Validate the Name/Package framing around `_S5_` at `name_idx` and decode the
/// first two package integers. Returns null on any structural or bounds miss.
fn parseS5At(aml: []const u8, name_idx: usize) ?SleepTypes {
    // NameOp(0x08) must precede the name — directly, or with a single root
    // prefix '\' (0x5C) between (i.e. `\_S5_`). This is what distinguishes the
    // real object from an incidental "_S5_" in data.
    const framed = (name_idx >= 1 and aml[name_idx - 1] == 0x08) or
        (name_idx >= 2 and aml[name_idx - 2] == 0x08 and aml[name_idx - 1] == 0x5C);
    if (!framed) return null;

    // PackageOp(0x12) directly after the 4-char name.
    var p = name_idx + 4;
    if (p >= aml.len or aml[p] != 0x12) return null;
    p += 1; // -> PkgLength byte 0

    // PkgLength field is 1 + ByteCount bytes (ByteCount = top two bits of byte
    // 0); NumElements is one more byte. Step over both to the first element.
    if (p >= aml.len) return null;
    const pkglen_field: usize = 1 + ((aml[p] & 0xC0) >> 6);
    p += pkglen_field + 1;

    const a = readPkgInt(aml, &p) orelse return null;
    // Single-element _S5_ packages exist; default SLP_TYPb to 0 (PM1b is absent
    // on most systems anyway) when the second element is missing/odd.
    const b = readPkgInt(aml, &p) orelse 0;
    return .{ .a = a, .b = b };
}

/// Decode one small-integer AML element at `aml[p.*]`, advancing `p.*` past it.
/// Covers the encodings an `_S5_` package realistically uses. Returns null for
/// out-of-bounds or any other opcode (caller treats as "no value").
fn readPkgInt(aml: []const u8, p: *usize) ?u8 {
    if (p.* >= aml.len) return null;
    switch (aml[p.*]) {
        0x00 => { // ZeroOp
            p.* += 1;
            return 0;
        },
        0x01 => { // OneOp
            p.* += 1;
            return 1;
        },
        0xFF => { // OnesOp
            p.* += 1;
            return 0xFF;
        },
        0x0A => { // BytePrefix + one data byte
            if (p.* + 1 >= aml.len) return null;
            const v = aml[p.* + 1];
            p.* += 2;
            return v;
        },
        else => return null,
    }
}
