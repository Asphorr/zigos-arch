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

// --- Module state ----------------------------------------------------------

var fadt: ?*align(1) const Fadt = null;
var madt: ?*align(1) const Madt = null;
var hpet: ?*align(1) const Hpet = null;
var mcfg: ?*align(1) const Mcfg = null;

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
    if (f.flags & FADT_F_RESET_REG_SUP == 0) return;
    if (f.reset_reg.address == 0) return;
    const io = @import("../io.zig");
    switch (f.reset_reg.addr_space) {
        // System I/O space (most common — even modern systems use this for
        // reset-control registers because they predate MMIO config).
        1 => io.outb(@truncate(f.reset_reg.address), f.reset_value),
        // System Memory (MMIO). Some server boards use this; a single byte
        // write at the indicated address triggers reset.
        0 => {
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

// --- Checksum + validation --------------------------------------------------

fn checksumOk(bytes: [*]const u8, len: usize) bool {
    var sum: u8 = 0;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        sum +%= bytes[i];
    }
    return sum == 0;
}

// --- RSDP discovery ---------------------------------------------------------

/// Validate the bytes at `addr` as an RSDP. The 1.0 checksum covers the
/// first 20 bytes; revision >= 2 also requires the extended checksum
/// over the full `length` field.
fn validateRsdp(addr: u64) ?*align(1) const Rsdp {
    if (addr == 0) return null;
    const r: *align(1) const Rsdp = @ptrFromInt(paging.physToVirt(addr));
    if (!std.mem.eql(u8, &r.signature, "RSD PTR ")) return null;
    if (!checksumOk(@ptrCast(r), 20)) return null;
    if (r.revision >= 2) {
        // r.length lives at offset 20 — outside the 1.0 checksum we just
        // verified. A corrupt/spoofed RSDP could carry a garbage length
        // (e.g. 0x80000000) that would walk checksumOk off the end of
        // mapped memory and fault. Real RSDPs are <= 36 bytes; cap at
        // 256 for headroom against future spec extensions.
        if (r.length < @sizeOf(Rsdp) or r.length > 256) return null;
        if (!checksumOk(@ptrCast(r), r.length)) return null;
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
    }
}

/// Iterate XSDT entries (8-byte pointers). Verifies each table's
/// checksum before caching it; mismatched tables are logged and skipped
/// rather than aborting boot, since one bad table shouldn't disable
/// shutdown / SMP / ECAM altogether. All ACPI structure pointers use
/// align(1) — ACPI tables are spec-aligned to 4, but the safety check
/// in @ptrFromInt is annoying when firmware does anything unusual, and
/// extern struct accesses with align(1) just work.
fn walkXsdt(xsdt_phys: u64) void {
    const hdr: *align(1) const SdtHeader = @ptrFromInt(paging.physToVirt(xsdt_phys));
    if (!checksumOk(@ptrCast(hdr), hdr.length)) {
        debug.klog("[acpi] XSDT checksum FAIL\n", .{});
        return;
    }
    const entry_count = (hdr.length - @sizeOf(SdtHeader)) / 8;
    const entries: [*]align(1) const u64 = @ptrFromInt(paging.physToVirt(xsdt_phys + @sizeOf(SdtHeader)));
    var i: usize = 0;
    while (i < entry_count) : (i += 1) {
        const tbl_phys = entries[i];
        if (tbl_phys == 0) continue;
        const tbl: *align(1) const SdtHeader = @ptrFromInt(paging.physToVirt(tbl_phys));
        if (!checksumOk(@ptrCast(tbl), tbl.length)) {
            debug.klog("[acpi] table {s} checksum FAIL\n", .{tbl.signature});
            continue;
        }
        debug.klog("[acpi] table {s} len={d} rev={d}\n", .{ tbl.signature, tbl.length, tbl.revision });
        dispatchTable(tbl);
    }
}

/// Same as walkXsdt but for legacy 32-bit pointers (RSDT). Used when
/// firmware only published an RSDT (revision < 2 or no XSDT given).
fn walkRsdt(rsdt_phys: u64) void {
    const hdr: *align(1) const SdtHeader = @ptrFromInt(paging.physToVirt(rsdt_phys));
    if (!checksumOk(@ptrCast(hdr), hdr.length)) {
        debug.klog("[acpi] RSDT checksum FAIL\n", .{});
        return;
    }
    const entry_count = (hdr.length - @sizeOf(SdtHeader)) / 4;
    const entries: [*]align(1) const u32 = @ptrFromInt(paging.physToVirt(rsdt_phys + @sizeOf(SdtHeader)));
    var i: usize = 0;
    while (i < entry_count) : (i += 1) {
        const tbl_phys = entries[i];
        if (tbl_phys == 0) continue;
        const tbl: *align(1) const SdtHeader = @ptrFromInt(paging.physToVirt(tbl_phys));
        if (!checksumOk(@ptrCast(tbl), tbl.length)) {
            debug.klog("[acpi] table {s} checksum FAIL\n", .{tbl.signature});
            continue;
        }
        debug.klog("[acpi] table {s} len={d} rev={d}\n", .{ tbl.signature, tbl.length, tbl.revision });
        dispatchTable(tbl);
    }
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

    if (r.revision >= 2 and r.xsdt_address != 0) {
        walkXsdt(r.xsdt_address);
    } else if (r.rsdt_address != 0) {
        walkRsdt(@as(u64, r.rsdt_address));
    } else {
        debug.klog("[acpi] RSDP has no XSDT or RSDT pointer\n", .{});
        return;
    }

    debug.klog("[acpi] ready: FADT={s} MADT={s} HPET={s} MCFG={s}\n", .{
        if (fadt != null) "yes" else "no",
        if (madt != null) "yes" else "no",
        if (hpet != null) "yes" else "no",
        if (mcfg != null) "yes" else "no",
    });
}

// --- MADT iterator ----------------------------------------------------------
//
// Walk MADT sub-entries with a callback. `cb` is called once per entry; it
// receives a pointer to the variable-length sub-entry header. Caller cases
// on `header.entry_type` and casts to MadtLapic/MadtIoapic/MadtIso/etc.

pub fn forEachMadtEntry(comptime Ctx: type, ctx: *Ctx, cb: *const fn (*Ctx, *align(1) const MadtEntryHeader) void) void {
    const m = madt orelse return;
    const base: usize = @intFromPtr(m) + @sizeOf(Madt);
    const end: usize = @intFromPtr(m) + m.header.length;
    var p: usize = base;
    while (p + @sizeOf(MadtEntryHeader) <= end) {
        const h: *align(1) const MadtEntryHeader = @ptrFromInt(p);
        if (h.length == 0) break; // malformed — bail rather than infinite loop
        cb(ctx, h);
        p += h.length;
    }
}
