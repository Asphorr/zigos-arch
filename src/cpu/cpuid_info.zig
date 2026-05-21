// CPU / microcode / APIC topology observability.
//
// One-shot dump at boot of the data points you wish you had captured the
// first time something goes weird on real HW:
//   - CPUID(0) vendor string
//   - CPUID(0x80000002..4) brand string (full marketing name)
//   - CPUID(1) family / model / stepping (raw + extended)
//   - CPUID(0x40000000) hypervisor vendor (when running virtualized)
//   - CPUID(0x80000008) MAXPHYADDR (matters for MTRR / paging masks)
//   - CPUID(0xB) topology (threads/core, cores/package)
//   - x2APIC capability bit
//   - IA32_BIOS_SIGN_ID / MSR_AMD64_PATCH_LEVEL microcode revision
//   - LAPIC ID list from MADT (sparse/dense, x2APIC vs xAPIC, BSP marker)
//
// On QEMU/KVM these always look "boring" (same values every boot). On real
// HW these are usually the first datapoints needed to triage an issue:
// "wait, that's a Skylake stepping with no microcode update applied" or
// "this BIOS hands us non-sequential LAPIC IDs."

const serial = @import("../debug/serial.zig");
const acpi = @import("../time/acpi.zig");

inline fn cpuid(leaf: u32, subleaf: u32) struct { eax: u32, ebx: u32, ecx: u32, edx: u32 } {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (eax),
          [_] "={ebx}" (ebx),
          [_] "={ecx}" (ecx),
          [_] "={edx}" (edx),
        : [_] "{eax}" (leaf),
          [_] "{ecx}" (subleaf),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

inline fn rdmsr(msr: u32) u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdmsr"
        : [_] "={eax}" (lo),
          [_] "={edx}" (hi),
        : [_] "{ecx}" (msr),
    );
    return (@as(u64, hi) << 32) | lo;
}

inline fn wrmsr(msr: u32, value: u64) void {
    asm volatile ("wrmsr"
        :
        : [_] "{ecx}" (msr),
          [_] "{eax}" (@as(u32, @truncate(value))),
          [_] "{edx}" (@as(u32, @truncate(value >> 32))),
    );
}

/// Verify required CPU features are present. Refuses to boot with a
/// clear message if any are missing — better than the default behavior
/// of GP-faulting deep inside paging/syscall init with no diagnostic.
///
/// All features here are mandatory on x86_64 (per AMD64 SDM Vol 1 §3.1)
/// and we already depend on them downstream:
///   CPUID.01H:EDX:
///     - SSE2 (bit 26)    — userspace + kernel use SSE registers
///     - FXSR (bit 24)    — kernel FXSAVE/FXRSTOR per process (#UD without)
///     - PAT  (bit 16)    — paging.setupPat() needs it
///     - CMOV (bit 15)    — emitted by Zig codegen
///     - APIC (bit 9)     — IPI, LAPIC timer
///     - MSR  (bit 5)     — STAR/LSTAR/EFER, IA32_PAT, etc.
///     - TSC  (bit 4)     — apic.zig calibration + scheduler
///     - FPU  (bit 0)
///   CPUID.80000001H:EDX:
///     - SYSCALL/SYSRET (bit 11) — syscall_entry uses these (#UD without)
///     - NX (bit 20)             — paging sets EFER.NXE (#GP without)
///
/// Call from BSP boot before paging.setupPat() / syscall_entry.init().
pub fn requireFeatures() void {
    const REQUIRED_EDX: u32 =
        (1 << 0) | // FPU
        (1 << 4) | // TSC
        (1 << 5) | // MSR
        (1 << 9) | // APIC
        (1 << 15) | // CMOV
        (1 << 16) | // PAT
        (1 << 24) | // FXSR
        (1 << 26); // SSE2
    const REQUIRED_EXT_EDX: u32 =
        (1 << 11) | // SYSCALL/SYSRET
        (1 << 20); // NX

    const fms = cpuid(1, 0);
    const ext_max = cpuid(0x80000000, 0).eax;
    const ext_edx: u32 = if (ext_max >= 0x80000001) cpuid(0x80000001, 0).edx else 0;

    const got = fms.edx & REQUIRED_EDX;
    const got_ext = ext_edx & REQUIRED_EXT_EDX;
    if (got == REQUIRED_EDX and got_ext == REQUIRED_EXT_EDX) return;

    const missing = REQUIRED_EDX & ~got;
    const missing_ext = REQUIRED_EXT_EDX & ~got_ext;
    serial.print("\n!!! ZigOS requires CPU features missing on this machine\n", .{});
    if (missing != 0) {
        serial.print("    CPUID.01H:EDX = 0x{X}, missing bits = 0x{X}\n", .{ fms.edx, missing });
        if (missing & (1 << 0) != 0) serial.print("    - FPU (bit 0)\n", .{});
        if (missing & (1 << 4) != 0) serial.print("    - TSC (bit 4)\n", .{});
        if (missing & (1 << 5) != 0) serial.print("    - MSR access (bit 5)\n", .{});
        if (missing & (1 << 9) != 0) serial.print("    - APIC (bit 9)\n", .{});
        if (missing & (1 << 15) != 0) serial.print("    - CMOV (bit 15)\n", .{});
        if (missing & (1 << 16) != 0) serial.print("    - PAT (bit 16)\n", .{});
        if (missing & (1 << 24) != 0) serial.print("    - FXSR (bit 24)\n", .{});
        if (missing & (1 << 26) != 0) serial.print("    - SSE2 (bit 26)\n", .{});
    }
    if (missing_ext != 0) {
        serial.print("    CPUID.80000001H:EDX = 0x{X}, missing bits = 0x{X}\n", .{ ext_edx, missing_ext });
        if (missing_ext & (1 << 11) != 0) serial.print("    - SYSCALL/SYSRET (bit 11)\n", .{});
        if (missing_ext & (1 << 20) != 0) serial.print("    - NX (bit 20)\n", .{});
    }
    serial.print("    halting.\n", .{});
    while (true) asm volatile ("cli\nhlt");
}

// MTRR memory-type names. Matches IA32_MTRR_DEF_TYPE / IA32_MTRR_PHYSBASE_n
// type encoding (Intel SDM Vol 3A §11.11).
fn mtrrTypeName(t: u8) []const u8 {
    return switch (t) {
        0 => "UC",
        1 => "WC",
        4 => "WT",
        5 => "WP",
        6 => "WB",
        else => "??",
    };
}

/// MAXPHYADDR (CPUID.80000008H:EAX[7:0]) — width of valid physical address
/// bits on this CPU. Common values: 36 (older Intel mobile), 39 (Skylake-
/// laptop), 46/48 (servers), 52 (theoretical max). Falls back to 36 if
/// leaf 0x80000008 is absent (very old CPUs). Spec caps at 52 in long mode.
fn maxPhysAddrBits() u8 {
    const ext_max = cpuid(0x80000000, 0).eax;
    if (ext_max >= 0x80000008) return @truncate(cpuid(0x80000008, 0).eax & 0xFF);
    return 36;
}

/// Dump MTRR config. Tells you whether firmware set the framebuffer to WC
/// or UC — combined with our PA4=WC, this resolves the question "why is
/// the desktop slow on real HW." Effective memory type = the *more
/// restrictive* of MTRR and PAT, so MTRR=UC vs MTRR=WC over the FB range
/// determines whether our PAT setting has any effect.
pub fn dumpMtrrs() void {
    // CPUID.01H:EDX bit 12 = MTRR. Older atoms / embedded CPUs may not
    // have it, so probe before reading the MSRs.
    const fms = cpuid(1, 0);
    if (fms.edx & (1 << 12) == 0) {
        serial.print("[mtrr] not supported\n", .{});
        return;
    }

    // Phys-addr mask must respect MAXPHYADDR — older laptops have only
    // 36–39 bits, and the upper bits of the MTRR base/mask MSRs are
    // reserved (read 0, but a hardcoded 52-bit mask would print garbage in
    // the upper nibble on those CPUs). Spec caps MAXPHYADDR at 52 in long
    // mode; clamp defensively in case CPUID lies.
    const safe_bits: u8 = @min(maxPhysAddrBits(), 52);
    const addr_mask: u64 = ((@as(u64, 1) << @as(u6, @intCast(safe_bits))) - 1) & ~@as(u64, 0xFFF);

    // IA32_MTRRCAP (0xFE): vcnt[7:0] = number of variable MTRRs.
    const cap = rdmsr(0xFE);
    const vcnt: u8 = @truncate(cap & 0xFF);
    const has_fixed = (cap & (1 << 8)) != 0;
    const has_wc = (cap & (1 << 10)) != 0;

    // IA32_MTRR_DEF_TYPE (0x2FF): default memory type, MTRR enable, fixed enable.
    const def = rdmsr(0x2FF);
    const def_type: u8 = @truncate(def & 0xFF);
    const fixed_en = (def & (1 << 10)) != 0;
    const mtrr_en = (def & (1 << 11)) != 0;

    serial.print("[mtrr] cap: vcnt={d} fixed={s} wc={s}\n", .{
        vcnt,
        if (has_fixed) "y" else "n",
        if (has_wc) "y" else "n",
    });
    serial.print("[mtrr] def_type={s} mtrr_en={s} fixed_en={s}\n", .{
        mtrrTypeName(def_type),
        if (mtrr_en) "y" else "n",
        if (fixed_en) "y" else "n",
    });

    if (!mtrr_en) return;

    // Variable MTRRs: pairs at 0x200 (PHYSBASE_n) / 0x201 (PHYSMASK_n).
    // PHYSBASE: bits 7:0 = type, 12+ = base phys.
    // PHYSMASK: bit 11 = valid, 12+ = mask. Length = ~mask + 1 (in pages).
    var i: u8 = 0;
    while (i < vcnt and i < 16) : (i += 1) {
        const base = rdmsr(0x200 + @as(u32, i) * 2);
        const mask = rdmsr(0x201 + @as(u32, i) * 2);
        if (mask & (1 << 11) == 0) continue; // not valid → skip
        const t: u8 = @truncate(base & 0xFF);
        const phys_base = base & addr_mask;
        const phys_mask = mask & addr_mask;
        // MTRR masks are required to be a contiguous run of 1s in the upper
        // bits — region size = 1 << ctz(mask). (Intel SDM Vol 3A §11.11.3)
        const size_ctz = @ctz(phys_mask);
        const size_bytes: u64 = @as(u64, 1) << @as(u6, @intCast(size_ctz));
        serial.print("[mtrr] var[{d}] {s} base=0x{X} size=", .{ i, mtrrTypeName(t), phys_base });
        if (size_bytes >= 1024 * 1024) {
            serial.print("{d} MB\n", .{size_bytes / (1024 * 1024)});
        } else {
            serial.print("{d} KB\n", .{size_bytes / 1024});
        }
    }
}

/// Dump CPU info to serial. Safe to call on BSP early in boot (no
/// dependencies beyond the serial driver).
pub fn dumpCpuInfo() void {
    // --- Vendor string ---
    const v = cpuid(0, 0);
    var vendor: [12]u8 = undefined;
    vendor[0..4].* = @bitCast(v.ebx);
    vendor[4..8].* = @bitCast(v.edx);
    vendor[8..12].* = @bitCast(v.ecx);

    // --- Family / model / stepping ---
    const fms = cpuid(1, 0);
    const stepping: u32 = fms.eax & 0xF;
    const base_model: u32 = (fms.eax >> 4) & 0xF;
    const base_family: u32 = (fms.eax >> 8) & 0xF;
    const ext_model: u32 = (fms.eax >> 16) & 0xF;
    const ext_family: u32 = (fms.eax >> 20) & 0xFF;
    // Per Intel/AMD convention: if base_family == 6 or 0xF, combine with extensions.
    const family: u32 = if (base_family == 0x6 or base_family == 0xF) base_family + ext_family else base_family;
    const model: u32 = if (base_family == 0x6 or base_family == 0xF) base_model | (ext_model << 4) else base_model;

    serial.print("[cpu] vendor=\"{s}\" family=0x{X} model=0x{X} stepping=0x{X}\n", .{ vendor, family, model, stepping });

    // --- Brand string (marketing name) ---
    var brand: [48]u8 = undefined;
    const ext_max = cpuid(0x80000000, 0).eax;
    if (ext_max >= 0x80000004) {
        var off: usize = 0;
        var leaf: u32 = 0x80000002;
        while (leaf <= 0x80000004) : (leaf += 1) {
            const b = cpuid(leaf, 0);
            brand[off..][0..4].* = @bitCast(b.eax);
            brand[off + 4 ..][0..4].* = @bitCast(b.ebx);
            brand[off + 8 ..][0..4].* = @bitCast(b.ecx);
            brand[off + 12 ..][0..4].* = @bitCast(b.edx);
            off += 16;
        }
        // Trim trailing NULs / spaces for readability.
        var trim: usize = 48;
        while (trim > 0 and (brand[trim - 1] == 0 or brand[trim - 1] == ' ')) : (trim -= 1) {}
        serial.print("[cpu] brand=\"{s}\"\n", .{brand[0..trim]});
    }

    // --- Hypervisor vendor (when ECX[31] is set) ---
    // CPUID.40000000H is non-architectural but every modern hypervisor uses
    // the same convention — a 12-byte vendor ID in EBX/ECX/EDX. Lets us
    // distinguish QEMU+TCG ("TCGTCGTCGTCG") from QEMU+KVM ("KVMKVMKVM"),
    // Microsoft Hv, bhyve, VMware, etc., from the boot dump alone.
    if (fms.ecx & (1 << 31) != 0) {
        const hv = cpuid(0x40000000, 0);
        var hv_str: [12]u8 = undefined;
        hv_str[0..4].* = @bitCast(hv.ebx);
        hv_str[4..8].* = @bitCast(hv.ecx);
        hv_str[8..12].* = @bitCast(hv.edx);
        serial.print("[cpu] hypervisor=\"{s}\"\n", .{hv_str});
    }

    // --- Phys-addr width + x2APIC capability ---
    const maxphy = maxPhysAddrBits();
    const has_x2apic = (fms.ecx & (1 << 21)) != 0;
    serial.print("[cpu] maxphyaddr={d} bits  x2apic={s}\n", .{
        maxphy,
        if (has_x2apic) "y" else "n",
    });

    // --- Topology (CPUID leaf 0xB) ---
    // Subleaves walk topology levels by type code in ECX[15:8]:
    //   1 = SMT (logical → core)    ebx = threads per core
    //   2 = Core (core → package)   ebx = logical procs per package
    // 0 terminates. We only care about threads/core and cores/package —
    // enough to confirm SMT is enabled and the SMP plumbing matches firmware.
    const max_basic = cpuid(0, 0).eax;
    if (max_basic >= 0xB) {
        var threads_per_core: u32 = 1;
        var logical_per_pkg: u32 = 1;
        var sub: u32 = 0;
        while (sub < 4) : (sub += 1) {
            const r = cpuid(0xB, sub);
            const level_type = (r.ecx >> 8) & 0xFF;
            if (level_type == 0) break;
            const procs = r.ebx & 0xFFFF;
            if (level_type == 1) threads_per_core = procs;
            if (level_type == 2) logical_per_pkg = procs;
        }
        const cores_per_pkg: u32 = if (threads_per_core > 0) logical_per_pkg / threads_per_core else 0;
        serial.print("[cpu] topology: threads/core={d} cores/pkg={d}\n", .{ threads_per_core, cores_per_pkg });
    }

    // --- Microcode revision ---
    // Intel (IA32_BIOS_SIGN_ID): write 0 to MSR 0x8B, execute CPUID(1),
    // then read MSR 0x8B; loaded revision is in bits 63:32.
    // AMD (MSR_AMD64_PATCH_LEVEL): same MSR number, but read directly
    // with the patch level in bits 31:0 — no zero+cpuid dance required.
    // Doing the Intel dance on AMD then reading bits 63:32 returns 0,
    // which is what the previous version of this code reported (wrong).
    const is_amd = v.ebx == 0x68747541; // "Auth" (AuthenticAMD)
    const ucode_rev: u32 = if (is_amd) blk: {
        break :blk @truncate(rdmsr(0x8B));
    } else blk: {
        wrmsr(0x8B, 0);
        _ = cpuid(1, 0);
        break :blk @truncate(rdmsr(0x8B) >> 32);
    };
    serial.print("[cpu] microcode rev=0x{X}\n", .{ucode_rev});

    // --- APIC topology from MADT ---
    if (acpi.getMadt() == null) {
        serial.print("[cpu] no MADT — APIC topology unknown\n", .{});
        return;
    }
    const bsp_id: u32 = blk: {
        const id_reg = cpuid(1, 0).ebx;
        break :blk id_reg >> 24;
    };
    serial.print("[cpu] LAPIC IDs (BSP=0x{X}): ", .{bsp_id});
    var count: u32 = 0;
    var it = acpi.madtEntries();
    while (it.next()) |h| {
        switch (@as(acpi.MadtType, @enumFromInt(h.entry_type))) {
            .processor_lapic => {
                const e: *align(1) const acpi.MadtLapic = @ptrCast(h);
                if (e.flags & 1 == 0) continue;
                if (count > 0) serial.print(", ", .{});
                if (e.apic_id == bsp_id) {
                    serial.print("0x{X}*", .{e.apic_id});
                } else {
                    serial.print("0x{X}", .{e.apic_id});
                }
                count += 1;
            },
            .processor_x2apic => {
                const e: *align(1) const acpi.MadtX2Apic = @ptrCast(h);
                if (e.flags & 1 == 0) continue;
                if (count > 0) serial.print(", ", .{});
                if (e.x2apic_id == bsp_id) {
                    serial.print("0x{X}*x2", .{e.x2apic_id});
                } else {
                    serial.print("0x{X}x2", .{e.x2apic_id});
                }
                count += 1;
            },
            else => {},
        }
    }
    serial.print(" ({d} enabled)\n", .{count});
}
