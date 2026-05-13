// Machine Check Exception (vector 18) handler.
//
// Architectural model (Intel SDM Vol. 3B Ch. 16): the CPU exposes N banks
// of MSRs at 0x400 + 4*i. Each bank has STATUS / ADDR / MISC / CTL MSRs.
// On a #MC the CPU writes the offending bank's STATUS with bits indicating
// whether the error is corrected (CE), uncorrected (UC), or fatal
// (UC + PCC = processor-context-corrupt). The handler's job is to:
//   1. Walk every bank looking for STATUS.VAL (bit 63) = 1.
//   2. Log the bank index + decoded fields.
//   3. Clear STATUS (write 0 — required so the next #MC observes a fresh
//      state).
//   4. Decide: corrected → log and resume; uncorrected → also clear and
//      try to resume; PCC fatal → panic.
//
// On QEMU TCG #MC almost never fires (no model for ECC errors). On KVM
// the host's mcelog can inject. On real HW DRAM ECC errors are the
// usual source. We still wire this up because the existing handleException
// treats vec 18 as a generic panic, which loses all the bank state.

const std = @import("std");
const debug = @import("../debug/debug.zig");
const serial = @import("../debug/serial.zig");

const MSR_IA32_MCG_CAP: u32 = 0x179;
const MSR_IA32_MCG_STATUS: u32 = 0x17A;
const MSR_IA32_MCG_CTL: u32 = 0x17B;
const MSR_IA32_MC0_CTL: u32 = 0x400;

// Per-bank MSR offsets (relative to MC0_CTL + bank*4).
const OFF_CTL: u32 = 0;
const OFF_STATUS: u32 = 1;
const OFF_ADDR: u32 = 2;
const OFF_MISC: u32 = 3;

// STATUS bits.
const STATUS_VAL: u64 = 1 << 63;
const STATUS_OVER: u64 = 1 << 62;
const STATUS_UC: u64 = 1 << 61;
const STATUS_EN: u64 = 1 << 60;
const STATUS_MISCV: u64 = 1 << 59;
const STATUS_ADDRV: u64 = 1 << 58;
const STATUS_PCC: u64 = 1 << 57;
const STATUS_S: u64 = 1 << 56; // signaling
const STATUS_AR: u64 = 1 << 55; // action required

// MCG_STATUS bits.
const MCG_STATUS_RIPV: u64 = 1 << 0;
const MCG_STATUS_EIPV: u64 = 1 << 1;
const MCG_STATUS_MCIP: u64 = 1 << 2;

pub var bank_count: u32 = 0;
pub var initialized: bool = false;

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

inline fn cpuid(leaf: u32, sub: u32) struct { eax: u32, ebx: u32, ecx: u32, edx: u32 } {
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
          [_] "{ecx}" (sub),
    );
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

/// Probe CPU for Machine Check support (CPUID.01H:EDX.MCE = bit 7;
/// .MCA = bit 14) and enable all banks. Call once on the BSP.
pub fn detect() void {
    const r = cpuid(1, 0);
    const mce_supported = (r.edx & (1 << 7)) != 0;
    const mca_supported = (r.edx & (1 << 14)) != 0;
    if (!mce_supported or !mca_supported) {
        debug.klog("[mce] CPUID: MCE={s} MCA={s} — skipping MC init\n", .{
            if (mce_supported) "y" else "n",
            if (mca_supported) "y" else "n",
        });
        return;
    }
    const cap = rdmsr(MSR_IA32_MCG_CAP);
    bank_count = @intCast(cap & 0xFF);
    const ctl_p: bool = (cap & (1 << 8)) != 0;
    debug.klog("[mce] MCG_CAP banks={d} ctl_p={s}\n", .{
        bank_count,
        if (ctl_p) "y" else "n",
    });
    // Globally enable all error reporting (if MCG_CTL exists, write all-1s).
    if (ctl_p) wrmsr(MSR_IA32_MCG_CTL, ~@as(u64, 0));
    // Enable all banks and start with cleared status.
    initBanks();
    // Flip CR4.MCE (bit 6) so #MC actually delivers as vector 18.
    var cr4 = asm volatile ("mov %%cr4, %[r]"
        : [r] "=r" (-> u64),
    );
    cr4 |= (1 << 6);
    asm volatile ("mov %[v], %%cr4"
        :
        : [v] "r" (cr4),
    );
    initialized = true;
}

/// Per-CPU init. APs call this after entering long mode so each CPU's
/// own MCi_CTL gets enabled (banks are largely per-thread for the
/// shared-resource ones, per-core for L1/L2).
pub fn perCpuInit() void {
    if (!initialized) return;
    initBanks();
    var cr4 = asm volatile ("mov %%cr4, %[r]"
        : [r] "=r" (-> u64),
    );
    cr4 |= (1 << 6);
    asm volatile ("mov %[v], %%cr4"
        :
        : [v] "r" (cr4),
    );
}

fn initBanks() void {
    var i: u32 = 0;
    while (i < bank_count) : (i += 1) {
        // Some Intel CPUs require bank 0's MC0_CTL to remain at 0 (legacy
        // Pentium 6 erratum). Modern Kaby Lake doesn't, but be safe and
        // mirror Linux: skip writing CTL for bank 0 on first init.
        if (i != 0) wrmsr(MSR_IA32_MC0_CTL + 4 * i + OFF_CTL, ~@as(u64, 0));
        wrmsr(MSR_IA32_MC0_CTL + 4 * i + OFF_STATUS, 0);
    }
}

/// Walk every MC bank, log any with STATUS.VAL=1, clear them. Returns
/// `.fatal` if any uncorrected error with PCC set was found; otherwise
/// `.recovered` (corrected or recoverable uncorrected, kernel resumes).
pub const Outcome = enum { recovered, fatal };

pub fn handle() Outcome {
    var any_fatal = false;
    var n: u32 = 0;
    const mcg = rdmsr(MSR_IA32_MCG_STATUS);
    serial.print("[mce] #MC fired MCG_STATUS=0x{X:0>16} RIPV={d} EIPV={d} MCIP={d}\n", .{
        mcg,
        @intFromBool((mcg & MCG_STATUS_RIPV) != 0),
        @intFromBool((mcg & MCG_STATUS_EIPV) != 0),
        @intFromBool((mcg & MCG_STATUS_MCIP) != 0),
    });
    var i: u32 = 0;
    while (i < bank_count) : (i += 1) {
        const sbase = MSR_IA32_MC0_CTL + 4 * i;
        const status = rdmsr(sbase + OFF_STATUS);
        if ((status & STATUS_VAL) == 0) continue;
        n += 1;
        const fatal = (status & STATUS_UC) != 0 and (status & STATUS_PCC) != 0;
        const addr_v = (status & STATUS_ADDRV) != 0;
        const misc_v = (status & STATUS_MISCV) != 0;
        const addr: u64 = if (addr_v) rdmsr(sbase + OFF_ADDR) else 0;
        const misc: u64 = if (misc_v) rdmsr(sbase + OFF_MISC) else 0;
        const mcacod: u16 = @truncate(status & 0xFFFF);
        const msec: u16 = @truncate((status >> 16) & 0xFFFF);
        serial.print(
            "[mce] bank{d} STATUS=0x{X:0>16} UC={d} PCC={d} OVER={d} mcacod=0x{X:0>4} msec=0x{X:0>4} addr=0x{X:0>16} misc=0x{X:0>16}\n",
            .{
                i,
                status,
                @intFromBool((status & STATUS_UC) != 0),
                @intFromBool((status & STATUS_PCC) != 0),
                @intFromBool((status & STATUS_OVER) != 0),
                mcacod,
                msec,
                addr,
                misc,
            },
        );
        // Clear by writing 0 so the next #MC observes a clean bank.
        wrmsr(sbase + OFF_STATUS, 0);
        if (fatal) any_fatal = true;
    }
    if (n == 0) {
        serial.print("[mce] no banks with STATUS.VAL — spurious #MC?\n", .{});
    }
    // Clear MCG_STATUS so subsequent #MCs can be distinguished from this one.
    wrmsr(MSR_IA32_MCG_STATUS, 0);
    return if (any_fatal) Outcome.fatal else Outcome.recovered;
}
