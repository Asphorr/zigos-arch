// Last Branch Records — circular ring of the last 32 branches the CPU has
// taken, kept in MSRs by the silicon for free. Capture is automatic; we
// just enable it at boot and read the MSRs at panic time.
//
// Caveat: 32-entry depth means if more than 32 branches happen between
// the corrupting write and our snapshot, the writer is gone. For our
// iretq-frame bug this matters because iretqValidate runs at the END of
// IRQ processing — possibly hundreds of branches after the writer. LBR
// is a flyer; if it doesn't show the writer, the next escalation is BTS
// or full Intel PT.
//
// Skylake/Kaby Lake/Coffee Lake layout: depth=32, IA32_LBR_TOS indexes
// the most recent slot, FROM_N/TO_N MSRs are paired. Bit 63 of FROM_N
// is the misprediction indicator on Skylake+; canonical address is in
// bits 0..47.

const std = @import("std");
const serial = @import("serial.zig");
const symbols = @import("symbols.zig");

const MSR_DEBUGCTL: u32 = 0x1D9;
const DEBUGCTL_LBR_BIT: u64 = 1 << 0;
const MSR_LBR_TOS: u32 = 0x1C9;
const MSR_LBR_FROM_0: u32 = 0x680;
const MSR_LBR_TO_0: u32 = 0x6C0;
const LBR_DEPTH: usize = 32;

var enabled: bool = false;

pub fn enable() void {
    var debugctl = readMsr(MSR_DEBUGCTL);
    debugctl |= DEBUGCTL_LBR_BIT;
    writeMsr(MSR_DEBUGCTL, debugctl);

    // Verify the bit stuck — KVM/Hyper-V may accept the WRMSR silently
    // without actually enabling LBR recording (and reads of LBR_FROM_N
    // may then #GP on us, which would triple-fault from inside any
    // exception handler that snapshots LBR). If verify fails we leave
    // `enabled` false so callers fall through to a zeroed snapshot.
    const verify = readMsr(MSR_DEBUGCTL);
    if ((verify & DEBUGCTL_LBR_BIT) == 0) {
        serial.print("[lbr] DEBUGCTL.LBR did not retain — hypervisor masked it; LBR disabled\n", .{});
        return;
    }
    enabled = true;
    serial.print("[lbr] enabled (DEBUGCTL.LBR=1, depth={d})\n", .{LBR_DEPTH});
}

pub const LbrSnap = struct {
    tos: u64,
    from: [LBR_DEPTH]u64,
    to: [LBR_DEPTH]u64,
};

pub fn snapshot() LbrSnap {
    var snap: LbrSnap = std.mem.zeroes(LbrSnap);
    if (!enabled) return snap;
    // Freeze recording BEFORE reading. Reading the 32 MSR pairs is a loop
    // whose own backedge is a taken branch — left recording, that loop would
    // overwrite the very ring we came to capture with ~31 copies of
    // snapshot()'s own backedge, evicting the spin loop / frame corruptor.
    // Clearing DEBUGCTL.LBR stops recording; the FROM/TO MSRs retain their
    // frozen contents and stay readable. Every caller is on a terminal panic
    // / halt path, so leaving recording off afterwards is harmless.
    freezeRecording();
    snap.tos = readMsr(MSR_LBR_TOS);
    for (0..LBR_DEPTH) |i| {
        snap.from[i] = readMsr(MSR_LBR_FROM_0 + @as(u32, @intCast(i)));
        snap.to[i] = readMsr(MSR_LBR_TO_0 + @as(u32, @intCast(i)));
    }
    return snap;
}

/// Stop LBR recording, preserving every other DEBUGCTL bit. Private —
/// callers reach it via snapshot(), which freezes so its own read loop can't
/// pollute the ring. No-op if LBR was never enabled.
fn freezeRecording() void {
    if (!enabled) return;
    var debugctl = readMsr(MSR_DEBUGCTL);
    debugctl &= ~DEBUGCTL_LBR_BIT;
    writeMsr(MSR_DEBUGCTL, debugctl);
}

/// Print the ring most-recent-first. `tos` is the index of the most
/// recently retired branch; we walk backwards modulo LBR_DEPTH.
pub fn dump(snap: *const LbrSnap) void {
    dumpImpl(snap, false);
}

/// Lock-free variant for NMI / panic-handler context. Uses
/// serial.emergencyPrint so it can't deadlock on a CPU that may hold
/// serial's write_lock — e.g. a wedged CPU caught by the watchdog NMI,
/// dumping its own LBR from inside nmiSnapshot before it halts.
pub fn emergencyDump(snap: *const LbrSnap) void {
    dumpImpl(snap, true);
}

fn dumpImpl(snap: *const LbrSnap, comptime emergency: bool) void {
    if (!enabled) {
        emit(emergency, "[lbr] dump skipped — never enabled\n", .{});
        return;
    }
    emit(emergency, "\n[lbr] last {d} branches (most recent first):\n", .{LBR_DEPTH});
    emit(emergency, "  tos={d}\n", .{snap.tos});
    var i: isize = @intCast(snap.tos);
    var n: usize = 0;
    while (n < LBR_DEPTH) : (n += 1) {
        const idx: usize = @intCast(@mod(i, @as(isize, @intCast(LBR_DEPTH))));
        const from = cleanAddr(snap.from[idx]);
        const to = cleanAddr(snap.to[idx]);
        if (from == 0 and to == 0) {
            i -= 1;
            continue;
        }
        emit(emergency, "  [{d:>2}] ", .{n});
        printSym(from, emergency);
        emit(emergency, " -> ", .{});
        printSym(to, emergency);
        emit(emergency, "\n", .{});
        i -= 1;
    }
}

/// Route a formatted line through the normal locked logger or the lock-free
/// emergency path, chosen at comptime so there is no per-call branch cost.
inline fn emit(comptime emergency: bool, comptime fmt: []const u8, args: anytype) void {
    if (emergency) serial.emergencyPrint(fmt, args) else serial.print(fmt, args);
}

inline fn cleanAddr(raw: u64) u64 {
    // Bit 63 may be the mispredict flag on Skylake+; canonical address
    // is bits 0..47. For our kernel (all branches below 0x10000000)
    // masking bit 47 sign-extension off is fine.
    return raw & 0x0000FFFFFFFFFFFF;
}

fn printSym(addr: u64, comptime emergency: bool) void {
    if (symbols.resolveKernel(addr)) |r| {
        emit(emergency, "{s}+0x{X}", .{ r.name, r.offset });
    } else {
        emit(emergency, "0x{X:0>16}", .{addr});
    }
}

fn readMsr(msr: u32) u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdmsr"
        : [lo] "={eax}" (lo),
          [hi] "={edx}" (hi),
        : [msr] "{ecx}" (msr),
    );
    return @as(u64, lo) | (@as(u64, hi) << 32);
}

fn writeMsr(msr: u32, value: u64) void {
    const lo: u32 = @truncate(value);
    const hi: u32 = @truncate(value >> 32);
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [lo] "{eax}" (lo),
          [hi] "{edx}" (hi),
    );
}
