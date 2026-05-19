// Per-CPU "last action" breadcrumb — one record per CPU, updated at every
// key kernel transition. At panic time, dumping the breadcrumbs tells you
// "cpu0 was deep inside doSyscall when cpu1 crashed in schedule()" without
// having to crawl through the sched ring + exec trail by hand.
//
// Cost: one atomic store per stamp (~1ns). Hot paths stamp on entry only,
// not on exit, so the record reflects the most recent ENTRY — typically the
// most diagnostically useful state. (If a CPU returns from a syscall and
// then sits idle, the breadcrumb stays at the last syscall; that's fine,
// the irq_tick_count tells us the CPU is making progress.)
//
// Design choice: separate from CpuLocal so adding action kinds doesn't
// touch the magic_end canary's layout. Atomically-stored u64 = (kind<<48)
// | (ctx & 0xFFFFFFFFFFFF) so a single load gives both.

const std = @import("std");
const smp = @import("../cpu/smp.zig");
const serial = @import("serial.zig");
const symbols = @import("symbols.zig");

/// Action kinds. Each marks the entry of a key kernel function or
/// transition. Codes are u8 so we can fit them in the high byte of a u64
/// along with a 48-bit context word.
///
/// Add new kinds at the END to preserve numeric values for log forensics —
/// log files reference codes by number in older runs.
pub const Kind = enum(u8) {
    none = 0,
    syscall_entry = 1, // ctx = syscall number
    irq0_timer = 2, // ctx = current_pid
    irq_dynamic = 3, // ctx = (vec << 16) | pid
    exception_entry = 4, // ctx = (vec << 32) | pid
    schedule_enter = 5, // ctx = current_pid (caller)
    schedule_dispatch = 6, // ctx = next_pid (selected)
    switch_to = 7, // ctx = next_kesp low 48 bits
    teardown_start = 8, // ctx = dying pid
    teardown_done = 9, // ctx = dying pid
};

/// One per-CPU breadcrumb. Single u64 atomic — no padding/alignment churn.
/// (kind << 48) | (ctx & 0x0000FFFFFFFFFFFF). Bit-packing keeps stamp at
/// one mov instruction.
const PACKED_KIND_SHIFT: u6 = 48;
const PACKED_CTX_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

pub var breadcrumbs: [smp.MAX_CPUS]u64 = [_]u64{0} ** smp.MAX_CPUS;

/// Stamp the current CPU's breadcrumb. Inline + atomic-store so the cost is
/// one indexed mov on the hot path. Safe to call from any context (cli or
/// not, kernel or user-entered).
pub inline fn stamp(kind: Kind, ctx: u64) void {
    const cpu = smp.myCpu();
    const packed_v: u64 = (@as(u64, @intFromEnum(kind)) << PACKED_KIND_SHIFT) |
        (ctx & PACKED_CTX_MASK);
    @atomicStore(u64, &breadcrumbs[cpu.cpu_id], packed_v, .monotonic);
}

fn kindName(k: Kind) []const u8 {
    return switch (k) {
        .none => "NONE",
        .syscall_entry => "SYSCALL",
        .irq0_timer => "IRQ0",
        .irq_dynamic => "IRQ_DYN",
        .exception_entry => "EXC",
        .schedule_enter => "SCHED_ENTER",
        .schedule_dispatch => "SCHED_DISPATCH",
        .switch_to => "SWITCH_TO",
        .teardown_start => "TEARDOWN_START",
        .teardown_done => "TEARDOWN_DONE",
    };
}

/// Dump all alive CPUs' breadcrumbs. Called from the crash autopsy after
/// dumpCpuSnapshot. Format chosen to be grep-friendly:
/// `[breadcrumb cpu0] kind=SYSCALL ctx=0x2A` (ctx interpretation depends
/// on kind — see Kind comments).
pub fn dump() void {
    serial.print("[kdbg] breadcrumbs (last per-CPU action):\n", .{});
    for (0..smp.MAX_CPUS) |i| {
        const cpu = &smp.cpus[i];
        if (i > 0 and !cpu.alive) continue;
        const v = @atomicLoad(u64, &breadcrumbs[i], .monotonic);
        const kind_u: u8 = @intCast(v >> PACKED_KIND_SHIFT);
        const ctx: u64 = v & PACKED_CTX_MASK;
        const kind: Kind = if (kind_u <= @intFromEnum(Kind.teardown_done))
            @enumFromInt(kind_u)
        else
            .none;
        serial.print(
            "  [breadcrumb cpu{d}] kind={s} ctx=0x{X}\n",
            .{ i, kindName(kind), ctx },
        );
    }
}
