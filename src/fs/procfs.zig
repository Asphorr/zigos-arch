// procfs — synthetic /proc filesystem.
//
// Mirrors devfs in shape (no on-disk state, kernel-side handler per file)
// but with two extra wrinkles:
//
//   1. Hierarchy: paths are either flat (`/proc/meminfo`) or nested under a
//      pid (`/proc/12/cmdline`). Listing the root enumerates static files
//      *plus* one directory per active process.
//
//   2. Volatile content: each read generates the file content fresh from
//      live kernel state. Files have no fixed length — we render into a
//      stack buffer on every read and slice based on the fd offset. Long
//      reads that span multiple syscalls may see slightly different snap-
//      shots between calls, which matches Linux procfs behavior.
//
// Inode encoding (in FileDesc.inode, u32):
//     bits 31..8  = Kind (the file type, see enum)
//     bits  7..0  = pid (only meaningful for pid_* kinds; 0 for root files)
//
// Add a new file by: extending Kind, mapping it in openFile/listToBuffer,
// and adding a render function in `read`.

const std = @import("std");
const process = @import("../proc/process.zig");
const pmm = @import("../mm/pmm.zig");
const smp = @import("../cpu/smp.zig");
const vfs = @import("vfs.zig");
const nvme = @import("../driver/nvme.zig");
const xhci = @import("../driver/xhci.zig");
const e1000 = @import("../driver/e1000.zig");
const virtio_net = @import("../driver/virtio_net.zig");
const virtio_gpu = @import("../driver/virtio_gpu.zig");
const ahci = @import("../driver/ahci.zig");
// `i225` collides with Zig's `iN` arbitrary-width int type (would parse as
// the type for 225-bit signed integers). Alias under a non-clashing name.
const i225_drv = @import("../driver/i225.zig");

pub const Kind = enum(u8) {
    meminfo,
    uptime,
    cpuinfo,
    version,
    interrupts,
    mounts,
    sessions,
    sched,
    net_info,
    net_sock,
    net_arp,
    pcid_stats,
    pid_cmdline,
    pid_status,
};

const StaticFile = struct {
    name: []const u8,
    kind: Kind,
};

const STATIC_FILES = [_]StaticFile{
    .{ .name = "meminfo", .kind = .meminfo },
    .{ .name = "uptime", .kind = .uptime },
    .{ .name = "cpuinfo", .kind = .cpuinfo },
    .{ .name = "version", .kind = .version },
    .{ .name = "interrupts", .kind = .interrupts },
    .{ .name = "mounts", .kind = .mounts },
    .{ .name = "sessions", .kind = .sessions },
    .{ .name = "sched", .kind = .sched },
    .{ .name = "netinfo", .kind = .net_info },
    .{ .name = "netsock", .kind = .net_sock },
    .{ .name = "netarp", .kind = .net_arp },
    .{ .name = "pcid_stats", .kind = .pcid_stats },
};

const PER_PID_FILES = [_]StaticFile{
    .{ .name = "cmdline", .kind = .pid_cmdline },
    .{ .name = "status", .kind = .pid_status },
};

fn makeInode(kind: Kind, pid: u8) u32 {
    return (@as(u32, @intFromEnum(kind)) << 8) | @as(u32, pid);
}

fn parsePid(s: []const u8) ?u8 {
    if (s.len == 0 or s.len > 3) return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    if (v >= process.MAX_PROCS) return null;
    return @intCast(v);
}

/// Resolve a path *relative to the /proc/ mount* to an inode.
/// `rel` examples:
///     ""               → null (root dir, callers should handle separately)
///     "meminfo"        → static-file inode
///     "12"             → null (the pid dir itself; sysChdir handles via mount lookup)
///     "12/cmdline"     → pid-file inode
pub fn openFile(rel: []const u8) ?u32 {
    if (rel.len == 0) return null;

    // Static root file?
    for (STATIC_FILES) |f| {
        if (std.mem.eql(u8, rel, f.name)) return makeInode(f.kind, 0);
    }

    // Otherwise must be "<pid>/<file>".
    const slash = std.mem.indexOfScalar(u8, rel, '/') orelse return null;
    const pid = parsePid(rel[0..slash]) orelse return null;
    if (process.procs[pid].state == .unused) return null;
    const sub = rel[slash + 1 ..];
    for (PER_PID_FILES) |f| {
        if (std.mem.eql(u8, sub, f.name)) return makeInode(f.kind, pid);
    }
    return null;
}

pub fn closeFile(_: u32) void {}

/// Stack-cost budget for procfs rendering: 2 KB on the BSS, never on the
/// kstack (the kstack-lean rule — see feedback_kstack_lean_syscall_paths).
/// /proc/sessions is the largest renderer; 32 procs worst case → ~1500
/// bytes for a fully populated run.
var render_buf: [2048]u8 = undefined;

/// Render the file's content fresh, then return up to `count` bytes
/// starting at `offset`. Returns 0 at EOF.
pub fn read(inode: u32, offset: u32, buf: [*]u8, count: u32) u32 {
    const rendered: []u8 = render_buf[0..];
    const kind: Kind = @enumFromInt(@as(u8, @intCast((inode >> 8) & 0xFF)));
    const pid: u8 = @intCast(inode & 0xFF);
    const net = @import("../net/net.zig");
    const len = switch (kind) {
        .meminfo => renderMeminfo(rendered),
        .uptime => renderUptime(rendered),
        .cpuinfo => renderCpuinfo(rendered),
        .version => renderVersion(rendered),
        .interrupts => renderInterrupts(rendered),
        .mounts => renderMounts(rendered),
        .sessions => renderSessions(rendered),
        .sched => renderSched(rendered),
        .net_info => net.renderProcInfo(rendered),
        .net_sock => net.renderProcSock(rendered),
        .net_arp => net.renderProcArp(rendered),
        .pcid_stats => renderPcidStats(rendered),
        .pid_cmdline => renderPidCmdline(pid, rendered),
        .pid_status => renderPidStatus(pid, rendered),
    };
    if (offset >= len) return 0;
    const remain: u32 = @intCast(len - offset);
    const take = @min(count, remain);
    @memcpy(buf[0..take], rendered[offset..][0..take]);
    return take;
}

/// Helper: format with std.fmt.bufPrint, fall back to truncated buf on
/// overflow. Returning a usize keeps render functions branchless.
fn fmt(buf: []u8, comptime f: []const u8, args: anytype) usize {
    const out = std.fmt.bufPrint(buf, f, args) catch buf;
    return out.len;
}

fn renderMeminfo(buf: []u8) usize {
    const free = pmm.freeFrameCount();
    const free_kb = free * 4;
    const free_mb = free_kb / 1024;
    return fmt(buf, "free_pages: {d}\nfree_kb:    {d}\nfree_mb:    {d}\n", .{ free, free_kb, free_mb });
}

fn renderUptime(buf: []u8) usize {
    // APIC timer is calibrated to ~10ms quantum, so tick_count / 100 ≈ seconds.
    const ticks = process.tick_count;
    const sec = ticks / 100;
    const ms = (ticks % 100) * 10;
    return fmt(buf, "uptime_sec: {d}.{d:0>2}\nticks:      {d}\n", .{ sec, ms / 10, ticks });
}

fn renderCpuinfo(buf: []u8) usize {
    return fmt(buf, "cpu_count: {d}\narch:      x86_64\nvendor:    QEMU/host\n", .{smp.cpu_count});
}

fn renderVersion(buf: []u8) usize {
    return fmt(buf, "ZigOS x86_64 (Zig 0.15.2 freestanding)\n", .{});
}

/// Per-driver IRQ tally. Each entry pulls from its driver's `pub var
/// irq_count` (or its `_irq_count` siblings — names vary because counters
/// were added independently per driver). New IRQ-driven drivers should
/// add a row here when they expose a counter.
///
/// We don't go through a centralized vector→counter table in `idt.zig`
/// because each handler increments its own counter on the slow path
/// already; aggregating at read time keeps the IRQ entry path lean.
const IrqRow = struct {
    name: []const u8,
    counter: *const u64,
};
const IRQ_ROWS = [_]IrqRow{
    .{ .name = "TIMER (LAPIC)", .counter = &process.tick_count },
    .{ .name = "NVMe", .counter = &nvme.irq_count },
    .{ .name = "AHCI", .counter = &ahci.irq_count },
    .{ .name = "xHCI", .counter = &xhci.xhci_irq_count },
    .{ .name = "e1000", .counter = &e1000.irq_count },
    .{ .name = "i225", .counter = &i225_drv.irq_count },
    .{ .name = "virtio-net", .counter = &virtio_net.irq_count },
    .{ .name = "virtio-gpu", .counter = &virtio_gpu.virtio_gpu_irq_count },
};

fn renderInterrupts(buf: []u8) usize {
    var n: usize = 0;
    n += fmt(buf[n..], "{s:<16} {s}\n", .{ "device", "count" });
    for (IRQ_ROWS) |row| {
        const c = @atomicLoad(u64, row.counter, .monotonic);
        n += fmt(buf[n..], "{s:<16} {d}\n", .{ row.name, c });
    }
    return n;
}

/// Per-PCID + global PCID telemetry. Surfaces counters from
/// `src/cpu/mmu/pcid.zig`: how many PCIDs allocated/freed, how often
/// CR3 loads hit the preserve-TLB path (bit 63 = 1, gen-coherent), how
/// often they miss (bit 63 = 0, forced flush), and how many eager
/// switch-out flushes narrowed future shootdown fan-out.
///
/// Derived metric: preserve-hit ratio = preserve_hits / (preserve_hits +
/// flush_misses). Lower-bound 0% means PCID is acting like plain CR3 reloads
/// (gen tracker forcing flushes); higher = TLB working sets surviving
/// context switches as designed.
fn renderPcidStats(buf: []u8) usize {
    const pcid = @import("../cpu/mmu/pcid.zig");
    const allocs = pcid.alloc_count.load(.monotonic);
    const frees = pcid.free_count.load(.monotonic);
    const hits = pcid.preserve_hits.load(.monotonic);
    const misses = pcid.flush_misses.load(.monotonic);
    const eager = pcid.eager_clears.load(.monotonic);
    const total = hits + misses;
    const hit_ratio = if (total == 0) 0 else (hits * 100) / total;
    var n: usize = 0;
    n += fmt(buf[n..], "MAX_PCID:        {d}\n", .{pcid.MAX_PCID});
    n += fmt(buf[n..], "alloc_count:     {d}\n", .{allocs});
    n += fmt(buf[n..], "free_count:      {d}\n", .{frees});
    n += fmt(buf[n..], "in_use:          {d}\n", .{allocs - frees});
    n += fmt(buf[n..], "preserve_hits:   {d}\n", .{hits});
    n += fmt(buf[n..], "flush_misses:    {d}\n", .{misses});
    n += fmt(buf[n..], "preserve_ratio:  {d}% ({d}/{d} cr3 loads kept TLB)\n", .{ hit_ratio, hits, total });
    n += fmt(buf[n..], "eager_clears:    {d}\n", .{eager});
    return n;
}

fn renderMounts(buf: []u8) usize {
    var n: usize = 0;
    for (vfs.mounts) |slot| {
        if (slot) |m| {
            n += fmt(buf[n..], "{s:<10} on {s}\n", .{ fsTypeName(m.fs), m.prefix });
        }
    }
    return n;
}

fn fsTypeName(t: vfs.FsType) []const u8 {
    return switch (t) {
        .ext2 => "ext2",
        .fat32 => "fat32",
        .tarfs => "tarfs",
        .devfs => "devfs",
        .procfs => "procfs",
    };
}

fn renderPidCmdline(pid: u8, buf: []u8) usize {
    if (pid >= process.MAX_PROCS) return 0;
    const pcb = &process.procs[pid];
    if (pcb.state == .unused) return 0;
    var n: usize = 0;
    var i: u32 = 0;
    while (i < pcb.argc) : (i += 1) {
        const tok = pcb.argv[i][0..pcb.arg_lens[i]];
        if (i > 0 and n < buf.len) {
            buf[n] = ' ';
            n += 1;
        }
        const take = @min(tok.len, buf.len - n);
        @memcpy(buf[n..][0..take], tok[0..take]);
        n += take;
        if (n >= buf.len) break;
    }
    if (n < buf.len) {
        buf[n] = '\n';
        n += 1;
    }
    return n;
}

fn renderPidStatus(pid: u8, buf: []u8) usize {
    if (pid >= process.MAX_PROCS) return 0;
    const pcb = &process.procs[pid];
    if (pcb.state == .unused) return 0;
    const name = pcb.name[0..pcb.name_len];
    const state_str = stateName(pcb.state);
    const prio_str = priorityName(pcb.priority);
    return fmt(buf,
        "name:       {s}\npid:        {d}\nparent_pid: {d}\ntgid:       {d}\npgid:       {d}\nsid:        {d}\nstate:      {s}\npriority:   {s}\nlast_cpu:   {d}\nticks_used: {d}\nuser_brk:   0x{x}\n",
        .{
            name,
            pid,
            pcb.parent_pid,
            pcb.tgid,
            pcb.pgid,
            pcb.sid,
            state_str,
            prio_str,
            pcb.last_cpu,
            pcb.ticks_used,
            pcb.user_brk,
        },
    );
}

/// /proc/sessions — group live PCBs by sid → pgid → members. Output looks like:
///   session 1 (leader: desktop)
///     group 1 (leader: desktop)
///       1 desktop
///       3 shell
///     group 4 (leader: forktest)
///       4 forktest
///   session 8 (leader: httpd)        — daemon escaped
///     group 8 (leader: httpd)
///       8 httpd
fn renderSessions(buf: []u8) usize {
    var n: usize = 0;
    var seen_sid: [process.MAX_PROCS]bool = .{false} ** process.MAX_PROCS;
    var i: u8 = 0;
    while (i < process.MAX_PROCS) : (i += 1) {
        if (process.procs[i].state == .unused) continue;
        const sid = process.procs[i].sid;
        if (seen_sid[sid]) continue;
        seen_sid[sid] = true;

        const sl = &process.procs[sid];
        const sl_alive = sl.state != .unused;
        const sl_name = if (sl_alive) sl.name[0..sl.name_len] else "<gone>";
        n += fmt(buf[n..], "session {d} (leader: {s})\n", .{ sid, sl_name });

        // Now pass over members of this session, grouping by pgid.
        var seen_pgid: [process.MAX_PROCS]bool = .{false} ** process.MAX_PROCS;
        var j: u8 = 0;
        while (j < process.MAX_PROCS) : (j += 1) {
            if (process.procs[j].state == .unused) continue;
            if (process.procs[j].sid != sid) continue;
            const pgid = process.procs[j].pgid;
            if (seen_pgid[pgid]) continue;
            seen_pgid[pgid] = true;

            const gl = &process.procs[pgid];
            const gl_alive = gl.state != .unused;
            const gl_name = if (gl_alive) gl.name[0..gl.name_len] else "<gone>";
            n += fmt(buf[n..], "  group {d} (leader: {s})\n", .{ pgid, gl_name });

            var k: u8 = 0;
            while (k < process.MAX_PROCS) : (k += 1) {
                if (process.procs[k].state == .unused) continue;
                if (process.procs[k].sid != sid) continue;
                if (process.procs[k].pgid != pgid) continue;
                const m_name = process.procs[k].name[0..process.procs[k].name_len];
                n += fmt(buf[n..], "    {d} {s}\n", .{ k, m_name });
                if (n >= buf.len) return n;
            }
        }
    }
    return n;
}

/// /proc/sched — per-CPU runqueue snapshot. Lets you SEE what the CFS
/// scheduler is doing instead of inferring from log silence:
///   - rq depth per priority band (interactive / normal / background)
///   - per-band min_vruntime (CFS fairness floor)
///   - migrations in/out (Phase 4 load balancer + sysSetAffinity activity)
///   - schedule() invocation counter (work pressure proxy)
///   - currently dispatched pid + name
///
/// One section per alive CPU, plus a `global:` summary at the bottom
/// counting alive PCBs by state.
fn renderSched(buf: []u8) usize {
    var n: usize = 0;
    var c: u8 = 0;
    while (c < smp.MAX_CPUS) : (c += 1) {
        const cpu = &smp.cpus[c];
        if (!cpu.alive) continue;
        const rq = &cpu.runqueue;

        // Header + dispatched pid (if any).
        const cur_pid: i32 = if (cpu.current_pid) |p| @intCast(p) else -1;
        const cur_name: []const u8 = if (cur_pid >= 0)
            process.procs[@intCast(cur_pid)].name[0..process.procs[@intCast(cur_pid)].name_len]
        else
            "<idle>";
        n += fmt(buf[n..], "cpu{d}:\n  current_pid:    {d} ({s})\n", .{ c, cur_pid, cur_name });

        // Schedule + migration counters (atomic loads — counters are bumped
        // from cross-CPU paths in some cases).
        const sched_n = @atomicLoad(u64, &cpu.schedule_count, .monotonic);
        const mig_in = @atomicLoad(u64, &cpu.migrations_in, .monotonic);
        const mig_out = @atomicLoad(u64, &cpu.migrations_out, .monotonic);
        n += fmt(buf[n..],
            "  schedule_count: {d}\n  migrations_in:  {d}\n  migrations_out: {d}\n",
            .{ sched_n, mig_in, mig_out },
        );

        // Runqueue snapshot. nr_runnable is the cheap-audit total; the
        // per-band counts come from each PriQueue. They should sum to
        // nr_runnable — divergence means rq audit drift (also logged
        // via process.rqAudit at 1/64 schedule cadence).
        n += fmt(buf[n..],
            "  rq nr_runnable: {d}  (interactive={d} normal={d} background={d})\n",
            .{ rq.nr_runnable, rq.interactive.count, rq.normal.count, rq.background.count },
        );

        // Per-band min_vruntime — the CFS fairness floor that woken
        // sleepers are bumped near (sleeper-bonus) and that migrated
        // tasks are translated against.
        n += fmt(buf[n..],
            "  min_vruntime:   interactive={d} normal={d} background={d}\n",
            .{ rq.min_vruntime[2], rq.min_vruntime[1], rq.min_vruntime[0] },
        );

        if (n + 256 > buf.len) break; // leave headroom for global section
    }

    // Global PCB-by-state summary.
    var by_state = [_]u32{0} ** 6;
    var total_alive: u32 = 0;
    var i: u8 = 0;
    while (i < process.MAX_PROCS) : (i += 1) {
        const s = process.procs[i].state;
        const idx: usize = @intFromEnum(s);
        by_state[idx] += 1;
        if (s != .unused) total_alive += 1;
    }
    n += fmt(buf[n..],
        "global:\n  alive: {d}  unused: {d}  loading: {d}  ready: {d}  running: {d}  sleeping: {d}  zombie: {d}\n",
        .{
            total_alive,
            by_state[@intFromEnum(process.State.unused)],
            by_state[@intFromEnum(process.State.loading)],
            by_state[@intFromEnum(process.State.ready)],
            by_state[@intFromEnum(process.State.running)],
            by_state[@intFromEnum(process.State.sleeping)],
            by_state[@intFromEnum(process.State.zombie)],
        },
    );
    return n;
}

fn stateName(s: process.State) []const u8 {
    return switch (s) {
        .unused => "unused",
        .loading => "loading",
        .ready => "ready",
        .running => "running",
        .sleeping => "sleeping",
        .zombie => "zombie",
    };
}

fn priorityName(p: process.Priority) []const u8 {
    return switch (p) {
        .background => "background",
        .normal => "normal",
        .interactive => "interactive",
    };
}

// FileEntry mirror — kept in lockstep with syscall.zig's local definition.
const FileEntry = extern struct {
    name: [32]u8,
    name_len: u8,
    file_size: u32 align(1),
    flags: u8,
    _pad: [10]u8,
};

/// Fill `entries[0..count]` based on the listing path:
///   rel = ""       → list root (static files + per-process dirs)
///   rel = "<pid>/" → list per-pid files (cmdline, status)
/// Anything else is treated as "not a directory" and returns 0.
pub fn listToBuffer(rel: []const u8, entries: [*]FileEntry, max: u32) u32 {
    if (rel.len == 0) return listRoot(entries, max);

    // Pid-directory listing — accept both "<pid>" and "<pid>/" since
    // sysReaddir paths come through as the canonical cwd (with trailing
    // slash) but a manual call site may omit it.
    var name = rel;
    if (name[name.len - 1] == '/') name = name[0 .. name.len - 1];
    const pid = parsePid(name) orelse return 0;
    if (process.procs[pid].state == .unused) return 0;

    var count: u32 = 0;
    for (PER_PID_FILES) |f| {
        if (count >= max) break;
        writeEntry(&entries[count], f.name, 0);
        count += 1;
    }
    return count;
}

fn listRoot(entries: [*]FileEntry, max: u32) u32 {
    var count: u32 = 0;
    for (STATIC_FILES) |f| {
        if (count >= max) break;
        writeEntry(&entries[count], f.name, 0);
        count += 1;
    }
    // One directory per active process.
    var name_buf: [4]u8 = undefined;
    for (0..process.MAX_PROCS) |i| {
        if (count >= max) break;
        if (process.procs[i].state == .unused) continue;
        const n = formatPid(@intCast(i), &name_buf);
        writeEntry(&entries[count], name_buf[0..n], 0);
        count += 1;
    }
    return count;
}

fn formatPid(pid: u8, buf: *[4]u8) usize {
    const out = std.fmt.bufPrint(buf, "{d}", .{pid}) catch return 0;
    return out.len;
}

fn writeEntry(e: *FileEntry, name: []const u8, size: u32) void {
    @memset(&e.name, 0);
    @memset(&e._pad, 0);
    const n = @min(name.len, 32);
    @memcpy(e.name[0..n], name[0..n]);
    e.name_len = @intCast(n);
    e.file_size = size;
    e.flags = 0;
}

/// Return whether `rel` is a procfs directory (root or a valid pid). Used
/// by sysStat to set the is_directory bit on `/proc/` and `/proc/<pid>`.
pub fn isDirectory(rel: []const u8) bool {
    if (rel.len == 0) return true;
    var name = rel;
    if (name[name.len - 1] == '/') name = name[0 .. name.len - 1];
    if (parsePid(name)) |pid| return process.procs[pid].state != .unused;
    return false;
}

/// Synthesize a size for stat(). Files report 0 (their content is
/// generated, true length is unknown until rendered).
pub fn fileSize(rel: []const u8) ?u32 {
    if (rel.len == 0) return 0;
    if (isDirectory(rel)) return 0;
    if (openFile(rel)) |_| return 0;
    return null;
}
