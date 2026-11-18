//! /proc as Linux programs read it (proc(5)): a directory for each process
//! by its number, self and thread-self, the per-process files ps, libuv,
//! Python and the C library read, and the system-wide ones. A file is
//! rendered when a read starts at offset 0; the reads after it see that
//! snapshot, as a seq_file's do. Native programs keep procfs.zig.

const std = @import("std");
const process = @import("../proc/process.zig");
const pid_nr = @import("../proc/pid_nr.zig");
const signals = @import("../proc/signals.zig");
const tty = @import("../proc/tty.zig");
const pty = @import("../proc/pty.zig");
const errno = @import("../proc/errno.zig");
const spinlock = @import("../proc/spinlock.zig");
const file = @import("file.zig");
const vfs = @import("vfs.zig");
const ext2 = @import("ext2/ext2.zig");
const devfs = @import("devfs.zig");
const heap = @import("../mm/heap.zig");
const pmm = @import("../mm/pmm.zig");
const vmm = @import("../mm/vmm.zig");
const memmap = @import("../mm/memmap.zig");
const shm = @import("../mm/shm.zig");
const smp = @import("../cpu/smp.zig");
const protect = @import("../cpu/arch/protect.zig");
const apic = @import("../time/apic.zig");
const time = @import("../time/time.zig");
const usercopy = @import("../cpu/arch/usercopy.zig");
const config = @import("../config.zig");

// --- The tree ----------------------------------------------------------------

pub const Kind = enum(u8) {
    root,
    pid_dir,
    task_dir,
    tid_dir,
    fd_dir,
    sys,
    sys_kernel,
    sys_kernel_random,
    sys_vm,
    sys_fs,
    sys_net,
    sys_net_core,
    sys_zigos,

    self_link,
    thread_self_link,
    mounts_link,
    exe_link,
    cwd_link,
    root_link,
    fd_link,

    meminfo,
    cpuinfo,
    stat,
    uptime,
    loadavg,
    version,
    filesystems,
    kcmdline,
    swaps,
    ostype,
    osrelease,
    hostname,
    domainname,
    pid_max,
    threads_max,
    ngroups_max,
    cap_last_cap,
    boot_id,
    uuid,
    overcommit_memory,
    max_map_count,
    file_max,
    nr_open,
    somaxconn,
    trace_paths,

    p_stat,
    p_statm,
    p_status,
    p_cmdline,
    p_environ,
    p_comm,
    p_maps,
    p_mounts,
    p_mountinfo,
    p_limits,
    p_cgroup,
    p_oom_score_adj,
    p_oom_score,
    p_auxv,
    p_loginuid,
};

pub const Class = enum { dir, file, link };

pub fn classOf(k: Kind) Class {
    return switch (k) {
        .root, .pid_dir, .task_dir, .tid_dir, .fd_dir, .sys, .sys_kernel, .sys_kernel_random, .sys_vm, .sys_fs, .sys_net, .sys_net_core, .sys_zigos => .dir,
        .self_link, .thread_self_link, .mounts_link, .exe_link, .cwd_link, .root_link, .fd_link => .link,
        else => .file,
    };
}

/// A name in the tree.
pub const Node = struct {
    kind: Kind,
    /// The task whose directory this is under: the process's number, or
    /// the thread's under task/.
    pid: u32 = 0,
    /// The number of the process `pid` is a thread of.
    tgid: u32 = 0,
    fd: u32 = 0,
    /// Under task/<tid>: the thread's view, not the process's.
    in_task: bool = false,
};

const Entry = struct { name: []const u8, kind: Kind };

const root_entries = [_]Entry{
    .{ .name = "self", .kind = .self_link },
    .{ .name = "thread-self", .kind = .thread_self_link },
    .{ .name = "mounts", .kind = .mounts_link },
    .{ .name = "meminfo", .kind = .meminfo },
    .{ .name = "cpuinfo", .kind = .cpuinfo },
    .{ .name = "stat", .kind = .stat },
    .{ .name = "uptime", .kind = .uptime },
    .{ .name = "loadavg", .kind = .loadavg },
    .{ .name = "version", .kind = .version },
    .{ .name = "filesystems", .kind = .filesystems },
    .{ .name = "cmdline", .kind = .kcmdline },
    .{ .name = "swaps", .kind = .swaps },
    .{ .name = "sys", .kind = .sys },
};

/// A process's directory; a thread's is the same less task/ (kept last).
const proc_entries = [_]Entry{
    .{ .name = "stat", .kind = .p_stat },
    .{ .name = "statm", .kind = .p_statm },
    .{ .name = "status", .kind = .p_status },
    .{ .name = "cmdline", .kind = .p_cmdline },
    .{ .name = "environ", .kind = .p_environ },
    .{ .name = "comm", .kind = .p_comm },
    .{ .name = "maps", .kind = .p_maps },
    .{ .name = "mounts", .kind = .p_mounts },
    .{ .name = "mountinfo", .kind = .p_mountinfo },
    .{ .name = "limits", .kind = .p_limits },
    .{ .name = "cgroup", .kind = .p_cgroup },
    .{ .name = "oom_score_adj", .kind = .p_oom_score_adj },
    .{ .name = "oom_score", .kind = .p_oom_score },
    .{ .name = "auxv", .kind = .p_auxv },
    .{ .name = "loginuid", .kind = .p_loginuid },
    .{ .name = "exe", .kind = .exe_link },
    .{ .name = "cwd", .kind = .cwd_link },
    .{ .name = "root", .kind = .root_link },
    .{ .name = "fd", .kind = .fd_dir },
    .{ .name = "task", .kind = .task_dir },
};

const sys_entries = [_]Entry{
    .{ .name = "kernel", .kind = .sys_kernel },
    .{ .name = "vm", .kind = .sys_vm },
    .{ .name = "fs", .kind = .sys_fs },
    .{ .name = "net", .kind = .sys_net },
    .{ .name = "zigos", .kind = .sys_zigos },
};
const sys_kernel_entries = [_]Entry{
    .{ .name = "ostype", .kind = .ostype },
    .{ .name = "osrelease", .kind = .osrelease },
    .{ .name = "hostname", .kind = .hostname },
    .{ .name = "domainname", .kind = .domainname },
    .{ .name = "pid_max", .kind = .pid_max },
    .{ .name = "threads-max", .kind = .threads_max },
    .{ .name = "ngroups_max", .kind = .ngroups_max },
    .{ .name = "cap_last_cap", .kind = .cap_last_cap },
    .{ .name = "random", .kind = .sys_kernel_random },
};
const sys_random_entries = [_]Entry{
    .{ .name = "boot_id", .kind = .boot_id },
    .{ .name = "uuid", .kind = .uuid },
};
const sys_vm_entries = [_]Entry{
    .{ .name = "overcommit_memory", .kind = .overcommit_memory },
    .{ .name = "max_map_count", .kind = .max_map_count },
};
const sys_fs_entries = [_]Entry{
    .{ .name = "file-max", .kind = .file_max },
    .{ .name = "nr_open", .kind = .nr_open },
};
const sys_net_entries = [_]Entry{.{ .name = "core", .kind = .sys_net_core }};
const sys_net_core_entries = [_]Entry{.{ .name = "somaxconn", .kind = .somaxconn }};
/// ZigOS's own switches, not Linux's.
const sys_zigos_entries = [_]Entry{.{ .name = "trace_paths", .kind = .trace_paths }};

/// (a) /proc/sys/zigos/trace_paths: a line on the kernel log for every
/// call a Linux program names a file in (linux.tracePath).
pub var trace_paths: bool = false;

/// The named children a directory always has.
fn fixedChildren(k: Kind) []const Entry {
    return switch (k) {
        .root => &root_entries,
        .pid_dir => &proc_entries,
        .tid_dir => proc_entries[0 .. proc_entries.len - 1],
        .sys => &sys_entries,
        .sys_kernel => &sys_kernel_entries,
        .sys_kernel_random => &sys_random_entries,
        .sys_vm => &sys_vm_entries,
        .sys_fs => &sys_fs_entries,
        .sys_net => &sys_net_entries,
        .sys_net_core => &sys_net_core_entries,
        .sys_zigos => &sys_zigos_entries,
        else => &.{},
    };
}

/// The slot of a task /proc shows, by number: alive or a zombie, not an
/// idle task.
fn slotOf(nr: u32) ?u8 {
    const slot = pid_nr.slotOf(nr) orelse return null;
    if (process.procs[slot].is_idle) return null;
    return slot;
}

fn leaderNr(slot: u8) u32 {
    return process.procs[process.procs[slot].tgid].pid_nr;
}

fn child(dir: Node, name: []const u8) ?Node {
    for (fixedChildren(dir.kind)) |e| {
        if (std.mem.eql(u8, e.name, name)) {
            return .{ .kind = e.kind, .pid = dir.pid, .tgid = dir.tgid, .in_task = dir.kind == .tid_dir or dir.in_task };
        }
    }
    const n = std.fmt.parseInt(u32, name, 10) catch return null;
    switch (dir.kind) {
        // Every task by its number; threads are not listed, as on Linux.
        .root => {
            const slot = slotOf(n) orelse return null;
            return .{ .kind = .pid_dir, .pid = n, .tgid = leaderNr(slot) };
        },
        .task_dir => {
            const slot = slotOf(n) orelse return null;
            if (leaderNr(slot) != dir.tgid) return null;
            return .{ .kind = .tid_dir, .pid = n, .tgid = dir.tgid, .in_task = true };
        },
        .fd_dir => {
            const f = fileOf(dir, n) orelse return null;
            file.put(f);
            return .{ .kind = .fd_link, .pid = dir.pid, .tgid = dir.tgid, .fd = n, .in_task = dir.in_task };
        },
        else => return null,
    }
}

fn parentOf(n: Node) Node {
    return switch (n.kind) {
        .task_dir => .{ .kind = .pid_dir, .pid = n.tgid, .tgid = n.tgid },
        .tid_dir => .{ .kind = .task_dir, .pid = n.tgid, .tgid = n.tgid },
        .fd_dir => .{ .kind = if (n.in_task) .tid_dir else .pid_dir, .pid = n.pid, .tgid = n.tgid, .in_task = n.in_task },
        .sys_kernel, .sys_vm, .sys_fs, .sys_net, .sys_zigos => .{ .kind = .sys },
        .sys_kernel_random => .{ .kind = .sys_kernel },
        .sys_net_core => .{ .kind = .sys_net },
        else => .{ .kind = .root },
    };
}

pub const Found = union(enum) {
    node: Node,
    /// A link out of /proc (exe, cwd, root), followed as the last name:
    /// the path it stands for.
    path: []const u8,
    missing,
    not_dir,
};

/// The node `rel` (a path inside /proc) names for `pcb`'s process. Links
/// inside /proc are followed on the way; a link out of it only as the last
/// name, with `follow_last`. An fd link stays itself: what it stands for is
/// an open file, not a path.
pub fn walk(pcb: *process.PCB, rel: []const u8, follow_last: bool, out: *[256]u8) Found {
    var cur = Node{ .kind = .root };
    var it = std.mem.tokenizeScalar(u8, rel, '/');
    while (it.next()) |comp| {
        if (std.mem.eql(u8, comp, ".")) continue;
        if (classOf(cur.kind) != .dir) return .not_dir;
        if (std.mem.eql(u8, comp, "..")) {
            cur = parentOf(cur);
            continue;
        }
        const last = it.peek() == null;
        var next = child(cur, comp) orelse return .missing;
        if (classOf(next.kind) == .link and next.kind != .fd_link and (!last or follow_last)) {
            switch (follow(pcb, next, out)) {
                .node => |n| next = n,
                .path => |p| return if (last) .{ .path = p } else .missing,
                .missing => return .missing,
                .not_dir => return .not_dir,
            }
        }
        cur = next;
    }
    return .{ .node = cur };
}

/// Where a link leads: a node, or a path outside /proc.
fn follow(pcb: *process.PCB, link: Node, out: *[256]u8) Found {
    const me_nr = process.leader(pcb).pid_nr;
    switch (link.kind) {
        .self_link => return .{ .node = .{ .kind = .pid_dir, .pid = me_nr, .tgid = me_nr } },
        .thread_self_link => {
            const cur = process.currentPCB() orelse return .missing;
            return .{ .node = .{ .kind = .tid_dir, .pid = cur.pid_nr, .tgid = me_nr, .in_task = true } };
        },
        .mounts_link => return .{ .node = .{ .kind = .p_mounts, .pid = me_nr, .tgid = me_nr } },
        else => return .{ .path = linkTarget(link, out) orelse return .missing },
    }
}

/// The text of a link, as readlink gives it.
pub fn linkTarget(n: Node, out: *[256]u8) ?[]const u8 {
    switch (n.kind) {
        .self_link => {
            const pcb = process.currentPCB() orelse return null;
            return std.fmt.bufPrint(out, "{d}", .{process.leader(pcb).pid_nr}) catch null;
        },
        .thread_self_link => {
            const pcb = process.currentPCB() orelse return null;
            return std.fmt.bufPrint(out, "{d}/task/{d}", .{ process.leader(pcb).pid_nr, pcb.pid_nr }) catch null;
        },
        .mounts_link => return copyOut(out, "self/mounts"),
        .root_link => return copyOut(out, "/"),
        .exe_link => {
            const lead = leadOf(n) orelse return null;
            if (lead.exe_path_len == 0) return null;
            return copyOut(out, lead.exe_path[0..lead.exe_path_len]);
        },
        .cwd_link => {
            const lead = leadOf(n) orelse return null;
            var cwd: []const u8 = lead.cwd[0..lead.cwd_len];
            if (cwd.len > 1 and cwd[cwd.len - 1] == '/') cwd = cwd[0 .. cwd.len - 1];
            return copyOut(out, cwd);
        },
        .fd_link => {
            const f = fileOf(n, n.fd) orelse return null;
            defer file.put(f);
            return fileName(f, out);
        },
        else => return null,
    }
}

fn copyOut(out: *[256]u8, s: []const u8) []const u8 {
    const len = @min(s.len, out.len);
    @memcpy(out[0..len], s[0..len]);
    return out[0..len];
}

/// The process a node is of, while it lives (a zombie too).
pub fn leadOf(n: Node) ?*process.PCB {
    const slot = slotOf(n.pid) orelse return null;
    return process.leader(&process.procs[slot]);
}

/// The task a node is of: the thread under task/, else the process.
fn taskOf(n: Node) ?*process.PCB {
    const slot = slotOf(n.pid) orelse return null;
    return &process.procs[slot];
}

/// File `fd` of the process `n` is of, with a reference to put.
fn fileOf(n: Node, fd: u32) ?*file.File {
    const lead = leadOf(n) orelse return null;
    // A lead whose thread ended before the others is the process still.
    if (lead.state == .zombie and !process.pinnedLead(lead.tgid)) return null;
    return file.get(lead, fd);
}

/// The name an open file goes by in fd/: a path, or what Linux calls the
/// kinds that have none.
pub fn fileName(f: *file.File, out: *[256]u8) ?[]const u8 {
    return switch (f.kind) {
        .ext2 => ext2Name(f, out),
        .pipe => std.fmt.bufPrint(out, "pipe:[{d}]", .{f.pipe_id}) catch null,
        .socket, .tcp_sock, .tcp_listener => std.fmt.bufPrint(out, "socket:[{d}]", .{@intFromPtr(f) & 0xFFFFFF}) catch null,
        .epoll => copyOut(out, "anon_inode:[eventpoll]"),
        .eventfd => copyOut(out, "anon_inode:[eventfd]"),
        .console => copyOut(out, "/dev/console"),
        .tty => if (pty.number(f)) |_| copyOut(out, "/dev/ptmx") else if (ptsOf(f.tty)) |p| std.fmt.bufPrint(out, "/dev/pts/{d}", .{p}) catch null else copyOut(out, "/dev/tty"),
        .devfs => std.fmt.bufPrint(out, "/dev/{s}", .{devfs.nameOf(f.inode) orelse "null"}) catch null,
        .lproc => if (openOf(f)) |o| pathOf(o.node, out) else null,
        .procfs => copyOut(out, "/proc"),
        .fat32 => copyOut(out, "/fat"),
        .tarfs => copyOut(out, "/tar"),
    };
}

/// An open ext2 file's path. A file a Linux program opened is named as its
/// directory names it now, or " (deleted)" as on Linux once it has no name
/// there; a directory, and a file opened otherwise, by its inode.
fn ext2Name(f: *file.File, out: *[256]u8) ?[]const u8 {
    if (f.dir_inode != 0) {
        if (ext2.pathIn(f.dir_inode, f.inode, out)) |p| return p;
        var was: [256]u8 = undefined;
        const old = noted(f.inode, &was) orelse "/";
        return std.fmt.bufPrint(out, "{s} (deleted)", .{old}) catch null;
    }
    return nameOf(f.inode, out) orelse std.fmt.bufPrint(out, "/ (inode {d})", .{f.inode}) catch null;
}

/// The pts number of terminal `id`, if it is a pty's.
fn ptsOf(id: u8) ?u32 {
    const t = tty.get(id) orelse return null;
    if (!t.pty) return null;
    return pty.ptsOfTty(id);
}

/// The directory a file or link is in, and its name there. Null for a
/// descriptor's link, which has a number for a name.
fn homeOf(n: Node) ?struct { dir: Node, name: []const u8 } {
    const dirs = [_]Kind{ .root, .pid_dir, .sys, .sys_kernel, .sys_kernel_random, .sys_vm, .sys_fs, .sys_net, .sys_net_core, .sys_zigos };
    for (dirs) |d| {
        for (fixedChildren(d)) |e| {
            if (e.kind != n.kind) continue;
            const dir: Node = if (d == .pid_dir)
                .{ .kind = if (n.in_task) .tid_dir else .pid_dir, .pid = n.pid, .tgid = n.tgid, .in_task = n.in_task }
            else
                .{ .kind = d };
            return .{ .dir = dir, .name = e.name };
        }
    }
    return null;
}

/// "/proc/..." for a node: what a directory fd stands for in the *at calls,
/// and the name an open file of /proc goes by.
pub fn pathOf(n: Node, out: *[256]u8) ?[]const u8 {
    return switch (n.kind) {
        .root => copyOut(out, "/proc"),
        .pid_dir => std.fmt.bufPrint(out, "/proc/{d}", .{n.pid}) catch null,
        .task_dir => std.fmt.bufPrint(out, "/proc/{d}/task", .{n.tgid}) catch null,
        .tid_dir => std.fmt.bufPrint(out, "/proc/{d}/task/{d}", .{ n.tgid, n.pid }) catch null,
        .fd_dir => if (n.in_task)
            std.fmt.bufPrint(out, "/proc/{d}/task/{d}/fd", .{ n.tgid, n.pid }) catch null
        else
            std.fmt.bufPrint(out, "/proc/{d}/fd", .{n.pid}) catch null,
        .sys => copyOut(out, "/proc/sys"),
        .sys_kernel => copyOut(out, "/proc/sys/kernel"),
        .sys_kernel_random => copyOut(out, "/proc/sys/kernel/random"),
        .sys_vm => copyOut(out, "/proc/sys/vm"),
        .sys_fs => copyOut(out, "/proc/sys/fs"),
        .sys_net => copyOut(out, "/proc/sys/net"),
        .sys_net_core => copyOut(out, "/proc/sys/net/core"),
        .sys_zigos => copyOut(out, "/proc/sys/zigos"),
        else => {
            const home = homeOf(n) orelse return copyOut(out, "/proc");
            var dir_buf: [256]u8 = undefined;
            const dir = pathOf(home.dir, &dir_buf) orelse return null;
            return std.fmt.bufPrint(out, "{s}/{s}", .{ dir, home.name }) catch null;
        },
    };
}

// --- Names of ext2 files, for fd/ and maps -----------------------------------

// An ext2 inode keeps no name of its own: the last path a Linux program
// opened it by stands for one. A directory's is found by walking up.
const NAMES: usize = 256;
const NAME_MAX: usize = 120;
const Name = struct { inum: u32 = 0, len: u8 = 0, path: [NAME_MAX]u8 = undefined };
var names: [NAMES]Name = [_]Name{.{}} ** NAMES; // (p:names_lock)
var names_lock: spinlock.SpinLock = .{};

/// `path` (absolute) is a name of ext2 inode `inum`.
pub fn noteName(inum: u32, path: []const u8) void {
    if (inum == 0 or path.len == 0 or path.len > NAME_MAX or path[0] != '/') return;
    names_lock.acquire();
    defer names_lock.release();
    const e = &names[inum % NAMES];
    e.inum = inum;
    e.len = @intCast(path.len);
    @memcpy(e.path[0..path.len], path);
}

/// A directory's path is found by walking up. A file's is the noted one
/// while it still names this inode: the number may have been another
/// file's before.
fn nameOf(inum: u32, out: *[256]u8) ?[]const u8 {
    if (ext2.pathOf(inum, out)) |p| return p;
    const p = noted(inum, out) orelse return null;
    return if (ext2.lookupPath(std.mem.trimLeft(u8, p, "/")) == inum) p else null;
}

fn noted(inum: u32, out: *[256]u8) ?[]const u8 {
    names_lock.acquire();
    defer names_lock.release();
    const e = &names[inum % NAMES];
    if (e.inum != inum) return null;
    return copyOut(out, e.path[0..e.len]);
}

// --- Facts and listing ---------------------------------------------------------

const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

pub const Facts = struct { mode: u32, nlink: u32, ino: u64 };

fn inoOf(n: Node) u64 {
    return (@as(u64, n.pid) << 24) ^ (@as(u64, @intFromEnum(n.kind)) << 16) ^ (n.fd & 0xFFFF) ^ (@as(u64, @intFromBool(n.in_task)) << 60) ^ 0x10000000000;
}

fn writable(k: Kind) bool {
    return k == .p_oom_score_adj or k == .trace_paths;
}

pub fn facts(n: Node) Facts {
    return switch (classOf(n.kind)) {
        .dir => .{ .mode = S_IFDIR | 0o555, .nlink = 2, .ino = inoOf(n) },
        .link => .{ .mode = S_IFLNK | 0o777, .nlink = 1, .ino = inoOf(n) },
        .file => .{ .mode = S_IFREG | @as(u32, if (writable(n.kind)) 0o644 else 0o444), .nlink = 1, .ino = inoOf(n) },
    };
}

fn dtypeOf(k: Kind) u8 {
    return switch (classOf(k)) {
        .dir => DT_DIR,
        .file => DT_REG,
        .link => DT_LNK,
    };
}

pub const Dent = struct { name: []const u8, ino: u64, dtype: u8, next: u64 };

/// The entry of directory `dir` at position `pos` or the first one after
/// it, and the position after that: ".", "..", the fixed names, then the
/// numbered ones (pos past the fixed names counts slots or fds).
pub fn entryAt(dir: Node, pos: u64, name_buf: *[16]u8) ?Dent {
    if (pos == 0) return .{ .name = ".", .ino = inoOf(dir), .dtype = DT_DIR, .next = 1 };
    if (pos == 1) return .{ .name = "..", .ino = inoOf(parentOf(dir)), .dtype = DT_DIR, .next = 2 };
    const fixed = fixedChildren(dir.kind);
    if (pos < 2 + fixed.len) {
        const e = fixed[@intCast(pos - 2)];
        const n = Node{ .kind = e.kind, .pid = dir.pid, .tgid = dir.tgid, .in_task = dir.kind == .tid_dir };
        return .{ .name = e.name, .ino = inoOf(n), .dtype = dtypeOf(e.kind), .next = pos + 1 };
    }
    var k: u64 = pos - 2 - fixed.len;
    switch (dir.kind) {
        .root, .task_dir => while (k < process.MAX_PROCS) : (k += 1) {
            const p = &process.procs[@intCast(k)];
            if (p.state == .unused or p.state == .loading or p.is_idle) continue;
            const lead_slot = p.tgid;
            if (dir.kind == .root and lead_slot != k) continue;
            if (dir.kind == .task_dir and process.procs[lead_slot].pid_nr != dir.tgid) continue;
            const name = std.fmt.bufPrint(name_buf, "{d}", .{p.pid_nr}) catch return null;
            const kind: Kind = if (dir.kind == .root) .pid_dir else .tid_dir;
            return .{ .name = name, .ino = inoOf(.{ .kind = kind, .pid = p.pid_nr }), .dtype = DT_DIR, .next = 2 + fixed.len + k + 1 };
        },
        .fd_dir => while (k < config.MAX_FDS) : (k += 1) {
            const f = fileOf(dir, @intCast(k)) orelse continue;
            file.put(f);
            const name = std.fmt.bufPrint(name_buf, "{d}", .{k}) catch return null;
            const n = Node{ .kind = .fd_link, .pid = dir.pid, .tgid = dir.tgid, .fd = @intCast(k), .in_task = dir.in_task };
            return .{ .name = name, .ino = inoOf(n), .dtype = DT_LNK, .next = 2 + fixed.len + k + 1 };
        },
        else => {},
    }
    return null;
}

// --- Open files ------------------------------------------------------------------

const Open = struct {
    node: Node,
    /// The rendered text the reads go through.
    snap: ?[]u8 = null,
    /// Held across a render, which may sleep (an address-space lock).
    render_lock: spinlock.Mutex = .{},
};

const file_ops: file.Ops = .{ .read = read, .write = write, .release = release };
const dir_ops: file.Ops = .{ .read = dirRead, .release = release };

fn dirRead(_: *file.File, _: *process.PCB, _: [*]u8, _: u32) u32 {
    return errno.err(.EISDIR);
}

pub fn openOf(f: *const file.File) ?*Open {
    if (f.kind != .lproc) return null;
    return @ptrCast(@alignCast(f.obj));
}

/// A file for node `n`. Null when memory is out.
pub fn open(n: Node, access: u8, nonblock: bool) ?*file.File {
    const raw = heap.kmallocAligned(@sizeOf(Open), @alignOf(Open)) orelse return null;
    const o: *Open = @ptrCast(@alignCast(raw));
    o.* = .{ .node = n };
    const f = file.create(.{
        .kind = .lproc,
        .ops = if (classOf(n.kind) == .dir) &dir_ops else &file_ops,
        .access = access,
        .nonblock = nonblock,
        .obj = o,
    }) orelse {
        heap.kfree(raw);
        return null;
    };
    return f;
}

fn release(f: *file.File) void {
    const o = openOf(f) orelse return;
    if (o.snap) |s| heap.kfree(s.ptr);
    heap.kfree(@ptrCast(o));
}

/// The scratch buffer a file is first rendered in, and the most bytes one
/// renders to (maps of an address space with tens of thousands of regions).
const RENDER_FIRST: usize = 128 * 1024;
const RENDER_MAX: usize = 8 * 1024 * 1024;

fn read(f: *file.File, pcb: *process.PCB, buf: [*]u8, count: u32) u32 {
    _ = pcb;
    const n = readAt(f, f.offset, buf, count);
    if (n < errno.ERR_SENTINEL_BASE) f.offset += n;
    return n;
}

/// Up to `count` bytes of the file's text from `off` (pread); the file's
/// own offset stays put. A read from the start renders the text anew.
pub fn readAt(f: *file.File, off: u64, buf: [*]u8, count: u32) u32 {
    const o = openOf(f) orelse return errno.err(.EBADF);
    if (classOf(o.node.kind) == .dir) return errno.err(.EISDIR);
    o.render_lock.acquire();
    defer o.render_lock.release();
    if (off == 0 or o.snap == null) {
        const fresh = render(o.node) orelse return errno.err(.ENOMEM);
        if (o.snap) |s| heap.kfree(s.ptr);
        o.snap = fresh;
    }
    const snap = o.snap.?;
    if (off >= snap.len) return 0;
    const at: usize = @intCast(off);
    const n = @min(count, snap.len - at);
    if (!usercopy.copyToUser(@intFromPtr(buf), snap[at..][0..n])) return errno.err(.EFAULT);
    return @intCast(n);
}

/// oom_score_adj takes a number from -1000 to 1000; trace_paths goes on
/// with "1", off with anything else.
fn write(f: *file.File, _: *process.PCB, buf: [*]const u8, count: u32) u32 {
    const o = openOf(f) orelse return errno.err(.EBADF);
    if (!writable(o.node.kind)) return errno.err(.EACCES);
    var text: [16]u8 = undefined;
    const n = @min(count, text.len);
    if (!usercopy.copyFromUser(text[0..n], @intFromPtr(buf))) return errno.err(.EFAULT);
    if (o.node.kind == .trace_paths) {
        if (n > 0) @atomicStore(bool, &trace_paths, text[0] == '1', .monotonic);
        return count;
    }
    const adj = std.fmt.parseInt(i32, std.mem.trim(u8, text[0..n], " \t\n"), 10) catch return errno.err(.EINVAL);
    if (count > text.len or adj < -1000 or adj > 1000) return errno.err(.EINVAL);
    const lead = leadOf(o.node) orelse return errno.err(.ESRCH);
    @atomicStore(i16, &lead.oom_score_adj, @intCast(adj), .monotonic);
    return count;
}

/// The node's text in a buffer of its own size. Null when memory is out.
/// A text that fills the scratch buffer is rendered again in a larger one.
fn render(n: Node) ?[]u8 {
    var size: usize = RENDER_FIRST;
    while (true) : (size *= 4) {
        const scratch = heap.kmalloc(size) orelse return null;
        defer heap.kfree(scratch);
        var out = Out{ .buf = scratch[0..size] };
        fill(n, &out);
        if (out.len == size and size < RENDER_MAX) continue;
        const kept = heap.kmalloc(@max(out.len, 1)) orelse return null;
        @memcpy(kept[0..out.len], out.buf[0..out.len]);
        return kept[0..out.len];
    }
}

/// A buffer rendering appends to; what doesn't fit is cut.
const Out = struct {
    buf: []u8,
    len: usize = 0,

    fn print(o: *Out, comptime f: []const u8, args: anytype) void {
        const s = std.fmt.bufPrint(o.buf[o.len..], f, args) catch {
            o.len = o.buf.len;
            return;
        };
        o.len += s.len;
    }

    fn put(o: *Out, s: []const u8) void {
        const n = @min(s.len, o.buf.len - o.len);
        @memcpy(o.buf[o.len..][0..n], s[0..n]);
        o.len += n;
    }

    /// Spaces up to column `col` of the line being written.
    fn padTo(o: *Out, line_start: usize, col: usize) void {
        while (o.len - line_start < col and o.len < o.buf.len) o.put(" ");
    }
};

fn fill(n: Node, out: *Out) void {
    switch (n.kind) {
        .meminfo => renderMeminfo(out),
        .cpuinfo => renderCpuinfo(out),
        .stat => renderStat(out),
        .uptime => renderUptime(out),
        .loadavg => renderLoadavg(out),
        .version => out.put("Linux version " ++ RELEASE ++ " (zigos@zigos) (zig 0.15.2) " ++ UTS_VERSION ++ "\n"),
        .filesystems => out.put("nodev\tproc\nnodev\tdevtmpfs\nnodev\tdevpts\nnodev\tpipefs\n\text2\n\tvfat\n"),
        .kcmdline => out.put("zigos\n"),
        .swaps => out.put("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"),
        .ostype => out.put("Linux\n"),
        .osrelease => out.put(RELEASE ++ "\n"),
        .hostname => out.put("zigos\n"),
        .domainname => out.put("(none)\n"),
        .pid_max => out.print("{d}\n", .{pid_nr.LIMIT}),
        .threads_max => out.print("{d}\n", .{process.MAX_PROCS}),
        .ngroups_max => out.put("65536\n"),
        .cap_last_cap => out.put("40\n"),
        .boot_id => uuidLine(out, bootId()),
        .uuid => uuidLine(out, freshUuid()),
        .overcommit_memory => out.put("0\n"),
        .max_map_count => out.put("65530\n"),
        .file_max => out.print("{d}\n", .{@as(u64, process.MAX_PROCS) * config.MAX_FDS}),
        .nr_open => out.print("{d}\n", .{config.MAX_FDS}),
        .somaxconn => out.put("4096\n"),
        .trace_paths => out.put(if (@atomicLoad(bool, &trace_paths, .monotonic)) "1\n" else "0\n"),
        .p_mounts => renderMounts(out),
        .p_mountinfo => renderMountinfo(out),
        .p_cgroup => out.put("0::/\n"),
        .p_oom_score_adj => out.print("{d}\n", .{if (leadOf(n)) |lead| @atomicLoad(i16, &lead.oom_score_adj, .monotonic) else 0}),
        .p_oom_score => out.print("{d}\n", .{if (leadOf(n)) |lead| oomScore(lead) else 0}),
        .p_loginuid => out.put("4294967295"),
        .p_limits => renderLimits(out),
        else => {
            const task = taskOf(n) orelse return;
            const lead = process.leader(task);
            const view = if (n.in_task) task else lead;
            switch (n.kind) {
                .p_stat => renderPidStat(view, lead, n.in_task, out),
                .p_statm => renderStatm(lead, out),
                .p_status => renderStatus(view, lead, n.in_task, out),
                .p_comm => out.print("{s}\n", .{nameOfTask(view)}),
                .p_cmdline => renderCmdline(lead, out),
                .p_environ => {
                    _ = copyFromTask(lead, .env, out);
                },
                .p_auxv => {
                    _ = copyFromTask(lead, .auxv, out);
                },
                .p_maps => renderMaps(lead, out),
                else => {},
            }
        },
    }
}

// --- The system's files ------------------------------------------------------

/// uname's release and version, as sysUname gives them.
const RELEASE = "6.6.0-zigos";
const UTS_VERSION = "#1 zigos";

fn kb(frames: u64) u64 {
    return frames * 4;
}

fn renderMeminfo(out: *Out) void {
    const total: u64 = pmm.managedFrameCount();
    const free: u64 = pmm.freeFrameCount();
    const used = total -| free;
    const rows = [_]struct { []const u8, u64 }{
        .{ "MemTotal", kb(total) },        .{ "MemFree", kb(free) },         .{ "MemAvailable", kb(free) },
        .{ "Buffers", 0 },                 .{ "Cached", 0 },                 .{ "SwapCached", 0 },
        .{ "Active", kb(used) },           .{ "Inactive", 0 },               .{ "Active(anon)", kb(used) },
        .{ "Inactive(anon)", 0 },          .{ "Active(file)", 0 },           .{ "Inactive(file)", 0 },
        .{ "Unevictable", 0 },             .{ "Mlocked", 0 },                .{ "SwapTotal", 0 },
        .{ "SwapFree", 0 },                .{ "Dirty", 0 },                  .{ "Writeback", 0 },
        .{ "AnonPages", kb(used) },        .{ "Mapped", 0 },                 .{ "Shmem", 0 },
        .{ "KReclaimable", 0 },            .{ "Slab", 0 },                   .{ "SReclaimable", 0 },
        .{ "SUnreclaim", 0 },              .{ "KernelStack", 0 },            .{ "PageTables", 0 },
        .{ "NFS_Unstable", 0 },            .{ "Bounce", 0 },                 .{ "WritebackTmp", 0 },
        .{ "CommitLimit", kb(total) },     .{ "Committed_AS", kb(used) },    .{ "VmallocTotal", 34359738367 },
        .{ "VmallocUsed", 0 },             .{ "VmallocChunk", 0 },           .{ "Percpu", 0 },
        .{ "HardwareCorrupted", 0 },       .{ "AnonHugePages", 0 },          .{ "ShmemHugePages", 0 },
        .{ "ShmemPmdMapped", 0 },          .{ "FileHugePages", 0 },          .{ "FilePmdMapped", 0 },
    };
    for (rows) |r| {
        const start = out.len;
        out.put(r[0]);
        out.put(":");
        const digits = std.fmt.count("{d}", .{r[1]});
        out.padTo(start, 24 - @min(digits, 24));
        out.print("{d} kB\n", .{r[1]});
    }
    out.put("HugePages_Total:       0\nHugePages_Free:        0\nHugePages_Rsvd:        0\nHugePages_Surp:        0\nHugepagesize:       2048 kB\nHugetlb:               0 kB\n");
}

const Flag = struct { bit: u5, name: []const u8 };

const LEAF1_EDX = [_]Flag{
    .{ .bit = 0, .name = "fpu" },     .{ .bit = 1, .name = "vme" },    .{ .bit = 2, .name = "de" },     .{ .bit = 3, .name = "pse" },
    .{ .bit = 4, .name = "tsc" },     .{ .bit = 5, .name = "msr" },    .{ .bit = 6, .name = "pae" },    .{ .bit = 7, .name = "mce" },
    .{ .bit = 8, .name = "cx8" },     .{ .bit = 9, .name = "apic" },   .{ .bit = 11, .name = "sep" },   .{ .bit = 12, .name = "mtrr" },
    .{ .bit = 13, .name = "pge" },    .{ .bit = 14, .name = "mca" },   .{ .bit = 15, .name = "cmov" },  .{ .bit = 16, .name = "pat" },
    .{ .bit = 17, .name = "pse36" },  .{ .bit = 19, .name = "clflush" }, .{ .bit = 23, .name = "mmx" }, .{ .bit = 24, .name = "fxsr" },
    .{ .bit = 25, .name = "sse" },    .{ .bit = 26, .name = "sse2" },  .{ .bit = 27, .name = "ss" },    .{ .bit = 28, .name = "ht" },
};
const EXT_EDX = [_]Flag{
    .{ .bit = 11, .name = "syscall" }, .{ .bit = 20, .name = "nx" }, .{ .bit = 26, .name = "pdpe1gb" }, .{ .bit = 27, .name = "rdtscp" }, .{ .bit = 29, .name = "lm" },
};
const LEAF1_ECX = [_]Flag{
    .{ .bit = 0, .name = "pni" },     .{ .bit = 1, .name = "pclmulqdq" }, .{ .bit = 3, .name = "monitor" }, .{ .bit = 9, .name = "ssse3" },
    .{ .bit = 12, .name = "fma" },    .{ .bit = 13, .name = "cx16" },  .{ .bit = 19, .name = "sse4_1" }, .{ .bit = 20, .name = "sse4_2" },
    .{ .bit = 21, .name = "x2apic" }, .{ .bit = 22, .name = "movbe" }, .{ .bit = 23, .name = "popcnt" }, .{ .bit = 24, .name = "tsc_deadline_timer" },
    .{ .bit = 25, .name = "aes" },    .{ .bit = 26, .name = "xsave" }, .{ .bit = 28, .name = "avx" },   .{ .bit = 29, .name = "f16c" },
    .{ .bit = 30, .name = "rdrand" }, .{ .bit = 31, .name = "hypervisor" },
};
const EXT_ECX = [_]Flag{
    .{ .bit = 0, .name = "lahf_lm" }, .{ .bit = 5, .name = "abm" }, .{ .bit = 8, .name = "3dnowprefetch" },
};
const LEAF7_EBX = [_]Flag{
    .{ .bit = 0, .name = "fsgsbase" }, .{ .bit = 3, .name = "bmi1" },   .{ .bit = 5, .name = "avx2" },    .{ .bit = 7, .name = "smep" },
    .{ .bit = 8, .name = "bmi2" },     .{ .bit = 9, .name = "erms" },   .{ .bit = 10, .name = "invpcid" }, .{ .bit = 16, .name = "avx512f" },
    .{ .bit = 17, .name = "avx512dq" }, .{ .bit = 18, .name = "rdseed" }, .{ .bit = 19, .name = "adx" },   .{ .bit = 20, .name = "smap" },
    .{ .bit = 23, .name = "clflushopt" }, .{ .bit = 24, .name = "clwb" }, .{ .bit = 28, .name = "avx512cd" }, .{ .bit = 29, .name = "sha_ni" },
    .{ .bit = 30, .name = "avx512bw" }, .{ .bit = 31, .name = "avx512vl" },
};
const LEAF7_ECX = [_]Flag{
    .{ .bit = 1, .name = "avx512vbmi" }, .{ .bit = 2, .name = "umip" }, .{ .bit = 3, .name = "pku" }, .{ .bit = 9, .name = "vaes" },
    .{ .bit = 10, .name = "vpclmulqdq" }, .{ .bit = 22, .name = "rdpid" },
};
const LEAFD1_EAX = [_]Flag{
    .{ .bit = 0, .name = "xsaveopt" }, .{ .bit = 1, .name = "xsavec" }, .{ .bit = 2, .name = "xgetbv1" }, .{ .bit = 3, .name = "xsaves" },
};

fn flags(out: *Out, word: u32, table: []const Flag) void {
    for (table) |f| {
        if (word & (@as(u32, 1) << f.bit) != 0) {
            out.put(" ");
            out.put(f.name);
        }
    }
}

fn renderCpuinfo(out: *Out) void {
    const l0 = protect.cpuidLeaf(0, 0);
    var vendor: [12]u8 = undefined;
    std.mem.writeInt(u32, vendor[0..4], l0.ebx, .little);
    std.mem.writeInt(u32, vendor[4..8], l0.edx, .little);
    std.mem.writeInt(u32, vendor[8..12], l0.ecx, .little);
    const l1 = protect.cpuidLeaf(1, 0);
    const base_family = (l1.eax >> 8) & 0xF;
    const family = if (base_family == 0xF) base_family + ((l1.eax >> 20) & 0xFF) else base_family;
    const model = ((l1.eax >> 4) & 0xF) | (if (base_family == 6 or base_family == 0xF) ((l1.eax >> 16) & 0xF) << 4 else 0);
    var brand: [48]u8 = [_]u8{0} ** 48;
    const ext_max = protect.cpuidLeaf(0x8000_0000, 0).eax;
    if (ext_max >= 0x8000_0004) {
        for (0..3) |i| {
            const r = protect.cpuidLeaf(0x8000_0002 + @as(u32, @intCast(i)), 0);
            std.mem.writeInt(u32, brand[i * 16 ..][0..4], r.eax, .little);
            std.mem.writeInt(u32, brand[i * 16 + 4 ..][0..4], r.ebx, .little);
            std.mem.writeInt(u32, brand[i * 16 + 8 ..][0..4], r.ecx, .little);
            std.mem.writeInt(u32, brand[i * 16 + 12 ..][0..4], r.edx, .little);
        }
    }
    const brand_s = std.mem.trim(u8, std.mem.sliceTo(&brand, 0), " ");
    const ext1 = if (ext_max >= 0x8000_0001) protect.cpuidLeaf(0x8000_0001, 0) else protect.CpuidRegs{ .eax = 0, .ebx = 0, .ecx = 0, .edx = 0 };
    const l7 = if (l0.eax >= 7) protect.cpuidLeaf(7, 0) else protect.CpuidRegs{ .eax = 0, .ebx = 0, .ecx = 0, .edx = 0 };
    const ld = if (l0.eax >= 0xD) protect.cpuidLeaf(0xD, 1) else protect.CpuidRegs{ .eax = 0, .ebx = 0, .ecx = 0, .edx = 0 };
    const sizes = if (ext_max >= 0x8000_0008) protect.cpuidLeaf(0x8000_0008, 0).eax else 0x3027;
    const mhz = apic.tscPerQuantumSane() * 100 / 1_000_000;
    const cpus: u32 = smp.cpu_count;
    for (0..smp.MAX_CPUS) |c| {
        const cpu = &smp.cpus[c];
        if (!cpu.alive and c != 0) continue;
        out.print("processor\t: {d}\nvendor_id\t: {s}\ncpu family\t: {d}\nmodel\t\t: {d}\nmodel name\t: {s}\nstepping\t: {d}\n", .{
            c, &vendor, family, model, if (brand_s.len > 0) brand_s else "x86_64 CPU", l1.eax & 0xF,
        });
        out.print("cpu MHz\t\t: {d}.000\ncache size\t: 8192 KB\nphysical id\t: 0\nsiblings\t: {d}\ncore id\t\t: {d}\ncpu cores\t: {d}\n", .{ mhz, cpus, c, cpus });
        out.print("apicid\t\t: {d}\ninitial apicid\t: {d}\nfpu\t\t: yes\nfpu_exception\t: yes\ncpuid level\t: {d}\nwp\t\t: yes\nflags\t\t:", .{ cpu.lapic_id, cpu.lapic_id, l0.eax });
        flags(out, l1.edx, &LEAF1_EDX);
        flags(out, ext1.edx, &EXT_EDX);
        out.put(" constant_tsc");
        flags(out, l1.ecx, &LEAF1_ECX);
        flags(out, ext1.ecx, &EXT_ECX);
        flags(out, l7.ebx, &LEAF7_EBX);
        flags(out, l7.ecx, &LEAF7_ECX);
        flags(out, ld.eax, &LEAFD1_EAX);
        out.print("\nbugs\t\t:\nbogomips\t: {d}.00\nclflush size\t: 64\ncache_alignment\t: 64\naddress sizes\t: {d} bits physical, {d} bits virtual\npower management:\n\n", .{
            mhz * 2, sizes & 0xFF, (sizes >> 8) & 0xFF,
        });
    }
}

/// Clock ticks (USER_HZ, 100 a second) a CPU has spent idle.
fn idleTicks(c: *const smp.CpuLocal, now_tsc: u64) u64 {
    const per_tick = apic.tscPerQuantumSane();
    if (per_tick == 0) return 0;
    return smp.idleCycles(c, now_tsc) / per_tick;
}

fn renderStat(out: *Out) void {
    const now = rdtsc();
    const ticks = process.tick_count;
    var all_busy: u64 = 0;
    var all_idle: u64 = 0;
    var rows: [smp.MAX_CPUS][2]u64 = undefined;
    for (0..smp.MAX_CPUS) |c| {
        const cpu = &smp.cpus[c];
        if (!cpu.alive and c != 0) {
            rows[c] = .{ 0, 0 };
            continue;
        }
        const idle = @min(idleTicks(cpu, now), ticks);
        rows[c] = .{ ticks - idle, idle };
        all_busy += ticks - idle;
        all_idle += idle;
    }
    out.print("cpu  {d} 0 0 {d} 0 0 0 0 0 0\n", .{ all_busy, all_idle });
    for (0..smp.MAX_CPUS) |c| {
        if (!smp.cpus[c].alive and c != 0) continue;
        out.print("cpu{d} {d} 0 0 {d} 0 0 0 0 0 0\n", .{ c, rows[c][0], rows[c][1] });
    }
    var running: u32 = 0;
    var total: u32 = 0;
    for (&process.procs) |*p| {
        if (p.state == .unused or p.state == .loading or p.is_idle) continue;
        total += 1;
        if (p.state == .running or p.state == .ready) running += 1;
    }
    out.print("intr {d}\nctxt {d}\nbtime {d}\nprocesses {d}\nprocs_running {d}\nprocs_blocked 0\nsoftirq 0 0 0 0 0 0 0 0 0 0 0\n", .{
        ticks, ticks, bootEpoch(), total, @max(running, 1),
    });
}

fn bootEpoch() u64 {
    return (time.realtimeNanos() -| time.monotonicNanos()) / std.time.ns_per_s;
}

fn renderUptime(out: *Out) void {
    const up_cs = time.monotonicNanos() / (10 * std.time.ns_per_ms);
    const now = rdtsc();
    var idle: u64 = 0;
    for (0..smp.MAX_CPUS) |c| {
        if (!smp.cpus[c].alive and c != 0) continue;
        idle += idleTicks(&smp.cpus[c], now);
    }
    out.print("{d}.{d:0>2} {d}.{d:0>2}\n", .{ up_cs / 100, up_cs % 100, idle / 100, idle % 100 });
}

fn renderLoadavg(out: *Out) void {
    var running: u32 = 0;
    var total: u32 = 0;
    var last: u32 = 0;
    for (&process.procs) |*p| {
        if (p.state == .unused or p.state == .loading or p.is_idle) continue;
        total += 1;
        if (p.state == .running or p.state == .ready) running += 1;
        last = @max(last, p.pid_nr);
    }
    const avg = @import("../proc/loadavg.zig").hundredths();
    out.print("{d}.{d:0>2} {d}.{d:0>2} {d}.{d:0>2} {d}/{d} {d}\n", .{
        avg[0] / 100,    avg[0] % 100, avg[1] / 100, avg[1] % 100, avg[2] / 100, avg[2] % 100,
        @max(running, 1), total,        last,
    });
}

fn rdtsc() u64 {
    return @import("../debug/perf.zig").rdtsc();
}

fn bootId() [16]u8 {
    if (!boot_id_set) {
        _ = @import("../crypto/random.zig").fillRandom(&boot_id);
        boot_id_set = true;
    }
    return boot_id;
}

var boot_id: [16]u8 = undefined;
var boot_id_set = false;

fn freshUuid() [16]u8 {
    var u: [16]u8 = undefined;
    _ = @import("../crypto/random.zig").fillRandom(&u);
    return u;
}

/// A random (version 4) UUID's text.
fn uuidLine(out: *Out, raw: [16]u8) void {
    var u = raw;
    u[6] = (u[6] & 0x0F) | 0x40;
    u[8] = (u[8] & 0x3F) | 0x80;
    for (u, 0..) |b, i| {
        if (i == 4 or i == 6 or i == 8 or i == 10) out.put("-");
        out.print("{x:0>2}", .{b});
    }
    out.put("\n");
}

const MountRow = struct { source: []const u8, dir: []const u8, fstype: []const u8, opts: []const u8 };

fn mountRow(m: vfs.Mount) MountRow {
    return switch (m.fs) {
        .ext2 => .{ .source = "/dev/root", .dir = "/", .fstype = "ext2", .opts = "rw,relatime" },
        .procfs => .{ .source = "proc", .dir = "/proc", .fstype = "proc", .opts = "rw,nosuid,nodev,noexec,relatime" },
        .devfs => .{ .source = "devtmpfs", .dir = "/dev", .fstype = "devtmpfs", .opts = "rw,relatime" },
        .fat32 => .{ .source = "/dev/fat0", .dir = "/fat", .fstype = "vfat", .opts = "rw,relatime" },
        .tarfs => .{ .source = "tarfs", .dir = "/tar", .fstype = "ramfs", .opts = "ro,relatime" },
    };
}

fn renderMounts(out: *Out) void {
    for (vfs.mounts) |m_opt| {
        const r = mountRow(m_opt orelse continue);
        out.print("{s} {s} {s} {s} 0 0\n", .{ r.source, r.dir, r.fstype, r.opts });
    }
    out.put("devpts /dev/pts devpts rw,relatime 0 0\n");
}

fn renderMountinfo(out: *Out) void {
    var id: u32 = 1;
    for (vfs.mounts) |m_opt| {
        const m = m_opt orelse continue;
        const r = mountRow(m);
        out.print("{d} 1 0:{d} / {s} {s} - {s} {s} rw\n", .{ id, id, r.dir, r.opts, r.fstype, r.source });
        id += 1;
    }
    out.print("{d} 1 0:{d} / /dev/pts rw,relatime - devpts devpts rw\n", .{ id, id });
}

fn renderLimits(out: *Out) void {
    const Row = struct { []const u8, ?u64, ?u64, []const u8 };
    const stack: u64 = memmap.LINUX_STACK_RESERVE;
    const rows = [_]Row{
        .{ "Max cpu time", null, null, "seconds" },
        .{ "Max file size", null, null, "bytes" },
        .{ "Max data size", null, null, "bytes" },
        .{ "Max stack size", stack, stack, "bytes" },
        .{ "Max core file size", 0, null, "bytes" },
        .{ "Max resident set", null, null, "bytes" },
        .{ "Max processes", process.MAX_PROCS, process.MAX_PROCS, "processes" },
        .{ "Max open files", config.MAX_FDS, config.MAX_FDS, "files" },
        .{ "Max locked memory", null, null, "bytes" },
        .{ "Max address space", null, null, "bytes" },
        .{ "Max file locks", null, null, "locks" },
        .{ "Max pending signals", 64, 64, "signals" },
        .{ "Max msgqueue size", null, null, "bytes" },
        .{ "Max nice priority", 0, 0, "" },
        .{ "Max realtime priority", 0, 0, "" },
        .{ "Max realtime timeout", null, null, "us" },
    };
    out.put("Limit                     Soft Limit           Hard Limit           Units     \n");
    for (rows) |r| {
        const start = out.len;
        out.put(r[0]);
        out.padTo(start, 26);
        limitCell(out, r[1]);
        out.padTo(start, 47);
        limitCell(out, r[2]);
        out.padTo(start, 68);
        out.put(r[3]);
        out.padTo(start, 78);
        out.put("\n");
    }
}

fn limitCell(out: *Out, v: ?u64) void {
    if (v) |n| out.print("{d}", .{n}) else out.put("unlimited");
}

// --- A process's files --------------------------------------------------------

fn nameOfTask(p: *const process.PCB) []const u8 {
    return p.name[0..p.name_len];
}

fn stateChar(p: *const process.PCB) u8 {
    if (@atomicLoad(bool, &p.job_stopped, .acquire)) return 'T';
    return switch (p.state) {
        .running, .ready, .loading => 'R',
        .sleeping => 'S',
        .zombie => 'Z',
        .unused => 'X',
    };
}

fn stateName(c: u8) []const u8 {
    return switch (c) {
        'R' => "R (running)",
        'S' => "S (sleeping)",
        'T' => "T (stopped)",
        'Z' => "Z (zombie)",
        else => "X (dead)",
    };
}

fn threadsOf(lead: *const process.PCB) u32 {
    var n: u32 = 0;
    for (&process.procs) |*p| {
        if (p.state == .unused or p.state == .loading or p.state == .zombie) continue;
        if (p.tgid == lead.tgid) n += 1;
    }
    return @max(n, 1);
}

/// The process's CPU time in clock ticks: its threads' together.
fn cpuTicks(lead: *const process.PCB) u64 {
    return process.groupCpuTicks(lead.tgid);
}

fn parentNr(p: *const process.PCB) u32 {
    const pp = p.parent_pid;
    if (pp >= process.MAX_PROCS or process.procs[pp].state == .unused or pp == p.tgid) return 0;
    return process.procs[process.procs[pp].tgid].pid_nr;
}

/// The terminal of a process's session: its device number and foreground
/// group (0 and -1 for none).
fn ttyFacts(lead: *const process.PCB) struct { dev: u32, fg: i64 } {
    const id = tty.ofSession(lead.sid) orelse return .{ .dev = 0, .fg = -1 };
    const t = tty.get(id) orelse return .{ .dev = 0, .fg = -1 };
    const fg: i64 = @atomicLoad(u32, &t.fg_pgid, .acquire);
    if (ptsOf(id)) |n| return .{ .dev = (136 << 8) | (n & 0xFF) | ((n >> 8) << 20), .fg = fg };
    return .{ .dev = (4 << 8) | (@as(u32, id) + 1), .fg = fg };
}

/// Sizes in bytes; `rss` in pages, counted in the tables as they are now.
const Vm = struct { size: u64 = 0, stack: u64 = 0, exe: u64 = 0, data: u64 = 0, rss: u64 = 0 };

fn vmOf(lead: *process.PCB) Vm {
    var vm = Vm{};
    if (!withAs(lead)) return vm;
    defer doneAs(lead);
    if (lead.page_directory) |pd| vm.rss = vmm.countUserPages(pd);
    for (lead.regions.slice()) |r| {
        const len: u64 = r.end - r.start;
        vm.size += len;
        if (r.start == lead.stack_base) {
            vm.stack += len;
        } else if (r.cache_inode != 0 and r.cache_inode == lead.text_inum) {
            vm.exe += len;
        } else if (r.prot & process.PROT_WRITE != 0) {
            vm.data += len;
        }
    }
    return vm;
}

/// oom_score on Linux's scale: the process's pages and its oom_score_adj
/// against all memory, 666 for none of either, 0 for one never chosen.
fn oomScore(lead: *process.PCB) u64 {
    const adj: i64 = @atomicLoad(i16, &lead.oom_score_adj, .monotonic);
    if (adj == -1000) return 0;
    const total: i64 = @intCast(@max(pmm.managedFrameCount(), 1000));
    const weight = @as(i64, @intCast(vmOf(lead).rss)) + adj * @divTrunc(total, 1000);
    return @intCast(@max(@divTrunc((1000 + @divTrunc(weight * 1000, total)) * 2, 3), 0));
}

/// Hold the read side of `lead`'s address-space lock, if the process still
/// has its image: teardown and execve change the tables and regions under
/// the write side, so they are read only after this. From another process
/// the lock is a foreign one (tearDownTask lets it go if the reader dies).
fn withAs(lead: *process.PCB) bool {
    const nr = lead.pid_nr;
    if (process.currentPCB()) |me| {
        if (me.tgid != lead.tgid) me.foreign_as_lock = lead.tgid;
    }
    lead.as_lock.acquireRead();
    // A zombie lead keeps the tables while other threads of it live.
    if (lead.pid_nr == nr and lead.page_directory != null and (lead.state != .zombie or process.pinnedLead(lead.tgid))) return true;
    doneAs(lead);
    return false;
}

fn doneAs(lead: *process.PCB) void {
    lead.as_lock.releaseRead();
    if (process.currentPCB()) |m| m.foreign_as_lock = process.NO_FOREIGN_LOCK;
}

fn sigSets(lead: *process.PCB) struct { ign: u64, cgt: u64 } {
    var ign: u64 = 0;
    var cgt: u64 = 0;
    const disp = signals.dispositions(lead);
    var s: u32 = 1;
    while (s < signals.NSIG) : (s += 1) {
        const h = disp[s].handler;
        if (h == signals.SIG_IGN) ign |= signals.bit(s) else if (h != signals.SIG_DFL) cgt |= signals.bit(s);
    }
    return .{ .ign = ign, .cgt = cgt };
}

fn renderPidStat(view: *process.PCB, lead: *process.PCB, in_task: bool, out: *Out) void {
    const t = ttyFacts(lead);
    const vm = vmOf(lead);
    const sets = sigSets(lead);
    const ticks = if (in_task) process.cpuTicksOf(view) else cpuTicks(lead);
    const pending = @atomicLoad(u64, &view.pending_signals, .acquire) | @atomicLoad(u64, &lead.shared_pending, .acquire);
    out.print("{d} ({s}) {c} {d} {d} {d} {d} {d} 0 {d} 0 0 0 {d} 0 0 0 {d} {d} {d} 0 {d} {d} {d} 18446744073709551615 ", .{
        view.pid_nr,                  nameOfTask(view),        stateChar(view),
        parentNr(lead),               lead.pgid,               lead.sid,
        t.dev,                        t.fg,                    view.acct_pf_count,
        ticks,                        20 + @as(i32, view.nice), view.nice,
        threadsOf(lead),              view.acct_start_tick,    vm.size,
        vm.rss,
    });
    out.print("0 0 {d} 0 0 {d} {d} {d} {d} 0 0 0 17 {d} 0 0 0 0 0 0 0 {d} {d} {d} {d} {d} 0\n", .{
        lead.stack_base +| memmap.LINUX_STACK_RESERVE, pending, view.signal_mask, sets.ign, sets.cgt,
        view.last_cpu,                                 lead.brk_base, lead.arg_start, lead.arg_end, lead.arg_end, lead.env_end,
    });
}

fn renderStatm(lead: *process.PCB, out: *Out) void {
    const vm = vmOf(lead);
    out.print("{d} {d} 0 {d} 0 {d} 0\n", .{ vm.size / 4096, vm.rss, vm.exe / 4096, vm.data / 4096 });
}

fn renderStatus(view: *process.PCB, lead: *process.PCB, in_task: bool, out: *Out) void {
    _ = in_task;
    const vm = vmOf(lead);
    const sets = sigSets(lead);
    out.print("Name:\t{s}\nUmask:\t{o:0>4}\nState:\t{s}\nTgid:\t{d}\nNgid:\t0\nPid:\t{d}\nPPid:\t{d}\nTracerPid:\t0\n", .{
        nameOfTask(view), lead.umask, stateName(stateChar(view)), lead.pid_nr, view.pid_nr, parentNr(lead),
    });
    out.print("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t{d}\nGroups:\t\nNStgid:\t{d}\nNSpid:\t{d}\nNSpgid:\t{d}\nNSsid:\t{d}\n", .{
        config.MAX_FDS, lead.pid_nr, view.pid_nr, lead.pgid, lead.sid,
    });
    out.print("VmPeak:\t{d: >8} kB\nVmSize:\t{d: >8} kB\nVmLck:\t       0 kB\nVmPin:\t       0 kB\nVmHWM:\t{d: >8} kB\nVmRSS:\t{d: >8} kB\n", .{
        vm.size / 1024, vm.size / 1024, kb(@max(lead.acct_peak_rss, vm.rss)), kb(vm.rss),
    });
    out.print("RssAnon:\t{d: >8} kB\nRssFile:\t       0 kB\nRssShmem:\t       0 kB\nVmData:\t{d: >8} kB\nVmStk:\t{d: >8} kB\nVmExe:\t{d: >8} kB\nVmLib:\t       0 kB\nVmPTE:\t       0 kB\nVmSwap:\t       0 kB\n", .{
        kb(vm.rss), vm.data / 1024, vm.stack / 1024, vm.exe / 1024,
    });
    const pending = @atomicLoad(u64, &view.pending_signals, .acquire);
    const shared = @atomicLoad(u64, &lead.shared_pending, .acquire);
    out.print("Threads:\t{d}\nSigQ:\t0/64\nSigPnd:\t{x:0>16}\nShdPnd:\t{x:0>16}\nSigBlk:\t{x:0>16}\nSigIgn:\t{x:0>16}\nSigCgt:\t{x:0>16}\n", .{
        threadsOf(lead), pending, shared, view.signal_mask, sets.ign, sets.cgt,
    });
    out.put("CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\n");
    const cpus: u32 = smp.cpu_count;
    const mask: u64 = if (cpus >= 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(cpus)) - 1;
    out.print("Cpus_allowed:\t{x}\nCpus_allowed_list:\t0-{d}\nvoluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n", .{ mask, cpus - 1 });
}

fn renderCmdline(lead: *process.PCB, out: *Out) void {
    if (copyFromTask(lead, .args, out)) return;
    // A native image keeps its arguments in the PCB.
    var i: u32 = 0;
    while (i < lead.argc) : (i += 1) {
        out.put(lead.argv[i][0..lead.arg_lens[i]]);
        out.put("\x00");
    }
}

const Span = enum { args, env, auxv };

/// The bytes of a span of `lead`'s memory, as far as they are present: a
/// page swapped out or never touched ends the copy. The bounds are image
/// fields, so they too are read under the lock. False only for a native
/// image's arguments, which live in the PCB instead.
fn copyFromTask(lead: *process.PCB, span: Span, out: *Out) bool {
    if (!withAs(lead)) return true;
    defer doneAs(lead);
    const from, const to = switch (span) {
        .args => .{ lead.arg_start, lead.arg_end },
        .env => .{ lead.arg_end, lead.env_end },
        .auxv => .{ lead.auxv_start, lead.auxv_end },
    };
    if (from == 0) return span != .args;
    const pml4 = lead.page_directory.?;
    var va = from;
    while (va < to and out.len < out.buf.len) {
        const page_left = 4096 - (va & 0xFFF);
        const n = @min(to - va, page_left);
        const phys = vmm.resolveUserPhys(pml4, va) orelse break;
        const src = phys.toVirt().ptr([*]const u8) + (va & 0xFFF);
        out.put(src[0..n]);
        va += n;
    }
    return true;
}

/// A region of the program's own ELF segments, read from its image buffer.
fn fromImage(r: process.LazyRegion, lead: *const process.PCB) bool {
    const src = r.source orelse return false;
    const img = lead.elf_buf orelse return false;
    return @intFromPtr(src) == @intFromPtr(img);
}

fn renderMaps(lead: *process.PCB, out: *Out) void {
    var name_buf: [256]u8 = undefined;
    if (!withAs(lead)) return;
    defer doneAs(lead);
    for (lead.regions.slice()) |r| {
        const shared = r.cache_shared or r.shm_id != shm.SHM_INVALID;
        var off: u64 = 0;
        var inode: u64 = 0;
        var name: []const u8 = "";
        if (r.cache_inode != 0) {
            off = r.cache_off;
            inode = r.cache_inode;
            name = if (r.cache_inode == lead.text_inum and lead.exe_path_len != 0)
                lead.exe_path[0..lead.exe_path_len]
            else // no disk reads under the lock (ext2 names only directories)
                noted(r.cache_inode, &name_buf) orelse "";
        } else if (fromImage(r, lead)) {
            off = r.src_offset;
            inode = lead.text_inum;
            name = lead.exe_path[0..lead.exe_path_len];
        } else if (r.start == lead.stack_base) {
            name = "[stack]";
        } else if (lead.heap_start != 0 and r.start == lead.heap_start) {
            name = "[heap]";
        } else if (r.shm_id != shm.SHM_INVALID) {
            off = @as(u64, r.shm_off) * 0x1000;
            name = "/dev/zero (deleted)";
        }
        const start = out.len;
        out.print("{x:0>8}-{x:0>8} {c}{c}{c}{c} {x:0>8} {s} {d}", .{
            r.start,                                                   r.end,
            if (r.prot & process.PROT_READ != 0) @as(u8, 'r') else '-', if (r.prot & process.PROT_WRITE != 0) @as(u8, 'w') else '-',
            if (r.prot & process.PROT_EXEC != 0) @as(u8, 'x') else '-', if (shared) @as(u8, 's') else 'p',
            off,                                                        if (inode != 0) "08:01" else "00:00",
            inode,
        });
        if (name.len > 0) {
            out.padTo(start, 73);
            out.put(name);
        }
        out.put("\n");
    }
}
