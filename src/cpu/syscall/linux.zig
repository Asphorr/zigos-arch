//! Linux x86-64 binary personality — syscall translation layer.
//!
//! When a process is loaded with `personality == .linux` (the Linux ELF path
//! in elf_loader), its `syscall` instructions land here instead of the native
//! doSyscallInner dispatch. We read the Linux ABI's six u64 args straight out
//! of the saved SyscallFrame (rdi/rsi/rdx/r10/r8/r9), switch on the Linux
//! syscall number (RAX, passed as `num`), translate onto zigos primitives, and
//! return a full 64-bit value per the Linux convention: a result, or an error
//! as the sign-extended `-errno` (a value in [-4095, -1]).
//!
//! This is the "run unmodified static Linux binaries" path.
//!   * M0 — the freestanding raw-syscall case (write + exit).
//!   * M1 — a static musl program that uses libc (`printf`): SysV initial stack
//!     (elf_loader.setupLinuxInitialStack), arch_prctl TLS, writev flush.
//!   * M2 — file I/O on the ext2 root: a libc program that opendir/readdir's or
//!     fopen/fread's a real file (openat/read/close/lseek/fstat/newfstatat/
//!     getdents64) plus anonymous mmap + brk for malloc.
//!
//! The native ABI (3×u32 args, native numbers, return u32) is entirely
//! separate and untouched — the only shared edge is doSyscall's one-line
//! personality check.

const signals = @import("../../proc/signals.zig");
const process = @import("../../proc/process.zig");
const vfs = @import("../../fs/vfs.zig");
const common = @import("common.zig");
const debug = @import("../../debug/debug.zig");
const ext2_inode = @import("../../fs/ext2/inode.zig");
const ext2_fs = @import("../../fs/ext2/ext2.zig");
const heap = @import("../../mm/heap.zig");

// --- Linux x86-64 errno (DISTINCT from zigos common.E_* — different values).
// Returned to userspace as the sign-extended negative, per the kernel ABI.
const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const ENOTDIR: i64 = 20;
const EISDIR: i64 = 21;
const EINVAL: i64 = 22;
const ENOTTY: i64 = 25;
const ERANGE: i64 = 34;
const ESPIPE: i64 = 29;
const ENOSYS: i64 = 38;

/// Encode a positive errno as the Linux-ABI return value (sign-extended -errno).
inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

// --- Linux x86-64 syscall numbers (subset; grows per milestone). ---
const SYS_read: u32 = 0;
const SYS_write: u32 = 1;
const SYS_open: u32 = 2;
const SYS_close: u32 = 3;
const SYS_fstat: u32 = 5;
const SYS_lseek: u32 = 8;
const SYS_mmap: u32 = 9;
const SYS_mprotect: u32 = 10;
const SYS_munmap: u32 = 11;
const SYS_brk: u32 = 12;
const SYS_rt_sigaction: u32 = 13;
const SYS_rt_sigprocmask: u32 = 14;
const SYS_ioctl: u32 = 16;
const SYS_readv: u32 = 19;
const SYS_writev: u32 = 20;
const SYS_fcntl: u32 = 72;

// fcntl commands (the few musl's open/opendir paths issue).
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const SYS_stat: u32 = 4;
const SYS_lstat: u32 = 6;
const SYS_uname: u32 = 63;
const SYS_getcwd: u32 = 79;
const SYS_getuid: u32 = 102;
const SYS_getgid: u32 = 104;
const SYS_setuid: u32 = 105;
const SYS_setgid: u32 = 106;
const SYS_geteuid: u32 = 107;
const SYS_getegid: u32 = 108;
// AT_FDCWD (-100): stat/lstat resolve their path against the cwd, exactly like
// newfstatat(AT_FDCWD, ...). statPath ignores the dirfd for a non-empty path.
const AT_FDCWD: u64 = 0xFFFF_FFFF_FFFF_FF9C;
const SYS_getpid: u32 = 39;
const SYS_exit: u32 = 60;
const SYS_getdents64: u32 = 217;
const SYS_set_tid_address: u32 = 218;
const SYS_exit_group: u32 = 231;
const SYS_openat: u32 = 257;
const SYS_newfstatat: u32 = 262;
const SYS_arch_prctl: u32 = 158;
const SYS_set_robust_list: u32 = 273;

// arch_prctl subfunction codes.
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;

const IA32_FS_BASE: u32 = 0xC0000100;

// open(2) flag bits (the few that map onto zigos vfs flags). Linux's other
// bits (O_DIRECTORY/O_CLOEXEC/O_NONBLOCK/access mode) are handled implicitly:
// we try a regular-file open then a directory open, so O_DIRECTORY needs no
// explicit decode for the cases that matter.
const LINUX_O_CREAT: u64 = 0x40;
const LINUX_O_TRUNC: u64 = 0x200;
const LINUX_O_APPEND: u64 = 0x400;

const MAP_ANONYMOUS: u64 = 0x20;
const AT_EMPTY_PATH: u64 = 0x1000;

// d_type values for getdents64.
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;

// struct stat st_mode format bits (same values as ext2 on-disk i_mode).
const S_IFCHR: u32 = 0o0020000;
const S_IFDIR: u32 = 0o0040000;
const S_IFREG: u32 = 0o0100000;

/// Linux iovec: { void *iov_base; size_t iov_len; } — 16 bytes, native order.
const Iovec = extern struct { base: u64, len: u64 };

/// Linux x86-64 `struct stat` — 144 bytes, exact field layout per
/// arch/x86/include/uapi/asm/stat.h. Defaults zero so unfilled fields read 0.
const LinuxStat = extern struct {
    st_dev: u64 = 0,
    st_ino: u64 = 0,
    st_nlink: u64 = 0,
    st_mode: u32 = 0,
    st_uid: u32 = 0,
    st_gid: u32 = 0,
    __pad0: u32 = 0,
    st_rdev: u64 = 0,
    st_size: i64 = 0,
    st_blksize: i64 = 0,
    st_blocks: i64 = 0,
    st_atime: u64 = 0,
    st_atime_nsec: u64 = 0,
    st_mtime: u64 = 0,
    st_mtime_nsec: u64 = 0,
    st_ctime: u64 = 0,
    st_ctime_nsec: u64 = 0,
    __unused: [3]i64 = .{ 0, 0, 0 },
};

/// Mirrors syscall.FileEntry / ext2.FileEntry (48 bytes) — ext2.listDir fills
/// an array of these. We read name / name_len / flags to serialize dirents.
const FileEntry = extern struct {
    name: [32]u8,
    name_len: u8,
    file_size: u32 align(1),
    flags: u8,
    _pad: [10]u8,
};
const FE_FLAG_IS_DIR: u8 = 0x02;

inline fn putU64(p: [*]u8, v: u64) void {
    @as(*align(1) u64, @ptrCast(p)).* = v;
}
inline fn putU16(p: [*]u8, v: u16) void {
    @as(*align(1) u16, @ptrCast(p)).* = v;
}

/// Linux-personality syscall dispatch. `num` is RAX (the Linux syscall number);
/// the six args are read from the frame in Linux register order
/// (rdi, rsi, rdx, r10, r8, r9). Returns the Linux-ABI u64 (result or -errno).
pub fn dispatch(num: u32, frame: *signals.SyscallFrame) u64 {
    const a1 = frame.rdi;
    const a2 = frame.rsi;
    const a3 = frame.rdx;
    const a4 = frame.r10;
    const a5 = frame.r8;
    const a6 = frame.r9;

    switch (num) {
        SYS_read => return sysRead(@truncate(a1), a2, a3),
        SYS_readv => return sysReadv(@truncate(a1), a2, a3),
        SYS_write => return sysWrite(@truncate(a1), a2, a3),
        SYS_writev => return sysWritev(@truncate(a1), a2, a3),
        SYS_fcntl => return sysFcntl(@truncate(a1), a2, a3),
        SYS_open => return sysOpenImpl(a1, a2),
        SYS_openat => return sysOpenImpl(a2, a3), // dirfd ignored: AT_FDCWD only (M2)
        SYS_close => return sysClose(@truncate(a1)),
        SYS_lseek => return sysLseek(@truncate(a1), a2, @truncate(a3)),
        SYS_fstat => return sysFstat(@truncate(a1), a2),
        SYS_newfstatat => return sysNewfstatat(a1, a2, a3, a4),
        SYS_getdents64 => return sysGetdents64(@truncate(a1), a2, a3),
        SYS_mmap => return sysMmap(a1, a2, a3, a4, a5, a6),
        SYS_munmap => return 0, // no per-region reclaim yet; freed at exit
        SYS_mprotect => return 0, // anon pages are already RW; no-op
        SYS_brk => return sysBrk(a1),
        // isatty / line-buffering probe: musl's first stdio write does
        // ioctl(fd, TIOCGWINSZ). Reporting "not a tty" (-ENOTTY) makes it pick
        // full buffering and flush via writev at exit — exactly what we want.
        SYS_ioctl => return err(ENOTTY),
        // TLS bring-up: musl's __init_tp does arch_prctl(ARCH_SET_FS, tcb).
        SYS_arch_prctl => return sysArchPrctl(a1, a2),
        // musl stores the return as its tid; the clear-child-tid pointer (a1)
        // is for futex-on-exit join, which we don't implement yet — ignore it.
        SYS_set_tid_address => return process.getCurrentPid(),
        SYS_getpid => return process.getCurrentPid(),
        // No Linux-signal delivery for these processes yet, so these are moot.
        SYS_rt_sigprocmask => return 0,
        SYS_rt_sigaction => return 0,
        SYS_set_robust_list => return 0,
        // Path-based stat/lstat == newfstatat against the cwd. We have no
        // symlinks, so lstat and stat are identical.
        SYS_stat, SYS_lstat => return sysNewfstatat(AT_FDCWD, a1, a2, 0),
        SYS_uname => return sysUname(a1),
        SYS_getcwd => return sysGetcwd(a1, a2),
        // Single-user system: everything runs as root (uid/gid 0). setuid/setgid
        // to any id "succeeds" as a no-op (we are already privileged).
        SYS_getuid, SYS_geteuid, SYS_getgid, SYS_getegid => return 0,
        SYS_setuid, SYS_setgid => return 0,
        SYS_exit, SYS_exit_group => {
            // Low byte is the wait-status exit code (per _exit(2)).
            process.destroyCurrentGraceful(@truncate(a1 & 0xFF));
            return 0; // never reached: destroyCurrentGraceful switches away.
        },
        else => {
            // Bring-up aid: surface exactly which syscall a binary needs next,
            // with its args, so growing M2→M3 is "read the log, add the arm".
            debug.klog("[linux] pid={d} unimpl syscall {d} (a1=0x{X} a2=0x{X} a3=0x{X})\n", .{
                process.getCurrentPid(), num, a1, a2, a3,
            });
            return err(ENOSYS);
        },
    }
}

/// write(fd, buf, count). Delegates to the same vfs.write the native path uses
/// (zigos user VAs are sub-4GB, so the 64-bit pointer round-trips through the
/// u32 helpers). Returns the byte count on success; a faulting buffer is
/// -EFAULT.
fn sysWrite(fd: u32, buf_va: u64, count: u64) u64 {
    if (count == 0) return 0;
    const len: usize = @intCast(count);
    if (buf_va > 0xFFFF_FFFF or !common.validateUserPtr(@truncate(buf_va), @truncate(len))) {
        return err(EFAULT);
    }
    const pcb = process.currentPCB() orelse return err(EFAULT);
    const buf: [*]const u8 = @ptrFromInt(@as(usize, @intCast(buf_va)));
    if (fd <= 2 and len <= 1024) debug.klog("[linux] write(fd={d}): {s}", .{ fd, buf[0..len] });
    const n = vfs.write(pcb, fd, buf, @truncate(len));
    if (n == 0xFFFF_FFFF) return err(EBADF);
    return n;
}

/// read(fd, buf, count). Delegates to vfs.read (returns 0 at EOF, 0xFFFFFFFF on
/// bad fd). Linux read of a directory fd is -EISDIR.
fn sysRead(fd: u32, buf_va: u64, count: u64) u64 {
    if (count == 0) return 0;
    if (buf_va > 0xFFFF_FFFF) return err(EFAULT);
    const len: u32 = if (count > 0xFFFF_F000) 0xFFFF_F000 else @truncate(count);
    if (!common.validateUserPtr(@truncate(buf_va), len)) return err(EFAULT);
    const pcb = process.currentPCB() orelse return err(EFAULT);
    if (fd < pcb.fd_table.len and pcb.fd_table[fd].in_use and pcb.fd_table[fd].fs_type == .ext2) {
        if (ext2_inode.readInode(pcb.fd_table[fd].inode)) |ino| {
            if (ext2_inode.isDir(&ino)) return err(EISDIR);
        }
    }
    const buf: [*]u8 = @ptrFromInt(@as(usize, @intCast(buf_va)));
    const n = vfs.read(pcb, fd, buf, len);
    if (n == 0xFFFF_FFFF) return err(EBADF);
    return n;
}

/// writev(fd, iov, iovcnt). musl's stdio writes everything through writev (the
/// FILE buffer + the new bytes as two iovecs), so this is the real output path
/// for printf. Walks the iovec array, writing each segment via vfs.write, and
/// returns the total bytes written (or -EFAULT / -EBADF).
fn sysWritev(fd: u32, iov_va: u64, iovcnt: u64) u64 {
    if (iovcnt == 0) return 0;
    if (iovcnt > 1024) return err(EINVAL); // sane cap; UIO_MAXIOV is 1024
    if (iov_va > 0xFFFF_FFFF) return err(EFAULT);
    const n: usize = @intCast(iovcnt);
    const array_bytes = n * @sizeOf(Iovec);
    if (!common.validateUserPtr(@truncate(iov_va), @truncate(array_bytes))) return err(EFAULT);
    const pcb = process.currentPCB() orelse return err(EFAULT);
    const iov: [*]align(1) const Iovec = @ptrFromInt(@as(usize, @intCast(iov_va)));

    var total: u64 = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const base = iov[i].base;
        const seg = iov[i].len;
        if (seg == 0) continue;
        if (seg > 0xFFFF_FFFF or base > 0xFFFF_FFFF or
            !common.validateUserPtr(@truncate(base), @truncate(seg)))
        {
            if (total > 0) return total;
            return err(EFAULT);
        }
        const buf: [*]const u8 = @ptrFromInt(@as(usize, @intCast(base)));
        const l: u32 = @truncate(seg);
        if (fd <= 2 and seg <= 1024) debug.klog("[linux] writev(fd={d}): {s}", .{ fd, buf[0..@intCast(seg)] });
        const w = vfs.write(pcb, fd, buf, l);
        if (w == 0xFFFF_FFFF) {
            if (total > 0) return total;
            return err(EBADF);
        }
        total += w;
        if (w < l) break; // short write — stop, report what landed
    }
    return total;
}

/// readv(fd, iov, iovcnt). musl's stdio fills its FILE buffer through readv
/// (mirror of how it flushes through writev), so this is the real input path
/// for fread. Reads each segment via vfs.read, which advances the fd offset, so
/// consecutive iovecs read sequentially. Stops on a short read (EOF).
fn sysReadv(fd: u32, iov_va: u64, iovcnt: u64) u64 {
    if (iovcnt == 0) return 0;
    if (iovcnt > 1024) return err(EINVAL);
    if (iov_va > 0xFFFF_FFFF) return err(EFAULT);
    const n: usize = @intCast(iovcnt);
    const array_bytes = n * @sizeOf(Iovec);
    if (!common.validateUserPtr(@truncate(iov_va), @truncate(array_bytes))) return err(EFAULT);
    const pcb = process.currentPCB() orelse return err(EFAULT);
    // Linux read of a directory fd is -EISDIR (same guard as sysRead).
    if (fd < pcb.fd_table.len and pcb.fd_table[fd].in_use and pcb.fd_table[fd].fs_type == .ext2) {
        if (ext2_inode.readInode(pcb.fd_table[fd].inode)) |ino| {
            if (ext2_inode.isDir(&ino)) return err(EISDIR);
        }
    }
    const iov: [*]align(1) const Iovec = @ptrFromInt(@as(usize, @intCast(iov_va)));
    var total: u64 = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const base = iov[i].base;
        const seg = iov[i].len;
        if (seg == 0) continue;
        if (seg > 0xFFFF_FFFF or base > 0xFFFF_FFFF or
            !common.validateUserPtr(@truncate(base), @truncate(seg)))
        {
            if (total > 0) return total;
            return err(EFAULT);
        }
        const buf: [*]u8 = @ptrFromInt(@as(usize, @intCast(base)));
        const l: u32 = @truncate(seg);
        const r = vfs.read(pcb, fd, buf, l);
        if (r == 0xFFFF_FFFF) {
            if (total > 0) return total;
            return err(EBADF);
        }
        total += r;
        if (r < l) break; // short read / EOF — stop
    }
    return total;
}

/// fcntl(fd, cmd, arg). musl's open/opendir paths issue F_SETFD(FD_CLOEXEC);
/// we don't share fds across a Linux exec yet, so cloexec is a no-op. The
/// flag-query/set commands return benign values. F_DUPFD and anything else is
/// unimplemented (logged via the default ENOSYS path is avoided — return it
/// directly so fcntl spam doesn't look like a missing syscall).
fn sysFcntl(fd: u32, cmd: u64, arg: u64) u64 {
    _ = arg;
    const pcb = process.currentPCB() orelse return err(EFAULT);
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return err(EBADF);
    return switch (cmd) {
        F_GETFD => 0, // FD_CLOEXEC not tracked
        F_SETFD => 0, // accept (cloexec no-op)
        F_GETFL => 0, // report O_RDONLY-ish; musl rarely depends on exact flags
        F_SETFL => 0,
        else => err(ENOSYS),
    };
}

/// Read a NUL-terminated user path (≤255 bytes) into `out`. Returns the slice,
/// or null on a faulting/empty pointer. `allow_empty` keeps a zero-length path
/// (newfstatat's AT_EMPTY_PATH form); otherwise empty → null.
fn readUserPath(va: u64, out: *[256]u8, allow_empty: bool) ?[]const u8 {
    if (va == 0 or va > 0xFFFF_FFFF) return null;
    const base: usize = @intCast(va);
    var nlen: usize = 0;
    while (nlen < 255) : (nlen += 1) {
        if (!common.validateUserPtr(@truncate(base + nlen), 1)) return null;
        const ch = @as([*]const u8, @ptrFromInt(base + nlen))[0];
        if (ch == 0) break;
        out[nlen] = ch;
    }
    if (nlen == 0 and !allow_empty) return null;
    return out[0..nlen];
}

/// open(path, flags) / openat(AT_FDCWD, path, flags). Tries the regular-file
/// path first (ext2.openFile rejects directories), then a directory open.
fn sysOpenImpl(path_va: u64, lflags: u64) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    var pbuf: [256]u8 = undefined;
    const path = readUserPath(path_va, &pbuf, false) orelse return err(EFAULT);
    var zflags: u32 = 0;
    if (lflags & LINUX_O_CREAT != 0) zflags |= vfs.O_CREATE;
    if (lflags & LINUX_O_TRUNC != 0) zflags |= vfs.O_TRUNC;
    if (lflags & LINUX_O_APPEND != 0) zflags |= vfs.O_APPEND;
    if (vfs.openFlags(pcb, path, zflags)) |fd| return fd;
    if (vfs.openDir(pcb, path)) |fd| return fd;
    return err(ENOENT);
}

fn sysClose(fd: u32) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    const r = vfs.close(pcb, fd);
    if (r != 0) return err(EBADF);
    return 0;
}

/// File size behind an fd (ext2 only; 0 otherwise) — for lseek SEEK_END.
fn fdFileSize(fe: *const process.FileDesc) u64 {
    if (fe.fs_type != .ext2) return 0;
    const ino = ext2_inode.readInode(fe.inode) orelse return 0;
    return ext2_inode.fileSize(&ino);
}

/// lseek(fd, off, whence). offset is u32 in the fd table; SEEK_SET/CUR/END.
fn sysLseek(fd: u32, off: u64, whence: u32) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return err(EBADF);
    if (fd < 3) return err(ESPIPE); // console isn't seekable
    const fe = &pcb.fd_table[fd];
    const new: u64 = switch (whence) {
        0 => off, // SEEK_SET
        1 => @as(u64, fe.offset) +% off, // SEEK_CUR
        2 => fdFileSize(fe) +% off, // SEEK_END
        else => return err(EINVAL),
    };
    if (new > 0xFFFF_FFFF) return err(EINVAL);
    fe.offset = @truncate(new);
    return new;
}

/// Fill a Linux struct stat for a console fd (stdin/out/err) — a char device.
fn fillStatConsole(st: *LinuxStat) void {
    st.st_mode = S_IFCHR | 0o620;
    st.st_nlink = 1;
    st.st_blksize = 1024;
    st.st_rdev = 0x0500;
}

/// Fill a Linux struct stat from an ext2 inode (the faithful path — real mode,
/// size, link count, times). Returns false if the inode can't be read.
fn fillStatExt2Inum(inum: u32, st: *LinuxStat) bool {
    const ino = ext2_inode.readInode(inum) orelse return false;
    st.st_ino = inum;
    st.st_mode = ino.mode;
    st.st_nlink = ino.links_count;
    st.st_uid = ino.uid;
    st.st_gid = ino.gid;
    st.st_size = @intCast(ext2_inode.fileSize(&ino));
    st.st_blksize = 4096;
    st.st_blocks = @intCast(ino.blocks); // ext2 i_blocks already in 512-B units
    st.st_atime = ino.atime;
    st.st_mtime = ino.mtime;
    st.st_ctime = ino.ctime;
    return true;
}

/// Synthesize a Linux struct stat from coarse {is_dir, size} (the path-stat
/// fallback via vfs.statPath, which only yields those facts).
fn fillStatSynth(st: *LinuxStat, is_dir: bool, size: u64) void {
    st.st_mode = if (is_dir) (S_IFDIR | 0o755) else (S_IFREG | 0o644);
    st.st_nlink = 1;
    st.st_size = @intCast(size);
    st.st_blksize = 4096;
    st.st_blocks = @intCast((size + 511) / 512);
}

/// fstat the file behind `fd` into the user stat buffer.
fn statByFd(pcb: *process.PCB, fd: u32, st: *LinuxStat) u64 {
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return err(EBADF);
    const fe = &pcb.fd_table[fd];
    switch (fe.fs_type) {
        .console => fillStatConsole(st),
        .ext2 => if (!fillStatExt2Inum(fe.inode, st)) return err(EBADF),
        else => fillStatSynth(st, false, 0),
    }
    return 0;
}

/// fstat(fd, statbuf).
fn sysFstat(fd: u32, statbuf_va: u64) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    if (statbuf_va > 0xFFFF_FFFF or !common.validateUserPtr(@truncate(statbuf_va), @sizeOf(LinuxStat))) return err(EFAULT);
    const st: *LinuxStat = @ptrFromInt(@as(usize, @intCast(statbuf_va)));
    st.* = .{};
    return statByFd(pcb, fd, st);
}

/// newfstatat(dirfd, path, statbuf, flags). M2 supports AT_FDCWD (path resolved
/// against cwd) and the AT_EMPTY_PATH / empty-path form (== fstat(dirfd)).
/// dirfd-relative resolution against an arbitrary directory fd is deferred.
fn sysNewfstatat(dirfd: u64, path_va: u64, statbuf_va: u64, flags: u64) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    if (statbuf_va > 0xFFFF_FFFF or !common.validateUserPtr(@truncate(statbuf_va), @sizeOf(LinuxStat))) return err(EFAULT);
    const st: *LinuxStat = @ptrFromInt(@as(usize, @intCast(statbuf_va)));
    st.* = .{};

    var pbuf: [256]u8 = undefined;
    const path = readUserPath(path_va, &pbuf, true) orelse return err(EFAULT);
    // Empty path: with AT_EMPTY_PATH this is fstat(dirfd) (how musl's fstat is
    // built); without the flag POSIX says -ENOENT.
    if (path.len == 0) {
        if (flags & AT_EMPTY_PATH == 0) return err(ENOENT);
        return statByFd(pcb, @truncate(dirfd), st);
    }
    var info: vfs.StatInfo = undefined;
    if (!vfs.statPath(pcb, path, &info)) return err(ENOENT);
    fillStatSynth(st, info.is_directory != 0, info.file_size);
    if (info.modify_time != 0) {
        st.st_mtime = info.modify_time;
        st.st_atime = info.modify_time;
        st.st_ctime = info.modify_time;
    }
    return 0;
}

/// uname(2): fill `struct utsname` — six 65-byte char fields (sysname,
/// nodename, release, version, machine, domainname). We report a Linux identity
/// (so `uname -s` reads "Linux", which is what a Linux binary expects) with a
/// zigos flavor in the node/release/version fields.
const UTS_LEN: usize = 65;
const UTSNAME_SIZE: usize = 6 * UTS_LEN; // 390 bytes

fn sysUname(buf_va: u64) u64 {
    if (buf_va == 0 or buf_va > 0xFFFF_FFFF or !common.validateUserPtr(@truncate(buf_va), UTSNAME_SIZE)) return err(EFAULT);
    const buf: []u8 = @as([*]u8, @ptrFromInt(@as(usize, @intCast(buf_va))))[0..UTSNAME_SIZE];
    @memset(buf, 0); // zero first so every field is NUL-terminated
    const fields = [_][]const u8{ "Linux", "zigos", "6.6.0-zigos", "#1 zigos", "x86_64", "(none)" };
    inline for (fields, 0..) |f, i| {
        const n = @min(f.len, UTS_LEN - 1);
        @memcpy(buf[i * UTS_LEN ..][0..n], f[0..n]);
    }
    return 0;
}

/// getcwd(buf, size): copy the process cwd + NUL into the user buffer. Linux
/// returns the byte length including the NUL (musl turns that into the buf
/// pointer); -ERANGE if the buffer is too small to hold path + NUL.
fn sysGetcwd(buf_va: u64, size: u64) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    const cwd = pcb.cwd[0..pcb.cwd_len];
    const needed: u64 = @as(u64, @intCast(cwd.len)) + 1; // path + NUL
    if (size < needed) return err(ERANGE);
    if (buf_va == 0 or buf_va > 0xFFFF_FFFF or !common.validateUserPtr(@truncate(buf_va), @as(usize, @intCast(needed)))) return err(EFAULT);
    const out: [*]u8 = @ptrFromInt(@as(usize, @intCast(buf_va)));
    @memcpy(out[0..cwd.len], cwd);
    out[cwd.len] = 0;
    return needed;
}

/// getdents64(fd, buf, count). Enumerates an ext2 directory fd into Linux
/// linux_dirent64 records. fd.offset is the cross-call cursor (entries already
/// returned); listDir always restarts at entry 0, so we skip `offset` of them.
/// `.`/`..`/`lost+found` are filtered by listDir (so this looks like `ls`).
fn sysGetdents64(fd: u32, buf_va: u64, count: u64) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    if (fd >= pcb.fd_table.len or !pcb.fd_table[fd].in_use) return err(EBADF);
    const fe = &pcb.fd_table[fd];
    if (fe.fs_type != .ext2) return err(ENOTDIR);
    const dino = ext2_inode.readInode(fe.inode) orelse return err(EBADF);
    if (!ext2_inode.isDir(&dino)) return err(ENOTDIR);
    if (buf_va > 0xFFFF_FFFF) return err(EFAULT);
    const cap: u32 = if (count > 0xFFFF_F000) 0xFFFF_F000 else @truncate(count);
    if (cap < 32) return err(EINVAL);
    if (!common.validateUserPtr(@truncate(buf_va), cap)) return err(EFAULT);

    // Heap temp (not stack): ext2.listDir already burns 4 KiB of stack for its
    // block buffer, so keep our own footprint off the kstack.
    const MAX_DIR_ENTS: u32 = 256;
    const tmp = heap.kmallocAligned(@as(usize, MAX_DIR_ENTS) * @sizeOf(FileEntry), @alignOf(FileEntry)) orelse return err(ENOMEM);
    defer heap.kfree(tmp);
    const fents: [*]FileEntry = @ptrCast(@alignCast(tmp));
    const total = ext2_fs.listDir(fe.inode, @ptrCast(fents), MAX_DIR_ENTS);

    if (fe.offset >= total) return 0; // all entries already returned (EOF)
    const ubuf: [*]u8 = @ptrFromInt(@as(usize, @intCast(buf_va)));
    var used: u32 = 0;
    var i: u32 = fe.offset;
    while (i < total) : (i += 1) {
        const e = &fents[i];
        const nlen: usize = @min(@as(usize, e.name_len), 32);
        const reclen: u32 = @intCast((19 + nlen + 1 + 7) & ~@as(usize, 7)); // 8-align
        if (used + reclen > cap) break;
        const rec = ubuf + used;
        putU64(rec, @as(u64, i) + 1); // d_ino (synthetic nonzero; FileEntry lacks inum)
        putU64(rec + 8, @as(u64, i) + 1); // d_off (opaque next-cursor cookie)
        putU16(rec + 16, @truncate(reclen)); // d_reclen
        rec[18] = if (e.flags & FE_FLAG_IS_DIR != 0) DT_DIR else DT_REG; // d_type
        var k: usize = 0;
        while (k < nlen) : (k += 1) rec[19 + k] = e.name[k];
        var p: usize = 19 + nlen;
        while (p < reclen) : (p += 1) rec[p] = 0; // NUL terminator + alignment pad
        used += reclen;
    }
    fe.offset = i; // advance cursor past what we emitted
    return used;
}

/// mmap(addr, len, prot, flags, fd, off). M2 implements MAP_ANONYMOUS only
/// (musl's mallocng allocates anonymous), reusing the native grow-down lazy
/// region machinery. File-backed mmap is reported unimplemented for now.
fn sysMmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) u64 {
    _ = addr;
    _ = prot;
    _ = off;
    if (len == 0) return err(EINVAL);
    if (flags & MAP_ANONYMOUS == 0) {
        debug.klog("[linux] mmap non-anon unsupported (flags=0x{X} fd=0x{X})\n", .{ flags, fd });
        return err(ENOSYS);
    }
    const pcb = process.currentPCB() orelse return err(EFAULT);
    _ = pcb.page_directory orelse return err(EFAULT);
    const lead = process.leader(pcb);
    lead.as_lock.acquire();
    defer lead.as_lock.release();
    if (lead.lazy_count >= process.MAX_LAZY_REGIONS) return err(ENOMEM);
    const len_pg: usize = (@as(usize, @intCast(@min(len, 0xFFFF_F000))) + 0xFFF) & ~@as(usize, 0xFFF);
    if (len_pg == 0 or len_pg > lead.mmap_top) return err(ENOMEM);
    const new_top = lead.mmap_top - len_pg;
    if (new_top < lead.user_brk) return err(ENOMEM);
    const lead_pid: u32 = lead.tgid;
    if (!process.addLazyRegion(lead_pid, new_top, lead.mmap_top, 0)) return err(ENOMEM);
    lead.lazy_regions[lead.lazy_count - 1].prot = process.PROT_RW;
    lead.mmap_top = new_top;
    return new_top;
}

/// brk(addr). Minimal: report the current break, never move it. musl (mallocng)
/// allocates via mmap and only probes brk(0); returning the current break for
/// any request makes it fall back to mmap rather than trusting a half-grown
/// heap. (Wire to the sbrk heap region if a brk-based allocator ever appears in
/// the log.)
fn sysBrk(addr: u64) u64 {
    _ = addr;
    const pcb = process.currentPCB() orelse return err(EFAULT);
    return @intCast(process.leader(pcb).user_brk);
}

/// arch_prctl(code, addr). Only ARCH_SET_FS / ARCH_GET_FS are meaningful for
/// us — musl's TLS bring-up sets %fs to its thread-control-block pointer.
/// Mirrors the native sysSetTls: store in PCB.fs_base (so context switches
/// re-apply it) AND write IA32_FS_BASE now so the calling thread sees TLS
/// before it returns to user.
fn sysArchPrctl(code: u64, addr: u64) u64 {
    const pcb = process.currentPCB() orelse return err(EFAULT);
    switch (code) {
        ARCH_SET_FS => {
            pcb.fs_base = addr;
            const lo: u32 = @truncate(addr);
            const hi: u32 = @truncate(addr >> 32);
            asm volatile ("wrmsr"
                :
                : [msr] "{ecx}" (IA32_FS_BASE),
                  [lo] "{eax}" (lo),
                  [hi] "{edx}" (hi),
            );
            return 0;
        },
        ARCH_GET_FS => {
            if (addr > 0xFFFF_FFFF or !common.validateUserPtr(@truncate(addr), 8)) return err(EFAULT);
            const p: *align(1) u64 = @ptrFromInt(@as(usize, @intCast(addr)));
            p.* = pcb.fs_base;
            return 0;
        },
        ARCH_SET_GS, ARCH_GET_GS => return err(EINVAL),
        else => return err(EINVAL),
    }
}
