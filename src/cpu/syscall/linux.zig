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
//!   * M3 — memory management (linux_mm.zig): mmap/munmap/mprotect/madvise/
//!     brk on the region set, anywhere in the 512 GB window; pread/pwrite;
//!     resource limits; clocks and sleeps (linux_time.zig).
//!   * M4 — threads (linux_thread.zig): clone of the pthread shape, futex,
//!     exit vs exit_group; the group shares the lead's fd table and cwd.
//!   * M5 — the file system a compiler's cache needs (linux_fs.zig): names
//!     relative to directory fds, mkdirat/unlinkat/renameat2/faccessat,
//!     statx, ftruncate, flock; here, preadv/pwritev and copy_file_range;
//!     /proc/self/exe, getrandom.
//!
//! The native ABI (3×u32 args, native numbers, return u32) is entirely
//! separate and untouched — the only shared edge is doSyscall's one-line
//! personality check.

const signals = @import("../../proc/signals.zig");
const process = @import("../../proc/process.zig");
const pid_nr = @import("../../proc/pid_nr.zig");
const vfs = @import("../../fs/vfs.zig");
const file = @import("../../fs/file.zig");
const common = @import("common.zig");
const debug = @import("../../debug/debug.zig");
const ext2_inode = @import("../../fs/ext2/inode.zig");
const heap = @import("../../mm/heap.zig");
const memmap = @import("../../mm/memmap.zig");
const config = @import("../../config.zig");
const errno = @import("../../proc/errno.zig");
const random = @import("../../crypto/random.zig");
const smp = @import("../smp.zig");
const linux_mm = @import("linux_mm.zig");
const linux_time = @import("linux_time.zig");
const linux_thread = @import("linux_thread.zig");
const linux_fs = @import("linux_fs.zig");
const linux_proc = @import("linux_proc.zig");
const linux_signal = @import("linux_signal.zig");
const linux_tty = @import("linux_tty.zig");
const linux_net = @import("linux_net.zig");
const linux_event = @import("linux_event.zig");
const native_proc = @import("proc.zig");

// --- Linux x86-64 errno (DISTINCT from zigos common.E_* — different values).
// Returned to userspace as the sign-extended negative, per the kernel ABI.
const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const ESRCH: i64 = 3;
const EBADF: i64 = 9;
const EAGAIN: i64 = 11;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const ENOTDIR: i64 = 20;
const EISDIR: i64 = 21;
const EINVAL: i64 = 22;
const ENOTTY: i64 = 25;
const ETXTBSY: i64 = 26;
const EFBIG: i64 = 27;
const ENOSPC: i64 = 28;
const EPIPE: i64 = 32;
const ERANGE: i64 = 34;
const ESPIPE: i64 = 29;
const ENOSYS: i64 = 38;
const EOVERFLOW: i64 = 75;
const EOPNOTSUPP: i64 = 95;

/// Encode a positive errno as the Linux-ABI return value (sign-extended -errno).
inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

const proc = linux_fs.proc;

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
pub const SYS_rt_sigreturn: u32 = 15;
const SYS_rt_sigpending: u32 = 127;
const SYS_rt_sigtimedwait: u32 = 128;
const SYS_rt_sigsuspend: u32 = 130;
const SYS_pause: u32 = 34;
const SYS_getitimer: u32 = 36;
const SYS_alarm: u32 = 37;
const SYS_setitimer: u32 = 38;
const SYS_ioctl: u32 = 16;
const SYS_pread64: u32 = 17;
const SYS_pwrite64: u32 = 18;
const SYS_readv: u32 = 19;
const SYS_writev: u32 = 20;
const SYS_mremap: u32 = 25;
const SYS_msync: u32 = 26;
const SYS_madvise: u32 = 28;
const SYS_fcntl: u32 = 72;
const SYS_getrlimit: u32 = 97;
const SYS_setrlimit: u32 = 160;
const SYS_prlimit64: u32 = 302;
const SYS_sched_yield: u32 = 24;
const SYS_nanosleep: u32 = 35;
const SYS_restart_syscall: u32 = 219;
const SYS_gettimeofday: u32 = 96;
const SYS_time: u32 = 201;
const SYS_sched_getaffinity: u32 = 204;
const SYS_clock_gettime: u32 = 228;
const SYS_clock_getres: u32 = 229;
const SYS_clock_nanosleep: u32 = 230;
const SYS_clone: u32 = 56;
const SYS_getppid: u32 = 110;
const SYS_setpgid: u32 = 109;
const SYS_getpgrp: u32 = 111;
const SYS_setsid: u32 = 112;
const SYS_getpgid: u32 = 121;
const SYS_getsid: u32 = 124;
const SYS_futex: u32 = 202;
const SYS_membarrier: u32 = 324;
const SYS_access: u32 = 21;
const SYS_flock: u32 = 73;
const SYS_fsync: u32 = 74;
const SYS_fdatasync: u32 = 75;
const SYS_truncate: u32 = 76;
const SYS_ftruncate: u32 = 77;
const SYS_rename: u32 = 82;
const SYS_mkdir: u32 = 83;
const SYS_rmdir: u32 = 84;
const SYS_link: u32 = 86;
const SYS_unlink: u32 = 87;
const SYS_symlink: u32 = 88;
const SYS_readlink: u32 = 89;
const SYS_sigaltstack: u32 = 131;
const SYS_mkdirat: u32 = 258;
const SYS_unlinkat: u32 = 263;
const SYS_renameat: u32 = 264;
const SYS_linkat: u32 = 265;
const SYS_symlinkat: u32 = 266;
const SYS_readlinkat: u32 = 267;
const SYS_faccessat: u32 = 269;
const SYS_preadv: u32 = 295;
const SYS_pwritev: u32 = 296;
const SYS_renameat2: u32 = 316;
const SYS_getrandom: u32 = 318;
const SYS_copy_file_range: u32 = 326;
const SYS_preadv2: u32 = 327;
const SYS_pwritev2: u32 = 328;
const SYS_statx: u32 = 332;
const SYS_setxattr: u32 = 188;
const SYS_lsetxattr: u32 = 189;
const SYS_fsetxattr: u32 = 190;
const SYS_getxattr: u32 = 191;
const SYS_lgetxattr: u32 = 192;
const SYS_fgetxattr: u32 = 193;
const SYS_listxattr: u32 = 194;
const SYS_llistxattr: u32 = 195;
const SYS_flistxattr: u32 = 196;
const SYS_removexattr: u32 = 197;
const SYS_lremovexattr: u32 = 198;
const SYS_fremovexattr: u32 = 199;
const SYS_faccessat2: u32 = 439;
const SYS_poll: u32 = 7;
const SYS_pipe: u32 = 22;
const SYS_dup: u32 = 32;
const SYS_dup2: u32 = 33;
const SYS_fork: u32 = 57;
const SYS_vfork: u32 = 58;
const SYS_execve: u32 = 59;
const SYS_wait4: u32 = 61;
const SYS_kill: u32 = 62;
const SYS_tkill: u32 = 200;
const SYS_tgkill: u32 = 234;
const SYS_sysinfo: u32 = 99;
const SYS_ppoll: u32 = 271;
const SYS_select: u32 = 23;
const SYS_pselect6: u32 = 270;
const SYS_epoll_create: u32 = 213;
const SYS_epoll_wait: u32 = 232;
const SYS_epoll_ctl: u32 = 233;
const SYS_epoll_pwait: u32 = 281;
const SYS_epoll_create1: u32 = 291;
const SYS_epoll_pwait2: u32 = 441;
const SYS_eventfd: u32 = 284;
const SYS_eventfd2: u32 = 290;
const SYS_socket: u32 = 41;
const SYS_connect: u32 = 42;
const SYS_accept: u32 = 43;
const SYS_sendto: u32 = 44;
const SYS_recvfrom: u32 = 45;
const SYS_sendmsg: u32 = 46;
const SYS_recvmsg: u32 = 47;
const SYS_shutdown: u32 = 48;
const SYS_bind: u32 = 49;
const SYS_listen: u32 = 50;
const SYS_getsockname: u32 = 51;
const SYS_getpeername: u32 = 52;
const SYS_socketpair: u32 = 53;
const SYS_setsockopt: u32 = 54;
const SYS_getsockopt: u32 = 55;
const SYS_accept4: u32 = 288;
const SYS_recvmmsg: u32 = 299;
const SYS_sendmmsg: u32 = 307;
const SYS_utimensat: u32 = 280;
const SYS_dup3: u32 = 292;
const SYS_pipe2: u32 = 293;
const SYS_process_vm_readv: u32 = 310;

// fcntl commands (the few musl's open/opendir paths issue).
const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;
const FD_CLOEXEC: u64 = 1;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_APPEND: u64 = 0x400;
const O_NONBLOCK: u64 = 0x800;
const SYS_stat: u32 = 4;
const SYS_lstat: u32 = 6;
const SYS_uname: u32 = 63;
const SYS_getcwd: u32 = 79;
const SYS_chdir: u32 = 80;
const SYS_fchdir: u32 = 81;
const SYS_sendfile: u32 = 40;
const SYS_chmod: u32 = 90;
const SYS_fchmod: u32 = 91;
const SYS_chown: u32 = 92;
const SYS_fchown: u32 = 93;
const SYS_lchown: u32 = 94;
const SYS_umask: u32 = 95;
const SYS_chroot: u32 = 161;
const SYS_getrusage: u32 = 98;
const SYS_times: u32 = 100;
const SYS_setreuid: u32 = 113;
const SYS_setregid: u32 = 114;
const SYS_getgroups: u32 = 115;
const SYS_setgroups: u32 = 116;
const SYS_setresuid: u32 = 117;
const SYS_getresuid: u32 = 118;
const SYS_setresgid: u32 = 119;
const SYS_getresgid: u32 = 120;
const SYS_setfsuid: u32 = 122;
const SYS_setfsgid: u32 = 123;
const SYS_statfs: u32 = 137;
const SYS_fstatfs: u32 = 138;
const SYS_getpriority: u32 = 140;
const SYS_setpriority: u32 = 141;
const SYS_prctl: u32 = 157;
const SYS_sync: u32 = 162;
const SYS_sched_setaffinity: u32 = 203;
const SYS_fadvise64: u32 = 221;
const SYS_fchownat: u32 = 260;
const SYS_fchmodat: u32 = 268;
const SYS_syncfs: u32 = 306;
const SYS_fchmodat2: u32 = 452;
const SYS_getuid: u32 = 102;
const SYS_getgid: u32 = 104;
const SYS_setuid: u32 = 105;
const SYS_setgid: u32 = 106;
const SYS_geteuid: u32 = 107;
const SYS_getegid: u32 = 108;
const AT_FDCWD = linux_fs.AT_FDCWD;
const SYS_getpid: u32 = 39;
const SYS_gettid: u32 = 186;
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

/// Linux iovec: { void *iov_base; size_t iov_len; } — 16 bytes, native order.
const Iovec = extern struct { base: u64, len: u64 };

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
        SYS_lseek => return sysLseek(@truncate(a1), a2, @truncate(a3)),
        SYS_pread64 => return sysPread(@truncate(a1), a2, a3, a4),
        SYS_pwrite64 => return sysPwrite(@truncate(a1), a2, a3, a4),
        SYS_preadv => return sysPreadv(@truncate(a1), a2, a3, a4),
        SYS_pwritev => return sysPwritev(@truncate(a1), a2, a3, a4),
        // preadv2/pwritev2(fd, iov, iovcnt, pos, pos_high, flags): the whole
        // offset is in pos on 64-bit; -1 is the fd's own. No RWF_* flags.
        SYS_preadv2, SYS_pwritev2 => {
            if (a6 != 0) return err(EOPNOTSUPP);
            const at_fd_offset = a4 == ~@as(u64, 0);
            if (num == SYS_preadv2) {
                return if (at_fd_offset) sysReadv(@truncate(a1), a2, a3) else sysPreadv(@truncate(a1), a2, a3, a4);
            }
            return if (at_fd_offset) sysWritev(@truncate(a1), a2, a3) else sysPwritev(@truncate(a1), a2, a3, a4);
        },
        SYS_copy_file_range => return sysCopyFileRange(a1, a2, a3, a4, a5, a6),
        SYS_sendfile => return sysSendfile(a1, a2, a3, a4),
        // Names, metadata and the tree (linux_fs.zig). The pre-*at calls are
        // their *at forms at the cwd.
        SYS_open => return linux_fs.openat(AT_FDCWD, a1, a2, a3),
        SYS_openat => return linux_fs.openat(a1, a2, a3, a4),
        SYS_close => return linux_fs.close(a1),
        SYS_fstat => return linux_fs.fstat(a1, a2),
        SYS_stat => return linux_fs.newfstatat(AT_FDCWD, a1, a2, 0),
        SYS_lstat => return linux_fs.newfstatat(AT_FDCWD, a1, a2, linux_fs.AT_SYMLINK_NOFOLLOW),
        SYS_newfstatat => return linux_fs.newfstatat(a1, a2, a3, a4),
        SYS_statx => return linux_fs.statx(a1, a2, a3, a4, a5),
        SYS_getdents64 => return linux_fs.getdents64(a1, a2, a3),
        SYS_mkdir => return linux_fs.mkdirat(AT_FDCWD, a1, a2),
        SYS_mkdirat => return linux_fs.mkdirat(a1, a2, a3),
        SYS_unlink => return linux_fs.unlinkat(AT_FDCWD, a1, 0),
        SYS_rmdir => return linux_fs.unlinkat(AT_FDCWD, a1, linux_fs.AT_REMOVEDIR),
        SYS_unlinkat => return linux_fs.unlinkat(a1, a2, a3),
        SYS_rename => return linux_fs.renameat2(AT_FDCWD, a1, AT_FDCWD, a2, 0),
        SYS_renameat => return linux_fs.renameat2(a1, a2, a3, a4, 0),
        SYS_renameat2 => return linux_fs.renameat2(a1, a2, a3, a4, a5),
        SYS_access => return linux_fs.faccessat(AT_FDCWD, a1),
        SYS_faccessat, SYS_faccessat2 => return linux_fs.faccessat(a1, a2),
        SYS_readlink => return linux_fs.readlinkat(AT_FDCWD, a1, a2, a3),
        SYS_readlinkat => return linux_fs.readlinkat(a1, a2, a3, a4),
        SYS_symlink => return linux_fs.symlinkat(a1, AT_FDCWD, a2),
        SYS_symlinkat => return linux_fs.symlinkat(a1, a2, a3),
        SYS_link => return linux_fs.linkat(AT_FDCWD, a1, AT_FDCWD, a2, 0),
        SYS_linkat => return linux_fs.linkat(a1, a2, a3, a4, a5),
        SYS_truncate => return linux_fs.truncate(a1, a2),
        SYS_ftruncate => return linux_fs.ftruncate(a1, a2),
        SYS_flock => return linux_fs.flock(a1, a2),
        SYS_setxattr => return linux_fs.xattrPath(a1, .follow, .set),
        SYS_lsetxattr => return linux_fs.xattrPath(a1, .nofollow, .set),
        SYS_fsetxattr => return linux_fs.xattrFd(a1, .set),
        SYS_getxattr => return linux_fs.xattrPath(a1, .follow, .get),
        SYS_lgetxattr => return linux_fs.xattrPath(a1, .nofollow, .get),
        SYS_fgetxattr => return linux_fs.xattrFd(a1, .get),
        SYS_listxattr => return linux_fs.xattrPath(a1, .follow, .list),
        SYS_llistxattr => return linux_fs.xattrPath(a1, .nofollow, .list),
        SYS_flistxattr => return linux_fs.xattrFd(a1, .list),
        SYS_removexattr => return linux_fs.xattrPath(a1, .follow, .remove),
        SYS_lremovexattr => return linux_fs.xattrPath(a1, .nofollow, .remove),
        SYS_fremovexattr => return linux_fs.xattrFd(a1, .remove),
        SYS_fsync, SYS_fdatasync => return linux_fs.fsync(a1),
        SYS_getrandom => return sysGetrandom(a1, a2, a3),
        SYS_sigaltstack => return linux_signal.sigaltstack(a1, a2, frame.user_rsp),
        SYS_mmap => return linux_mm.mmap(a1, a2, a3, a4, a5, a6),
        SYS_munmap => return linux_mm.munmap(a1, a2),
        SYS_mprotect => return linux_mm.mprotect(a1, a2, a3),
        SYS_madvise => return linux_mm.madvise(a1, a2, a3),
        SYS_msync => return linux_mm.msync(a1, a2, a3),
        SYS_brk => return linux_mm.brk(a1),
        SYS_mremap => return linux_mm.mremap(),
        SYS_getrlimit => return sysPrlimit(0, a1, 0, a2),
        SYS_setrlimit => return sysPrlimit(0, a1, a2, 0),
        SYS_prlimit64 => return sysPrlimit(a1, a2, a3, a4),
        SYS_clock_gettime => return linux_time.clockGettime(a1, a2),
        SYS_clock_getres => return linux_time.clockGetres(a1, a2),
        SYS_gettimeofday => return linux_time.gettimeofday(a1, a2),
        SYS_time => return linux_time.timeNow(a1),
        SYS_nanosleep => return linux_time.nanosleep(a1, a2),
        SYS_restart_syscall => return linux_time.restartSyscall(),
        SYS_clock_nanosleep => return linux_time.clockNanosleep(a1, a2, a3, a4),
        SYS_sched_yield => return native_proc.sysYield(),
        SYS_sched_getaffinity => return sysSchedGetaffinity(a1, a2, a3),
        // A terminal's calls, ENOTTY for the rest (linux_tty.zig): isatty,
        // and musl's first stdio write, ask TIOCGWINSZ to tell.
        SYS_ioctl => return linux_tty.ioctl(a1, a2, a3),
        // TLS bring-up: musl's __init_tp does arch_prctl(ARCH_SET_FS, tcb).
        SYS_arch_prctl => return sysArchPrctl(a1, a2),
        SYS_clone => return linux_thread.clone(frame, a1, a2, a3, a4, a5),
        // Processes and pipes (linux_proc.zig). vfork is a fork: the parent
        // runs on, which a correct vfork child can't tell.
        SYS_fork, SYS_vfork => return linux_proc.fork(frame),
        SYS_execve => return linux_proc.execve(frame, a1, a2, a3),
        SYS_wait4 => return linux_proc.wait4(a1, a2, a3, a4),
        SYS_kill => return linux_proc.kill(a1, a2),
        SYS_tkill => return linux_proc.tkill(a1, a2),
        SYS_tgkill => return linux_proc.tgkill(a1, a2, a3),
        SYS_pipe => return linux_proc.pipe2(a1, 0),
        SYS_pipe2 => return linux_proc.pipe2(a1, a2),
        SYS_dup => return linux_proc.dup(a1),
        SYS_dup2 => return linux_proc.dup2(a1, a2),
        SYS_dup3 => return linux_proc.dup3(a1, a2, a3),
        SYS_poll => return linux_proc.poll(a1, a2, a3),
        SYS_ppoll => return linux_proc.ppoll(a1, a2, a3, a4, a5),
        // The other ways to wait on many files (linux_event.zig).
        SYS_select => return linux_event.select(a1, a2, a3, a4, a5),
        SYS_pselect6 => return linux_event.pselect6(a1, a2, a3, a4, a5, a6),
        SYS_epoll_create => return if (@as(i32, @bitCast(@as(u32, @truncate(a1)))) <= 0) err(EINVAL) else linux_event.epollCreate(0),
        SYS_epoll_create1 => return linux_event.epollCreate(a1),
        SYS_epoll_ctl => return linux_event.epollCtl(a1, a2, a3, a4),
        SYS_epoll_wait => return linux_event.epollPwait(a1, a2, a3, a4, 0, 0),
        SYS_epoll_pwait => return linux_event.epollPwait(a1, a2, a3, a4, a5, a6),
        SYS_epoll_pwait2 => return linux_event.epollPwait2(a1, a2, a3, a4, a5, a6),
        SYS_eventfd => return linux_event.eventfd2(a1, 0),
        SYS_eventfd2 => return linux_event.eventfd2(a1, a2),
        // Sockets (linux_net.zig).
        SYS_socket => return linux_net.sysSocket(a1, a2, a3),
        SYS_socketpair => return linux_net.sysSocketpair(a1, a2, a3, a4),
        SYS_bind => return linux_net.sysBind(a1, a2, a3),
        SYS_connect => return linux_net.sysConnect(a1, a2, a3),
        SYS_listen => return linux_net.sysListen(a1),
        SYS_accept => return linux_net.sysAccept4(a1, a2, a3, 0),
        SYS_accept4 => return linux_net.sysAccept4(a1, a2, a3, a4),
        SYS_getsockname => return linux_net.sysGetsockname(a1, a2, a3),
        SYS_getpeername => return linux_net.sysGetpeername(a1, a2, a3),
        SYS_shutdown => return linux_net.sysShutdown(a1, a2),
        SYS_sendto => return linux_net.sysSendto(a1, a2, a3, a4, a5, a6),
        SYS_recvfrom => return linux_net.sysRecvfrom(a1, a2, a3, a4, a5, a6),
        SYS_sendmsg => return linux_net.sysSendmsg(a1, a2, a3),
        SYS_recvmsg => return linux_net.sysRecvmsg(a1, a2, a3),
        SYS_sendmmsg => return linux_net.sysSendmmsg(a1, a2, a3, a4),
        SYS_recvmmsg => return linux_net.sysRecvmmsg(a1, a2, a3, a4),
        SYS_setsockopt => return linux_net.sysSetsockopt(a1, a2, a3, a4, a5),
        SYS_getsockopt => return linux_net.sysGetsockopt(a1, a2, a3, a4, a5),
        SYS_process_vm_readv => return linux_proc.processVmReadv(a1, a2, a3, a4, a5, a6),
        SYS_sysinfo => return linux_proc.sysinfo(a1),
        SYS_utimensat => return linux_fs.utimensat(a1, a2, a3, a4),
        // Permission bits are kept (not enforced); owners are not: chown
        // takes anything a file that is there is given.
        SYS_chmod => return linux_fs.chmodAt(AT_FDCWD, a1, a2),
        SYS_fchmodat, SYS_fchmodat2 => return linux_fs.chmodAt(a1, a2, a3),
        SYS_fchmod => return linux_fs.fchmod(a1, a2),
        SYS_chown => return linux_fs.setAttr(AT_FDCWD, a1, false),
        SYS_lchown => return linux_fs.setAttr(AT_FDCWD, a1, true),
        SYS_fchownat => return linux_fs.setAttr(a1, a2, a5 & linux_fs.AT_SYMLINK_NOFOLLOW != 0),
        SYS_fchown => return linux_fs.setAttrFd(a1),
        SYS_chroot => return linux_fs.chroot(a1),
        SYS_umask => {
            const p = proc() orelse return err(EFAULT);
            const old = p.umask;
            p.umask = @truncate(a1 & 0o777);
            return old;
        },
        SYS_statfs => return linux_fs.statfs(a1, a2),
        SYS_fstatfs => return linux_fs.fstatfs(a1, a2),
        SYS_sync, SYS_syncfs => return linux_fs.sync(),
        SYS_fadvise64 => return 0,
        SYS_times => return linux_proc.times(a1),
        SYS_getrusage => return linux_proc.getrusage(a2),
        SYS_prctl => return linux_proc.prctl(a1, a2),
        SYS_getpriority => return 20, // nice 0, as the call encodes it
        SYS_setpriority, SYS_sched_setaffinity => return 0,
        SYS_futex => return linux_thread.futex(a1, a2, a3, a4, a5, a6),
        SYS_set_tid_address => return linux_thread.setTidAddress(a1),
        // Pids are numbers (pid_nr.zig), not slots. A thread's tid is its
        // own; the process id is the group lead's.
        SYS_getpid => return (proc() orelse return err(EFAULT)).pid_nr,
        SYS_gettid => return (process.currentPCB() orelse return err(EFAULT)).pid_nr,
        SYS_getppid => return pid_nr.of((proc() orelse return err(EFAULT)).parent_pid),
        SYS_getpgrp => return linux_proc.getpgid(0),
        SYS_getpgid => return linux_proc.getpgid(a1),
        SYS_setpgid => return linux_proc.setpgid(a1, a2),
        SYS_getsid => return linux_proc.getsid(a1),
        SYS_setsid => return linux_proc.setsid(),
        // musl registers at its first pthread_create and does without.
        SYS_membarrier => return err(ENOSYS),
        // Signals (linux_signal.zig). rt_sigreturn is taken before the
        // dispatch (doSyscall): it returns through a frame of its own.
        SYS_rt_sigaction => return linux_signal.rtSigaction(a1, a2, a3, a4),
        SYS_rt_sigprocmask => return linux_signal.rtSigprocmask(a1, a2, a3, a4),
        SYS_rt_sigpending => return linux_signal.rtSigpending(a1, a2),
        SYS_rt_sigsuspend => return linux_signal.rtSigsuspend(a1, a2),
        SYS_rt_sigtimedwait => return linux_signal.rtSigtimedwait(a1, a2, a3, a4),
        SYS_pause => return linux_signal.pause(),
        SYS_alarm => return linux_signal.alarm(a1),
        SYS_setitimer => return linux_signal.setitimer(a1, a2, a3),
        SYS_getitimer => return linux_signal.getitimer(a1, a2),
        SYS_set_robust_list => return 0,
        SYS_uname => return sysUname(a1),
        SYS_getcwd => return sysGetcwd(a1, a2),
        SYS_chdir => return linux_fs.chdir(a1),
        SYS_fchdir => return linux_fs.fchdir(a1),
        // Single-user system: everything runs as root (uid/gid 0). setuid/setgid
        // to any id "succeeds" as a no-op (we are already privileged).
        SYS_getuid, SYS_geteuid, SYS_getgid, SYS_getegid => return 0,
        SYS_setuid, SYS_setgid, SYS_setreuid, SYS_setregid, SYS_setresuid, SYS_setresgid => return 0,
        SYS_setfsuid, SYS_setfsgid, SYS_getgroups, SYS_setgroups => return 0,
        SYS_getresuid, SYS_getresgid => return linux_proc.getresid(a1, a2, a3),
        SYS_exit => return linux_thread.exitThread(a1),
        SYS_exit_group => return linux_thread.exitGroup(a1),
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

/// Most bytes one read or write moves, as Linux's MAX_RW_COUNT; vfs counts
/// in u32.
const MAX_RW: u64 = 0x7FFF_F000;

inline fn rwLen(count: u64) u32 {
    return @intCast(@min(count, MAX_RW));
}

/// Most bytes one read from anything but an ext2 file asks for. Validating
/// the buffer maps every page of it, so a read sized to a huge lazy reserve
/// would commit all of it; pipes, consoles and sockets return short anyway.
const MAX_STREAM_READ: u32 = 1 << 20;

/// What a read of `count` bytes from `fd` can return at most: what is left
/// of an ext2 file, MAX_STREAM_READ from anything else.
fn readLen(pcb: *process.PCB, fd: u32, count: u64) u32 {
    const len = rwLen(count);
    const fe = file.get(pcb, fd) orelse return len;
    defer file.put(fe);
    if (fe.kind != .ext2) return @min(len, MAX_STREAM_READ);
    const size = fdFileSize(fe);
    const at = fe.offset;
    if (at >= size) return 0;
    return @intCast(@min(len, size - at));
}

/// A vfs read or write result as a Linux return: the count, or -errno for
/// the codes vfs packs into the top of u32 (all ones, VFS_ERR, is a bad fd
/// or an fd that can't do this).
fn vfsResult(n: u32) u64 {
    if (n < errno.ERR_SENTINEL_BASE) return n;
    return err(switch (n) {
        @intFromEnum(errno.Errno.ETXTBSY) => ETXTBSY,
        @intFromEnum(errno.Errno.ENOSPC) => ENOSPC,
        @intFromEnum(errno.Errno.EAGAIN) => EAGAIN,
        // A read or write a signal cut short before a byte moved.
        @intFromEnum(errno.Errno.EINTR) => linux_signal.ERESTARTSYS,
        // A write with nobody left to read it: SIGPIPE for the writer, and
        // EPIPE if that doesn't end it.
        @intFromEnum(errno.Errno.EPIPE) => blk: {
            if (process.currentPCB()) |me| {
                _ = signals.sendInfo(@intCast(process.getCurrentPid()), signals.SIGPIPE, .{
                    .code = signals.SI_USER_CODE,
                    .pid = process.leader(me).pid_nr,
                });
            }
            break :blk EPIPE;
        },
        @intFromEnum(errno.Errno.EFAULT) => EFAULT,
        @intFromEnum(errno.Errno.ENOMEM) => ENOMEM,
        @intFromEnum(errno.Errno.EISDIR) => EISDIR,
        @intFromEnum(errno.Errno.EACCES) => 13,
        // A background read SIGTTIN can't stop.
        @intFromEnum(errno.Errno.EIO) => 5,
        // What a socket's read and write end with.
        @intFromEnum(errno.Errno.ENOTCONN) => 107,
        @intFromEnum(errno.Errno.ECONNREFUSED) => 111,
        @intFromEnum(errno.Errno.ECONNRESET) => 104,
        @intFromEnum(errno.Errno.ETIMEDOUT) => 110,
        @intFromEnum(errno.Errno.EHOSTUNREACH) => 113,
        @intFromEnum(errno.Errno.EMSGSIZE) => 90,
        @intFromEnum(errno.Errno.EDESTADDRREQ) => 89,
        @intFromEnum(errno.Errno.EOPNOTSUPP) => EOPNOTSUPP,
        else => EBADF,
    });
}

/// vfsResult for a read or write of `fd`. The all-ones code is a bad
/// descriptor or a file that can't do this (EBADF) from the files of the
/// file systems, and a bad argument from an object that judges its own.
fn ioResult(pcb: *process.PCB, fd: u32, n: u32) u64 {
    if (n != @intFromEnum(errno.Errno.EINVAL)) return vfsResult(n);
    const fe = file.get(pcb, fd) orelse return err(EBADF);
    defer file.put(fe);
    return err(switch (fe.kind) {
        .socket, .eventfd, .epoll => EINVAL,
        else => EBADF,
    });
}

/// Linux read of an ext2 directory fd is -EISDIR.
fn isDirFd(pcb: *process.PCB, fd: u32) bool {
    const fe = file.get(pcb, fd) orelse return false;
    defer file.put(fe);
    if (fe.kind != .ext2) return false;
    const ino = ext2_inode.readInode(fe.inode) orelse return false;
    return ext2_inode.isDir(&ino);
}

/// write(fd, buf, count). Delegates to the same vfs.write the native path
/// uses. Returns the byte count on success; a faulting buffer is -EFAULT.
fn sysWrite(fd: u32, buf_va: u64, count: u64) u64 {
    if (count == 0) return 0;
    const len = rwLen(count);
    if (!common.validateUserPtr(buf_va, len)) return err(EFAULT);
    const pcb = proc() orelse return err(EFAULT);
    const buf: [*]const u8 = @ptrFromInt(buf_va);
    if (fd <= 2 and len <= 1024) debug.klog("[linux] write(fd={d}): {s}", .{ fd, buf[0..len] });
    return ioResult(pcb, fd, vfs.write(pcb, fd, buf, len));
}

/// read(fd, buf, count). Delegates to vfs.read, which returns 0 at EOF.
fn sysRead(fd: u32, buf_va: u64, count: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    if (isDirFd(pcb, fd)) return err(EISDIR);
    const len = readLen(pcb, fd, count);
    if (len == 0) return 0;
    if (!common.validateUserPtrWrite(buf_va, len)) return err(EFAULT);
    return ioResult(pcb, fd, vfs.read(pcb, fd, @ptrFromInt(buf_va), len));
}

/// writev(fd, iov, iovcnt). musl's stdio writes everything through writev (the
/// FILE buffer + the new bytes as two iovecs), so this is the real output path
/// for printf. Walks the iovec array, writing each segment via vfs.write, and
/// returns the total bytes written (or -EFAULT / -EBADF).
fn sysWritev(fd: u32, iov_va: u64, iovcnt: u64) u64 {
    if (iovcnt == 0) return 0;
    if (iovcnt > 1024) return err(EINVAL); // sane cap; UIO_MAXIOV is 1024
    const n: usize = @intCast(iovcnt);
    const array_bytes = n * @sizeOf(Iovec);
    if (!common.validateUserPtr(iov_va, array_bytes)) return err(EFAULT);
    const pcb = proc() orelse return err(EFAULT);
    const iov: [*]align(1) const Iovec = @ptrFromInt(iov_va);

    var total: u64 = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const base = iov[i].base;
        const seg = iov[i].len;
        if (seg == 0) continue;
        const l = rwLen(seg);
        if (!common.validateUserPtr(base, l)) {
            if (total > 0) return total;
            return err(EFAULT);
        }
        const buf: [*]const u8 = @ptrFromInt(base);
        if (fd <= 2 and l <= 1024) debug.klog("[linux] writev(fd={d}): {s}", .{ fd, buf[0..l] });
        const w = vfs.write(pcb, fd, buf, l);
        if (w >= errno.ERR_SENTINEL_BASE) {
            if (total > 0) return total;
            return ioResult(pcb, fd, w);
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
    const n: usize = @intCast(iovcnt);
    const array_bytes = n * @sizeOf(Iovec);
    if (!common.validateUserPtr(iov_va, array_bytes)) return err(EFAULT);
    const pcb = proc() orelse return err(EFAULT);
    if (isDirFd(pcb, fd)) return err(EISDIR);
    const iov: [*]align(1) const Iovec = @ptrFromInt(iov_va);
    // readLen over the whole call; the segments draw on it in turn.
    var budget = readLen(pcb, fd, MAX_RW);
    var total: u64 = 0;
    var i: usize = 0;
    while (i < n and budget > 0) : (i += 1) {
        const base = iov[i].base;
        const seg = iov[i].len;
        if (seg == 0) continue;
        const l = @min(rwLen(seg), budget);
        if (!common.validateUserPtrWrite(base, l)) {
            if (total > 0) return total;
            return err(EFAULT);
        }
        const r = vfs.read(pcb, fd, @ptrFromInt(base), l);
        if (r >= errno.ERR_SENTINEL_BASE) {
            if (total > 0) return total;
            return ioResult(pcb, fd, r);
        }
        total += r;
        budget -= r;
        if (r < l) break; // short read / EOF — stop
    }
    return total;
}

/// fcntl(fd, cmd, arg): dups, the descriptor's and the file's flags, record
/// locks (linux_fs.fcntlLock). Another command is logged and gets ENOSYS.
fn sysFcntl(fd: u32, cmd: u64, arg: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const fe = file.get(pcb, fd) orelse return err(EBADF);
    defer file.put(fe);
    // The descriptor's own flag; the status flags below are the file's,
    // shared with every dup of it.
    const slot = &pcb.fd_table[fd];
    return switch (cmd) {
        F_DUPFD => linux_proc.dupFrom(fd, arg, false),
        F_DUPFD_CLOEXEC => linux_proc.dupFrom(fd, arg, true),
        F_GETFD => @intFromBool(slot.cloexec),
        F_SETFD => blk: {
            slot.cloexec = arg & FD_CLOEXEC != 0;
            break :blk 0;
        },
        F_GETFL => @as(u64, switch (fe.access) {
            file.READ => O_RDONLY,
            file.WRITE => O_WRONLY,
            else => O_RDWR,
        }) |
            @as(u64, if (fe.nonblock) O_NONBLOCK else 0) |
            @as(u64, if (fe.append) O_APPEND else 0),
        F_SETFL => blk: {
            fe.nonblock = arg & O_NONBLOCK != 0;
            fe.append = arg & O_APPEND != 0;
            break :blk 0;
        },
        linux_fs.F_GETLK, linux_fs.F_SETLK, linux_fs.F_SETLKW, linux_fs.F_OFD_GETLK, linux_fs.F_OFD_SETLK, linux_fs.F_OFD_SETLKW => linux_fs.fcntlLock(pcb, fd, fe, cmd, arg),
        else => blk: {
            debug.klog("[linux] pid={d} unimpl fcntl cmd {d} (fd={d} arg=0x{X})\n", .{ process.getCurrentPid(), cmd, fd, arg });
            break :blk err(ENOSYS);
        },
    };
}

/// File size behind an fd (ext2 only; 0 otherwise) — for lseek SEEK_END.
fn fdFileSize(fe: *const file.File) u64 {
    if (fe.kind != .ext2) return 0;
    const ino = ext2_inode.readInode(fe.inode) orelse return 0;
    return ext2_inode.fileSize(&ino);
}

/// lseek(fd, off, whence): SEEK_SET/CUR/END on the file's offset, which
/// every descriptor on the file shares.
fn sysLseek(fd: u32, off: u64, whence: u32) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const fe = file.get(pcb, fd) orelse return err(EBADF);
    defer file.put(fe);
    switch (fe.kind) {
        .console, .pipe, .tcp_sock, .tcp_listener, .socket, .epoll, .eventfd, .tty => return err(ESPIPE),
        else => {},
    }
    const new: u64 = switch (whence) {
        0 => off, // SEEK_SET
        1 => fe.offset +% off, // SEEK_CUR
        2 => fdFileSize(fe) +% off, // SEEK_END
        else => return err(EINVAL),
    };
    if (@as(i64, @bitCast(new)) < 0) return err(EINVAL);
    fe.offset = new;
    return new;
}

/// uname(2): fill `struct utsname` — six 65-byte char fields (sysname,
/// nodename, release, version, machine, domainname). We report a Linux identity
/// (so `uname -s` reads "Linux", which is what a Linux binary expects) with a
/// zigos flavor in the node/release/version fields.
const UTS_LEN: usize = 65;
const UTSNAME_SIZE: usize = 6 * UTS_LEN; // 390 bytes

fn sysUname(buf_va: u64) u64 {
    if (buf_va == 0 or !common.validateUserPtrWrite(buf_va, UTSNAME_SIZE)) return err(EFAULT);
    const buf: []u8 = @as([*]u8, @ptrFromInt(buf_va))[0..UTSNAME_SIZE];
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
    const pcb = proc() orelse return err(EFAULT);
    // The cwd is kept with a slash at its end; Linux names it without one.
    var cwd: []const u8 = pcb.cwd[0..pcb.cwd_len];
    if (cwd.len > 1 and cwd[cwd.len - 1] == '/') cwd = cwd[0 .. cwd.len - 1];
    const needed: u64 = @as(u64, @intCast(cwd.len)) + 1; // path + NUL
    if (size < needed) return err(ERANGE);
    if (buf_va == 0 or !common.validateUserPtrWrite(buf_va, needed)) return err(EFAULT);
    const out: [*]u8 = @ptrFromInt(buf_va);
    @memcpy(out[0..cwd.len], cwd);
    out[cwd.len] = 0;
    return needed;
}

/// The ext2 file behind `fd` for a positioned read or write, with a
/// reference the caller puts back: -EBADF for a closed fd, -ESPIPE for
/// anything without a byte offset of its own.
fn positionedFile(pcb: *process.PCB, fd: u32, off: u64) union(enum) { file: *file.File, fail: u64 } {
    const fe = file.get(pcb, fd) orelse return .{ .fail = err(EBADF) };
    const why: i64 = if (@as(i64, @bitCast(off)) < 0) EINVAL else if (fe.kind != .ext2) ESPIPE else return .{ .file = fe };
    file.put(fe);
    return .{ .fail = err(why) };
}

/// pread64(fd, buf, count, off): read at `off`; the fd offset stays put.
fn sysPread(fd: u32, buf_va: u64, count: u64, off: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const fe = switch (positionedFile(pcb, fd, off)) {
        .file => |f| f,
        .fail => |e| return e,
    };
    defer file.put(fe);
    if (isDirFd(pcb, fd)) return err(EISDIR);
    if (!fe.readable()) return err(EBADF);
    const size = fdFileSize(fe);
    if (off >= size) return 0;
    const len: u32 = @intCast(@min(rwLen(count), size - off));
    if (len == 0) return 0;
    if (!common.validateUserPtrWrite(buf_va, len)) return err(EFAULT);
    return vfs.readThroughCache(fe.inode, off, @ptrFromInt(buf_va), len);
}

/// pwrite64(fd, buf, count, off): write at `off`; the fd offset stays put.
fn sysPwrite(fd: u32, buf_va: u64, count: u64, off: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const fe = switch (positionedFile(pcb, fd, off)) {
        .file => |f| f,
        .fail => |e| return e,
    };
    defer file.put(fe);
    if (!fe.writable()) return err(EBADF);
    if (count == 0) return 0;
    const len = rwLen(count);
    if (!common.validateUserPtr(buf_va, len)) return err(EFAULT);
    if (off +| len > MAX_FILE) return err(EFBIG);
    return vfsResult(vfs.writeAt(fe.inode, off, @ptrFromInt(buf_va), len));
}

/// Largest file the positioned writes grow: ext2 LARGE_FILE's 2^48 bytes.
const MAX_FILE: u64 = 1 << 48;

/// The `iovcnt` iovecs at `iov_va`, or the errno for a bad vector.
fn iovecs(iov_va: u64, iovcnt: u64) union(enum) { iov: []align(1) const Iovec, fail: u64 } {
    if (iovcnt > 1024) return .{ .fail = err(EINVAL) }; // UIO_MAXIOV
    const n: usize = @intCast(iovcnt);
    if (n == 0) return .{ .iov = &.{} };
    if (!common.validateUserPtr(iov_va, n * @sizeOf(Iovec))) return .{ .fail = err(EFAULT) };
    return .{ .iov = @as([*]align(1) const Iovec, @ptrFromInt(iov_va))[0..n] };
}

/// preadv(fd, iov, iovcnt, off): the iovecs in turn from `off`, stopping at
/// a short read; the fd offset stays put.
fn sysPreadv(fd: u32, iov_va: u64, iovcnt: u64, off: u64) u64 {
    const iov = switch (iovecs(iov_va, iovcnt)) {
        .iov => |v| v,
        .fail => |e| return e,
    };
    var total: u64 = 0;
    for (iov) |v| {
        if (v.len == 0) continue;
        const r = sysPread(fd, v.base, v.len, off +% total);
        if (@as(i64, @bitCast(r)) < 0) return if (total > 0) total else r;
        total += r;
        if (r < v.len) break;
    }
    return total;
}

/// pwritev(fd, iov, iovcnt, off): the iovecs in turn from `off`; the fd
/// offset stays put.
fn sysPwritev(fd: u32, iov_va: u64, iovcnt: u64, off: u64) u64 {
    const iov = switch (iovecs(iov_va, iovcnt)) {
        .iov => |v| v,
        .fail => |e| return e,
    };
    var total: u64 = 0;
    for (iov) |v| {
        if (v.len == 0) continue;
        const r = sysPwrite(fd, v.base, v.len, off +% total);
        if (@as(i64, @bitCast(r)) < 0) return if (total > 0) total else r;
        total += r;
        if (r < v.len) break;
    }
    return total;
}

/// Most bytes one copy_file_range moves; callers loop on a short count.
const MAX_COPY: u64 = 1 << 20;

/// The offset a copy_file_range side starts at: `*off_va` when given (it
/// gets the end offset back), else the fd's own.
fn copyOffset(fe: *const file.File, off_va: u64) ?u64 {
    if (off_va == 0) return fe.offset;
    if (!common.validateUserPtrWriteAligned(off_va, 8, 8)) return null;
    const off = @as(*const i64, @ptrFromInt(off_va)).*;
    if (off < 0) return null;
    return @intCast(off);
}

/// copy_file_range(fd_in, off_in, fd_out, off_out, len, flags) between ext2
/// files, through a kernel page. A null offset pointer means the fd's own
/// offset, which advances; a given one is updated instead.
fn sysCopyFileRange(fd_in: u64, off_in_va: u64, fd_out: u64, off_out_va: u64, len: u64, flags: u64) u64 {
    if (flags != 0) return err(EINVAL);
    const pcb = proc() orelse return err(EFAULT);
    const in_fe = file.get(pcb, fd_in) orelse return err(EBADF);
    defer file.put(in_fe);
    const out_fe = file.get(pcb, fd_out) orelse return err(EBADF);
    defer file.put(out_fe);
    if (!in_fe.readable() or !out_fe.writable() or out_fe.append) return err(EBADF);
    if (in_fe.kind != .ext2 or out_fe.kind != .ext2) return err(EINVAL);
    if (isDirFd(pcb, @intCast(fd_in)) or isDirFd(pcb, @intCast(fd_out))) return err(EISDIR);
    var in_off = copyOffset(in_fe, off_in_va) orelse return err(EFAULT);
    var out_off = copyOffset(out_fe, off_out_va) orelse return err(EFAULT);
    const size = fdFileSize(in_fe);
    const want = @min(len, MAX_COPY, size -| in_off);
    if (want == 0) return 0;
    if (in_fe.inode == out_fe.inode and in_off < out_off + want and out_off < in_off + want) return err(EINVAL);
    if (out_off +| want > MAX_FILE) return err(EFBIG);
    const buf = heap.kmallocAligned(4096, 4096) orelse return err(ENOMEM);
    defer heap.kfree(buf);
    var done: u64 = 0;
    while (done < want) {
        const chunk: u32 = @intCast(@min(want - done, 4096));
        const got = vfs.readThroughCache(in_fe.inode, in_off, buf, chunk);
        if (got == 0) break;
        const put = vfs.writeAt(out_fe.inode, out_off, buf, got);
        if (put >= errno.ERR_SENTINEL_BASE) {
            if (done > 0) break;
            return vfsResult(put);
        }
        done += put;
        in_off += put;
        out_off += put;
        if (put < got) break;
    }
    if (off_in_va != 0) @as(*u64, @ptrFromInt(off_in_va)).* = in_off else in_fe.offset = in_off;
    if (off_out_va != 0) @as(*u64, @ptrFromInt(off_out_va)).* = out_off else out_fe.offset = out_off;
    return done;
}

/// sendfile(out_fd, in_fd, offset, count): bytes of an ext2 file to anything
/// that can be written, through a kernel page. A null `offset` reads at the
/// input's own offset, which moves; a given one is read from and updated,
/// and the input's own stays.
fn sysSendfile(out_fd: u64, in_fd: u64, off_va: u64, count: u64) u64 {
    const pcb = proc() orelse return err(EFAULT);
    const in_fe = file.get(pcb, in_fd) orelse return err(EBADF);
    defer file.put(in_fe);
    if (!in_fe.readable()) return err(EBADF);
    if (in_fe.kind != .ext2) return err(EINVAL);
    if (isDirFd(pcb, @intCast(in_fd))) return err(EISDIR);
    if (!linux_fs.fdOpen(pcb, out_fd)) return err(EBADF);
    var in_off = copyOffset(in_fe, off_va) orelse return err(EFAULT);
    const want = @min(count, MAX_COPY, fdFileSize(in_fe) -| in_off);
    if (want == 0) return 0;
    const buf = heap.kmallocAligned(4096, 4096) orelse return err(ENOMEM);
    defer heap.kfree(buf);
    var done: u64 = 0;
    while (done < want) {
        const chunk: u32 = @intCast(@min(want - done, 4096));
        const got = vfs.readThroughCache(in_fe.inode, in_off, buf, chunk);
        if (got == 0) break;
        const put = vfs.write(pcb, @intCast(out_fd), buf, got);
        if (put >= errno.ERR_SENTINEL_BASE) {
            if (done > 0) break;
            return vfsResult(put);
        }
        done += put;
        in_off += put;
        if (put < got) break;
    }
    if (off_va != 0) @as(*u64, @ptrFromInt(off_va)).* = in_off else in_fe.offset = in_off;
    return done;
}

/// Most bytes one getrandom returns; Linux may return short past 256.
const MAX_RANDOM: u64 = 1 << 20;

/// getrandom(buf, len, flags): the kernel CSPRNG (RDSEED/RDRAND), never
/// blocking, whichever pool the flags name.
fn sysGetrandom(buf_va: u64, len: u64, flags: u64) u64 {
    if (flags & ~@as(u64, 7) != 0) return err(EINVAL); // GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE
    const n = @min(len, MAX_RANDOM);
    if (n == 0) return 0;
    if (!common.validateUserPtrWrite(buf_va, n)) return err(EFAULT);
    _ = random.fillRandom(@as([*]u8, @ptrFromInt(buf_va))[0..n]);
    return n;
}

const RLIMIT_STACK: u64 = 3;
const RLIMIT_NOFILE: u64 = 7;
const RLIMIT_NLIMITS: u64 = 16;
const RLIM_INFINITY: u64 = ~@as(u64, 0);

const Rlimit = extern struct { cur: u64, max: u64 };

fn rlimitOf(resource: u64) Rlimit {
    return switch (resource) {
        RLIMIT_STACK => .{ .cur = memmap.LINUX_STACK_RESERVE, .max = memmap.LINUX_STACK_RESERVE },
        RLIMIT_NOFILE => .{ .cur = config.MAX_FDS, .max = config.MAX_FDS },
        else => .{ .cur = RLIM_INFINITY, .max = RLIM_INFINITY },
    };
}

/// prlimit64(pid, resource, new, old), and getrlimit/setrlimit through it.
/// The limits are fixed: the stack is the stack region, open files the fd
/// table, the rest unlimited. A well-formed new limit is accepted and has no
/// effect.
fn sysPrlimit(pid: u64, resource: u64, new_va: u64, old_va: u64) u64 {
    const me = proc() orelse return err(EFAULT);
    if (pid != 0) {
        const slot = pid_nr.slotOf(pid) orelse return err(ESRCH);
        if (process.procs[slot].tgid != me.tgid) return err(ESRCH);
    }
    if (resource >= RLIMIT_NLIMITS) return err(EINVAL);
    if (new_va != 0) {
        if (!common.validateUserPtr(new_va, @sizeOf(Rlimit))) return err(EFAULT);
        const want = @as(*align(1) const Rlimit, @ptrFromInt(new_va)).*;
        if (want.cur > want.max) return err(EINVAL);
    }
    if (old_va != 0) {
        if (!common.validateUserPtrWrite(old_va, @sizeOf(Rlimit))) return err(EFAULT);
        @as(*align(1) Rlimit, @ptrFromInt(old_va)).* = rlimitOf(resource);
    }
    return 0;
}

/// sched_getaffinity(pid, len, mask): every online CPU, as one long (the
/// bytes written, which is what the syscall returns), for any live task.
fn sysSchedGetaffinity(pid: u64, len: u64, mask_va: u64) u64 {
    if (pid != 0) {
        const slot = pid_nr.slotOf(pid) orelse return err(ESRCH);
        if (process.procs[slot].state == .zombie) return err(ESRCH);
    }
    if (len < 8 or len & 7 != 0) return err(EINVAL);
    if (!common.validateUserPtrWrite(mask_va, 8)) return err(EFAULT);
    var mask: u64 = 0;
    for (&smp.cpus, 0..) |*c, i| {
        if (@atomicLoad(bool, &c.alive, .acquire)) mask |= @as(u64, 1) << @intCast(i);
    }
    @as(*align(1) u64, @ptrFromInt(mask_va)).* = mask;
    return 8;
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
            // wrmsr #GPs on a non-canonical base; Linux refuses anything
            // past the user window the same way.
            if (addr >= memmap.USER_SPACE_END) return err(EPERM);
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
            if (!common.validateUserPtrWrite(addr, 8)) return err(EFAULT);
            const p: *align(1) u64 = @ptrFromInt(addr);
            p.* = pcb.fs_base;
            return 0;
        },
        ARCH_SET_GS, ARCH_GET_GS => return err(EINVAL),
        else => return err(EINVAL),
    }
}
