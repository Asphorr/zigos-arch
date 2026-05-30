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
//!   * M1 — a static musl program that uses libc (`printf`). Its `_start` reads
//!     argc/argv/envp/auxv off the SysV initial stack (built by
//!     elf_loader.setupLinuxInitialStack) and sets up TLS via arch_prctl before
//!     `main` runs; printf's output flushes through writev at exit.
//!
//! The native ABI (3×u32 args, native numbers, return u32) is entirely
//! separate and untouched — the only shared edge is doSyscall's one-line
//! personality check.

const signals = @import("../../proc/signals.zig");
const process = @import("../../proc/process.zig");
const vfs = @import("../../fs/vfs.zig");
const common = @import("common.zig");
const debug = @import("../../debug/debug.zig");

// --- Linux x86-64 errno (DISTINCT from zigos common.E_* — different values).
// Returned to userspace as the sign-extended negative, per the kernel ABI.
const EPERM: i64 = 1;
const ENOENT: i64 = 2;
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOTTY: i64 = 25;
const ENOSYS: i64 = 38;

/// Encode a positive errno as the Linux-ABI return value (sign-extended -errno).
inline fn err(e: i64) u64 {
    return @bitCast(-e);
}

// --- Linux x86-64 syscall numbers (subset; grows per milestone). ---
const SYS_write: u32 = 1;
const SYS_writev: u32 = 20;
const SYS_ioctl: u32 = 16;
const SYS_brk: u32 = 12;
const SYS_rt_sigprocmask: u32 = 14;
const SYS_getpid: u32 = 39;
const SYS_exit: u32 = 60;
const SYS_arch_prctl: u32 = 158;
const SYS_set_tid_address: u32 = 218;
const SYS_set_robust_list: u32 = 273;
const SYS_exit_group: u32 = 231;

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
    // a4 = frame.r10, a5 = frame.r8, a6 = frame.r9 — unused until later milestones.

    switch (num) {
        SYS_write => return sysWrite(@truncate(a1), a2, a3),
        SYS_writev => return sysWritev(@truncate(a1), a2, a3),
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
        // No Linux-signal delivery for these processes yet, so masking is moot.
        SYS_rt_sigprocmask => return 0,
        // Robust-futex list is only consulted on a thread's abnormal exit; with
        // no Linux threads yet, recording it is a no-op.
        SYS_set_robust_list => return 0,
        SYS_exit, SYS_exit_group => {
            // Low byte is the wait-status exit code (per _exit(2)).
            process.destroyCurrentGraceful(@truncate(a1 & 0xFF));
            return 0; // never reached: destroyCurrentGraceful switches away.
        },
        else => {
            // Bring-up aid: surface exactly which syscall a binary needs next,
            // with its args, so growing M1→M2 is "read the log, add the arm".
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
    // validateUserPtr operates on u32 VAs (user space is sub-4GB). A pointer
    // above 4GB can't be a valid zigos user address → -EFAULT.
    if (buf_va > 0xFFFF_FFFF or !common.validateUserPtr(@truncate(buf_va), @truncate(len))) {
        return err(EFAULT);
    }
    const pcb = process.currentPCB() orelse return err(EFAULT);
    const buf: [*]const u8 = @ptrFromInt(@as(usize, @intCast(buf_va)));
    // Mirror stdout/stderr into the kernel log so a Linux binary's output is
    // visible in serial.log regardless of where its fd 1/2 is wired. (User
    // access is already STAC-unlocked for this syscall — see doSyscall.)
    if (fd <= 2 and len <= 256) debug.klog("[linux] write(fd={d}): {s}", .{ fd, buf[0..len] });
    const n = vfs.write(pcb, fd, buf, @truncate(len));
    // vfs.write returns 0xFFFFFFFF on failure (bad fd, read-only fs, wrong-side
    // pipe). Zero-extended that reads back as a bogus +4G "success" — map it to
    // a Linux errno instead. (M1: refine to per-case errno; the stdout/stderr
    // console path returns the real byte count on success.)
    if (n == 0xFFFF_FFFF) return err(EBADF);
    return n;
}

/// writev(fd, iov, iovcnt). musl's stdio writes everything through writev (the
/// FILE buffer + the new bytes as two iovecs), so this is the real output path
/// for printf. Walks the iovec array, writing each segment via vfs.write, and
/// returns the total bytes written (or -EFAULT / -EBADF). Each user pointer is
/// validated separately — the array first, then every base it names.
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
        // A segment longer than user space (or above 4GB) can't be valid.
        if (seg > 0xFFFF_FFFF or base > 0xFFFF_FFFF or
            !common.validateUserPtr(@truncate(base), @truncate(seg)))
        {
            // POSIX: if some bytes were already written, report the partial
            // count rather than the error (the next writev re-hits the fault).
            if (total > 0) return total;
            return err(EFAULT);
        }
        const buf: [*]const u8 = @ptrFromInt(@as(usize, @intCast(base)));
        const l: u32 = @truncate(seg);
        if (fd <= 2 and seg <= 256) debug.klog("[linux] writev(fd={d}): {s}", .{ fd, buf[0..@intCast(seg)] });
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
        // We don't run anything that touches %gs from user space yet.
        ARCH_SET_GS, ARCH_GET_GS => return err(EINVAL),
        else => return err(EINVAL),
    }
}
