//! Shared syscall-handler helpers — split out of syscall.zig (#797).
//! errno constants + user-pointer validation used by every domain handler
//! file (proc/mem/fs/window/gpu/net/sys). Imported by each as `common`, with
//! file-local `const E_X = common.E_X;` / `const validateUserPtr = ...` aliases
//! so the moved handler bodies need no edits.

const errno = @import("../../proc/errno.zig");
const memmap = @import("../../mm/memmap.zig");
const process = @import("../../proc/process.zig");

pub const E_INVAL: u32 = errno.err(.EINVAL);
pub const E_NOENT: u32 = errno.err(.ENOENT);
pub const E_FAULT: u32 = errno.err(.EFAULT);
pub const E_BADF: u32 = errno.err(.EBADF);
pub const E_NOMEM: u32 = errno.err(.ENOMEM);
pub const E_AGAIN: u32 = errno.err(.EAGAIN);
pub const E_BUSY: u32 = errno.err(.EBUSY);
pub const E_NAMETOOLONG: u32 = errno.err(.ENAMETOOLONG);
pub const E_PIPE: u32 = errno.err(.EPIPE);
pub const E_SRCH: u32 = errno.err(.ESRCH);
pub const E_NOSYS: u32 = errno.err(.ENOSYS);
pub const E_PERM: u32 = errno.err(.EPERM);
pub const E_CHILD: u32 = errno.err(.ECHILD);
pub const E_INTR: u32 = errno.err(.EINTR);

// memmap.USER_SPACE_START sits below USER_VA_FLOOR to cover the user
// stack region (16 pages just under 0x500000). Earlier this was a local
// `= memmap.USER_VA_FLOOR` shadow, which silently drifted when memmap
// added the stack reserve — every syscall taking a stack-buffer arg
// (e.g. sysGetScreenSize) returned EFAULT, and apps tripped on the
// uninitialized (0xAAAAAAAA) buffer they assumed the kernel had filled.
pub const USER_SPACE_START: usize = memmap.USER_SPACE_START;
pub const USER_SPACE_END: usize = memmap.USER_SPACE_END;

/// Validate that a user pointer + length is within user address space, and
/// pre-fault any demand-paged pages in the range. Without the pre-fault, a
/// kernel-mode read of e.g. an app's .rodata string would bypass the USER
/// bit check and return inherited 2MB-page data (random kernel memory)
/// instead of the app's content.
pub fn validateUserPtr(ptr: usize, len: usize) bool {
    if (!memmap.userDataRangeOk(ptr, len)) return false;
    // Instrument the slow part — prefault + per-page PT walk. Cheap range
    // checks above don't need bracketing; the meaningful cost starts here.
    const sp = @import("../../debug/syscall_perf.zig").scope(.user_ptr_walk);
    defer sp.end();
    if (len > 0) process.prefaultUserRange(ptr, len);
    // prefaultUserRange only maps pages inside registered lazy_regions; a
    // pointer to scratch user-VA stays unmapped and the kernel's @memcpy
    // would #PF in supervisor mode. Verify every page is actually present
    // before letting the syscall body dereference it. Found by redteam
    // fuzzer hitting sysGetcwd with a random user-range pointer.
    if (len > 0 and !process.allCurrentUserPagesMapped(ptr, len)) return false;
    // Validation succeeded — caller is about to deref. STAC unlocks user
    // memory access for the remainder of this syscall; doSyscall's defer
    // CLACs on exit. Cheap: with SMAP off this is a noop branch.
    @import("../arch/protect.zig").allowUserAccess();
    return true;
}

/// validateUserPtr + alignment check. Use whenever the caller is about to
/// `@ptrFromInt` to `*T` or `[*]T` with `@alignOf(T) > 1` — Zig's runtime
/// safety panics on misaligned cast (separate bug class from null/unmapped).
/// Found by redteam fuzzer hitting sysSigprocmask with an unaligned u32 ptr.
pub fn validateUserPtrAligned(ptr: usize, len: usize, comptime align_to: usize) bool {
    if (align_to > 1 and ptr & (align_to - 1) != 0) return false;
    return validateUserPtr(ptr, len);
}

/// validateUserPtr for a WRITE target: additionally guarantees every page in
/// the range is WRITABLE (breaking COW as needed) so the syscall body can copy
/// data OUT to the user buffer without a kernel-mode #PF this ring-3-only fault
/// handler can't service (which panics/halts the box). Use for EVERY syscall
/// that writes through the pointer — read() dest, stat buf, getcwd, getdents,
/// gettimeofday, poll revents, the OLD sigaction/sigmask, etc. Read-only args
/// (path strings, write() source buffers) stay on plain validateUserPtr.
/// process.ensureUserRangeWritable returns false for a genuinely read-only page
/// (an app's own .text/.rodata, or an mprotect'd-RO region), so a hostile or
/// buggy pointer becomes a clean EFAULT instead of a kernel fault. Found by the
/// redteam fuzzer handing sysGettimeofday a pointer into its read-only code.
pub fn validateUserPtrWrite(ptr: usize, len: usize) bool {
    if (!validateUserPtr(ptr, len)) return false;
    if (len > 0 and !process.ensureUserRangeWritable(ptr, len)) return false;
    return true;
}

/// validateUserPtrWrite + alignment check (see validateUserPtrAligned). Use for
/// write targets cast to `*T` / `[*]T` with `@alignOf(T) > 1`.
pub fn validateUserPtrWriteAligned(ptr: usize, len: usize, comptime align_to: usize) bool {
    if (align_to > 1 and ptr & (align_to - 1) != 0) return false;
    return validateUserPtrWrite(ptr, len);
}

/// Wrap a kernel-side socket slot in a per-process fd. Used by socket-
/// allocating syscalls (tcp_connect, tcp_listen, tcp_accept) so userspace
/// gets a uniform fd back instead of a separate slot namespace. Returns
/// null if the caller's fd_table is full — caller must roll back the
/// slot allocation in that case.
pub fn allocSocketFd(pcb: *process.PCB, kind: process.FsType, slot: u8) ?u32 {
    const vfs = @import("../../fs/vfs.zig");
    const fd_idx = vfs.allocFd(pcb) orelse return null;
    pcb.fd_table[fd_idx] = .{
        .in_use = true,
        .fs_type = kind,
        .inode = @as(u32, slot),
    };
    return @intCast(fd_idx);
}

/// Resolve a socket fd back to the kernel slot. Verifies the fd is in use
/// AND that its fs_type matches the expected kind, so tcpSend on a pipe
/// fd or a tcp_listener fd is rejected with EBADF instead of silently
/// indexing into the wrong table. Returns the u8 slot id on success.
pub fn resolveSocketFd(pcb: *process.PCB, fd: u32, expected_kind: process.FsType) ?u8 {
    if (fd >= pcb.fd_table.len) return null;
    const e = &pcb.fd_table[fd];
    if (!e.in_use) return null;
    if (e.fs_type != expected_kind) return null;
    return @intCast(e.inode);
}
