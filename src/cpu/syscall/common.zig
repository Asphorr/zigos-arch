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
    if (ptr < USER_SPACE_START or ptr >= USER_SPACE_END) return false;
    if (len > 0 and ptr + len > USER_SPACE_END) return false;
    if (len > 0 and ptr + len < ptr) return false; // overflow
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
    @import("../protect.zig").allowUserAccess();
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
