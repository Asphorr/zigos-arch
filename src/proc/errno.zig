// Syscall error returns. Codes pack into the top of u32 so existing
// `return 0xFFFFFFFF` callers stay bit-compatible — that value equals
// `err(.EINVAL)`. Userspace tests "any error" with `r >= ERR_SENTINEL_BASE`,
// then converts to a positive errno via `~r +% 1`.
//
// We use a small Linux-style subset. Add codes here as the kernel grows
// new failure modes — but resist inventing per-syscall enums; the value
// of a shared errno is that callers can write generic error-handling
// without learning each syscall's bestiary.

pub const ERR_SENTINEL_BASE: u32 = 0xFFFFF000;

pub const Errno = enum(u32) {
    EINVAL = 0xFFFFFFFF, // Invalid argument (catch-all — preserves legacy 0xFFFFFFFF returns)
    ENOENT = 0xFFFFFFFE, // No such file or directory
    EFAULT = 0xFFFFFFFD, // Bad address (user pointer invalid, kernel state broken)
    EBADF = 0xFFFFFFFC, // Bad file descriptor
    EACCES = 0xFFFFFFFB, // Permission denied
    EAGAIN = 0xFFFFFFFA, // Resource temporarily unavailable / would block
    ENOMEM = 0xFFFFFFF9, // Out of memory / no contiguous frames
    EBUSY = 0xFFFFFFF8, // Device or resource busy
    ENOSPC = 0xFFFFFFF7, // No space left on device
    EEXIST = 0xFFFFFFF6, // File exists
    ENOTDIR = 0xFFFFFFF5, // Not a directory
    EISDIR = 0xFFFFFFF4, // Is a directory
    ENOSYS = 0xFFFFFFF3, // Function not implemented
    EPIPE = 0xFFFFFFF2, // Broken pipe
    EINTR = 0xFFFFFFF1, // Interrupted system call
    ECHILD = 0xFFFFFFF0, // No child processes
    ESRCH = 0xFFFFFFEF, // No such process
    EPERM = 0xFFFFFFEE, // Operation not permitted
    ERANGE = 0xFFFFFFED, // Result too large
    ENAMETOOLONG = 0xFFFFFFEC, // File name too long
    E2BIG = 0xFFFFFFEB, // Argument list too long
    ENXIO = 0xFFFFFFEA, // No such device or address
    ENODEV = 0xFFFFFFE9, // No such device
    EIO = 0xFFFFFFE8, // I/O error
    ECONNREFUSED = 0xFFFFFFE7,
    ETIMEDOUT = 0xFFFFFFE6,
    EHOSTUNREACH = 0xFFFFFFE5,
    ENETDOWN = 0xFFFFFFE4,
    ENOTCONN = 0xFFFFFFE3,
    EALREADY = 0xFFFFFFE2,
    ETXTBSY = 0xFFFFFFE1, // Text file busy — write/truncate of a running executable's image
};

/// Encode an errno as a syscall return value.
pub inline fn err(e: Errno) u32 {
    return @intFromEnum(e);
}

/// True if `r` is any errno return (sits in the top sentinel range).
pub inline fn isErr(r: u32) bool {
    return r >= ERR_SENTINEL_BASE;
}
