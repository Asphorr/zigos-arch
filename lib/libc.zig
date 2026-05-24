// ZigOS User-space libc
// Syscall wrappers and utilities for user applications

const std = @import("std");

// --- Syscall errors ---
//
// Syscalls returning u32 use the high sentinel range [0xFFFFF000, 0xFFFFFFFF]
// for errors, mirroring `src/proc/errno.zig`. `isErr` tests "any error";
// `errnoOf` extracts a small positive code suitable for switching on.
//
// Backward compat: legacy callers checking `r == 0xFFFFFFFF` still work,
// because that value is `EINVAL` (the catch-all errno).

pub const ERR_SENTINEL_BASE: u32 = 0xFFFFF000;

pub const Errno = enum(u32) {
    OK = 0,
    EINVAL = 0xFFFFFFFF,
    ENOENT = 0xFFFFFFFE,
    EFAULT = 0xFFFFFFFD,
    EBADF = 0xFFFFFFFC,
    EACCES = 0xFFFFFFFB,
    EAGAIN = 0xFFFFFFFA,
    ENOMEM = 0xFFFFFFF9,
    EBUSY = 0xFFFFFFF8,
    ENOSPC = 0xFFFFFFF7,
    EEXIST = 0xFFFFFFF6,
    ENOTDIR = 0xFFFFFFF5,
    EISDIR = 0xFFFFFFF4,
    ENOSYS = 0xFFFFFFF3,
    EPIPE = 0xFFFFFFF2,
    EINTR = 0xFFFFFFF1,
    ECHILD = 0xFFFFFFF0,
    ESRCH = 0xFFFFFFEF,
    EPERM = 0xFFFFFFEE,
    ERANGE = 0xFFFFFFED,
    ENAMETOOLONG = 0xFFFFFFEC,
    E2BIG = 0xFFFFFFEB,
    ENXIO = 0xFFFFFFEA,
    ENODEV = 0xFFFFFFE9,
    EIO = 0xFFFFFFE8,
    ECONNREFUSED = 0xFFFFFFE7,
    ETIMEDOUT = 0xFFFFFFE6,
    EHOSTUNREACH = 0xFFFFFFE5,
    ENETDOWN = 0xFFFFFFE4,
    ENOTCONN = 0xFFFFFFE3,
    EALREADY = 0xFFFFFFE2,
    _,
};

pub inline fn isErr(r: u32) bool {
    return r >= ERR_SENTINEL_BASE;
}

/// Decode an error return into an Errno (or .OK for non-error returns).
pub inline fn errnoOf(r: u32) Errno {
    if (!isErr(r)) return .OK;
    return @enumFromInt(r);
}

// --- Syscall primitives ---

pub inline fn syscall(num: u32, arg1: u32, arg2: u32) u32 {
    return syscall3(num, arg1, arg2, 0);
}

pub inline fn syscall3(num: u32, arg1: u32, arg2: u32, arg3: u32) u32 {
    var ret: u32 = undefined;
    // Use native syscall instruction (40% faster than int 0x80)
    // Calling convention: RAX=num, RDI=arg1, RSI=arg2, RDX=arg3.
    // The kernel's syscall_entry shuffles RDI/RSI/RDX into the SysV registers
    // before invoking doSyscall, so those — plus the syscall-defined RCX/R11
    // scratch — must be marked clobbered. Without this the compiler skips
    // reloading args between back-to-back syscalls and we pass garbage
    // (e.g. mapBlob saw size=48 because ESI was left over from a prior call).
    asm volatile ("syscall"
        : [ret] "={eax}" (ret),
        : [num] "{eax}" (num),
          [a1] "{edi}" (arg1),
          [a2] "{esi}" (arg2),
          [a3] "{edx}" (arg3),
        : .{ .rcx = true, .r11 = true, .rdi = true, .rsi = true, .rdx = true, .memory = true }
    );
    return ret;
}

// --- Syscall wrappers ---

/// Write `msg` to stdout (fd 1). Routed through fd 1 (not syscall 1 sys_print)
/// so that pipeline redirection — `cmd1 | cmd2` in the shell — actually carries
/// data. When stdout is the console (the default), the kernel's vfs.write also
/// mirrors output to serial with an `[app] ` prefix, so kernel debug logging
/// is preserved.
pub fn print(msg: []const u8) void {
    _ = fwrite(1, msg);
}

/// Verify that the kernel preserves r8/r9/r10 across a syscall. Run this once
/// at app startup (or from a CLI command) — if the kernel's syscall handler
/// drops a callee-volatile register, every malloc-heavy app silently corrupts
/// downstream code (we lost an hour debugging exactly this when r8 held a
/// stack pointer across a print syscall). Prints `[abi] OK` on success or a
/// loud warning naming the busted register.
pub fn syscallAbiSelfTest() void {
    const r8_in: u64 = 0xCAFEBABEDEADBEEF;
    const r9_in: u64 = 0xDEADBEEFCAFEBABE;
    const r10_in: u64 = 0x123456789ABCDEF0;
    var r8_out: u64 = 0;
    var r9_out: u64 = 0;
    var r10_out: u64 = 0;
    // Issue a yield syscall (#7) with sentinels in r8/r9/r10. The clobber
    // list is intentionally MINIMAL — we want to catch any reg the kernel
    // accidentally drops, so we tell the compiler we expect them preserved.
    asm volatile (
        \\ mov %[s8],  %%r8
        \\ mov %[s9],  %%r9
        \\ mov %[s10], %%r10
        \\ mov $7, %%eax
        \\ xor %%edi, %%edi
        \\ xor %%esi, %%esi
        \\ xor %%edx, %%edx
        \\ syscall
        \\ mov %%r8,  %[o8]
        \\ mov %%r9,  %[o9]
        \\ mov %%r10, %[o10]
        : [o8] "=r" (r8_out),
          [o9] "=r" (r9_out),
          [o10] "=r" (r10_out),
        : [s8] "r" (r8_in),
          [s9] "r" (r9_in),
          [s10] "r" (r10_in),
        : .{ .rax = true, .rcx = true, .rdx = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .memory = true }
    );
    if (r8_out != r8_in or r9_out != r9_in or r10_out != r10_in) {
        var msg: [256]u8 = undefined;
        const written = std.fmt.bufPrint(&msg,
            "[abi] !!! KERNEL SYSCALL ABI BROKEN !!! r8 0x{X:0>16}->0x{X:0>16} r9 0x{X:0>16}->0x{X:0>16} r10 0x{X:0>16}->0x{X:0>16}\n",
            .{ r8_in, r8_out, r9_in, r9_out, r10_in, r10_out },
        ) catch return;
        print(written);
    } else {
        print("[abi] syscall preserves r8/r9/r10 OK\n");
    }
}

pub fn clear() void {
    _ = syscall(2, 0, 0);
}

pub fn exit() noreturn {
    _ = syscall(3, 0, 0);
    unreachable;
}

pub fn readChar() u8 {
    return @truncate(syscall(4, 0, 0));
}

/// Blocking read of one byte from fd 0 (syscall 113). Parks until a byte is
/// available rather than returning immediately; returns 0 on a pending signal
/// (EINTR) or EOF. Interactive readers should prefer this over the
/// readChar()+sleep() poll loop — it drops idle CPU to ~0.
pub fn readCharBlocking() u8 {
    return @truncate(syscall(113, 0, 0));
}

// --- Window event API (syscall 90) ---
//
// The kernel maintains a per-window event queue (see src/ui/events.zig).
// Events are typed records — keyboard chars, special keys, mouse moves
// and clicks, focus transitions, resize, close requests. Apps that
// would otherwise poll several distinct things (readChar + getMouse +
// getWindowSize + … and infer state changes by diffing) can instead
// drain a single ordered queue.
//
// Layout MUST match `src/ui/events.zig:Event` (16 bytes) and
// `EventKind` exactly — the kernel writes raw bytes into our buffer.

pub const EventKind = enum(u8) {
    none = 0,
    key_char = 1,
    key_special = 2,
    mouse_move = 3,
    mouse_button = 4,
    mouse_wheel = 5,
    focus_in = 6,
    focus_out = 7,
    resize = 8,
    close_request = 9,
    _,
};

pub const Event = extern struct {
    kind: u8,
    _pad: [3]u8 = .{ 0, 0, 0 },
    a: u32 = 0,
    b: u32 = 0,
    c: u32 = 0,

    /// True iff the event should be ignored (queue was empty / no focus).
    pub fn isNone(self: Event) bool {
        return self.kind == @intFromEnum(EventKind.none);
    }

    /// Decode the EventKind. Matches what `pollEvent` returned, but
    /// useful when handing an Event back from a function.
    pub fn kindOf(self: Event) EventKind {
        return @enumFromInt(self.kind);
    }

    // --- mouse_button helpers ---

    pub fn buttonIndex(self: Event) u8 {
        return @truncate(self.a);
    }
    pub fn buttonPressed(self: Event) bool {
        return ((self.a >> 8) & 0xFF) != 0;
    }
    pub fn buttonsState(self: Event) u8 {
        return @truncate(self.a >> 16);
    }
};

/// Modifier bits packed into `Event.b` for key events.
pub const MOD_SHIFT: u32 = 1 << 0;
pub const MOD_CTRL: u32 = 1 << 1;
pub const MOD_ALT: u32 = 1 << 2;
pub const MOD_CAPS: u32 = 1 << 3;

/// Drain one event from this window's queue. Returns `null` when the
/// queue is empty, this process doesn't own the focused window, or
/// there is no focused visible window. Non-blocking — apps poll in a
/// loop and yield/sleep when nothing's available.
pub fn pollEvent() ?Event {
    var ev: Event = .{ .kind = 0 };
    const kind = syscall(90, @truncate(@intFromPtr(&ev)), 0);
    // 0 = empty queue / no focus. Any value above the highest known kind
    // (currently `close_request = 9`) is a kernel error like E_NOSYS —
    // treat as null instead of returning a zero-`kind` event that callers
    // would loop on forever.
    if (kind == 0 or kind > @intFromEnum(EventKind.close_request)) return null;
    return ev;
}

comptime {
    std.debug.assert(@sizeOf(Event) == 16);
}

pub fn sbrk(increment: u32) ?[*]u8 {
    const result = syscall(5, increment, 0);
    if (result == 0xFFFFFFFF) return null;
    return @ptrFromInt(result);
}

/// Shrink the data segment by `decrement` bytes. Returns true on success;
/// the kernel unmaps and frees PMM frames for any pages whose VA falls in
/// the released range, then shortens the heap lazy region. Caller is
/// responsible for not shrinking past live allocations — `malloc_trim`
/// below is the supported high-level entry.
pub fn sbrkShrink(decrement: u32) bool {
    const neg: i32 = -@as(i32, @intCast(decrement));
    const result = syscall(5, @bitCast(neg), 0);
    return result != 0xFFFFFFFF;
}

pub fn getpid() u32 {
    return syscall(6, 0, 0);
}

pub fn yield() void {
    _ = syscall(7, 0, 0);
}

pub fn sleep(ms: u32) void {
    _ = syscall(8, ms, 0);
}

pub fn open(name: []const u8) ?u32 {
    if (name.len == 0) return null;
    var buf: [100]u8 = undefined;
    const copy_len = if (name.len > 99) @as(usize, 99) else name.len;
    @memcpy(buf[0..copy_len], name[0..copy_len]);
    buf[copy_len] = 0;
    const result = syscall(9, @truncate(@intFromPtr(&buf)), 0);
    if (result == 0xFFFFFFFF) return null;
    return result;
}

pub fn fread(fd: u32, buf: []u8) u32 {
    return syscall3(10, fd, @truncate(@intFromPtr(buf.ptr)), @intCast(buf.len));
}

pub fn fwrite(fd: u32, data: []const u8) u32 {
    return syscall3(11, fd, @truncate(@intFromPtr(data.ptr)), @intCast(data.len));
}

pub fn close(fd: u32) void {
    _ = syscall(12, fd, 0);
}

/// Reposition the fd's cursor. whence: 0=SET (absolute), 1=CUR (relative
/// to current offset). Returns new offset, or null on failure.
pub fn seek(fd: u32, offset: u32, whence: u32) ?u32 {
    const r = syscall3(111, fd, offset, whence);
    if (r == 0xFFFFFFFF) return null;
    return r;
}

/// Change the calling process's working directory. Returns true on success.
/// Path may be absolute (starting with '/') or relative to the current cwd.
/// Examples: `chdir("/tar/")`, `chdir("/fat/sub")`, `chdir("foo")`.
pub fn chdir(path: []const u8) bool {
    if (path.len == 0 or path.len > 254) return false;
    var buf: [256]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return syscall(39, @truncate(@intFromPtr(&buf)), 0) == 0;
}

/// Copy the calling process's cwd into `out`. Returns the cwd as a slice of
/// `out`, or null if the buffer is too small. The returned slice does NOT
/// include a NUL terminator; the kernel writes one past `out[len]` when there
/// is room (`len + 1 <= out.len`), but callers should rely on the slice length.
pub fn getCwd(out: []u8) ?[]const u8 {
    if (out.len == 0) return null;
    const n = syscall(40, @truncate(@intFromPtr(out.ptr)), @intCast(out.len));
    if (n == 0xFFFFFFFF) return null;
    return out[0..n];
}

/// Anonymous, zero-filled, demand-paged memory region. Returns a slice
/// covering the (page-aligned) requested length, or null on failure (out of
/// VA, lazy-region table full, would collide with sbrk heap, etc.). The
/// kernel doesn't allocate physical pages until first touch — reading or
/// writing through the slice triggers a page fault that gets resolved on
/// the spot. Pair with `munmap` to release.
pub fn mmap(len: usize) ?[]u8 {
    if (len == 0) return null;
    const va = syscall3(57, @intCast(len), 0xFFFFFFFF, 0);
    if (va == 0xFFFFFFFF) return null;
    const aligned: usize = (len + 0xFFF) & ~@as(usize, 0xFFF);
    const ptr: [*]u8 = @ptrFromInt(@as(usize, va));
    return ptr[0..aligned];
}

/// Map `len` bytes of file `fd` starting at `offset` into a fresh user VA
/// region. The kernel reads the slice into a per-region buffer once, then
/// demand-pages user copies on first touch — so this is MAP_PRIVATE-ish: each
/// call gets its own snapshot of the file, writes through the returned slice
/// don't propagate back to disk or to other mappings. Real shared semantics
/// would need a page cache.
///
/// `len` is rounded up to a page boundary; bytes past EOF read as zero. The
/// caller's read position on `fd` is preserved across this call.
pub fn mmapFile(fd: u32, offset: u32, len: usize) ?[]u8 {
    if (len == 0) return null;
    const va = syscall3(57, @intCast(len), fd, offset);
    if (va == 0xFFFFFFFF) return null;
    const aligned: usize = (len + 0xFFF) & ~@as(usize, 0xFFF);
    const ptr: [*]u8 = @ptrFromInt(@as(usize, va));
    return ptr[0..aligned];
}

/// io_uring Sqe / Cqe / RingHeader — must match src/cpu/iouring.zig byte-for-byte.
pub const IoUringSqe = extern struct {
    opcode: u8,
    flags: u8,
    _pad1: u16,
    fd: u32,
    off: u64,
    addr: u64,
    len: u32,
    user_data: u64,
    _pad2: [28]u8,
};

pub const IoUringCqe = extern struct {
    user_data: u64,
    res: i32,
    flags: u32,
};

pub const IoUringHeader = extern struct {
    sq_head: u32,
    sq_tail: u32,
    sq_mask: u32,
    sq_entries: u32,
    cq_head: u32,
    cq_tail: u32,
    cq_mask: u32,
    cq_entries: u32,
    sqes_offset: u32,
    cqes_offset: u32,
    _pad: [24]u8,
};

pub const IOURING_OP_NOP: u8 = 0;
pub const IOURING_OP_READ: u8 = 1;
pub const IOURING_OP_WRITE: u8 = 2;
/// Raw-LBA NVMe ops (Phase 3 A1): bypass VFS, true per-IRQ async.
///   sqe.fd     = NVMe controller idx (0 primary, 1 secondary, ...)
///   sqe.off    = LBA (32-bit; high bits truncated)
///   sqe.addr   = user buffer VA
///   sqe.len    = sectors (NOT bytes) — bytes = sectors * controller block size
/// CQE.res on success = bytes transferred; negative errno on error.
pub const IOURING_OP_NVME_READ: u8 = 3;
pub const IOURING_OP_NVME_WRITE: u8 = 4;

pub const IoUring = struct {
    header: *volatile IoUringHeader,
    sqes: [*]IoUringSqe,
    cqes: [*]volatile IoUringCqe,
    base_va: usize,
    // Tentative-submit counter: getSqe() bumps; submit() flushes via
    // sq_tail += pending. Mirrors liburing's io_uring_get_sqe so back-to-
    // back getSqe calls return DIFFERENT slots between submit() flushes.
    pending: u32 = 0,

    /// Get the next free Sqe slot. Returns null if the SQ ring is full
    /// (kernel hasn't caught up to draining previous batch). The caller
    /// fills the returned Sqe in place; `submit()` later flushes by
    /// publishing sq_tail to the kernel.
    pub fn getSqe(self: *IoUring) ?*IoUringSqe {
        const tail = self.header.sq_tail +% self.pending;
        const head = self.header.sq_head;
        if (tail -% head >= self.header.sq_entries) return null;
        self.pending += 1;
        return &self.sqes[tail & self.header.sq_mask];
    }

    /// Flush queued Sqes by publishing sq_tail. `count` should match the
    /// number of getSqe calls since the last submit (or 0 — we'll use
    /// the tracked pending count). Always uses release ordering so the
    /// kernel's acquire-load of sq_tail observes our Sqe writes.
    pub fn submit(self: *IoUring, count: u32) void {
        const n = if (count != 0) count else self.pending;
        const new_tail = self.header.sq_tail +% n;
        @atomicStore(u32, &self.header.sq_tail, new_tail, .release);
        self.pending = 0;
    }

    /// Reap one completion. Returns null if the CQ ring is empty.
    /// The returned Cqe is a copy; advances cq_head atomically.
    pub fn reapCqe(self: *IoUring) ?IoUringCqe {
        const head = self.header.cq_head;
        const tail = @atomicLoad(u32, &self.header.cq_tail, .acquire);
        if (head == tail) return null;
        const cqe = self.cqes[head & self.header.cq_mask];
        @atomicStore(u32, &self.header.cq_head, head +% 1, .release);
        return cqe;
    }

    /// Drive submission + completion. Returns # SQEs processed, or null on error.
    pub fn enter(self: *IoUring, to_submit: u32, min_complete: u32) ?u32 {
        const r = syscall3(116, @truncate(self.base_va), to_submit, min_complete);
        if (r == 0xFFFFFFFF) return null;
        return r;
    }
};

/// Set up a new io_uring with at least `entries` SQ/CQ slots. Returns a
/// wrapper struct or null on failure.
pub fn ioUringSetup(entries: u32) ?IoUring {
    const va = syscall(115, entries, 0);
    if (va == 0) return null;
    const base: usize = @as(usize, va);
    const hdr: *volatile IoUringHeader = @ptrFromInt(base);
    const sqes_ptr: [*]IoUringSqe = @ptrFromInt(base + hdr.sqes_offset);
    const cqes_ptr: [*]volatile IoUringCqe = @ptrFromInt(base + hdr.cqes_offset);
    return .{
        .header = hdr,
        .sqes = sqes_ptr,
        .cqes = cqes_ptr,
        .base_va = base,
    };
}

/// POSIX MAP_SHARED|MAP_ANONYMOUS. Returns a slice that's truly shared
/// across fork() — child sees parent's writes byte-for-byte and vice
/// versa (no COW break). munmap on either side decrements the shm
/// region's refcount; the underlying frames stay alive until the last
/// attacher releases. Returns null on out-of-table / OOM / oversize.
pub fn mmapSharedAnon(len: usize) ?[]u8 {
    if (len == 0) return null;
    const va = syscall(114, @intCast(len), 0);
    if (va == 0) return null;
    const aligned: usize = (len + 0xFFF) & ~@as(usize, 0xFFF);
    const ptr: [*]u8 = @ptrFromInt(@as(usize, va));
    return ptr[0..aligned];
}

/// Release an mmap region. The slice must be exactly what `mmap` returned —
/// partial unmaps aren't supported. Returns true on success.
pub fn munmap(buf: []u8) bool {
    if (buf.len == 0) return false;
    return syscall(58, @truncate(@intFromPtr(buf.ptr)), @intCast(buf.len)) == 0;
}

// Page-protection bits for `mprotect`. PROT_READ is informational — pages
// are readable as soon as they're mapped — but PROT_WRITE / PROT_EXEC gate
// access through the PTE's RW and NX bits. PROT_NONE = 0 maps the page
// non-executable and non-writable; reads still work since x86 has no
// "no-read" bit, but writes/executes trap.
pub const PROT_NONE: u32 = 0;
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;

/// Change page-protection on an mmap region. `buf` must match the slice
/// originally returned by `mmap`/`mmapFile` — partial mprotect (sub-range
/// of a registered region) isn't supported yet. Returns true on success;
/// on failure (no matching region, kernel rejected the call) the existing
/// prot is unchanged.
pub fn mprotect(buf: []u8, prot: u32) bool {
    if (buf.len == 0) return false;
    return syscall3(59, @truncate(@intFromPtr(buf.ptr)), @intCast(buf.len), prot) == 0;
}

// --- Utilities ---

pub fn printChar(ch: u8) void {
    var buf: [1]u8 = .{ch};
    print(&buf);
}

pub fn println(msg: []const u8) void {
    print(msg);
    printChar('\n');
}

pub fn printNum(n: u32) void {
    if (n == 0) {
        printChar('0');
        return;
    }
    var digits: [10]u8 = undefined;
    var dlen: usize = 0;
    var val = n;
    while (val > 0) {
        digits[dlen] = @truncate('0' + (val % 10));
        dlen += 1;
        val /= 10;
    }
    var i: usize = dlen;
    while (i > 0) {
        i -= 1;
        printChar(digits[i]);
    }
}

pub fn printHex(n: u32) void {
    print("0x");
    const hex = "0123456789ABCDEF";
    var i: u5 = 8;
    while (i > 0) {
        i -= 1;
        printChar(hex[@as(u4, @truncate((n >> (@as(u5, i) * 4))))]);
    }
}

// --- Graphics ---

/// Allocated framebuffer + actual stride. The kernel needs alloc_w to be
/// 16-pixel aligned for the GPU compositor's zero-copy slot path; libc
/// rounds up automatically and reports back the actual value here. Apps
/// MUST use `alloc_w` from this struct (not their requested width) as
/// the row stride for any FB writes — otherwise rows shear diagonally.
pub const WindowFb = struct {
    fb: [*]volatile u32,
    alloc_w: u32, // actual stride in pixels (16-aligned, ≥ requested w)
    alloc_h: u32,
};

/// Round-up an alloc width to the kernel's required alignment (16 pixels
/// = 64 bytes for B8G8R8A8, matching Lavapipe's LINEAR rowPitch). Apps
/// that compute their own alloc_w (e.g. via a budget bisection loop)
/// don't need to call this — `createWindow*` does it internally.
pub fn alignWindowAllocW(w: u32) u32 {
    return (w + 15) & ~@as(u32, 15);
}

pub fn createWindow(w: u32, h: u32) ?WindowFb {
    const aligned = alignWindowAllocW(w);
    const ret = syscall(13, aligned, h);
    if (ret == 0xFFFFFFFF) return null;
    return .{ .fb = @ptrFromInt(ret), .alloc_w = aligned, .alloc_h = h };
}

/// Create window with over-allocated FB. Display visible region is
/// `disp_w × disp_h`; FB allocation is `alloc_w × alloc_h` where the
/// returned `alloc_w` is rounded up to 16 pixels.
pub fn createWindowEx(alloc_w: u32, alloc_h: u32, disp_w: u32, disp_h: u32) ?WindowFb {
    const aligned = alignWindowAllocW(alloc_w);
    const display_wh = (disp_h << 16) | disp_w;
    const ret = syscall3(13, aligned, alloc_h, display_wh);
    if (ret == 0xFFFFFFFF) return null;
    return .{ .fb = @ptrFromInt(ret), .alloc_w = aligned, .alloc_h = alloc_h };
}

pub fn present() void {
    _ = syscall(14, 0, 0);
}

pub const MouseState = struct { x: i32, y: i32, buttons: u32, dx: i32 = 0, dy: i32 = 0 };

pub fn getMouse() MouseState {
    var buf: [5]u32 align(4) = undefined;
    _ = syscall(15, @truncate(@intFromPtr(&buf)), 0);
    return .{
        .x = @bitCast(buf[0]),
        .y = @bitCast(buf[1]),
        .buttons = buf[2],
        .dx = @bitCast(buf[3]),
        .dy = @bitCast(buf[4]),
    };
}

pub fn destroyWindow() void {
    _ = syscall(16, 0, 0);
}

pub fn uptime() u32 {
    return syscall(17, 0, 0);
}

pub const MemInfo = struct { free_frames: u32, total_frames: u32 };
pub fn meminfo() MemInfo {
    var buf: [2]u32 align(4) = undefined;
    _ = syscall(18, @truncate(@intFromPtr(&buf)), 0);
    return .{ .free_frames = buf[0], .total_frames = buf[1] };
}

/// Per-CPU tick counters used to compute utilization. Caller takes two
/// snapshots `dt` apart and computes `((irq_d - idle_d) * 100) / irq_d`
/// for each CPU to get instantaneous CPU usage in percent.
pub const CpuStat = extern struct {
    irq_ticks: u64,
    idle_ticks: u64,
};

/// Fill `out` with stats for up to `out.len` alive CPUs. Returns how many
/// were written. On error returns a u32 in the errno band (>0xFFFFFFF0).
pub fn cpuStats(out: []CpuStat) u32 {
    if (out.len == 0) return 0;
    return syscall(105, @truncate(@intFromPtr(out.ptr)), @truncate(out.len));
}

/// Snapshot of the kernel's active L3 config + NIC presence. Layout
/// mirrors src/cpu/syscall.zig:NetInfo — keep both in sync when adding
/// fields.
pub const NetInfo = extern struct {
    local_ip: [4]u8,
    gateway_ip: [4]u8,
    dns_ip: [4]u8,
    subnet_mask: [4]u8,
    mac: [6]u8,
    _pad: [2]u8 = .{ 0, 0 },
    dhcp_configured: u32,
    dhcp_lease_secs: u32,
    nic_present: u32,
};

/// Pull the current network configuration into `out`. Returns 0 on
/// success, E_FAULT on bad pointer. Static fields like `mac` are stable
/// for the lifetime of the kernel; `local_ip`/`gateway_ip`/`dns_ip` may
/// change on DHCP renewal (none today, but planned).
pub fn netInfo(out: *NetInfo) u32 {
    return syscall(106, @truncate(@intFromPtr(out)), 0);
}

// --- Configuration ---

pub const Config = struct {
    pub const resolution: u32 = 0;
    pub const background: u32 = 1;
    pub const theme: u32 = 2;
    pub const mouse_speed: u32 = 3;
    pub const dock_pos: u32 = 4;
};

pub fn setConfig(key: u32, value: u32) void {
    _ = syscall(19, key, value);
}

pub fn applyConfig() void {
    _ = syscall(19, 255, 0);
}

pub fn notify(text: []const u8) void {
    _ = syscall(20, @truncate(@intFromPtr(text.ptr)), @as(u32, @intCast(text.len)));
}

// --- File listing and exec ---

/// Bit layout for `FileEntry.flags`. Filesystems set the from_* bit that
/// matches their backing fs plus is_elf for `.elf` names + is_directory
/// when the entry is a directory.
pub const FE_FLAG_IS_ELF: u8 = 0x01;
pub const FE_FLAG_IS_DIR: u8 = 0x02;
pub const FE_FLAG_FROM_FAT32: u8 = 0x04;
pub const FE_FLAG_FROM_EXT2: u8 = 0x08;
pub const FE_FLAG_FROM_TARFS: u8 = 0x10;

pub const FileEntry = extern struct {
    name: [32]u8,
    name_len: u8,
    file_size: u32 align(1),
    flags: u8,
    _pad: [10]u8,
};

pub fn listdir(buf: []FileEntry) u32 {
    const ptr: u32 = @truncate(@intFromPtr(buf.ptr));
    const size = @as(u32, @intCast(buf.len)) * @sizeOf(FileEntry);
    const result = syscall(21, ptr, size);
    if (result == 0xFFFFFFFF) return 0;
    return result;
}

/// Path-aware variant of `listdir`. `path` must be NUL-terminatable (ends up
/// in a 256-byte stack buffer); pass an absolute path or a path relative to
/// the current cwd. Returns the number of entries written, 0 on error.
pub fn readdir(path: []const u8, buf: []FileEntry) u32 {
    if (path.len == 0 or path.len > 254) return 0;
    var pbuf: [256]u8 = undefined;
    @memcpy(pbuf[0..path.len], path);
    pbuf[path.len] = 0;
    const bsize = @as(u32, @intCast(buf.len)) * @sizeOf(FileEntry);
    const result = syscall3(42, @truncate(@intFromPtr(&pbuf)), @truncate(@intFromPtr(buf.ptr)), bsize);
    if (result == 0xFFFFFFFF) return 0;
    return result;
}

pub fn exec(name: []const u8) u32 {
    return syscall(22, @truncate(@intFromPtr(name.ptr)), @as(u32, @intCast(name.len)));
}

pub fn getExecArg(buf: []u8) u32 {
    return syscall(25, @truncate(@intFromPtr(buf.ptr)), 0);
}

/// Number of argv entries the kernel populated, INCLUDING argv[0] (the
/// program name). Read once at startup; user args are at argv[1..argc].
pub fn getArgc() u32 {
    return syscall(55, 0, 0);
}

/// Copy argv[idx] into `buf` and return its length. Returns 0xFFFFFFFF if
/// `idx >= argc`. Truncates silently if the arg is longer than `buf` —
/// callers should pass at least MAX_ARG_LEN (32) bytes.
pub fn getArgv(idx: u32, buf: []u8) u32 {
    return syscall3(56, idx, @truncate(@intFromPtr(buf.ptr)), @intCast(buf.len));
}

/// Query if a PS/2 scancode key is currently held down.
/// Common scancodes: W=0x11, A=0x1E, S=0x1F, D=0x20, Space=0x39
/// Up=0x48, Down=0x50, Left=0x4B, Right=0x4D
pub fn keyHeld(scancode: u8) bool {
    return syscall(26, scancode, 0) != 0;
}

pub fn setCursorVisible(visible: bool) void {
    _ = syscall(27, @intFromBool(visible), 0);
}

pub fn centerMouse() void {
    _ = syscall(28, 0, 0);
}

/// Write 16-bit signed stereo PCM samples to the audio device (22050 Hz).
pub fn audioWrite(samples: [*]const i16, num_stereo_samples: u32) bool {
    return syscall(38, @truncate(@intFromPtr(samples)), num_stereo_samples) == 0;
}

pub fn fsize(name: []const u8) ?u32 {
    if (name.len == 0) return null;
    var buf: [100]u8 = undefined;
    const copy_len = if (name.len > 99) @as(usize, 99) else name.len;
    @memcpy(buf[0..copy_len], name[0..copy_len]);
    buf[copy_len] = 0;
    const result = syscall(29, @truncate(@intFromPtr(&buf)), 0);
    if (result == 0xFFFFFFFF) return null;
    return result;
}

// --- GPU 3D API ---

pub fn gpuCtxCreate(capset_id: u32) ?u32 {
    const result = syscall(30, capset_id, 0);
    if (result == 0xFFFFFFFF) return null;
    return result;
}

pub fn gpuSubmit3D(buf: []const u8) bool {
    return syscall(31, @truncate(@intFromPtr(buf.ptr)), @truncate(buf.len)) == 0;
}

pub fn gpuCtxDestroy() void {
    _ = syscall(32, 0, 0);
}

pub fn gpuGetCapsetInfo(index: u32, out: *[3]u32) bool {
    return syscall(33, index, @truncate(@intFromPtr(out))) == 0;
}

pub fn gpuCreateBlob(blob_mem: u32, size: u32) ?u32 {
    const result = syscall(34, blob_mem, size);
    if (result == 0xFFFFFFFF) return null;
    return result;
}

/// Create a blob resource with a specific blob_id (for VkDeviceMemory-backed blobs).
/// blob_id connects the blob to a Venus VkDeviceMemory handle.
pub fn gpuCreateBlobWithId(blob_mem: u32, size: u32, blob_id: u32) ?u32 {
    const result = syscall3(34, blob_mem, size, blob_id);
    if (result == 0xFFFFFFFF) return null;
    return result;
}

/// Create a 3D resource (texture). params = [target, format, bind, width, height]
pub fn gpuResourceCreate3D(params: *const [5]u32) ?u32 {
    const result = syscall(35, @truncate(@intFromPtr(params)), 0);
    if (result == 0xFFFFFFFF) return null;
    return result;
}

/// Transfer 3D resource to host. params = [width, height, stride]
pub fn gpuTransferToHost3D(resource_id: u32, params: *const [3]u32) bool {
    return syscall(36, resource_id, @truncate(@intFromPtr(params))) == 0;
}

/// Transfer 3D resource FROM host back to guest. Used to read pixels
/// rendered by Lavapipe (or any host 3D backend) into a guest-mmapped
/// blob — the explicit readback path when auto-dmabuf-sharing isn't
/// engaged. Call after vkDeviceWaitIdle, before reading mapped pixels.
/// params = [width, height, stride]
pub fn gpuTransferFromHost3D(resource_id: u32, params: *const [3]u32) bool {
    return syscall(87, resource_id, @truncate(@intFromPtr(params))) == 0;
}

/// Point a scanout slot at a blob resource — display Vulkan-rendered
/// content directly without a CPU readback round-trip. Hijacks the
/// scanout slot (other content on that slot becomes invisible). Call
/// once during setup, then push frames via gpuResourceFlush.
/// params = [scanout_id, width, height, format, stride]
pub fn gpuSetScanoutBlob(resource_id: u32, params: *const [5]u32) bool {
    return syscall(88, resource_id, @truncate(@intFromPtr(params))) == 0;
}

/// Force a re-display of a scanned-out resource. Call after each render
/// pass once setScanoutBlob is wired. params = [width, height]
pub fn gpuResourceFlush(resource_id: u32, params: *const [2]u32) bool {
    return syscall(89, resource_id, @truncate(@intFromPtr(params))) == 0;
}

/// Allocate guest physical pages, create a BLOB_MEM_GUEST virtio-gpu
/// resource backed by them, and map the pages into user space. The
/// returned pointer is the user VA where pages are mapped; the
/// resource_id is written to `out_resource_id` so it can be passed to
/// Venus `encodeAllocateMemoryImport` to make Lavapipe's VkDeviceMemory
/// share those same pages. This is the working path for getting
/// Vulkan-rendered pixels back to the guest.
pub fn gpuCreateGuestBlob(size: u32, out_resource_id: *u32) ?[*]volatile u8 {
    const result = syscall(91, size, @truncate(@intFromPtr(out_resource_id)));
    if (result == 0xFFFFFFFF) return null;
    return @ptrFromInt(result);
}

/// Map a blob resource into user address space. Returns pointer to mapped memory.
pub fn gpuMapBlob(resource_id: u32, size: u32) ?[*]volatile u8 {
    const result = syscall(37, resource_id, size);
    if (result == 0xFFFFFFFF) return null;
    return @ptrFromInt(result);
}

pub const O_CREATE: u32 = 0x100;
pub const O_TRUNC: u32 = 0x200;
pub const O_APPEND: u32 = 0x400;

pub fn openFlags(name: []const u8, flags: u32) ?u32 {
    if (name.len == 0) return null;
    var buf: [100]u8 = undefined;
    const copy_len = if (name.len > 99) @as(usize, 99) else name.len;
    @memcpy(buf[0..copy_len], name[0..copy_len]);
    buf[copy_len] = 0;
    const result = syscall(9, @truncate(@intFromPtr(&buf)), flags);
    if (result == 0xFFFFFFFF) return null;
    return result;
}

pub const ScreenSize = struct { w: u32, h: u32 };
pub fn getScreenSize() ScreenSize {
    var buf: [2]u32 align(4) = undefined;
    _ = syscall(23, @truncate(@intFromPtr(&buf)), 0);
    return .{ .w = buf[0], .h = buf[1] };
}

pub const WindowSize = struct { w: u32, h: u32 };
pub fn getWindowSize() WindowSize {
    var buf: [2]u32 align(4) = undefined;
    _ = syscall(24, @truncate(@intFromPtr(&buf)), 0);
    return .{ .w = buf[0], .h = buf[1] };
}

pub const WindowAlloc = struct { w: u32, h: u32 };
/// Current framebuffer allocation = (stride width in px, rows). The compositor
/// can GROW this past what we requested at create time (F10 maximize) so the
/// app renders crisply instead of being upscaled. Re-fetch on a `.resize`
/// event and rebuild your canvas with `w` as the row stride.
pub fn getWindowAlloc() WindowAlloc {
    var buf: [2]u32 align(4) = undefined;
    _ = syscall(112, @truncate(@intFromPtr(&buf)), 0);
    return .{ .w = buf[0], .h = buf[1] };
}

// --- Heap allocator: thread-safe boundary-tag with magic-protected blocks --
//
// Each allocation is preceded by a 16-byte Block header carrying:
//   - this block's size (multiple of 16, includes header)
//   - a magic word (MAGIC_ALLOC when in-use, MAGIC_FREE when on the free list)
//   - the preceding block's size (Knuth boundary tag — backward coalesce is
//     O(1): on free we look at `prev_size` instead of walking from heap_start)
//
// Thread safety: `heap_lock` (Mutex) wraps every public API. Uncontended path
// is a single atomic CAS; contended falls into the futex.
//
// Block magic is the main corruption canary. `free()` validates it before
// touching anything, catching:
//   - free(ptr_not_from_malloc): random memory rarely has MAGIC_ALLOC at -16
//   - free(ptr + offset): mid-block frees, rejected by the alignment check
//   - free(ptr); free(ptr): second free sees MAGIC_FREE, returns silently
//   - buffer overflow scribbling the next block's header: magic mismatch
//
// Allocation policy is next-fit-with-hint: each malloc starts the free-list
// scan from where the last successful alloc landed, wrapping at heap_end.
// Spreads allocations out (reduces fragmentation vs first-fit) and skips
// the "long prefix of used blocks" walk-cost as the heap fills.
//
// realloc tries three strategies before fall-back:
//   1. Already big enough → shrink in place + split remainder
//   2. Next block is free and combined size fits → merge in place
//   3. malloc + memcpy + free
// All three run under a single heap_lock acquire so the source bytes can't
// be racily reused between the strategy-3 malloc and free.

const BLOCK_MAGIC_ALLOC: u32 = 0xA110_CA7E; // "ALLOCATE"
const BLOCK_MAGIC_FREE: u32 = 0xFEED_5EED; // "FEED-SEED"

/// Pattern written into freed payload when HEAP_DEBUG_FILL is true. 0xDD
/// catches use-after-free by ensuring re-reads of freed data return junk
/// rather than the previously-stored value. Off by default — adds a memset
/// per free.
const FREE_FILL: u8 = 0xDD;
const HEAP_DEBUG_FILL: bool = false;

const Block = extern struct {
    size: u32, // total block size including this 16-byte header (multiple of 16)
    magic: u32, // BLOCK_MAGIC_ALLOC or BLOCK_MAGIC_FREE; 0 on a defensively-invalidated block
    prev_size: u32, // size of preceding block in the same sbrk chunk; 0 = first
    _pad: u32 = 0,
};
const HEADER_SIZE: usize = @sizeOf(Block); // 16 bytes
const MIN_SPLIT: usize = HEADER_SIZE + 16; // don't split if remainder smaller

pub const HeapStats = extern struct {
    used_bytes: u64,
    free_bytes: u64,
    total_bytes: u64,
    blocks: u32,
};

var heap_start: usize = 0; // address of first block (set on first sbrk)
var heap_end: usize = 0; // one past last block (== sbrk top)
var heap_hint: usize = 0; // next-fit cursor; wraps to heap_start at heap_end
var heap_lock: Mutex = .{};
var heap_used: usize = 0;
var heap_free: usize = 0;
var heap_blocks: u32 = 0;

inline fn alignUp(x: usize, a: usize) usize {
    return (x + a - 1) & ~(a - 1);
}

/// After a block at `addr` changes size (split, merge, etc.), update the
/// `prev_size` field of whichever block now follows it so the boundary tag
/// stays consistent.
inline fn linkPrevSize(addr: usize, new_size: u32) void {
    const after = addr + new_size;
    if (after < heap_end) {
        const next: *Block = @ptrFromInt(after);
        next.prev_size = new_size;
    }
}

/// Validate a user-supplied pointer and return the matching Block, or null
/// if it's clearly not a live allocation. Catches OOB pointers, mid-block
/// frees, double-frees (MAGIC_FREE), and non-malloc pointers (random magic).
inline fn blockFromUser(user_addr: usize) ?*Block {
    if (user_addr < heap_start + HEADER_SIZE or user_addr >= heap_end) return null;
    if ((user_addr & 15) != 0) return null; // malloc payloads are always 16-aligned
    const block: *Block = @ptrFromInt(user_addr - HEADER_SIZE);
    if (block.magic != BLOCK_MAGIC_ALLOC) return null;
    return block;
}

fn growHeap(min_bytes: usize) ?usize {
    const min_request: usize = 65536;
    const raw = if (min_bytes < min_request) min_request else min_bytes;
    const request = alignUp(raw, 4096);
    const ptr = sbrk(@intCast(request)) orelse return null;
    const addr = @intFromPtr(ptr);
    if (heap_start == 0) {
        heap_start = addr;
        heap_hint = addr;
    }
    // Head of new sbrk chunk: prev_size = 0. We don't try to coalesce across
    // gaps between sbrk chunks — current sbrk impl makes them contiguous in
    // practice, but the safe behavior is to treat each chunk as its own
    // boundary-tag chain.
    const block: *Block = @ptrFromInt(addr);
    block.* = .{ .size = @intCast(request), .magic = BLOCK_MAGIC_FREE, .prev_size = 0 };
    heap_end = addr + request;
    heap_free += request;
    heap_blocks += 1;
    return addr;
}

fn mallocLocked(size: usize) ?[*]u8 {
    if (size == 0) return null;
    const need = alignUp(size, 16) + HEADER_SIZE;

    // Next-fit pass 1: start from hint, sweep to heap_end.
    var addr = if (heap_hint != 0) heap_hint else heap_start;
    while (addr != 0 and addr < heap_end) {
        const block: *Block = @ptrFromInt(addr);
        if (block.size == 0) break; // corrupted; bail to grow path rather than spin
        if (block.magic == BLOCK_MAGIC_FREE and block.size >= need) {
            return claimBlock(addr, need);
        }
        addr += block.size;
    }
    // Pass 2: wrap from heap_start to original hint.
    addr = heap_start;
    while (addr != 0 and addr < heap_hint) {
        const block: *Block = @ptrFromInt(addr);
        if (block.size == 0) break;
        if (block.magic == BLOCK_MAGIC_FREE and block.size >= need) {
            return claimBlock(addr, need);
        }
        addr += block.size;
    }

    // No fit — grow.
    const new_addr = growHeap(need) orelse return null;
    return claimBlock(new_addr, need);
}

pub fn malloc(size: usize) ?[*]u8 {
    heap_lock.lock();
    defer heap_lock.unlock();
    return mallocLocked(size);
}

fn claimBlock(addr: usize, need: usize) [*]u8 {
    const block: *Block = @ptrFromInt(addr);
    const original_size = block.size;
    if (original_size >= need + MIN_SPLIT) {
        const next_addr = addr + need;
        const next_block: *Block = @ptrFromInt(next_addr);
        next_block.* = .{
            .size = original_size - @as(u32, @intCast(need)),
            .magic = BLOCK_MAGIC_FREE,
            .prev_size = @intCast(need),
        };
        block.size = @intCast(need);
        linkPrevSize(next_addr, next_block.size);
        heap_blocks += 1;
    }
    block.magic = BLOCK_MAGIC_ALLOC;
    heap_used += block.size;
    heap_free -= block.size;
    heap_hint = addr + block.size;
    if (heap_hint >= heap_end) heap_hint = heap_start;
    return @ptrFromInt(addr + HEADER_SIZE);
}

fn freeLocked(ptr: ?[*]u8) void {
    const p = ptr orelse return;
    const user_addr = @intFromPtr(p);
    var block = blockFromUser(user_addr) orelse return; // bad ptr, double-free, or corruption
    var block_addr = user_addr - HEADER_SIZE;

    block.magic = BLOCK_MAGIC_FREE;
    heap_used -= block.size;
    heap_free += block.size;

    if (HEAP_DEBUG_FILL) {
        const payload: [*]u8 = @ptrFromInt(user_addr);
        @memset(payload[0 .. block.size - HEADER_SIZE], FREE_FILL);
    }

    // Forward coalesce (this block + immediately-following block, if free).
    const next_addr = block_addr + block.size;
    if (next_addr < heap_end) {
        const next_block: *Block = @ptrFromInt(next_addr);
        if (next_block.magic == BLOCK_MAGIC_FREE) {
            block.size += next_block.size;
            next_block.magic = 0; // defensive: kill the absorbed header
            heap_blocks -= 1;
            if (heap_hint == next_addr) heap_hint = block_addr;
        }
    }

    // Backward coalesce — O(1) via boundary tag.
    if (block.prev_size != 0) {
        const prev_addr = block_addr - block.prev_size;
        const prev_block: *Block = @ptrFromInt(prev_addr);
        if (prev_block.magic == BLOCK_MAGIC_FREE) {
            prev_block.size += block.size;
            block.magic = 0; // defensive
            heap_blocks -= 1;
            if (heap_hint == block_addr) heap_hint = prev_addr;
            block_addr = prev_addr;
            block = prev_block;
        }
    }

    linkPrevSize(block_addr, block.size);
}

pub fn free(ptr: ?[*]u8) void {
    heap_lock.lock();
    defer heap_lock.unlock();
    freeLocked(ptr);
}

/// Return trailing free heap pages to the kernel (sbrk(-N)). If the
/// final block is FREE and big enough, asks the kernel to unmap the
/// trailing pages and shortens our heap_end to match. `keep_bytes`
/// leaves that much slack at the end to avoid thrashing on small
/// re-grows; pass 0 to give back as much as possible. Returns the
/// number of bytes returned to the kernel.
pub fn malloc_trim(keep_bytes: usize) usize {
    heap_lock.lock();
    defer heap_lock.unlock();
    if (heap_start == 0 or heap_end <= heap_start) return 0;
    // Boundary-tag layout is contiguous — a single forward walk finds
    // the last block.
    var addr: usize = heap_start;
    var last_addr: usize = 0;
    while (addr < heap_end) {
        const blk: *Block = @ptrFromInt(addr);
        if (blk.size == 0) return 0; // corruption guard — bail out
        last_addr = addr;
        addr += blk.size;
    }
    if (last_addr == 0) return 0;
    const last: *Block = @ptrFromInt(last_addr);
    if (last.magic != BLOCK_MAGIC_FREE) return 0;
    // Snapshot the header NOW: in consume_whole the header itself sits in
    // the about-to-be-unmapped range, so any read after sbrkShrink would
    // page-fault. Bug surfaced 2026-05-25 — pid=4 settings crashed on
    // `heap_free -= last.size` immediately after a shrink fully consumed
    // the tail block.
    const last_size: usize = last.size;
    if (last_size <= keep_bytes + 4096) return 0;

    // Pick the largest page-aligned amount we can release while leaving
    // either zero residual (consume the whole block) or a residual that
    // is still a valid block (>= HEADER_SIZE).
    var trim_bytes: usize = (last_size - keep_bytes) & ~@as(usize, 4095);
    if (trim_bytes < 4096) return 0;
    var consume_whole = false;
    var residual = last_size - trim_bytes;
    if (residual == 0) {
        consume_whole = true;
    } else if (residual < HEADER_SIZE) {
        // Back off one page so the residual is a sane size, or consume
        // the whole block if that's not possible.
        if (trim_bytes >= 4096) {
            trim_bytes -= 4096;
            residual = last_size - trim_bytes;
            if (trim_bytes == 0) return 0;
        } else {
            return 0;
        }
    }

    const new_end = heap_end - trim_bytes;
    // Update bookkeeping BEFORE the shrink so we never need to re-read
    // the block header (which may be in the released range).
    if (consume_whole) {
        heap_free -= last_size;
        heap_blocks -= 1;
        if (heap_hint >= new_end) heap_hint = heap_start;
    } else {
        // Partial trim: residual > 0 means last_addr < new_end, so the
        // header stays mapped. Write the new size now anyway — keeps
        // the "no post-shrink reads" invariant tidy.
        last.size = @intCast(residual);
        heap_free -= trim_bytes;
    }
    heap_end = new_end;
    if (heap_hint >= heap_end) heap_hint = heap_start;

    if (!sbrkShrink(@intCast(trim_bytes))) {
        // Rollback — kernel refused (shouldn't happen given we validated)
        // but stay correct if it does.
        if (consume_whole) {
            heap_free += last_size;
            heap_blocks += 1;
        } else {
            last.size = @intCast(last_size);
            heap_free += trim_bytes;
        }
        heap_end += trim_bytes;
        return 0;
    }
    return trim_bytes;
}

/// Return the usable payload size for `ptr` (i.e. block.size - header).
/// Returns 0 for null or invalid pointers (silent — caller's responsibility
/// to know what they passed).
pub fn malloc_usable_size(ptr: ?[*]u8) usize {
    const p = ptr orelse return 0;
    const user_addr = @intFromPtr(p);
    heap_lock.lock();
    defer heap_lock.unlock();
    const block = blockFromUser(user_addr) orelse return 0;
    return block.size - HEADER_SIZE;
}

/// Snapshot of current heap state. Consistent under heap_lock.
pub fn malloc_stats() HeapStats {
    heap_lock.lock();
    defer heap_lock.unlock();
    return .{
        .used_bytes = heap_used,
        .free_bytes = heap_free,
        .total_bytes = heap_end - heap_start,
        .blocks = heap_blocks,
    };
}

pub fn calloc(nmemb: usize, size: usize) ?[*]u8 {
    const total = nmemb * size;
    const ptr = malloc(total) orelse return null;
    @memset(ptr[0..total], 0);
    return ptr;
}

pub fn realloc(old_ptr: ?[*]u8, new_size: usize) ?[*]u8 {
    if (new_size == 0) {
        free(old_ptr);
        return null;
    }
    const old = old_ptr orelse return malloc(new_size);
    const old_user_addr = @intFromPtr(old);

    heap_lock.lock();
    defer heap_lock.unlock();

    const block = blockFromUser(old_user_addr) orelse return null;
    const need = alignUp(new_size, 16) + HEADER_SIZE;
    const block_addr = old_user_addr - HEADER_SIZE;

    // Strategy 1: shrink in place.
    if (block.size >= need) {
        if (block.size >= need + MIN_SPLIT) {
            const remainder_addr = block_addr + need;
            const remainder: *Block = @ptrFromInt(remainder_addr);
            remainder.* = .{
                .size = block.size - @as(u32, @intCast(need)),
                .magic = BLOCK_MAGIC_FREE,
                .prev_size = @intCast(need),
            };
            linkPrevSize(remainder_addr, remainder.size);
            heap_used -= remainder.size;
            heap_free += remainder.size;
            heap_blocks += 1;
            block.size = @intCast(need);
        }
        return @ptrFromInt(old_user_addr);
    }

    // Strategy 2: merge with next free block if combined fits.
    const next_addr = block_addr + block.size;
    if (next_addr < heap_end) {
        const next_block: *Block = @ptrFromInt(next_addr);
        if (next_block.magic == BLOCK_MAGIC_FREE and block.size + next_block.size >= need) {
            const absorbed_size = next_block.size;
            const merged_size = block.size + absorbed_size;
            heap_used += absorbed_size;
            heap_free -= absorbed_size;
            heap_blocks -= 1;
            next_block.magic = 0; // defensive
            block.size = merged_size;
            if (block.size >= need + MIN_SPLIT) {
                const remainder_addr = block_addr + need;
                const remainder: *Block = @ptrFromInt(remainder_addr);
                remainder.* = .{
                    .size = block.size - @as(u32, @intCast(need)),
                    .magic = BLOCK_MAGIC_FREE,
                    .prev_size = @intCast(need),
                };
                linkPrevSize(remainder_addr, remainder.size);
                heap_used -= remainder.size;
                heap_free += remainder.size;
                heap_blocks += 1;
                block.size = @intCast(need);
            } else {
                linkPrevSize(block_addr, block.size);
            }
            return @ptrFromInt(old_user_addr);
        }
    }

    // Strategy 3: malloc + memcpy + freeLocked. We hold heap_lock across the
    // entire op so the source bytes can't be racily reused between the
    // mallocLocked and freeLocked calls — `old` stays valid until we say so.
    const old_payload = block.size - HEADER_SIZE;
    const new_ptr = mallocLocked(new_size) orelse return null;
    const copy_len = if (old_payload < new_size) old_payload else new_size;
    @memcpy(new_ptr[0..copy_len], old[0..copy_len]);
    freeLocked(old);
    return new_ptr;
}

// --- New filesystem syscalls ---

/// Create a directory (syscall 41). Path must be NUL-terminatable; max 254.
pub fn mkdir(path: []const u8) bool {
    if (path.len == 0 or path.len > 254) return false;
    var buf: [256]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return syscall(41, @truncate(@intFromPtr(&buf)), 0) == 0;
}

/// Power off (mode 0) or reboot (mode 1) the machine (syscall 82). The
/// kernel flushes filesystem caches, then writes ACPI/PCI reset ports.
/// On a successful poweroff this never returns; on failure (e.g. a
/// platform we don't have a magic port for) the kernel halts and this
/// call effectively hangs the calling process.
pub fn shutdown(mode: u32) void {
    _ = syscall(82, mode, 0);
}

/// Delete a file (syscall 43)
pub fn unlink(path: []const u8) bool {
    if (path.len == 0 or path.len > 256) return false;
    const result = syscall(43, @truncate(@intFromPtr(path.ptr)), @intCast(path.len));
    return result == 0;
}

/// Get file metadata (syscall 44)
pub const FileStat = struct {
    file_size: u32,
    is_directory: u32,
    create_time: u32,
    modify_time: u32,
};

pub fn stat(path: []const u8, stat_buf: *FileStat) bool {
    if (path.len == 0 or path.len > 256) return false;
    const result = syscall3(44, @truncate(@intFromPtr(path.ptr)), @intCast(path.len), @truncate(@intFromPtr(stat_buf)));
    return result == 0;
}

/// Rename/move a file (syscall 45)
pub fn rename(old_path: []const u8, new_path: []const u8) bool {
    if (old_path.len == 0 or old_path.len > 256) return false;
    if (new_path.len == 0 or new_path.len > 256) return false;

    // Pack new path: u32 length + bytes
    var buf: [260]u8 align(4) = undefined;
    const len_ptr: *u32 = @ptrCast(@alignCast(&buf[0]));
    len_ptr.* = @intCast(new_path.len);
    @memcpy(buf[4..][0..new_path.len], new_path);

    const result = syscall3(45, @truncate(@intFromPtr(old_path.ptr)), @intCast(old_path.len), @truncate(@intFromPtr(&buf)));
    return result == 0;
}

/// Remove empty directory (syscall 46)
pub fn rmdir(path: []const u8) bool {
    if (path.len == 0 or path.len > 256) return false;
    const result = syscall(46, @truncate(@intFromPtr(path.ptr)), @intCast(path.len));
    return result == 0;
}

// --- Process tree + IPC (Task #73) ---

/// One entry of the fd_remap array passed to execAs. parent_fd = 0xFF marks
/// the end of the array (sentinel). Layout matches the kernel's FdRemap.
pub const FdRemap = extern struct {
    parent_fd: u8,
    child_fd: u8,
    _pad: u16 = 0,
};

pub const SIGTERM: u32 = 15;
pub const SIGKILL: u32 = 9;
pub const WAIT_ANY: u32 = 0xFFFFFFFF;

/// exit(status) — like exit() but records `status` for the parent's waitpid.
/// Existing exit() (syscall 3) keeps working with status = 0.
pub fn exitWith(status: u32) noreturn {
    _ = syscall(48, status, 0);
    unreachable;
}

/// waitpid(pid, *status) — block until child `pid` exits (or any child if
/// pid == WAIT_ANY). Returns the reaped child's pid, or 0xFFFFFFFF if the
/// caller has no such child.
pub fn waitpid(pid: u32, status: ?*u32) u32 {
    const sp = if (status) |p| @intFromPtr(p) else 0;
    return syscall(49, pid, @truncate(sp));
}

/// fork() — clone the calling process. Parent receives the child's PID; child
/// receives 0. Both sides resume at the instruction after this call with
/// independent (copy-on-write) address spaces. Returns 0xFFFFFFFA (E_AGAIN)
/// on resource shortage (process table full / OOM during clone).
pub fn fork() u32 {
    return syscall(92, 0, 0);
}

// --- Sessions / process groups ---------------------------------------------

/// setsid() — promote the caller to leader of a new session and process
/// group. Returns the new sid (== caller's pid) on success, 0xFFFFFFE7
/// (E_PERM) if the caller is already a process group leader. Daemons
/// invoke this in the middle of a double-fork; see `daemon()`.
pub fn setsid() u32 {
    return syscall(93, 0, 0);
}

/// setpgid(pid, pgid) — move process `pid` (or self if 0) into group
/// `pgid` (or a fresh group named after pid if 0). Returns 0 on success.
pub fn setpgid(pid: u32, pgid: u32) u32 {
    return syscall(94, pid, pgid);
}

/// getpgrp() — caller's current process group id.
pub fn getpgrp() u32 {
    return syscall(95, 0, 0);
}

/// getpgid(pid) — process `pid`'s pgid (or self if pid==0).
pub fn getpgid(pid: u32) u32 {
    return syscall(96, pid, 0);
}

/// getsid(pid) — process `pid`'s session id (or self if pid==0).
pub fn getsid(pid: u32) u32 {
    return syscall(97, pid, 0);
}

/// Set the desktop wallpaper to the given RGBA-packed image. `pixels` is
/// `w * h` u32 entries in B8G8R8A8 format (matches the screen FB layout —
/// callers decoding from stb_image's R,G,B,A bytes need to repack as
/// `(R << 16) | (G << 8) | B` per pixel before calling). Pass
/// `setWallpaperClear()` to revert to gradient. Returns true on success.
pub fn setWallpaper(pixels: [*]const u32, w: u32, h: u32) bool {
    return syscall3(98, @truncate(@intFromPtr(pixels)), w, h) == 0;
}

pub fn setWallpaperClear() bool {
    return syscall3(98, 0, 0, 0) == 0;
}

/// daemon(nochdir, noclose) — turn the calling process into a daemon via
/// the classic double-fork:
///   1. fork; if we got a child PID, parent exits cleanly. The first
///      fork detaches us from the shell's foreground process group.
///   2. setsid in the child — escapes the shell's session, no
///      controlling terminal afterwards.
///   3. fork again; the middle child exits. The grandchild can no
///      longer re-acquire a controlling terminal because it's not a
///      session leader (only session leaders can).
///   4. (Optional) chdir("/") so the daemon doesn't pin a mount point.
///   5. (Optional) close fd 0/1/2 — currently a no-op stub since we
///      don't have /dev/null. The kernel inherits whatever stdio the
///      shell handed us; once init takes over (Phase 3+), it'll spawn
///      daemons with stdio redirected to /dev/null or /var/log/messages.
///
/// Returns 0 on success in the daemonised grandchild. The first two
/// parents call exitWith(0) and never return. Returns 0xFFFFFFFF if any
/// fork fails.
pub fn daemon(nochdir: bool, noclose: bool) u32 {
    // First fork — parent exits, child is no longer a process group leader,
    // so the upcoming setsid() is allowed.
    const c1 = fork();
    if (c1 == 0xFFFFFFFF or c1 == 0xFFFFFFFA) return 0xFFFFFFFF;
    if (c1 != 0) exitWith(0);

    // We're the middle child. Detach from session/controlling terminal.
    _ = setsid();

    // Second fork — grandchild can never reacquire a controlling terminal.
    const c2 = fork();
    if (c2 == 0xFFFFFFFF or c2 == 0xFFFFFFFA) return 0xFFFFFFFF;
    if (c2 != 0) exitWith(0);

    if (!nochdir) _ = chdir("/");
    // noclose is honoured trivially today: with no /dev/null and no
    // logging daemon, redirecting fd 0/1/2 to "the void" would lose
    // diagnostics. When init lands, this branch will redirect to its
    // service log file. For now we leave stdio as inherited.
    _ = noclose;
    return 0;
}

/// kill(pid, sig) — post `sig` to `pid`. Goes through the kernel's signal
/// queue, so the target's installed handler runs (or default action takes
/// effect if SIG_DFL). pid == self IS allowed and behaves as raise(sig).
/// Returns 0 on success, 0xFFFFFFFF on bad inputs / dead target.
pub fn kill(pid: u32, sig: u32) u32 {
    return syscall(50, pid, sig);
}

/// raise(sig) — send `sig` to the calling process. Same as kill(getpid(), sig).
pub fn raise(sig: u32) u32 {
    return kill(getpid(), sig);
}

// --- POSIX signal API ---

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
// SIGKILL = 9 (defined above)
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
// SIGTERM = 15 (defined above)
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

pub const SA_RESTART: u32 = 0x10000000;
pub const SA_NODEFER: u32 = 0x40000000;
pub const SA_RESETHAND: u32 = 0x80000000;
/// When set, the kernel passes a populated `Siginfo` as the handler's
/// second arg (signature: `void(int, *Siginfo, *MContext)`). When clear,
/// the kernel passes NULL there — both signatures are SysV-compatible
/// because unused args land in caller-saved registers.
pub const SA_SIGINFO: u32 = 0x00000004;

/// Mirrors the kernel's `signals.Siginfo`. Apps requesting SA_SIGINFO get a
/// pointer to this as their 2nd arg. si_addr is the faulting VA for
/// SIGSEGV/SIGBUS/SIGFPE/SIGILL; si_pid is set by future kill() bookkeeping.
pub const Siginfo = extern struct {
    si_signo: u32,
    si_errno: u32,
    si_code: u32,
    _pad0: u32,
    si_pid: u32,
    si_uid: u32,
    si_addr: u64,
    si_status: u32,
    _pad1: u32,
};

// si_code values
pub const SI_USER: u32 = 0;
pub const SI_KERNEL: u32 = 0x80;
pub const SEGV_MAPERR: u32 = 1;
pub const SEGV_ACCERR: u32 = 2;
pub const ILL_ILLOPC: u32 = 1;
pub const FPE_INTDIV: u32 = 1;
pub const TRAP_BRKPT: u32 = 1;

pub const SIG_BLOCK: u32 = 0;
pub const SIG_UNBLOCK: u32 = 1;
pub const SIG_SETMASK: u32 = 2;

/// Layout matches the kernel's signals.SigAction. Handler fits a u64 because
/// user code lives in the lower 4GB but the kernel stores it as 64 bits to
/// keep the struct ABI stable across a future high-memory load.
pub const SigAction = extern struct {
    handler: u64 = SIG_DFL,
    flags: u32 = 0,
    mask: u32 = 0,
    /// Set automatically by `sigaction()` if zero — points at __sigreturn,
    /// the libc trampoline that issues the sigreturn syscall when the
    /// handler returns. Apps almost never override this.
    restorer: u64 = 0,
};

/// Naked sigreturn trampoline. The kernel pushes &__sigreturn as the handler's
/// return address; on `ret` from the handler we land here, the user RSP points
/// at the saved MContext (placed by the kernel above this RA), and we issue
/// syscall #62 which rewrites the kernel-stack frame so sysret resumes pre-
/// signal user state. Naked because we MUST NOT touch RSP or any GPR before
/// the syscall — those are the values that need to be restored.
pub fn __sigreturn() callconv(.naked) noreturn {
    asm volatile (
        \\ movl $62, %%eax
        \\ syscall
        \\ ud2
    );
}

/// sigaction(signum, &new, &old) — install a handler. `new` may be null to
/// just read the existing disposition; `old` may be null to discard. Returns
/// 0 on success. SIGKILL/SIGSTOP can't be installed but reading their slot
/// works fine (returns the default action). If `new.restorer == 0`, this
/// function patches it to point at __sigreturn — apps almost never need to
/// override the trampoline.
pub fn sigaction(signum: u32, new: ?*const SigAction, old: ?*SigAction) u32 {
    var patched: SigAction = undefined;
    var new_ptr: u32 = 0;
    if (new) |n| {
        patched = n.*;
        if (patched.handler != SIG_DFL and patched.handler != SIG_IGN and patched.restorer == 0) {
            patched.restorer = @intFromPtr(&__sigreturn);
        }
        new_ptr = @truncate(@intFromPtr(&patched));
    }
    const old_ptr: u32 = if (old) |o| @truncate(@intFromPtr(o)) else 0;
    return syscall3(60, signum, new_ptr, old_ptr);
}

/// signal(signum, handler) — BSD-style convenience wrapper. Installs `handler`
/// with empty mask + flags=SA_RESETHAND (one-shot, the way classic `signal()`
/// has always behaved on most Unixes). Returns the previous handler, or
/// SIG_DFL if there was none. Use sigaction() for anything fancier.
pub fn signal(signum: u32, handler: u64) u64 {
    var new: SigAction = .{ .handler = handler, .flags = SA_RESETHAND };
    new.restorer = @intFromPtr(&__sigreturn);
    var old: SigAction = .{};
    if (sigaction(signum, &new, &old) != 0) return SIG_DFL;
    return old.handler;
}

/// sigprocmask(how, &set, &oldset) — block, unblock, or replace the calling
/// process's signal mask. SIGKILL/SIGSTOP are silently stripped from `set`.
pub fn sigprocmask(how: u32, set: ?*const u32, oldset: ?*u32) u32 {
    const set_ptr: u32 = if (set) |s| @truncate(@intFromPtr(s)) else 0;
    const old_ptr: u32 = if (oldset) |o| @truncate(@intFromPtr(o)) else 0;
    return syscall3(61, how, set_ptr, old_ptr);
}

/// sigpending(&set) — write the bitmap of pending-but-blocked signals.
pub fn sigpending(set: *u32) u32 {
    return syscall(63, @truncate(@intFromPtr(set)), 0);
}

/// sigsuspend(&mask) — atomically replace mask + sleep until any non-blocked
/// signal arrives. Always returns 0xFFFFFFFF when interrupted (after the
/// handler runs).
pub fn sigsuspend(mask: *const u32) u32 {
    return syscall(64, @truncate(@intFromPtr(mask)), 0);
}

/// pause() — sleep until any signal is delivered.
pub fn pause() u32 {
    return syscall(65, 0, 0);
}

/// alarm(seconds) — schedule a SIGALRM after `seconds` seconds. Returns the
/// seconds remaining on the prior alarm (0 if none). seconds == 0 cancels.
pub fn alarm(seconds: u32) u32 {
    return syscall(66, seconds, 0);
}

/// klog(msg) — write `msg` directly to kernel serial with a [klog pid=N]
/// prefix, no fd lookup. Use for debug diagnostics in apps whose stdout is
/// piped to a terminal/desktop (so wouldn't otherwise reach serial.log).
/// Truncates at 256 bytes.
pub fn klog(msg: []const u8) void {
    if (msg.len == 0) return;
    _ = syscall(67, @truncate(@intFromPtr(msg.ptr)), @intCast(msg.len));
}

/// klogFmt — sprintf-then-klog for numeric diagnostics. Caps buffer at 256
/// (matches kernel side). Useful pattern: `klogFmt("frame={d} px={d}\n", .{f, p})`.
pub fn klogFmt(comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const written = std.fmt.bufPrint(&buf, fmt, args) catch return;
    klog(written);
}

/// pipe() — allocate a pipe and return [read_fd, write_fd]. Returns null on
/// failure (pipe pool full or fd_table full).
pub fn pipe() ?[2]u32 {
    var fds: [2]u32 = .{ 0, 0 };
    if (syscall(51, @truncate(@intFromPtr(&fds)), 0) != 0) return null;
    return fds;
}

/// execAs(name, remap) — like exec() but pre-populates a few of the child's
/// fd_table slots from the parent's. `remap` is a slice of FdRemap entries
/// (max 8); a sentinel is appended internally so the caller doesn't need one.
/// Used to wire a pipe end into the child's stdin/stdout for shell pipelines.
pub fn execAs(name: []const u8, remap: []const FdRemap) u32 {
    if (name.len == 0 or name.len > 100) return 0xFFFFFFFF;
    if (remap.len > 8) return 0xFFFFFFFF;

    var buf: [9]FdRemap = undefined;
    for (remap, 0..) |r, i| buf[i] = r;
    buf[remap.len] = .{ .parent_fd = 0xFF, .child_fd = 0xFF };

    return syscall3(
        52,
        @truncate(@intFromPtr(name.ptr)),
        @intCast(name.len),
        @truncate(@intFromPtr(&buf)),
    );
}

// --- Wall-clock time + microsecond sleep (Task #74) ---

/// Result of gettimeofday: Unix epoch seconds + microseconds within the
/// current second [0, 999999]. Same layout the kernel writes (16-byte buffer
/// with u64 sec + u32 usec + u32 padding).
pub const TimeOfDay = extern struct {
    sec: u64,
    usec: u32,
    _pad: u32 = 0,
};

/// Get current wall-clock time as { sec, usec } since the Unix epoch.
/// Combines an RTC-derived boot baseline with HPET sub-second precision —
/// monotonic across calls (HPET counter), tied to absolute time at boot.
pub fn gettimeofday() TimeOfDay {
    var t: TimeOfDay = .{ .sec = 0, .usec = 0 };
    _ = syscall(53, @truncate(@intFromPtr(&t)), 0);
    return t;
}

/// Sleep for `usec` microseconds. Sub-10ms sleeps are pure busy-wait via HPET
/// (no scheduling cost); longer sleeps deschedule down to the last ~5ms then
/// busy-wait for fine precision. Caller doesn't need to care which path runs.
pub fn usleep(usec: u32) void {
    _ = syscall(54, usec, 0);
}

// --- Networking ---
//
// Two synchronous, blocking helpers mapped onto the kernel's existing TCP/IP
// stack. There's no socket API here yet — apps that need raw TCP can grow
// one later. For now this covers `nslookup` and `wget`-shaped tools.

/// Parse a dotted-quad IPv4 address ("10.0.2.2") into a `[4]u8`, or null on
/// any malformed input — wrong octet count, non-digit chars, octet > 255.
/// Useful as a first-pass before falling back to `resolve()` for hostnames.
pub fn parseIp(s: []const u8) ?[4]u8 {
    var ip: [4]u8 = undefined;
    var octet: u32 = 0;
    var part: usize = 0;
    var digits: u8 = 0;
    for (s) |c| {
        if (c == '.') {
            if (digits == 0 or part >= 3) return null;
            ip[part] = @intCast(octet);
            part += 1;
            octet = 0;
            digits = 0;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            if (octet > 255) return null;
            digits += 1;
            if (digits > 3) return null;
        } else {
            return null;
        }
    }
    if (digits == 0 or part != 3) return null;
    ip[3] = @intCast(octet);
    return ip;
}

/// Resolve `hostname` to an IPv4 address via the DNS server configured by the
/// kernel (10.0.2.3 under QEMU user-mode networking). Returns null on any
/// failure: empty / overlong hostname, network not initialized, no answer.
pub fn resolve(hostname: []const u8) ?[4]u8 {
    if (hostname.len == 0 or hostname.len > 255) return null;
    var ip: [4]u8 = undefined;
    const result = syscall3(
        68,
        @truncate(@intFromPtr(hostname.ptr)),
        @intCast(hostname.len),
        @truncate(@intFromPtr(&ip)),
    );
    if (result == 0xFFFFFFFF) return null;
    return ip;
}

/// Synchronous HTTP/1.0 GET. The full response — status line, headers, body —
/// is copied verbatim into `response_buf`; the byte count is returned. Returns
/// null on parse error / DNS failure / connect failure / 10s timeout.
///
/// Body finding is the caller's job: scan for the `\r\n\r\n` header terminator.
pub fn httpGet(url: []const u8, response_buf: []u8) ?usize {
    if (url.len == 0 or url.len > 1024) return null;
    if (response_buf.len == 0) return null;

    const HttpReq = extern struct {
        buf_ptr: u32,
        buf_len: u32,
    };
    var req: HttpReq = .{
        .buf_ptr = @truncate(@intFromPtr(response_buf.ptr)),
        .buf_len = @intCast(response_buf.len),
    };
    const result = syscall3(
        69,
        @truncate(@intFromPtr(url.ptr)),
        @intCast(url.len),
        @truncate(@intFromPtr(&req)),
    );
    if (result == 0xFFFFFFFF) return null;
    return result;
}

/// TCP socket API. The kernel keeps a small fixed pool of connections (TCP_MAX_CONNS,
/// currently 2), addressed by `slot`. tcpConnect blocks; tcpSend blocks until all
/// bytes are queued; tcpRecv is non-blocking (poll). Status check returns a bitmask
/// distinguishing "connected" from "peer half-closed".

pub const TCP_STATUS_CONNECTED: u32 = 1;
pub const TCP_STATUS_PEER_CLOSED: u32 = 2;

/// Open a TCP connection to `ip:port`. Returns a slot id (≥0) or null on
/// failure. Blocks for up to 5 seconds during the handshake.
pub fn tcpConnect(ip: [4]u8, port: u16) ?u8 {
    var ip_buf: [4]u8 = ip;
    const result = syscall(
        70,
        @truncate(@intFromPtr(&ip_buf)),
        @as(u32, port),
    );
    if (result == 0xFFFFFFFF) return null;
    return @truncate(result);
}

/// Send `data` over the connection. Returns false on any failure (including
/// peer disconnect mid-send). Larger writes are split into MSS chunks
/// kernel-side; callers pass the full buffer in one call.
pub fn tcpSend(slot: u8, data: []const u8) bool {
    if (data.len == 0) return true;
    if (data.len > 64 * 1024) return false;
    return syscall3(
        71,
        @as(u32, slot),
        @truncate(@intFromPtr(data.ptr)),
        @intCast(data.len),
    ) == 0;
}

/// Receive up to `buf.len` bytes from the connection. Non-blocking: returns
/// 0 if nothing is buffered yet. Callers poll (with a small sleep) until
/// status reports peer_closed AND a recv returns 0 — that's true EOF.
pub fn tcpRecv(slot: u8, buf: []u8) usize {
    if (buf.len == 0) return 0;
    return @intCast(syscall3(
        72,
        @as(u32, slot),
        @truncate(@intFromPtr(buf.ptr)),
        @intCast(buf.len),
    ));
}

/// Close the connection. Sends FIN, waits briefly for the peer's FIN-ACK,
/// then frees the slot. Idempotent — safe to call on an already-closed slot.
pub fn tcpClose(slot: u8) void {
    _ = syscall(73, @as(u32, slot), 0);
}

/// Bitmask of connection state. Use `TCP_STATUS_CONNECTED` /
/// `TCP_STATUS_PEER_CLOSED` rather than raw bit indices.
pub fn tcpStatus(slot: u8) u32 {
    return syscall(74, @as(u32, slot), 0);
}

/// Bind a server-side TCP socket to `port`. Returns the listener slot id, or
/// null on failure (port in use, listener pool full).
pub fn tcpListen(port: u16) ?u8 {
    const result = syscall(75, @as(u32, port), 0);
    if (result == 0xFFFFFFFF) return null;
    return @truncate(result);
}

/// Release a listener. Already-accepted conns keep working; only new SYNs
/// stop being accepted on this port.
pub fn tcpUnlisten(listener_slot: u8) void {
    _ = syscall(76, @as(u32, listener_slot), 0);
}

/// Pop one ESTABLISHED conn slot from the listener's accept queue. Returns
/// null if nothing is queued (poll). The returned slot is a regular conn id
/// usable with tcpSend/Recv/Close/Status.
pub fn tcpAccept(listener_slot: u8) ?u8 {
    const result = syscall(77, @as(u32, listener_slot), 0);
    if (result == 0xFFFFFFFF) return null;
    return @truncate(result);
}

// ---- TLS 1.3 syscalls (107-110) -----------------------------------------
// Kernel does the entire TLS handshake (X25519, ChaCha20-Poly1305, RSA-PSS
// or ECDSA CertificateVerify) plus Mozilla NSS trust anchor lookup. From
// userspace this looks just like the tcp* API but with handshake-blocking
// connect and encrypted application data.

const TlsConnectArgs = extern struct {
    ip: [4]u8,
    port: u16,
    _pad: u16,
    sni_ptr: u32,
    sni_len: u32,
};

/// Open a TLS 1.3 connection to `ip:port` with the given SNI hostname.
/// Returns a slot id (0..3) or null on any failure. Blocks for the
/// full handshake (typically < 2 s on the local network).
pub fn tlsConnect(ip: [4]u8, port: u16, sni: []const u8) ?u8 {
    var args: TlsConnectArgs = .{
        .ip = ip,
        .port = port,
        ._pad = 0,
        .sni_ptr = @truncate(@intFromPtr(sni.ptr)),
        .sni_len = @intCast(sni.len),
    };
    const result = syscall(107, @truncate(@intFromPtr(&args)), 0);
    // Treat any errno-band value as failure — without this, an
    // E_NOSYS (0xFFFFFFF3) silently passes through @truncate as
    // slot 0xF3 = 243, and the app marches on with a bogus slot.
    if (isErr(result)) return null;
    return @truncate(result);
}

/// Encrypt `data` and send it over the TLS conn. Returns bytes sent (=
/// data.len on success), or null on failure.
pub fn tlsSend(slot: u8, data: []const u8) ?usize {
    if (data.len == 0) return 0;
    if (data.len > 16 * 1024) return null;
    const result = syscall3(108, @as(u32, slot), @truncate(@intFromPtr(data.ptr)), @intCast(data.len));
    if (isErr(result)) return null;
    return @intCast(result);
}

/// Decrypt and drain up to `buf.len` bytes of plaintext from the
/// connection. Blocks until at least one record arrives or the peer
/// closes. Returns:
///   > 0 bytes read
///   = 0 peer sent close_notify (graceful EOF)
///   null error (corrupt record, AEAD tag mismatch, etc.)
pub fn tlsRecv(slot: u8, buf: []u8) ?usize {
    if (buf.len == 0) return 0;
    const result = syscall3(109, @as(u32, slot), @truncate(@intFromPtr(buf.ptr)), @intCast(buf.len));
    if (isErr(result)) return null;
    return @intCast(result);
}

/// Send TLS close_notify alert + tear down TCP. Idempotent.
pub fn tlsClose(slot: u8) void {
    _ = syscall(110, @as(u32, slot), 0);
}

// --- Process inspection ---

pub const PROC_STATE_UNUSED: u8 = 0;
pub const PROC_STATE_READY: u8 = 1;
pub const PROC_STATE_RUNNING: u8 = 2;
pub const PROC_STATE_SLEEPING: u8 = 3;
pub const PROC_STATE_ZOMBIE: u8 = 4;

pub const PROC_PRIO_BACKGROUND: u8 = 0;
pub const PROC_PRIO_NORMAL: u8 = 1;
pub const PROC_PRIO_INTERACTIVE: u8 = 2;

/// Snapshot of one PCB for `ps` / `top` style display. Layout matches the
/// kernel's ProcInfoUser exactly — the syscall writes raw bytes here.
pub const ProcInfo = extern struct {
    pid: u8,
    state: u8,
    parent_pid: u8,
    priority: u8,
    last_cpu: u8,
    name_len: u8,
    _pad: [2]u8 = .{ 0, 0 },
    ticks_used: u32,
    user_brk: u32,
    name: [16]u8,
    // Layout below MUST match cpu/syscall.zig:ProcInfoUser exactly. tgid +
    // pgid + sid were appended after start_tick so old readers that stop
    // at start_tick still see correct values for everything before it.
    // Accounting fields — must match `cpu/syscall.zig:ProcInfoUser` exactly
    // (kernel writes raw bytes via @memcpy). Zero on a not-yet-tracked PCB.
    cpu_ticks: u64 align(1) = 0,
    pf_count: u32 align(1) = 0,
    syscall_count: u64 align(1) = 0,
    peak_rss_pages: u32 align(1) = 0,
    current_rss_pages: u32 align(1) = 0,
    start_tick: u64 align(1) = 0,
    tgid: u8 = 0,
    pgid: u8 = 0,
    sid: u8 = 0,
    // CFS scheduler fields (added 2026-05-10) — see cpu/syscall.zig
    // ProcInfoUser for the kernel-side mirror this must match.
    nice: i8 = 0,
    assigned_cpu: u8 = 0xFF,
    pinned_cpu: u8 = 0xFF,
    _pad2: [2]u8 = .{ 0, 0 },
    vruntime: u64 align(1) = 0,
    _pad3: [4]u8 = .{ 0, 0, 0, 0 },
};

/// Fill `buf` with one ProcInfo per active (non-unused) process slot.
/// Returns the count. Caller's buffer should be at least MAX_PROCS=32 entries.
pub fn processList(buf: []ProcInfo) u32 {
    if (buf.len == 0) return 0;
    return syscall(
        78,
        @truncate(@intFromPtr(buf.ptr)),
        @intCast(buf.len),
    );
}

// --- USB Mass Storage ---

/// Information about the first connected USB Mass Storage device.
/// `present` is 0 if no device is connected (and other fields are 0);
/// 1 otherwise.
pub const UsbInfo = extern struct {
    present: u8,
    _pad: [3]u8 = .{ 0, 0, 0 },
    block_size: u32,
    block_count: u32,
};

pub fn usbInfo() ?UsbInfo {
    var info: UsbInfo = .{ .present = 0, .block_size = 0, .block_count = 0 };
    const r = syscall(79, @truncate(@intFromPtr(&info)), 0);
    if (r == 0xFFFFFFFF) return null;
    return info;
}

/// Read one block from `lba` into `buf`. `buf.len` must be at least the
/// device's block_size (call usbInfo first). Returns false on any failure
/// (no device, SCSI command rejected).
pub fn usbReadSector(lba: u32, buf: []u8) bool {
    if (buf.len == 0) return false;
    return syscall(80, lba, @truncate(@intFromPtr(buf.ptr))) == 0;
}

/// Write one block to `lba` from `buf`. Same sizing rules as `usbReadSector`.
pub fn usbWriteSector(lba: u32, buf: []const u8) bool {
    if (buf.len == 0) return false;
    return syscall(81, lba, @truncate(@intFromPtr(buf.ptr))) == 0;
}

// --- Threads (sysClone + sysFutex + sysSetTls) -----------------------------
//
// pthread-style API atop the kernel's clone/futex/set_tls primitives.
// The new thread enters via `threadTrampoline` which sets up TLS, runs
// the user's start_routine, stashes the return value, futex-wakes any
// joiner, and then exit_thread()s.

pub const ThreadFn = *const fn (?*anyopaque) callconv(.c) ?*anyopaque;

pub const Tcb = extern struct {
    tid: u32 = 0,
    /// Set to 1 when the thread has finished. pthread_join futex-waits
    /// on this word.
    done: u32 = 0,
    start_routine: ThreadFn,
    arg: ?*anyopaque,
    retval: ?*anyopaque = null,
    /// Owning stack region returned by `mmap` so pthread_join can free
    /// it after the thread has finished.
    stack_base: usize = 0,
    stack_len: usize = 0,
};

const THREAD_STACK_SIZE: usize = 64 * 1024;

fn threadTrampoline(tcb_arg: ?*anyopaque) callconv(.c) noreturn {
    const tcb: *Tcb = @ptrCast(@alignCast(tcb_arg.?));
    // Establish TLS before any %fs:NN load — even though the user's
    // start_routine may not use it, libc internals (errno, future
    // __thread vars) might.
    _ = syscall(84, @truncate(@intFromPtr(tcb)), 0);
    tcb.retval = tcb.start_routine(tcb.arg);
    @atomicStore(u32, &tcb.done, 1, .release);
    // Wake any pthread_join. fits one waiter (the joiner).
    _ = syscall3(85, @truncate(@intFromPtr(&tcb.done)), 1, 1); // FUTEX_WAKE, n=1
    _ = syscall(86, 0, 0); // exit_thread; doesn't return
    while (true) {}
}

/// Spawn a new thread. The TCB is heap-allocated by the caller (typically
/// libc's malloc) and passed back to pthread_join. Returns null if the
/// stack mmap fails or the kernel can't allocate a PCB slot.
pub fn pthreadCreate(start: ThreadFn, arg: ?*anyopaque) ?*Tcb {
    const stack = mmap(THREAD_STACK_SIZE) orelse return null;
    // Allocate the TCB on the user heap. malloc returns a [*]u8;
    // pthreadJoin frees it via the same pointer once the thread is gone.
    const tcb_raw = malloc(@sizeOf(Tcb)) orelse {
        _ = munmap(stack);
        return null;
    };
    const tcb: *Tcb = @ptrCast(@alignCast(tcb_raw));
    tcb.* = .{
        .start_routine = start,
        .arg = arg,
        .stack_base = @intFromPtr(stack.ptr),
        .stack_len = stack.len,
    };
    const stack_top: u32 = @truncate(@intFromPtr(stack.ptr) + stack.len);
    const tid = syscall3(83, @truncate(@intFromPtr(&threadTrampoline)), stack_top, @truncate(@intFromPtr(tcb)));
    if (tid == 0xFFFFFFFF) {
        _ = munmap(stack);
        free(tcb_raw);
        return null;
    }
    tcb.tid = tid;
    return tcb;
}

/// Wait for `tcb`'s thread to finish, then free its stack + TCB.
/// Returns the value the thread's start_routine returned. Must be
/// called exactly once per pthread (no detached/joined-twice support).
pub fn pthreadJoin(tcb: *Tcb) ?*anyopaque {
    while (@atomicLoad(u32, &tcb.done, .acquire) == 0) {
        // FUTEX_WAIT(uaddr, val=0). If `done` already != 0, kernel
        // returns EAGAIN and we re-check on the next iteration.
        _ = syscall3(85, @truncate(@intFromPtr(&tcb.done)), 0, 0);
    }
    const ret = tcb.retval;
    if (tcb.stack_base != 0) {
        const stack_slice: []u8 = @as([*]u8, @ptrFromInt(tcb.stack_base))[0..tcb.stack_len];
        _ = munmap(stack_slice);
    }
    free(@as([*]u8, @ptrCast(tcb)));
    return ret;
}

// --- pthread_mutex --------------------------------------------------------
//
// Three-state futex mutex (Drepper's design):
//   0 = unlocked, 1 = locked-no-waiters, 2 = locked-with-waiters
// Fast path is a single CAS. Only contended locks call into the kernel
// via FUTEX_WAIT / FUTEX_WAKE.

pub const Mutex = extern struct {
    state: u32 = 0,

    pub fn lock(self: *Mutex) void {
        // Try the uncontended-acquire fast path.
        const expected: u32 = 0;
        if (@cmpxchgStrong(u32, &self.state, expected, 1, .acquire, .acquire) == null) return;

        while (true) {
            // Mark the mutex as having waiters so the holder will WAKE on unlock.
            const prev = @atomicRmw(u32, &self.state, .Xchg, 2, .acquire);
            if (prev == 0) return; // we got it after all
            // Sleep until someone wakes us — they will only do so after
            // setting state back to 0, so we try the CAS afresh on wake.
            _ = syscall3(85, @truncate(@intFromPtr(&self.state)), 0, 2); // WAIT, val=2
        }
    }

    pub fn unlock(self: *Mutex) void {
        // If we held in state=1 (no waiters), no syscall needed. If 2,
        // we owe a wake. Single decrement covers both common cases.
        const prev = @atomicRmw(u32, &self.state, .Sub, 1, .release);
        if (prev != 1) {
            // Was 2 (had waiters). Reset to 0 and wake one.
            @atomicStore(u32, &self.state, 0, .release);
            _ = syscall3(85, @truncate(@intFromPtr(&self.state)), 1, 1); // WAKE, n=1
        }
    }
};

// --- pthread_cond ---------------------------------------------------------
//
// Sequence-counter condvar (Linux pthreads-style). `seq` is bumped on every
// signal/broadcast; waiters sample it before releasing the mutex and pass
// the sample to FUTEX_WAIT. If a signal lands between unlock and wait the
// kernel sees `seq != sampled` and returns EAGAIN — no sleep, no missed
// wake. Waiters re-acquire `mu` before returning, matching pthread semantics.
//
// `wait` can spuriously return (signal that races multiple waiters, etc.);
// callers MUST recheck their predicate in a loop, the standard contract.

pub const Cond = extern struct {
    seq: u32 = 0,

    /// Atomically release `mu`, wait for a signal/broadcast, re-acquire `mu`.
    pub fn wait(self: *Cond, mu: *Mutex) void {
        const sampled = @atomicLoad(u32, &self.seq, .acquire);
        mu.unlock();
        _ = syscall3(85, @truncate(@intFromPtr(&self.seq)), 0, sampled); // WAIT
        mu.lock();
    }

    /// Wake one waiter (no-op if none).
    pub fn signal(self: *Cond) void {
        _ = @atomicRmw(u32, &self.seq, .Add, 1, .release);
        _ = syscall3(85, @truncate(@intFromPtr(&self.seq)), 1, 1); // WAKE n=1
    }

    /// Wake all waiters. No FUTEX_REQUEUE optimization yet (kernel only
    /// supports WAIT/WAKE) so this is a thundering herd — every woken
    /// thread tries to re-acquire `mu` and most go back to sleep on its
    /// futex. Fine for v1; add REQUEUE if/when contention shows up.
    pub fn broadcast(self: *Cond) void {
        _ = @atomicRmw(u32, &self.seq, .Add, 1, .release);
        _ = syscall3(85, @truncate(@intFromPtr(&self.seq)), 1, 0xFFFFFFFF); // WAKE n=∞
    }
};

// --- pthread_rwlock -------------------------------------------------------
//
// Single-word reader-writer lock: bit 31 = writer holds, bits 0..30 = reader
// count. Writer-prefers-readers stampede on unlock (FUTEX_WAKE all) — could
// starve writers under heavy reader churn. Fairness left for v2.

pub const RwLock = extern struct {
    state: u32 = 0,

    const WRITER_BIT: u32 = 0x80000000;
    const READER_MASK: u32 = 0x7FFFFFFF;

    pub fn lockShared(self: *RwLock) void {
        while (true) {
            const cur = @atomicLoad(u32, &self.state, .acquire);
            if (cur & WRITER_BIT == 0) {
                // Try to add a reader. CAS protects against concurrent writers
                // grabbing the bit between our load and increment.
                if (@cmpxchgWeak(u32, &self.state, cur, cur + 1, .acquire, .acquire) == null) return;
                continue;
            }
            // Writer holds — sleep until state changes.
            _ = syscall3(85, @truncate(@intFromPtr(&self.state)), 0, cur); // WAIT
        }
    }

    pub fn unlockShared(self: *RwLock) void {
        const prev = @atomicRmw(u32, &self.state, .Sub, 1, .release);
        // If we were the last reader, wake any writer waiting.
        if ((prev & READER_MASK) == 1) {
            _ = syscall3(85, @truncate(@intFromPtr(&self.state)), 1, 1); // WAKE n=1
        }
    }

    pub fn lockExclusive(self: *RwLock) void {
        while (true) {
            const cur = @atomicLoad(u32, &self.state, .acquire);
            if (cur == 0) {
                if (@cmpxchgWeak(u32, &self.state, 0, WRITER_BIT, .acquire, .acquire) == null) return;
                continue;
            }
            _ = syscall3(85, @truncate(@intFromPtr(&self.state)), 0, cur); // WAIT
        }
    }

    pub fn unlockExclusive(self: *RwLock) void {
        @atomicStore(u32, &self.state, 0, .release);
        // Wake all — could be N readers (let them all in), or one of M
        // waiting writers (first to CAS wins, others re-sleep).
        _ = syscall3(85, @truncate(@intFromPtr(&self.state)), 1, 0xFFFFFFFF);
    }
};

// --- pthread_sem ----------------------------------------------------------
//
// Counting semaphore. `wait` decrements (blocks if zero), `post` increments
// (wakes one waiter). Bounded-queue producer/consumer is the canonical use.

pub const Sem = extern struct {
    count: u32 = 0,

    pub fn init(self: *Sem, value: u32) void {
        @atomicStore(u32, &self.count, value, .release);
    }

    pub fn wait(self: *Sem) void {
        while (true) {
            const cur = @atomicLoad(u32, &self.count, .acquire);
            if (cur > 0) {
                if (@cmpxchgWeak(u32, &self.count, cur, cur - 1, .acquire, .acquire) == null) return;
                continue;
            }
            _ = syscall3(85, @truncate(@intFromPtr(&self.count)), 0, 0); // WAIT, val=0
        }
    }

    pub fn post(self: *Sem) void {
        _ = @atomicRmw(u32, &self.count, .Add, 1, .release);
        _ = syscall3(85, @truncate(@intFromPtr(&self.count)), 1, 1); // WAKE n=1
    }
};

// --- Once -----------------------------------------------------------------
//
// Call-once primitive for lazy init. The first caller to CAS state 0→1 runs
// `f`; concurrent callers block until state hits 2 (done). Cheap fast-path
// after init: single atomic load, no syscall.

pub const Once = extern struct {
    state: u32 = 0, // 0=fresh, 1=in-progress, 2=done

    pub fn call(self: *Once, f: *const fn () void) void {
        if (@atomicLoad(u32, &self.state, .acquire) == 2) return;
        if (@cmpxchgStrong(u32, &self.state, 0, 1, .acquire, .acquire) == null) {
            f();
            @atomicStore(u32, &self.state, 2, .release);
            _ = syscall3(85, @truncate(@intFromPtr(&self.state)), 1, 0xFFFFFFFF); // WAKE all
            return;
        }
        // Someone else is initializing — wait for state==2.
        while (@atomicLoad(u32, &self.state, .acquire) != 2) {
            _ = syscall3(85, @truncate(@intFromPtr(&self.state)), 0, 1); // WAIT, val=1
        }
    }
};

// --- Scheduler affinity ---
//
// sched_setaffinity / sched_getaffinity expose syscalls #99 / #100 — pin
// or query a thread's CPU. pid==0 means self; otherwise the target must
// share our tgid (kernel enforces — pthread-style "own threads only").

pub const AFFINITY_UNPINNED: i32 = -1;

/// sched_setaffinity(pid, cpu) — pin pid to `cpu`, or unpin if cpu < 0.
/// pid==0 → self. Returns 0 on success, -1 on E_INVAL/E_PERM.
pub fn sched_setaffinity(pid: u32, cpu: i32) i32 {
    const cpu_arg: u32 = if (cpu < 0) 0xFFFFFFFF else @intCast(cpu);
    const r = syscall(99, pid, cpu_arg);
    if (r == 0) return 0;
    return -1;
}

/// sched_getaffinity(pid) — read pid's pinned CPU.
/// Returns 0..MAX_CPUS-1 if pinned, AFFINITY_UNPINNED (-1) if unpinned,
/// or -2 on error (bad pid, different tgid, no caller PCB).
///
/// Kernel uses offset-by-1 encoding (0 = unpinned, 1..N = pinned to N-1,
/// 0xFFFFFFFF = error) so errno values (E_INVAL=1, etc.) don't alias
/// CPU id 0 over the syscall ABI.
pub fn sched_getaffinity(pid: u32) i32 {
    const r = syscall(100, pid, 0);
    if (r == 0xFFFFFFFF) return -2;
    if (r == 0) return AFFINITY_UNPINNED;
    return @intCast(r - 1);
}

// --- Nice values (within-band CPU share) ---
//
// Lower nice = more CPU share, higher nice = less. Range -20..19; out-of-
// range values clamp at the kernel side. Affects vruntime accumulation
// rate within a priority band; cross-band scheduling is unchanged
// (interactive ALWAYS beats normal beats background — that's setpriority(),
// syscall #47, not nice).

/// sched_setnice(pid, value) — set pid's nice value (-20..19).
/// pid==0 = self. Returns 0 on success, -1 on error (E_INVAL/E_PERM).
pub fn sched_setnice(pid: u32, value: i32) i32 {
    const r = syscall(101, pid, @bitCast(value));
    if (r == 0) return 0;
    return -1;
}

/// sched_getnice(pid) — read pid's nice value. Returns -20..19, or
/// -100 on error (we use -100 because -1 is a valid nice value).
///
/// Kernel uses offset-by-21 encoding (1..40 = nice -20..+19, 0xFFFFFFFF =
/// error). Caller subtracts 21 to recover.
pub fn sched_getnice(pid: u32) i32 {
    const r = syscall(102, pid, 0);
    if (r == 0xFFFFFFFF) return -100;
    return @as(i32, @intCast(r)) - 21;
}

/// nice(inc) — POSIX nice(2): adjust calling thread's nice by `inc` and
/// return the new nice value (or -100 on error).
pub fn nice(inc: i32) i32 {
    const cur = sched_getnice(0);
    if (cur == -100) return -100;
    if (sched_setnice(0, cur + inc) != 0) return -100;
    return sched_getnice(0);
}

// --- Clipboard ---
//
// Single system-wide clipboard buffer in the kernel. Any app can put
// bytes in via `setClipboard` and any app can read them out via
// `getClipboard`. No MIME or format negotiation — bytes are bytes.

pub const CLIPBOARD_MAX: u32 = 64 * 1024;

/// Copy `data` into the kernel clipboard. Returns the number of bytes
/// actually written (which is `data.len` on success). Passing an empty
/// slice clears the clipboard.
pub fn setClipboard(data: []const u8) u32 {
    if (data.len > CLIPBOARD_MAX) return 0;
    return syscall(103, @intCast(@intFromPtr(data.ptr)), @intCast(data.len));
}

/// Read the current clipboard contents into `dest`. Returns the actual
/// length of the clipboard contents — if it's larger than `dest.len`,
/// only `dest.len` bytes were written (compare return value to know).
pub fn getClipboard(dest: []u8) u32 {
    if (dest.len == 0) return syscall(104, 0, 0);
    return syscall(104, @intCast(@intFromPtr(dest.ptr)), @intCast(dest.len));
}
