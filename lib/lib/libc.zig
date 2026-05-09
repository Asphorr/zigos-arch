// ZigOS User-space libc
// Syscall wrappers and utilities for user applications

// --- Syscall primitives ---

pub inline fn syscall(num: u32, arg1: u32, arg2: u32) u32 {
    return syscall3(num, arg1, arg2, 0);
}

pub inline fn syscall3(num: u32, arg1: u32, arg2: u32, arg3: u32) u32 {
    var ret: u32 = undefined;
    asm volatile ("int $0x80"
        : [ret] "={eax}" (ret),
        : [num] "{eax}" (num),
          [a1] "{ebx}" (arg1),
          [a2] "{ecx}" (arg2),
          [a3] "{edx}" (arg3),
        : .{ .memory = true });
    return ret;
}

// --- Syscall wrappers ---

pub fn print(msg: []const u8) void {
    _ = syscall(1, @truncate(@intFromPtr(msg.ptr)), @intCast(msg.len));
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

pub fn sbrk(increment: u32) ?[*]u8 {
    const result = syscall(5, increment, 0);
    if (result == 0xFFFFFFFF) return null;
    return @ptrFromInt(result);
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

pub fn createWindow(w: u32, h: u32) ?[*]volatile u32 {
    const ret = syscall(13, w, h);
    if (ret == 0xFFFFFFFF) return null;
    return @ptrFromInt(ret);
}

/// Create window with over-allocated FB. Display starts at disp_w x disp_h, FB is alloc_w x alloc_h.
pub fn createWindowEx(alloc_w: u32, alloc_h: u32, disp_w: u32, disp_h: u32) ?[*]volatile u32 {
    const display_wh = (disp_h << 16) | disp_w;
    const ret = syscall3(13, alloc_w, alloc_h, display_wh);
    if (ret == 0xFFFFFFFF) return null;
    return @ptrFromInt(ret);
}

pub fn present() void {
    _ = syscall(14, 0, 0);
}

pub const MouseState = struct { x: i32, y: i32, buttons: u32 };

pub fn getMouse() MouseState {
    var buf: [3]u32 align(4) = undefined;
    _ = syscall(15, @truncate(@intFromPtr(&buf)), 0);
    return .{
        .x = @bitCast(buf[0]),
        .y = @bitCast(buf[1]),
        .buttons = buf[2],
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

pub fn exec(name: []const u8) u32 {
    return syscall(22, @truncate(@intFromPtr(name.ptr)), @as(u32, @intCast(name.len)));
}

pub fn getExecArg(buf: []u8) u32 {
    return syscall(25, @truncate(@intFromPtr(buf.ptr)), 0);
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

pub const O_CREATE: u32 = 0x100;

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

// --- Bump allocator ---

var heap_base: usize = 0;
var heap_used: usize = 0;
var heap_capacity: usize = 0;

pub fn malloc(size: usize) ?[*]u8 {
    const aligned_size = (size + 3) & ~@as(usize, 3);
    while (heap_used + aligned_size > heap_capacity) {
        const ptr = sbrk(4096) orelse return null;
        if (heap_base == 0) {
            heap_base = @intFromPtr(ptr);
        }
        heap_capacity += 4096;
    }
    const result: [*]u8 = @ptrFromInt(heap_base + heap_used);
    heap_used += aligned_size;
    return result;
}
