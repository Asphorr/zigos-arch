//! Per-process heap allocator — extracted from lib/libc.zig as a static
//! library so that edits to malloc/free/realloc don't fan out into every
//! app's recompile path. See [[libc-heap-static-lib-2026-05-28]].
//!
//! Public API (linked as C-ABI symbols):
//!   __libc_malloc            __libc_malloc_trim
//!   __libc_free              __libc_malloc_usable_size
//!   __libc_realloc           __libc_malloc_stats
//!   __libc_calloc
//!
//! lib/libc.zig declares matching `pub extern fn` decls and exposes thin
//! `pub inline fn malloc(...)` wrappers, so app callers still write
//! `libc.malloc(sz)` unchanged. The linker resolves the wrapper's extern
//! call to one of the exports below.
//!
//! This file deliberately duplicates a handful of tiny helpers (syscall
//! asm shim, sbrk, a minimal Mutex, a print fn for diagnostics) instead
//! of `@import("libc")` — importing libc.zig here would re-couple the two
//! files' source hashes and defeat the whole point of the split. The
//! duplicates are <40 lines combined and unlikely to drift.

const std = @import("std");

// --- Minimal syscall ABI -----------------------------------------------------

inline fn syscall(num: u32, arg1: u32, arg2: u32) u32 {
    return syscall3(num, arg1, arg2, 0);
}

inline fn syscall3(num: u32, arg1: u32, arg2: u32, arg3: u32) u32 {
    var ret: u32 = undefined;
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

fn sbrk(increment: u32) ?[*]u8 {
    const result = syscall(5, increment, 0);
    if (result == 0xFFFFFFFF) return null;
    return @ptrFromInt(result);
}

fn sbrkShrink(decrement: u32) bool {
    const neg: i32 = -@as(i32, @intCast(decrement));
    const result = syscall(5, @bitCast(neg), 0);
    return result != 0xFFFFFFFF;
}

/// fd=1 write for diagnostic prints. Bypasses fwrite/fread plumbing since
/// we want zero coupling to the rest of libc.
fn diagPrint(msg: []const u8) void {
    if (msg.len == 0) return;
    // syscall 9 = sys_fwrite (fd, buf_ptr, len). Same ABI as libc.fwrite.
    _ = syscall3(9, 1, @truncate(@intFromPtr(msg.ptr)), @truncate(msg.len));
}

// --- Minimal Mutex (heap's internal use only) --------------------------------
//
// Three-state futex mutex; mirrors lib/libc.zig's `Mutex` definition. Kept
// separate because importing libc.zig here would defeat the static-lib
// split (heap edits would re-trigger app recompiles via libc.zig's
// transitive hash).

const Mutex = extern struct {
    state: u32 = 0,

    fn lock(self: *Mutex) void {
        const expected: u32 = 0;
        if (@cmpxchgStrong(u32, &self.state, expected, 1, .acquire, .acquire) == null) return;
        while (true) {
            const prev = @atomicRmw(u32, &self.state, .Xchg, 2, .acquire);
            if (prev == 0) return;
            _ = syscall3(85, @truncate(@intFromPtr(&self.state)), 0, 2); // FUTEX_WAIT val=2
        }
    }

    fn unlock(self: *Mutex) void {
        const prev = @atomicRmw(u32, &self.state, .Sub, 1, .release);
        if (prev != 1) {
            @atomicStore(u32, &self.state, 0, .release);
            _ = syscall3(85, @truncate(@intFromPtr(&self.state)), 1, 1); // FUTEX_WAKE n=1
        }
    }
};

// --- Block layout + constants ------------------------------------------------

const BLOCK_MAGIC_ALLOC: u32 = 0xA110_CA7E;
const BLOCK_MAGIC_FREE: u32 = 0xFEED_5EED;
const FREE_FILL: u8 = 0xDD;
const HEAP_DEBUG_FILL: bool = false;

const Block = extern struct {
    size: u32, // total block size including this 16-byte header
    magic: u32,
    prev_size: u32, // size of preceding block in same sbrk chunk; 0 if first
    _pad: u32 = 0,
};

const HEADER_SIZE: usize = @sizeOf(Block);
const MIN_SPLIT: usize = HEADER_SIZE + 16;

pub const HeapStats = extern struct {
    used_bytes: u64,
    free_bytes: u64,
    total_bytes: u64,
    blocks: u32,
};

// --- Heap state --------------------------------------------------------------

var heap_start: usize = 0;
var heap_end: usize = 0;
var heap_hint: usize = 0;
var heap_lock: Mutex = .{};
var heap_used: usize = 0;
var heap_free: usize = 0;
var heap_blocks: u32 = 0;

inline fn alignUp(x: usize, a: usize) usize {
    return (x + a - 1) & ~(a - 1);
}

/// Heap integrity hunt scaffold — flip to true to walk the boundary-tag
/// chain on every malloc/free/realloc entry. Cost is O(N-blocks) per call;
/// leave off in normal dev, bring back when chasing the next bug.
const HEAP_VERIFY = false;

inline fn heapUsedSub(amount: u32, comptime site: []const u8) void {
    if (@as(usize, amount) > heap_used) {
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "[heap-drift] {s}: heap_used={d} sub={d}\n", .{ site, heap_used, amount }) catch return;
        diagPrint(msg);
    }
    heap_used -= amount;
}

inline fn heapFreeSub(amount: u32, comptime site: []const u8) void {
    if (@as(usize, amount) > heap_free) {
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "[heap-drift] {s}: heap_free={d} sub={d}\n", .{ site, heap_free, amount }) catch return;
        diagPrint(msg);
    }
    heap_free -= amount;
}

fn verifyHeap(comptime site: []const u8) bool {
    if (!HEAP_VERIFY) return true;
    if (heap_start == 0) return true;
    var addr: usize = heap_start;
    var sum_used: usize = 0;
    var sum_free: usize = 0;
    var blocks: u32 = 0;
    var iter: u32 = 0;
    while (addr < heap_end) {
        iter += 1;
        if (iter > 200_000) {
            var buf: [128]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "[heap-verify] {s}: walk exceeded 200k blocks; bailing\n", .{site}) catch return false;
            diagPrint(msg);
            return false;
        }
        const blk: *Block = @ptrFromInt(addr);
        if (blk.size == 0 or (blk.size & 15) != 0) {
            var buf: [200]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "[heap-verify] {s}: bad size at 0x{X} size={d} (iter={d})\n", .{ site, addr, blk.size, iter }) catch return false;
            diagPrint(msg);
            return false;
        }
        if (blk.magic != BLOCK_MAGIC_ALLOC and blk.magic != BLOCK_MAGIC_FREE) {
            var buf: [220]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "[heap-verify] {s}: bad magic at 0x{X} magic=0x{X} size={d} (iter={d})\n", .{ site, addr, blk.magic, blk.size, iter }) catch return false;
            diagPrint(msg);
            return false;
        }
        if (addr + blk.size > heap_end) {
            var buf: [220]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "[heap-verify] {s}: overruns heap_end at 0x{X} size={d} heap_end=0x{X}\n", .{ site, addr, blk.size, heap_end }) catch return false;
            diagPrint(msg);
            return false;
        }
        if (blk.magic == BLOCK_MAGIC_ALLOC) sum_used += blk.size else sum_free += blk.size;
        addr += blk.size;
        blocks += 1;
    }
    if (sum_used != heap_used or sum_free != heap_free or blocks != heap_blocks) {
        const total = heap_end - heap_start;
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "[hv] {s}: u={d}/{d} f={d}/{d} b={d}/{d} t={d}\n", .{
            site, sum_used, heap_used, sum_free, heap_free, blocks, heap_blocks, total,
        }) catch return false;
        diagPrint(msg);
        return false;
    }
    return true;
}

inline fn linkPrevSize(addr: usize, new_size: u32) void {
    const after = addr + new_size;
    if (after < heap_end) {
        const next: *Block = @ptrFromInt(after);
        next.prev_size = new_size;
    }
}

inline fn blockFromUser(user_addr: usize) ?*Block {
    if (user_addr < heap_start + HEADER_SIZE or user_addr >= heap_end) return null;
    if ((user_addr & 15) != 0) return null;
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

    var addr = if (heap_hint != 0) heap_hint else heap_start;
    while (addr != 0 and addr < heap_end) {
        const block: *Block = @ptrFromInt(addr);
        if (block.size == 0) break;
        if (block.magic == BLOCK_MAGIC_FREE and block.size >= need) {
            return claimBlock(addr, need);
        }
        addr += block.size;
    }
    addr = heap_start;
    while (addr != 0 and addr < heap_hint) {
        const block: *Block = @ptrFromInt(addr);
        if (block.size == 0) break;
        if (block.magic == BLOCK_MAGIC_FREE and block.size >= need) {
            return claimBlock(addr, need);
        }
        addr += block.size;
    }

    const new_addr = growHeap(need) orelse return null;
    return claimBlock(new_addr, need);
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
    heapFreeSub(block.size, "claimBlock");
    heap_hint = addr + block.size;
    if (heap_hint >= heap_end) heap_hint = heap_start;
    return @ptrFromInt(addr + HEADER_SIZE);
}

fn freeLocked(ptr: ?[*]u8) void {
    const p = ptr orelse return;
    const user_addr = @intFromPtr(p);
    var block = blockFromUser(user_addr) orelse return;
    var block_addr = user_addr - HEADER_SIZE;

    block.magic = BLOCK_MAGIC_FREE;
    heapUsedSub(block.size, "freeLocked");
    heap_free += block.size;

    if (HEAP_DEBUG_FILL) {
        const payload: [*]u8 = @ptrFromInt(user_addr);
        @memset(payload[0 .. block.size - HEADER_SIZE], FREE_FILL);
    }

    const next_addr = block_addr + block.size;
    if (next_addr < heap_end) {
        const next_block: *Block = @ptrFromInt(next_addr);
        if (next_block.magic == BLOCK_MAGIC_FREE) {
            block.size += next_block.size;
            next_block.magic = 0;
            heap_blocks -= 1;
            if (heap_hint == next_addr) heap_hint = block_addr;
        }
    }

    if (block.prev_size != 0) {
        const prev_addr = block_addr - block.prev_size;
        const prev_block: *Block = @ptrFromInt(prev_addr);
        if (prev_block.magic == BLOCK_MAGIC_FREE) {
            prev_block.size += block.size;
            block.magic = 0;
            heap_blocks -= 1;
            if (heap_hint == block_addr) heap_hint = prev_addr;
            block_addr = prev_addr;
            block = prev_block;
        }
    }

    linkPrevSize(block_addr, block.size);
}

// --- Exported C-ABI entrypoints -----------------------------------------------

export fn __libc_malloc(size: usize) ?[*]u8 {
    heap_lock.lock();
    defer heap_lock.unlock();
    _ = verifyHeap("malloc-entry");
    return mallocLocked(size);
}

export fn __libc_free(ptr: ?[*]u8) void {
    heap_lock.lock();
    defer heap_lock.unlock();
    _ = verifyHeap("free-entry");
    freeLocked(ptr);
}

export fn __libc_realloc(old_ptr: ?[*]u8, new_size: usize) ?[*]u8 {
    if (new_size == 0) {
        __libc_free(old_ptr);
        return null;
    }
    const old = old_ptr orelse return __libc_malloc(new_size);
    const old_user_addr = @intFromPtr(old);

    heap_lock.lock();
    defer heap_lock.unlock();
    _ = verifyHeap("realloc-entry");

    const block = blockFromUser(old_user_addr) orelse return null;
    const need = alignUp(new_size, 16) + HEADER_SIZE;
    const block_addr = old_user_addr - HEADER_SIZE;

    // Strategy 1: shrink in place + split remainder.
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
            heapUsedSub(remainder.size, "realloc/S1");
            heap_free += remainder.size;
            heap_blocks += 1;
            block.size = @intCast(need);
        }
        return @ptrFromInt(old_user_addr);
    }

    // Strategy 2: merge with next free block if combined size fits.
    const next_addr = block_addr + block.size;
    if (next_addr < heap_end) {
        const next_block: *Block = @ptrFromInt(next_addr);
        if (next_block.magic == BLOCK_MAGIC_FREE and block.size + next_block.size >= need) {
            const absorbed_size = next_block.size;
            const merged_size = block.size + absorbed_size;
            heap_used += absorbed_size;
            heapFreeSub(absorbed_size, "realloc/S2-merge");
            heap_blocks -= 1;
            next_block.magic = 0;
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
                heapUsedSub(remainder.size, "realloc/S2-split");
                heap_free += remainder.size;
                heap_blocks += 1;
                block.size = @intCast(need);
            } else {
                linkPrevSize(block_addr, block.size);
            }
            return @ptrFromInt(old_user_addr);
        }
    }

    // Strategy 3: malloc + memcpy + freeLocked under one lock so the source
    // bytes can't be racily reused.
    const old_payload = block.size - HEADER_SIZE;
    const new_ptr = mallocLocked(new_size) orelse return null;
    const copy_len = if (old_payload < new_size) old_payload else new_size;
    @memcpy(new_ptr[0..copy_len], old[0..copy_len]);
    freeLocked(old);
    return new_ptr;
}

export fn __libc_calloc(nmemb: usize, size: usize) ?[*]u8 {
    const total = nmemb * size;
    const ptr = __libc_malloc(total) orelse return null;
    @memset(ptr[0..total], 0);
    return ptr;
}

export fn __libc_malloc_trim(keep_bytes: usize) usize {
    heap_lock.lock();
    defer heap_lock.unlock();
    if (heap_start == 0 or heap_end <= heap_start) return 0;
    var addr: usize = heap_start;
    var last_addr: usize = 0;
    while (addr < heap_end) {
        const blk: *Block = @ptrFromInt(addr);
        if (blk.size == 0) return 0;
        last_addr = addr;
        addr += blk.size;
    }
    if (last_addr == 0) return 0;
    const last: *Block = @ptrFromInt(last_addr);
    if (last.magic != BLOCK_MAGIC_FREE) return 0;
    // Snapshot before sbrkShrink — the header may be in the released range.
    const last_size: usize = last.size;
    if (last_size <= keep_bytes + 4096) return 0;

    var trim_bytes: usize = (last_size - keep_bytes) & ~@as(usize, 4095);
    if (trim_bytes < 4096) return 0;
    var consume_whole = false;
    var residual = last_size - trim_bytes;
    if (residual == 0) {
        consume_whole = true;
    } else if (residual < HEADER_SIZE) {
        if (trim_bytes >= 4096) {
            trim_bytes -= 4096;
            residual = last_size - trim_bytes;
            if (trim_bytes == 0) return 0;
        } else {
            return 0;
        }
    }

    const new_end = heap_end - trim_bytes;
    if (consume_whole) {
        heapFreeSub(@intCast(last_size), "trim/whole");
        heap_blocks -= 1;
        if (heap_hint >= new_end) heap_hint = heap_start;
    } else {
        last.size = @intCast(residual);
        heapFreeSub(@intCast(trim_bytes), "trim/partial");
    }
    heap_end = new_end;
    if (heap_hint >= heap_end) heap_hint = heap_start;

    if (!sbrkShrink(@intCast(trim_bytes))) {
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

export fn __libc_malloc_usable_size(ptr: ?[*]u8) usize {
    const p = ptr orelse return 0;
    const user_addr = @intFromPtr(p);
    heap_lock.lock();
    defer heap_lock.unlock();
    const block = blockFromUser(user_addr) orelse return 0;
    return block.size - HEADER_SIZE;
}

export fn __libc_malloc_stats(out: *HeapStats) void {
    heap_lock.lock();
    defer heap_lock.unlock();
    out.* = .{
        .used_bytes = heap_used,
        .free_bytes = heap_free,
        .total_bytes = heap_end - heap_start,
        .blocks = heap_blocks,
    };
}
