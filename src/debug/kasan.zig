// KASAN: an address sanitizer for the kernel.
//
// `-Dkasan` runs LLVM's `asan<kernel>` pass over the kernel (build.zig,
// instrumentedObject): every memory access in an instrumented function
// calls `__asan_load{1,2,4,8,16}` / `__asan_store*` here, which look the
// address up in shadow memory — one byte to 8 of memory, as in Linux's
// generic KASAN. The allocators mark what they free and the gaps they leave
// around what they hand out; an access to either is reported.
//
// Tracked: RAM as the physmap shows it, and the vmalloc arena — where the
// heap, the slabs, the kernel stacks and vmalloc's blocks are. The image is
// not: nothing in it is poisoned (--asan-stack=false, --asan-globals=false).
//
// Without the flag there is no shadow and every call here returns at once.

const std = @import("std");
const memmap = @import("../mm/memmap.zig");
const vmalloc = @import("../mm/vmalloc.zig");

// ---- Configuration ----

pub const SHADOW_SCALE_SHIFT: u6 = 3; // 1 byte of shadow per (1<<3) = 8 bytes

/// No more RAM than this is tracked; its shadow is an eighth of it.
const PHYS_COVER_MAX: usize = 4 << 30;
/// Less than this and KASAN stays off: the heap would not be in it.
const PHYS_COVER_MIN: usize = 64 << 20;
/// The shadow of this much, and of its halves down to the minimum, is a
/// whole number of pages.
const COVER_ALIGN: usize = 0x200000;

// ---- Shadow byte taxonomy ----
//
// Designed to be Linux-KASAN-bit-compatible so a future compiler patch can
// reuse stock LLVM AddressSanitizer constants without translation.

pub const SHADOW_VALID: u8 = 0x00;
/// 1..7 = "first N bytes of this 8-byte group are valid, rest are
///        out-of-bounds" — used for sub-8B-granularity allocations.
pub const SHADOW_RED_ZONE: u8 = 0xFA;
pub const SHADOW_FREED: u8 = 0xFB;
pub const SHADOW_USE_AFTER_SCOPE: u8 = 0xF8;
pub const SHADOW_STACK_LEFT: u8 = 0xF1;
pub const SHADOW_STACK_MID: u8 = 0xF2;
pub const SHADOW_STACK_RIGHT: u8 = 0xF3;
pub const SHADOW_GLOBAL_REDZONE: u8 = 0xF9;
pub const SHADOW_GENERIC: u8 = 0xFF;

// ---- Runtime state ----

/// The shadow: RAM's (`phys_covered` >> 3 bytes), then the vmalloc arena's.
var shadow_base: usize = 0;
var shadow_bytes: usize = 0;
/// RAM below this physical address is tracked.
var phys_covered: usize = 0;
var vmalloc_shadow: usize = 0;
var initialized: bool = false;

/// True iff `addr` lands inside the kasan shadow window. Used by
/// debug.addrinfo to label otherwise-nondescript addresses.
pub fn isShadowAddr(addr: usize) bool {
    return initialized and addr >= shadow_base and addr < shadow_base + shadow_bytes;
}

/// Takes the shadow from the PMM as one run and marks all of it valid.
pub fn init() void {
    const pmm = @import("../mm/pmm.zig");
    const debug = @import("debug.zig");
    const build_options = @import("build_options");

    // Build-time opt-out. Compile-time-folded so the shadow alloc and the
    // hot-path callers (allocFrame's unpoison, etc.) compile away entirely
    // when the flag is off. On 128 MB QEMU the 32 MB shadow is the single
    // biggest user of contiguous PMM; disabling it frees the room needed
    // for big-bitmap user apps (wallpaper.elf, photo.elf) to run without
    // hitting fragmentation.
    if (!build_options.kasan_enabled) {
        debug.klog("[kasan] disabled at build time (-Dkasan=false); skipping shadow alloc\n", .{});
        return;
    }

    var ram_end: u64 = 0;
    for (memmap.bootMap()) |region| {
        if (region.kind == .usable) ram_end = @max(ram_end, region.base +| region.length);
    }
    var cover: usize = @intCast(@min(std.mem.alignForward(u64, ram_end, COVER_ALIGN), PHYS_COVER_MAX));
    const arena_shadow = vmalloc.VMALLOC_SIZE >> SHADOW_SCALE_SHIFT;
    // RAM with no free run this long tracks its lower half, and so on down.
    const run = while (cover >= PHYS_COVER_MIN) : (cover /= 2) {
        const pages: u32 = @intCast(((cover >> SHADOW_SCALE_SHIFT) + arena_shadow) >> 12);
        if (pmm.allocContiguous(pages)) |found| break found;
    } else {
        debug.klog("[kasan] init: no run of RAM for a shadow — disabled\n", .{});
        return;
    };
    shadow_base = run.toVirt().raw();
    shadow_bytes = (cover >> SHADOW_SCALE_SHIFT) + arena_shadow;
    phys_covered = cover;
    vmalloc_shadow = shadow_base + (cover >> SHADOW_SCALE_SHIFT);

    // All of it valid: the allocators poison what they free and fence.
    const buf: [*]u8 = @ptrFromInt(shadow_base);
    @memset(buf[0..shadow_bytes], SHADOW_VALID);
    initialized = true;

    debug.klog("[kasan] shadow @ 0x{X:0>16}, {d} KB: RAM below 0x{X} (it ends at 0x{X}) and the vmalloc arena\n", .{
        shadow_base, shadow_bytes >> 10, cover, ram_end,
    });

    selfTest();
}

/// A round trip through both pieces of the shadow. A failure turns KASAN
/// off: a kernel that boots says more than one that reports its own shadow.
fn selfTest() void {
    const debug = @import("debug.zig");
    const probes = [_]usize{
        memmap.PHYSMAP_BASE + phys_covered / 2,
        vmalloc.VMALLOC_BASE + vmalloc.VMALLOC_SIZE / 2,
    };
    for (probes) |addr| {
        const at = locate(addr) orelse {
            debug.klog("[kasan] selfTest: 0x{X} is not tracked\n", .{addr});
            initialized = false;
            return;
        };
        const saved = at.shadow[0];
        poison(addr, 8, SHADOW_FREED);
        const poisoned = at.shadow[0];
        unpoison(addr, 8);
        const cleared = at.shadow[0];
        at.shadow[0] = saved;
        if (poisoned != SHADOW_FREED or cleared != SHADOW_VALID) {
            debug.klog("[kasan] selfTest: 0x{X} read 0x{X:0>2} poisoned, 0x{X:0>2} cleared\n", .{ addr, poisoned, cleared });
            initialized = false;
            return;
        }
    }
    debug.klog("[kasan] selfTest: poison/unpoison roundtrip OK\n", .{});
}

const Tracked = struct {
    /// The shadow byte of the address's granule.
    shadow: [*]u8,
    /// Bytes from the address to the end of what is tracked with it.
    room: usize,
};

/// Where `addr`'s shadow is; null for memory KASAN does not track.
inline fn locate(addr: usize) ?Tracked {
    const phys = addr -% memmap.PHYSMAP_BASE;
    if (phys < phys_covered) return .{
        .shadow = @ptrFromInt(shadow_base + (phys >> SHADOW_SCALE_SHIFT)),
        .room = phys_covered - phys,
    };
    const in_arena = addr -% vmalloc.VMALLOC_BASE;
    if (in_arena < vmalloc.VMALLOC_SIZE) return .{
        .shadow = @ptrFromInt(vmalloc_shadow + (in_arena >> SHADOW_SCALE_SHIFT)),
        .room = vmalloc.VMALLOC_SIZE - in_arena,
    };
    return null;
}

/// Whether an access at `byte_addr` is one the tag of its granule forbids.
/// 1..7: that many bytes of the granule are valid, from its start.
inline fn forbidden(tag: u8, byte_addr: usize, size: usize) bool {
    if (tag == SHADOW_VALID) return false;
    return !(tag <= 7 and (byte_addr & 7) + size <= tag);
}

// ---- Poison / unpoison API ----

/// Mark `len` bytes starting at `addr` with the given shadow tag.
/// `len` is rounded up to the 8-byte shadow granule.
pub fn poison(addr: usize, len: usize, tag: u8) void {
    if (!initialized) return;
    const at = locate(addr) orelse return;
    // A run that starts in what is tracked may end past it; the shadow does not.
    const covered = @min(len, at.room);
    const shadow_len = (covered + 7) >> SHADOW_SCALE_SHIFT;
    @memset(at.shadow[0..shadow_len], tag);
}

pub fn unpoison(addr: usize, len: usize) void {
    poison(addr, len, SHADOW_VALID);
}

// ---- Access checking ----

/// Compile-time-specialized check. `size` and `is_write` get inlined per
/// call site, so the hot path is a single shadow-byte load + branch.
pub inline fn check(comptime size: usize, comptime is_write: bool, addr: usize) void {
    if (!initialized) return;
    const at = locate(addr) orelse return;
    // One that runs off the end of what is tracked has no shadow to its end.
    if (at.room < size) return;

    // Fast path: 8-byte-aligned access of size <= 8. One shadow byte, one
    // compare. Linux's "outline" mode does this same dance; we get there
    // for free from comptime.
    if (size <= 8 and (addr & 7) == 0) {
        const tag = at.shadow[0];
        if (forbidden(tag, addr, size)) @call(.never_inline, report, .{ addr, size, is_write, tag });
        return;
    }

    // Slow path: misaligned or >8B. Walk every shadow byte spanned.
    var off: usize = 0;
    while (off < size) {
        const byte_addr = addr + off;
        const in_granule = @min(8 - (byte_addr & 7), size - off);
        const tag = at.shadow[((addr & 7) + off) >> SHADOW_SCALE_SHIFT];
        if (forbidden(tag, byte_addr, in_granule)) {
            @call(.never_inline, report, .{ byte_addr, size, is_write, tag });
            return;
        }
        off += in_granule;
    }
}

/// An access whose size is known only at run time, byte by byte.
fn checkRun(addr: usize, size: usize, is_write: bool) void {
    if (!initialized) return;
    var off: usize = 0;
    while (off < size) : (off += 1) {
        const at = locate(addr + off) orelse continue;
        const tag = at.shadow[0];
        if (forbidden(tag, addr + off, 1)) {
            @call(.never_inline, report, .{ addr + off, 1, is_write, tag });
            return;
        }
    }
}

pub inline fn checkRead(comptime size: usize, addr: usize) void {
    check(size, false, addr);
}

pub inline fn checkWrite(comptime size: usize, addr: usize) void {
    check(size, true, addr);
}

fn tagName(tag: u8) []const u8 {
    return switch (tag) {
        SHADOW_VALID => "VALID",
        SHADOW_RED_ZONE => "RED_ZONE",
        SHADOW_FREED => "FREED",
        SHADOW_USE_AFTER_SCOPE => "USE_AFTER_SCOPE",
        SHADOW_STACK_LEFT => "STACK_LEFT_REDZONE",
        SHADOW_STACK_MID => "STACK_MID_REDZONE",
        SHADOW_STACK_RIGHT => "STACK_RIGHT_REDZONE",
        SHADOW_GLOBAL_REDZONE => "GLOBAL_REDZONE",
        SHADOW_GENERIC => "POISONED",
        1...7 => "PARTIAL_VALID_OUT_OF_BOUNDS",
        else => "UNKNOWN",
    };
}

fn report(addr: usize, size: usize, is_write: bool, tag: u8) void {
    const serial = @import("serial.zig");
    const symbols = @import("symbols.zig");

    // Stop new KASAN trips during the dump itself. Without this, the
    // crashAutopsy that walks page tables / shadow rings would re-enter
    // report() if anything it touches has been poisoned, and we'd loop.
    initialized = false;

    serial.print("\n!!! KASAN: {s} of size {d} at 0x{X:0>16} !!!\n", .{
        if (is_write) "store" else "load", size, addr,
    });
    serial.print("  Shadow tag: 0x{X:0>2} ({s})\n", .{ tag, tagName(tag) });

    // Owner attribution (task #244). If the bad address falls inside the
    // kstack_pool, name which PCB slot owned this kstack — usually enough
    // to locate the kill/destroy event in the proc ring below and find
    // when (and by whom) the kstack was freed.
    {
        const process = @import("../proc/process.zig");
        const pool_base = @intFromPtr(&process.kstack_pool[0]);
        const pool_end = pool_base + process.KSTACK_POOL_BYTES;
        if (addr >= pool_base and addr < pool_end) {
            const slot_size = @sizeOf(@TypeOf(process.kstack_pool[0]));
            const slot_idx = (addr - pool_base) / slot_size;
            const off_in_slot = (addr - pool_base) % slot_size;
            const cur_state = process.getStateRaw(slot_idx);
            serial.print("  Owner: kstack_pool[{d}] (offset 0x{X} into slot, current state byte = 0x{X:0>2})\n", .{
                slot_idx, off_in_slot, cur_state,
            });
            serial.print("  --> grep proc ring below for 'kill pid={d}' or 'destroy pid={d}' to find the freer\n", .{
                slot_idx, slot_idx,
            });
        }
    }

    // Hex dump: 32 bytes around the faulting addr, 16-aligned for readability.
    const dump_start = addr & ~@as(usize, 0xF);
    serial.print("  Hex @ 0x{X:0>16}:\n", .{dump_start});
    const dump_ptr: [*]const u8 = @ptrFromInt(dump_start);
    for (0..2) |row| {
        serial.print("    +0x{X:0>2}:", .{row * 16});
        for (0..16) |col| {
            serial.print(" {X:0>2}", .{dump_ptr[row * 16 + col]});
        }
        serial.print("\n", .{});
    }

    // Shadow bytes around the trip address: 8 before, 16 around the byte
    // for `addr`, 8 after. Helps distinguish a single corrupted byte
    // (write-through-of-bound from a neighbor) from a wider stomp.
    if (locate(addr)) |at| {
        const sh_addr = @intFromPtr(at.shadow);
        const sh_dump_start = sh_addr & ~@as(usize, 0xF);
        serial.print("  Shadow @ 0x{X:0>16} (center byte for addr): \n", .{sh_dump_start});
        const sh_dump_ptr: [*]const u8 = @ptrFromInt(sh_dump_start);
        for (0..2) |row| {
            serial.print("    +0x{X:0>2}:", .{row * 16});
            for (0..16) |col| {
                serial.print(" {X:0>2}", .{sh_dump_ptr[row * 16 + col]});
            }
            serial.print("\n", .{});
        }
        serial.print("  Shadow base 0x{X:0>16}, {d} KB\n", .{ shadow_base, shadow_bytes >> 10 });
    }

    // Symbol-resolved RBP-chain backtrace. Bounded depth to prevent runaway.
    serial.print("  Backtrace:\n", .{});
    const rbp_now: u64 = asm volatile ("mov %%rbp, %[r]"
        : [r] "=r" (-> u64),
    );
    var rbp: u64 = rbp_now;
    var depth: u32 = 0;
    while (depth < 12) : (depth += 1) {
        // A kernel stack is in the kernel's half.
        if (rbp < memmap.PHYSMAP_BASE) break;
        const frame: [*]const u64 = @ptrFromInt(rbp);
        const ret_addr = frame[1];
        if (ret_addr == 0) break;
        serial.print("    [{d}] 0x{X:0>16}", .{ depth, ret_addr });
        if (symbols.resolveKernel(ret_addr)) |r| {
            serial.print("  {s}+0x{X}", .{ r.name, r.offset });
        }
        serial.print("\n", .{});
        const next = frame[0];
        if (next <= rbp) break;
        rbp = next;
    }

    // Hand off to kdbg for the full state dump (CPU snap, proc snap, ring
    // dumps). KASAN already disabled itself above so this can't recurse.
    @import("kdbg.zig").crashAutopsy(.{ .kernel_rsp = rbp_now });

    @panic("KASAN: bad memory access");
}

// =============================================================================
// Heap hooks
// =============================================================================
//
// Heap.zig calls allocHook() right after a successful kmalloc and freeHook()
// just before relinking a freed block. Each block is sandwiched between two
// `HEAP_REDZONE`-byte poisoned regions so a 1..16-byte overflow trips KASAN
// instead of silently corrupting the next allocation.
//
// Quarantine: freed blocks stay poisoned for QUARANTINE_RING entries past the
// kfree before kmalloc can re-hand them out. That window catches typical
// "kfree(p); use(p);" use-after-free races even though the heap immediately
// puts the slot back on its free list.

pub const HEAP_REDZONE: usize = 16;
const QUARANTINE_RING: usize = 64;

const QuarantineEntry = struct { addr: usize = 0, len: usize = 0 };
var quarantine: [QUARANTINE_RING]QuarantineEntry = [_]QuarantineEntry{.{}} ** QUARANTINE_RING;
var quarantine_head: usize = 0;

/// Mark a freshly-allocated block: redzones either side, body unpoisoned.
pub fn allocHook(addr: usize, user_size: usize) void {
    if (!initialized) return;
    if (addr < HEAP_REDZONE) return;
    poison(addr - HEAP_REDZONE, HEAP_REDZONE, SHADOW_RED_ZONE);
    unpoison(addr, user_size);
    // Right redzone must start on the next 8-byte shadow granule boundary.
    // unpoison() rounds the body UP to a whole granule (1 shadow byte per 8
    // bytes), so poisoning the redzone at the raw addr+user_size — which is
    // mid-granule whenever user_size isn't a multiple of 8 — would memset
    // that shared tail granule to RED_ZONE and bury the live body bytes
    // under it, tripping a false-positive report on the allocation's own
    // tail. Rounding the start up keeps the redzone on bytes genuinely past
    // the (granule-rounded) body.
    const body_rounded = (user_size + 7) & ~@as(usize, 7);
    poison(addr + body_rounded, HEAP_REDZONE, SHADOW_RED_ZONE);
}

/// Mark a freed block: entire span (with both redzones) poisoned as freed.
/// The block enters the quarantine ring; KASAN keeps the poison until at
/// least QUARANTINE_RING further frees displace it.
pub fn freeHook(addr: usize, user_size: usize) void {
    if (!initialized) return;
    if (addr < HEAP_REDZONE) return;
    const span = HEAP_REDZONE + user_size + HEAP_REDZONE;
    poison(addr - HEAP_REDZONE, span, SHADOW_FREED);
    quarantine[quarantine_head] = .{ .addr = addr - HEAP_REDZONE, .len = span };
    quarantine_head = (quarantine_head + 1) % QUARANTINE_RING;
}

// =============================================================================
// IRQ-frame canary
// =============================================================================
//
// The wild-writer hunt has been blocked because corruption only manifests on
// the next ret/iretq long after the writer has moved on. The canary inverts
// that: at every IRQ entry we stamp a magic word into the slot just below
// RSP; on exit we verify it. If the value isn't ours, something hit our
// kstack between entry and exit — KASAN trips with backtrace pointing at the
// IRQ handler that failed the check (one frame up from the writer).

pub const FRAME_CANARY_MAGIC: u64 = 0xCA5A_DEAD_BEEF_FACE;

pub inline fn placeFrameCanary(rsp: u64) void {
    if (!initialized) return;
    const slot: *u64 = @ptrFromInt(rsp - 8);
    slot.* = FRAME_CANARY_MAGIC;
}

pub inline fn checkFrameCanary(rsp: u64, where: []const u8) void {
    if (!initialized) return;
    const slot: *const u64 = @ptrFromInt(rsp - 8);
    if (slot.* != FRAME_CANARY_MAGIC) {
        const serial = @import("serial.zig");
        serial.print("\n!!! KASAN frame canary clobbered ({s}) !!!\n", .{where});
        serial.print("  slot 0x{X:0>16} expected 0x{X:0>16} got 0x{X:0>16}\n", .{
            rsp - 8, FRAME_CANARY_MAGIC, slot.*,
        });
        @panic("KASAN: frame canary corrupted");
    }
}

// =============================================================================
// Boot-time region poisoning
// =============================================================================
//
// Helpers for installing redzones at known boundaries. Call from kmain after
// kasan.init() but before user-mode is reached.

/// Poison the unmapped guard portion at the bottom of every kstack-pool slot.
/// Catches overflows that would otherwise have to survive a hardware page-
/// fault to reach our diagnostic.
pub fn installKstackRedZones(pool_base: usize, slot_count: usize, slot_size: usize, body_size: usize) void {
    if (!initialized) return;
    const guard_size = slot_size - body_size;
    for (0..slot_count) |i| {
        poison(pool_base + i * slot_size, guard_size, SHADOW_STACK_LEFT);
    }
}

/// Mark a freshly-spawned process's kstack body as valid. Counterpart to
/// markPcbDead(); call when a slot transitions from .unused to .ready.
pub fn markPcbAlive(kstack_base: usize, kstack_body_size: usize) void {
    if (!initialized) return;
    unpoison(kstack_base, kstack_body_size);
}

/// Mark a dead PCB's kstack as freed. Call from process exit / reapZombie.
pub fn markPcbDead(kstack_base: usize, kstack_body_size: usize) void {
    if (!initialized) return;
    poison(kstack_base, kstack_body_size, SHADOW_FREED);
}

// =============================================================================
// Manual instrumentation convenience
// =============================================================================
//
// Drop these into hot paths the compiler doesn't yet auto-instrument.

pub inline fn markDead(addr: usize, len: usize) void {
    poison(addr, len, SHADOW_FREED);
}

pub inline fn markAlive(addr: usize, len: usize) void {
    unpoison(addr, len);
}

/// Assert every byte in [addr, addr+len) is currently SHADOW_VALID. Use at
/// known invariants (e.g. "the iretq frame slot must be valid right now").
pub fn expectValid(addr: usize, len: usize) void {
    checkRun(addr, len, false);
}

// =============================================================================
// Compiler-emitted entry points
// =============================================================================
//
// The `asan<kernel>` pass (`-Dkasan`: build.zig, instrumentedObject) is run
// with --asan-instrumentation-with-call-threshold=0: every access in an
// instrumented function is a CALL to one of the symbols below, none is a
// shadow lookup inlined at the site. It has to be so: the shadow is in two
// pieces, and an inlined lookup knows one offset.
//
//   • `__asan_loadN(addr)` / `__asan_storeN(addr)` — the access checks.
//     These return; each is a `check()`.
//
//   • `__asan_report_loadN(addr)` / `__asan_report_storeN(addr)`, and the
//     `_n` pair with a size — what an inlined check would call. Followed by
//     `unreachable`, so they MUST NOT return; they panic.
//
//   • `__asan_handle_no_return()` — called before any noreturn function.
//
//   • `__asan_register_globals(...)` and friends — module-ctor stubs.

/// What an inlined check would add to `addr >> 3`. The pass wants the
/// symbol (--asan-force-dynamic-shadow) and loads it; nothing uses the value.
export var __asan_shadow_memory_dynamic_address: u64 = 0;

fn reportInline(addr: usize, size: usize, is_write: bool) callconv(.c) noreturn {
    // The pass emits `unreachable` immediately after these calls, so we must
    // not return. Look up the actual shadow byte ourselves so the report
    // shows what tripped (RED_ZONE vs FREED vs misalign) rather than a bogus
    // SHADOW_GENERIC placeholder.
    const tag: u8 = if (locate(addr)) |at| at.shadow[0] else SHADOW_GENERIC;
    @call(.never_inline, report, .{ addr, size, is_write, tag });
    unreachable;
}

comptime {
    const sizes = [_]usize{ 1, 2, 4, 8, 16 };
    for (sizes) |sz| {
        const Outline = struct {
            fn load(addr: usize) callconv(.c) void {
                check(sz, false, addr);
            }
            fn store(addr: usize) callconv(.c) void {
                check(sz, true, addr);
            }
        };
        const Reporter = struct {
            fn load(addr: usize) callconv(.c) noreturn {
                reportInline(addr, sz, false);
            }
            fn store(addr: usize) callconv(.c) noreturn {
                reportInline(addr, sz, true);
            }
        };
        @export(&Outline.load, .{ .name = std.fmt.comptimePrint("__asan_load{d}", .{sz}) });
        @export(&Outline.store, .{ .name = std.fmt.comptimePrint("__asan_store{d}", .{sz}) });
        @export(&Reporter.load, .{ .name = std.fmt.comptimePrint("__asan_report_load{d}", .{sz}) });
        @export(&Reporter.store, .{ .name = std.fmt.comptimePrint("__asan_report_store{d}", .{sz}) });
    }
}

// Variable-size variants. The pass calls these for vector / memcpy-like ops.

export fn __asan_loadN(addr: usize, size: usize) callconv(.c) void {
    checkRun(addr, size, false);
}

export fn __asan_storeN(addr: usize, size: usize) callconv(.c) void {
    checkRun(addr, size, true);
}

export fn __asan_report_load_n(addr: usize, size: usize) callconv(.c) noreturn {
    reportInline(addr, size, false);
}

export fn __asan_report_store_n(addr: usize, size: usize) callconv(.c) noreturn {
    reportInline(addr, size, true);
}

/// Called once per module to register itself. We have nothing to do.
export fn __asan_init() callconv(.c) void {}

/// Called before any noreturn function. We don't track stack red zones yet,
/// so it's a no-op. (When we add stack instrumentation, this is where we'd
/// flush the shadow for any unwound stack frames.)
export fn __asan_handle_no_return() callconv(.c) void {}

/// Globals registration — emitted at module init for `.data` red zones.
/// No-op for now. The kernel has one module so the pass calls these once
/// from `asan.module_ctor` which we manually invoke from kmain (or skip).
export fn __asan_register_globals(_: usize, _: usize) callconv(.c) void {}
export fn __asan_unregister_globals(_: usize, _: usize) callconv(.c) void {}
export fn __asan_register_image_globals(_: usize) callconv(.c) void {}
export fn __asan_unregister_image_globals(_: usize) callconv(.c) void {}
export fn __asan_register_elf_globals(_: usize, _: usize, _: usize) callconv(.c) void {}
export fn __asan_unregister_elf_globals(_: usize, _: usize, _: usize) callconv(.c) void {}
export fn __asan_before_dynamic_init(_: usize) callconv(.c) void {}
export fn __asan_after_dynamic_init() callconv(.c) void {}

/// Pointer comparison hooks (emitted with `--asan-detect-invalid-pointer-pair`).
/// Off by default; provide stubs in case the pass enables them.
export fn __sanitizer_ptr_cmp(_: usize, _: usize) callconv(.c) void {}
export fn __sanitizer_ptr_sub(_: usize, _: usize) callconv(.c) void {}
