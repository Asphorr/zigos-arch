// KASAN-style address sanitizer skeleton for ZigOS.
//
// Scope of this file (deliberately): a runtime that *would* receive calls
// from compiler-emitted instrumentation if we ever taught Zig 0.15.x to
// pass `-fsanitize=kernel-address` through to LLVM. Today it serves as:
//
//   1) a manual-instrumentation library — `kasan.checkWrite(@sizeOf(T), addr)`
//      at chosen sites in the kernel, no compiler help required;
//   2) a proof of concept that the runtime side fits cleanly in idiomatic
//      Zig: comptime-generated `__asan_load{1,2,4,8,16}` and `__asan_store*`
//      thunks (one source line per family vs Linux/Rust's hand-rolled 20+);
//   3) a shadow-memory translation that exists at compile time — the math
//      to find a shadow byte for any address inside the covered region is
//      a pure comptime arithmetic, no runtime tables.
//
// Coverage region: [REGION_LO, REGION_HI). Shadow is one byte per 8 bytes
// of memory (1:8 scale, same as Linux KASAN's classic mode).
//
// Not yet wired: stack red zones around iretq frames, allocator hooks
// (PMM mark-free → poison), heap red zones. Those are the next 500-LOC
// pass once the runtime is proven.

const std = @import("std");
const memmap = @import("../mm/memmap.zig");

// ---- Configuration ----

/// Lowest address covered by the shadow. The compiler-emitted inline check
/// has no bounds test — every memory access in an instrumented function
/// computes `shadow = (addr >> 3) + dyn_addr` unconditionally. So the
/// shadow region must cover every address those functions might touch.
/// `0` covers IVT/EBDA/VGA-text (0xB8000) too, costing only an extra 128 KB
/// of shadow memory (the size delta for shifting REGION_LO from 0x100000).
pub const REGION_LO: usize = 0x0;

/// Highest address covered by the shadow. 256 MB ceiling — covers kernel
/// image, heap, guest FB, back buffer, kstack pool, per-CPU TSS, and the
/// bulk of PMM-allocated kernel pages including GUI framebuffers and
/// per-process page tables. Shadow size = 32 MB. Anything above this
/// (LAPIC, HPET, PCI BARs ≥ 4 GB) MUST be handled in denylisted code, or
/// the inline check will read garbage from above shadow_base + 32 MB.
pub const REGION_HI: usize = 0x10000000;

pub const REGION_SIZE: usize = REGION_HI - REGION_LO;
pub const SHADOW_SCALE_SHIFT: u6 = 3; // 1 byte of shadow per (1<<3) = 8 bytes
pub const SHADOW_SIZE: usize = REGION_SIZE >> SHADOW_SCALE_SHIFT;

// Sanity: shadow must be a whole number of pages.
comptime {
    if (SHADOW_SIZE & 0xFFF != 0) @compileError("kasan: SHADOW_SIZE not page-aligned");
    if (REGION_LO & 7 != 0) @compileError("kasan: REGION_LO must be 8-byte aligned");
}

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

var shadow_base: usize = 0;
var initialized: bool = false;

/// True iff `addr` lands inside the kasan shadow window. Used by
/// debug.addrinfo to label otherwise-nondescript addresses.
pub fn isShadowAddr(addr: usize) bool {
    return initialized and addr >= shadow_base and addr < shadow_base + SHADOW_SIZE;
}

/// Allocate a contiguous physical block for the shadow region and zero it.
/// Below 4 GB is fine — kernel VA is identity-mapped to PA there.
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

    const num_pages: u32 = @intCast(SHADOW_SIZE >> 12);
    debug.klog("[kasan] init: requesting {d} contiguous pages ({d} KB)\n", .{ num_pages, SHADOW_SIZE >> 10 });
    const phys = pmm.allocContiguous(num_pages) orelse {
        debug.klog("[kasan] init: pmm.allocContiguous({d}) failed — disabling\n", .{num_pages});
        return;
    };
    debug.klog("[kasan] init: got phys=0x{X} — zeroing\n", .{phys});
    // Phase 3: store the physmap-translated VA so the shadow stays
    // dereferenceable after PML4[0] is dropped. The compiler-emitted
    // inline check below uses (addr >> 3) + dyn_addr; dyn_addr is
    // computed from `shadow_base`, so it inherits the same translation.
    const paging = @import("../mm/paging.zig");
    shadow_base = paging.physToVirt(phys);

    // Mark everything valid by default. Callers later poison specific
    // regions (red zones, freed allocations) via poison().
    const buf: [*]u8 = @ptrFromInt(shadow_base);
    @memset(buf[0..SHADOW_SIZE], SHADOW_VALID);
    debug.klog("[kasan] init: zeroed\n", .{});

    // Wire up the dynamic shadow address for compiler-injected inline checks.
    // Pass emits `shadow_byte = *((addr >> 3) + dyn_addr)`, so:
    //   dyn_addr = shadow_base - (REGION_LO >> 3)
    // makes the lookup land at `shadow_base + ((addr - REGION_LO) >> 3)`.
    // Until this line runs, the global is 0 — every instrumented function
    // load would compute a bogus shadow VA. The early-boot denylist in
    // `tools/kasan_pipeline.sh` covers all callers that may execute before
    // we get here.
    __asan_shadow_memory_dynamic_address = @intCast(shadow_base -% (REGION_LO >> SHADOW_SCALE_SHIFT));

    initialized = true;

    debug.klog("[kasan] shadow @ 0x{X:0>16}, {d} KB covers [0x{X}..0x{X})\n", .{
        shadow_base, SHADOW_SIZE >> 10, REGION_LO, REGION_HI,
    });

    selfTest();
}

/// Boot-time roundtrip exercise. Picks an address inside the tracked
/// region but unlikely to be in active use, poisons it, verifies the
/// shadow byte changed, unpoisons, restores. If anything fails, log and
/// disable KASAN — better silent than crashing the kernel during init.
fn selfTest() void {
    const debug = @import("debug.zig");
    if (!initialized) return;

    const test_addr: usize = REGION_LO + (REGION_SIZE / 2);
    const sh_ptr = memToShadow(test_addr) orelse {
        debug.klog("[kasan] selfTest: memToShadow returned null\n", .{});
        initialized = false;
        return;
    };
    const saved = sh_ptr[0];

    poison(test_addr, 64, SHADOW_FREED);
    if (sh_ptr[0] != SHADOW_FREED) {
        debug.klog("[kasan] selfTest: poison did not stick (got 0x{X:0>2})\n", .{sh_ptr[0]});
        initialized = false;
        return;
    }
    unpoison(test_addr, 64);
    if (sh_ptr[0] != SHADOW_VALID) {
        debug.klog("[kasan] selfTest: unpoison did not stick (got 0x{X:0>2})\n", .{sh_ptr[0]});
        initialized = false;
        return;
    }
    sh_ptr[0] = saved;
    debug.klog("[kasan] selfTest: poison/unpoison roundtrip OK\n", .{});
}

/// Translate an address inside the covered region to its shadow byte.
/// Returns null for addresses outside [REGION_LO, REGION_HI).
inline fn memToShadow(addr: usize) ?[*]u8 {
    if (addr < REGION_LO or addr >= REGION_HI) return null;
    const off = (addr - REGION_LO) >> SHADOW_SCALE_SHIFT;
    return @ptrFromInt(shadow_base + off);
}

// ---- Poison / unpoison API ----

/// Mark `len` bytes starting at `addr` with the given shadow tag.
/// `len` is rounded up to the 8-byte shadow granule.
pub fn poison(addr: usize, len: usize, tag: u8) void {
    if (!initialized) return;
    const ptr = memToShadow(addr) orelse return;
    const shadow_len = (len + 7) >> SHADOW_SCALE_SHIFT;
    @memset(ptr[0..shadow_len], tag);
}

pub fn unpoison(addr: usize, len: usize) void {
    poison(addr, len, SHADOW_VALID);
}

// ---- Access checking ----

/// Compile-time-specialized check. `size` and `is_write` get inlined per
/// call site, so the hot path is a single shadow-byte load + branch.
pub inline fn check(comptime size: usize, comptime is_write: bool, addr: usize) void {
    if (!initialized) return;
    if (addr < REGION_LO or addr + size > REGION_HI) return;

    // Fast path: 8-byte-aligned access of size <= 8. One shadow byte, one
    // compare. Linux's "outline" mode does this same dance; we get there
    // for free from comptime.
    if (size <= 8 and (addr & 7) == 0) {
        const sh: [*]u8 = @ptrFromInt(shadow_base + ((addr - REGION_LO) >> SHADOW_SCALE_SHIFT));
        const tag = sh[0];
        if (tag == SHADOW_VALID) return;
        // Sub-8B partial validity: tag = N means first N bytes ok.
        if (tag >= 1 and tag <= 7 and size <= tag) return;
        @call(.never_inline, report, .{ addr, size, is_write, tag });
        return;
    }

    // Slow path: misaligned or >8B. Walk every shadow byte spanned.
    var off: usize = 0;
    while (off < size) {
        const byte_addr = addr + off;
        const sh: [*]u8 = @ptrFromInt(shadow_base + ((byte_addr - REGION_LO) >> SHADOW_SCALE_SHIFT));
        const tag = sh[0];
        if (tag != SHADOW_VALID) {
            const last_byte_in_group = byte_addr & 7;
            if (!(tag >= 1 and tag <= 7 and last_byte_in_group < tag)) {
                @call(.never_inline, report, .{ byte_addr, size, is_write, tag });
                return;
            }
        }
        off += 8 - (byte_addr & 7);
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
    if (memToShadow(addr)) |sh_center| {
        const sh_addr = @intFromPtr(sh_center);
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
        serial.print("  Shadow base 0x{X:0>16}, dyn_addr 0x{X:0>16}\n", .{
            shadow_base, __asan_shadow_memory_dynamic_address,
        });
    }

    // Symbol-resolved RBP-chain backtrace. Bounded depth to prevent runaway.
    serial.print("  Backtrace:\n", .{});
    const rbp_now: u64 = asm volatile ("mov %%rbp, %[r]"
        : [r] "=r" (-> u64),
    );
    var rbp: u64 = rbp_now;
    var depth: u32 = 0;
    while (depth < 12) : (depth += 1) {
        if (rbp == 0 or rbp < REGION_LO) break;
        if (rbp >= 0x0000_8000_0000_0000 and rbp < 0xFFFF_8000_0000_0000) break;
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
    poison(addr + user_size, HEAP_REDZONE, SHADOW_RED_ZONE);
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
    if (!initialized) return;
    if (addr < REGION_LO or addr + len > REGION_HI) return;
    var off: usize = 0;
    while (off < len) : (off += 1) {
        const sh = memToShadow(addr + off) orelse continue;
        const tag = sh[0];
        if (tag == SHADOW_VALID) continue;
        if (tag >= 1 and tag <= 7 and ((addr + off) & 7) < tag) continue;
        @call(.never_inline, report, .{ addr + off, 1, false, tag });
        return;
    }
}

// =============================================================================
// Compiler-emitted entry points
// =============================================================================
//
// When the kernel is built via the LLVM `asan<kernel>` IR-pass pipeline (see
// `tools/kasan_pipeline.sh` + `-Dkasan=true` in build.zig), the pass injects
// inline shadow checks at every memory access in instrumented functions and
// emits CALLS to the symbols below for the slow paths:
//
//   • `__asan_report_loadN(addr)` / `__asan_report_storeN(addr)` — invoked
//     when the inline shadow check trips. Followed by `unreachable`, so these
//     MUST NOT return; they panic.
//
//   • `__asan_report_load_n(addr, size)` / `__asan_report_store_n(...)` —
//     same for accesses with a runtime-variable size (vectorized stores).
//
//   • `__asan_loadN(addr)` / `__asan_storeN(addr)` — out-of-line variants for
//     when the pass disables inlining. These DO return; equivalent to a
//     manual `check()` call.
//
//   • `__asan_handle_no_return()` — called before any noreturn function.
//
//   • `__asan_register_globals(...)` and friends — module-ctor stubs.
//
//   • `__asan_shadow_memory_dynamic_address` — i64 global the pass loads at
//     each instrumented function's prologue. We set it from `kasan.init()`
//     to `shadow_base - (REGION_LO >> 3)`, so the inline check
//     `shadow_byte = *((addr >> 3) + dyn_addr)` lands inside our shadow.
//
// Until kasan.init() runs, the global is 0. Functions that may run before
// init MUST be on the no_sanitize denylist in `tools/kasan_pipeline.sh` —
// otherwise they'd dereference a bogus shadow address and trip a phantom
// report on entry.

/// Set by kasan.init() to `shadow_base - (REGION_LO >> 3)`. Read by every
/// instrumented function as part of its inline shadow check. Must be a real
/// `var` (not `const`) — the LLVM pass emits a load from this symbol.
export var __asan_shadow_memory_dynamic_address: u64 = 0;

fn reportInline(addr: usize, size: usize, is_write: bool) callconv(.c) noreturn {
    // The pass emits `unreachable` immediately after these calls, so we must
    // not return. Look up the actual shadow byte ourselves so the report
    // shows what tripped (RED_ZONE vs FREED vs misalign) rather than a bogus
    // SHADOW_GENERIC placeholder.
    const tag: u8 = if (memToShadow(addr)) |sh| sh[0] else SHADOW_GENERIC;
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
    if (!initialized) return;
    if (addr < REGION_LO or addr + size > REGION_HI) return;
    var off: usize = 0;
    while (off < size) : (off += 1) {
        const sh = memToShadow(addr + off) orelse continue;
        if (sh[0] == SHADOW_VALID) continue;
        @call(.never_inline, report, .{ addr + off, 1, false, sh[0] });
        return;
    }
}

export fn __asan_storeN(addr: usize, size: usize) callconv(.c) void {
    if (!initialized) return;
    if (addr < REGION_LO or addr + size > REGION_HI) return;
    var off: usize = 0;
    while (off < size) : (off += 1) {
        const sh = memToShadow(addr + off) orelse continue;
        if (sh[0] == SHADOW_VALID) continue;
        @call(.never_inline, report, .{ addr + off, 1, true, sh[0] });
        return;
    }
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
