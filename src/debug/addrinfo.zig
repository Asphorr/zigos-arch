// Address annotator. Given a kernel/user address, return a one-line
// human-readable description of WHAT the address is. Used by panic dumps,
// watch-hit reports, KASAN reports, and hex dumps so the reader doesn't
// have to mentally cross-reference a raw 0xFFFF... bare integer against
// memmap.zig + symbols + slab/heap state.
//
// Output buffer is a single global slice — describe() is called from
// synchronous diagnostic contexts (panic critical section, watch handler)
// where one CPU is already serialized. Caller must consume the result
// before calling describe() again.
//
// Categories, checked in order:
//   1. Kernel high half (>= KERNEL_VIRT_BASE, < PHYSMAP_BASE) — symbol+offset
//   2. Physmap window — heap range / slab object / kasan shadow / generic
//   3. Kstack of pid N — based on expected_kstack_tops[]
//   4. User space — VA range + sub-region (text/heap/stack)
//   5. Static low-VA memmap regions — guest_fb, back_buffer, uefi_pt, etc.
//   6. Otherwise: unmapped / unknown
//
// Cheap-and-best-effort: we never deref untrusted pointers (the slab query
// uses page-mask + magic check, never walks unmapped memory).

const std = @import("std");
const memmap = @import("../mm/memmap.zig");
const symbols = @import("symbols.zig");
const heap = @import("../mm/heap.zig");
const slab = @import("../mm/slab.zig");
const kasan = @import("kasan.zig");
const config = @import("../config.zig");

var buf: [256]u8 = undefined;

/// One-line description of `addr`. Returned slice points into a static
/// buffer that the next describe() call will overwrite.
pub fn describe(addr: usize) []const u8 {
    return render(addr) catch "<addrinfo: format overflow>";
}

fn render(addr: usize) ![]const u8 {
    if (addr == 0) return std.fmt.bufPrint(&buf, "null", .{});

    // 1. Kernel image — top 2 GB of canonical address space (KERNEL_VIRT_BASE
    // is HIGHER than PHYSMAP_BASE numerically, so it must come first; checking
    // physmap before this would mis-claim kernel-image addresses).
    if (addr >= memmap.KERNEL_VIRT_BASE) {
        if (symbols.resolveKernel(addr)) |r| {
            return std.fmt.bufPrint(&buf, "kernel:{s}+0x{x}", .{ r.name, r.offset });
        }
        return std.fmt.bufPrint(&buf, "kernel-image @0x{x}", .{addr});
    }

    // 2. Physmap window — kernel's view of any phys frame.
    if (addr >= memmap.PHYSMAP_BASE and addr < memmap.PHYSMAP_BASE + memmap.PHYSMAP_SIZE) {
        const phys = addr - memmap.PHYSMAP_BASE;
        if (addr >= heap.HEAP_START and addr < heap.HEAP_START + heap.HEAP_SIZE) {
            return std.fmt.bufPrint(&buf, "heap[+0x{x}/0x{x}] phys=0x{x}", .{
                addr - heap.HEAP_START, heap.HEAP_SIZE, phys,
            });
        }
        if (slab.querySlabAddr(addr)) |info| {
            if (info.is_header) {
                return std.fmt.bufPrint(&buf, "slab '{s}' header phys=0x{x}", .{ info.cache_name, phys });
            }
            return std.fmt.bufPrint(&buf, "slab '{s}' obj#{d}/+0x{x} phys=0x{x}", .{
                info.cache_name, info.obj_index, info.obj_byte_off, phys,
            });
        }
        if (kasan.isShadowAddr(addr)) {
            return std.fmt.bufPrint(&buf, "kasan-shadow phys=0x{x}", .{phys});
        }
        return std.fmt.bufPrint(&buf, "physmap phys=0x{x}", .{phys});
    }

    // 3. Kstack — walk expected_kstack_tops[] for any pid that owns this VA.
    const proc = @import("../proc/process.zig");
    for (proc.expected_kstack_tops, 0..) |top, pid| {
        if (top == 0) continue;
        const lo = top - config.KSTACK_SIZE;
        if (addr >= lo and addr < top) {
            return std.fmt.bufPrint(&buf, "kstack pid={d} '{s}' top-0x{x}", .{
                pid, procName(@intCast(pid)), top - addr,
            });
        }
    }

    // 4. User-space layout. The "user-text" sub-range is a heuristic for
    // labelling backtraces — apps typically have .text within ~2 MB of the
    // load base, so anything in [USER_VA_FLOOR, USER_VA_FLOOR+0x200000) is
    // probably code. Outside that but inside user space → likely heap/mmap.
    const USER_TEXT_HI: usize = memmap.USER_VA_FLOOR + 0x200000;
    if (addr >= memmap.USER_VA_FLOOR and addr < memmap.USER_SPACE_END) {
        if (addr < USER_TEXT_HI) {
            return std.fmt.bufPrint(&buf, "user-text @0x{x}", .{addr});
        }
        return std.fmt.bufPrint(&buf, "user-va @0x{x}", .{addr});
    }
    if (addr >= memmap.USER_SPACE_START and addr < memmap.USER_VA_FLOOR) {
        return std.fmt.bufPrint(&buf, "user-stack-reserve @0x{x}", .{addr});
    }

    // 5. Static low-VA memmap regions.
    if (addr >= memmap.GUEST_FB_BASE and addr < memmap.GUEST_FB_BASE + memmap.GUEST_FB_SIZE) {
        return std.fmt.bufPrint(&buf, "guest_fb +0x{x}", .{addr - memmap.GUEST_FB_BASE});
    }
    if (addr >= memmap.BACK_BUFFER_BASE and addr < memmap.BACK_BUFFER_BASE + memmap.BACK_BUFFER_SIZE) {
        return std.fmt.bufPrint(&buf, "back_buffer +0x{x}", .{addr - memmap.BACK_BUFFER_BASE});
    }
    if (addr >= memmap.UEFI_PT_BASE and addr < memmap.UEFI_PT_BASE + memmap.UEFI_PT_SIZE) {
        return std.fmt.bufPrint(&buf, "uefi_pt +0x{x}", .{addr - memmap.UEFI_PT_BASE});
    }
    if (addr >= memmap.KERNEL_PHYS_START and addr < memmap.kernelEndPhys()) {
        return std.fmt.bufPrint(&buf, "kernel-image-phys @0x{x}", .{addr});
    }

    return std.fmt.bufPrint(&buf, "unmapped/unknown 0x{x}", .{addr});
}

fn procName(pid: u8) []const u8 {
    const proc = @import("../proc/process.zig");
    if (pid >= proc.MAX_PROCS) return "?";
    const p = &proc.procs[pid];
    if (p.name_len == 0) return "?";
    return p.name[0..p.name_len];
}
