// GOP scanout driver — the real-hardware display path.
//
// QEMU has virtio-gpu (and BGA); a real machine has neither — after
// ExitBootServices the only display the kernel can reach without a vendor
// GPU driver is the UEFI GOP linear framebuffer. And real CSM-less UEFI has
// NO VGA text mode either (writes to 0xB8000 go nowhere), so "decline the
// GOP and fall back to text" — the old early_fb behavior for any GOP that
// wasn't BGRA with stride == width — meant a completely dark machine.
//
// gfx has no row-pitch concept (every primitive addresses pixels as
// `y * width + x` and writes 0x00RRGGBB), so the two real-firmware GOP
// shapes it can't address directly are handled by mode here:
//
//   direct: BGRA and stride == width. gfx renders straight into the panel
//           framebuffer — exactly what early_fb has always done on QEMU/OVMF.
//           flush()/flushRect() are no-ops (the panel scans the live buffer).
//
//   blit:   padded stride (1366-wide panels pad scanlines to 1376 px) and/or
//           RGBA byte order. gfx renders into the fixed GUEST_FB region —
//           8 MB reserved in the kernel memory layout (uefi_layout.zig),
//           mapped from the first instruction, PMM-reserved at init, and
//           otherwise idle when virtio-gpu isn't present — and flush copies
//           rows into the panel FB honoring pixels-per-scanline, swapping
//           R/B for RGBA. The same TRANSFER+FLUSH shape as virtio-gpu, so
//           the desktop's flush call sites dispatch here unchanged (see
//           ui/display.zig).
//
// main.zig remaps the GOP FB write-combining once PAT is up (Phase 2), so
// blits run at WC speed for the rest of boot and the whole desktop session.
//
// Resolution changes are impossible here: GOP SetMode is boot-services-only,
// gone after ExitBootServices. The bootloader picks the best kernel-fit mode
// (uefi_boot.zig pickBestGopMode) — ≤ 1920x1080, ≤ 8 MB, preferring BGRA
// with stride == width — so `direct` is the common case even on real metal.

const boot_info_mod = @import("../boot/boot_info.zig");
const paging = @import("../mm/paging.zig");
const memmap = @import("../mm/memmap.zig");
const debug = @import("../debug/debug.zig");

pub var active: bool = false;
/// True when gfx renders into the panel FB itself (flush is then a no-op).
pub var direct: bool = false;
/// What gfx renders into: the panel FB (direct) or the GUEST_FB region (blit).
pub var framebuffer: [*]volatile u32 = undefined;
pub var width: u32 = 0;
pub var height: u32 = 0;

var panel: [*]volatile u32 = undefined; // the real GOP FB through the physmap
var stride_px: u32 = 0; // panel pixels-per-scanline (>= width)
var rgba: bool = false; // panel wants R/B swapped relative to gfx's BGRA

/// Adopt the BootInfo GOP framebuffer. Idempotent — the first successful
/// call wins. False when there is no usable GOP: absent/zero descriptor,
/// unknown pixel format, stride narrower than the width (malformed), or a
/// blit-mode resolution too big for the GUEST_FB back buffer (the bootloader
/// mode picker prevents that; this is the belt to its suspenders).
///
/// Safe to call before PMM/heap exist: both the panel FB and GUEST_FB are
/// reached through the boot page tables' physmap, and GUEST_FB is a fixed
/// layout region (never PMM-allocated) that pmm.init reserves wholesale.
pub fn init(fb: boot_info_mod.FramebufferInfo) bool {
    if (active) return true;
    if (fb.base == 0 or fb.width == 0 or fb.height == 0) return false;
    if (fb.format != 0 and fb.format != 1) return false; // 0=BGRA 1=RGBA
    if (fb.stride < fb.width) return false;

    width = fb.width;
    height = fb.height;
    stride_px = fb.stride;
    rgba = fb.format == 1;
    panel = @ptrFromInt(paging.physToVirt(@as(usize, @intCast(fb.base))));
    direct = !rgba and stride_px == width;

    if (direct) {
        framebuffer = panel;
    } else {
        const need: u64 = @as(u64, width) * @as(u64, height) * 4;
        if (need > memmap.GUEST_FB_SIZE) {
            debug.klog("[gop] {d}x{d} needs {d} KB > GUEST_FB ({d} KB) — cannot back-buffer\n", .{ width, height, need / 1024, memmap.GUEST_FB_SIZE / 1024 });
            return false;
        }
        framebuffer = @ptrFromInt(paging.physToVirt(memmap.GUEST_FB_BASE));
        // The region is never bulk-zeroed; clear our slice of it once so the
        // first partial flush doesn't push stale memory to the panel.
        const words: usize = @as(usize, width) * @as(usize, height);
        var i: usize = 0;
        while (i < words) : (i += 1) framebuffer[i] = 0;
    }

    active = true;
    debug.klog("[gop] {s} scanout {d}x{d} (panel stride {d} px, {s}) fb=0x{X}\n", .{
        if (direct) "direct" else "blit",
        width,                          height,
        stride_px,                      if (rgba) "RGBA" else "BGRA",
        fb.base,
    });
    return true;
}

/// Push the full frame to the panel. No-op in direct mode (live scanout).
pub fn flush() void {
    flushRect(0, 0, width, height);
}

/// Push one rectangle to the panel, honoring the panel's row stride and byte
/// order. Plain row copies — called from the desktop's single compositor
/// task (plus boot/panic screens before/after it exists), so no locking;
/// a racing caller at worst paints pixels twice.
pub fn flushRect(x: u32, y: u32, w: u32, h: u32) void {
    if (!active or direct) return;
    if (x >= width or y >= height) return;
    const cw = @min(w, width - x);
    const ch = @min(h, height - y);
    var row: u32 = 0;
    while (row < ch) : (row += 1) {
        const sy = y + row;
        var src: usize = @as(usize, sy) * width + x;
        var dst: usize = @as(usize, sy) * stride_px + x;
        if (!rgba) {
            var col: u32 = 0;
            while (col < cw) : (col += 1) {
                panel[dst] = framebuffer[src];
                src += 1;
                dst += 1;
            }
        } else {
            // gfx writes 0x00RRGGBB (BGRA memory order); an RGBA panel wants
            // the R and B bytes exchanged.
            var col: u32 = 0;
            while (col < cw) : (col += 1) {
                const v = framebuffer[src];
                panel[dst] = (v & 0xFF00FF00) | ((v & 0x00FF0000) >> 16) | ((v & 0x000000FF) << 16);
                src += 1;
                dst += 1;
            }
        }
    }
}
