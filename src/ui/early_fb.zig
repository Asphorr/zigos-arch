// Early framebuffer bring-up.
//
// Called from `kernelMain` before any other init so the boot screen can
// render in graphical mode instead of VGA text mode for the *entire* boot.
//
// Two paths:
//   - UEFI: the bootloader already set up GOP and stashed the framebuffer
//     descriptor in `boot_info.framebuffer`. We just point `gfx.setScreen`
//     at it. boot.asm's identity map covers the FB phys address (UEFI's
//     pre-kernel page setup also handles >4GB FB locations — see
//     `project_kstack_guards_uefi_skip.md` / 64GB 1GB-page mapping).
//   - Multiboot: QEMU's `-kernel` loader doesn't pass framebuffer info,
//     and probing BGA on virtio-vga-gl is a trap — the registers respond
//     so detection succeeds, but writes hit memory that never scans out.
//     Multiboot stays in VGA text mode until `tryVirtioGpu` upgrades it
//     mid-Phase-2 once PMM/paging/heap are ready.
//
// Returns true if a framebuffer was set up and `gfx.screen_w/h` are non-zero.
// On false, callers fall back to VGA text mode rendering.

const gfx = @import("gfx.zig");
const virtio_gpu = @import("../driver/virtio_gpu.zig");
const boot_info_mod = @import("../boot/boot_info.zig");
const paging = @import("../mm/paging.zig");
const serial = @import("../debug/serial.zig");

pub var active: bool = false;

pub fn init(boot_info: *const boot_info_mod.BootInfo) bool {
    // UEFI path — bootloader already has GOP up; just adopt it.
    if (boot_info.has_framebuffer != 0) {
        const fb = boot_info.framebuffer;
        if (fb.base == 0 or fb.width == 0 or fb.height == 0) {
            // has_framebuffer was set, but the descriptor is unusable (no linear
            // GOP FB, or a zero dimension). Fall back to VGA text — but log it as
            // a *UEFI* failure, not the Multiboot "no framebuffer" path below,
            // which used to swallow this case and read as the wrong boot protocol.
            serial.print("[early-fb] UEFI framebuffer descriptor invalid (base=0x{X} {d}x{d}); VGA text fallback\n", .{ fb.base, fb.width, fb.height });
            return false;
        }
        // gfx has no row-pitch concept: every primitive addresses pixels as
        // `y * width + x` (see gfx.putPixel/fillRect/drawChar), and it writes
        // 0x00RRGGBB, which only scans out correctly on a little-endian BGRA
        // framebuffer. The GOP scanout driver bridges both real-firmware gaps:
        // direct mode for BGRA-with-stride==width (QEMU/OVMF — gfx draws
        // straight to the panel, byte-identical to the old path here), blit
        // mode for padded strides / RGBA (gfx draws into the fixed GUEST_FB
        // region — no PMM needed, it's a reserved layout region — and every
        // post_blit flush copies rows out with stride/byte-order fixup).
        // This matters because real CSM-less UEFI has NO VGA text mode: the
        // old "decline and stay in text" fallback was a dark machine there.
        const gop = @import("../driver/gop_fb.zig");
        if (!gop.init(fb)) {
            serial.print("[early-fb] UEFI GOP unusable (stride={d} width={d} fmt={d}); VGA text, awaiting tryVirtioGpu\n", .{ fb.stride, fb.width, fb.format });
            return false;
        }
        gfx.setScreen(gop.framebuffer, gop.width, gop.height);
        // gfx primitives (fillRect/drawString) write to `target`, not
        // `screen`. Point target at the render surface so boot_screen draws
        // without a separate back buffer this early in boot.
        gfx.useFramebuffer();
        // In blit mode the panel only updates on flush; boot_screen and the
        // panic screen already call post_blit_fn after drawing. In direct
        // mode this is a cheap no-op.
        gfx.post_blit_fn = &gop.flush;
        active = true;
        serial.print("[early-fb] UEFI GOP {d}x{d} fb=0x{X} ({s})\n", .{ gop.width, gop.height, fb.base, if (gop.direct) "direct" else "blit" });
        return true;
    }

    // Multiboot: no early FB. Boot continues in VGA text mode; tryVirtioGpu
    // upgrades to graphical once PMM/heap are up.
    serial.print("[early-fb] multiboot: no early framebuffer; awaiting tryVirtioGpu\n", .{});
    return false;
}

/// Release the early framebuffer's claim on `active`. Called before
/// virtio-gpu takes over (so `tryVirtioGpu`'s `if (active)` gate clears),
/// and from the panic path so the panic screen can repaint the FB without
/// `tryVirtioGpu` short-circuiting on a stale flag.
pub fn release() void {
    active = false;
}

/// Multiboot post-Phase-2 upgrade path. UEFI already has GOP via init();
/// Multiboot starts in VGA text mode (BGA on virtio-vga-gl doesn't actually
/// scan out). After PMM/heap/paging are up, we can bring up virtio-gpu
/// itself and switch the boot screen to graphical mode for Phases 3+.
///
/// Caller (kernelMain) is expected to invoke boot_screen.upgradeToGraphical()
/// after this returns true so the static layout repaints with the gfx
/// primitives instead of vga.MEM writes.
///
/// Returns true if virtio-gpu came up. False on any failure — boot screen
/// stays in VGA text mode for the rest of boot. The vga.print path keeps
/// working in either case.
pub fn tryVirtioGpu() bool {
    if (active) return false; // already on a graphical FB — nothing to do
    if (!virtio_gpu.init(1920, 1080)) {
        serial.print("[early-fb] virtio-gpu init failed; staying in VGA text mode\n", .{});
        return false;
    }
    gfx.setScreen(virtio_gpu.framebuffer, virtio_gpu.width, virtio_gpu.height);
    gfx.useFramebuffer();
    // post_blit_fn flushes the scanout resource to the host. boot_screen
    // calls it after every draw because we don't have a back buffer yet —
    // direct-to-resource writes need a TRANSFER+FLUSH to actually display.
    gfx.post_blit_fn = &virtio_gpu.flush;
    active = true;
    serial.print("[early-fb] upgraded to virtio-gpu {d}x{d}\n", .{ virtio_gpu.width, virtio_gpu.height });
    return true;
}
