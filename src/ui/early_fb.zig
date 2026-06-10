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
        // framebuffer. So the early path can only adopt a GOP whose stride
        // (pixels-per-scanline) equals its visible width AND whose format is
        // BGRA (boot_info format 0). A padded stride would shear the whole boot
        // screen diagonally; an RGBA (1) or unknown/Blt-only (2) format would
        // swap R/B or have no linear FB to write at all.
        //
        // We can't honor either here — there's no back buffer and no PMM yet to
        // make one — so rather than paint a corrupt boot screen we decline the
        // GOP FB and stay in always-correct VGA text mode. tryVirtioGpu() still
        // upgrades to graphical later via the width-packed BGRA virtio/BGA
        // device once PMM/heap are up. (On QEMU/OVMF stride == width and
        // format == BGRA, so this adopts exactly as before — no behavior change
        // on the path we can actually boot.)
        if (fb.stride != fb.width or fb.format != 0) {
            serial.print("[early-fb] UEFI GOP unsupported by early gfx (stride={d} width={d} fmt={d}); VGA text, awaiting tryVirtioGpu\n", .{ fb.stride, fb.width, fb.format });
            return false;
        }
        // GOP framebuffer phys (typ. 0x80000000) reached through the
        // kernel physmap. Phase 3 dropped PML4[0], so a raw phys
        // pointer would fault on the first fillRect once the desktop
        // takes over. The physmap covers all phys < 64 GB.
        const ptr: [*]volatile u32 = @ptrFromInt(paging.physToVirt(@as(usize, fb.base)));
        gfx.setScreen(ptr, fb.width, fb.height);
        // gfx primitives (fillRect/drawString) write to `target`, not
        // `screen`. Point target at the live FB so boot_screen draws
        // straight to the panel — no back buffer this early in boot
        // (no PMM, no place to put one).
        gfx.useFramebuffer();
        active = true;
        serial.print("[early-fb] UEFI GOP {d}x{d} fb=0x{X}\n", .{ fb.width, fb.height, fb.base });
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
