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
//     so we probe the Bochs VGA Adapter (BGA, 0x1234:0x1111). The BGA
//     framebuffer BAR is always 32-bit (< 4 GB), already covered by
//     boot.asm's 4 GB 2 MB-page identity map; `paging.mapMMIO` would be
//     a no-op here anyway since paging.init hasn't run yet. Cache
//     attribute on the FB stays write-back, which is fine for QEMU.
//
// Returns true if a framebuffer was set up and `gfx.screen_w/h` are non-zero.
// On false, callers fall back to VGA text mode rendering.

const gfx = @import("gfx.zig");
const bga = @import("bga.zig");
const virtio_gpu = @import("../driver/virtio_gpu.zig");
const boot_info_mod = @import("../boot/boot_info.zig");
const serial = @import("../debug/serial.zig");

pub var active: bool = false;
pub var via_bga: bool = false;
pub var via_virtio_gpu: bool = false;

pub fn init(boot_info: *const boot_info_mod.BootInfo) bool {
    // UEFI path — bootloader already has GOP up; just adopt it.
    if (boot_info.has_framebuffer != 0) {
        const fb = boot_info.framebuffer;
        if (fb.base != 0 and fb.width != 0 and fb.height != 0) {
            // GOP framebuffer phys (typ. 0x80000000) reached through the
            // kernel physmap. Phase 3 dropped PML4[0], so a raw phys
            // pointer would fault on the first fillRect once the desktop
            // takes over. The physmap covers all phys < 64 GB.
            const paging = @import("../mm/paging.zig");
            const ptr: [*]volatile u32 = @ptrFromInt(paging.physToVirt(@as(usize, @intCast(fb.base))));
            gfx.setScreen(ptr, fb.width, fb.height);
            // gfx primitives (fillRect/drawString) write to `target`, not
            // `screen`. Point target at the live FB so boot_screen draws
            // straight to the panel — no back buffer this early in boot
            // (no PMM, no place to put one).
            gfx.useFramebuffer();
            active = true;
            via_bga = false;
            serial.print("[early-fb] UEFI GOP {d}x{d} fb=0x{X}\n", .{ fb.width, fb.height, fb.base });
            return true;
        }
    }

    // Multiboot path: NO BGA attempt here. The Bochs VGA register set
    // responds on QEMU's virtio-vga-gl (so detection succeeds) but the
    // device scans out from its own virtio-gpu resource, not BGA's
    // framebuffer — writes go into memory that's never displayed and the
    // entire boot screen is invisible. Multiboot starts in VGA text mode
    // (also invisible on virtio-vga-gl, but cheap and harmless) and gets
    // upgraded to a real graphical framebuffer mid-Phase-2 by
    // tryVirtioGpu() once PMM/paging/heap are ready.
    serial.print("[early-fb] multiboot: no early framebuffer; awaiting tryVirtioGpu\n", .{});
    active = false;
    via_bga = false;
    return false;
}

/// Called by desktop.zig right before it brings up virtio-gpu so the
/// scanout transitions cleanly from BGA to virtio. UEFI-supplied FBs are
/// left alone (the GOP framebuffer is replaced by virtio_gpu.framebuffer
/// when desktop calls gfx.setScreen on it — no teardown needed).
pub fn handoffToVirtioGpu() void {
    if (!active) return;
    if (via_bga) bga.disable();
    active = false;
    via_bga = false;
    via_virtio_gpu = false;
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
    via_virtio_gpu = true;
    serial.print("[early-fb] upgraded to virtio-gpu {d}x{d}\n", .{ virtio_gpu.width, virtio_gpu.height });
    return true;
}
