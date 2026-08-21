// scanout — pick the display device and hand back a framebuffer.
//
// One preference order, used by everything that paints a full screen:
// virtio-gpu (QEMU), then BGA, then the UEFI GOP framebuffer (real metal).
// The chain lived inline in desktop.run() until the installer needed the
// identical bring-up. Two copies of "which device scans out" is exactly the
// shape that drifted the font atlases apart in May (see aa_font.zig's note) —
// a second copy doesn't fail loudly, it fails on the one machine whose
// display took the branch the stale copy never learned about.
//
// Deliberately NOT including back-buffer policy. That decision differs per
// caller in ways that matter: the desktop forces a separate back buffer under
// boot_mode 9 so the GPU compositor owns the screen FB, and the installer must
// not inherit that. Sharing it would mean threading a mode flag through here,
// which is how a shared helper turns into a switch on its callers.

const gfx = @import("gfx.zig");
const bga = @import("bga.zig");
const debug = @import("../debug/debug.zig");
const virtio_gpu = @import("../driver/virtio_gpu.zig");
const gpu_kit = @import("../driver/gpu.zig");
const gop = @import("../driver/gop_fb.zig");

/// Which device won the probe. Callers branch on this for the handful of
/// device-specific decisions that survive bring-up — chiefly GOP's blit mode,
/// where the framebuffer only reaches the panel on an explicit flush.
pub const Kind = enum { virtio_gpu, bga, gop };

pub const Scanout = struct {
    kind: Kind,
    width: u32,
    height: u32,
    /// True when the framebuffer is not scanned out continuously, so its
    /// contents only reach the panel via `display.flush()`. Such a buffer is
    /// already a back buffer and callers should not allocate another.
    deferred: bool,
};

/// Probe the display chain and point `gfx.screen` at whatever won. Returns
/// null when nothing can scan out; the caller is responsible for saying so to
/// the user, since only it knows where its errors go.
///
/// Sets `gfx.post_blit_fn` for the backends that need a transfer after a blit.
/// Does not touch `gfx.target` — pick a render target after this returns.
pub fn bringUp() ?Scanout {
    // The virtio attempt is gated on the boot GPU inventory: on real hardware
    // (no virtio function on the bus) the probe is a guaranteed miss, so skip
    // straight to the fallbacks instead of re-scanning the bus to learn what
    // boot already knew.
    if (gpu_kit.mayHaveVirtioGpu() and virtio_gpu.init(1920, 1080)) {
        gfx.setScreen(virtio_gpu.framebuffer, virtio_gpu.width, virtio_gpu.height);
        gfx.post_blit_fn = &virtio_gpu.flush;
        debug.klog("[scanout] virtio-gpu {d}x{d}\n", .{ virtio_gpu.width, virtio_gpu.height });
        // The host sees nothing until TRANSFER_TO_HOST_2D + RESOURCE_FLUSH,
        // so the device's resource backing is itself a back buffer.
        return .{ .kind = .virtio_gpu, .width = virtio_gpu.width, .height = virtio_gpu.height, .deferred = true };
    }

    if (bga.init(1280, 720)) {
        // Pull dimensions from the BGA device — `gfx.screen_w` is still 0 here
        // because setScreen hasn't run yet. Reading it gave (0,0), which then
        // propagated through showSplash's centering math (`(sw - logo_w) / 2`)
        // and overflowed in ReleaseSafe right at boot.
        gfx.setScreen(bga.framebuffer, bga.width, bga.height);
        debug.klog("[scanout] BGA {d}x{d}\n", .{ bga.width, bga.height });
        // Live framebuffer: the host scans it out continuously, so painting
        // into it directly tears.
        return .{ .kind = .bga, .width = bga.width, .height = bga.height, .deferred = false };
    }

    if (gop.active) {
        // Real hardware: no virtio, no BGA — the UEFI GOP framebuffer that
        // early_fb adopted at kernelMain entry is the display. Direct mode
        // (BGRA, packed stride) scans out live like BGA; blit mode renders
        // into GUEST_FB and display.flush() pushes rows to the panel.
        gfx.setScreen(gop.framebuffer, gop.width, gop.height);
        gfx.post_blit_fn = &gop.flush;
        debug.klog("[scanout] GOP {d}x{d} ({s})\n", .{ gop.width, gop.height, if (gop.direct) "direct" else "blit" });
        return .{ .kind = .gop, .width = gop.width, .height = gop.height, .deferred = !gop.direct };
    }

    return null;
}
