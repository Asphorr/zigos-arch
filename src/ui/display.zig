// Display flush dispatch — one call site shape for every scanout backend.
//
// The desktop's compositor used to call virtio_gpu.flush/flushRect directly,
// gated on `vgpu.active` (or `gfx.post_blit_fn != null` for the cursor
// rects). That hardcoded QEMU's device into a dozen call sites and silently
// dropped flushes on the GOP path real hardware uses. This module is the
// tiny indirection that fixes it: virtio-gpu when it's up (QEMU), the GOP
// scanout blitter otherwise (real metal), no-op when neither is active
// (BGA's live framebuffer needs no flush; headless needs nothing).
//
// Deliberately NOT a vtable/driver-registry: two backends with a strict
// preference order is an `if`, and the desktop calls these on every frame.

const virtio_gpu = @import("../driver/virtio_gpu.zig");
const gop = @import("../driver/gop_fb.zig");

/// Push the full frame to whatever scans out.
pub fn flush() void {
    if (virtio_gpu.active) {
        virtio_gpu.flush();
        return;
    }
    if (gop.active) gop.flush();
}

/// Push one rectangle to whatever scans out.
pub fn flushRect(x: u32, y: u32, w: u32, h: u32) void {
    if (virtio_gpu.active) {
        virtio_gpu.flushRect(x, y, w, h);
        return;
    }
    if (gop.active) gop.flushRect(x, y, w, h);
}
