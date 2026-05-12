// GPU compositor — boot_mode=9 entry point.
//
// LONG-TERM goal (not yet built): replace the CPU compositor's per-window
// memcpy + screen-FB blit with a Vulkan/Lavapipe path where each window's
// FB is a Venus dma-buf, the compositor binds them as sampled images, and
// a fragment shader composites them onto the virtio-gpu scanout in one
// pass. See project_gpu_compositor_direction.md for the architecture and
// project_venus_fence_lies.md for why a GPU compositor structurally avoids
// the cube's fence-vs-pixel-completion race (no CPU readback in the path).
//
// CURRENT state (step 5 — Vulkan-driven clear-color render to screen):
// after the Vulkan device is up (steps 1–4), the compositor allocates
// a 320×240 render image (Exportable, DMA_BUF) backed by a HOST3D blob
// mapped into kernel space, plus the supporting render pass / framebuffer
// / command pool / cmd buffer / fence. Each frame: encode a single-clear-
// color pass with an animated RGB cycle, submit + wait fence, memcpy the
// rendered pixels to a centered rect on screen. Screen background is
// fillRect dark gray. Visible result: a dark gray screen with an
// animated colored rectangle in the middle, rendered entirely through
// Lavapipe-via-Venus from the kernel. Animation falls back to plain
// fillRect on any Vulkan failure — boot stays usable.
//
// Multiboot dispatch:  add `-append "boot_mode=9"` to the QEMU launcher.
// UEFI dispatch:       pick "GPU Compositor (experimental)" from the menu.

const std = @import("std");
const debug = @import("../debug/debug.zig");
const pmm = @import("../mm/pmm.zig");
const gfx = @import("gfx.zig");
const paging = @import("../mm/paging.zig");
const process = @import("../proc/process.zig");
const virtio_gpu = @import("../driver/virtio_gpu.zig");
const venus = @import("venus_kernel.zig");
const shaders = @import("gpu_compositor_shaders.zig");

// ── Venus / Vulkan setup state ──────────────────────────────────────────
//
// virtio-gpu context ID for the kernel-side compositor. User processes
// get IDs from a counter starting at 1; we pick a high value so collisions
// require >190 concurrent ctx-creating user processes — implausible.
const COMPOSITOR_CTX_ID: u32 = 0xC0;

// virtio-gpu BLOB memory type for "host-allocated, host-3D-aware blob"
// — what we want for shared dma-buf-backed Vulkan resources. Mirrors
// the constant used by lib/venus.zig (which is private to userspace).
const BLOB_MEM_HOST3D: u32 = 2;

// Venus reply ring. Host writes per-command replies (return codes,
// structured outputs) here; we register the location with
// vkSetReplyCommandStreamMESA. 4 KB is plenty — most replies are 8–32 B
// and we can Seek(0) per frame so the ring never fills.
const REPLY_RING_SIZE: u32 = 4096;

var reply_ring: ?[*]volatile u8 = null;
var reply_ring_res_id: u32 = 0;

// Single 4 KB scratch CmdStream reused across all setup + per-frame
// encoding. Hoisted to module BSS because the kernel kstack is only
// ~64 KB and step 7 had ~20 separate `var cs = .{}` locals in the
// setup paths — the resulting overlapping 4 KB buffers blew past
// kstack and triple-faulted in `historyMarkCurrent` (the panic
// handler's own NVRAM write was the secondary fault, after the
// primary stack overflow). All callers must `scratch_cs.reset()`
// before encoding.
var scratch_cs: venus.CmdStream = .{};

// Compositor-owned Venus handle IDs. Chosen disjoint from the cube's
// (cube uses 100–500); we sit at 200 so multiple GPU clients can coexist
// in future. Disjoint by Venus-context anyway, but readable namespacing
// helps when reading klog.
const COMPOSITOR_INSTANCE: u64 = 200;
const COMPOSITOR_PHYS_DEV: u64 = 201;
const COMPOSITOR_DEVICE: u64 = 202;
const COMPOSITOR_QUEUE: u64 = 203;
const COMPOSITOR_RENDER_IMAGE: u64 = 300;
const COMPOSITOR_RENDER_MEM: u64 = 301;
const COMPOSITOR_RENDER_VIEW: u64 = 302;
const COMPOSITOR_RENDER_PASS: u64 = 303;
const COMPOSITOR_FRAMEBUFFER: u64 = 304;
const COMPOSITOR_CMD_POOL: u64 = 305;
const COMPOSITOR_CMD_BUF: u64 = 306;
const COMPOSITOR_FENCE: u64 = 307;
const COMPOSITOR_VERT_MODULE: u64 = 308;
const COMPOSITOR_FRAG_MODULE: u64 = 309;
const COMPOSITOR_PIPELINE_LAYOUT: u64 = 310;
const COMPOSITOR_PIPELINE: u64 = 311;
// Step 7: background source image (backbuf downsample) + descriptor.
const COMPOSITOR_SOURCE_IMAGE: u64 = 312;
const COMPOSITOR_SOURCE_MEM: u64 = 313;
const COMPOSITOR_SOURCE_VIEW: u64 = 314;
const COMPOSITOR_SAMPLER: u64 = 315;
const COMPOSITOR_DESC_SET_LAYOUT: u64 = 316;
const COMPOSITOR_DESC_POOL: u64 = 317;
const COMPOSITOR_DESC_SET: u64 = 318;
// Step 8c-5: per-window source image (focused window only for now,
// scaled to N when this proves out). Same descriptor layout as the
// background, allocated from the same pool.
const COMPOSITOR_FOCUSED_IMAGE: u64 = 320;
const COMPOSITOR_FOCUSED_MEM: u64 = 321;
const COMPOSITOR_FOCUSED_VIEW: u64 = 322;
const COMPOSITOR_FOCUSED_DESC_SET: u64 = 323;
// Step 8d: scanout-replacing blobs. We allocate up to two B8G8R8A8 LINEAR
// images with their VkDeviceMemory exposed as HOST3D blobs (CROSS_DEVICE
// flag → virgl exports them as dmabuf). virtio-gpu's SET_SCANOUT_BLOB
// then points the display at the dmabuf, so the kernel's per-frame
// flush is just RESOURCE_FLUSH (no TRANSFER_TO_HOST_2D copy). IDs split
// off the per-blob 4-element pattern: image, mem, view, _pad. View is
// unused by scanout but Venus's bind path is happier when the image
// has one. blob 0 lives at 330..333, blob 1 at 334..337.
const COMPOSITOR_SCANOUT_IMAGE_BASE: u64 = 330;
// Step 9.1: SHM-backed read-back buffer. The render image is Venus-
// allocated host memory (fast for Lavapipe but slow for kernel reads
// via SHM BAR at 8 MB), so each frame we vkCmdCopyImageToBuffer the
// rendered pixels into a VkBuffer bound to an SHM blob. The kernel
// reads from the SHM blob's mapping at memory-bandwidth speed.
//
// Step 9.3: doubled to a pair (A, B) for tear-free page-flip. Each
// frame writes to whichever buffer is currently the BACK
// (= virtio_gpu.blob_resource_ids[1 - virtio_gpu.blob_front]); the
// driver's flushUnconditional flips SCANOUT_BLOB to that back, which
// then becomes the front, and the previous front becomes the back for
// the next frame. Vulkan never writes into the buffer the host is
// scanning out, so pixels can't be torn.
const COMPOSITOR_READBACK_BUFFER: u64 = 340;
const COMPOSITOR_READBACK_MEM: u64 = 341;
const COMPOSITOR_READBACK_BUFFER_2: u64 = 342;
const COMPOSITOR_READBACK_MEM_2: u64 = 343;

// Task A — Phase 1: secondary command ring. A 64 KB HOST3D blob laid
// out as:
//   [head:u32 @ 0][tail:u32 @ 4][status:u32 @ 8][pad @ 12]
//   [buffer @ 16, 32 KB] [extra @ 32784, ~32 KB]
// Buffer size MUST be a power of 2 (vkr_ring asserts util_is_power_of_two_nonzero).
// After vkCreateRingMESA the host spins up a dedicated thread that drains
// commands from this ring instead of going through ctrl_vq SUBMIT_3D.
// Phase 1 creates the ring and verifies the host accepts it; Phase 2
// would actually emit per-frame commands through it.
const COMPOSITOR_RING: u64 = 500;
const RING_TOTAL_SIZE: u64 = 64 * 1024;
const RING_HEAD_OFFSET: u64 = 0;
const RING_TAIL_OFFSET: u64 = 4;
const RING_STATUS_OFFSET: u64 = 8;
const RING_BUFFER_OFFSET: u64 = 16;
const RING_BUFFER_SIZE: u64 = 32 * 1024; // power of 2
const RING_EXTRA_OFFSET: u64 = RING_BUFFER_OFFSET + RING_BUFFER_SIZE;
const RING_EXTRA_SIZE: u64 = RING_TOTAL_SIZE - RING_EXTRA_OFFSET;
var ring_kvirt: ?[*]volatile u8 = null;
var ring_res_id: u32 = 0;
var ring_created: bool = false;

// Step 9.4: per-window Venus image slots. Each visible app window
// gets its own Venus VkImage (LINEAR + SAMPLED + TRANSFER_DST), backed
// by a HOST3D blob with udmabuf so the kernel can write through the
// SHM BAR (gui_fb pointer the app sees) AND the Venus context can
// sample the same memory as a texture. Per slot:
//   mem_id  = WINDOW_SLOT_MEM_BASE  + slot * STRIDE
//   image   = WINDOW_SLOT_IMAGE_BASE + slot * STRIDE
//   view    = WINDOW_SLOT_VIEW_BASE + slot * STRIDE
//   descset = WINDOW_SLOT_DESC_SET_BASE + slot * STRIDE
const WINDOW_SLOT_MEM_BASE: u64 = 400;
const WINDOW_SLOT_IMAGE_BASE: u64 = 401;
const WINDOW_SLOT_VIEW_BASE: u64 = 402;
const WINDOW_SLOT_DESC_SET_BASE: u64 = 403;
const WINDOW_SLOT_STRIDE: u64 = 4;
pub const MAX_WINDOW_SLOTS: u8 = 16;
const FOCUSED_W: u32 = 256;
const FOCUSED_H: u32 = 256;
const FOCUSED_PX_BYTES: u32 = FOCUSED_W * FOCUSED_H * 4;

// Source-image dimensions. Step 9.2: bumped to native screen resolution
// so the fragment shader's 1:1 sample produces crisp output (the previous
// 320×180 → 1920×1080 upscale via the LINEAR sampler was the "blurry but
// recognizable" look). Costs an 8 MB CPU memcpy per frame in
// fillBackgroundSource; with `map_fixed` in QEMU master, BAR writes are
// EPT-direct so this lands at ~1-2 ms.
const SOURCE_W: u32 = 1920;
const SOURCE_H: u32 = 1080;
const SOURCE_PX_BYTES: u32 = SOURCE_W * SOURCE_H * 4;

// Step 9.1: Vulkan renders fullscreen. Render image at native screen
// resolution (1920×1080) and is the per-frame compositor output. The
// kernel never CPU-paints the scanout in mode 9 anymore — the per-frame
// loop is "fill source, render, memcpy render→scanout, flush". Source
// is still 320×180 in this step (visibly blurry upscale); step 9.2
// gives the source its own full-res anonymous blob for crisp output.
const RENDER_W: u32 = 1920;
const RENDER_H: u32 = 1080;
const RENDER_PX_BYTES: u32 = RENDER_W * RENDER_H * 4;

var vulkan_device_ready: bool = false;
var vulkan_render_ready: bool = false;
var render_pixel_buf: ?[*]volatile u8 = null;
var source_pixel_buf: ?[*]volatile u8 = null;
var focused_pixel_buf: ?[*]volatile u8 = null;
// virtio-gpu resource id of the readback HOST3D blob. Once Vulkan setup
// succeeds we promote this same blob to scanout (SET_SCANOUT_BLOB), so
// vkCmdCopyImageToBuffer's destination IS the host's display source —
// no kernel-side memcpy from BAR to scanout pages needed.
//
// Step 9.3: doubled to a pair for tear-free page flip. Each frame
// targets the BACK buffer (= 1 - virtio_gpu.blob_front); flushUnconditional
// flips SCANOUT_BLOB to that buffer once Vulkan finishes writing.
var readback_res_ids: [2]u32 = .{ 0, 0 };
var readback_buf_handles: [2]u64 = .{ COMPOSITOR_READBACK_BUFFER, COMPOSITOR_READBACK_BUFFER_2 };
var readback_mem_handles: [2]u64 = .{ COMPOSITOR_READBACK_MEM, COMPOSITOR_READBACK_MEM_2 };
var readback_pixel_bufs: [2]?[*]volatile u8 = .{ null, null };
var readback_promoted_to_scanout: bool = false;

// Per-window image slots (Step 9.4). Each visible GUI window gets one;
// the slot owns a Venus dmabuf + image view + descriptor set. The
// kernel pointer is what apps see as their gui_fb (writes go through
// the SHM BAR, EPT-direct).
//
// Phase B.2: image dims may differ from memory dims. Image extent =
// (width, height) — the visible region the compositor samples.
// Memory size = mem_w * mem_h * 4 — the full app-visible buffer.
// In typical apps mem_w == width (just height differs), so the
// image's natural rowPitch matches the memory's row stride and apps
// can write into the dmabuf directly.
pub const WindowSlot = struct {
    in_use: bool = false,
    width: u32 = 0,                  // image extent width (visible / sampled)
    height: u32 = 0,                 // image extent height (visible / sampled)
    mem_w: u32 = 0,                  // memory layout width (16-aligned)
    mem_h: u32 = 0,                  // memory layout height
    pitch_pixels: u32 = 0,           // row stride in pixels — equals mem_w
    res_id: u32 = 0,                 // virtio-gpu resource id (HOST3D blob)
    desc_set_id: u64 = 0,            // Venus descriptor set handle
    kernel_ptr: ?[*]volatile u8 = null,
    phys: usize = 0,                 // BAR-phys for user-space mapping
    mem_bytes: u64 = 0,              // total allocation size (page-rounded)
};
pub var window_slots: [MAX_WINDOW_SLOTS]WindowSlot = blk: {
    var x: [MAX_WINDOW_SLOTS]WindowSlot = undefined;
    for (&x) |*s| s.* = .{};
    break :blk x;
};

// Cached focused-window screen rect (scaled to render image coords)
// for the per-window draw. Updated each frame by fillSourceFrame.
var focused_rect_x: u32 = 0;
var focused_rect_y: u32 = 0;
var focused_rect_w: u32 = 0;
var focused_rect_h: u32 = 0;
// Screen dimensions snapshotted at startup; used by the multi-window
// composite to scale window screen-space rects into source-image coords.
var screen_w_cache: u32 = 0;
var screen_h_cache: u32 = 0;

// Event-driven wake plumbing. The compositor parks via kernelSleepMs(33)
// — a 30 Hz timer fallback that bounds wake latency if the wake-flip
// race kicks in — and external damage sources call `requestRender()` to
// flip the counter and explicit-wake the kernel task. process.wake on a
// PCB whose state == .sleeping flips it to .ready, which exits
// kernelSleepMs early; if the wake interleaves between our atomic check
// and the kernelSleepMs state-flip, the 33 ms timer covers it. So
// worst-case idle latency = 33 ms, typical = sub-ms.
pub var compositor_pid: u8 = 0xFF;
var pending_wakes: u32 = 0;

// Per-frame damage snapshot. The desktop calls into requestRenderRects
// to hand us a list of changed rects in screen coords; we copy only
// those regions from the desktop backbuf to the source image, instead
// of re-uploading the whole 8 MB every frame. Initial frames + .full
// dispatches go through requestRenderFull which sets pending_full and
// the next frame does a single rep movsq.
//
// Why a separate buffer rather than reading desktop's dirty.zig
// directly: desktop's dispatch resets that storage at the end of every
// tick, before the compositor wakes up. We snapshot synchronously while
// the desktop is still mid-tick.
pub const MAX_PENDING_RECTS: u8 = 16;
var pending_rects: [MAX_PENDING_RECTS][4]u32 = undefined;
var pending_rect_count: u8 = 0;
var pending_full: bool = true; // initial frame copies everything

/// Plain wake — equivalent to "the whole scene may have changed,
/// re-upload everything". Used for .full/.drag paths and any caller
/// that doesn't track rects.
pub fn requestRender() void {
    pending_full = true;
    _ = @atomicRmw(u32, &pending_wakes, .Add, 1, .seq_cst);
    if (compositor_pid != 0xFF) {
        @import("../proc/process.zig").wake(compositor_pid);
    }
}

/// Wake the compositor and queue a single dirty rect (screen coords).
/// Used by callers that already know exactly what changed without
/// going through the desktop's tile-grid tracker (e.g. .text_only's
/// terminal text row). Coalesces — multiple rects accumulate up to
/// MAX_PENDING_RECTS, then fall back to full.
pub fn requestRenderRect(x: u32, y: u32, w: u32, h: u32) void {
    if (!pending_full) {
        if (pending_rect_count >= MAX_PENDING_RECTS) {
            pending_full = true;
            pending_rect_count = 0;
        } else {
            pending_rects[pending_rect_count] = .{ x, y, w, h };
            pending_rect_count += 1;
        }
    }
    _ = @atomicRmw(u32, &pending_wakes, .Add, 1, .seq_cst);
    if (compositor_pid != 0xFF) {
        @import("../proc/process.zig").wake(compositor_pid);
    }
}

/// Wake the compositor and snapshot the desktop's tile-grid dirty rects
/// — only the listed regions get copied from backbuf to source. For
/// typical events (terminal text row 1920×16, dock tooltip 240×80,
/// button press) this is <1% of the full 8 MB upload, so per-frame CPU
/// drops from ~3 ms to <100 µs.
///
/// Called by the desktop's main-loop dispatch right before
/// resetDirtyRects so we get the snapshot before it's cleared. Falls
/// back to full upload on overflow or empty list.
pub fn requestRenderFromDirty() void {
    const dirty = @import("desktop/dirty.zig");
    if (dirty.isFull()) {
        pending_full = true;
    } else if (!pending_full) {
        const n = dirty.rectCount();
        var i: u8 = 0;
        while (i < n) : (i += 1) {
            if (pending_rect_count >= MAX_PENDING_RECTS) {
                pending_full = true;
                pending_rect_count = 0;
                break;
            }
            pending_rects[pending_rect_count] = dirty.getRect(i);
            pending_rect_count += 1;
        }
    }
    _ = @atomicRmw(u32, &pending_wakes, .Add, 1, .seq_cst);
    if (compositor_pid != 0xFF) {
        @import("../proc/process.zig").wake(compositor_pid);
    }
}

/// Bring up a Venus-capable virtio-gpu context for the compositor and
/// allocate the reply ring. Best-effort — failures klog and return false;
/// caller is expected to keep running (animation loop) so the boot mode
/// is at least visually verifiable.
fn setupVulkanContext() bool {
    if (!virtio_gpu.has_virgl) {
        debug.klog("[gpu-comp] no virgl support — skipping Vulkan setup\n", .{});
        return false;
    }
    if (!virtio_gpu.has_blob) {
        debug.klog("[gpu-comp] no blob support — skipping Vulkan setup\n", .{});
        return false;
    }

    // 1. Create the kernel-side compositor context with the Venus capset.
    if (!virtio_gpu.ctxCreate(COMPOSITOR_CTX_ID, 4, "compositor")) {
        debug.klog("[gpu-comp] ctxCreate FAILED\n", .{});
        return false;
    }
    debug.klog("[gpu-comp] ctxCreate ok ctx={d} capset=4\n", .{COMPOSITOR_CTX_ID});

    // 2. Allocate + attach a HOST3D blob for the Venus reply ring.
    reply_ring_res_id = virtio_gpu.alloc3DResourceId();
    // blob_flags = 1 = MAPPABLE, matches what userspace gpuCreateBlob's
    // blob_id=0 path uses — see sysGpuCreateBlob in src/cpu/syscall.zig.
    if (!virtio_gpu.resourceCreateBlob(
        COMPOSITOR_CTX_ID,
        reply_ring_res_id,
        BLOB_MEM_HOST3D,
        1,
        0,
        REPLY_RING_SIZE,
    )) {
        debug.klog("[gpu-comp] reply ring resourceCreateBlob FAILED\n", .{});
        return false;
    }
    if (!virtio_gpu.ctxAttachResource(COMPOSITOR_CTX_ID, reply_ring_res_id)) {
        debug.klog("[gpu-comp] reply ring ctxAttachResource FAILED\n", .{});
        return false;
    }

    // 3. Map the reply ring into kernel space through the physmap. The SHM
    //    BAR is in the 0..64 GB physmap range, mapped WB by boot.asm — so
    //    physToVirt gives a coherent kernel pointer with no extra mapping
    //    work required (mapWBRange would be a no-op here).
    const reply_phys = virtio_gpu.resourceMapBlob(reply_ring_res_id, REPLY_RING_SIZE) orelse {
        debug.klog("[gpu-comp] reply ring resourceMapBlob FAILED\n", .{});
        return false;
    };
    const reply_buf: [*]volatile u8 = @ptrFromInt(paging.physToVirt(reply_phys));
    for (0..REPLY_RING_SIZE) |i| reply_buf[i] = 0;
    reply_ring = reply_buf;
    debug.klog("[gpu-comp] reply ring res_id={d} phys=0x{X} size={d}\n", .{ reply_ring_res_id, reply_phys, REPLY_RING_SIZE });

    // 4. Build SetReplyCommandStreamMESA Venus command and submit. After
    //    this, the host knows where to write replies for any subsequent
    //    reply-generating command (vkCreateInstance, etc.).
    scratch_cs.reset();
    scratch_cs.cmdHeader(venus.CMD_vkSetReplyCommandStreamMESA, 0);
    scratch_cs.writePresent(); // pStream
    scratch_cs.writeU32(reply_ring_res_id);
    scratch_cs.writeU64(0); // offset
    scratch_cs.writeU64(REPLY_RING_SIZE);
    if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) {
        debug.klog("[gpu-comp] SetReplyCommandStreamMESA submit FAILED\n", .{});
        return false;
    }
    debug.klog("[gpu-comp] SetReplyCommandStreamMESA submit ok — Venus reply ring registered\n", .{});
    return true;
}

/// Bring up Vulkan: Instance, PhysicalDevice, Device, Queue. Each step
/// reads its VkResult from the reply ring and klogs it. Returns true
/// only if every step lands SUCCESS (=0).
fn setupVulkanDevice() bool {
    const ring = reply_ring orelse return false;

    // --- Step 4a: vkCreateInstance ---
    {
        scratch_cs.reset();
        venus.encodeCreateInstance(&scratch_cs, COMPOSITOR_INSTANCE);
        for (0..32) |i| ring[i] = 0; // clear reply
        if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) {
            debug.klog("[gpu-comp] vkCreateInstance submit FAILED\n", .{});
            return false;
        }
        const r = venus.readReplyResult(ring);
        if (r != 0) {
            debug.klog("[gpu-comp] vkCreateInstance VkResult={d}\n", .{r});
            return false;
        }
        debug.klog("[gpu-comp] vkCreateInstance ok handle={d}\n", .{COMPOSITOR_INSTANCE});
    }

    // --- Step 4b: vkEnumeratePhysicalDevices (we expect exactly one — Lavapipe) ---
    {
        scratch_cs.reset();
        venus.encodeEnumeratePhysicalDevices(&scratch_cs, COMPOSITOR_INSTANCE, COMPOSITOR_PHYS_DEV);
        for (0..32) |i| ring[i] = 0;
        if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) {
            debug.klog("[gpu-comp] vkEnumeratePhysicalDevices submit FAILED\n", .{});
            return false;
        }
        const r = venus.readReplyResult(ring);
        if (r != 0) {
            debug.klog("[gpu-comp] vkEnumeratePhysicalDevices VkResult={d}\n", .{r});
            return false;
        }
        debug.klog("[gpu-comp] vkEnumeratePhysicalDevices ok phys={d}\n", .{COMPOSITOR_PHYS_DEV});
    }

    // --- Step 4c: vkCreateDevice (queue family 0, single queue) ---
    {
        scratch_cs.reset();
        venus.encodeCreateDevice(&scratch_cs, COMPOSITOR_PHYS_DEV, 0, COMPOSITOR_DEVICE);
        for (0..32) |i| ring[i] = 0;
        if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) {
            debug.klog("[gpu-comp] vkCreateDevice submit FAILED\n", .{});
            return false;
        }
        const r = venus.readReplyResult(ring);
        if (r != 0) {
            debug.klog("[gpu-comp] vkCreateDevice VkResult={d}\n", .{r});
            return false;
        }
        debug.klog("[gpu-comp] vkCreateDevice ok device={d}\n", .{COMPOSITOR_DEVICE});
    }

    // --- Step 4d: vkGetDeviceQueue2 (void-returning; no VkResult to check) ---
    {
        scratch_cs.reset();
        venus.encodeGetDeviceQueue(&scratch_cs, COMPOSITOR_DEVICE, 0, 0, COMPOSITOR_QUEUE);
        if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) {
            debug.klog("[gpu-comp] vkGetDeviceQueue2 submit FAILED\n", .{});
            return false;
        }
        debug.klog("[gpu-comp] vkGetDeviceQueue2 ok queue={d}\n", .{COMPOSITOR_QUEUE});
    }

    return true;
}

/// Submit a single Venus command + read the VkResult from the reply ring.
/// Caller is responsible for ensuring the command was encoded with
/// `CMD_FLAG_GENERATE_REPLY`. Returns the i32 VkResult (0 = SUCCESS,
/// negative = error). On submit failure returns INT_MIN as a sentinel
/// so callers can distinguish "transport failed" from "Vulkan errored".
var backbuf_logged: bool = false;
var focused_logged: bool = false;

/// Step 8c-5: build per-frame source textures.
///   - Background source (source_pixel_buf): downsampled view of the
///     desktop's back buffer (chrome + windows). Used by draw 1.
///   - Focused-window source (focused_pixel_buf): downsampled view of
///     the focused GUI window's gui_fb (or backs[pub] if presented).
///     Used by draw 2 with bounds = the window's screen rect scaled to
///     render-image coords. If no focused GUI window, focused_rect_w
///     stays 0 and renderVulkanFrame skips draw 2.
fn fillSourceFrame(_: u32) void {
    fillBackgroundSource();
    fillFocusedSource();
    fillWindowSlots();
}

/// Step 9.4 Phase 3: copy each visible window's gui_fb (or its
/// triple-buffered active back) into its Venus slot's dmabuf so the
/// fragment shader can sample directly. Per-row copy honors the slot's
/// pitch_pixels alignment (Lavapipe requires LINEAR images to use a
/// pitch ≥ width, padded to a multiple of 64 in our case).
fn fillWindowSlots() void {
    const wm = @import("desktop/window.zig");
    const flags = wm.lockWindows();
    defer wm.unlockWindows(flags);

    var i: u8 = 0;
    while (i < wm.windows.len) : (i += 1) {
        if (!wm.slot_used[i]) continue;
        const w = &wm.windows[i];
        if (!w.visible or w.minimized) continue;
        const slot_idx = w.gpu_slot orelse continue;
        if (slot_idx >= MAX_WINDOW_SLOTS) continue;
        const sl = &window_slots[slot_idx];
        if (!sl.in_use) continue;
        const dst_raw = sl.kernel_ptr orelse continue;
        const dst: [*]volatile u32 = @ptrCast(@alignCast(dst_raw));

        // Phase B.2: when gui_fb IS the slot's kernel mapping (user-
        // space maps directly at the dmabuf phys), there's nothing to
        // copy — the app's writes are already in the texture the
        // compositor samples. Detect by pointer equality.
        if (w.gui_fb) |fb| {
            if (@intFromPtr(fb) == @intFromPtr(dst)) continue;
        }

        // Pick the source: published back if the app has called
        // present(), otherwise the user-mapped front. Same logic
        // renderWindow uses (so rendering matches what the desktop
        // would have drawn).
        const pi = w.gui_fb_pub.load(.acquire);
        const src_opt: ?[*]volatile u32 = if (w.has_presented) w.gui_fb_backs[pi] else w.gui_fb;
        const src = src_opt orelse continue;

        const src_stride: u32 = if (w.gui_alloc_w > 0) w.gui_alloc_w else w.gui_w;
        const dst_stride: u32 = sl.pitch_pixels;
        const copy_w: u32 = @min(w.gui_w, sl.width);
        const copy_h: u32 = @min(w.gui_h, sl.height);
        if (copy_w == 0 or copy_h == 0) continue;

        // Per-row rep movsd. dst_stride == src_stride is common for
        // non-aliased windows (gui_alloc_w == gui_w) — but we keep
        // separate stride math because the slot pitch is padded.
        var y: u32 = 0;
        while (y < copy_h) : (y += 1) {
            const src_row = @intFromPtr(src) + @as(usize, y) * src_stride * 4;
            const dst_row = @intFromPtr(dst) + @as(usize, y) * dst_stride * 4;
            asm volatile ("cld; rep movsd"
                :
                : [dst] "{rdi}" (dst_row),
                  [src] "{rsi}" (src_row),
                  [cnt] "{rcx}" (copy_w),
                : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true });
        }
    }
}

fn fillBackgroundSource() void {
    const buf = source_pixel_buf orelse return;
    const dst: [*]volatile u32 = @ptrCast(@alignCast(buf));

    const desktop = @import("desktop.zig");
    const bb = desktop.getBackBuffer() orelse {
        const total: u32 = SOURCE_W * SOURCE_H;
        const bg: u32 = 0xFF101820;
        var i: u32 = 0;
        while (i < total) : (i += 1) dst[i] = bg;
        return;
    };
    const sw = screen_w_cache;
    const sh = screen_h_cache;
    if (sw == 0 or sh == 0) return;

    if (!backbuf_logged) {
        debug.klog("[gpu-comp] background source: backbuf {d}x{d} -> {d}x{d}\n", .{ sw, sh, SOURCE_W, SOURCE_H });
        backbuf_logged = true;
    }

    // Fast path: when source dims match the backbuf dims, the
    // nearest-neighbor scale collapses to an identity copy.
    if (sw == SOURCE_W and sh == SOURCE_H) {
        if (pending_full or pending_rect_count == 0) {
            // Full 8 MB rep movsq — initial frame or wholesale change.
            const u64_count: usize = (@as(usize, SOURCE_W) * SOURCE_H * 4) / 8;
            asm volatile ("cld; rep movsq"
                :
                : [dst] "{rdi}" (@intFromPtr(dst)),
                  [src] "{rsi}" (@intFromPtr(bb)),
                  [cnt] "{rcx}" (u64_count),
                : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true });
        } else {
            // Per-rect copy: only the regions desktop reports dirty.
            // For typical events (terminal row, button press, dock
            // tooltip) this is <1% of the full upload.
            var i: u8 = 0;
            while (i < pending_rect_count) : (i += 1) {
                const rx = pending_rects[i][0];
                const ry = pending_rects[i][1];
                const rw = pending_rects[i][2];
                const rh = pending_rects[i][3];
                if (rx >= sw or ry >= sh) continue;
                const eff_w = @min(rw, sw - rx);
                const eff_h = @min(rh, sh - ry);
                if (eff_w == 0 or eff_h == 0) continue;
                const u64_per_row: usize = @as(usize, eff_w) * 4 / 8;
                const tail_bytes: usize = (@as(usize, eff_w) * 4) - u64_per_row * 8;
                var rr: u32 = 0;
                while (rr < eff_h) : (rr += 1) {
                    const row = ry + rr;
                    const src_off = (@as(usize, row) * sw + rx);
                    const dst_off = (@as(usize, row) * SOURCE_W + rx);
                    const src_p = @intFromPtr(bb) + src_off * 4;
                    const dst_p = @intFromPtr(dst) + dst_off * 4;
                    if (u64_per_row > 0) {
                        asm volatile ("cld; rep movsq"
                            :
                            : [dst] "{rdi}" (dst_p),
                              [src] "{rsi}" (src_p),
                              [cnt] "{rcx}" (u64_per_row),
                            : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true });
                    }
                    if (tail_bytes != 0) {
                        // Odd-pixel tail — w is even in practice (BORDER + multiples of 2)
                        // but be defensive. 4 bytes at a time.
                        const tdst: [*]volatile u32 = @ptrFromInt(dst_p + u64_per_row * 8);
                        const tsrc: [*]volatile u32 = @ptrFromInt(src_p + u64_per_row * 8);
                        const tail_words: usize = tail_bytes / 4;
                        var ti: usize = 0;
                        while (ti < tail_words) : (ti += 1) tdst[ti] = tsrc[ti];
                    }
                }
            }
        }
        pending_full = false;
        pending_rect_count = 0;
        return;
    }

    var y: u32 = 0;
    while (y < SOURCE_H) : (y += 1) {
        const sy: u32 = (y * sh) / SOURCE_H;
        const row_off: usize = @as(usize, sy) * sw;
        var x: u32 = 0;
        while (x < SOURCE_W) : (x += 1) {
            const sx: u32 = (x * sw) / SOURCE_W;
            dst[y * SOURCE_W + x] = bb[row_off + sx];
        }
    }
}

fn fillFocusedSource() void {
    focused_rect_w = 0;
    focused_rect_h = 0;
    // Step 9.2: focused-overlay draw disabled. The background source is
    // now 1:1 1920×1080 of the desktop backbuf — which already contains
    // every GUI window rendered correctly (desktop.renderScene blits
    // gui_fb → backbuf). The 256×256 focused-source upscale that this
    // function feeds was DEGRADING quality on focused GUI apps (visible
    // as a low-res blur on settings/sysmon/paint when focused; terminals
    // looked fine because they have no gui_fb and the overlay short-
    // circuited). Plumbing kept for step 9.3 (per-window effects).
    if (true) return;
    const buf = focused_pixel_buf orelse return;
    const dst: [*]volatile u32 = @ptrCast(@alignCast(buf));

    const wm = @import("desktop/window.zig");
    var src_ptr: [*]volatile u32 = undefined;
    var src_w: u32 = 0;
    var src_h: u32 = 0;
    var src_stride: u32 = 0;
    var win_x: i32 = 0;
    var win_y: i32 = 0;
    var win_pixel_w: u32 = 0;
    var win_pixel_h: u32 = 0;
    var found: bool = false;
    {
        const flags = wm.lockWindows();
        defer wm.unlockWindows(flags);
        const idx = wm.focused;
        if (idx >= wm.windows.len) return;
        if (!wm.slot_used[idx]) return;
        const win = &wm.windows[idx];
        if (!win.visible or win.minimized) return;
        if (win.gui_w == 0 or win.gui_alloc_w == 0) return;
        const candidate: ?[*]volatile u32 = if (win.has_presented) blk: {
            const pi = win.gui_fb_pub.load(.acquire);
            break :blk win.gui_fb_backs[pi];
        } else win.gui_fb;
        const ptr = candidate orelse return;
        src_ptr = ptr;
        src_w = win.gui_w;
        src_h = win.gui_h;
        src_stride = win.gui_alloc_w;
        win_x = win.x;
        win_y = win.y + 28; // skip title bar (TITLEBAR_H)
        win_pixel_w = win.width;
        win_pixel_h = win.height -| 28;
        found = true;
    }
    if (!found or win_pixel_w == 0 or win_pixel_h == 0) return;

    if (!focused_logged) {
        debug.klog("[gpu-comp] focused source: window {d}x{d} -> {d}x{d}\n", .{ src_w, src_h, FOCUSED_W, FOCUSED_H });
        focused_logged = true;
    }

    // Downsample window content (gui_w x gui_h) to FOCUSED_W x FOCUSED_H.
    var y: u32 = 0;
    while (y < FOCUSED_H) : (y += 1) {
        const sy: u32 = (y * src_h) / FOCUSED_H;
        const row_off: usize = @as(usize, sy) * src_stride;
        var x: u32 = 0;
        while (x < FOCUSED_W) : (x += 1) {
            const sx: u32 = (x * src_w) / FOCUSED_W;
            dst[y * FOCUSED_W + x] = src_ptr[row_off + sx];
        }
    }

    // Compute the render-image rect for the focused window. The render
    // image is RENDER_W x RENDER_H, mapping 1:1 to screen dimensions.
    const sw = screen_w_cache;
    const sh = screen_h_cache;
    if (sw == 0 or sh == 0) return;
    const ex0: i32 = if (win_x < 0) 0 else win_x;
    const ey0: i32 = if (win_y < 0) 0 else win_y;
    if (ex0 >= @as(i32, @intCast(sw)) or ey0 >= @as(i32, @intCast(sh))) return;
    const rx0: u32 = (@as(u32, @intCast(ex0)) * RENDER_W) / sw;
    const ry0: u32 = (@as(u32, @intCast(ey0)) * RENDER_H) / sh;
    const rx1: u32 = @min(RENDER_W, ((@as(u32, @intCast(ex0)) + win_pixel_w) * RENDER_W) / sw);
    const ry1: u32 = @min(RENDER_H, ((@as(u32, @intCast(ey0)) + win_pixel_h) * RENDER_H) / sh);
    if (rx1 <= rx0 or ry1 <= ry0) return;
    focused_rect_x = rx0;
    focused_rect_y = ry0;
    focused_rect_w = rx1 - rx0;
    focused_rect_h = ry1 - ry0;
}

/// Copy a rectangular region from desktop's back buffer to the screen FB.
/// Used for both full-screen and dirty-rect blits.
fn blitRectToScreen(x: u32, y: u32, w: u32, h: u32) void {
    const desktop = @import("desktop.zig");
    const bb = desktop.getBackBuffer() orelse return;
    const sw = screen_w_cache;
    const sh = screen_h_cache;
    if (sw == 0 or sh == 0) return;
    const x1 = @min(x + w, sw);
    const y1 = @min(y + h, sh);
    if (x >= x1 or y >= y1) return;
    const eff_w = x1 - x;
    const fb_int = @intFromPtr(virtio_gpu.framebuffer);
    const bb_int = @intFromPtr(bb);
    var ry: u32 = y;
    while (ry < y1) : (ry += 1) {
        const row_off = ry * sw + x;
        asm volatile ("cld; rep movsl"
            :
            : [dst] "{rdi}" (fb_int + row_off * 4),
              [src] "{rsi}" (bb_int + row_off * 4),
              [cnt] "{rcx}" (eff_w),
            : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
        );
    }
}

/// Copy desktop back buffer → screen FB. Strategy depends on scanout mode:
///
///   - Double-buffered blob (blob_count==2): always do a full-screen
///     memcpy. Each flip alternates which blob the host displays, so
///     the back buffer (where we just wrote) becomes front next frame
///     and the OTHER blob (now back) has content from 2 frames ago.
///     Dirty-rect blits would leave that stale content visible. Full
///     8 MB memcpy ≈ 1.3 ms — cheap enough to do every frame.
///
///   - Single-blob (blob_count<=1) or 2D fallback: classic dirty-rect
///     blits. The same blob is read by host and written by guest, so
///     we only need to update the regions the desktop redrew.
///
/// Either way, does NOT flush — the per-frame loop does one
/// flushUnconditional after the corner rect work.
fn syncBackBufferToScreen() bool {
    if (!virtio_gpu.active) return false;
    const desktop = @import("desktop.zig");
    const bb = desktop.getBackBuffer() orelse return false;
    const sw = screen_w_cache;
    const sh = screen_h_cache;
    if (sw == 0 or sh == 0) return false;
    const dirty_rects_mod = @import("desktop/dirty.zig");

    // Double-buffer: full-screen sync each frame.
    if (virtio_gpu.blob_count >= 2) {
        const u64_count: usize = (@as(usize, sw) * sh * 4) / 8;
        asm volatile ("cld; rep movsq"
            :
            : [dst] "{rdi}" (@intFromPtr(virtio_gpu.framebuffer)),
              [src] "{rsi}" (@intFromPtr(bb)),
              [cnt] "{rcx}" (u64_count),
            : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
        );
        dirty_rects_mod.reset();
        return true;
    }

    // Single-buffer / 2D path: dirty-rect blits.
    if (dirty_rects_mod.isFull()) {
        const u64_count: usize = (@as(usize, sw) * sh * 4) / 8;
        asm volatile ("cld; rep movsq"
            :
            : [dst] "{rdi}" (@intFromPtr(virtio_gpu.framebuffer)),
              [src] "{rsi}" (@intFromPtr(bb)),
              [cnt] "{rcx}" (u64_count),
            : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
        );
        dirty_rects_mod.reset();
        return true;
    }
    const n = dirty_rects_mod.rectCount();
    var i: u8 = 0;
    while (i < n) : (i += 1) {
        const r = dirty_rects_mod.getRect(i);
        blitRectToScreen(r[0], r[1], r[2], r[3]);
    }
    dirty_rects_mod.reset();
    return n > 0;
}

fn submitAndReadResult(cs: *venus.CmdStream) i32 {
    const ring = reply_ring orelse return std.math.minInt(i32);
    for (0..32) |i| ring[i] = 0;
    if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, cs.bytes())) return std.math.minInt(i32);
    return venus.readReplyResult(ring);
}

/// Submit a Venus command that doesn't generate a reply.
fn submitFireAndForget(cs: *venus.CmdStream) bool {
    return virtio_gpu.submit3D(COMPOSITOR_CTX_ID, cs.bytes());
}

/// Task A Phase 1: allocate a 64 KB HOST3D blob, lay out the ring
/// regions, zero them, and call vkCreateRingMESA. After this returns
/// true the host has a dedicated thread polling our ring tail.
///
/// Phase 1 stops here — we don't actually write commands to the ring
/// yet. Phase 2 would replace per-frame submit3D() with ring writes.
fn setupCommandRing() bool {
    if (reply_ring == null) return false; // need Venus reply ring up first

    const res_id = virtio_gpu.alloc3DResourceId();
    // Anonymous virgl blob (blob_id=0) — virgl_renderer manages the
    // backing memory directly. Same recipe as the reply ring.
    if (!virtio_gpu.resourceCreateBlob(COMPOSITOR_CTX_ID, res_id, BLOB_MEM_HOST3D, 1, 0, RING_TOTAL_SIZE)) {
        debug.klog("[gpu-comp] ring: resourceCreateBlob FAILED\n", .{});
        return false;
    }
    if (!virtio_gpu.ctxAttachResource(COMPOSITOR_CTX_ID, res_id)) {
        debug.klog("[gpu-comp] ring: ctxAttachResource FAILED\n", .{});
        return false;
    }
    const phys = virtio_gpu.resourceMapBlob(res_id, @intCast(RING_TOTAL_SIZE)) orelse {
        debug.klog("[gpu-comp] ring: resourceMapBlob FAILED\n", .{});
        return false;
    };
    const kvirt: [*]volatile u8 = @ptrFromInt(paging.physToVirt(phys));
    // Zero the entire ring region (vkr_ring expects head=0, status=0 at create).
    for (0..RING_TOTAL_SIZE) |i| kvirt[i] = 0;

    // Call vkCreateRingMESA via Venus.
    scratch_cs.reset();
    venus.encodeCreateRing(
        &scratch_cs,
        COMPOSITOR_RING,
        res_id,
        0, // region offset within the resource
        RING_TOTAL_SIZE,
        50_000, // idleTimeout: 50 ms — host thread sleeps after this much idle
        RING_HEAD_OFFSET,
        RING_TAIL_OFFSET,
        RING_STATUS_OFFSET,
        RING_BUFFER_OFFSET,
        RING_BUFFER_SIZE,
        RING_EXTRA_OFFSET,
        RING_EXTRA_SIZE,
    );
    if (!submitFireAndForget(&scratch_cs)) {
        debug.klog("[gpu-comp] ring: vkCreateRingMESA submit FAILED\n", .{});
        return false;
    }

    ring_kvirt = kvirt;
    ring_res_id = res_id;
    ring_created = true;
    debug.klog("[gpu-comp] ring: created (res={d} phys=0x{X} total={d} buf={d}) — Phase 1 ok\n", .{ res_id, phys, RING_TOTAL_SIZE, RING_BUFFER_SIZE });

    // Sanity: read back head/tail/status (should all be 0).
    const head_ptr: *align(1) const volatile u32 = @ptrCast(kvirt + RING_HEAD_OFFSET);
    const tail_ptr: *align(1) const volatile u32 = @ptrCast(kvirt + RING_TAIL_OFFSET);
    const status_ptr: *align(1) const volatile u32 = @ptrCast(kvirt + RING_STATUS_OFFSET);
    debug.klog("[gpu-comp] ring: post-create head={d} tail={d} status=0x{X}\n", .{ head_ptr.*, tail_ptr.*, status_ptr.* });

    return true;
}

/// Step 5/9.1: stand up the rendering objects so each frame can submit
/// one render pass and the kernel can read the rendered pixels back
/// through an SHM-backed VkBuffer.
///
/// Backing strategy:
///   - Render image: OPTIMAL VkImage with COLOR_ATTACHMENT | TRANSFER_SRC,
///     bound to Venus-allocated VkDeviceMemory (vkAllocateMemoryExportable).
///     Lavapipe writes here at full speed; the slow KVM-memory-region
///     overhead only bites kernel-side reads, not Vulkan-side writes.
///   - Read-back buffer: SHM blob (blob_id=0, flags=MAPPABLE only) ->
///     virgl's create_resource_from_shm path, host anonymous mmap with
///     direct EPT mapping (kernel reads at memory-bandwidth speed).
///     The blob is Venus-imported as VkDeviceMemory and a VkBuffer
///     (TRANSFER_DST) is bound to it.
///   - Per frame: render pass writes to the image; an inline pipeline
///     barrier transitions COLOR_ATTACHMENT_OPTIMAL -> TRANSFER_SRC_OPTIMAL;
///     vkCmdCopyImageToBuffer copies pixels into the SHM buffer; fence
///     wait; kernel memcpy from buffer's SHM mapping -> 2D scanout.
///   - We can't bind a VkImage directly to SHM-imported memory (Venus
///     errors out with "vkBindImageMemory CS error" — SHM imports lack
///     the dmabuf lineage Lavapipe expects for image binding). VkBuffer
///     binds to SHM imports cleanly.
fn setupVulkanRender() bool {
    if (reply_ring == null) return false;

    // 1. Create the render image: OPTIMAL + COLOR_ATTACHMENT | TRANSFER_SRC,
    //    DMA_BUF-exportable. OPTIMAL because Lavapipe's color-attachment
    //    write path silently uses an internal tiled layout; matching
    //    that with OPTIMAL avoids confusion. We never read its bytes
    //    through SHM BAR — vkCmdCopyImageToBuffer untiles for us.
    {
        scratch_cs.reset();
        // BATCH 1: render image + memory + bind. Three Venus fire-and-
        // forget cmds in one ctrl_vq round-trip. Equivalent to what
        // vkExecuteCommandStreamsMESA gives you at the protocol level —
        // simpler here because all cmds live in the same scratch_cs.
        // Host's dispatch loop runs them in order within one stream.
        venus.encodeCreateImageExportable(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            RENDER_W,
            RENDER_H,
            venus.VK_FORMAT_B8G8R8A8_UNORM,
            venus.VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | venus.VK_IMAGE_USAGE_TRANSFER_SRC_BIT,
            COMPOSITOR_RENDER_IMAGE,
        );
        venus.encodeAllocateMemoryExportable(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            RENDER_PX_BYTES,
            0,
            COMPOSITOR_RENDER_MEM,
        );
        venus.encodeBindImageMemory(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_RENDER_IMAGE, COMPOSITOR_RENDER_MEM, 0);
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] batch1 (render image + mem + bind) FAILED\n", .{});
            return false;
        }
    }

    // 3. Read-back buffer pair: two Venus-allocated VkDeviceMemory each
    //    wrapped as a HOST3D blob (blob_id=mem_id, MAPPABLE|CROSS_DEVICE).
    //    With VKR_DEBUG=udmabuf the allocations turn into memfd→udmabuf-
    //    fd, so each is a real dmabuf accessible to the host scanout
    //    layer. Step 9.3 pairs them for tear-free page flip: each frame
    //    Vulkan writes into the BACK (= 1 - blob_front), then driver's
    //    flushUnconditional flips SCANOUT_BLOB to that buffer.
    debug.klog("[gpu-comp] render image {d}x{d} (Venus-allocated, OPTIMAL)\n", .{ RENDER_W, RENDER_H });
    var bi: u32 = 0;
    while (bi < 2) : (bi += 1) {
        const mem_handle = readback_mem_handles[bi];
        const buf_handle = readback_buf_handles[bi];
        // BATCH 2: per-readback mem alloc + buffer create + bind, one
        // ctrl_vq round-trip per readback (was three).
        {
            scratch_cs.reset();
            venus.encodeAllocateMemoryExportable(&scratch_cs, COMPOSITOR_DEVICE, RENDER_PX_BYTES, 0, mem_handle);
            venus.encodeCreateBufferExportable(&scratch_cs, COMPOSITOR_DEVICE, RENDER_PX_BYTES, venus.VK_BUFFER_USAGE_TRANSFER_DST_BIT, buf_handle);
            venus.encodeBindBufferMemory(&scratch_cs, COMPOSITOR_DEVICE, buf_handle, mem_handle, 0);
            if (!submitFireAndForget(&scratch_cs)) {
                debug.klog("[gpu-comp] readback[{d}] batch (mem+buf+bind) FAILED\n", .{bi});
                return false;
            }
        }
        const res_id = virtio_gpu.alloc3DResourceId();
        if (!virtio_gpu.resourceCreateBlob(COMPOSITOR_CTX_ID, res_id, BLOB_MEM_HOST3D, 5, mem_handle, RENDER_PX_BYTES)) {
            debug.klog("[gpu-comp] readback[{d}] resourceCreateBlob FAILED\n", .{bi});
            return false;
        }
        if (!virtio_gpu.ctxAttachResource(COMPOSITOR_CTX_ID, res_id)) {
            debug.klog("[gpu-comp] readback[{d}] ctxAttachResource FAILED\n", .{bi});
            return false;
        }
        const phys = virtio_gpu.resourceMapBlob(res_id, RENDER_PX_BYTES) orelse {
            debug.klog("[gpu-comp] readback[{d}] resourceMapBlob FAILED\n", .{bi});
            return false;
        };
        readback_res_ids[bi] = res_id;
        readback_pixel_bufs[bi] = @ptrFromInt(paging.physToVirt(phys));
        debug.klog("[gpu-comp] readback[{d}] res={d} phys=0x{X} (HOST3D blob+udmabuf)\n", .{ bi, res_id, phys });

        // C: probe memory properties. memoryTypeBits tells us which host
        // Vulkan memory types can import this resource as VkDeviceMemory.
        // If zero, the resource can't be imported — that would be a red
        // flag that the dma-buf export isn't actually usable. Also a
        // sanity check that the Venus reply ring + flag plumbing works
        // for OUT-param queries.
        if (reply_ring) |ring| {
            scratch_cs.reset();
            venus.encodeGetMemoryResourceProperties(&scratch_cs, COMPOSITOR_DEVICE, res_id);
            for (0..32) |i| ring[i] = 0;
            if (virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) {
                const r = venus.readGetMemoryResourcePropertiesReply(ring);
                debug.klog("[gpu-comp] readback[{d}] mem props: VkResult={d} typeBits=0x{X}\n", .{ bi, r.result, r.type_bits });
            } else {
                debug.klog("[gpu-comp] readback[{d}] mem props probe submit FAILED\n", .{bi});
            }
        }
    }
    // Legacy alias for the kernel-side rep movsq fallback (only fires
    // when scanout promotion fails). Points at buffer 0.
    render_pixel_buf = readback_pixel_bufs[0];

    // BATCH 3: image view + render pass + framebuffer + cmd pool +
    // cmd buf + fence + source image + source mem + source bind.
    // Nine cmds, all fire-and-forget, in one ctrl_vq round-trip.
    {
        scratch_cs.reset();
        venus.encodeCreateImageView(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            COMPOSITOR_RENDER_IMAGE,
            venus.VK_FORMAT_B8G8R8A8_UNORM,
            venus.VK_IMAGE_ASPECT_COLOR_BIT,
            COMPOSITOR_RENDER_VIEW,
        );
        venus.encodeCreateRenderPass(&scratch_cs, COMPOSITOR_DEVICE, venus.VK_FORMAT_B8G8R8A8_UNORM, COMPOSITOR_RENDER_PASS);
        venus.encodeCreateFramebuffer(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            COMPOSITOR_RENDER_PASS,
            COMPOSITOR_RENDER_VIEW,
            RENDER_W,
            RENDER_H,
            COMPOSITOR_FRAMEBUFFER,
        );
        venus.encodeCreateCommandPool(&scratch_cs, COMPOSITOR_DEVICE, 0, COMPOSITOR_CMD_POOL);
        venus.encodeAllocateCommandBuffers(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_CMD_POOL, COMPOSITOR_CMD_BUF);
        venus.encodeCreateFence(&scratch_cs, COMPOSITOR_DEVICE, 0, COMPOSITOR_FENCE);
        venus.encodeCreateImageSampledLinear(&scratch_cs, COMPOSITOR_DEVICE, SOURCE_W, SOURCE_H, venus.VK_FORMAT_B8G8R8A8_UNORM, COMPOSITOR_SOURCE_IMAGE);
        venus.encodeAllocateMemoryExportable(&scratch_cs, COMPOSITOR_DEVICE, SOURCE_PX_BYTES, 0, COMPOSITOR_SOURCE_MEM);
        venus.encodeBindImageMemory(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_SOURCE_IMAGE, COMPOSITOR_SOURCE_MEM, 0);
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] batch3 (view+pass+fb+cmdpool+cmdbuf+fence+source) FAILED\n", .{});
            return false;
        }
    }
    const source_res_id = virtio_gpu.alloc3DResourceId();
    if (!virtio_gpu.resourceCreateBlob(
        COMPOSITOR_CTX_ID,
        source_res_id,
        BLOB_MEM_HOST3D,
        5,
        COMPOSITOR_SOURCE_MEM,
        SOURCE_PX_BYTES,
    )) {
        debug.klog("[gpu-comp] source resourceCreateBlob FAILED\n", .{});
        return false;
    }
    if (!virtio_gpu.ctxAttachResource(COMPOSITOR_CTX_ID, source_res_id)) {
        debug.klog("[gpu-comp] source ctxAttachResource FAILED\n", .{});
        return false;
    }
    const source_phys = virtio_gpu.resourceMapBlob(source_res_id, SOURCE_PX_BYTES) orelse {
        debug.klog("[gpu-comp] source resourceMapBlob FAILED\n", .{});
        return false;
    };
    const source_buf: [*]volatile u8 = @ptrFromInt(paging.physToVirt(source_phys));
    source_pixel_buf = source_buf;
    debug.klog("[gpu-comp] source image res={d} phys=0x{X} {d}x{d}\n", .{ source_res_id, source_phys, SOURCE_W, SOURCE_H });

    // Image view (color aspect, 2D). Created BEFORE the layout transition
    // so the descriptor-set update later has something to reference.
    {
        scratch_cs.reset();
        venus.encodeCreateImageView(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            COMPOSITOR_SOURCE_IMAGE,
            venus.VK_FORMAT_B8G8R8A8_UNORM,
            venus.VK_IMAGE_ASPECT_COLOR_BIT,
            COMPOSITOR_SOURCE_VIEW,
        );
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] source vkCreateImageView submit FAILED\n", .{});
            return false;
        }
    }

    // One-time submit: transition source image UNDEFINED → GENERAL so
    // the host can write (= our kernel writes via dma-buf), and Lavapipe
    // can later sample. Single command buffer, fence-gated.
    {
        scratch_cs.reset();
        venus.encodeBeginCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
        venus.encodeCmdPipelineBarrier(
            &scratch_cs,
            COMPOSITOR_CMD_BUF,
            COMPOSITOR_SOURCE_IMAGE,
            0, // UNDEFINED
            1, // GENERAL
            0x1, // srcStage = TOP_OF_PIPE
            0x4000, // dstStage = HOST
            0, // srcAccess = 0
            0x4000, // dstAccess = HOST_WRITE
        );
        venus.encodeEndCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
        venus.encodeResetFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE);
        venus.encodeQueueSubmitFence(&scratch_cs, COMPOSITOR_QUEUE, COMPOSITOR_CMD_BUF, COMPOSITOR_FENCE);
        venus.encodeSeekReplyCommandStream(&scratch_cs, 0);
        venus.encodeWaitForFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE, 1_000_000_000);
        if (reply_ring) |ring| {
            for (0..32) |i| ring[i] = 0;
        }
        if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) {
            debug.klog("[gpu-comp] source layout transition submit FAILED\n", .{});
            return false;
        }
    }

    // Kernel writes initial frame into the source image. With LINEAR
    // tiling + GENERAL layout, byte order is row-major B,G,R,A and
    // Lavapipe's sampler reads them as B8G8R8A8_UNORM.
    fillSourceFrame(0);
    debug.klog("[gpu-comp] source image filled (initial frame)\n", .{});

    // 5c. Sampler + descriptor set machinery so the fragment shader can
    //     sample the source image at `set=0, binding=0`.
    {
        scratch_cs.reset();
        venus.encodeCreateSampler(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_SAMPLER);
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] vkCreateSampler submit FAILED\n", .{});
            return false;
        }
    }
    // BATCH 4: descriptor set layout + descriptor pool. Two FAF cmds,
    // one round-trip.
    {
        scratch_cs.reset();
        venus.encodeCreateDescriptorSetLayoutSampler(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_DESC_SET_LAYOUT);
        // Pool sized for: 2 legacy sets (background + focused-overlay,
        // currently disabled) + MAX_WINDOW_SLOTS for per-window textures
        // (step 9.4). Each set has 1 combined image sampler, so
        // descriptorCount == max_sets.
        const pool_size: u32 = 2 + @as(u32, MAX_WINDOW_SLOTS);
        venus.encodeCreateDescriptorPoolN(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_DESC_POOL, pool_size, pool_size);
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] batch4 (desc set layout + pool) FAILED\n", .{});
            return false;
        }
    }
    {
        scratch_cs.reset();
        venus.encodeAllocateDescriptorSet(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_DESC_POOL, COMPOSITOR_DESC_SET_LAYOUT, COMPOSITOR_DESC_SET);
        if (reply_ring) |ring| {
            for (0..32) |i| ring[i] = 0;
        }
        if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) {
            debug.klog("[gpu-comp] vkAllocateDescriptorSets submit FAILED\n", .{});
            return false;
        }
        if (reply_ring) |ring| {
            const r = venus.readReplyResult(ring);
            if (r != 0) {
                debug.klog("[gpu-comp] vkAllocateDescriptorSets VkResult={d}\n", .{r});
                return false;
            }
        }
    }
    {
        // Bind the source image view + sampler to descriptor set 0,
        // binding 0. image_layout = GENERAL (1) since that's where we
        // transitioned the source.
        scratch_cs.reset();
        venus.encodeUpdateDescriptorSetSampler(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            COMPOSITOR_DESC_SET,
            COMPOSITOR_SAMPLER,
            COMPOSITOR_SOURCE_VIEW,
            1, // GENERAL
        );
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] vkUpdateDescriptorSets submit FAILED\n", .{});
            return false;
        }
    }

    // BATCH 5: focused image + mem + bind. Three FAF cmds, one round-trip.
    {
        scratch_cs.reset();
        venus.encodeCreateImageSampledLinear(&scratch_cs, COMPOSITOR_DEVICE, FOCUSED_W, FOCUSED_H, venus.VK_FORMAT_B8G8R8A8_UNORM, COMPOSITOR_FOCUSED_IMAGE);
        venus.encodeAllocateMemoryExportable(&scratch_cs, COMPOSITOR_DEVICE, FOCUSED_PX_BYTES, 0, COMPOSITOR_FOCUSED_MEM);
        venus.encodeBindImageMemory(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FOCUSED_IMAGE, COMPOSITOR_FOCUSED_MEM, 0);
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] batch5 (focused image+mem+bind) FAILED\n", .{});
            return false;
        }
    }
    const focused_res_id = virtio_gpu.alloc3DResourceId();
    if (!virtio_gpu.resourceCreateBlob(
        COMPOSITOR_CTX_ID,
        focused_res_id,
        BLOB_MEM_HOST3D,
        5,
        COMPOSITOR_FOCUSED_MEM,
        FOCUSED_PX_BYTES,
    )) return false;
    if (!virtio_gpu.ctxAttachResource(COMPOSITOR_CTX_ID, focused_res_id)) return false;
    const focused_phys = virtio_gpu.resourceMapBlob(focused_res_id, FOCUSED_PX_BYTES) orelse return false;
    focused_pixel_buf = @as([*]volatile u8, @ptrFromInt(paging.physToVirt(focused_phys)));
    debug.klog("[gpu-comp] focused image res={d} phys=0x{X} {d}x{d}\n", .{ focused_res_id, focused_phys, FOCUSED_W, FOCUSED_H });
    {
        scratch_cs.reset();
        venus.encodeCreateImageView(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            COMPOSITOR_FOCUSED_IMAGE,
            venus.VK_FORMAT_B8G8R8A8_UNORM,
            venus.VK_IMAGE_ASPECT_COLOR_BIT,
            COMPOSITOR_FOCUSED_VIEW,
        );
        if (!submitFireAndForget(&scratch_cs)) return false;
    }
    // Layout transition: UNDEFINED -> GENERAL (kernel host writes).
    {
        scratch_cs.reset();
        venus.encodeBeginCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
        venus.encodeCmdPipelineBarrier(
            &scratch_cs,
            COMPOSITOR_CMD_BUF,
            COMPOSITOR_FOCUSED_IMAGE,
            0, // UNDEFINED
            1, // GENERAL
            0x1, // srcStage = TOP_OF_PIPE
            0x4000, // dstStage = HOST
            0, // srcAccess = 0
            0x4000, // dstAccess = HOST_WRITE
        );
        venus.encodeEndCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
        venus.encodeResetFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE);
        venus.encodeQueueSubmitFence(&scratch_cs, COMPOSITOR_QUEUE, COMPOSITOR_CMD_BUF, COMPOSITOR_FENCE);
        venus.encodeWaitForFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE, 1_000_000_000);
        if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) return false;
    }
    // Allocate the focused-window descriptor set from the pool.
    {
        scratch_cs.reset();
        venus.encodeAllocateDescriptorSet(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_DESC_POOL, COMPOSITOR_DESC_SET_LAYOUT, COMPOSITOR_FOCUSED_DESC_SET);
        if (reply_ring) |ring| {
            for (0..32) |i| ring[i] = 0;
        }
        if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) return false;
        if (reply_ring) |ring| {
            const r = venus.readReplyResult(ring);
            if (r != 0) {
                debug.klog("[gpu-comp] vkAllocateDescriptorSets(focused) VkResult={d}\n", .{r});
                return false;
            }
        }
    }
    {
        scratch_cs.reset();
        venus.encodeUpdateDescriptorSetSampler(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            COMPOSITOR_FOCUSED_DESC_SET,
            COMPOSITOR_SAMPLER,
            COMPOSITOR_FOCUSED_VIEW,
            1, // GENERAL
        );
        if (!submitFireAndForget(&scratch_cs)) return false;
    }

    // BATCH 6: shaders + pipeline layout + graphics pipeline. Four FAF
    // cmds. Shader modules inline their SPIR-V (~500 bytes total here),
    // pipeline encoder is ~500 bytes. Total ~1.2 KB — well within 4 KB
    // scratch_cs. If shaders grow, split into two batches.
    {
        scratch_cs.reset();
        venus.encodeCreateShaderModule(&scratch_cs, COMPOSITOR_DEVICE, &shaders.vert_spv, COMPOSITOR_VERT_MODULE);
        venus.encodeCreateShaderModule(&scratch_cs, COMPOSITOR_DEVICE, &shaders.frag_spv, COMPOSITOR_FRAG_MODULE);
        venus.encodeCreatePipelineLayoutFull(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            COMPOSITOR_DESC_SET_LAYOUT,
            0x10, // FRAGMENT_BIT for push constants
            32, // vec4 rect + vec4 uv_scale
            COMPOSITOR_PIPELINE_LAYOUT,
        );
        venus.encodeCreateGraphicsPipelinesFullscreen(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            COMPOSITOR_PIPELINE_LAYOUT,
            COMPOSITOR_RENDER_PASS,
            COMPOSITOR_VERT_MODULE,
            COMPOSITOR_FRAG_MODULE,
            RENDER_W,
            RENDER_H,
            COMPOSITOR_PIPELINE,
        );
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] batch6 (shaders+pipeline-layout+pipeline) FAILED\n", .{});
            return false;
        }
    }

    debug.klog("[gpu-comp] render setup ok — image + fb + cmd buf + pipeline ready\n", .{});
    return true;
}

/// True once Vulkan device + render path are up. Callers (e.g.
/// sysCreateWindow) check this before calling allocateWindowImage —
/// if false, fall back to legacy PMM-allocated gui_fb.
pub fn isReady() bool {
    return vulkan_render_ready;
}

/// Step 9.4 Phase B.2: allocate one per-window Venus image slot with
/// separate image and memory dimensions.
///
/// `image_w` × `image_h` is the visible region the fragment shader
/// samples (typically the window's display dims). `mem_w` × `mem_h` is
/// the underlying buffer size (typically the app's alloc dims) — must
/// be ≥ image dims and `mem_w` should be 16-aligned to match Lavapipe's
/// rowPitch expectation. `mem_w` IS the row stride; apps writing into
/// this dmabuf must use that as their pitch.
///
/// Returns the slot index, or null on failure. Caller can read the slot
/// from `window_slots[idx]` for kernel_ptr (kernel mapping), phys
/// (for vmm.mapUserPage), and desc_set_id (for compositor draws).
pub fn allocateWindowImage(image_w: u32, image_h: u32, mem_w: u32, mem_h: u32) ?u8 {
    if (!vulkan_render_ready) return null;
    if (image_w == 0 or image_h == 0 or mem_w == 0 or mem_h == 0) return null;
    if (mem_w < image_w or mem_h < image_h) return null;
    if ((mem_w & 15) != 0) return null; // caller must pre-align mem_w to 16
    // The Vulkan image is created at MEM dims (alloc_w × alloc_h), not
    // image dims (disp_w × disp_h). Reason: Lavapipe's rowPitch for a
    // LINEAR B8G8R8A8 image is `align(width*4, cacheline)`; for an
    // image with width=disp_w, that wouldn't match the user's stride
    // (= mem_w). By making the image extent match mem_w, both rowPitch
    // and user stride agree at mem_w*4 bytes. The compositor's per-
    // window draw passes uv_scale = (image_w/mem_w, image_h/mem_h) so
    // only the (image_w × image_h) drawn portion is sampled — the over-
    // allocated columns/rows stay invisible.

    // Find a free slot.
    var slot_idx: u8 = 0;
    while (slot_idx < MAX_WINDOW_SLOTS) : (slot_idx += 1) {
        if (!window_slots[slot_idx].in_use) break;
    }
    if (slot_idx >= MAX_WINDOW_SLOTS) {
        debug.klog("[gpu-comp] allocateWindowImage: all {d} slots in use\n", .{MAX_WINDOW_SLOTS});
        return null;
    }

    const sl = &window_slots[slot_idx];
    // Memory must be page-aligned — round up to 4 KB so the user-space
    // mapping covers the whole allocation cleanly.
    const px_bytes: u64 = @as(u64, mem_w) * @as(u64, mem_h) * 4;
    const px_bytes_aligned: u64 = (px_bytes + 4095) & ~@as(u64, 4095);
    const stride: u64 = @as(u64, slot_idx) * WINDOW_SLOT_STRIDE;
    const mem_id = WINDOW_SLOT_MEM_BASE + stride;
    const image_id = WINDOW_SLOT_IMAGE_BASE + stride;
    const view_id = WINDOW_SLOT_VIEW_BASE + stride;
    const desc_set_id = WINDOW_SLOT_DESC_SET_BASE + stride;

    // 1. Venus VkImage (LINEAR, SAMPLED|TRANSFER_DST). Image extent =
    //    MEM dims so rowPitch matches user write stride.
    {
        scratch_cs.reset();
        venus.encodeCreateImageSampledLinear(&scratch_cs, COMPOSITOR_DEVICE, mem_w, mem_h, venus.VK_FORMAT_B8G8R8A8_UNORM, image_id);
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] slot[{d}] vkCreateImage FAILED\n", .{slot_idx});
            return null;
        }
    }
    // 2. Venus VkDeviceMemory (exportable; udmabuf via VKR_DEBUG=udmabuf).
    {
        scratch_cs.reset();
        venus.encodeAllocateMemoryExportable(&scratch_cs, COMPOSITOR_DEVICE, @intCast(px_bytes_aligned), 0, mem_id);
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] slot[{d}] vkAllocateMemory FAILED\n", .{slot_idx});
            return null;
        }
    }
    // 3. Bind image to memory.
    {
        scratch_cs.reset();
        venus.encodeBindImageMemory(&scratch_cs, COMPOSITOR_DEVICE, image_id, mem_id, 0);
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] slot[{d}] vkBindImageMemory FAILED\n", .{slot_idx});
            return null;
        }
    }
    // 4. Wrap the VkDeviceMemory as a HOST3D blob, attach to ctx,
    //    map into the SHM BAR for kernel/user access.
    const res_id = virtio_gpu.alloc3DResourceId();
    if (!virtio_gpu.resourceCreateBlob(COMPOSITOR_CTX_ID, res_id, BLOB_MEM_HOST3D, 5, mem_id, px_bytes_aligned)) {
        debug.klog("[gpu-comp] slot[{d}] resourceCreateBlob FAILED\n", .{slot_idx});
        return null;
    }
    if (!virtio_gpu.ctxAttachResource(COMPOSITOR_CTX_ID, res_id)) {
        debug.klog("[gpu-comp] slot[{d}] ctxAttachResource FAILED\n", .{slot_idx});
        return null;
    }
    const phys = virtio_gpu.resourceMapBlob(res_id, @intCast(px_bytes_aligned)) orelse {
        debug.klog("[gpu-comp] slot[{d}] resourceMapBlob FAILED\n", .{slot_idx});
        return null;
    };
    const kvirt: [*]volatile u8 = @ptrFromInt(paging.physToVirt(phys));

    // 5. Image view (color aspect, B8G8R8A8).
    {
        scratch_cs.reset();
        venus.encodeCreateImageView(&scratch_cs, COMPOSITOR_DEVICE, image_id, venus.VK_FORMAT_B8G8R8A8_UNORM, venus.VK_IMAGE_ASPECT_COLOR_BIT, view_id);
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] slot[{d}] vkCreateImageView FAILED\n", .{slot_idx});
            return null;
        }
    }
    // 6. Layout transition UNDEFINED → GENERAL so HOST writes (kernel/
    //    user) are valid and Lavapipe can sample. Same pattern as the
    //    background source.
    {
        scratch_cs.reset();
        venus.encodeBeginCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
        venus.encodeCmdPipelineBarrier(&scratch_cs, COMPOSITOR_CMD_BUF, image_id, 0, 1, 0x1, 0x4000, 0, 0x4000);
        venus.encodeEndCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
        venus.encodeResetFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE);
        venus.encodeQueueSubmitFence(&scratch_cs, COMPOSITOR_QUEUE, COMPOSITOR_CMD_BUF, COMPOSITOR_FENCE);
        venus.encodeWaitForFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE, 1_000_000_000);
        if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) {
            debug.klog("[gpu-comp] slot[{d}] layout transition FAILED\n", .{slot_idx});
            return null;
        }
    }
    // 7. Descriptor set (one per slot, allocated from the bumped pool).
    {
        scratch_cs.reset();
        venus.encodeAllocateDescriptorSet(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_DESC_POOL, COMPOSITOR_DESC_SET_LAYOUT, desc_set_id);
        if (reply_ring) |ring| {
            for (0..32) |i| ring[i] = 0;
        }
        if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) {
            debug.klog("[gpu-comp] slot[{d}] vkAllocateDescriptorSets submit FAILED\n", .{slot_idx});
            return null;
        }
        if (reply_ring) |ring| {
            const r = venus.readReplyResult(ring);
            if (r != 0) {
                debug.klog("[gpu-comp] slot[{d}] vkAllocateDescriptorSets VkResult={d}\n", .{ slot_idx, r });
                return null;
            }
        }
    }
    {
        scratch_cs.reset();
        venus.encodeUpdateDescriptorSetSampler(&scratch_cs, COMPOSITOR_DEVICE, desc_set_id, COMPOSITOR_SAMPLER, view_id, 1);
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] slot[{d}] vkUpdateDescriptorSets FAILED\n", .{slot_idx});
            return null;
        }
    }

    sl.in_use = true;
    sl.width = image_w;
    sl.height = image_h;
    sl.mem_w = mem_w;
    sl.mem_h = mem_h;
    sl.pitch_pixels = mem_w; // mem_w is aligned and IS the row stride
    sl.res_id = res_id;
    sl.desc_set_id = desc_set_id;
    sl.kernel_ptr = kvirt;
    sl.phys = phys;
    sl.mem_bytes = px_bytes_aligned;
    debug.klog("[gpu-comp] slot[{d}] allocated: image={d}x{d} mem={d}x{d} bytes={d} res={d} kvirt=0x{X} phys=0x{X}\n", .{ slot_idx, image_w, image_h, mem_w, mem_h, px_bytes_aligned, res_id, @intFromPtr(kvirt), phys });
    return slot_idx;
}

/// Step 8d: allocate `n_blobs` 1920×1080 B8G8R8A8 LINEAR images via Venus,
/// export their VkDeviceMemory as HOST3D blobs (CROSS_DEVICE → virgl
/// dmabuf), point virtio-gpu's scanout at blob 0, and tell virtio_gpu to
/// flush via flip-or-just-flush instead of the 2D transfer path.
///
/// Returns true if the scanout was switched. On failure leaves the
/// existing 2D scanout intact and the compositor continues working with
/// the slow-path TRANSFER_TO_HOST_2D flush.
///
/// Why HOST3D-via-Venus instead of BLOB_MEM_GUEST: QEMU 9.2's
/// `virgl_cmd_resource_create_blob` (virtio-gpu-virgl.c:701) inverts the
/// success check on `virtio_gpu_create_mapping_iov`, so any guest-blob
/// create returns RESP_ERR_UNSPEC. Routing through Venus avoids the
/// virgl blob-create path entirely — we go through `vkAllocateMemory` +
/// `resourceCreateBlob(blob_id=mem_id)` which virgl handles via a
/// different code path that DOES work.
fn setupBlobScanout(n_blobs: u32) bool {
    if (!virtio_gpu.has_blob) {
        debug.klog("[gpu-comp] setupBlobScanout: BLOB feature not advertised\n", .{});
        return false;
    }
    if (n_blobs < 1 or n_blobs > 2) return false;
    if (reply_ring == null) return false;

    const w = virtio_gpu.width;
    const h = virtio_gpu.height;
    const fb_size_bytes: u64 = @as(u64, w) * h * 4;

    var res_ids: [2]u32 = .{ 0, 0 };
    var virts: [2][*]volatile u32 = .{ undefined, undefined };

    var i: u32 = 0;
    while (i < n_blobs) : (i += 1) {
        // 1. Create an anonymous HOST3D blob (blob_id=0, no Venus
        //    backing). virgl_renderer allocates its own memory and
        //    exports a dmabuf. Reply ring uses this same path at 4 KB
        //    and works fast — mapping points into the SHM BAR with
        //    direct EPT-backed access (no MMIO emulation per write).
        //
        //    Initially we tried Venus-allocated VkDeviceMemory wrapped
        //    in a blob (blob_id=mem_id), but kernel writes were ~200x
        //    slower than to the existing 230 KB source blob — Lavapipe
        //    appears to put large allocations in a memory pool that's
        //    not directly EPT-mapped, causing per-write KVM exits.
        //    Anonymous virgl-managed blobs avoid that pool entirely.
        //
        //    blob_flags=5 = MAPPABLE | CROSS_DEVICE so virgl exports
        //    as dmabuf (SET_SCANOUT_BLOB requires `dmabuf_fd >= 0`).
        const res_id = virtio_gpu.alloc3DResourceId();
        if (!virtio_gpu.resourceCreateBlob(COMPOSITOR_CTX_ID, res_id, 2, 5, 0, fb_size_bytes)) {
            debug.klog("[gpu-comp] scanout[{d}] resourceCreateBlob FAILED\n", .{i});
            return false;
        }
        if (!virtio_gpu.ctxAttachResource(COMPOSITOR_CTX_ID, res_id)) {
            debug.klog("[gpu-comp] scanout[{d}] ctxAttachResource FAILED\n", .{i});
            return false;
        }

        // 2. Map the blob into the SHM BAR so the kernel can write
        //    directly via memcpy.
        const phys = virtio_gpu.resourceMapBlob(res_id, @intCast(fb_size_bytes)) orelse {
            debug.klog("[gpu-comp] scanout[{d}] resourceMapBlob FAILED\n", .{i});
            return false;
        };
        const kvirt: [*]volatile u32 = @ptrFromInt(paging.physToVirt(phys));

        // Pre-fill blob 0 with the existing FB contents so the user
        // doesn't see a black flash during the transition. Blob 1 stays
        // zero — the first compositor frame paints into it.
        if (i == 0) {
            const fb_count: usize = @intCast(fb_size_bytes / 4);
            const old_fb = virtio_gpu.framebuffer;
            var k: usize = 0;
            while (k < fb_count) : (k += 1) kvirt[k] = old_fb[k];
        }

        // No layout transition: the scanout image is never sampled or
        // rendered to by Vulkan — the kernel writes pixels via SHM BAR
        // and the host's display reads the dmabuf as a raw GL texture
        // (glEGLImageTargetTexture2DOES doesn't care about Vulkan
        // VkImageLayout). Skipping the transition also avoids using
        // COMPOSITOR_CMD_BUF/FENCE before setupVulkanRender allocates
        // them, which would corrupt Venus state for subsequent Vulkan
        // calls (root cause of resourceCreateBlob failing in
        // setupVulkanRender when this function ran first).

        res_ids[i] = res_id;
        virts[i] = kvirt;
        debug.klog("[gpu-comp] scanout blob[{d}] res={d} kvirt=0x{X} phys=0x{X}\n", .{ i, res_id, @intFromPtr(kvirt), phys });
    }

    // 7. Tell virtio-gpu to flip the scanout to blob 0.
    if (!virtio_gpu.armBlobScanout(res_ids[0..n_blobs], virts[0..n_blobs], n_blobs)) {
        debug.klog("[gpu-comp] armBlobScanout FAILED\n", .{});
        return false;
    }

    // 8. Drop the original 2D scanout backing. Only safe AFTER
    //    armBlobScanout has flipped the active surface — otherwise the
    //    detach races against the host still presenting it.
    virtio_gpu.dropOriginal2DScanout();

    debug.klog("[gpu-comp] blob scanout armed: {d} blob(s), {d}x{d}\n", .{ n_blobs, w, h });
    return true;
}

/// Wrap COMPOSITOR_RENDER_MEM (the VkDeviceMemory bound to the render
/// image) as a HOST3D blob and arm it as the scanout. The render image
/// renders directly into this memory each frame; the host's
/// dpy_gl_scanout_dmabuf path imports it as a dma-buf for display.
///
/// This is the vulkan_cube pattern (image-backed memory as the blob),
/// chosen because dma-buf export of Venus-allocated memory works
/// reliably when the memory backs a VkImage but appears to fail
/// silently when it backs a VkBuffer (step 9 zerocopy used the buffer
/// path → black screen on Hyper-V/synthvid).
///
/// Single-buffer scanout — host reads while Vulkan writes → some
/// tearing. The May 8 working state had this exact characteristic.
/// Page-flip (n=2) would require two render images + per-frame
/// framebuffer ping-pong — left for a follow-up.
var render_scanout_res_id: u32 = 0;
fn renderImageAsScanout() bool {
    const w = virtio_gpu.width;
    const h = virtio_gpu.height;
    const fb_size_bytes: u64 = @as(u64, w) * h * 4;

    const res_id = virtio_gpu.alloc3DResourceId();
    if (!virtio_gpu.resourceCreateBlob(COMPOSITOR_CTX_ID, res_id, BLOB_MEM_HOST3D, 5, COMPOSITOR_RENDER_MEM, fb_size_bytes)) {
        debug.klog("[gpu-comp] renderImageAsScanout: resourceCreateBlob FAILED\n", .{});
        return false;
    }
    if (!virtio_gpu.ctxAttachResource(COMPOSITOR_CTX_ID, res_id)) {
        debug.klog("[gpu-comp] renderImageAsScanout: ctxAttachResource FAILED\n", .{});
        return false;
    }
    const phys = virtio_gpu.resourceMapBlob(res_id, @intCast(fb_size_bytes)) orelse {
        debug.klog("[gpu-comp] renderImageAsScanout: resourceMapBlob FAILED\n", .{});
        return false;
    };
    const kvirt: [*]volatile u32 = @ptrFromInt(paging.physToVirt(phys));

    var res_ids = [_]u32{ res_id, 0 };
    var virts = [_][*]volatile u32{ kvirt, undefined };
    if (!virtio_gpu.armBlobScanout(res_ids[0..1], virts[0..1], 1)) {
        debug.klog("[gpu-comp] renderImageAsScanout: armBlobScanout FAILED\n", .{});
        return false;
    }
    virtio_gpu.dropOriginal2DScanout();
    render_scanout_res_id = res_id;
    debug.klog("[gpu-comp] renderImageAsScanout: ok res={d} phys=0x{X}\n", .{ res_id, phys });
    return true;
}

var frame_counter: u64 = 0;

/// Per-frame Venus cmd_type → args length lookup. Only the cmd_types that
/// `renderVulkanFrame` actually emits are listed; any other cmd_type means
/// either the encoder wrote a wrong opcode, the parser drifted, or memory
/// got clobbered. Returns null on unknown cmd_type. For PushConstants
/// (variable length), reads the inline `size` field from `args_buf` and
/// adds the (4-aligned) data blob length.
fn perFrameCmdArgsLen(cmd_type: u32, args_buf: []const u8) ?usize {
    return switch (cmd_type) {
        18 => 92, // vkQueueSubmit (one VkSubmitInfo with 1 cmd_buf, no semas; + fence)
        37 => 28, // vkResetFences (one fence)
        39 => 40, // vkWaitForFences (one fence)
        90 => 40, // vkBeginCommandBuffer
        91 => 8, // vkEndCommandBuffer
        93 => 20, // vkCmdBindPipeline
        103 => 56, // vkCmdBindDescriptorSets (one set, no dynamic offsets)
        106 => 24, // vkCmdDraw
        116 => 96, // vkCmdCopyImageToBuffer (1 region: u64 cmd_buf+u64 src+u32 layout+u64 dst+u32 cnt+u64 arr+VkBufferImageCopy(56))
        126 => 120, // vkCmdPipelineBarrier (single image barrier, no mem/buf)
        132 => blk: {
            // PushConstants: u64 cmd_buf + u64 layout + u32 stage + u32 off
            // + u32 size + u64 array_size + blob(size, padded to 4).
            if (args_buf.len < 36) break :blk null;
            const size_at: usize = 8 + 8 + 4 + 4;
            const size_ptr: *align(1) const u32 = @ptrCast(args_buf.ptr + size_at);
            const size: u32 = size_ptr.*;
            const data_aligned: u32 = (size + 3) & ~@as(u32, 3);
            break :blk 36 + @as(usize, data_aligned);
        },
        133 => 108, // vkCmdBeginRenderPass (one clear color)
        135 => 8, // vkCmdEndRenderPass
        179 => 8, // vkSeekReplyCommandStreamMESA
        else => null,
    };
}

/// Walks the encoded cmd stream byte-by-byte, validating that every cmd
/// header has a recognized cmd_type and the args fit. Returns true on
/// success. On failure, klogs the offending cmd_type, the trace of all
/// previously-decoded cmds, and a hex dump around the fault site.
fn validatePerFrameStream(buf: []const u8) bool {
    var pos: usize = 0;
    var trace: [128]u32 = undefined;
    var trace_n: u32 = 0;

    while (pos < buf.len) {
        if (pos + 8 > buf.len) {
            debug.klog("[gpu-comp] CS validate FAIL frame={d}: truncated header at pos={d} buf.len={d}\n", .{ frame_counter, pos, buf.len });
            return false;
        }
        const ct_ptr: *align(1) const u32 = @ptrCast(buf.ptr + pos);
        const cmd_type: u32 = ct_ptr.*;
        const args_len = perFrameCmdArgsLen(cmd_type, buf[pos + 8 ..]) orelse {
            debug.klog("[gpu-comp] CS validate FAIL frame={d}: unknown cmd_type={d} at pos={d} (buf.len={d})\n", .{ frame_counter, cmd_type, pos, buf.len });
            debug.klog("[gpu-comp] trace ({d} cmds before fault):\n", .{trace_n});
            var ti: u32 = 0;
            while (ti < trace_n) : (ti += 1) {
                debug.klog("  [{d}] cmd_type={d}\n", .{ ti, trace[ti] });
            }
            const dump_start: usize = pos -| 32;
            const dump_end: usize = @min(pos + 64, buf.len);
            debug.klog("[gpu-comp] hex dump pos={d} (fault at +{d}):\n", .{ dump_start, pos - dump_start });
            var bi: usize = dump_start;
            while (bi < dump_end) : (bi += 16) {
                const lim: usize = @min(bi + 16, dump_end);
                debug.klog("  {x:0>4}: ", .{bi});
                var bj: usize = bi;
                while (bj < lim) : (bj += 1) {
                    debug.klog("{x:0>2} ", .{buf[bj]});
                }
                debug.klog("\n", .{});
            }
            return false;
        };
        if (pos + 8 + args_len > buf.len) {
            debug.klog("[gpu-comp] CS validate FAIL frame={d}: cmd_type={d} args_len={d} overruns at pos={d} buf.len={d}\n", .{ frame_counter, cmd_type, args_len, pos, buf.len });
            return false;
        }
        if (trace_n < trace.len) {
            trace[trace_n] = cmd_type;
            trace_n += 1;
        }
        pos += 8 + args_len;
    }
    return pos == buf.len;
}

/// Encode + submit one render frame: clear background, then fullscreen-
/// triangle draw with the procedural fragment shader (`shaders.frag_spv`).
/// Push constants drive the animation: float t + vec2 image_size = 16 B.
/// All commands batched into one cs.submit; one virtio-gpu round-trip
/// per frame.
fn renderVulkanFrame(_: f32) bool {
    // Pack 32-byte push constants: vec4 rect + vec4 uv_scale (only .xy used).
    const packPush = struct {
        fn p(out: *[32]u8, x: f32, y: f32, w: f32, h: f32, ux: f32, uy: f32) void {
            const vals = [_]f32{ x, y, w, h, ux, uy, 0.0, 0.0 };
            inline for (vals, 0..) |v, i| {
                const bits: u32 = @bitCast(v);
                @memcpy(out[i * 4 ..][0..4], @as(*const [4]u8, @ptrCast(&bits)));
            }
        }
    };

    var bg_push: [32]u8 = undefined;
    // Background image (backbuf) is allocated at exact screen size, so
    // uv_scale = (1, 1) — sample full image extent.
    packPush.p(&bg_push, 0.0, 0.0, @floatFromInt(RENDER_W), @floatFromInt(RENDER_H), 1.0, 1.0);
    // Phase 3: replaced the single-focused-overlay draw with a loop
    // over all visible windows that have a gpu_slot. The old
    // focused_rect_* and win_push are still computed in fillFocusedSource
    // but the latter early-returns since Phase 9.2.

    scratch_cs.reset();
    venus.encodeBeginCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
    venus.encodeCmdBeginRenderPassClear(
        &scratch_cs,
        COMPOSITOR_CMD_BUF,
        COMPOSITOR_RENDER_PASS,
        COMPOSITOR_FRAMEBUFFER,
        RENDER_W,
        RENDER_H,
        0.05,
        0.05,
        0.07,
        1.0,
    );
    venus.encodeCmdBindPipeline(&scratch_cs, COMPOSITOR_CMD_BUF, COMPOSITOR_PIPELINE);

    // Draw 1: background — desktop chrome layer (backbuf as one big
    // texture).  Window content rects in the backbuf are stale (Phase
    // 4 will skip the gui_fb→backbuf blit entirely); the per-window
    // draws below overlay the live pixels on top.
    venus.encodeCmdBindDescriptorSets(&scratch_cs, COMPOSITOR_CMD_BUF, COMPOSITOR_PIPELINE_LAYOUT, COMPOSITOR_DESC_SET);
    venus.encodeCmdPushConstants(&scratch_cs, COMPOSITOR_CMD_BUF, COMPOSITOR_PIPELINE_LAYOUT, 0x10, &bg_push);
    venus.encodeCmdDraw(&scratch_cs, COMPOSITOR_CMD_BUF, 3, 1);

    // Step 9.4 Phase 3: per-window draws. Each visible window with a
    // gpu_slot binds its own descriptor set + pushes its on-screen
    // rect (below the title bar — the chrome stays in the backbuf
    // layer). Fragment shader's bounds-test discards pixels outside
    // the rect.
    {
        const wm = @import("desktop/window.zig");
        const TITLEBAR_H: u32 = @import("desktop/layout.zig").TITLEBAR_H;
        const flags = wm.lockWindows();
        defer wm.unlockWindows(flags);
        var wi: u8 = 0;
        while (wi < wm.windows.len) : (wi += 1) {
            if (!wm.slot_used[wi]) continue;
            const w_ref = &wm.windows[wi];
            if (!w_ref.visible or w_ref.minimized) continue;
            const slot_idx = w_ref.gpu_slot orelse continue;
            if (slot_idx >= MAX_WINDOW_SLOTS) continue;
            const sl = &window_slots[slot_idx];
            if (!sl.in_use) continue;

            // Window rect on screen, content area only (skip title bar).
            const wx: f32 = @floatFromInt(w_ref.x);
            const wy: f32 = @floatFromInt(w_ref.y + @as(i32, @intCast(TITLEBAR_H)));
            const ww: f32 = @floatFromInt(w_ref.width);
            const wh: f32 = @floatFromInt(w_ref.height -| TITLEBAR_H);
            if (ww <= 0 or wh <= 0) continue;
            // uv_scale = (sl.width / sl.mem_w, sl.height / sl.mem_h). The
            // image is allocated at slot mem dims (full alloc area); only
            // the (sl.width × sl.height) drawn portion needs to be visible
            // in the on-screen rect, so we shrink the sampling uv accordingly.
            const ux: f32 = @as(f32, @floatFromInt(sl.width)) / @as(f32, @floatFromInt(sl.mem_w));
            const uy: f32 = @as(f32, @floatFromInt(sl.height)) / @as(f32, @floatFromInt(sl.mem_h));
            var per_win_push: [32]u8 = undefined;
            packPush.p(&per_win_push, wx, wy, ww, wh, ux, uy);

            venus.encodeCmdBindDescriptorSets(&scratch_cs, COMPOSITOR_CMD_BUF, COMPOSITOR_PIPELINE_LAYOUT, sl.desc_set_id);
            venus.encodeCmdPushConstants(&scratch_cs, COMPOSITOR_CMD_BUF, COMPOSITOR_PIPELINE_LAYOUT, 0x10, &per_win_push);
            venus.encodeCmdDraw(&scratch_cs, COMPOSITOR_CMD_BUF, 3, 1);
        }
    }

    venus.encodeCmdEndRenderPass(&scratch_cs, COMPOSITOR_CMD_BUF);
    // Step 9.1: render image -> readback buffer.
    // Transition COLOR_ATTACHMENT_OPTIMAL -> TRANSFER_SRC_OPTIMAL so the
    // copy can read it. srcStage=COLOR_ATTACHMENT_OUTPUT (0x400) flushes
    // the render writes; dstStage=TRANSFER (0x1000) gates the copy on
    // those writes.
    venus.encodeCmdPipelineBarrier(
        &scratch_cs,
        COMPOSITOR_CMD_BUF,
        COMPOSITOR_RENDER_IMAGE,
        2, // COLOR_ATTACHMENT_OPTIMAL
        venus.VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, // 6
        0x400, // srcStage = COLOR_ATTACHMENT_OUTPUT
        0x1000, // dstStage = TRANSFER
        0x100, // srcAccess = COLOR_ATTACHMENT_WRITE
        0x800, // dstAccess = TRANSFER_READ
    );
    // Step 9.3: copy into the BACK readback buffer (the one not currently
    // being scanned out). flushUnconditional flips after we finish.
    // virtio_gpu.blob_front is the index currently displayed; back = 1-front.
    const back_idx: u32 = if (readback_promoted_to_scanout) (1 - virtio_gpu.blob_front) else 0;
    venus.encodeCmdCopyImageToBuffer(
        &scratch_cs,
        COMPOSITOR_CMD_BUF,
        COMPOSITOR_RENDER_IMAGE,
        venus.VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        readback_buf_handles[back_idx],
        RENDER_W,
        RENDER_H,
    );
    venus.encodeEndCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
    venus.encodeResetFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE);
    venus.encodeQueueSubmitFence(&scratch_cs, COMPOSITOR_QUEUE, COMPOSITOR_CMD_BUF, COMPOSITOR_FENCE);
    venus.encodeSeekReplyCommandStream(&scratch_cs, 0);
    venus.encodeWaitForFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE, 1_000_000_000);
    if (reply_ring) |ring| {
        for (0..32) |i| ring[i] = 0;
    }
    frame_counter += 1;
    if (!validatePerFrameStream(scratch_cs.bytes())) {
        debug.klog("[gpu-comp] aborting before submit3D — see trace above. scratch_cs.pos={d}\n", .{scratch_cs.pos});
        // ud2 → #UD → idt #UD handler → kdbg autopsy (Ring 0 panic path).
        asm volatile ("ud2");
        unreachable;
    }
    return virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes());
}

pub fn taskEntry() callconv(.c) noreturn {
    // Same Phase-3 ritual as desktop.taskEntry: BSP is now on its high-VA
    // kernel task stack, drop the legacy low identity then re-enable IRQs.
    paging.dropLowIdentity();
    // BSP off the UEFI low-half boot stack — enable SMAP now (mirror of
    // desktop.taskEntry; boot_mode=9 takes this path instead).
    @import("../cpu/protect.zig").enableSmapPerCpu();
    asm volatile ("sti");
    run();
    asm volatile ("ud2");
    unreachable;
}

fn run() noreturn {
    @import("../cpu/smp.zig").assertBSP("gpu_compositor.run");
    debug.klog("[gpu-comp] entered as side task.\n", .{});

    // Publish our PID so requestRender() can wake us.
    compositor_pid = @intCast(process.getCurrentPid());

    // Co-op mode: the desktop is already running and owns the display.
    // We sample one of its windows' published gui_fb back-buffers as our
    // Vulkan source texture, render with shader effects, and blit the
    // result into a corner rect on top of the desktop's output.
    if (!virtio_gpu.active) {
        debug.klog("[gpu-comp] virtio-gpu not active; aborting.\n", .{});
        while (true) process.kernelSleepMs(1000);
    }
    const disp_w: u32 = virtio_gpu.width;
    const disp_h: u32 = virtio_gpu.height;
    screen_w_cache = disp_w;
    screen_h_cache = disp_h;
    debug.klog("[gpu-comp] sharing screen {d}x{d}\n", .{ disp_w, disp_h });

    // Step 8d (single-blob) is set up below after the Venus device is up
    // — Venus is required because we route around the QEMU 9.2 virgl
    // BLOB_MEM_GUEST bug by allocating a HOST3D blob via vkAllocateMemory
    // instead. Step 8e (double-buffer swap) lifts to n_blobs=2 once the
    // dirty-rect content-sync issue is solved.

    // Steps 3+4+5 — best-effort. Each step lights up the next gate;
    // any failure shorts the chain and the side-task just idles.
    if (setupVulkanContext()) {
        if (setupVulkanDevice()) {
            vulkan_device_ready = true;
            debug.klog("[gpu-comp] Vulkan device ready\n", .{});
            if (setupVulkanRender()) {
                vulkan_render_ready = true;
                debug.klog("[gpu-comp] Vulkan render path ready\n", .{});

                // Task A Phase 1: experimentally create a Venus command ring.
                // Doesn't replace any per-frame work yet — just verifies the
                // protocol round-trip works and gives us SHM-mapped head/tail/
                // status/buffer/extra regions to play with.
                _ = setupCommandRing();
                // Promote the readback HOST3D blob to scanout. After
                // this, vkCmdCopyImageToBuffer's destination IS the
                // host's display source: no kernel BAR→scanout memcpy,
                // and flushUnconditional skips TRANSFER_TO_HOST_2D.
                // The blob is real udmabuf (VKR_DEBUG=udmabuf forces
                // memfd→udmabuf for Venus exports), so the host's
                // dpy_gl_scanout_dmabuf path consumes it directly.
                // Promote the readback HOST3D blob pair to scanout.
                // vkCmdCopyImageToBuffer's destination IS the host's
                // display source — no kernel BAR→scanout memcpy needed
                // and flushUnconditional skips TRANSFER_TO_HOST_2D.
                //
                // Requires guest RAM backed by `-object memory-backend-memfd`
                // so virglrenderer can convert the Venus-allocated
                // VkDeviceMemory into a real udmabuf-fd (via
                // VKR_DEBUG=udmabuf). See run-uefi-ext2.sh.
                if (readback_res_ids[0] != 0 and readback_res_ids[1] != 0) {
                    if (readback_pixel_bufs[0]) |rb_a| {
                        if (readback_pixel_bufs[1]) |rb_b| {
                            var res_ids = [_]u32{ readback_res_ids[0], readback_res_ids[1] };
                            var virts = [_][*]volatile u32{
                                @as([*]volatile u32, @ptrCast(@alignCast(rb_a))),
                                @as([*]volatile u32, @ptrCast(@alignCast(rb_b))),
                            };
                            if (virtio_gpu.armBlobScanout(&res_ids, &virts, 2)) {
                                virtio_gpu.dropOriginal2DScanout();
                                readback_promoted_to_scanout = true;
                                debug.klog("[gpu-comp] scanout=readback HOST3D blob pair (tear-free page-flip)\n", .{});
                            } else {
                                debug.klog("[gpu-comp] armBlobScanout(readback x2) FAILED — keeping 2D fallback\n", .{});
                            }
                        }
                    }
                }

                // Step 9.4 Phase 2: real per-window slots get allocated
                // by sysCreateWindow when the compositor is ready. The
                // Phase-1 self-test that previously lived here has been
                // removed — slot 0 was held by it indefinitely, eating
                // capacity. Phase 3 will wire the rendering.
            } else {
                debug.klog("[gpu-comp] Vulkan render setup failed — idling\n", .{});
            }
        } else {
            debug.klog("[gpu-comp] Vulkan device setup failed — idling\n", .{});
        }
    } else {
        debug.klog("[gpu-comp] Vulkan context setup failed — idling\n", .{});
    }

    // Prime the wake counter so the very first frame goes through
    // (renders the initial scene before any external requestRender fires).
    _ = @atomicRmw(u32, &pending_wakes, .Add, 1, .seq_cst);

    var frame_no: u32 = 0;
    var fps_last_tick: u64 = 0;
    var fps_frames: u32 = 0;
    // Frame-interval histogram. Each bucket counts frames whose
    // interval (time since previous frame_start) fell in a given band.
    // Log-scale bands so we capture both sub-frame stutter (4ms) and
    // dropped frames (64+ms) in one printout.
    //   bucket 0: 0..4ms      (very fast, possibly back-to-back wakes)
    //   bucket 1: 4..8ms      (faster than 60Hz)
    //   bucket 2: 8..16ms     (60-125Hz range)
    //   bucket 3: 16..24ms    (~60Hz target band)
    //   bucket 4: 24..33ms    (30-45Hz, mild stutter)
    //   bucket 5: 33..50ms    (idle wake from kernelSleepMs(33))
    //   bucket 6: 50..100ms   (visible stutter)
    //   bucket 7: 100ms+      (frame drop)
    var interval_hist: [8]u32 = .{0} ** 8;
    var prev_frame_tsc: u64 = 0;
    while (true) : (frame_no += 1) {
        // Sleep until something asks for a frame. Idle desktop = ~30 Hz
        // wake-and-recheck, no work; active desktop = woken sub-ms by
        // requestRender(). The kernelSleepMs timer covers the rare
        // wake-vs-sleep race (kernelSleepMs sets state=.sleeping AFTER
        // we've checked the counter — if a wake fired in between, the
        // explicit process.wake() flipped state to .ready and we exit
        // immediately; if not, the 33 ms timer fires).
        while (@atomicLoad(u32, &pending_wakes, .seq_cst) == 0) {
            process.kernelSleepMs(33);
        }
        @atomicStore(u32, &pending_wakes, 0, .seq_cst);

        const perf = @import("../debug/perf.zig");
        // Frame-start timestamp + interval bucketing. Done AFTER the
        // sleep wait so the interval reflects "renderable frame to
        // renderable frame", which is what the user actually perceives.
        const apic = @import("../time/apic.zig");
        const frame_start_tsc = apic.readTsc();
        if (prev_frame_tsc != 0) {
            const interval_ms = apic.tscToMs(frame_start_tsc -% prev_frame_tsc);
            const bucket: usize = if (interval_ms < 4) 0
                else if (interval_ms < 8) 1
                else if (interval_ms < 16) 2
                else if (interval_ms < 24) 3
                else if (interval_ms < 33) 4
                else if (interval_ms < 50) 5
                else if (interval_ms < 100) 6
                else 7;
            interval_hist[bucket] +%= 1;
        }
        prev_frame_tsc = frame_start_tsc;

        if (vulkan_render_ready) {
            // 1. Sample-source fill — the fragment shader reads from
            //    `source_pixel_buf` (320×180 backbuf downsample). Step
            //    9.2 will replace this with a full-resolution source.
            {
                const t = perf.enter();
                defer perf.leave(.comp_fill_src, t);
                fillSourceFrame(frame_no);
            }
            // 2. Render fullscreen pass into the render image (Lavapipe
            //    writes to the imported anonymous-blob memory).
            const ok = blk: {
                const t = perf.enter();
                defer perf.leave(.comp_vk_render, t);
                break :blk renderVulkanFrame(@as(f32, @floatFromInt(frame_no)) / 30.0);
            };
            // 3. If the readback blob has been promoted to scanout, the
            //    vkCmdCopyImageToBuffer above already wrote into the
            //    host-visible dmabuf — flushUnconditional just sends
            //    RESOURCE_FLUSH and the host displays it. No kernel
            //    memcpy needed. Otherwise, fall back to the slow path
            //    (BAR memcpy + 2D TRANSFER_TO_HOST inside flushUnconditional).
            if (ok) {
                if (readback_promoted_to_scanout) {
                    @import("desktop/dirty.zig").reset();
                } else if (render_pixel_buf) |src_b| {
                    const t = perf.enter();
                    defer perf.leave(.comp_sync, t);
                    const u64_count: usize = (@as(usize, RENDER_W) * RENDER_H * 4) / 8;
                    asm volatile ("cld; rep movsq"
                        :
                        : [dst] "{rdi}" (@intFromPtr(virtio_gpu.framebuffer)),
                          [src] "{rsi}" (@intFromPtr(src_b)),
                          [cnt] "{rcx}" (u64_count),
                        : .{ .rdi = true, .rsi = true, .rcx = true, .memory = true }
                    );
                    @import("desktop/dirty.zig").reset();
                }
            }
        } else {
            // Vulkan render path not up — fall back to the legacy
            // dirty-rect blit so the screen still updates.
            const t = perf.enter();
            defer perf.leave(.comp_sync, t);
            _ = syncBackBufferToScreen();
        }

        // 4. ONE flush per frame. Wrapped in comp_flush so we can tell
        // whether host vblank actually back-pressures here (~16ms) or
        // returns instantly (instant return = tearing source — page
        // flip happens mid-display-refresh).
        if (virtio_gpu.active) {
            const t = perf.enter();
            defer perf.leave(.comp_flush, t);
            virtio_gpu.flushUnconditional();
        }

        fps_frames += 1;
        const now = process.tick_count;
        if (fps_last_tick == 0) fps_last_tick = now;
        if (now -% fps_last_tick >= 500) {
            const elapsed_ms: u64 = (now -% fps_last_tick) * 10;
            const fps = if (elapsed_ms > 0) (@as(u64, fps_frames) * 1000) / elapsed_ms else 0;
            debug.klog("[gpu-comp] frame {d}, ~{d} fps over {d} ms (vulkan={d}) | intervals <4ms={d} <8={d} <16={d} <24={d} <33={d} <50={d} <100={d} 100+={d}\n", .{
                frame_no, fps, elapsed_ms, @intFromBool(vulkan_render_ready),
                interval_hist[0], interval_hist[1], interval_hist[2], interval_hist[3],
                interval_hist[4], interval_hist[5], interval_hist[6], interval_hist[7],
            });
            fps_last_tick = now;
            fps_frames = 0;
            interval_hist = .{0} ** 8;
        }

        // No artificial sleep — flushUnconditional's RESOURCE_FLUSH
        // blocks on host vblank (~16ms at 60 Hz) so the loop is paced
        // by the display, not by us. Restore a sleep here if we ever
        // pin a CPU at 100% with no display attached.
    }
}
