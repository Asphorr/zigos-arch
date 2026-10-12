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
//
// Host GPUs: memory types come from the host's properties, and on a host
// that cannot sample LINEAR images the sources go through staging
// buffers (see `direct_sources`). A host that cannot export host-visible
// memory as dma-buf still maps it, and the scanout becomes a single
// mapped buffer flushed by damage rect (see `scanout_flip`).
//
// Frames are damage-limited: the desktop reports the rects it repainted,
// and a frame uploads, renders (a LOAD pass, one scissor per rect) and
// reads back only those. A full frame clears and redraws everything.
//
// Once the render path is up, the desktop draws straight into the
// background source (`bg_in_place`): the CPU never copies the backbuf.
// source_lock keeps its drawing and a frame's GPU reads apart.

const std = @import("std");
const debug = @import("../debug/debug.zig");
const pmm = @import("../mm/pmm.zig");
const gfx = @import("gfx.zig");
const paging = @import("../mm/paging.zig");
const process = @import("../proc/process.zig");
const virtio_gpu = @import("../driver/virtio_gpu.zig");
const Phys = @import("../util/addr.zig").Phys;
const Mutex = @import("../proc/spinlock.zig").Mutex;
const venus = @import("venus_kernel.zig");
const shaders = @import("gpu_compositor_shaders.zig");

// ── Venus / Vulkan setup state ──────────────────────────────────────────
//
// virtio-gpu context ID for the kernel-side compositor. User processes
// get IDs from a counter starting at 1 that skips this one
// (sysGpuCtxCreate).
pub const COMPOSITOR_CTX_ID: u32 = 0xC0;

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

// Serializes scratch_cs, the reply ring, COMPOSITOR_CMD_BUF/FENCE and
// every submit on the compositor context: the compositor task and
// sysCreateWindow (allocateWindowImage) both drive it. Held across the
// reply wait, so a submit's reply cannot be overwritten by another's.
var venus_lock: Mutex = .{};

// Checked submits: replies go to offset 0 (the stream seeks there first),
// then a vkEnumerateInstanceVersion marker replies in a slot of its own
// past REPLY_MARKER_BASE. The host writes replies after submit3D returns,
// so the slot is pre-filled with REPLY_SENTINEL and polled. A reply's
// cmd_type lands before its body; the marker's arrival is what proves the
// reply before it complete (the host executes streams in order). Rotating
// the slot keeps a submit we gave up on (timeout, or its task killed
// mid-wait) from passing its late marker off as a later submit's.
const REPLY_SENTINEL: u32 = 0xFFFF_FFFF;
const REPLY_MARKER_BASE: usize = 1024; // past the largest reply (memory properties, ~0.5 KB)
const REPLY_MARKER_STRIDE: usize = 32;
const REPLY_MARKER_SLOTS: usize = (REPLY_RING_SIZE - REPLY_MARKER_BASE) / REPLY_MARKER_STRIDE;
var reply_marker_seq: usize = 0;
var reply_marker_off: usize = REPLY_MARKER_BASE;
// Generous: a nested host (zigvm) can be paused by the outer hypervisor for
// most of a second at a time, and the guest clock counts that. Timing out
// is fatal for the GPU path, so only a host that stopped answering should.
const REPLY_TIMEOUT_MS: u64 = 30_000;
const FRAME_TIMEOUT_MS: u64 = 30_000;
// Host-side vkWaitForFences bound, same reasoning.
const FENCE_TIMEOUT_NS: u64 = 10_000_000_000;

fn beginChecked() void {
    scratch_cs.reset();
    venus.encodeSeekReplyCommandStream(&scratch_cs, 0);
}

/// Make the command encoded at scratch_cs offset `at` generate a reply.
fn markReply(at: usize) void {
    const flags: *align(1) u32 = @ptrCast(scratch_cs.buf[at + 4 ..][0..4]);
    flags.* = venus.CMD_FLAG_GENERATE_REPLY;
}

fn appendReplyMarker() void {
    reply_marker_seq +%= 1;
    reply_marker_off = REPLY_MARKER_BASE + (reply_marker_seq % REPLY_MARKER_SLOTS) * REPLY_MARKER_STRIDE;
    venus.encodeSeekReplyCommandStream(&scratch_cs, reply_marker_off);
    venus.encodeEnumerateInstanceVersion(&scratch_cs);
}

const SubmitResult = enum {
    replied,
    /// The stream was not handed to the host (or its acceptance was lost).
    not_sent,
    /// Sent, but the marker never came back: the host may still be on it.
    no_reply,
};

/// Submit scratch_cs (marker already appended) and wait for the marker.
fn submitChecked(timeout_ms: u64) SubmitResult {
    const ring = reply_ring orelse return .not_sent;
    if (scratch_cs.overflowed) {
        debug.klog("[gpu-comp] command stream overflowed ({d} B)\n", .{scratch_cs.pos});
        return .not_sent;
    }
    for (0..64) |i| ring[i] = 0xFF;
    for (0..4) |i| ring[reply_marker_off + i] = 0xFF;
    if (!virtio_gpu.submit3D(COMPOSITOR_CTX_ID, scratch_cs.bytes())) return .not_sent;
    const apic = @import("../time/apic.zig");
    const start = apic.readTsc();
    while (venus.readReplyCmdType(ring + reply_marker_off) == REPLY_SENTINEL) {
        const waited = apic.tscToMs(apic.readTsc() -% start);
        if (waited >= timeout_ms) return .no_reply;
        // Most waits end within a few yields; longer ones sleep so the
        // CPU can idle.
        if (waited < 2) @import("../proc/sched_asm.zig").softYield() else process.kernelSleepMs(1);
    }
    const waited = apic.tscToMs(apic.readTsc() -% start);
    if (waited >= 500) debug.klog("[gpu-comp] slow host reply: {d} ms\n", .{waited});
    return .replied;
}

/// Finish a beginChecked stream whose last reply-generating command is
/// `cmd`: submit, wait, and confirm that command's reply is at offset 0.
fn endChecked(name: []const u8, cmd: u32) bool {
    appendReplyMarker();
    const sent = submitChecked(REPLY_TIMEOUT_MS);
    if (sent != .replied) {
        debug.klog("[gpu-comp] {s}: {s}\n", .{ name, if (sent == .not_sent) "submit failed" else "no reply" });
        return false;
    }
    const got = venus.readReplyCmdType(reply_ring.?);
    if (got != cmd) {
        debug.klog("[gpu-comp] {s}: reply cmd_type={d}, expected {d}\n", .{ name, got, cmd });
        return false;
    }
    return true;
}

/// endChecked for commands returning a VkResult; true only on VK_SUCCESS.
fn endCheckedResult(name: []const u8, cmd: u32) bool {
    if (!endChecked(name, cmd)) return false;
    const r = venus.readReplyResult(reply_ring.?);
    if (r != 0) {
        debug.klog("[gpu-comp] {s}: VkResult={d}\n", .{ name, r });
        return false;
    }
    return true;
}

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
// Same attachment as COMPOSITOR_RENDER_PASS (so the framebuffer and the
// pipeline serve both) but it loads the previous frame instead of clearing.
const COMPOSITOR_RENDER_PASS_LOAD: u64 = 319;
// Step 8c-5: per-window source image (focused window only for now,
// scaled to N when this proves out). Same descriptor layout as the
// background, allocated from the same pool.
const COMPOSITOR_FOCUSED_IMAGE: u64 = 320;
const COMPOSITOR_FOCUSED_MEM: u64 = 321;
const COMPOSITOR_FOCUSED_VIEW: u64 = 322;
const COMPOSITOR_FOCUSED_DESC_SET: u64 = 323;
// Staging buffers for the two sources when !direct_sources.
const COMPOSITOR_SOURCE_STAGING: u64 = 324;
const COMPOSITOR_SOURCE_STAGING_MEM: u64 = 325;
const COMPOSITOR_FOCUSED_STAGING: u64 = 326;
const COMPOSITOR_FOCUSED_STAGING_MEM: u64 = 327;
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
// gets its own source texture (see Texture) whose CPU side is a HOST3D
// blob mapped through the SHM BAR — the gui_fb the app writes — and
// which the Venus context samples. Each allocation takes the next
// WINDOW_SLOT_STRIDE ids from WINDOW_SLOT_ID_BASE: the texture's five
// (image, view, mem, staging buffer, staging mem), then the descriptor
// set. Clear of COMPOSITOR_RING (500).
const WINDOW_SLOT_ID_BASE: u64 = 1000;
const WINDOW_SLOT_STRIDE: u64 = 8;
var next_window_ids: u64 = WINDOW_SLOT_ID_BASE;
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
// Readback buffers in use: 2 when the host scans them out as dma-bufs
// (it samples the front one asynchronously, so frames flip), 1 when it
// only maps them — the host then copies the flushed rect during
// RESOURCE_FLUSH itself, so one buffer is tear-free and only damage
// needs copying.
var readback_count: u32 = 0;
var scanout_flip: bool = false;

// Host memory types (vkGetPhysicalDeviceMemoryProperties).
var mem_props: venus.MemoryProperties = .{};
const HOST_MAPPED: u32 = venus.VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | venus.VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;

// Source textures — everything the fragment shader samples is written by
// the CPU. When the host samples LINEAR images (Lavapipe) the CPU writes
// straight into the image's memory. When it cannot (a host GPU: dzn keeps
// LINEAR images transfer-only), the CPU writes a host-visible staging
// buffer and each frame the GPU copies what changed into an OPTIMAL
// device-local image — the only copy left is the GPU's own upload.
var direct_sources: bool = true;

const TextureIds = struct {
    image: u64 = 0,
    view: u64 = 0,
    mem: u64 = 0,
    staging_buf: u64 = 0,
    staging_mem: u64 = 0,
};

const Texture = struct {
    ids: TextureIds = .{},
    w: u32 = 0,
    h: u32 = 0,
    /// Row stride in pixels of the CPU-visible side.
    row_pixels: u32 = 0,
    res_id: u32 = 0,
    kptr: ?[*]volatile u8 = null,
    phys: Phys = Phys.of(0),
    /// Size of the CPU-visible mapping.
    bytes: u64 = 0,
};

var source_tex: Texture = .{};
var focused_tex: Texture = .{};

// Per-window image slots (Step 9.4). Each visible GUI window gets one;
// the slot owns a source texture + descriptor set. The kernel pointer is
// what apps see as their gui_fb (writes go through the SHM BAR,
// EPT-direct).
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
    phys: Phys = Phys.of(0),         // SHM-BAR phys for user-space mapping
    mem_bytes: u64 = 0,              // total allocation size (page-rounded)
    tex_ids: TextureIds = .{},       // for the per-frame upload (!direct_sources)
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

// Event-driven wake plumbing. The compositor parks in parkUntilRender, and
// damage sources call `requestRender()` to bump pending_wakes and wake the
// kernel task.
pub var compositor_pid: u8 = 0xFF;
var pending_wakes: u32 = 0;

// The desktop's backbuf, the background source and the pending damage
// belong to whoever holds source_lock: the desktop for one loop iteration
// (beginDraw/endDraw), a frame until the GPU has read them. Taken before
// venus_lock.
var source_lock: Mutex = .{};
// The desktop draws straight into the background source's CPU side, so a
// frame uploads (or samples) the backbuf in place instead of copying it.
var bg_in_place: bool = false;
// The background source, offered to the desktop as its backbuf once the
// render path is up (see takeOfferedBackBuffer).
var offered_backbuf: ?[*]volatile u32 = null;

/// Mode 9: called by the desktop before it touches the backbuf in a loop
/// iteration. True if it now holds source_lock (release with endDraw).
pub fn beginDraw() bool {
    if (@atomicLoad(u8, &compositor_pid, .acquire) == 0xFF) return false;
    source_lock.acquire();
    return true;
}

pub fn endDraw() void {
    source_lock.release();
}

/// The memory the desktop should draw into from now on, once; null if it
/// keeps its own backbuf. Caller holds source_lock and calls
/// backBufferAdopted after switching.
pub fn takeOfferedBackBuffer() ?[*]volatile u32 {
    const p = offered_backbuf orelse return null;
    offered_backbuf = null;
    return p;
}

pub fn backBufferAdopted() void {
    bg_in_place = true;
    requestRender();
}

/// Liveness backstop for the compositor's park: a frame request that
/// somehow bypasses requestRender's wake is honored within this many
/// ticks. Longer than the BSP's 10-quanta idle stretch, so an idle
/// desktop never has the compositor as its tickless clamp.
pub const PARK_BACKSTOP_TICKS: u64 = 100;

/// Block the compositor task until requestRender wakes it or the backstop
/// expires. Same shape as desktop.parkOrYield: wake_tick stored, deadline
/// registered, then blockOn (whose wake_pending handshake catches a wake
/// that raced the caller's pending_wakes check); wake_tick cleared after
/// so a stale one-shot can't trip the orphan-sleep diagnostics later.
fn parkUntilRender() void {
    const me: usize = process.getCurrentPid();
    const pcb = &process.procs[me];
    const deadline = process.tick_count + PARK_BACKSTOP_TICKS;
    @atomicStore(u64, &pcb.wake_tick, deadline, .release);
    @import("../proc/sched.zig").registerWakeDeadline(deadline);
    process.blockOn(.compositor, 0);
    @atomicStore(u64, &pcb.wake_tick, 0, .release);
}

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

/// This frame's damage, taken from the pending state at frame start:
/// either the whole screen or rects clipped to the source/render size.
/// `bg` is what changed in the desktop backbuf; `out` is what changed on
/// screen — `bg` plus every visible GPU-slot window, whose apps write
/// their pixels without reporting damage.
const Damage = struct {
    full: bool = true,
    bg_count: u8 = 0,
    bg: [MAX_PENDING_RECTS][4]u32 = undefined,
    out_count: u8 = 0,
    out: [MAX_PENDING_RECTS + MAX_WINDOW_SLOTS][4]u32 = undefined,

    fn addOut(self: *Damage, x: i32, y: i32, w: u32, h: u32) void {
        if (self.full) return;
        if (self.out_count == self.out.len) {
            self.full = true;
            return;
        }
        const x0: u32 = @intCast(std.math.clamp(x, 0, @as(i32, RENDER_W)));
        const y0: u32 = @intCast(std.math.clamp(y, 0, @as(i32, RENDER_H)));
        const x1: u32 = @intCast(std.math.clamp(@as(i64, x) + w, 0, RENDER_W));
        const y1: u32 = @intCast(std.math.clamp(@as(i64, y) + h, 0, RENDER_H));
        if (x1 <= x0 or y1 <= y0) return;
        self.out[self.out_count] = .{ x0, y0, x1 - x0, y1 - y0 };
        self.out_count += 1;
    }
};
var frame_damage: Damage = .{};
const FULL_SCREEN = [_][4]u32{.{ 0, 0, RENDER_W, RENDER_H }};
/// Draw calls (damage rects × layers) a frame may scissor one by one; ~200
/// bytes of command stream each.
const MAX_SCISSORED_DRAWS: usize = 24;

fn takeDamage() void {
    frame_damage.bg_count = 0;
    frame_damage.out_count = 0;
    frame_damage.full = pending_full or pending_rect_count == 0;
    if (!frame_damage.full) {
        const n = @min(pending_rect_count, MAX_PENDING_RECTS);
        var i: u8 = 0;
        while (i < n) : (i += 1) {
            const r = pending_rects[i];
            if (r[0] >= RENDER_W or r[1] >= RENDER_H) continue;
            const w = @min(r[2], RENDER_W - r[0]);
            const h = @min(r[3], RENDER_H - r[1]);
            if (w == 0 or h == 0) continue;
            frame_damage.bg[frame_damage.bg_count] = .{ r[0], r[1], w, h };
            frame_damage.bg_count += 1;
            frame_damage.out[frame_damage.out_count] = .{ r[0], r[1], w, h };
            frame_damage.out_count += 1;
        }
        if (frame_damage.bg_count == 0) frame_damage.full = true;
    }
    pending_full = false;
    pending_rect_count = 0;
    if (frame_damage.full) return;

    // GPU-slot windows: their content area is drawn from the slot image.
    // A window that moves before the draw is clipped to this frame's
    // render area; the desktop's repaint of the move brings the next frame.
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
        if (slot_idx >= MAX_WINDOW_SLOTS or !window_slots[slot_idx].in_use) continue;
        frame_damage.addOut(w_ref.x, w_ref.y + @as(i32, @intCast(TITLEBAR_H)), w_ref.width, w_ref.height -| TITLEBAR_H);
    }
}

/// Backbuf rects to upload this frame.
fn bgDamage() []const [4]u32 {
    return if (frame_damage.full) &FULL_SCREEN else frame_damage.bg[0..frame_damage.bg_count];
}

/// Screen rects to read back and present this frame.
fn outDamage() []const [4]u32 {
    return if (frame_damage.full) &FULL_SCREEN else frame_damage.out[0..frame_damage.out_count];
}

/// Bounding box {x, y, w, h} of outDamage().
fn damageBounds() [4]u32 {
    var x0: u32 = RENDER_W;
    var y0: u32 = RENDER_H;
    var x1: u32 = 0;
    var y1: u32 = 0;
    for (outDamage()) |r| {
        x0 = @min(x0, r[0]);
        y0 = @min(y0, r[1]);
        x1 = @max(x1, r[0] + r[2]);
        y1 = @max(y1, r[1] + r[3]);
    }
    if (x1 <= x0 or y1 <= y0) return FULL_SCREEN[0];
    return .{ x0, y0, x1 - x0, y1 - y0 };
}

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
    // Nothing changed on screen. Waking anyway would cost a full frame:
    // a wake with no rects pending reads as "everything".
    if (!dirty.isFull()) {
        const n = dirty.rectCount(); // can flip to full on cap overflow
        if (n == 0 and !dirty.isFull()) return;
    }
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
    const reply_buf: [*]volatile u8 = @ptrFromInt(reply_phys.toVirt().raw());
    for (0..REPLY_RING_SIZE) |i| reply_buf[i] = 0;
    reply_ring = reply_buf;
    debug.klog("[gpu-comp] reply ring res_id={d} phys=0x{X} size={d}\n", .{ reply_ring_res_id, reply_phys.raw(), REPLY_RING_SIZE });

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

/// Bring up Vulkan: Instance, PhysicalDevice, Device, Queue, plus the
/// host's memory types and whether it samples LINEAR images. Each step
/// waits for its reply and klogs a failure.
fn setupVulkanDevice() bool {
    const ring = reply_ring orelse return false;

    beginChecked();
    venus.encodeCreateInstance(&scratch_cs, COMPOSITOR_INSTANCE);
    if (!endCheckedResult("vkCreateInstance", venus.CMD_vkCreateInstance)) return false;
    debug.klog("[gpu-comp] vkCreateInstance ok handle={d}\n", .{COMPOSITOR_INSTANCE});

    // We take the first physical device (Lavapipe, or the host GPU).
    beginChecked();
    venus.encodeEnumeratePhysicalDevices(&scratch_cs, COMPOSITOR_INSTANCE, COMPOSITOR_PHYS_DEV);
    if (!endCheckedResult("vkEnumeratePhysicalDevices", venus.CMD_vkEnumeratePhysicalDevices)) return false;
    debug.klog("[gpu-comp] vkEnumeratePhysicalDevices ok phys={d}\n", .{COMPOSITOR_PHYS_DEV});

    beginChecked();
    venus.encodeGetPhysicalDeviceMemoryProperties(&scratch_cs, COMPOSITOR_PHYS_DEV);
    if (!endChecked("vkGetPhysicalDeviceMemoryProperties", venus.CMD_vkGetPhysicalDeviceMemoryProperties)) return false;
    mem_props = venus.decodeMemoryPropertiesReply(ring) orelse {
        debug.klog("[gpu-comp] memory properties: malformed reply\n", .{});
        return false;
    };
    var ti: u32 = 0;
    while (ti < mem_props.type_count) : (ti += 1) {
        debug.klog("[gpu-comp] memory type {d}: flags=0x{X}\n", .{ ti, mem_props.type_flags[ti] });
    }

    beginChecked();
    venus.encodeGetPhysicalDeviceFormatProperties(&scratch_cs, COMPOSITOR_PHYS_DEV, venus.VK_FORMAT_B8G8R8A8_UNORM);
    if (!endChecked("vkGetPhysicalDeviceFormatProperties", venus.CMD_vkGetPhysicalDeviceFormatProperties)) return false;
    const fmt = venus.decodeFormatPropertiesReply(ring) orelse {
        debug.klog("[gpu-comp] format properties: malformed reply\n", .{});
        return false;
    };
    direct_sources = fmt.linear & venus.VK_FORMAT_FEATURE_SAMPLED_IMAGE_BIT != 0;

    // Queue family 0, single queue. dma-buf export when the host has it;
    // without it the host still maps host-visible memory for blobs.
    beginChecked();
    venus.encodeCreateDevice(&scratch_cs, COMPOSITOR_PHYS_DEV, 0, COMPOSITOR_DEVICE, true);
    if (!endCheckedResult("vkCreateDevice(dma-buf)", venus.CMD_vkCreateDevice)) {
        venus.export_handle_types = 0;
        beginChecked();
        venus.encodeCreateDevice(&scratch_cs, COMPOSITOR_PHYS_DEV, 0, COMPOSITOR_DEVICE, false);
        if (!endCheckedResult("vkCreateDevice", venus.CMD_vkCreateDevice)) return false;
    }
    debug.klog("[gpu-comp] vkCreateDevice ok device={d} dma-buf={} sources={s}\n", .{
        COMPOSITOR_DEVICE,
        venus.export_handle_types != 0,
        if (direct_sources) "direct (LINEAR sampled)" else "staged (GPU upload)",
    });

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
    if (bg_in_place) return;
    const buf = source_pixel_buf orelse return;
    const dst: [*]volatile u32 = @ptrCast(@alignCast(buf));

    const desktop = @import("desktop.zig");
    const bb = desktop.getBackBuffer() orelse {
        frame_damage.full = true;
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
        if (frame_damage.full) {
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
            for (bgDamage()) |r| {
                const rx = r[0];
                const ry = r[1];
                const rw = r[2];
                const rh = r[3];
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
        return;
    }

    // Scaled: every source pixel changes, so the frame is fully damaged.
    frame_damage.full = true;
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

/// Submit a Venus command that doesn't generate a reply.
fn submitFireAndForget(cs: *venus.CmdStream) bool {
    if (cs.overflowed) return false;
    return virtio_gpu.submit3D(COMPOSITOR_CTX_ID, cs.bytes());
}

fn pageAlign(n: u64) u64 {
    return (n + 4095) & ~@as(u64, 4095);
}

fn imageRequirements(image: u64, name: []const u8) ?venus.MemoryRequirements {
    beginChecked();
    venus.encodeGetImageMemoryRequirements(&scratch_cs, COMPOSITOR_DEVICE, image);
    if (!endChecked(name, venus.CMD_vkGetImageMemoryRequirements)) return null;
    return venus.decodeMemoryRequirementsReply(reply_ring.?);
}

fn bufferRequirements(buffer: u64, name: []const u8) ?venus.MemoryRequirements {
    beginChecked();
    venus.encodeGetBufferMemoryRequirements(&scratch_cs, COMPOSITOR_DEVICE, buffer);
    if (!endChecked(name, venus.CMD_vkGetBufferMemoryRequirements)) return null;
    return venus.decodeMemoryRequirementsReply(reply_ring.?);
}

/// vkAllocateMemory of `size` bytes from a type in `req.type_bits` with
/// the `required` flags, preferring `wanted` and avoiding `unwanted`.
fn allocateMemory(mem_id: u64, size: u64, req: venus.MemoryRequirements, required: u32, wanted: u32, unwanted: u32, name: []const u8) bool {
    const mem_type = mem_props.pick(req.type_bits, required, wanted, unwanted) orelse {
        debug.klog("[gpu-comp] {s}: no memory type in 0x{X} with flags 0x{X}\n", .{ name, req.type_bits, required });
        return false;
    };
    beginChecked();
    const at = scratch_cs.pos;
    venus.encodeAllocateMemoryExportable(&scratch_cs, COMPOSITOR_DEVICE, size, mem_type, mem_id);
    markReply(at);
    if (!endCheckedResult(name, venus.CMD_vkAllocateMemory)) return false;
    debug.klog("[gpu-comp] {s}: {d} B from memory type {d}\n", .{ name, size, mem_type });
    return true;
}

const MappedBlob = struct { res_id: u32, phys: Phys, kind: virtio_gpu.MemoryBlob };

/// Expose VkDeviceMemory `mem_id` as a HOST3D blob mapped in the SHM BAR.
fn mapMemoryBlob(mem_id: u64, size: u64, name: []const u8) ?MappedBlob {
    const res_id = virtio_gpu.alloc3DResourceId();
    // Without dma-buf export on the device the host can only map it.
    const try_dma_buf = venus.export_handle_types != 0;
    const kind = virtio_gpu.resourceCreateMemoryBlob(COMPOSITOR_CTX_ID, res_id, BLOB_MEM_HOST3D, mem_id, size, try_dma_buf) orelse {
        debug.klog("[gpu-comp] {s}: resourceCreateBlob FAILED\n", .{name});
        return null;
    };
    if (!virtio_gpu.ctxAttachResource(COMPOSITOR_CTX_ID, res_id)) {
        debug.klog("[gpu-comp] {s}: ctxAttachResource FAILED\n", .{name});
        return null;
    }
    const phys = virtio_gpu.resourceMapBlob(res_id, @intCast(size)) orelse {
        debug.klog("[gpu-comp] {s}: resourceMapBlob FAILED\n", .{name});
        return null;
    };
    return .{ .res_id = res_id, .phys = phys, .kind = kind };
}

/// One-shot submit on COMPOSITOR_CMD_BUF: UNDEFINED → GENERAL for a source
/// image, made visible to whoever writes it (the host CPU when sampled in
/// place, the GPU's upload copy otherwise) and to the fragment shader.
fn transitionSourceImage(image: u64, name: []const u8) bool {
    const HOST: u32 = 0x4000; // stage and access (HOST_WRITE) share the bit
    const TRANSFER: u32 = 0x1000; // stage and access (TRANSFER_WRITE) share the bit
    const FRAGMENT_SHADER: u32 = 0x80;
    const SHADER_READ: u32 = 0x20;
    beginChecked();
    venus.encodeBeginCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
    venus.encodeCmdPipelineBarrier(
        &scratch_cs,
        COMPOSITOR_CMD_BUF,
        image,
        0, // UNDEFINED
        1, // GENERAL
        0x1, // srcStage = TOP_OF_PIPE
        if (direct_sources) HOST else TRANSFER | FRAGMENT_SHADER,
        0,
        if (direct_sources) HOST else TRANSFER | SHADER_READ,
    );
    venus.encodeEndCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
    venus.encodeResetFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE);
    venus.encodeQueueSubmitFence(&scratch_cs, COMPOSITOR_QUEUE, COMPOSITOR_CMD_BUF, COMPOSITOR_FENCE);
    venus.encodeSeekReplyCommandStream(&scratch_cs, 0);
    venus.encodeWaitForFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE, FENCE_TIMEOUT_NS);
    return endCheckedResult(name, venus.CMD_vkWaitForFences);
}

/// Create a w×h B8G8R8A8 source texture with its view, CPU-visible side
/// mapped in the SHM BAR, and layout GENERAL. See `direct_sources`.
/// `cpu_reads`: the CPU also reads that side back (the desktop's backbuf).
fn createTexture(ids: TextureIds, w: u32, h: u32, cpu_reads: bool, name: []const u8) ?Texture {
    const cpu_bytes = pageAlign(@as(u64, w) * h * 4);
    const fmt = venus.VK_FORMAT_B8G8R8A8_UNORM;

    scratch_cs.reset();
    if (direct_sources) {
        venus.encodeCreateImageSampledLinear(&scratch_cs, COMPOSITOR_DEVICE, w, h, fmt, ids.image);
    } else {
        venus.encodeCreateImageExportable(&scratch_cs, COMPOSITOR_DEVICE, w, h, fmt, venus.VK_IMAGE_USAGE_SAMPLED_BIT | venus.VK_IMAGE_USAGE_TRANSFER_DST_BIT, ids.image);
    }
    if (!submitFireAndForget(&scratch_cs)) return null;
    const image_req = imageRequirements(ids.image, name) orelse return null;

    var mapped_mem = ids.mem;
    var mapped_bytes: u64 = undefined;
    if (direct_sources) {
        // The CPU writes rows of `w` texels into the image memory itself
        // (Lavapipe's LINEAR row pitch for 16-aligned widths).
        mapped_bytes = @max(pageAlign(image_req.size), cpu_bytes);
        if (!allocateMemory(ids.mem, mapped_bytes, image_req, HOST_MAPPED, 0, 0, name)) return null;
    } else {
        if (!allocateMemory(ids.mem, image_req.size, image_req, 0, venus.VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, 0, name)) return null;
        scratch_cs.reset();
        venus.encodeCreateBufferExportable(&scratch_cs, COMPOSITOR_DEVICE, cpu_bytes, venus.VK_BUFFER_USAGE_TRANSFER_SRC_BIT, ids.staging_buf);
        if (!submitFireAndForget(&scratch_cs)) return null;
        const staging_req = bufferRequirements(ids.staging_buf, name) orelse return null;
        // CPU writes, GPU reads once: uncached (write-combined) when
        // offered, unless the CPU reads it too.
        mapped_bytes = @max(pageAlign(staging_req.size), cpu_bytes);
        const cached = venus.VK_MEMORY_PROPERTY_HOST_CACHED_BIT;
        if (!allocateMemory(ids.staging_mem, mapped_bytes, staging_req, HOST_MAPPED, if (cpu_reads) cached else 0, if (cpu_reads) 0 else cached, name)) return null;
        mapped_mem = ids.staging_mem;
    }

    scratch_cs.reset();
    venus.encodeBindImageMemory(&scratch_cs, COMPOSITOR_DEVICE, ids.image, ids.mem, 0);
    if (!direct_sources) venus.encodeBindBufferMemory(&scratch_cs, COMPOSITOR_DEVICE, ids.staging_buf, ids.staging_mem, 0);
    venus.encodeCreateImageView(&scratch_cs, COMPOSITOR_DEVICE, ids.image, fmt, venus.VK_IMAGE_ASPECT_COLOR_BIT, ids.view);
    if (!submitFireAndForget(&scratch_cs)) return null;

    const blob = mapMemoryBlob(mapped_mem, mapped_bytes, name) orelse return null;
    if (!transitionSourceImage(ids.image, name)) return null;
    return .{
        .ids = ids,
        .w = w,
        .h = h,
        .row_pixels = w,
        .res_id = blob.res_id,
        .kptr = @ptrFromInt(blob.phys.toVirt().raw()),
        .phys = blob.phys,
        .bytes = mapped_bytes,
    };
}

/// Allocate descriptor set `set_id` and point it at `view`.
fn createDescriptorSet(set_id: u64, view: u64, name: []const u8) bool {
    beginChecked();
    venus.encodeAllocateDescriptorSet(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_DESC_POOL, COMPOSITOR_DESC_SET_LAYOUT, set_id);
    if (!endCheckedResult(name, venus.CMD_vkAllocateDescriptorSets)) return false;
    scratch_cs.reset();
    venus.encodeUpdateDescriptorSetSampler(&scratch_cs, COMPOSITOR_DEVICE, set_id, COMPOSITOR_SAMPLER, view, 1); // GENERAL
    return submitFireAndForget(&scratch_cs);
}

/// Record the staging → image upload of `rects` (no-op for direct sources).
fn recordUpload(ids: TextureIds, row_pixels: u32, rects: []const [4]u32) void {
    if (direct_sources or rects.len == 0) return;
    venus.encodeCmdCopyBufferToImageRects(&scratch_cs, COMPOSITOR_CMD_BUF, ids.staging_buf, ids.image, 1, row_pixels, rects);
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
    const kvirt: [*]volatile u8 = @ptrFromInt(phys.toVirt().raw());
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
    debug.klog("[gpu-comp] ring: created (res={d} phys=0x{X} total={d} buf={d}) — Phase 1 ok\n", .{ res_id, phys.raw(), RING_TOTAL_SIZE, RING_BUFFER_SIZE });

    // Sanity: read back head/tail/status (should all be 0).
    const head_ptr: *align(1) const volatile u32 = @ptrCast(kvirt + RING_HEAD_OFFSET);
    const tail_ptr: *align(1) const volatile u32 = @ptrCast(kvirt + RING_TAIL_OFFSET);
    const status_ptr: *align(1) const volatile u32 = @ptrCast(kvirt + RING_STATUS_OFFSET);
    debug.klog("[gpu-comp] ring: post-create head={d} tail={d} status=0x{X}\n", .{ head_ptr.*, tail_ptr.*, status_ptr.* });

    return true;
}

/// Read-back buffer `i`: a TRANSFER_DST VkBuffer the render image is
/// copied into, its memory exposed as a mapped blob. Returns how the host
/// backs the blob.
fn setupReadback(i: usize) ?virtio_gpu.MemoryBlob {
    const buf = readback_buf_handles[i];
    const mem = readback_mem_handles[i];
    scratch_cs.reset();
    venus.encodeCreateBufferExportable(&scratch_cs, COMPOSITOR_DEVICE, RENDER_PX_BYTES, venus.VK_BUFFER_USAGE_TRANSFER_DST_BIT, buf);
    if (!submitFireAndForget(&scratch_cs)) return null;
    const req = bufferRequirements(buf, "readback") orelse return null;
    const bytes = @max(pageAlign(req.size), pageAlign(RENDER_PX_BYTES));
    // The host display reads these with the CPU: cached memory when offered.
    if (!allocateMemory(mem, bytes, req, HOST_MAPPED, venus.VK_MEMORY_PROPERTY_HOST_CACHED_BIT, 0, "readback")) return null;
    scratch_cs.reset();
    venus.encodeBindBufferMemory(&scratch_cs, COMPOSITOR_DEVICE, buf, mem, 0);
    if (!submitFireAndForget(&scratch_cs)) return null;
    const blob = mapMemoryBlob(mem, bytes, "readback") orelse return null;
    readback_res_ids[i] = blob.res_id;
    readback_pixel_bufs[i] = @ptrFromInt(blob.phys.toVirt().raw());
    debug.klog("[gpu-comp] readback[{d}] res={d} phys=0x{X} ({s})\n", .{ i, blob.res_id, blob.phys.raw(), @tagName(blob.kind) });

    // memoryTypeBits says which host memory types can import the dma-buf;
    // zero would mean the export is not actually usable.
    if (blob.kind == .dma_buf) {
        beginChecked();
        venus.encodeGetMemoryResourceProperties(&scratch_cs, COMPOSITOR_DEVICE, blob.res_id);
        if (endChecked("readback mem props", venus.CMD_vkGetMemoryResourcePropertiesMESA)) {
            const r = venus.readGetMemoryResourcePropertiesReply(reply_ring.?);
            debug.klog("[gpu-comp] readback[{d}] mem props: VkResult={d} typeBits=0x{X}\n", .{ i, r.result, r.type_bits });
        }
    }
    return blob.kind;
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
        venus.encodeCreateImageExportable(
            &scratch_cs,
            COMPOSITOR_DEVICE,
            RENDER_W,
            RENDER_H,
            venus.VK_FORMAT_B8G8R8A8_UNORM,
            venus.VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | venus.VK_IMAGE_USAGE_TRANSFER_SRC_BIT,
            COMPOSITOR_RENDER_IMAGE,
        );
        if (!submitFireAndForget(&scratch_cs)) return false;
        const req = imageRequirements(COMPOSITOR_RENDER_IMAGE, "render image") orelse return false;
        if (!allocateMemory(COMPOSITOR_RENDER_MEM, req.size, req, 0, venus.VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, 0, "render image")) return false;
        scratch_cs.reset();
        venus.encodeBindImageMemory(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_RENDER_IMAGE, COMPOSITOR_RENDER_MEM, 0);
        if (!submitFireAndForget(&scratch_cs)) return false;
    }

    // 3. Read-back buffers: Venus VkDeviceMemory wrapped as HOST3D blobs
    //    (blob_id=mem_id). As dma-bufs (VKR_DEBUG=udmabuf on Lavapipe)
    //    they pair for tear-free page flip: each frame Vulkan writes into
    //    the BACK (= 1 - blob_front), then driver's flushUnconditional
    //    flips SCANOUT_BLOB to that buffer. Mapped-only, one is enough
    //    (see readback_count).
    debug.klog("[gpu-comp] render image {d}x{d} (Venus-allocated, OPTIMAL)\n", .{ RENDER_W, RENDER_H });
    const kind0 = setupReadback(0) orelse return false;
    scanout_flip = kind0 == .dma_buf and (setupReadback(1) orelse return false) == .dma_buf;
    readback_count = if (scanout_flip) 2 else 1;
    debug.klog("[gpu-comp] scanout: {s}\n", .{if (scanout_flip) "dma-buf pair, page flip" else "single mapped buffer, damage flush"});
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
        venus.encodeCreateRenderPass(&scratch_cs, COMPOSITOR_DEVICE, venus.VK_FORMAT_B8G8R8A8_UNORM, COMPOSITOR_RENDER_PASS, false);
        // Partial frames: each frame ends with the image in TRANSFER_SRC.
        venus.encodeCreateRenderPass(&scratch_cs, COMPOSITOR_DEVICE, venus.VK_FORMAT_B8G8R8A8_UNORM, COMPOSITOR_RENDER_PASS_LOAD, true);
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
        if (!submitFireAndForget(&scratch_cs)) {
            debug.klog("[gpu-comp] batch3 (view+pass+fb+cmdpool+cmdbuf+fence) FAILED\n", .{});
            return false;
        }
    }

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
    // Background source: the desktop backbuf, 1:1 (row-major B,G,R,A). The
    // first frame is a full one and fills it.
    source_tex = createTexture(.{
        .image = COMPOSITOR_SOURCE_IMAGE,
        .view = COMPOSITOR_SOURCE_VIEW,
        .mem = COMPOSITOR_SOURCE_MEM,
        .staging_buf = COMPOSITOR_SOURCE_STAGING,
        .staging_mem = COMPOSITOR_SOURCE_STAGING_MEM,
    }, SOURCE_W, SOURCE_H, true, "source") orelse return false;
    source_pixel_buf = source_tex.kptr;
    debug.klog("[gpu-comp] source image res={d} phys=0x{X} {d}x{d}\n", .{ source_tex.res_id, source_tex.phys.raw(), SOURCE_W, SOURCE_H });
    if (!createDescriptorSet(COMPOSITOR_DESC_SET, COMPOSITOR_SOURCE_VIEW, "source descriptor set")) return false;

    focused_tex = createTexture(.{
        .image = COMPOSITOR_FOCUSED_IMAGE,
        .view = COMPOSITOR_FOCUSED_VIEW,
        .mem = COMPOSITOR_FOCUSED_MEM,
        .staging_buf = COMPOSITOR_FOCUSED_STAGING,
        .staging_mem = COMPOSITOR_FOCUSED_STAGING_MEM,
    }, FOCUSED_W, FOCUSED_H, false, "focused") orelse return false;
    focused_pixel_buf = focused_tex.kptr;
    debug.klog("[gpu-comp] focused image res={d} phys=0x{X} {d}x{d}\n", .{ focused_tex.res_id, focused_tex.phys.raw(), FOCUSED_W, FOCUSED_H });
    if (!createDescriptorSet(COMPOSITOR_FOCUSED_DESC_SET, COMPOSITOR_FOCUSED_VIEW, "focused descriptor set")) return false;

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

    venus_lock.acquire();
    defer venus_lock.release();
    // A frame may have failed while we waited for the lock.
    if (!vulkan_render_ready) return null;

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
    // Fresh ids per attempt: a failed one may leave objects behind on the
    // host, and creating over a live id is fatal for the context.
    const base = next_window_ids;
    next_window_ids += WINDOW_SLOT_STRIDE;
    const ids: TextureIds = .{
        .image = base,
        .view = base + 1,
        .mem = base + 2,
        .staging_buf = base + 3,
        .staging_mem = base + 4,
    };
    const desc_set_id = base + 5;

    // Texture at MEM dims so the CPU row stride is mem_w (see above).
    const tex = createTexture(ids, mem_w, mem_h, false, "window slot") orelse {
        debug.klog("[gpu-comp] slot[{d}] texture FAILED\n", .{slot_idx});
        return null;
    };
    if (!createDescriptorSet(desc_set_id, ids.view, "window slot descriptor set")) return null;
    const kvirt = tex.kptr.?;
    const phys = tex.phys;
    const res_id = tex.res_id;
    // What the app maps; the blob behind it may be larger.
    const px_bytes_aligned = pageAlign(@as(u64, mem_w) * mem_h * 4);

    sl.tex_ids = ids;
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
    debug.klog("[gpu-comp] slot[{d}] allocated: image={d}x{d} mem={d}x{d} bytes={d} res={d} kvirt=0x{X} phys=0x{X}\n", .{ slot_idx, image_w, image_h, mem_w, mem_h, px_bytes_aligned, res_id, @intFromPtr(kvirt), phys.raw() });
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
        const kvirt: [*]volatile u32 = @ptrFromInt(phys.toVirt().raw());

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
        debug.klog("[gpu-comp] scanout blob[{d}] res={d} kvirt=0x{X} phys=0x{X}\n", .{ i, res_id, @intFromPtr(kvirt), phys.raw() });
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
    const kvirt: [*]volatile u32 = @ptrFromInt(phys.toVirt().raw());

    var res_ids = [_]u32{ res_id, 0 };
    var virts = [_][*]volatile u32{ kvirt, undefined };
    if (!virtio_gpu.armBlobScanout(res_ids[0..1], virts[0..1], 1)) {
        debug.klog("[gpu-comp] renderImageAsScanout: armBlobScanout FAILED\n", .{});
        return false;
    }
    virtio_gpu.dropOriginal2DScanout();
    render_scanout_res_id = res_id;
    debug.klog("[gpu-comp] renderImageAsScanout: ok res={d} phys=0x{X}\n", .{ res_id, phys.raw() });
    return true;
}

var frame_counter: u64 = 0;

fn readU32At(buf: []const u8, off: usize) u32 {
    const p: *align(1) const u32 = @ptrCast(buf.ptr + off);
    return p.*;
}

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
        95 => 40, // vkCmdSetScissor (one rect)
        103 => 56, // vkCmdBindDescriptorSets (one set, no dynamic offsets)
        106 => 24, // vkCmdDraw
        // vkCmdCopyBufferToImage / vkCmdCopyImageToBuffer: three handles +
        // layout (28 B), u32 regionCount, u64 array size, the regions.
        115, 116 => blk: {
            if (args_buf.len < 40) break :blk null;
            const n = readU32At(args_buf, 28);
            if (n == 0 or n > 64) break :blk null;
            break :blk 40 + @as(usize, n) * venus.BUFFER_IMAGE_COPY_SIZE;
        },
        // vkCmdPipelineBarrier: u64 cmd_buf + stages + flags (20 B), then
        // memory (20 B each), buffer (none expected) and image (64 B each)
        // barrier arrays, each as u32 count + u64 array size + elements.
        126 => blk: {
            var p: usize = 20;
            if (args_buf.len < p + 12) break :blk null;
            p += 12 + @as(usize, readU32At(args_buf, p)) * 20;
            if (args_buf.len < p + 12 or readU32At(args_buf, p) != 0) break :blk null;
            p += 12;
            if (args_buf.len < p + 12) break :blk null;
            p += 12 + @as(usize, readU32At(args_buf, p)) * 64;
            break :blk p;
        },
        137 => 8, // vkEnumerateInstanceVersion (reply marker)
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
const FrameResult = enum {
    ok,
    /// Not presented; the GPU path stays usable.
    dropped,
    /// The host may still be running it: COMPOSITOR_CMD_BUF is unusable.
    failed,
};

/// Pack 32-byte push constants: vec4 rect + vec4 uv_scale (only .xy used).
fn packPush(out: *[32]u8, x: f32, y: f32, w: f32, h: f32, ux: f32, uy: f32) void {
    const vals = [_]f32{ x, y, w, h, ux, uy, 0.0, 0.0 };
    inline for (vals, 0..) |v, i| {
        const bits: u32 = @bitCast(v);
        @memcpy(out[i * 4 ..][0..4], @as(*const [4]u8, @ptrCast(&bits)));
    }
}

/// A GPU-slot window as this frame draws it: content rect [x0, y0, x1, y1),
/// its sampling state, and the backbuf rects on top of it, already clipped
/// to the content rect.
const SlotLayer = struct {
    rect: [4]i32,
    push: [32]u8,
    desc_set: u64,
    occ_count: u8,
    occ: [MAX_OCCLUDERS][4]i32,
};
const MAX_OCCLUDERS = 12;
var slot_layers: [MAX_WINDOW_SLOTS]SlotLayer = undefined;
var slot_layer_count: u8 = 0;
/// Draws a frame records per scissor at most. ~220 bytes of command stream
/// for a draw with its bindings, ~80 for a backbuf redraw that reuses them.
const MAX_LAYER_DRAWS: usize = 32;

fn intersect(a: [4]i32, b: [4]i32) ?[4]i32 {
    const r = [4]i32{ @max(a[0], b[0]), @max(a[1], b[1]), @min(a[2], b[2]), @min(a[3], b[3]) };
    return if (r[0] < r[2] and r[1] < r[3]) r else null;
}

/// `r` [x0, y0, x1, y1) clipped to scissor `sc` {x, y, w, h}, as a scissor.
fn clipToScissor(r: [4]i32, sc: [4]u32) ?[4]u32 {
    const s = [4]i32{ @intCast(sc[0]), @intCast(sc[1]), @intCast(sc[0] + sc[2]), @intCast(sc[1] + sc[3]) };
    const c = intersect(r, s) orelse return null;
    return .{ @intCast(c[0]), @intCast(c[1]), @intCast(c[2] - c[0]), @intCast(c[3] - c[1]) };
}

/// Snapshot the visible GPU-slot windows, bottom to top, into slot_layers.
/// Returns the draws one scissor takes (the backbuf, then each window and
/// its occluders), trimming occluders past MAX_LAYER_DRAWS. Caller holds
/// the windows lock and source_lock.
fn collectSlotLayers() usize {
    const wm = @import("desktop/window.zig");
    const desktop = @import("desktop.zig");
    const TITLEBAR_H: u32 = @import("desktop/layout.zig").TITLEBAR_H;
    slot_layer_count = 0;
    var draws: usize = 1;
    for (wm.z_stack[0..wm.z_count]) |wi| {
        const w_ref = &wm.windows[wi];
        if (!w_ref.visible or w_ref.minimized) continue;
        const slot_idx = w_ref.gpu_slot orelse continue;
        if (slot_idx >= MAX_WINDOW_SLOTS) continue;
        const sl = &window_slots[slot_idx];
        if (!sl.in_use) continue;
        const content_h: u32 = w_ref.height -| TITLEBAR_H;
        if (w_ref.width == 0 or content_h == 0) continue;
        if (draws == MAX_LAYER_DRAWS) break;

        const l = &slot_layers[slot_layer_count];
        const y0 = w_ref.y + @as(i32, @intCast(TITLEBAR_H));
        l.rect = .{ w_ref.x, y0, w_ref.x + @as(i32, @intCast(w_ref.width)), y0 + @as(i32, @intCast(content_h)) };
        l.desc_set = sl.desc_set_id;
        // The image spans the slot's memory dims; sample only the
        // sl.width × sl.height the app draws.
        const ux: f32 = @as(f32, @floatFromInt(sl.width)) / @as(f32, @floatFromInt(sl.mem_w));
        const uy: f32 = @as(f32, @floatFromInt(sl.height)) / @as(f32, @floatFromInt(sl.mem_h));
        packPush(&l.push, @floatFromInt(w_ref.x), @floatFromInt(y0), @floatFromInt(w_ref.width), @floatFromInt(content_h), ux, uy);
        draws += 1;

        var above: [MAX_OCCLUDERS][4]i32 = undefined;
        const n = desktop.occludersAbove(wi, &above);
        l.occ_count = 0;
        for (above[0..n]) |o| {
            if (draws == MAX_LAYER_DRAWS) break;
            l.occ[l.occ_count] = intersect(o, l.rect) orelse continue;
            l.occ_count += 1;
            draws += 1;
        }
        slot_layer_count += 1;
    }
    return draws;
}

/// The backbuf draw under the current scissor.
fn recordBackgroundDraw(bg_push: *const [32]u8) void {
    venus.encodeCmdBindDescriptorSets(&scratch_cs, COMPOSITOR_CMD_BUF, COMPOSITOR_PIPELINE_LAYOUT, COMPOSITOR_DESC_SET);
    venus.encodeCmdPushConstants(&scratch_cs, COMPOSITOR_CMD_BUF, COMPOSITOR_PIPELINE_LAYOUT, 0x10, bg_push);
    venus.encodeCmdDraw(&scratch_cs, COMPOSITOR_CMD_BUF, 3, 1);
}

fn renderVulkanFrame(_: f32) FrameResult {
    var bg_push: [32]u8 = undefined;
    // Background image (backbuf) is allocated at exact screen size, so
    // uv_scale = (1, 1) — sample full image extent.
    packPush(&bg_push, 0.0, 0.0, @floatFromInt(RENDER_W), @floatFromInt(RENDER_H), 1.0, 1.0);

    scratch_cs.reset();
    venus.encodeBeginCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
    if (!direct_sources) {
        // Upload what the CPU wrote since the last frame: the backbuf's
        // damage, and each visible window (apps write those without
        // reporting damage). The previous frame finished before this one
        // was recorded, so nothing still samples these images.
        recordUpload(source_tex.ids, source_tex.row_pixels, bgDamage());
        const wm = @import("desktop/window.zig");
        const flags = wm.lockWindows();
        var wi: u8 = 0;
        while (wi < wm.windows.len) : (wi += 1) {
            if (!wm.slot_used[wi]) continue;
            const w_ref = &wm.windows[wi];
            if (!w_ref.visible or w_ref.minimized) continue;
            const slot_idx = w_ref.gpu_slot orelse continue;
            if (slot_idx >= MAX_WINDOW_SLOTS) continue;
            const sl = &window_slots[slot_idx];
            if (!sl.in_use) continue;
            const whole = [_][4]u32{.{ 0, 0, sl.width, sl.height }};
            recordUpload(sl.tex_ids, sl.pitch_pixels, &whole);
        }
        wm.unlockWindows(flags);
        venus.encodeCmdMemoryBarrier(
            &scratch_cs,
            COMPOSITOR_CMD_BUF,
            0x1000, // srcStage = TRANSFER
            0x80, // dstStage = FRAGMENT_SHADER
            0x1000, // srcAccess = TRANSFER_WRITE
            0x20, // dstAccess = SHADER_READ
        );
    }
    const per_scissor = blk: {
        const wm = @import("desktop/window.zig");
        const flags = wm.lockWindows();
        defer wm.unlockWindows(flags);
        break :blk collectSlotLayers();
    };

    // Render only the damage: the render image keeps the previous frame
    // (LOAD pass), so outside the damage it is already current. A full
    // frame clears instead — the image may not hold a frame yet. Each
    // damage rect gets the draws under its own scissor; where rects
    // overlap the same pixels are drawn twice (no blending). Too many
    // rects × draws would outgrow the command stream: then one scissor
    // over the bounds.
    const bounds = if (frame_damage.full) FULL_SCREEN[0] else damageBounds();
    const bounds_only = [_][4]u32{bounds};
    const draws = outDamage().len * per_scissor;
    const scissors: []const [4]u32 = if (frame_damage.full or draws > MAX_SCISSORED_DRAWS) &bounds_only else outDamage();
    venus.encodeCmdBeginRenderPassClear(
        &scratch_cs,
        COMPOSITOR_CMD_BUF,
        if (frame_damage.full) COMPOSITOR_RENDER_PASS else COMPOSITOR_RENDER_PASS_LOAD,
        COMPOSITOR_FRAMEBUFFER,
        bounds,
        0.05,
        0.05,
        0.07,
        1.0,
    );
    venus.encodeCmdBindPipeline(&scratch_cs, COMPOSITOR_CMD_BUF, COMPOSITOR_PIPELINE);

    for (scissors) |sc| {
        // The backbuf: chrome, CPU-drawn windows, menubar, dock, overlays.
        venus.encodeCmdSetScissor(&scratch_cs, COMPOSITOR_CMD_BUF, sc);
        recordBackgroundDraw(&bg_push);

        // GPU-slot windows bottom to top: the content area from the slot
        // image (the chrome stays in the backbuf layer), then the backbuf
        // again wherever something is on top of the window.
        for (slot_layers[0..slot_layer_count]) |*l| {
            const vis = clipToScissor(l.rect, sc) orelse continue;
            venus.encodeCmdSetScissor(&scratch_cs, COMPOSITOR_CMD_BUF, vis);
            venus.encodeCmdBindDescriptorSets(&scratch_cs, COMPOSITOR_CMD_BUF, COMPOSITOR_PIPELINE_LAYOUT, l.desc_set);
            venus.encodeCmdPushConstants(&scratch_cs, COMPOSITOR_CMD_BUF, COMPOSITOR_PIPELINE_LAYOUT, 0x10, &l.push);
            venus.encodeCmdDraw(&scratch_cs, COMPOSITOR_CMD_BUF, 3, 1);
            var bound = false;
            for (l.occ[0..l.occ_count]) |o| {
                const r = clipToScissor(o, vis) orelse continue;
                venus.encodeCmdSetScissor(&scratch_cs, COMPOSITOR_CMD_BUF, r);
                if (bound) {
                    venus.encodeCmdDraw(&scratch_cs, COMPOSITOR_CMD_BUF, 3, 1);
                } else {
                    recordBackgroundDraw(&bg_push);
                    bound = true;
                }
            }
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
    // A flipped buffer last held the frame before the previous one, so it
    // gets everything; the single mapped buffer gets only the damage.
    const back_idx: u32 = if (readback_promoted_to_scanout and scanout_flip) (1 - virtio_gpu.blob_front) else 0;
    venus.encodeCmdCopyImageToBufferRects(
        &scratch_cs,
        COMPOSITOR_CMD_BUF,
        COMPOSITOR_RENDER_IMAGE,
        venus.VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
        readback_buf_handles[back_idx],
        RENDER_W,
        if (scanout_flip) &FULL_SCREEN else outDamage(),
    );
    venus.encodeCmdMemoryBarrier(
        &scratch_cs,
        COMPOSITOR_CMD_BUF,
        0x1000, // srcStage = TRANSFER
        0x4000, // dstStage = HOST
        0x1000, // srcAccess = TRANSFER_WRITE
        0x2000, // dstAccess = HOST_READ
    );
    venus.encodeEndCommandBuffer(&scratch_cs, COMPOSITOR_CMD_BUF);
    venus.encodeResetFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE);
    venus.encodeQueueSubmitFence(&scratch_cs, COMPOSITOR_QUEUE, COMPOSITOR_CMD_BUF, COMPOSITOR_FENCE);
    venus.encodeSeekReplyCommandStream(&scratch_cs, 0);
    venus.encodeWaitForFences(&scratch_cs, COMPOSITOR_DEVICE, COMPOSITOR_FENCE, FENCE_TIMEOUT_NS);
    appendReplyMarker();
    frame_counter += 1;
    if (scratch_cs.overflowed) {
        debug.klog("[gpu-comp] frame {d}: command stream overflowed, frame dropped\n", .{frame_counter});
        return .dropped;
    }
    if (!validatePerFrameStream(scratch_cs.bytes())) {
        debug.klog("[gpu-comp] aborting before submit3D — see trace above. scratch_cs.pos={d}\n", .{scratch_cs.pos});
        // ud2 → #UD → idt #UD handler → kdbg autopsy (Ring 0 panic path).
        asm volatile ("ud2");
        unreachable;
    }
    // The flush that follows presents these pixels, so wait for the GPU.
    switch (submitChecked(FRAME_TIMEOUT_MS)) {
        .replied => {},
        .not_sent => {
            // Nothing of it runs on the host, or (acceptance lost) it runs
            // whole before the next frame's stream, own fence wait
            // included — either way the next frame may reuse the buffers.
            debug.klog("[gpu-comp] frame {d}: submit failed, frame dropped\n", .{frame_counter});
            return .dropped;
        },
        .no_reply => {
            debug.klog("[gpu-comp] frame {d}: no reply from the host\n", .{frame_counter});
            return .failed;
        },
    }
    const ring = reply_ring.?;
    if (venus.readReplyCmdType(ring) != venus.CMD_vkWaitForFences or venus.readReplyResult(ring) != 0) {
        debug.klog("[gpu-comp] frame {d}: fence wait cmd={d} VkResult={d}\n", .{ frame_counter, venus.readReplyCmdType(ring), venus.readReplyResult(ring) });
        return .failed;
    }
    return .ok;
}

pub fn taskEntry() callconv(.c) noreturn {
    // Same Phase-3 ritual as desktop.taskEntry: BSP is now on its high-VA
    // kernel task stack, drop the legacy low identity then re-enable IRQs.
    paging.dropLowIdentity();
    // BSP off the UEFI low-half boot stack — enable SMAP now (mirror of
    // desktop.taskEntry; boot_mode=9 takes this path instead).
    @import("../cpu/arch/protect.zig").enableSmapPerCpu();
    asm volatile ("sti");
    run();
    asm volatile ("ud2");
    unreachable;
}

fn run() noreturn {
    @import("../cpu/smp.zig").assertBSP("gpu_compositor.run");
    debug.klog("[gpu-comp] entered as side task.\n", .{});

    // Registered: a process dying inside allocateWindowImage gets the lock
    // force-released instead of stalling the compositor for good. Both
    // before the pid is published: from then on the desktop takes
    // source_lock (beginDraw).
    @import("../proc/spinlock.zig").registerMutex("gpu_compositor.venus_lock", &venus_lock);
    @import("../proc/spinlock.zig").registerMutex("gpu_compositor.source_lock", &source_lock);
    // Publish our PID so requestRender() can wake us.
    @atomicStore(u8, &compositor_pid, @intCast(process.getCurrentPid()), .release);

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
    venus_lock.acquire();
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
                //
                // A host that only maps the blob scans it out by copying
                // the flushed rect (one buffer, readback_count = 1).
                var res_ids: [2]u32 = undefined;
                var virts: [2][*]volatile u32 = undefined;
                var n: u32 = 0;
                while (n < readback_count) : (n += 1) {
                    res_ids[n] = readback_res_ids[n];
                    virts[n] = @ptrCast(@alignCast(readback_pixel_bufs[n].?));
                }
                if (virtio_gpu.armBlobScanout(res_ids[0..n], virts[0..n], n)) {
                    virtio_gpu.dropOriginal2DScanout();
                    readback_promoted_to_scanout = true;
                    debug.klog("[gpu-comp] scanout=readback HOST3D blob x{d}\n", .{n});
                } else {
                    debug.klog("[gpu-comp] armBlobScanout(readback x{d}) FAILED — keeping 2D fallback\n", .{n});
                }

                // Same size and row pitch as the backbuf: the desktop can
                // draw into the background source itself.
                if (disp_w == SOURCE_W and disp_h == SOURCE_H and source_tex.row_pixels == disp_w) {
                    offered_backbuf = @ptrCast(@alignCast(source_pixel_buf.?));
                    @import("desktop/wake.zig").requestWake();
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
    venus_lock.release();

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
    //   bucket 5: 33..50ms    (a slow frame; the old 33 ms idle poll lived here)
    //   bucket 6: 50..100ms   (visible stutter)
    //   bucket 7: 100ms+      (frame drop)
    var interval_hist: [8]u32 = .{0} ** 8;
    var full_damage_frames: u32 = 0;
    // Damaged screen area (sum of the damage rects), per stats window.
    var damage_px: u64 = 0;
    var prev_frame_tsc: u64 = 0;
    while (true) : (frame_no += 1) {
        // Park until something asks for a frame: requestRender() bumps
        // pending_wakes and process.wake()s us from any CPU, and blockOn's
        // wake_pending handshake makes the check-then-park race-free (a
        // wake landing between the load below and the park returns at
        // once). The wake_tick is a liveness backstop only. Until
        // 2026-09-17 this was a 33 ms kernelSleepMs poll — the desktop
        // never truly idled, and the BSP's tickless stretch was clamped to
        // 3 quanta by this task's next deadline for the life of the boot.
        // Xchg, not load-then-store-0: a requestRender landing between the
        // two would lose its increment (harmless today only because every
        // caller publishes its damage before bumping — made structural).
        while (@atomicRmw(u32, &pending_wakes, .Xchg, 0, .seq_cst) == 0) {
            parkUntilRender();
        }

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

        // Single mapped scanout: flush just the damage (the host copies
        // the flushed rect). Null = flush the whole screen.
        var flush_rect: ?[4]u32 = null;
        var present = true;
        source_lock.acquire();
        if (vulkan_render_ready) {
            takeDamage();
            if (frame_damage.full) full_damage_frames += 1;
            for (outDamage()) |r| damage_px += @as(u64, r[2]) * r[3];
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
            const result = blk: {
                const t = perf.enter();
                defer perf.leave(.comp_vk_render, t);
                venus_lock.acquire();
                defer venus_lock.release();
                const r = renderVulkanFrame(@as(f32, @floatFromInt(frame_no)) / 30.0);
                // A frame that never completed may still be running on
                // the host, and COMPOSITOR_CMD_BUF cannot be re-recorded
                // under it. Cleared under the lock so a waiting
                // allocateWindowImage sees it. Stay on the CPU path from
                // here on (windows drawn only through their GPU slots go
                // blank).
                if (r == .failed) vulkan_render_ready = false;
                break :blk r;
            };
            // 3. If the readback blob has been promoted to scanout, the
            //    vkCmdCopyImageToBuffer above already wrote into the
            //    host-visible dmabuf — flushUnconditional just sends
            //    RESOURCE_FLUSH and the host displays it. No kernel
            //    memcpy needed. Otherwise, fall back to the slow path
            //    (BAR memcpy + 2D TRANSFER_TO_HOST inside flushUnconditional).
            if (result == .failed) {
                present = false;
                debug.klog("[gpu-comp] Vulkan frame failed — falling back to the CPU path\n", .{});
            } else if (result == .dropped) {
                // This frame's damage never reached the screen: redo it all.
                present = false;
                pending_full = true;
                _ = @atomicRmw(u32, &pending_wakes, .Add, 1, .seq_cst);
            } else if (readback_promoted_to_scanout) {
                @import("desktop/dirty.zig").reset();
                if (!scanout_flip and !frame_damage.full) flush_rect = damageBounds();
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
        } else {
            // Vulkan render path not up — fall back to the legacy
            // dirty-rect blit so the screen still updates.
            const t = perf.enter();
            defer perf.leave(.comp_sync, t);
            _ = syncBackBufferToScreen();
        }
        source_lock.release();

        // 4. ONE flush per frame. Wrapped in comp_flush so we can tell
        // whether host vblank actually back-pressures here (~16ms) or
        // returns instantly (instant return = tearing source — page
        // flip happens mid-display-refresh).
        if (virtio_gpu.active and present) {
            const t = perf.enter();
            defer perf.leave(.comp_flush, t);
            if (flush_rect) |r| {
                virtio_gpu.flushRectUnconditional(r[0], r[1], r[2], r[3]);
            } else {
                virtio_gpu.flushUnconditional();
            }
        }

        fps_frames += 1;
        const now = process.tick_count;
        if (fps_last_tick == 0) fps_last_tick = now;
        if (now -% fps_last_tick >= 500) {
            const elapsed_ms: u64 = (now -% fps_last_tick) * 10;
            const fps = if (elapsed_ms > 0) (@as(u64, fps_frames) * 1000) / elapsed_ms else 0;
            debug.klog("[gpu-comp] frame {d}, ~{d} fps over {d} ms (vulkan={d}, full-damage={d}, avg-area={d}px) | intervals <4ms={d} <8={d} <16={d} <24={d} <33={d} <50={d} <100={d} 100+={d}\n", .{
                frame_no, fps, elapsed_ms, @intFromBool(vulkan_render_ready), full_damage_frames,
                if (fps_frames > 0) damage_px / fps_frames else 0,
                interval_hist[0], interval_hist[1], interval_hist[2], interval_hist[3],
                interval_hist[4], interval_hist[5], interval_hist[6], interval_hist[7],
            });
            fps_last_tick = now;
            fps_frames = 0;
            full_damage_frames = 0;
            damage_px = 0;
            interval_hist = .{0} ** 8;
        }

        // No artificial sleep — flushUnconditional's RESOURCE_FLUSH
        // blocks on host vblank (~16ms at 60 Hz) so the loop is paced
        // by the display, not by us. Restore a sleep here if we ever
        // pin a CPU at 100% with no display attached.
    }
}
