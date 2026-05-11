// Kernel-side Venus protocol encoder. Mirrors `lib/venus.zig` (which is
// userspace-only because it imports libc for syscall transport) — the
// encoders themselves are pure buffer math, so duplicating them is the
// cheapest path to letting the kernel speak Venus directly via
// `virtio_gpu.submit3D`. Future cleanup: refactor lib/venus.zig to
// abstract its transport so both sides can share encoders.
//
// Per-submit reply convention: each `virtio_gpu.submit3D(ctx, cs.bytes())`
// call is one Venus submit. The host's reply-write head appears to reset
// per submit, so single-command submits read the reply at offset 4 of
// the reply ring. For multi-command batched submits we'd need an explicit
// `Seek(0)` before the reply-generating command (cube does this for its
// per-frame WaitForFences).

const std = @import("std");
const virtio_gpu = @import("../driver/virtio_gpu.zig");

// --- VkCommandTypeEXT constants ---
pub const CMD_vkCreateInstance: u32 = 0;
pub const CMD_vkEnumeratePhysicalDevices: u32 = 2;
pub const CMD_vkCreateDevice: u32 = 11;
pub const CMD_vkQueueSubmit: u32 = 18;
pub const CMD_vkAllocateMemory: u32 = 21;
pub const CMD_vkBindImageMemory: u32 = 29;
pub const CMD_vkCreateFence: u32 = 35;
pub const CMD_vkResetFences: u32 = 37;
pub const CMD_vkWaitForFences: u32 = 39;
pub const CMD_vkCreateImage: u32 = 54;
pub const CMD_vkCreateImageView: u32 = 57;
pub const CMD_vkCreateShaderModule: u32 = 59;
pub const CMD_vkCreateGraphicsPipelines: u32 = 65;
pub const CMD_vkCreatePipelineLayout: u32 = 68;
pub const CMD_vkCreateSampler: u32 = 70;
pub const CMD_vkCreateDescriptorSetLayout: u32 = 72;
pub const CMD_vkCreateDescriptorPool: u32 = 74;
pub const CMD_vkAllocateDescriptorSets: u32 = 77;
pub const CMD_vkUpdateDescriptorSets: u32 = 79;
pub const CMD_vkCreateFramebuffer: u32 = 80;
pub const CMD_vkCreateRenderPass: u32 = 82;
pub const CMD_vkCreateCommandPool: u32 = 85;
pub const CMD_vkAllocateCommandBuffers: u32 = 88;
pub const CMD_vkBeginCommandBuffer: u32 = 90;
pub const CMD_vkEndCommandBuffer: u32 = 91;
pub const CMD_vkCmdBindPipeline: u32 = 93;
pub const CMD_vkCmdBindDescriptorSets: u32 = 103;
pub const CMD_vkCmdDraw: u32 = 106;
pub const CMD_vkCmdPipelineBarrier: u32 = 126;
pub const CMD_vkCmdPushConstants: u32 = 132;
pub const CMD_vkCmdBeginRenderPass: u32 = 133;
pub const CMD_vkCmdEndRenderPass: u32 = 135;
pub const CMD_vkGetDeviceQueue2: u32 = 155;
pub const CMD_vkBindBufferMemory: u32 = 28;
pub const CMD_vkCreateBuffer: u32 = 50;
pub const CMD_vkCmdCopyImageToBuffer: u32 = 116;
pub const CMD_vkSetReplyCommandStreamMESA: u32 = 178;
pub const CMD_vkSeekReplyCommandStreamMESA: u32 = 179;
pub const CMD_vkExecuteCommandStreamsMESA: u32 = 180;
pub const CMD_vkCreateRingMESA: u32 = 188;
pub const CMD_vkDestroyRingMESA: u32 = 189;
pub const CMD_vkNotifyRingMESA: u32 = 190;
pub const CMD_vkWriteRingExtraMESA: u32 = 191;
pub const CMD_vkGetMemoryResourcePropertiesMESA: u32 = 192;
pub const CMD_vkResetFenceResourceMESA: u32 = 244;
pub const CMD_vkWaitSemaphoreResourceMESA: u32 = 245;
pub const CMD_vkImportSemaphoreResourceMESA: u32 = 246;
pub const CMD_vkSubmitVirtqueueSeqnoMESA: u32 = 251;
pub const CMD_vkWaitVirtqueueSeqnoMESA: u32 = 252;
pub const CMD_vkWaitRingSeqnoMESA: u32 = 253;
pub const CMD_vkCopyImageToMemoryMESA: u32 = 297;
pub const CMD_vkCopyMemoryToImageMESA: u32 = 298;
pub const CMD_vkWriteSamplerDescriptorMESA: u32 = 335;
pub const CMD_vkWriteResourceDescriptorMESA: u32 = 336;

pub const CMD_FLAG_GENERATE_REPLY: u32 = 0x00000001;

// --- VkStructureType constants ---
pub const VK_STRUCTURE_TYPE_APPLICATION_INFO: u32 = 0;
pub const VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO: u32 = 1;
pub const VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO: u32 = 2;
pub const VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO: u32 = 3;
pub const VK_STRUCTURE_TYPE_SUBMIT_INFO: u32 = 4;
pub const VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO: u32 = 5;
pub const VK_STRUCTURE_TYPE_FENCE_CREATE_INFO: u32 = 8;
pub const VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO: u32 = 14;
pub const VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO: u32 = 15;
pub const VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO: u32 = 16;
pub const VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO: u32 = 31;
pub const VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO: u32 = 32;
pub const VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO: u32 = 33;
pub const VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO: u32 = 34;
pub const VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET: u32 = 35;
pub const VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO: u32 = 18;
pub const VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO: u32 = 19;
pub const VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO: u32 = 20;
pub const VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO: u32 = 22;
pub const VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO: u32 = 23;
pub const VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO: u32 = 24;
pub const VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO: u32 = 25;
pub const VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO: u32 = 26;
pub const VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO: u32 = 28;
pub const VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO: u32 = 30;
pub const VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO: u32 = 37;
pub const VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO: u32 = 38;
pub const VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO: u32 = 39;
pub const VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO: u32 = 40;
pub const VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO: u32 = 42;
pub const VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO: u32 = 43;
pub const VK_STRUCTURE_TYPE_DEVICE_QUEUE_INFO_2: u32 = 1000145003;
pub const VK_STRUCTURE_TYPE_DEVICE_QUEUE_TIMELINE_INFO_MESA: u32 = 1000384005;

// --- Vulkan format / usage constants used by the compositor ---
pub const VK_FORMAT_B8G8R8A8_UNORM: u32 = 44;
pub const VK_IMAGE_USAGE_TRANSFER_SRC_BIT: u32 = 0x1;
pub const VK_IMAGE_USAGE_SAMPLED_BIT: u32 = 0x4;
pub const VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT: u32 = 0x10;
pub const VK_IMAGE_ASPECT_COLOR_BIT: u32 = 1;

pub const CmdStream = struct {
    buf: [4096]u8 align(8) = undefined,
    pos: usize = 0,

    pub fn writeU32(self: *CmdStream, val: u32) void {
        if (self.pos + 4 > self.buf.len) return;
        const ptr: *align(1) u32 = @ptrCast(self.buf[self.pos..][0..4]);
        ptr.* = val;
        self.pos += 4;
    }

    pub fn writeU64(self: *CmdStream, val: u64) void {
        if (self.pos + 8 > self.buf.len) return;
        const ptr: *align(1) u64 = @ptrCast(self.buf[self.pos..][0..8]);
        ptr.* = val;
        self.pos += 8;
    }

    pub fn writeF32(self: *CmdStream, val: f32) void {
        self.writeU32(@bitCast(val));
    }

    pub fn writePresent(self: *CmdStream) void {
        self.writeU64(1);
    }

    pub fn writeNull(self: *CmdStream) void {
        self.writeU64(0);
    }

    pub fn cmdHeader(self: *CmdStream, cmd_type: u32, flags: u32) void {
        self.writeU32(cmd_type);
        self.writeU32(flags);
    }

    pub fn writeString(self: *CmdStream, s: []const u8) void {
        const len = s.len + 1;
        self.writeU64(len);
        if (self.pos + len > self.buf.len) return;
        @memcpy(self.buf[self.pos..][0..s.len], s);
        self.buf[self.pos + s.len] = 0;
        self.pos += len;
        const aligned = (self.pos + 3) & ~@as(usize, 3);
        while (self.pos < aligned) {
            self.buf[self.pos] = 0;
            self.pos += 1;
        }
    }

    /// Write raw bytes (4-byte aligned). Used by encodeCmdPushConstants.
    pub fn writeBytes(self: *CmdStream, data: []const u8) void {
        if (self.pos + data.len > self.buf.len) return;
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
        const aligned = (self.pos + 3) & ~@as(usize, 3);
        while (self.pos < aligned) {
            self.buf[self.pos] = 0;
            self.pos += 1;
        }
    }

    pub fn bytes(self: *CmdStream) []const u8 {
        return self.buf[0..self.pos];
    }

    pub fn reset(self: *CmdStream) void {
        self.pos = 0;
    }
};

// ============================================================================
// MESA extension encoders (Venus-specific protocol commands)
// ============================================================================

/// One sub-stream reference for `vkExecuteCommandStreamsMESA`. Points at
/// a region inside a SHM-backed virtio-gpu resource that contains an
/// already-encoded Venus command stream. Wire layout: u32 resourceId +
/// size_t offset + size_t size (size_t = u64 in our ABI).
pub const CommandStreamDesc = struct {
    resource_id: u32,
    offset: u64,
    size: u64,
};

/// Run multiple pre-built Venus command streams in one Venus dispatch.
/// Each `streams[i]` references a (resource_id, offset, size) tuple
/// pointing at a SHM-backed virtio-gpu resource that already holds an
/// encoded Venus command stream. The host's dispatch decoder runs each
/// stream's commands in order.
///
/// For the compositor's setup path we use simpler in-place scratch_cs
/// batching (multiple encoded commands in one stream, one submit) which
/// is equivalent to vkExecuteCommandStreamsMESA but doesn't require
/// allocating separate SHM resources. This encoder is here for future
/// uses: e.g. pre-recorded per-frame streams that get triggered many
/// times without re-encoding.
pub fn encodeExecuteCommandStreams(
    cs: *CmdStream,
    streams: []const CommandStreamDesc,
    flags: u32,
) void {
    cs.cmdHeader(CMD_vkExecuteCommandStreamsMESA, 0);
    cs.writeU32(@intCast(streams.len));
    // pStreams: array of VkCommandStreamDescriptionMESA
    cs.writePresent();
    cs.writeU64(streams.len);
    for (streams) |s| {
        cs.writeU32(s.resource_id);
        cs.writeU64(s.offset);
        cs.writeU64(s.size);
    }
    cs.writeNull(); // pReplyPositions = NULL (no per-stream reply offsets)
    cs.writeU32(0); // dependencyCount
    cs.writeNull(); // pDependencies = NULL
    cs.writeU32(flags); // VkCommandStreamExecutionFlagsMESA
}

pub const VK_STRUCTURE_TYPE_MEMORY_RESOURCE_PROPERTIES_MESA: u32 = 1000384001;
pub const VK_STRUCTURE_TYPE_COPY_IMAGE_TO_MEMORY_INFO_MESA: u32 = 1000384003;
pub const VK_STRUCTURE_TYPE_RING_CREATE_INFO_MESA: u32 = 1000384000;

/// Register a Venus secondary command ring. The ring is a SHM-backed
/// virtio-gpu resource laid out as:
///   [head u32] [tail u32] [status u32] [buffer ...] [extra ...]
/// at the offsets the caller supplies. After creation, the guest writes
/// Venus commands to the buffer region at `tail` (atomically bumping
/// tail), and the host has a dedicated thread that drains commands from
/// `head` to `tail`. status is a bitmask of ALIVE/FATAL/IDLE.
///
/// Fire-and-forget at the protocol level (reply is just an ack — no
/// fields). idleTimeout in microseconds; host thread sleeps after that
/// many µs of an empty ring.
pub fn encodeCreateRing(
    cs: *CmdStream,
    ring_id: u64,
    resource_id: u32,
    region_offset: u64,
    region_size: u64,
    idle_timeout_us: u64,
    head_offset: u64,
    tail_offset: u64,
    status_offset: u64,
    buffer_offset: u64,
    buffer_size: u64,
    extra_offset: u64,
    extra_size: u64,
) void {
    cs.cmdHeader(CMD_vkCreateRingMESA, 0);
    cs.writeU64(ring_id);
    cs.writePresent(); // pCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_RING_CREATE_INFO_MESA);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(resource_id);
    cs.writeU64(region_offset);
    cs.writeU64(region_size);
    cs.writeU64(idle_timeout_us);
    cs.writeU64(head_offset);
    cs.writeU64(tail_offset);
    cs.writeU64(status_offset);
    cs.writeU64(buffer_offset);
    cs.writeU64(buffer_size);
    cs.writeU64(extra_offset);
    cs.writeU64(extra_size);
}

pub fn encodeDestroyRing(cs: *CmdStream, ring_id: u64) void {
    cs.cmdHeader(CMD_vkDestroyRingMESA, 0);
    cs.writeU64(ring_id);
}

/// Wake the host's ring thread. Use after writing commands + bumping tail.
/// Optional — the host thread polls but may sleep on `idle_timeout`; an
/// explicit notify cuts wake latency to ~µs.
pub fn encodeNotifyRing(cs: *CmdStream, ring_id: u64, seqno: u32, flags: u32) void {
    cs.cmdHeader(CMD_vkNotifyRingMESA, 0);
    cs.writeU64(ring_id);
    cs.writeU32(seqno);
    cs.writeU32(flags);
}

/// Write a u32 value into the ring's `extra` region at the given offset.
/// Used for seqno completion tracking — host runs the cmds preceding
/// this write, then writes the value. Guest polls extra[offset] to see
/// when the seqno has been reached.
pub fn encodeWriteRingExtra(cs: *CmdStream, ring_id: u64, offset: u64, value: u32) void {
    cs.cmdHeader(CMD_vkWriteRingExtraMESA, 0);
    cs.writeU64(ring_id);
    cs.writeU64(offset);
    cs.writeU32(value);
}

/// Block until the ring's seqno (in the extra region) reaches the given
/// value. Host-side wait — saves a guest poll loop, but goes through
/// ctrl_vq so it's only worth using when the wait is expected to be long.
pub fn encodeWaitRingSeqno(cs: *CmdStream, ring_id: u64, seqno: u64) void {
    cs.cmdHeader(CMD_vkWaitRingSeqnoMESA, CMD_FLAG_GENERATE_REPLY);
    cs.writeU64(ring_id);
    cs.writeU64(seqno);
}

/// Host-direct image → memory copy. Unlike vkCmdCopyImageToBuffer this
/// is NOT a command buffer cmd — it's a synchronous Venus call, the
/// host does the copy and writes the result inline into the reply
/// stream's blob storage (allocated from the reply encoder, not a
/// caller-provided pointer).
///
/// Caveat for our use case: the destination is the REPLY STREAM, not
/// the scanout blob. To use this productively for the compositor's
/// scanout path we'd need to either (a) make the reply stream large
/// enough to hold a full frame (8MB at 1920×1080) AND switch it to
/// point at the scanout blob before this call, or (b) kernel-memcpy
/// from reply-stream → scanout-blob after the call. Neither is faster
/// than the existing vkCmdCopyImageToBuffer path that writes directly
/// into the scanout blob's memory (since the readback VkBuffer is
/// bound to that same memory).
///
/// Keeping the encoder around for: vkCopyMemoryToImage-style uploads
/// of small textures, debug dumps of host-only Vulkan resources, etc.
pub fn encodeCopyImageToMemoryMESA(
    cs: *CmdStream,
    device_id: u64,
    src_image_id: u64,
    src_image_layout: u32,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    data_size: u64,
) void {
    cs.cmdHeader(CMD_vkCopyImageToMemoryMESA, CMD_FLAG_GENERATE_REPLY);
    cs.writeU64(device_id);
    // pCopyImageToMemoryInfo: full struct
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_COPY_IMAGE_TO_MEMORY_INFO_MESA);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU64(src_image_id);
    cs.writeU32(src_image_layout);
    cs.writeU32(0); // memoryRowLength = 0 (tightly packed)
    cs.writeU32(0); // memoryImageHeight = 0
    // VkImageSubresourceLayers
    cs.writeU32(1); // aspectMask = COLOR
    cs.writeU32(0); // mipLevel
    cs.writeU32(0); // baseArrayLayer
    cs.writeU32(1); // layerCount
    // VkOffset3D
    cs.writeU32(x);
    cs.writeU32(y);
    cs.writeU32(0); // z
    // VkExtent3D
    cs.writeU32(w);
    cs.writeU32(h);
    cs.writeU32(1); // depth
    // dataSize + array_size (must match)
    cs.writeU64(data_size);
    cs.writeU64(data_size);
}

/// Query the memory properties of a virtio-gpu resource. Returns the
/// memoryTypeBits mask — a bitmask of host memory types compatible with
/// importing this resource. The reply encoder pattern is the same as
/// vkCreateInstance: set CMD_FLAG_GENERATE_REPLY and read from the reply
/// ring after submit. Reply layout:
///   u32 cmd_type (192 = vkGetMemoryResourcePropertiesMESA_EXT)
///   u32 VkResult
///   u64 simple_pointer = 1
///   u32 sType (must be 1000384001)
///   u64 pNext = 0
///   u32 memoryTypeBits  <-- this is what we want
pub fn encodeGetMemoryResourceProperties(
    cs: *CmdStream,
    device_id: u64,
    resource_id: u32,
) void {
    cs.cmdHeader(CMD_vkGetMemoryResourcePropertiesMESA, CMD_FLAG_GENERATE_REPLY);
    cs.writeU64(device_id);
    cs.writeU32(resource_id);
    // pMemoryResourceProperties: partial struct (sType + pNext only)
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_MEMORY_RESOURCE_PROPERTIES_MESA);
    cs.writeNull(); // pNext
}

/// Parse the vkGetMemoryResourcePropertiesMESA reply from the reply ring.
/// Returns (VkResult, memoryTypeBits). Caller must have zeroed and
/// Seek(0)'d the reply ring before submit.
pub fn readGetMemoryResourcePropertiesReply(ring: [*]volatile u8) struct { result: i32, type_bits: u32 } {
    // ring[0..4]   = cmd_type (192)
    // ring[4..8]   = VkResult
    // ring[8..16]  = simple_pointer (= 1)
    // ring[16..20] = sType
    // ring[20..28] = pNext
    // ring[28..32] = memoryTypeBits
    const result_ptr: *align(1) const volatile i32 = @ptrCast(ring + 4);
    const type_bits_ptr: *align(1) const volatile u32 = @ptrCast(ring + 28);
    return .{ .result = result_ptr.*, .type_bits = type_bits_ptr.* };
}

// ============================================================================
// Setup-time encoders (called once per resource lifetime)
// ============================================================================

pub fn encodeCreateInstance(cs: *CmdStream, instance_id: u64) void {
    cs.cmdHeader(CMD_vkCreateInstance, CMD_FLAG_GENERATE_REPLY);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writePresent(); // pApplicationInfo
    cs.writeU32(VK_STRUCTURE_TYPE_APPLICATION_INFO);
    cs.writeNull();
    cs.writeString("ZigOS-Compositor");
    cs.writeU32(1);
    cs.writeString("ZigOS");
    cs.writeU32(1);
    cs.writeU32((1 << 22) | (2 << 12)); // VK_API_VERSION_1_2
    cs.writeU32(0);
    cs.writeU64(0);
    cs.writeU32(0);
    cs.writeU64(0);
    cs.writeNull();
    cs.writePresent();
    cs.writeU64(instance_id);
}

pub fn encodeEnumeratePhysicalDevices(cs: *CmdStream, instance_id: u64, phys_dev_id: u64) void {
    cs.cmdHeader(CMD_vkEnumeratePhysicalDevices, CMD_FLAG_GENERATE_REPLY);
    cs.writeU64(instance_id);
    cs.writePresent();
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeU64(phys_dev_id);
}

/// Exportable variant of vkCreateDevice — enables VK_KHR_external_memory_fd
/// + VK_EXT_external_memory_dma_buf so we can allocate DMA_BUF-exportable
/// VkDeviceMemory and back it with a virtio-gpu HOST3D blob (the same
/// pattern the cube uses).
pub fn encodeCreateDevice(
    cs: *CmdStream,
    phys_dev_id: u64,
    queue_family: u32,
    device_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateDevice, CMD_FLAG_GENERATE_REPLY);
    cs.writeU64(phys_dev_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeU32(VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(queue_family);
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeF32(1.0);
    // layers
    cs.writeU32(0);
    cs.writeU64(0);
    // extensions (DMA_BUF export pair)
    cs.writeU32(2);
    cs.writeU64(2);
    cs.writeString("VK_KHR_external_memory_fd");
    cs.writeString("VK_EXT_external_memory_dma_buf");
    cs.writeNull(); // pEnabledFeatures
    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(device_id);
}

pub fn encodeGetDeviceQueue(
    cs: *CmdStream,
    device_id: u64,
    queue_family: u32,
    queue_index: u32,
    queue_id: u64,
) void {
    cs.cmdHeader(CMD_vkGetDeviceQueue2, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_DEVICE_QUEUE_INFO_2);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_DEVICE_QUEUE_TIMELINE_INFO_MESA);
    cs.writeNull();
    cs.writeU32(1); // ringIdx
    cs.writeU32(0);
    cs.writeU32(queue_family);
    cs.writeU32(queue_index);
    cs.writePresent();
    cs.writeU64(queue_id);
}

/// 2D color image, OPTIMAL tiling, single-mip/single-layer, with DMA_BUF
/// external-memory pNext chain so it can bind to memory allocated via
/// `encodeAllocateMemoryExportable`.
pub fn encodeCreateImageExportable(
    cs: *CmdStream,
    device_id: u64,
    w: u32,
    h: u32,
    format: u32,
    usage: u32,
    image_id: u64,
) void {
    encodeCreateImageImpl(cs, device_id, w, h, format, usage, 0, 0, image_id);
}

/// Sampled image — LINEAR tiling, USAGE_SAMPLED, exportable. Used for
/// source textures the compositor wants to read pixels from. LINEAR
/// guarantees deterministic row-major byte layout in the dma-buf
/// memory, so the kernel can write a known pattern via the SHM BAR
/// mapping and Lavapipe's sampler will read those bytes back as B8G8R8A8.
pub fn encodeCreateImageSampledLinear(
    cs: *CmdStream,
    device_id: u64,
    w: u32,
    h: u32,
    format: u32,
    image_id: u64,
) void {
    // tiling=1 (LINEAR), usage=0x04 (SAMPLED), initial_layout=0 (UNDEFINED).
    // We transition UNDEFINED→GENERAL once, then the kernel writes the
    // pattern via the dma-buf mapping. Sampling from GENERAL is allowed.
    encodeCreateImageImpl(cs, device_id, w, h, format, 0x04, 1, 0, image_id);
}

/// Color attachment image, LINEAR tiling, exportable. Used for a Vulkan
/// render target whose pixels the kernel reads directly via the dma-buf
/// mapping (no vkCmdCopyImage tile-untiling step). Lavapipe accepts
/// LINEAR + COLOR_ATTACHMENT because it's pure software — no hardware
/// tiling constraints. usage = COLOR_ATTACHMENT_BIT (0x10).
pub fn encodeCreateImageColorAttachmentLinear(
    cs: *CmdStream,
    device_id: u64,
    w: u32,
    h: u32,
    format: u32,
    image_id: u64,
) void {
    encodeCreateImageImpl(cs, device_id, w, h, format, 0x10, 1, 0, image_id);
}

fn encodeCreateImageImpl(
    cs: *CmdStream,
    device_id: u64,
    w: u32,
    h: u32,
    format: u32,
    usage: u32,
    tiling: u32,
    initial_layout: u32,
    image_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateImage, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO);
    cs.writePresent(); // pNext -> VkExternalMemoryImageCreateInfo
    cs.writeU32(1000072001);
    cs.writeNull();
    cs.writeU32(0x200); // DMA_BUF
    cs.writeU32(0); // flags
    cs.writeU32(1); // imageType = 2D
    cs.writeU32(format);
    cs.writeU32(w);
    cs.writeU32(h);
    cs.writeU32(1);
    cs.writeU32(1);
    cs.writeU32(1);
    cs.writeU32(1);
    cs.writeU32(tiling);
    cs.writeU32(usage);
    cs.writeU32(0); // sharingMode
    cs.writeU32(0);
    cs.writeU64(0);
    cs.writeU32(initial_layout);
    cs.writeNull();
    cs.writePresent();
    cs.writeU64(image_id);
}

pub fn encodeAllocateMemoryExportable(
    cs: *CmdStream,
    device_id: u64,
    alloc_size: u64,
    memory_type_index: u32,
    memory_id: u64,
) void {
    cs.cmdHeader(CMD_vkAllocateMemory, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO);
    cs.writePresent();
    cs.writeU32(1000072002); // VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO
    cs.writeNull();
    cs.writeU32(0x200); // handleTypes = DMA_BUF
    cs.writeU64(alloc_size);
    cs.writeU32(memory_type_index);
    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(memory_id);
}

pub const VK_STRUCTURE_TYPE_IMPORT_MEMORY_RESOURCE_INFO_MESA: u32 = 1000384002;

/// vkAllocateMemory chained with VkImportMemoryResourceInfoMESA — wraps
/// an existing virtio-gpu resource (typically an anonymous HOST3D blob)
/// as the VkDeviceMemory's storage. The kernel memcpy path stays fast
/// because anonymous blobs use virgl's directly EPT-mapped memory pool,
/// while Vulkan can sample/render from the same bytes through the
/// imported VkDeviceMemory. pNext chain Import → Export so the bound
/// image (declared DMA_BUF in encodeCreateImage*) passes validation.
pub fn encodeAllocateMemoryImport(
    cs: *CmdStream,
    device_id: u64,
    alloc_size: u64,
    memory_type_index: u32,
    resource_id: u32,
    memory_id: u64,
) void {
    cs.cmdHeader(CMD_vkAllocateMemory, 0);
    cs.writeU64(device_id);

    cs.writePresent(); // pAllocateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO);
    cs.writePresent(); // outer pNext -> Import
    cs.writeU32(VK_STRUCTURE_TYPE_IMPORT_MEMORY_RESOURCE_INFO_MESA);
    cs.writePresent(); // import pNext -> Export
    cs.writeU32(1000072002); // VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO
    cs.writeNull(); // export pNext
    cs.writeU32(0x200); // handleTypes = DMA_BUF
    cs.writeU32(resource_id); // ImportInfo.resourceId
    cs.writeU64(alloc_size);
    cs.writeU32(memory_type_index);

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pMemory
    cs.writeU64(memory_id);
}

/// Create a VkBuffer with the given size + usage. No DMA_BUF external
/// info chain — use this for buffers backed by SHM-imported memory or
/// regular Venus-allocated memory. Same shape as encodeCreateImage's
/// non-exportable variant.
pub fn encodeCreateBuffer(
    cs: *CmdStream,
    device_id: u64,
    size: u64,
    usage: u32,
    buffer_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateBuffer, 0);
    cs.writeU64(device_id);

    cs.writePresent(); // pCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO);
    cs.writeNull(); // pNext = null
    cs.writeU32(0); // flags
    cs.writeU64(size);
    cs.writeU32(usage);
    cs.writeU32(0); // sharingMode = EXCLUSIVE
    cs.writeU32(0); // queueFamilyIndexCount
    cs.writeU64(0); // pQueueFamilyIndices = null

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pBuffer
    cs.writeU64(buffer_id);
}

/// VkBuffer with VkExternalMemoryBufferCreateInfo declaring DMA_BUF
/// handle type. Required when the buffer will bind to memory that
/// itself was allocated with VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF
/// (vkAllocateMemoryExportable + udmabuf, or import-from-resource).
/// Without this declaration, vkBindBufferMemory fails validation
/// (VUID-vkBindBufferMemory-memory-02985).
pub fn encodeCreateBufferExportable(
    cs: *CmdStream,
    device_id: u64,
    size: u64,
    usage: u32,
    buffer_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateBuffer, 0);
    cs.writeU64(device_id);

    cs.writePresent(); // pCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO);
    cs.writePresent(); // pNext -> VkExternalMemoryBufferCreateInfo
    cs.writeU32(1000072000); // VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO
    cs.writeNull(); // external info pNext
    cs.writeU32(0x200); // handleTypes = DMA_BUF
    cs.writeU32(0); // flags
    cs.writeU64(size);
    cs.writeU32(usage);
    cs.writeU32(0); // sharingMode = EXCLUSIVE
    cs.writeU32(0); // queueFamilyIndexCount
    cs.writeU64(0); // pQueueFamilyIndices = null

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pBuffer
    cs.writeU64(buffer_id);
}

pub fn encodeBindBufferMemory(
    cs: *CmdStream,
    device_id: u64,
    buffer_id: u64,
    memory_id: u64,
    offset: u64,
) void {
    cs.cmdHeader(CMD_vkBindBufferMemory, 0);
    cs.writeU64(device_id);
    cs.writeU64(buffer_id);
    cs.writeU64(memory_id);
    cs.writeU64(offset);
}

/// vkCmdCopyImageToBuffer — used to copy a render image's pixels into
/// an SHM-bound buffer the kernel can read directly. Single full-image
/// region, tight packing, color aspect.
pub fn encodeCmdCopyImageToBuffer(
    cs: *CmdStream,
    cmd_buf_id: u64,
    src_image: u64,
    image_layout: u32,
    dst_buffer: u64,
    width: u32,
    height: u32,
) void {
    cs.cmdHeader(CMD_vkCmdCopyImageToBuffer, 0);
    cs.writeU64(cmd_buf_id);
    cs.writeU64(src_image);
    cs.writeU32(image_layout);
    cs.writeU64(dst_buffer);
    cs.writeU32(1); // regionCount
    cs.writeU64(1); // pRegions array size
    // VkBufferImageCopy
    cs.writeU64(0); // bufferOffset
    cs.writeU32(0); // bufferRowLength (0 = tightly packed)
    cs.writeU32(0); // bufferImageHeight (0 = tightly packed)
    // imageSubresource
    cs.writeU32(VK_IMAGE_ASPECT_COLOR_BIT);
    cs.writeU32(0); // mipLevel
    cs.writeU32(0); // baseArrayLayer
    cs.writeU32(1); // layerCount
    // imageOffset
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0);
    // imageExtent
    cs.writeU32(width);
    cs.writeU32(height);
    cs.writeU32(1);
}

pub const VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO: u32 = 12;
pub const VK_BUFFER_USAGE_TRANSFER_DST_BIT: u32 = 0x2;
pub const VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL: u32 = 6;

pub fn encodeBindImageMemory(
    cs: *CmdStream,
    device_id: u64,
    image_id: u64,
    memory_id: u64,
    offset: u64,
) void {
    cs.cmdHeader(CMD_vkBindImageMemory, 0);
    cs.writeU64(device_id);
    cs.writeU64(image_id);
    cs.writeU64(memory_id);
    cs.writeU64(offset);
}

pub fn encodeCreateImageView(
    cs: *CmdStream,
    device_id: u64,
    image_id: u64,
    format: u32,
    aspect_mask: u32,
    view_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateImageView, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU64(image_id);
    cs.writeU32(1); // viewType = 2D
    cs.writeU32(format);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(aspect_mask);
    cs.writeU32(0);
    cs.writeU32(1);
    cs.writeU32(0);
    cs.writeU32(1);
    cs.writeNull();
    cs.writePresent();
    cs.writeU64(view_id);
}

/// Single color attachment; clear → store; final layout = COLOR_ATTACHMENT_OPTIMAL
pub fn encodeCreateRenderPass(
    cs: *CmdStream,
    device_id: u64,
    format: u32,
    render_pass_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateRenderPass, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writeU32(1); // attachmentCount
    cs.writeU64(1);
    cs.writeU32(0); // attachment flags
    cs.writeU32(format);
    cs.writeU32(1); // samples
    cs.writeU32(1); // loadOp = CLEAR
    cs.writeU32(0); // storeOp = STORE
    cs.writeU32(2); // stencilLoadOp = DONT_CARE
    cs.writeU32(1); // stencilStoreOp = DONT_CARE
    cs.writeU32(0); // initialLayout = UNDEFINED
    cs.writeU32(2); // finalLayout = COLOR_ATTACHMENT_OPTIMAL
    cs.writeU32(1); // subpassCount
    cs.writeU64(1);
    cs.writeU32(0); // subpass flags
    cs.writeU32(0); // pipelineBindPoint = GRAPHICS
    cs.writeU32(0); // inputAttachmentCount
    cs.writeU64(0);
    cs.writeU32(1); // colorAttachmentCount
    cs.writeU64(1);
    cs.writeU32(0); // attachment index
    cs.writeU32(2); // layout = COLOR_ATTACHMENT_OPTIMAL
    cs.writeNull(); // pResolveAttachments
    cs.writeNull(); // pDepthStencilAttachment
    cs.writeU32(0); // preserveAttachmentCount
    cs.writeU64(0);
    cs.writeU32(0); // dependencyCount
    cs.writeU64(0);
    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(render_pass_id);
}

pub fn encodeCreateFramebuffer(
    cs: *CmdStream,
    device_id: u64,
    render_pass_id: u64,
    image_view_id: u64,
    w: u32,
    h: u32,
    fb_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateFramebuffer, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU64(render_pass_id);
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeU64(image_view_id);
    cs.writeU32(w);
    cs.writeU32(h);
    cs.writeU32(1);
    cs.writeNull();
    cs.writePresent();
    cs.writeU64(fb_id);
}

pub fn encodeCreateCommandPool(
    cs: *CmdStream,
    device_id: u64,
    queue_family: u32,
    pool_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateCommandPool, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0x02); // RESET_COMMAND_BUFFER_BIT
    cs.writeU32(queue_family);
    cs.writeNull();
    cs.writePresent();
    cs.writeU64(pool_id);
}

pub fn encodeAllocateCommandBuffers(
    cs: *CmdStream,
    device_id: u64,
    pool_id: u64,
    cmd_buf_id: u64,
) void {
    cs.cmdHeader(CMD_vkAllocateCommandBuffers, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO);
    cs.writeNull();
    cs.writeU64(pool_id);
    cs.writeU32(0); // PRIMARY
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeU64(cmd_buf_id);
}

pub fn encodeCreateFence(cs: *CmdStream, device_id: u64, flags: u32, fence_id: u64) void {
    cs.cmdHeader(CMD_vkCreateFence, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_FENCE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(flags);
    cs.writeNull();
    cs.writePresent();
    cs.writeU64(fence_id);
}

// ============================================================================
// Per-frame encoders (called every render iteration)
// ============================================================================

pub fn encodeBeginCommandBuffer(cs: *CmdStream, cmd_buf_id: u64) void {
    cs.cmdHeader(CMD_vkBeginCommandBuffer, 0);
    cs.writeU64(cmd_buf_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writeNull(); // pInheritanceInfo
}

pub fn encodeEndCommandBuffer(cs: *CmdStream, cmd_buf_id: u64) void {
    cs.cmdHeader(CMD_vkEndCommandBuffer, 0);
    cs.writeU64(cmd_buf_id);
}

/// Begin a render pass with a single color clear value (RGBA float).
pub fn encodeCmdBeginRenderPassClear(
    cs: *CmdStream,
    cmd_buf_id: u64,
    render_pass_id: u64,
    framebuffer_id: u64,
    w: u32,
    h: u32,
    r: f32,
    g: f32,
    b: f32,
    a: f32,
) void {
    cs.cmdHeader(CMD_vkCmdBeginRenderPass, 0);
    cs.writeU64(cmd_buf_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO);
    cs.writeNull();
    cs.writeU64(render_pass_id);
    cs.writeU64(framebuffer_id);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(w);
    cs.writeU32(h);
    cs.writeU32(1); // clearValueCount
    cs.writeU64(1);
    cs.writeU32(0); // VkClearValue tag = color
    cs.writeU32(0); // VkClearColorValue tag = float32
    cs.writeU64(4);
    cs.writeF32(r);
    cs.writeF32(g);
    cs.writeF32(b);
    cs.writeF32(a);
    cs.writeU32(0); // VK_SUBPASS_CONTENTS_INLINE
}

pub fn encodeCmdEndRenderPass(cs: *CmdStream, cmd_buf_id: u64) void {
    cs.cmdHeader(CMD_vkCmdEndRenderPass, 0);
    cs.writeU64(cmd_buf_id);
}

/// Image-layout pipeline barrier. Used to transition the render image
/// from `COLOR_ATTACHMENT_OPTIMAL` → `GENERAL` so the host can read it
/// for guest-blob access. Same shape as the cube's pipeline barrier.
pub fn encodeCmdPipelineBarrier(
    cs: *CmdStream,
    cmd_buf_id: u64,
    image_id: u64,
    old_layout: u32,
    new_layout: u32,
    src_stage: u32,
    dst_stage: u32,
    src_access: u32,
    dst_access: u32,
) void {
    cs.cmdHeader(CMD_vkCmdPipelineBarrier, 0);
    cs.writeU64(cmd_buf_id);
    cs.writeU32(src_stage);
    cs.writeU32(dst_stage);
    cs.writeU32(0); // dependencyFlags
    cs.writeU32(0); // memoryBarrierCount
    cs.writeU64(0);
    cs.writeU32(0); // bufferMemoryBarrierCount
    cs.writeU64(0);
    cs.writeU32(1); // imageMemoryBarrierCount
    cs.writeU64(1);
    cs.writeU32(45); // VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER
    cs.writeNull();
    cs.writeU32(src_access);
    cs.writeU32(dst_access);
    cs.writeU32(old_layout);
    cs.writeU32(new_layout);
    cs.writeU32(0xFFFFFFFF); // srcQueueFamilyIndex
    cs.writeU32(0xFFFFFFFF); // dstQueueFamilyIndex
    cs.writeU64(image_id);
    cs.writeU32(VK_IMAGE_ASPECT_COLOR_BIT);
    cs.writeU32(0);
    cs.writeU32(1);
    cs.writeU32(0);
    cs.writeU32(1);
}

pub fn encodeResetFences(cs: *CmdStream, device_id: u64, fence_id: u64) void {
    cs.cmdHeader(CMD_vkResetFences, 0);
    cs.writeU64(device_id);
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeU64(fence_id);
}

pub fn encodeQueueSubmitFence(cs: *CmdStream, queue_id: u64, cmd_buf_id: u64, fence_id: u64) void {
    cs.cmdHeader(CMD_vkQueueSubmit, 0);
    cs.writeU64(queue_id);
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeU32(VK_STRUCTURE_TYPE_SUBMIT_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU64(0);
    cs.writeU64(0);
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeU64(cmd_buf_id);
    cs.writeU32(0);
    cs.writeU64(0);
    cs.writeU64(fence_id);
}

pub fn encodeWaitForFences(cs: *CmdStream, device_id: u64, fence_id: u64, timeout_ns: u64) void {
    cs.cmdHeader(CMD_vkWaitForFences, CMD_FLAG_GENERATE_REPLY);
    cs.writeU64(device_id);
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeU64(fence_id);
    cs.writeU32(1); // waitAll
    cs.writeU64(timeout_ns);
}

pub fn encodeSeekReplyCommandStream(cs: *CmdStream, position: u64) void {
    cs.cmdHeader(CMD_vkSeekReplyCommandStreamMESA, 0);
    cs.writeU64(position);
}

/// Read VkResult from offset 4 of a reply (cmd_type at 0..4, VkResult at 4..8).
pub fn readReplyResult(reply_buf: [*]volatile u8) i32 {
    const ptr: *align(1) const volatile i32 = @ptrCast(reply_buf + 4);
    return ptr.*;
}

// ============================================================================
// Step 6: shaders + pipeline + draw encoders
// ============================================================================

pub fn encodeCreateShaderModule(
    cs: *CmdStream,
    device_id: u64,
    spirv_code: []const u32,
    module_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateShaderModule, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writeU64(spirv_code.len * 4); // codeSize (bytes)
    cs.writeU64(spirv_code.len); // pCode array size (in u32 elements)
    for (spirv_code) |word| cs.writeU32(word);
    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(module_id);
}

/// Pipeline layout with no descriptors but a single push-constant range.
pub fn encodeCreatePipelineLayoutPush(
    cs: *CmdStream,
    device_id: u64,
    push_stage_flags: u32,
    push_size: u32,
    layout_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreatePipelineLayout, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(0); // setLayoutCount
    cs.writeU64(0);
    cs.writeU32(1); // pushConstantRangeCount
    cs.writeU64(1);
    cs.writeU32(push_stage_flags);
    cs.writeU32(0);
    cs.writeU32(push_size);
    cs.writeNull();
    cs.writePresent();
    cs.writeU64(layout_id);
}

/// Graphics pipeline for a fullscreen-triangle pass: no vertex input,
/// no depth/stencil, no blending, no culling, viewport = full image.
/// Caller draws 3 vertices via vkCmdDraw (positions come from the
/// vertex shader's gl_VertexIndex math, no buffer needed).
pub fn encodeCreateGraphicsPipelinesFullscreen(
    cs: *CmdStream,
    device_id: u64,
    layout_id: u64,
    render_pass_id: u64,
    vert_module_id: u64,
    frag_module_id: u64,
    width: u32,
    height: u32,
    pipeline_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateGraphicsPipelines, 0);
    cs.writeU64(device_id);
    cs.writeU64(0); // pipelineCache = NULL
    cs.writeU32(1);
    cs.writeU64(1);

    // VkGraphicsPipelineCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);

    // 2 shader stages
    cs.writeU32(2);
    cs.writeU64(2);
    // Vertex stage
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(0x01); // VERTEX_BIT
    cs.writeU64(vert_module_id);
    cs.writeString("main");
    cs.writeNull();
    // Fragment stage
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(0x10); // FRAGMENT_BIT
    cs.writeU64(frag_module_id);
    cs.writeString("main");
    cs.writeNull();

    // pVertexInputState — empty (no bindings, no attributes)
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU64(0);
    cs.writeU32(0);
    cs.writeU64(0);

    // pInputAssemblyState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(3); // TRIANGLE_LIST
    cs.writeU32(0);

    // pTessellationState = null
    cs.writeNull();

    // pViewportState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(1);
    cs.writeU64(1);
    const fw: f32 = @floatFromInt(width);
    const fh: f32 = @floatFromInt(height);
    cs.writeF32(0.0);
    cs.writeF32(0.0);
    cs.writeF32(fw);
    cs.writeF32(fh);
    cs.writeF32(0.0);
    cs.writeF32(1.0);
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(width);
    cs.writeU32(height);

    // pRasterizationState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(0); // depthClampEnable
    cs.writeU32(0); // rasterizerDiscardEnable
    cs.writeU32(0); // polygonMode = FILL
    cs.writeU32(0); // cullMode = NONE
    cs.writeU32(0); // frontFace = CCW
    cs.writeU32(0); // depthBiasEnable
    cs.writeF32(0.0);
    cs.writeF32(0.0);
    cs.writeF32(0.0);
    cs.writeF32(1.0); // lineWidth

    // pMultisampleState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(1); // rasterizationSamples
    cs.writeU32(0);
    cs.writeF32(1.0);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(0);

    // pDepthStencilState = null (no depth attachment in render pass)
    cs.writeNull();

    // pColorBlendState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(0); // logicOpEnable
    cs.writeU32(0);
    cs.writeU32(1); // attachmentCount
    cs.writeU64(1);
    cs.writeU32(0); // blendEnable
    cs.writeU32(1); // srcColor = ONE
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(1);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0xF); // RGBA
    cs.writeU64(4);
    cs.writeF32(0.0);
    cs.writeF32(0.0);
    cs.writeF32(0.0);
    cs.writeF32(0.0);

    // pDynamicState = null
    cs.writeNull();

    cs.writeU64(layout_id);
    cs.writeU64(render_pass_id);
    cs.writeU32(0); // subpass
    cs.writeU64(0);
    cs.writeU32(@bitCast(@as(i32, -1)));

    cs.writeNull(); // pAllocator
    cs.writeU64(1);
    cs.writeU64(pipeline_id);
}

pub fn encodeCmdBindPipeline(cs: *CmdStream, cmd_buf_id: u64, pipeline_id: u64) void {
    cs.cmdHeader(CMD_vkCmdBindPipeline, 0);
    cs.writeU64(cmd_buf_id);
    cs.writeU32(0); // GRAPHICS
    cs.writeU64(pipeline_id);
}

pub fn encodeCmdDraw(cs: *CmdStream, cmd_buf_id: u64, vertex_count: u32, instance_count: u32) void {
    cs.cmdHeader(CMD_vkCmdDraw, 0);
    cs.writeU64(cmd_buf_id);
    cs.writeU32(vertex_count);
    cs.writeU32(instance_count);
    cs.writeU32(0); // firstVertex
    cs.writeU32(0); // firstInstance
}

pub fn encodeCmdPushConstants(
    cs: *CmdStream,
    cmd_buf_id: u64,
    layout_id: u64,
    stage_flags: u32,
    data: []const u8,
) void {
    cs.cmdHeader(CMD_vkCmdPushConstants, 0);
    cs.writeU64(cmd_buf_id);
    cs.writeU64(layout_id);
    cs.writeU32(stage_flags);
    cs.writeU32(0);
    cs.writeU32(@intCast(data.len));
    cs.writeU64(data.len);
    cs.writeBytes(data);
}

// ============================================================================
// Step 7: sampler + descriptor set + texture sampling
// ============================================================================

/// Default 2D sampler — linear filter, repeat wrap, no mipmap, no
/// anisotropy, no compare, normalized coords. Matches what most simple
/// fragment shaders expect for `texture(sampler2D, uv)`.
pub fn encodeCreateSampler(cs: *CmdStream, device_id: u64, sampler_id: u64) void {
    cs.cmdHeader(CMD_vkCreateSampler, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_SAMPLER_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(1); // magFilter = LINEAR
    cs.writeU32(1); // minFilter = LINEAR
    cs.writeU32(0); // mipmapMode = NEAREST
    cs.writeU32(0); // addressModeU = REPEAT
    cs.writeU32(0); // addressModeV = REPEAT
    cs.writeU32(0); // addressModeW = REPEAT
    cs.writeF32(0.0); // mipLodBias
    cs.writeU32(0); // anisotropyEnable
    cs.writeF32(1.0); // maxAnisotropy
    cs.writeU32(0); // compareEnable
    cs.writeU32(0); // compareOp = NEVER
    cs.writeF32(0.0); // minLod
    cs.writeF32(0.0); // maxLod (single-mip — set to 0)
    cs.writeU32(0); // borderColor = FLOAT_TRANSPARENT_BLACK
    cs.writeU32(0); // unnormalizedCoordinates = false
    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(sampler_id);
}

/// Single-binding descriptor set layout: binding 0, COMBINED_IMAGE_SAMPLER,
/// FRAGMENT stage. Matches `layout(set=0, binding=0) uniform sampler2D`.
pub fn encodeCreateDescriptorSetLayoutSampler(
    cs: *CmdStream,
    device_id: u64,
    layout_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateDescriptorSetLayout, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writeU32(1); // bindingCount
    cs.writeU64(1); // pBindings array size
    // VkDescriptorSetLayoutBinding
    cs.writeU32(0); // binding
    cs.writeU32(1); // descriptorType = COMBINED_IMAGE_SAMPLER
    cs.writeU32(1); // descriptorCount
    cs.writeU32(0x10); // stageFlags = FRAGMENT_BIT
    cs.writeU64(0); // pImmutableSamplers = null array
    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(layout_id);
}

/// Descriptor pool sized for 1 set, 1 sampler descriptor.
pub fn encodeCreateDescriptorPool(
    cs: *CmdStream,
    device_id: u64,
    pool_id: u64,
) void {
    encodeCreateDescriptorPoolN(cs, device_id, pool_id, 1, 1);
}

/// Create a descriptor pool sized for `max_sets` sets and `desc_count`
/// COMBINED_IMAGE_SAMPLER descriptors total. Compositor uses N>1 so a
/// single pool can back per-window descriptor sets.
pub fn encodeCreateDescriptorPoolN(
    cs: *CmdStream,
    device_id: u64,
    pool_id: u64,
    max_sets: u32,
    desc_count: u32,
) void {
    cs.cmdHeader(CMD_vkCreateDescriptorPool, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writeU32(max_sets);
    cs.writeU32(1); // poolSizeCount
    cs.writeU64(1); // pPoolSizes array size
    cs.writeU32(1); // type = COMBINED_IMAGE_SAMPLER
    cs.writeU32(desc_count);
    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(pool_id);
}

pub fn encodeAllocateDescriptorSet(
    cs: *CmdStream,
    device_id: u64,
    pool_id: u64,
    layout_id: u64,
    set_id: u64,
) void {
    cs.cmdHeader(CMD_vkAllocateDescriptorSets, CMD_FLAG_GENERATE_REPLY);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO);
    cs.writeNull();
    cs.writeU64(pool_id);
    cs.writeU32(1); // descriptorSetCount
    cs.writeU64(1); // pSetLayouts array size
    cs.writeU64(layout_id);
    cs.writeU64(1); // pDescriptorSets array (returned)
    cs.writeU64(set_id);
}

/// Update a descriptor set with a single combined-image-sampler write
/// (binding 0, array element 0). `image_layout` should be GENERAL or
/// SHADER_READ_ONLY_OPTIMAL — whatever the sampled image is in.
pub fn encodeUpdateDescriptorSetSampler(
    cs: *CmdStream,
    device_id: u64,
    set_id: u64,
    sampler_id: u64,
    view_id: u64,
    image_layout: u32,
) void {
    cs.cmdHeader(CMD_vkUpdateDescriptorSets, 0);
    cs.writeU64(device_id);
    cs.writeU32(1); // descriptorWriteCount
    cs.writeU64(1); // pDescriptorWrites array size
    // VkWriteDescriptorSet
    cs.writeU32(VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET);
    cs.writeNull(); // pNext
    cs.writeU64(set_id); // dstSet
    cs.writeU32(0); // dstBinding
    cs.writeU32(0); // dstArrayElement
    cs.writeU32(1); // descriptorCount
    cs.writeU32(1); // descriptorType = COMBINED_IMAGE_SAMPLER
    // pImageInfo array (size 1)
    cs.writeU64(1);
    cs.writeU64(sampler_id);
    cs.writeU64(view_id);
    cs.writeU32(image_layout);
    // pBufferInfo = null array
    cs.writeU64(0);
    // pTexelBufferView = null array
    cs.writeU64(0);
    cs.writeU32(0); // descriptorCopyCount
    cs.writeU64(0); // pDescriptorCopies = null array
}

/// Pipeline layout with both 1 descriptor set + 1 push constant range.
pub fn encodeCreatePipelineLayoutFull(
    cs: *CmdStream,
    device_id: u64,
    set_layout_id: u64,
    push_stage_flags: u32,
    push_size: u32,
    layout_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreatePipelineLayout, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writeU32(1); // setLayoutCount
    cs.writeU64(1); // pSetLayouts array size
    cs.writeU64(set_layout_id);
    cs.writeU32(1); // pushConstantRangeCount
    cs.writeU64(1); // pPushConstantRanges array size
    cs.writeU32(push_stage_flags);
    cs.writeU32(0); // offset
    cs.writeU32(push_size);
    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(layout_id);
}

pub fn encodeCmdBindDescriptorSets(
    cs: *CmdStream,
    cmd_buf_id: u64,
    layout_id: u64,
    set_id: u64,
) void {
    cs.cmdHeader(CMD_vkCmdBindDescriptorSets, 0);
    cs.writeU64(cmd_buf_id);
    cs.writeU32(0); // pipelineBindPoint = GRAPHICS
    cs.writeU64(layout_id);
    cs.writeU32(0); // firstSet
    cs.writeU32(1); // descriptorSetCount
    cs.writeU64(1); // pDescriptorSets array size
    cs.writeU64(set_id);
    cs.writeU32(0); // dynamicOffsetCount
    cs.writeU64(0); // pDynamicOffsets = null array
}
