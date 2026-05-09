// Venus Wire Protocol Encoder
// Encodes Vulkan commands for submission via virtio-gpu CMD_SUBMIT_3D
// with Venus capset (id=4). Wire format matches virglrenderer's Venus decoder.
//
// Protocol format:
//   Command = cmd_type(u32) + cmd_flags(u32) + args...
//   Pointer = u64 (0=null, non-zero=present)
//   Handle  = u64 (guest-assigned ID)
//   String  = u64(length) + chars (4-byte aligned)
//   Struct  = sType(u32) + pNext(pointer) + fields...
//   size_t  = u64

const libc = @import("libc");

// --- VkCommandTypeEXT ---
pub const CMD_vkSetReplyCommandStreamMESA: u32 = 178;
pub const CMD_vkSeekReplyCommandStreamMESA: u32 = 179;
pub const CMD_vkCreateInstance: u32 = 0;
pub const CMD_vkDestroyInstance: u32 = 1;
pub const CMD_vkEnumeratePhysicalDevices: u32 = 2;
pub const CMD_vkGetPhysicalDeviceFeatures: u32 = 3;
pub const CMD_vkGetPhysicalDeviceProperties: u32 = 6;
pub const CMD_vkGetPhysicalDeviceQueueFamilyProperties: u32 = 7;
pub const CMD_vkGetPhysicalDeviceMemoryProperties: u32 = 8;
pub const CMD_vkCreateDevice: u32 = 11;
pub const CMD_vkDestroyDevice: u32 = 12;
pub const CMD_vkEnumerateInstanceVersion: u32 = 137;
pub const CMD_vkGetDeviceQueue: u32 = 17;
pub const CMD_vkGetDeviceQueue2: u32 = 155;
pub const CMD_vkQueueSubmit: u32 = 18;
pub const CMD_vkQueueWaitIdle: u32 = 19;
pub const CMD_vkDeviceWaitIdle: u32 = 20;
pub const CMD_vkAllocateMemory: u32 = 21;
pub const CMD_vkBindBufferMemory: u32 = 28;
pub const CMD_vkBindImageMemory: u32 = 29;
pub const CMD_vkCreateFence: u32 = 35;
pub const CMD_vkDestroyFence: u32 = 36;
pub const CMD_vkResetFences: u32 = 37;
pub const CMD_vkWaitForFences: u32 = 39;
pub const CMD_vkCreateBuffer: u32 = 50;
pub const CMD_vkCreateImage: u32 = 54;
pub const CMD_vkCreateImageView: u32 = 57;
pub const CMD_vkCreateShaderModule: u32 = 59;
pub const CMD_vkCreateGraphicsPipelines: u32 = 65;
pub const CMD_vkCreatePipelineLayout: u32 = 68;
pub const CMD_vkCreateRenderPass: u32 = 82;
pub const CMD_vkCreateFramebuffer: u32 = 80;
pub const CMD_vkCreateCommandPool: u32 = 85;
pub const CMD_vkDestroyCommandPool: u32 = 86;
pub const CMD_vkResetCommandPool: u32 = 87;
pub const CMD_vkAllocateCommandBuffers: u32 = 88;
pub const CMD_vkFreeCommandBuffers: u32 = 89;
pub const CMD_vkBeginCommandBuffer: u32 = 90;
pub const CMD_vkEndCommandBuffer: u32 = 91;
pub const CMD_vkResetCommandBuffer: u32 = 92;
pub const CMD_vkCmdBindPipeline: u32 = 93;
pub const CMD_vkCmdBindVertexBuffers: u32 = 105;
pub const CMD_vkCmdDraw: u32 = 106;
pub const CMD_vkCmdCopyImageToBuffer: u32 = 116;
pub const CMD_vkCmdUpdateBuffer: u32 = 117;
pub const CMD_vkCmdPipelineBarrier: u32 = 126;
pub const CMD_vkCmdPushConstants: u32 = 132;
pub const CMD_vkCmdBeginRenderPass: u32 = 133;
pub const CMD_vkCmdEndRenderPass: u32 = 135;

// --- VkCommandFlagsEXT ---
pub const CMD_FLAG_GENERATE_REPLY: u32 = 0x00000001;

// --- VkStructureType ---
pub const VK_STRUCTURE_TYPE_APPLICATION_INFO: u32 = 0;
pub const VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO: u32 = 1;
pub const VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO: u32 = 2;
pub const VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO: u32 = 3;
pub const VK_STRUCTURE_TYPE_SUBMIT_INFO: u32 = 4;
pub const VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO: u32 = 5;
pub const VK_STRUCTURE_TYPE_FENCE_CREATE_INFO: u32 = 8;
pub const VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO: u32 = 9;
pub const VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO: u32 = 14;
pub const VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO: u32 = 15;
pub const VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO: u32 = 16;
pub const VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO: u32 = 18;
pub const VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO: u32 = 19;
pub const VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO: u32 = 20;
pub const VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO: u32 = 22;
pub const VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO: u32 = 23;
pub const VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO: u32 = 24;
pub const VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO: u32 = 26;
pub const VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO: u32 = 28;
pub const VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO: u32 = 30;
pub const VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO: u32 = 38;
pub const VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO: u32 = 37;
pub const VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO: u32 = 39;
pub const VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO: u32 = 40;
pub const VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO: u32 = 42;
pub const VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO: u32 = 43;
pub const VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO: u32 = 12;
pub const VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO: u32 = 25;
pub const VK_STRUCTURE_TYPE_COMMAND_STREAM_DESCRIPTION_MESA: u32 = 1000384001;

// --- Venus Command Stream Encoder ---

pub const CmdStream = struct {
    buf: [8192]u8 align(8) = undefined,
    pos: usize = 0,

    /// Write a u32 value
    pub fn writeU32(self: *CmdStream, val: u32) void {
        if (self.pos + 4 > self.buf.len) return;
        const ptr: *align(1) u32 = @ptrCast(self.buf[self.pos..][0..4]);
        ptr.* = val;
        self.pos += 4;
    }

    /// Write a u64 value (used for handles, pointers, size_t, array sizes)
    pub fn writeU64(self: *CmdStream, val: u64) void {
        if (self.pos + 8 > self.buf.len) return;
        const ptr: *align(1) u64 = @ptrCast(self.buf[self.pos..][0..8]);
        ptr.* = val;
        self.pos += 8;
    }

    /// Write f32 as raw bits
    pub fn writeF32(self: *CmdStream, val: f32) void {
        self.writeU32(@bitCast(val));
    }

    /// Write "pointer present" (u64 = 1)
    pub fn writePresent(self: *CmdStream) void {
        self.writeU64(1);
    }

    /// Write "pointer null" (u64 = 0)
    pub fn writeNull(self: *CmdStream) void {
        self.writeU64(0);
    }

    /// Write command header: cmd_type + cmd_flags
    pub fn cmdHeader(self: *CmdStream, cmd_type: u32, flags: u32) void {
        self.writeU32(cmd_type);
        self.writeU32(flags);
    }

    /// Write a string (u64 length including null + chars + padding to 4-byte align)
    pub fn writeString(self: *CmdStream, s: []const u8) void {
        const len = s.len + 1; // include null terminator
        self.writeU64(len); // array size = length including null
        if (self.pos + len > self.buf.len) return;
        @memcpy(self.buf[self.pos..][0..s.len], s);
        self.buf[self.pos + s.len] = 0; // null terminator
        self.pos += len;
        // Align to 4 bytes
        const aligned = (self.pos + 3) & ~@as(usize, 3);
        while (self.pos < aligned) {
            self.buf[self.pos] = 0;
            self.pos += 1;
        }
    }

    /// Write raw bytes (4-byte aligned)
    pub fn writeBytes(self: *CmdStream, data: []const u8) void {
        if (self.pos + data.len > self.buf.len) return;
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
        // Align to 4 bytes
        const aligned = (self.pos + 3) & ~@as(usize, 3);
        while (self.pos < aligned) {
            self.buf[self.pos] = 0;
            self.pos += 1;
        }
    }

    /// Get the encoded buffer as a byte slice
    pub fn bytes(self: *CmdStream) []const u8 {
        return self.buf[0..self.pos];
    }

    /// Submit the command stream via GPU syscall
    pub fn submit(self: *CmdStream) bool {
        return libc.gpuSubmit3D(self.bytes());
    }

    /// Reset for reuse
    pub fn reset(self: *CmdStream) void {
        self.pos = 0;
    }
};

// --- Reply stream helpers ---

/// BLOB_MEM types for gpuCreateBlob
pub const BLOB_MEM_HOST3D: u32 = 2;

/// Set up a reply stream: create blob, map it, send vkSetReplyCommandStreamMESA.
/// Returns the mapped reply buffer pointer and resource ID, or null.
pub fn setupReplyStream(reply_size: u32) ?struct { buf: [*]volatile u8, res_id: u32 } {
    // Create a HOST3D blob resource for reply data
    const res_id = libc.gpuCreateBlob(BLOB_MEM_HOST3D, reply_size) orelse return null;

    // Map it into user space
    const buf = libc.gpuMapBlob(res_id, reply_size) orelse return null;

    // Zero the reply buffer
    for (0..reply_size) |i| buf[i] = 0;

    // Send vkSetReplyCommandStreamMESA to tell host where to write replies
    var cs = CmdStream{};
    cs.cmdHeader(CMD_vkSetReplyCommandStreamMESA, 0);
    // pStream (pointer present)
    cs.writePresent();
    // VkCommandStreamDescriptionMESA { resourceId, offset, size }
    cs.writeU32(res_id); // resourceId
    cs.writeU64(0); // offset (size_t = u64)
    cs.writeU64(reply_size); // size (size_t = u64)

    if (!cs.submit()) return null;

    return .{ .buf = buf, .res_id = res_id };
}

/// Read a VkResult (i32) from the reply stream at the current position.
/// The reply format is: cmd_type(u32) + VkResult(i32) + ...
pub fn readReplyResult(reply_buf: [*]volatile u8) i32 {
    // Skip cmd_type (4 bytes), read VkResult
    const result_ptr: *align(1) const volatile i32 = @ptrCast(reply_buf + 4);
    return result_ptr.*;
}

/// Encode vkSeekReplyCommandStreamMESA — reset the host-side write position
/// of the reply ring to `position`. Without this, every WaitForFences reply
/// (and any other reply we generate) advances the host's internal write
/// head; after ~500 frames at 8 bytes/reply our 4 KB reply blob fills up,
/// the host can no longer write replies, our subsequent WaitForFences
/// silently doesn't wait, and the cube context dies in a cascade of
/// VUID validation errors. Seeking to 0 before each new wait keeps the
/// ring permanently usable. Fire-and-forget — no GENERATE_REPLY flag.
/// Costs nothing if batched with WaitForFences in the same cs.submit().
pub fn encodeSeekReplyCommandStream(cs: *CmdStream, position: u64) void {
    cs.cmdHeader(CMD_vkSeekReplyCommandStreamMESA, 0);
    cs.writeU64(position);
}

// --- High-level Venus command encoders ---

/// Encode vkCreateInstance command (fire-and-forget, no reply)
/// Returns the handle ID assigned to the instance.
pub fn encodeCreateInstance(cs: *CmdStream, instance_id: u64) void {
    cs.cmdHeader(CMD_vkCreateInstance, 0);

    // pCreateInfo (pointer present)
    cs.writePresent();
    // VkInstanceCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO); // sType
    cs.writeNull(); // pNext = null
    cs.writeU32(0); // flags

    // pApplicationInfo (pointer present)
    cs.writePresent();
    // VkApplicationInfo
    cs.writeU32(VK_STRUCTURE_TYPE_APPLICATION_INFO); // sType
    cs.writeNull(); // pNext = null
    cs.writeString("ZigOS"); // pApplicationName
    cs.writeU32(1); // applicationVersion
    cs.writeString("ZigOS"); // pEngineName
    cs.writeU32(1); // engineVersion
    cs.writeU32((1 << 22) | (2 << 12)); // apiVersion = VK_API_VERSION_1_2

    // enabledLayerCount = 0
    cs.writeU32(0);
    cs.writeU64(0); // ppEnabledLayerNames = null array (size 0)
    // enabledExtensionCount = 0
    cs.writeU32(0);
    cs.writeU64(0); // ppEnabledExtensionNames = null array (size 0)

    // pAllocator = null
    cs.writeNull();

    // pInstance (pointer present, provides handle ID)
    cs.writePresent();
    cs.writeU64(instance_id);
}

/// Encode vkDestroyInstance command
pub fn encodeDestroyInstance(cs: *CmdStream, instance_id: u64) void {
    cs.cmdHeader(CMD_vkDestroyInstance, 0);
    cs.writeU64(instance_id); // instance handle
    cs.writeNull(); // pAllocator = null
}

/// Encode vkEnumeratePhysicalDevices (fire-and-forget with pre-assigned IDs)
pub fn encodeEnumeratePhysicalDevices(
    cs: *CmdStream,
    instance_id: u64,
    phys_dev_ids: []const u64,
) void {
    cs.cmdHeader(CMD_vkEnumeratePhysicalDevices, 0);
    cs.writeU64(instance_id); // instance handle

    // pPhysicalDeviceCount (pointer present)
    cs.writePresent();
    cs.writeU32(@intCast(phys_dev_ids.len)); // count

    // pPhysicalDevices array
    cs.writeU64(phys_dev_ids.len); // array size
    for (phys_dev_ids) |id| {
        cs.writeU64(id);
    }
}

/// Encode vkCreateDevice
pub fn encodeCreateDevice(
    cs: *CmdStream,
    phys_dev_id: u64,
    queue_family: u32,
    device_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateDevice, 0);
    cs.writeU64(phys_dev_id); // physicalDevice handle

    // pCreateInfo (pointer present)
    cs.writePresent();
    // VkDeviceCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO); // sType
    cs.writeNull(); // pNext = null
    cs.writeU32(0); // flags

    // queueCreateInfoCount = 1
    cs.writeU32(1);
    // pQueueCreateInfos array (size 1)
    cs.writeU64(1);
    // VkDeviceQueueCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO); // sType
    cs.writeNull(); // pNext = null
    cs.writeU32(0); // flags
    cs.writeU32(queue_family); // queueFamilyIndex
    cs.writeU32(1); // queueCount
    // pQueuePriorities array (size 1)
    cs.writeU64(1);
    cs.writeF32(1.0); // priority

    // enabledLayerCount = 0
    cs.writeU32(0);
    cs.writeU64(0); // ppEnabledLayerNames = null
    // enabledExtensionCount = 0
    cs.writeU32(0);
    cs.writeU64(0); // ppEnabledExtensionNames = null
    // pEnabledFeatures = null
    cs.writeNull();

    // pAllocator = null
    cs.writeNull();

    // pDevice (pointer present, provides handle ID)
    cs.writePresent();
    cs.writeU64(device_id);
}

/// Encode vkCreateDevice with external memory extensions for blob export
pub fn encodeCreateDeviceExportable(
    cs: *CmdStream,
    phys_dev_id: u64,
    queue_family: u32,
    device_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateDevice, 0);
    cs.writeU64(phys_dev_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(1); // queueCreateInfoCount
    cs.writeU64(1); // array size
    cs.writeU32(VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(queue_family);
    cs.writeU32(1); // queueCount
    cs.writeU64(1); // pQueuePriorities array
    cs.writeF32(1.0);
    // layers
    cs.writeU32(0);
    cs.writeU64(0);
    // extensions: 2
    cs.writeU32(2);
    cs.writeU64(2);
    cs.writeString("VK_KHR_external_memory_fd");
    cs.writeString("VK_EXT_external_memory_dma_buf");
    // pEnabledFeatures = null
    cs.writeNull();
    // pAllocator = null
    cs.writeNull();
    // pDevice
    cs.writePresent();
    cs.writeU64(device_id);
}

/// Encode vkGetDeviceQueue2 (Venus requires Queue2, not Queue)
pub fn encodeGetDeviceQueue(
    cs: *CmdStream,
    device_id: u64,
    queue_family: u32,
    queue_index: u32,
    queue_id: u64,
) void {
    cs.cmdHeader(CMD_vkGetDeviceQueue2, 0);
    cs.writeU64(device_id); // device handle
    // pQueueInfo (VkDeviceQueueInfo2 struct)
    cs.writePresent();
    cs.writeU32(1000145003); // sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_INFO_2
    // pNext -> VkDeviceQueueTimelineInfoMESA (required by Venus)
    cs.writePresent();
    cs.writeU32(1000384005); // sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_TIMELINE_INFO_MESA
    cs.writeNull(); // pNext = null (no further chain)
    cs.writeU32(1); // ringIdx = 1 (must be non-zero)
    // VkDeviceQueueInfo2 fields
    cs.writeU32(0); // flags
    cs.writeU32(queue_family);
    cs.writeU32(queue_index);
    // pQueue
    cs.writePresent();
    cs.writeU64(queue_id);
}

/// Encode vkCreateCommandPool
pub fn encodeCreateCommandPool(
    cs: *CmdStream,
    device_id: u64,
    queue_family: u32,
    pool_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateCommandPool, 0);
    cs.writeU64(device_id);

    // pCreateInfo
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0x02); // flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT
    cs.writeU32(queue_family);

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pCommandPool
    cs.writeU64(pool_id);
}

/// Encode vkAllocateCommandBuffers
pub fn encodeAllocateCommandBuffers(
    cs: *CmdStream,
    device_id: u64,
    pool_id: u64,
    cmd_buf_id: u64,
) void {
    cs.cmdHeader(CMD_vkAllocateCommandBuffers, 0);
    cs.writeU64(device_id);

    // pAllocateInfo
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU64(pool_id); // commandPool handle
    cs.writeU32(0); // level = VK_COMMAND_BUFFER_LEVEL_PRIMARY
    cs.writeU32(1); // commandBufferCount

    // pCommandBuffers array (size 1)
    cs.writeU64(1);
    cs.writeU64(cmd_buf_id);
}

/// Encode vkBeginCommandBuffer
pub fn encodeBeginCommandBuffer(cs: *CmdStream, cmd_buf_id: u64) void {
    cs.cmdHeader(CMD_vkBeginCommandBuffer, 0);
    cs.writeU64(cmd_buf_id);

    // pBeginInfo
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0x00); // flags = 0 (reusable command buffer, re-recorded each frame)
    cs.writeNull(); // pInheritanceInfo = null
}

/// Encode vkResetCommandPool — reset all command buffers in `pool_id` back to
/// the initial state. Use as a per-frame reset when the host's implicit-reset
/// path on vkBeginCommandBuffer doesn't take (Lavapipe via Venus has been
/// observed to silently ignore re-recordings of the same buffer).
pub fn encodeResetCommandPool(cs: *CmdStream, device_id: u64, pool_id: u64) void {
    cs.cmdHeader(CMD_vkResetCommandPool, 0);
    cs.writeU64(device_id);
    cs.writeU64(pool_id);
    cs.writeU32(0); // flags = 0 (no RELEASE_RESOURCES)
}

/// Encode vkEndCommandBuffer
pub fn encodeEndCommandBuffer(cs: *CmdStream, cmd_buf_id: u64) void {
    cs.cmdHeader(CMD_vkEndCommandBuffer, 0);
    cs.writeU64(cmd_buf_id);
}

/// Encode vkCmdBeginRenderPass
pub fn encodeCmdBeginRenderPass(
    cs: *CmdStream,
    cmd_buf_id: u64,
    render_pass_id: u64,
    framebuffer_id: u64,
    w: u32,
    h: u32,
) void {
    cs.cmdHeader(CMD_vkCmdBeginRenderPass, 0);
    cs.writeU64(cmd_buf_id);

    // pRenderPassBegin
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU64(render_pass_id); // renderPass handle
    cs.writeU64(framebuffer_id); // framebuffer handle
    // renderArea: VkRect2D { offset: {0,0}, extent: {w,h} }
    cs.writeU32(0); // offset.x
    cs.writeU32(0); // offset.y
    cs.writeU32(w); // extent.width
    cs.writeU32(h); // extent.height
    // clearValueCount = 1
    cs.writeU32(1);
    // pClearValues array (size 1)
    cs.writeU64(1);
    // VkClearValue union: tag 0 = color
    cs.writeU32(0); // VkClearValue tag: color
    // VkClearColorValue union: tag 0 = float32
    cs.writeU32(0); // VkClearColorValue tag: float32
    cs.writeU64(4); // array size = 4
    cs.writeF32(0.0); // r
    cs.writeF32(0.0); // g
    cs.writeF32(0.0); // b
    cs.writeF32(1.0); // a

    // VkSubpassContents = VK_SUBPASS_CONTENTS_INLINE (0)
    cs.writeU32(0);
}

/// Encode vkCmdBindPipeline
pub fn encodeCmdBindPipeline(
    cs: *CmdStream,
    cmd_buf_id: u64,
    pipeline_id: u64,
) void {
    cs.cmdHeader(CMD_vkCmdBindPipeline, 0);
    cs.writeU64(cmd_buf_id);
    cs.writeU32(0); // VK_PIPELINE_BIND_POINT_GRAPHICS
    cs.writeU64(pipeline_id);
}

/// Encode vkCmdDraw
pub fn encodeCmdDraw(
    cs: *CmdStream,
    cmd_buf_id: u64,
    vertex_count: u32,
    instance_count: u32,
) void {
    cs.cmdHeader(CMD_vkCmdDraw, 0);
    cs.writeU64(cmd_buf_id);
    cs.writeU32(vertex_count);
    cs.writeU32(instance_count);
    cs.writeU32(0); // firstVertex
    cs.writeU32(0); // firstInstance
}

/// Encode vkCmdEndRenderPass
pub fn encodeCmdEndRenderPass(cs: *CmdStream, cmd_buf_id: u64) void {
    cs.cmdHeader(CMD_vkCmdEndRenderPass, 0);
    cs.writeU64(cmd_buf_id);
}

/// Encode vkQueueSubmit (single command buffer, no semaphores)
pub fn encodeQueueSubmit(
    cs: *CmdStream,
    queue_id: u64,
    cmd_buf_id: u64,
) void {
    cs.cmdHeader(CMD_vkQueueSubmit, 0);
    cs.writeU64(queue_id);

    // submitCount = 1
    cs.writeU32(1);
    // pSubmits array (size 1)
    cs.writeU64(1);
    // VkSubmitInfo
    cs.writeU32(VK_STRUCTURE_TYPE_SUBMIT_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0); // waitSemaphoreCount
    cs.writeU64(0); // pWaitSemaphores = null
    cs.writeU64(0); // pWaitDstStageMask = null
    cs.writeU32(1); // commandBufferCount
    cs.writeU64(1); // pCommandBuffers array (size 1)
    cs.writeU64(cmd_buf_id);
    cs.writeU32(0); // signalSemaphoreCount
    cs.writeU64(0); // pSignalSemaphores = null

    // fence = VK_NULL_HANDLE
    cs.writeU64(0);
}

/// Encode vkDeviceWaitIdle
pub fn encodeDeviceWaitIdle(cs: *CmdStream, device_id: u64) void {
    cs.cmdHeader(CMD_vkDeviceWaitIdle, 0);
    cs.writeU64(device_id);
}

/// Encode vkQueueWaitIdle. Queue-level wait — finer-grained than DeviceWaitIdle
/// and (per Lavapipe-via-Venus observation) doesn't escalate validation hiccups
/// to VK_ERROR_DEVICE_LOST the way DeviceWaitIdle does.
pub fn encodeQueueWaitIdle(cs: *CmdStream, queue_id: u64) void {
    cs.cmdHeader(CMD_vkQueueWaitIdle, 0);
    cs.writeU64(queue_id);
}

// --- Fence-based sync (the only path Venus actually implements) ---
//
// virglrenderer's vkr_dispatch_vkDeviceWaitIdle and vkr_dispatch_vkQueueWaitIdle
// are stubbed:
//
//     /* no blocking call */
//     vkr_context_set_fatal(ctx);
//
// — i.e. calling either of those instantly invalidates the context. The host
// destroys the device, all subsequent submits go into the void, the cube's
// dma-buf-backed render image is never written. That's exactly what kept
// `pixel_ptr` at zero for thousands of frames.
//
// vkWaitForFences IS implemented (vkr_queue.c calls vk->WaitForFences with
// the real timeout), so the fix is: submit with a fence, wait on the fence,
// reset the fence, repeat.

/// Encode vkCreateFence. flags=0 for unsignaled, 1 for VK_FENCE_CREATE_SIGNALED_BIT.
pub fn encodeCreateFence(cs: *CmdStream, device_id: u64, flags: u32, fence_id: u64) void {
    cs.cmdHeader(CMD_vkCreateFence, 0);
    cs.writeU64(device_id);

    cs.writePresent(); // pCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_FENCE_CREATE_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(flags); // VkFenceCreateFlags

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pFence
    cs.writeU64(fence_id);
}

/// Encode vkResetFences for a single fence.
pub fn encodeResetFences(cs: *CmdStream, device_id: u64, fence_id: u64) void {
    cs.cmdHeader(CMD_vkResetFences, 0);
    cs.writeU64(device_id);
    cs.writeU32(1); // fenceCount
    cs.writeU64(1); // array_size
    cs.writeU64(fence_id);
}

/// Encode vkWaitForFences for a single fence with `timeout_ns` nanoseconds.
/// Sets the GENERATE_REPLY flag — the reply has VkResult at offset 4 and is
/// readable via readReplyResult. Pass UINT64_MAX for "wait forever".
pub fn encodeWaitForFences(cs: *CmdStream, device_id: u64, fence_id: u64, timeout_ns: u64) void {
    cs.cmdHeader(CMD_vkWaitForFences, CMD_FLAG_GENERATE_REPLY);
    cs.writeU64(device_id);
    cs.writeU32(1); // fenceCount
    cs.writeU64(1); // array_size
    cs.writeU64(fence_id);
    cs.writeU32(1); // waitAll = VK_TRUE
    cs.writeU64(timeout_ns);
}

/// Encode vkQueueSubmit with a fence to signal on completion. Same body as
/// encodeQueueSubmit but writes fence_id at the trailing fence slot instead
/// of VK_NULL_HANDLE.
pub fn encodeQueueSubmitFence(cs: *CmdStream, queue_id: u64, cmd_buf_id: u64, fence_id: u64) void {
    cs.cmdHeader(CMD_vkQueueSubmit, 0);
    cs.writeU64(queue_id);

    cs.writeU32(1); // submitCount
    cs.writeU64(1); // pSubmits array_size
    cs.writeU32(VK_STRUCTURE_TYPE_SUBMIT_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0); // waitSemaphoreCount
    cs.writeU64(0); // pWaitSemaphores = null
    cs.writeU64(0); // pWaitDstStageMask = null
    cs.writeU32(1); // commandBufferCount
    cs.writeU64(1); // pCommandBuffers array_size
    cs.writeU64(cmd_buf_id);
    cs.writeU32(0); // signalSemaphoreCount
    cs.writeU64(0); // pSignalSemaphores = null

    cs.writeU64(fence_id); // fence
}

/// Encode vkCreateRenderPass (single color attachment, clear+store)
pub fn encodeCreateRenderPass(
    cs: *CmdStream,
    device_id: u64,
    format: u32,
    render_pass_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateRenderPass, 0);
    cs.writeU64(device_id);

    // pCreateInfo
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags

    // attachmentCount = 1
    cs.writeU32(1);
    // pAttachments array (size 1)
    cs.writeU64(1);
    // VkAttachmentDescription
    cs.writeU32(0); // flags
    cs.writeU32(format); // format
    cs.writeU32(1); // samples = VK_SAMPLE_COUNT_1_BIT
    cs.writeU32(1); // loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR
    cs.writeU32(0); // storeOp = VK_ATTACHMENT_STORE_OP_STORE
    cs.writeU32(2); // stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE
    cs.writeU32(1); // stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE
    cs.writeU32(0); // initialLayout = VK_IMAGE_LAYOUT_UNDEFINED
    cs.writeU32(2); // finalLayout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL

    // subpassCount = 1
    cs.writeU32(1);
    // pSubpasses array (size 1)
    cs.writeU64(1);
    // VkSubpassDescription
    cs.writeU32(0); // flags
    cs.writeU32(0); // pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS
    cs.writeU32(0); // inputAttachmentCount
    cs.writeU64(0); // pInputAttachments = null
    cs.writeU32(1); // colorAttachmentCount
    cs.writeU64(1); // pColorAttachments array (size 1)
    // VkAttachmentReference
    cs.writeU32(0); // attachment index
    cs.writeU32(2); // layout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL
    cs.writeNull(); // pResolveAttachments = null
    cs.writeNull(); // pDepthStencilAttachment = null
    cs.writeU32(0); // preserveAttachmentCount
    cs.writeU64(0); // pPreserveAttachments = null

    // dependencyCount = 0
    cs.writeU32(0);
    cs.writeU64(0); // pDependencies = null

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pRenderPass
    cs.writeU64(render_pass_id);
}

/// Encode vkCreatePipelineLayout (empty — no descriptors)
pub fn encodeCreatePipelineLayout(
    cs: *CmdStream,
    device_id: u64,
    layout_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreatePipelineLayout, 0);
    cs.writeU64(device_id);

    // pCreateInfo
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(0); // setLayoutCount
    cs.writeU64(0); // pSetLayouts = null
    cs.writeU32(0); // pushConstantRangeCount
    cs.writeU64(0); // pPushConstantRanges = null

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pPipelineLayout
    cs.writeU64(layout_id);
}

/// Encode vkCreateShaderModule
pub fn encodeCreateShaderModule(
    cs: *CmdStream,
    device_id: u64,
    spirv_code: []const u32,
    module_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateShaderModule, 0);
    cs.writeU64(device_id);

    // pCreateInfo
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU64(spirv_code.len * 4); // codeSize (in bytes) — encoded as size_t (u64)
    // pCode array — array size is element count (u32 words), NOT byte count
    cs.writeU64(spirv_code.len); // array size in u32 elements
    for (spirv_code) |word| {
        cs.writeU32(word);
    }

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pShaderModule
    cs.writeU64(module_id);
}

/// Encode vkCreateFramebuffer
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

    // pCreateInfo
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU64(render_pass_id); // renderPass handle
    cs.writeU32(1); // attachmentCount
    cs.writeU64(1); // pAttachments array (size 1)
    cs.writeU64(image_view_id); // attachment[0]
    cs.writeU32(w); // width
    cs.writeU32(h); // height
    cs.writeU32(1); // layers

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pFramebuffer
    cs.writeU64(fb_id);
}

/// Encode vkCreateImage (2D, single sample, single mip/layer)
pub fn encodeCreateImage(
    cs: *CmdStream,
    device_id: u64,
    w: u32,
    h: u32,
    format: u32,
    usage: u32,
    image_id: u64,
) void {
    encodeCreateImageImpl(cs, device_id, w, h, format, usage, image_id, false);
}

/// Like encodeCreateImage but with VkExternalMemoryImageCreateInfo in pNext
/// declaring DMA_BUF handle type. Required when binding the image to memory
/// allocated via encodeAllocateMemoryExportable — Vulkan validation rejects
/// the bind with VUID-vkBindImageMemory-memory-02728 if the external handle
/// types don't match. (Khronos validation layer caught this; the spec
/// section is "External Memory Handle Types".)
pub fn encodeCreateImageExportable(
    cs: *CmdStream,
    device_id: u64,
    w: u32,
    h: u32,
    format: u32,
    usage: u32,
    image_id: u64,
) void {
    encodeCreateImageImpl(cs, device_id, w, h, format, usage, image_id, true);
}

fn encodeCreateImageImpl(
    cs: *CmdStream,
    device_id: u64,
    w: u32,
    h: u32,
    format: u32,
    usage: u32,
    image_id: u64,
    exportable: bool,
) void {
    cs.cmdHeader(CMD_vkCreateImage, 0);
    cs.writeU64(device_id);

    cs.writePresent(); // pCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO); // sType
    if (exportable) {
        // pNext → VkExternalMemoryImageCreateInfo
        cs.writePresent();
        cs.writeU32(1000072001); // VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_IMAGE_CREATE_INFO
        cs.writeNull(); // pNext of external info
        cs.writeU32(0x200); // handleTypes = DMA_BUF (matches export memory alloc)
    } else {
        cs.writeNull(); // pNext = null
    }
    cs.writeU32(0); // flags
    cs.writeU32(1); // imageType = VK_IMAGE_TYPE_2D
    cs.writeU32(format);
    // VkExtent3D
    cs.writeU32(w);
    cs.writeU32(h);
    cs.writeU32(1); // depth
    cs.writeU32(1); // mipLevels
    cs.writeU32(1); // arrayLayers
    cs.writeU32(1); // samples = VK_SAMPLE_COUNT_1_BIT
    cs.writeU32(0); // tiling = VK_IMAGE_TILING_OPTIMAL
    cs.writeU32(usage);
    cs.writeU32(0); // sharingMode = VK_SHARING_MODE_EXCLUSIVE
    cs.writeU32(0); // queueFamilyIndexCount
    cs.writeU64(0); // pQueueFamilyIndices = null
    cs.writeU32(0); // initialLayout = VK_IMAGE_LAYOUT_UNDEFINED

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pImage
    cs.writeU64(image_id);
}

/// Encode vkCreateImageView
pub fn encodeCreateImageView(
    cs: *CmdStream,
    device_id: u64,
    image_id: u64,
    format: u32,
    view_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateImageView, 0);
    cs.writeU64(device_id);

    cs.writePresent(); // pCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU64(image_id); // image handle
    cs.writeU32(1); // viewType = VK_IMAGE_VIEW_TYPE_2D
    cs.writeU32(format);
    // VkComponentMapping (identity)
    cs.writeU32(0); // r = IDENTITY
    cs.writeU32(0); // g
    cs.writeU32(0); // b
    cs.writeU32(0); // a
    // VkImageSubresourceRange
    cs.writeU32(1); // aspectMask = VK_IMAGE_ASPECT_COLOR_BIT
    cs.writeU32(0); // baseMipLevel
    cs.writeU32(1); // levelCount
    cs.writeU32(0); // baseArrayLayer
    cs.writeU32(1); // layerCount

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pImageView
    cs.writeU64(view_id);
}

/// Encode vkAllocateMemory
pub fn encodeAllocateMemory(
    cs: *CmdStream,
    device_id: u64,
    alloc_size: u64,
    memory_type_index: u32,
    memory_id: u64,
) void {
    cs.cmdHeader(CMD_vkAllocateMemory, 0);
    cs.writeU64(device_id);

    cs.writePresent(); // pAllocateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO); // sType
    cs.writeNull(); // pNext (no export)
    cs.writeU64(alloc_size); // allocationSize (VkDeviceSize = u64)
    cs.writeU32(memory_type_index);

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pMemory
    cs.writeU64(memory_id);
}

/// Encode vkAllocateMemory chained with VkImportMemoryResourceInfoMESA —
/// imports a virtio-gpu resource (typically a BLOB_MEM_GUEST resource)
/// as the VkDeviceMemory's storage. Lavapipe's writes go directly to
/// the resource's pages (which are guest-mapped), so the guest reads
/// see what Lavapipe wrote. This is the path that actually delivers
/// rendered pixels — pair with `libc.gpuCreateGuestBlob` to obtain
/// `resource_id`. sType verified against vn_protocol_driver_defines.h.
pub const VK_STRUCTURE_TYPE_IMPORT_MEMORY_RESOURCE_INFO_MESA: u32 = 1000384002;

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
    // pNext chain: Import -> Export -> NULL.
    // Import marks the resource as the storage; Export declares the
    // DMA_BUF handle type so validation lets us bind to images created
    // via encodeCreateImageExportable (which themselves declare DMA_BUF).
    cs.writePresent(); // outer pNext -> Import
    cs.writeU32(VK_STRUCTURE_TYPE_IMPORT_MEMORY_RESOURCE_INFO_MESA);
    cs.writePresent(); // import pNext -> Export
    cs.writeU32(1000072002); // VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO
    cs.writeNull(); // export pNext
    cs.writeU32(0x200); // handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT
    cs.writeU32(resource_id); // back to ImportInfo's resourceId
    // resume VkMemoryAllocateInfo fields
    cs.writeU64(alloc_size);
    cs.writeU32(memory_type_index);

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pMemory
    cs.writeU64(memory_id);
}

/// Encode vkAllocateMemory with VkExportMemoryAllocateInfo for blob export
// --- vkGetPhysicalDeviceMemoryProperties ---
// We need to query memory types because hardcoding `memory_type_index = 0`
// is what kept the cube's pixel buffer at all-zeros: Lavapipe enumerates
// multiple types and only the ones with HOST_VISIBLE | HOST_COHERENT
// produce a CPU-mappable dma-buf when exported. Without those bits the
// host's mmap of the dma-buf is opaque and the SHM-BAR path reads zeros.

pub const VK_MAX_MEMORY_TYPES: u32 = 32;
pub const VK_MAX_MEMORY_HEAPS: u32 = 16;

pub const VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT: u32 = 0x1;
pub const VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT: u32 = 0x2;
pub const VK_MEMORY_PROPERTY_HOST_COHERENT_BIT: u32 = 0x4;
pub const VK_MEMORY_PROPERTY_HOST_CACHED_BIT: u32 = 0x8;

pub const MemoryType = struct {
    property_flags: u32,
    heap_index: u32,
};

pub const MemoryProperties = struct {
    memory_type_count: u32,
    memory_types: [VK_MAX_MEMORY_TYPES]MemoryType,
    memory_heap_count: u32,
};

/// Encode vkGetPhysicalDeviceMemoryProperties. Reply carries the populated
/// VkPhysicalDeviceMemoryProperties — feed reply_buf into
/// `decodeMemoryPropertiesReply`. The request body is just placeholders
/// (partial_partial = 0 bytes per type/heap entry plus the array-size
/// headers) — we tell the renderer how many slots to fill, not what to
/// fill them with.
pub fn encodeGetPhysicalDeviceMemoryProperties(cs: *CmdStream, phys_dev_id: u64) void {
    cs.cmdHeader(CMD_vkGetPhysicalDeviceMemoryProperties, CMD_FLAG_GENERATE_REPLY);
    cs.writeU64(phys_dev_id);
    cs.writePresent(); // pMemoryProperties pointer present
    cs.writeU64(VK_MAX_MEMORY_TYPES); // array_size for memoryTypes (each elem partial = 0 bytes)
    cs.writeU64(VK_MAX_MEMORY_HEAPS); // array_size for memoryHeaps (each elem partial = 0 bytes)
}

inline fn r32(buf: [*]volatile const u8, off: usize) u32 {
    const ptr: *align(1) const volatile u32 = @ptrCast(buf + off);
    return ptr.*;
}
inline fn r64(buf: [*]volatile const u8, off: usize) u64 {
    const ptr: *align(1) const volatile u64 = @ptrCast(buf + off);
    return ptr.*;
}

/// Decode the reply for vkGetPhysicalDeviceMemoryProperties.
/// Reply format (per Mesa vn_decode_VkPhysicalDeviceMemoryProperties):
///   u32 cmd_type
///   u64 simple_pointer (1 = present, 0 = null)
///   if present:
///     u32 memoryTypeCount
///     u64 array_size (= 32)
///     32 × { u32 propertyFlags; u32 heapIndex }
///     u32 memoryHeapCount
///     u64 array_size (= 16)
///     16 × { u64 size; u32 flags } — heaps; we skip them (caller doesn't need them)
pub fn decodeMemoryPropertiesReply(reply_buf: [*]volatile const u8) MemoryProperties {
    var props: MemoryProperties = .{
        .memory_type_count = 0,
        .memory_types = undefined,
        .memory_heap_count = 0,
    };
    var p: usize = 4; // skip cmd_type
    const present = r64(reply_buf, p);
    p += 8;
    if (present == 0) return props;

    props.memory_type_count = r32(reply_buf, p);
    p += 4;
    _ = r64(reply_buf, p); // array_size, expected 32
    p += 8;
    var i: u32 = 0;
    while (i < VK_MAX_MEMORY_TYPES) : (i += 1) {
        props.memory_types[i].property_flags = r32(reply_buf, p);
        p += 4;
        props.memory_types[i].heap_index = r32(reply_buf, p);
        p += 4;
    }
    props.memory_heap_count = r32(reply_buf, p);
    p += 4;
    // heaps follow but we don't read them — picking a memory type only needs flags.
    return props;
}

/// Find the first memory type whose property_flags satisfies `required`
/// bits and excludes `forbidden` bits. Returns null if none match.
pub fn pickMemoryType(props: *const MemoryProperties, required: u32, forbidden: u32) ?u32 {
    var i: u32 = 0;
    while (i < props.memory_type_count and i < VK_MAX_MEMORY_TYPES) : (i += 1) {
        const flags = props.memory_types[i].property_flags;
        if ((flags & required) == required and (flags & forbidden) == 0) return i;
    }
    return null;
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

    cs.writePresent(); // pAllocateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO); // sType
    // pNext -> VkExportMemoryAllocateInfo
    cs.writePresent();
    cs.writeU32(1000072002); // VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO
    cs.writeNull(); // pNext of export info
    cs.writeU32(0x200); // handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT
    // back to VkMemoryAllocateInfo fields
    cs.writeU64(alloc_size);
    cs.writeU32(memory_type_index);

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pMemory
    cs.writeU64(memory_id);
}

/// Encode vkBindImageMemory
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
    cs.writeU64(offset); // memoryOffset
}

/// Encode vkCreateGraphicsPipelines (single pipeline, minimal config)
pub fn encodeCreateGraphicsPipelines(
    cs: *CmdStream,
    device_id: u64,
    layout_id: u64,
    render_pass_id: u64,
    vert_module_id: u64,
    frag_module_id: u64,
    pipeline_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateGraphicsPipelines, 0);
    cs.writeU64(device_id);
    cs.writeU64(0); // pipelineCache = VK_NULL_HANDLE

    // createInfoCount = 1
    cs.writeU32(1);
    // pCreateInfos array (size 1)
    cs.writeU64(1);

    // VkGraphicsPipelineCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags

    // stageCount = 2
    cs.writeU32(2);
    // pStages array (size 2)
    cs.writeU64(2);

    // Vertex stage
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(0x01); // stage = VK_SHADER_STAGE_VERTEX_BIT
    cs.writeU64(vert_module_id);
    cs.writeString("main");
    cs.writeNull(); // pSpecializationInfo

    // Fragment stage
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(0x10); // stage = VK_SHADER_STAGE_FRAGMENT_BIT
    cs.writeU64(frag_module_id);
    cs.writeString("main");
    cs.writeNull(); // pSpecializationInfo

    // pVertexInputState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(0); // vertexBindingDescriptionCount
    cs.writeU64(0); // pVertexBindingDescriptions
    cs.writeU32(0); // vertexAttributeDescriptionCount
    cs.writeU64(0); // pVertexAttributeDescriptions

    // pInputAssemblyState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(3); // topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST
    cs.writeU32(0); // primitiveRestartEnable = false

    // pTessellationState = null
    cs.writeNull();

    // pViewportState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(1); // viewportCount
    // pViewports array (size 1)
    cs.writeU64(1);
    // VkViewport
    cs.writeF32(0.0); // x
    cs.writeF32(0.0); // y
    cs.writeF32(320.0); // width
    cs.writeF32(240.0); // height
    cs.writeF32(0.0); // minDepth
    cs.writeF32(1.0); // maxDepth
    cs.writeU32(1); // scissorCount
    // pScissors array (size 1)
    cs.writeU64(1);
    // VkRect2D
    cs.writeU32(0); // offset.x
    cs.writeU32(0); // offset.y
    cs.writeU32(320); // extent.width
    cs.writeU32(240); // extent.height

    // pRasterizationState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(0); // depthClampEnable
    cs.writeU32(0); // rasterizerDiscardEnable
    cs.writeU32(0); // polygonMode = VK_POLYGON_MODE_FILL
    cs.writeU32(0); // cullMode = NONE
    cs.writeU32(0); // frontFace = COUNTER_CLOCKWISE
    cs.writeU32(0); // depthBiasEnable
    cs.writeF32(0.0); // depthBiasConstantFactor
    cs.writeF32(0.0); // depthBiasClamp
    cs.writeF32(0.0); // depthBiasSlopeFactor
    cs.writeF32(1.0); // lineWidth

    // pMultisampleState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(1); // rasterizationSamples = VK_SAMPLE_COUNT_1_BIT
    cs.writeU32(0); // sampleShadingEnable
    cs.writeF32(1.0); // minSampleShading
    cs.writeNull(); // pSampleMask = null
    cs.writeU32(0); // alphaToCoverageEnable
    cs.writeU32(0); // alphaToOneEnable

    // pDepthStencilState = null
    cs.writeNull();

    // pColorBlendState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(0); // logicOpEnable
    cs.writeU32(0); // logicOp
    cs.writeU32(1); // attachmentCount
    // pAttachments array (size 1)
    cs.writeU64(1);
    // VkPipelineColorBlendAttachmentState
    cs.writeU32(0); // blendEnable = false
    cs.writeU32(1); // srcColorBlendFactor (ONE)
    cs.writeU32(0); // dstColorBlendFactor (ZERO)
    cs.writeU32(0); // colorBlendOp (ADD)
    cs.writeU32(1); // srcAlphaBlendFactor (ONE)
    cs.writeU32(0); // dstAlphaBlendFactor (ZERO)
    cs.writeU32(0); // alphaBlendOp (ADD)
    cs.writeU32(0xF); // colorWriteMask = RGBA
    // blendConstants array (size prefix + 4 floats)
    cs.writeU64(4); // array size = 4
    cs.writeF32(0.0);
    cs.writeF32(0.0);
    cs.writeF32(0.0);
    cs.writeF32(0.0);

    // pDynamicState = null
    cs.writeNull();

    // layout
    cs.writeU64(layout_id);
    // renderPass
    cs.writeU64(render_pass_id);
    // subpass
    cs.writeU32(0);
    // basePipelineHandle
    cs.writeU64(0);
    // basePipelineIndex
    cs.writeU32(@bitCast(@as(i32, -1)));

    cs.writeNull(); // pAllocator
    // pPipelines (size 1)
    cs.writeU64(1);
    cs.writeU64(pipeline_id);
}

/// Encode vkCmdCopyImageToBuffer (CMD=116) — copy full image to buffer
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
    cs.writeU32(image_layout); // srcImageLayout
    cs.writeU64(dst_buffer);
    // regionCount = 1
    cs.writeU32(1);
    cs.writeU64(1); // pRegions array size
    // VkBufferImageCopy
    cs.writeU64(0); // bufferOffset
    cs.writeU32(0); // bufferRowLength (0 = tightly packed)
    cs.writeU32(0); // bufferImageHeight (0 = tightly packed)
    // imageSubresource
    cs.writeU32(1); // aspectMask = COLOR
    cs.writeU32(0); // mipLevel
    cs.writeU32(0); // baseArrayLayer
    cs.writeU32(1); // layerCount
    // imageOffset
    cs.writeU32(0); // x
    cs.writeU32(0); // y
    cs.writeU32(0); // z
    // imageExtent
    cs.writeU32(width);
    cs.writeU32(height);
    cs.writeU32(1); // depth
}

/// Encode vkCmdUpdateBuffer (CMD=117) — copy inline data into dst_buffer.
/// dst_buffer must have VK_BUFFER_USAGE_TRANSFER_DST_BIT (0x02) usage.
/// The data travels inside the command stream itself, bypassing any
/// guest↔host blob memory sharing — useful when udmabuf isn't actually
/// engaged (validate.log shows udmabuf_fd=0). Per Vulkan spec: dataSize
/// must be a multiple of 4 and ≤ 65536 bytes.
pub fn encodeCmdUpdateBuffer(
    cs: *CmdStream,
    cmd_buf_id: u64,
    dst_buffer: u64,
    dst_offset: u64,
    data: []const u8,
) void {
    cs.cmdHeader(CMD_vkCmdUpdateBuffer, 0);
    cs.writeU64(cmd_buf_id);
    cs.writeU64(dst_buffer);
    cs.writeU64(dst_offset);
    cs.writeU64(@intCast(data.len)); // dataSize
    cs.writeU64(@intCast(data.len)); // array_size for inline blob
    cs.writeBytes(data);             // 4-byte aligned
}

/// Encode vkCmdPipelineBarrier with a single image memory barrier
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
    cs.writeU32(src_stage); // srcStageMask
    cs.writeU32(dst_stage); // dstStageMask
    cs.writeU32(0); // dependencyFlags
    // memoryBarrierCount = 0
    cs.writeU32(0);
    cs.writeU64(0); // pMemoryBarriers = null
    // bufferMemoryBarrierCount = 0
    cs.writeU32(0);
    cs.writeU64(0); // pBufferMemoryBarriers = null
    // imageMemoryBarrierCount = 1
    cs.writeU32(1);
    cs.writeU64(1); // pImageMemoryBarriers array size
    // VkImageMemoryBarrier
    cs.writeU32(45); // sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER
    cs.writeNull(); // pNext
    cs.writeU32(src_access); // srcAccessMask
    cs.writeU32(dst_access); // dstAccessMask
    cs.writeU32(old_layout);
    cs.writeU32(new_layout);
    cs.writeU32(0xFFFFFFFF); // srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED
    cs.writeU32(0xFFFFFFFF); // dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED
    cs.writeU64(image_id); // image handle
    // VkImageSubresourceRange
    cs.writeU32(1); // aspectMask = COLOR
    cs.writeU32(0); // baseMipLevel
    cs.writeU32(1); // levelCount
    cs.writeU32(0); // baseArrayLayer
    cs.writeU32(1); // layerCount
}

/// Encode vkCmdPipelineBarrier with a single memory barrier (no image/buffer specific)
pub fn encodeCmdMemoryBarrier(
    cs: *CmdStream,
    cmd_buf_id: u64,
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
    // memoryBarrierCount = 1
    cs.writeU32(1);
    cs.writeU64(1); // pMemoryBarriers array size
    // VkMemoryBarrier
    cs.writeU32(46); // sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER
    cs.writeNull(); // pNext
    cs.writeU32(src_access);
    cs.writeU32(dst_access);
    // bufferMemoryBarrierCount = 0
    cs.writeU32(0);
    cs.writeU64(0);
    // imageMemoryBarrierCount = 0
    cs.writeU32(0);
    cs.writeU64(0);
}

/// Encode vkCreateRenderPass with custom final layout
pub fn encodeCreateRenderPassEx(
    cs: *CmdStream,
    device_id: u64,
    format: u32,
    final_layout: u32,
    render_pass_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateRenderPass, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(1); // attachmentCount
    cs.writeU64(1); // pAttachments array
    // VkAttachmentDescription
    cs.writeU32(0); // flags
    cs.writeU32(format);
    cs.writeU32(1); // samples = 1
    cs.writeU32(1); // loadOp = CLEAR
    cs.writeU32(0); // storeOp = STORE
    cs.writeU32(2); // stencilLoadOp = DONT_CARE
    cs.writeU32(1); // stencilStoreOp = DONT_CARE
    cs.writeU32(0); // initialLayout = UNDEFINED
    cs.writeU32(final_layout);
    // subpasses
    cs.writeU32(1);
    cs.writeU64(1);
    cs.writeU32(0); // flags
    cs.writeU32(0); // pipelineBindPoint = GRAPHICS
    cs.writeU32(0); // inputAttachmentCount
    cs.writeU64(0);
    cs.writeU32(1); // colorAttachmentCount
    cs.writeU64(1);
    cs.writeU32(0); // attachment 0
    cs.writeU32(2); // layout = COLOR_ATTACHMENT_OPTIMAL
    cs.writeNull(); // pResolveAttachments
    cs.writeNull(); // pDepthStencilAttachment
    cs.writeU32(0); // preserveAttachmentCount
    cs.writeU64(0);
    // dependencies
    cs.writeU32(0);
    cs.writeU64(0);
    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(render_pass_id);
}

// ===== New encode functions for spinning cube =====

/// Encode vkCreateBuffer (CMD=50)
pub fn encodeCreateBuffer(
    cs: *CmdStream,
    device_id: u64,
    size: u64,
    usage: u32,
    buffer_id: u64,
) void {
    encodeCreateBufferImpl(cs, device_id, size, usage, buffer_id, false);
}

/// Same as encodeCreateBuffer but with VkExternalMemoryBufferCreateInfo in
/// pNext declaring DMA_BUF handle type. Pair with encodeAllocateMemoryExportable.
pub fn encodeCreateBufferExportable(
    cs: *CmdStream,
    device_id: u64,
    size: u64,
    usage: u32,
    buffer_id: u64,
) void {
    encodeCreateBufferImpl(cs, device_id, size, usage, buffer_id, true);
}

fn encodeCreateBufferImpl(
    cs: *CmdStream,
    device_id: u64,
    size: u64,
    usage: u32,
    buffer_id: u64,
    exportable: bool,
) void {
    cs.cmdHeader(CMD_vkCreateBuffer, 0);
    cs.writeU64(device_id);

    cs.writePresent(); // pCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO); // sType
    if (exportable) {
        cs.writePresent(); // pNext → VkExternalMemoryBufferCreateInfo
        cs.writeU32(1000072000); // VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO
        cs.writeNull(); // pNext of external info
        cs.writeU32(0x200); // handleTypes = DMA_BUF
    } else {
        cs.writeNull(); // pNext = null
    }
    cs.writeU32(0); // flags
    cs.writeU64(size); // size (VkDeviceSize)
    cs.writeU32(usage); // usage
    cs.writeU32(0); // sharingMode = EXCLUSIVE
    cs.writeU32(0); // queueFamilyIndexCount
    cs.writeU64(0); // pQueueFamilyIndices = null

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pBuffer
    cs.writeU64(buffer_id);
}

/// Encode vkBindBufferMemory (CMD=28)
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

/// Encode vkCmdBindVertexBuffers (CMD=105) — single buffer binding
pub fn encodeCmdBindVertexBuffers(
    cs: *CmdStream,
    cmd_buf_id: u64,
    buffer_id: u64,
) void {
    cs.cmdHeader(CMD_vkCmdBindVertexBuffers, 0);
    cs.writeU64(cmd_buf_id);
    cs.writeU32(0); // firstBinding
    cs.writeU32(1); // bindingCount
    cs.writeU64(1); // pBuffers array size
    cs.writeU64(buffer_id);
    cs.writeU64(1); // pOffsets array size
    cs.writeU64(0); // offset = 0
}

/// Encode vkCmdPushConstants (CMD=132)
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
    cs.writeU32(0); // offset
    cs.writeU32(@intCast(data.len)); // size
    cs.writeU64(data.len); // pValues array size (byte count)
    cs.writeBytes(data);
}

/// Encode vkCreatePipelineLayout with push constant range (CMD=68)
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
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO); // sType
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU32(0); // setLayoutCount
    cs.writeU64(0); // pSetLayouts = null
    cs.writeU32(1); // pushConstantRangeCount
    cs.writeU64(1); // pPushConstantRanges array size
    // VkPushConstantRange
    cs.writeU32(push_stage_flags); // stageFlags
    cs.writeU32(0); // offset
    cs.writeU32(push_size); // size

    cs.writeNull(); // pAllocator
    cs.writePresent(); // pPipelineLayout
    cs.writeU64(layout_id);
}

/// Encode vkCreateRenderPass with color + depth attachments
pub fn encodeCreateRenderPassDepth(
    cs: *CmdStream,
    device_id: u64,
    color_format: u32,
    depth_format: u32,
    render_pass_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateRenderPass, 0);
    cs.writeU64(device_id);
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags

    // 2 attachments
    cs.writeU32(2); // attachmentCount
    cs.writeU64(2); // pAttachments array size

    // Attachment 0: color
    cs.writeU32(0); // flags
    cs.writeU32(color_format);
    cs.writeU32(1); // samples = 1
    cs.writeU32(1); // loadOp = CLEAR
    cs.writeU32(0); // storeOp = STORE
    cs.writeU32(2); // stencilLoadOp = DONT_CARE
    cs.writeU32(1); // stencilStoreOp = DONT_CARE
    cs.writeU32(0); // initialLayout = UNDEFINED
    cs.writeU32(2); // finalLayout = COLOR_ATTACHMENT_OPTIMAL

    // Attachment 1: depth
    cs.writeU32(0); // flags
    cs.writeU32(depth_format);
    cs.writeU32(1); // samples = 1
    cs.writeU32(1); // loadOp = CLEAR
    cs.writeU32(1); // storeOp = DONT_CARE
    cs.writeU32(2); // stencilLoadOp = DONT_CARE
    cs.writeU32(1); // stencilStoreOp = DONT_CARE
    cs.writeU32(0); // initialLayout = UNDEFINED
    cs.writeU32(3); // finalLayout = DEPTH_STENCIL_ATTACHMENT_OPTIMAL

    // 1 subpass
    cs.writeU32(1); // subpassCount
    cs.writeU64(1); // pSubpasses array
    cs.writeU32(0); // flags
    cs.writeU32(0); // pipelineBindPoint = GRAPHICS
    cs.writeU32(0); // inputAttachmentCount
    cs.writeU64(0); // pInputAttachments = null
    cs.writeU32(1); // colorAttachmentCount
    cs.writeU64(1); // pColorAttachments array
    cs.writeU32(0); // attachment 0
    cs.writeU32(2); // layout = COLOR_ATTACHMENT_OPTIMAL
    cs.writeNull(); // pResolveAttachments = null
    // pDepthStencilAttachment — PRESENT
    cs.writePresent();
    cs.writeU32(1); // attachment 1
    cs.writeU32(3); // layout = DEPTH_STENCIL_ATTACHMENT_OPTIMAL
    cs.writeU32(0); // preserveAttachmentCount
    cs.writeU64(0); // pPreserveAttachments = null

    // dependencies
    cs.writeU32(0);
    cs.writeU64(0);
    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(render_pass_id);
}

/// Encode vkCreateFramebuffer with 2 attachments (color + depth)
pub fn encodeCreateFramebuffer2(
    cs: *CmdStream,
    device_id: u64,
    render_pass_id: u64,
    color_view_id: u64,
    depth_view_id: u64,
    w: u32,
    h: u32,
    fb_id: u64,
) void {
    cs.cmdHeader(CMD_vkCreateFramebuffer, 0);
    cs.writeU64(device_id);

    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU64(render_pass_id);
    cs.writeU32(2); // attachmentCount
    cs.writeU64(2); // pAttachments array size
    cs.writeU64(color_view_id);
    cs.writeU64(depth_view_id);
    cs.writeU32(w);
    cs.writeU32(h);
    cs.writeU32(1); // layers

    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(fb_id);
}

/// Encode vkCreateImageView with configurable aspect mask
pub fn encodeCreateImageViewEx(
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
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    cs.writeU64(image_id);
    cs.writeU32(1); // viewType = 2D
    cs.writeU32(format);
    // VkComponentMapping (identity)
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0);
    // VkImageSubresourceRange
    cs.writeU32(aspect_mask);
    cs.writeU32(0); // baseMipLevel
    cs.writeU32(1); // levelCount
    cs.writeU32(0); // baseArrayLayer
    cs.writeU32(1); // layerCount

    cs.writeNull(); // pAllocator
    cs.writePresent();
    cs.writeU64(view_id);
}

/// Encode vkCreateGraphicsPipelines with vertex input, depth test, and configurable viewport
pub fn encodeCreateGraphicsPipelinesCube(
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
    cs.writeU64(0); // pipelineCache = VK_NULL_HANDLE

    cs.writeU32(1); // createInfoCount
    cs.writeU64(1); // pCreateInfos array

    // VkGraphicsPipelineCreateInfo
    cs.writeU32(VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags

    // 2 shader stages
    cs.writeU32(2);
    cs.writeU64(2);

    // Vertex stage
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writeU32(0x01); // VERTEX_BIT
    cs.writeU64(vert_module_id);
    cs.writeString("main");
    cs.writeNull(); // pSpecializationInfo

    // Fragment stage
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(0x10); // FRAGMENT_BIT
    cs.writeU64(frag_module_id);
    cs.writeString("main");
    cs.writeNull(); // pSpecializationInfo

    // pVertexInputState — 1 binding, 3 attributes (pos, normal, color)
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writeU32(1); // vertexBindingDescriptionCount
    cs.writeU64(1); // array size
    // VkVertexInputBindingDescription
    cs.writeU32(0); // binding
    cs.writeU32(36); // stride (3+3+3 floats = 36 bytes)
    cs.writeU32(0); // inputRate = VERTEX
    cs.writeU32(3); // vertexAttributeDescriptionCount
    cs.writeU64(3); // array size
    // Attribute 0: position (vec3)
    cs.writeU32(0); // location
    cs.writeU32(0); // binding
    cs.writeU32(106); // format = VK_FORMAT_R32G32B32_SFLOAT
    cs.writeU32(0); // offset
    // Attribute 1: normal (vec3)
    cs.writeU32(1); // location
    cs.writeU32(0); // binding
    cs.writeU32(106); // format = VK_FORMAT_R32G32B32_SFLOAT
    cs.writeU32(12); // offset
    // Attribute 2: color (vec3)
    cs.writeU32(2); // location
    cs.writeU32(0); // binding
    cs.writeU32(106); // format = VK_FORMAT_R32G32B32_SFLOAT
    cs.writeU32(24); // offset

    // pInputAssemblyState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(3); // TRIANGLE_LIST
    cs.writeU32(0); // primitiveRestartEnable = false

    // pTessellationState = null
    cs.writeNull();

    // pViewportState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0);
    cs.writeU32(1); // viewportCount
    cs.writeU64(1);
    const fw: f32 = @floatFromInt(width);
    const fh: f32 = @floatFromInt(height);
    cs.writeF32(0.0);
    cs.writeF32(0.0);
    cs.writeF32(fw);
    cs.writeF32(fh);
    cs.writeF32(0.0);
    cs.writeF32(1.0);
    cs.writeU32(1); // scissorCount
    cs.writeU64(1);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(width);
    cs.writeU32(height);

    // pRasterizationState — with back-face culling
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
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
    cs.writeU32(1); // rasterizationSamples = 1
    cs.writeU32(0); // sampleShadingEnable
    cs.writeF32(1.0);
    cs.writeNull(); // pSampleMask
    cs.writeU32(0); // alphaToCoverageEnable
    cs.writeU32(0); // alphaToOneEnable

    // pDepthStencilState — depth test enabled
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_DEPTH_STENCIL_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writeU32(1); // depthTestEnable = TRUE
    cs.writeU32(1); // depthWriteEnable = TRUE
    cs.writeU32(1); // depthCompareOp = LESS
    cs.writeU32(0); // depthBoundsTestEnable = FALSE
    cs.writeU32(0); // stencilTestEnable = FALSE
    // front VkStencilOpState (7 u32s, all zero)
    cs.writeU32(0); // failOp
    cs.writeU32(0); // passOp
    cs.writeU32(0); // depthFailOp
    cs.writeU32(0); // compareOp
    cs.writeU32(0); // compareMask
    cs.writeU32(0); // writeMask
    cs.writeU32(0); // reference
    // back VkStencilOpState (7 u32s, all zero)
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeU32(0);
    cs.writeF32(0.0); // minDepthBounds
    cs.writeF32(1.0); // maxDepthBounds

    // pColorBlendState
    cs.writePresent();
    cs.writeU32(VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO);
    cs.writeNull();
    cs.writeU32(0); // flags
    cs.writeU32(0); // logicOpEnable
    cs.writeU32(0); // logicOp
    cs.writeU32(1); // attachmentCount
    cs.writeU64(1);
    cs.writeU32(0); // blendEnable = false
    cs.writeU32(1); // srcColorBlendFactor (ONE)
    cs.writeU32(0); // dstColorBlendFactor (ZERO)
    cs.writeU32(0); // colorBlendOp (ADD)
    cs.writeU32(1); // srcAlphaBlendFactor (ONE)
    cs.writeU32(0); // dstAlphaBlendFactor (ZERO)
    cs.writeU32(0); // alphaBlendOp (ADD)
    cs.writeU32(0xF); // colorWriteMask = RGBA
    cs.writeU64(4); // blendConstants array
    cs.writeF32(0.0);
    cs.writeF32(0.0);
    cs.writeF32(0.0);
    cs.writeF32(0.0);

    // pDynamicState = null
    cs.writeNull();

    cs.writeU64(layout_id);
    cs.writeU64(render_pass_id);
    cs.writeU32(0); // subpass
    cs.writeU64(0); // basePipelineHandle
    cs.writeU32(@bitCast(@as(i32, -1))); // basePipelineIndex

    cs.writeNull(); // pAllocator
    cs.writeU64(1); // pPipelines array
    cs.writeU64(pipeline_id);
}

/// Encode vkCmdBeginRenderPass with depth clear value
pub fn encodeCmdBeginRenderPassDepth(
    cs: *CmdStream,
    cmd_buf_id: u64,
    render_pass_id: u64,
    framebuffer_id: u64,
    w: u32,
    h: u32,
) void {
    cs.cmdHeader(CMD_vkCmdBeginRenderPass, 0);
    cs.writeU64(cmd_buf_id);

    cs.writePresent(); // pRenderPassBegin
    cs.writeU32(VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO);
    cs.writeNull(); // pNext
    cs.writeU64(render_pass_id);
    cs.writeU64(framebuffer_id);
    // renderArea
    cs.writeU32(0); // offset.x
    cs.writeU32(0); // offset.y
    cs.writeU32(w); // extent.width
    cs.writeU32(h); // extent.height
    // 2 clear values. Venus's vn_encode_VkClearValue ALWAYS writes the outer
    // union tag as 0 (color) and the inner VkClearColorValue tag as 2 (uint32)
    // regardless of whether the attachment is color or depth — see Mesa's
    // vn_protocol_driver_command_buffer.h:676. The host uses the attachment
    // format from the render pass to interpret the 4×u32 payload (RGBA for
    // color, depth-bit-pattern in [0] for depth). Each clear value is exactly
    // 32 bytes (4 outer-tag + 4 inner-tag + 8 array-size + 16 four-u32s).
    //
    // Earlier this encoder wrote depth as tag=1 + 8 bytes, total 12 — the
    // host then misread the next 20 bytes of garbage as depth/color, and
    // the depth buffer never actually cleared to 1.0. Cube showed the
    // classic "see-through faces" depth-stencil-not-clearing artifact.
    cs.writeU32(2); // clearValueCount
    cs.writeU64(2); // pClearValues array size
    // Clear value 0 — color attachment (background dark gray)
    cs.writeU32(0); // outer tag (always 0)
    cs.writeU32(2); // inner tag (always 2)
    cs.writeU64(4); // array size = 4
    cs.writeF32(0.1); // r
    cs.writeF32(0.1); // g
    cs.writeF32(0.15); // b
    cs.writeF32(1.0); // a
    // Clear value 1 — depth attachment. Encoded with the SAME color shape;
    // host treats float[0] as the depth clear value because attachment 1
    // is declared D32_SFLOAT in the render pass.
    cs.writeU32(0); // outer tag (always 0)
    cs.writeU32(2); // inner tag (always 2)
    cs.writeU64(4); // array size = 4
    cs.writeF32(1.0); // depth = 1.0 (far plane — LESS compare clears to far so all fragments pass)
    cs.writeF32(0.0); // padding
    cs.writeF32(0.0);
    cs.writeF32(0.0);

    cs.writeU32(0); // contents = INLINE
}
