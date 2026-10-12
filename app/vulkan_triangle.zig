// Vulkan Triangle — Venus wire protocol over virtio-gpu.
// Renders into a device-local image, copies it into a host-visible buffer and
// reads that buffer through a mapped HOST3D blob. Memory types come from the
// host driver's reported properties, so this runs on real GPUs as well as on
// lavapipe's single all-purpose type.

const libc = @import("libc");
const venus = @import("venus");

// SPIR-V shaders
const vert_spirv = [_]u32{
    0x07230203, 0x00010000, 0x00000000, 0x00000027, 0x00000000, 0x00020011, 0x00000001, 0x0003000E,
    0x00000000, 0x00000001, 0x0007000F, 0x00000000, 0x00000001, 0x6E69616D, 0x00000000, 0x00000002,
    0x00000003, 0x00040047, 0x00000002, 0x0000000B, 0x0000002A, 0x00040047, 0x00000003, 0x0000000B,
    0x00000000, 0x00020013, 0x0000000A, 0x00030021, 0x0000000B, 0x0000000A, 0x00030016, 0x0000000C,
    0x00000020, 0x00040017, 0x0000000D, 0x0000000C, 0x00000002, 0x00040017, 0x0000000E, 0x0000000C,
    0x00000004, 0x00040015, 0x0000000F, 0x00000020, 0x00000001, 0x00040015, 0x00000012, 0x00000020,
    0x00000000, 0x00040020, 0x00000010, 0x00000001, 0x0000000F, 0x00040020, 0x00000011, 0x00000003,
    0x0000000E, 0x0004002B, 0x00000012, 0x00000013, 0x00000003, 0x0004001C, 0x0000001B, 0x0000000D,
    0x00000013, 0x00040020, 0x0000001C, 0x00000007, 0x0000001B, 0x00040020, 0x0000001D, 0x00000007,
    0x0000000D, 0x0004002B, 0x0000000C, 0x00000014, 0x00000000, 0x0004002B, 0x0000000C, 0x00000015,
    0x3F000000, 0x0004002B, 0x0000000C, 0x00000016, 0xBF000000, 0x0004002B, 0x0000000C, 0x00000017,
    0x3F800000, 0x0005002C, 0x0000000D, 0x00000018, 0x00000014, 0x00000016, 0x0005002C, 0x0000000D,
    0x00000019, 0x00000015, 0x00000015, 0x0005002C, 0x0000000D, 0x0000001A, 0x00000016, 0x00000015,
    0x0006002C, 0x0000001B, 0x00000020, 0x00000018, 0x00000019, 0x0000001A, 0x0004003B, 0x00000010,
    0x00000002, 0x00000001, 0x0004003B, 0x00000011, 0x00000003, 0x00000003, 0x00050036, 0x0000000A,
    0x00000001, 0x00000000, 0x0000000B, 0x000200F8, 0x0000001E, 0x0004003B, 0x0000001C, 0x0000001F,
    0x00000007, 0x0003003E, 0x0000001F, 0x00000020, 0x0004003D, 0x0000000F, 0x00000021, 0x00000002,
    0x00050041, 0x0000001D, 0x00000022, 0x0000001F, 0x00000021, 0x0004003D, 0x0000000D, 0x00000023,
    0x00000022, 0x00050051, 0x0000000C, 0x00000024, 0x00000023, 0x00000000, 0x00050051, 0x0000000C,
    0x00000025, 0x00000023, 0x00000001, 0x00070050, 0x0000000E, 0x00000026, 0x00000024, 0x00000025,
    0x00000014, 0x00000017, 0x0003003E, 0x00000003, 0x00000026, 0x000100FD, 0x00010038,
};
const frag_spirv = [_]u32{
    0x07230203, 0x00010000, 0x00000000, 0x00000013, 0x00000000, 0x00020011, 0x00000001, 0x0003000E,
    0x00000000, 0x00000001, 0x0006000F, 0x00000004, 0x00000001, 0x6E69616D, 0x00000000, 0x00000002,
    0x00030010, 0x00000001, 0x00000007, 0x00040047, 0x00000002, 0x0000001E, 0x00000000, 0x00020013,
    0x0000000A, 0x00030021, 0x0000000B, 0x0000000A, 0x00030016, 0x0000000C, 0x00000020, 0x00040017,
    0x0000000D, 0x0000000C, 0x00000004, 0x00040020, 0x0000000E, 0x00000003, 0x0000000D, 0x0004002B,
    0x0000000C, 0x0000000F, 0x3F800000, 0x0004002B, 0x0000000C, 0x00000010, 0x00000000, 0x0007002C,
    0x0000000D, 0x00000011, 0x0000000F, 0x00000010, 0x00000010, 0x0000000F, 0x0004003B, 0x0000000E,
    0x00000002, 0x00000003, 0x00050036, 0x0000000A, 0x00000001, 0x00000000, 0x0000000B, 0x000200F8,
    0x00000012, 0x0003003E, 0x00000002, 0x00000011, 0x000100FD, 0x00010038,
};

const RT_W: u32 = 320;
const RT_H: u32 = 240;
const PX_BYTES: u32 = RT_W * RT_H * 4;
const VK_FORMAT_R8G8B8A8_UNORM: u32 = 37;

const VK_IMAGE_USAGE_TRANSFER_SRC_BIT: u32 = 0x1;
const VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT: u32 = 0x10;
const VK_BUFFER_USAGE_TRANSFER_DST_BIT: u32 = 0x2;
const VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL: u32 = 6;
const VK_PIPELINE_STAGE_TRANSFER_BIT: u32 = 0x1000;
const VK_PIPELINE_STAGE_HOST_BIT: u32 = 0x4000;
const VK_ACCESS_TRANSFER_WRITE_BIT: u32 = 0x1000;
const VK_ACCESS_HOST_READ_BIT: u32 = 0x2000;

const INSTANCE: u64 = 100;
const PHYS_DEV: u64 = 101;
const DEVICE: u64 = 102;
const QUEUE: u64 = 103;
const IMAGE: u64 = 200;
const IMAGE_VIEW: u64 = 201;
const RENDER_MEM: u64 = 202;
const READBACK_BUF: u64 = 203;
const READBACK_MEM: u64 = 204;
const RENDER_PASS: u64 = 300;
const PIPELINE_LAYOUT: u64 = 301;
const VERT_MODULE: u64 = 302;
const FRAG_MODULE: u64 = 303;
const PIPELINE: u64 = 304;
const FRAMEBUFFER: u64 = 305;
const CMD_POOL: u64 = 400;
const CMD_BUF: u64 = 401;
const FENCE: u64 = 402;

var cs: venus.CmdStream = .{};
var reply_buf: [*]volatile u8 = undefined;

export fn _start() callconv(.c) noreturn {
    libc.print("=== Vulkan Triangle ===\n\n");

    // Find Venus capset
    var found_venus = false;
    for (0..16) |i| {
        var info: [3]u32 = undefined;
        if (!libc.gpuGetCapsetInfo(@intCast(i), &info)) break;
        if (info[0] == 0 and info[2] == 0) break;
        if (info[0] == 4) found_venus = true;
    }
    if (!found_venus) { libc.print("No Venus!\n"); halt(); }

    _ = libc.gpuCtxCreate(4) orelse { libc.print("Ctx fail!\n"); halt(); };

    const reply = venus.setupReplyStream(4096) orelse {
        libc.print("Reply stream fail!\n");
        cleanup(); halt();
    };
    reply_buf = reply.buf;
    libc.print("Reply stream OK\n");

    // vkCreateInstance
    if (!vkCmd(struct {
        fn f(s: *venus.CmdStream) void {
            s.cmdHeader(venus.CMD_vkCreateInstance, venus.CMD_FLAG_GENERATE_REPLY);
            s.writePresent();
            s.writeU32(venus.VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO);
            s.writeNull(); s.writeU32(0);
            s.writePresent();
            s.writeU32(venus.VK_STRUCTURE_TYPE_APPLICATION_INFO);
            s.writeNull();
            s.writeString("VkTri"); s.writeU32(1);
            s.writeString("ZigOS"); s.writeU32(1);
            s.writeU32((1 << 22) | (2 << 12));
            s.writeU32(0); s.writeU64(0); s.writeU32(0); s.writeU64(0);
            s.writeNull(); s.writePresent(); s.writeU64(INSTANCE);
        }
    }.f, "vkCreateInstance")) { cleanup(); halt(); }

    if (!vkCmd(struct {
        fn f(s: *venus.CmdStream) void {
            s.cmdHeader(venus.CMD_vkEnumeratePhysicalDevices, venus.CMD_FLAG_GENERATE_REPLY);
            s.writeU64(INSTANCE); s.writePresent(); s.writeU32(1);
            s.writeU64(1); s.writeU64(PHYS_DEV);
        }
    }.f, "vkEnumPhysDev")) { cleanup(); halt(); }

    // Memory types as the host driver reports them.
    beginChecked();
    venus.encodeGetPhysicalDeviceMemoryProperties(&cs, PHYS_DEV);
    if (!submitAndWait() or replyCmd() != venus.CMD_vkGetPhysicalDeviceMemoryProperties) {
        libc.print("  memory properties: no reply\n");
        cleanup(); halt();
    }
    const props = venus.decodeMemoryPropertiesReply(reply_buf);
    if (props.memory_type_count > venus.VK_MAX_MEMORY_TYPES) { cleanup(); halt(); }
    libc.print("  memory types:");
    for (0..props.memory_type_count) |i| {
        libc.print(" ");
        libc.printNum(@intCast(i));
        libc.print("=");
        libc.printHex(props.memory_types[i].property_flags);
    }
    libc.print("\n");
    if (props.memory_type_count == 0) { cleanup(); halt(); }

    if (!vkEnc(venus.encodeCreateDevice, .{ PHYS_DEV, 0, DEVICE }, "vkCreateDevice")) { cleanup(); halt(); }
    fire(venus.encodeGetDeviceQueue, .{ DEVICE, 0, 0, QUEUE });

    // Render target: device-local where the host has such a type.
    if (!vkEnc(venus.encodeCreateImage, .{ DEVICE, RT_W, RT_H, VK_FORMAT_R8G8B8A8_UNORM, VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT, IMAGE }, "vkCreateImage")) { cleanup(); halt(); }
    const img_req = requirements(venus.encodeGetImageMemoryRequirements, IMAGE, "image") orelse { cleanup(); halt(); };
    const img_type = venus.pickMemoryTypeBits(&props, img_req.type_bits, venus.VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, 0) orelse
        venus.pickMemoryTypeBits(&props, img_req.type_bits, 0, 0) orelse { libc.print("  no memory type for image\n"); cleanup(); halt(); };
    if (!vkEnc(venus.encodeAllocateMemory, .{ DEVICE, img_req.size, img_type, RENDER_MEM }, "vkAllocMemory(image)")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeBindImageMemory, .{ DEVICE, IMAGE, RENDER_MEM, 0 }, "vkBindImgMem")) { cleanup(); halt(); }

    // Readback buffer: host-visible, mapped straight into this process.
    if (!vkEnc(venus.encodeCreateBuffer, .{ DEVICE, @as(u64, PX_BYTES), VK_BUFFER_USAGE_TRANSFER_DST_BIT, READBACK_BUF }, "vkCreateBuffer")) { cleanup(); halt(); }
    const buf_req = requirements(venus.encodeGetBufferMemoryRequirements, READBACK_BUF, "buffer") orelse { cleanup(); halt(); };
    const buf_type = venus.pickMemoryTypeBits(&props, buf_req.type_bits, venus.VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | venus.VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, 0) orelse {
        libc.print("  no host-visible memory type for buffer\n");
        cleanup(); halt();
    };
    // the blob maps whole pages
    const buf_size: u32 = @intCast((@max(buf_req.size, PX_BYTES) + 4095) & ~@as(u64, 4095));
    if (!vkEnc(venus.encodeAllocateMemory, .{ DEVICE, @as(u64, buf_size), buf_type, READBACK_MEM }, "vkAllocMemory(buffer)")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeBindBufferMemory, .{ DEVICE, READBACK_BUF, READBACK_MEM, 0 }, "vkBindBufMem")) { cleanup(); halt(); }

    var pixel_ptr: ?[*]volatile u8 = null;
    if (libc.gpuCreateBlobWithId(venus.BLOB_MEM_HOST3D, buf_size, @intCast(READBACK_MEM))) |br| {
        pixel_ptr = libc.gpuMapBlob(br, buf_size);
        libc.print(if (pixel_ptr != null) "  readback buffer mapped\n" else "  mapBlob fail\n");
    } else {
        libc.print("  createBlob fail (CPU fallback)\n");
    }

    if (!vkEnc(venus.encodeCreateImageView, .{ DEVICE, IMAGE, VK_FORMAT_R8G8B8A8_UNORM, IMAGE_VIEW }, "vkCreateImgView")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateRenderPassEx, .{ DEVICE, VK_FORMAT_R8G8B8A8_UNORM, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, RENDER_PASS }, "vkRenderPass")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateFramebuffer, .{ DEVICE, RENDER_PASS, IMAGE_VIEW, RT_W, RT_H, FRAMEBUFFER }, "vkFB")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateShaderModule, .{ DEVICE, &vert_spirv, VERT_MODULE }, "vkShader(v)")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateShaderModule, .{ DEVICE, &frag_spirv, FRAG_MODULE }, "vkShader(f)")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreatePipelineLayout, .{ DEVICE, PIPELINE_LAYOUT }, "vkPipeLayout")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateGraphicsPipelines, .{ DEVICE, PIPELINE_LAYOUT, RENDER_PASS, VERT_MODULE, FRAG_MODULE, PIPELINE }, "vkPipeline")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateCommandPool, .{ DEVICE, 0, CMD_POOL }, "vkCmdPool")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeAllocateCommandBuffers, .{ DEVICE, CMD_POOL, CMD_BUF }, "vkCmdBuf")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeCreateFence, .{ DEVICE, 0, FENCE }, "vkCreateFence")) { cleanup(); halt(); }

    fire(venus.encodeBeginCommandBuffer, .{CMD_BUF});
    fire(venus.encodeCmdBeginRenderPass, .{ CMD_BUF, RENDER_PASS, FRAMEBUFFER, RT_W, RT_H });
    fire(venus.encodeCmdBindPipeline, .{ CMD_BUF, PIPELINE });
    fire(venus.encodeCmdDraw, .{ CMD_BUF, 3, 1 });
    fire(venus.encodeCmdEndRenderPass, .{CMD_BUF});
    fire(venus.encodeCmdCopyImageToBuffer, .{ CMD_BUF, IMAGE, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, READBACK_BUF, RT_W, RT_H });
    fire(venus.encodeCmdMemoryBarrier, .{ CMD_BUF, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT, VK_ACCESS_TRANSFER_WRITE_BIT, VK_ACCESS_HOST_READ_BIT });
    fire(venus.encodeEndCommandBuffer, .{CMD_BUF});

    // vkr does not implement the *WaitIdle calls (they kill the context): wait on a fence.
    if (!vkEnc(venus.encodeQueueSubmitFence, .{ QUEUE, CMD_BUF, FENCE }, "vkSubmit")) { cleanup(); halt(); }
    if (!vkEnc(venus.encodeWaitForFences, .{ DEVICE, FENCE, @as(u64, 5_000_000_000) }, "vkWaitForFences")) { cleanup(); halt(); }

    libc.print("\nAll Vulkan calls OK!\n");

    // Display
    const win = libc.createWindow(RT_W, RT_H) orelse { cleanup(); halt(); };
    const fb = win.fb;
    const stride = win.alloc_w;

    if (pixel_ptr) |pixels| {
        var lit: u32 = 0;
        for (0..RT_H) |py| {
            for (0..RT_W) |px| {
                const off = (py * RT_W + px) * 4;
                const r: u32 = pixels[off];
                const g: u32 = pixels[off + 1];
                const b: u32 = pixels[off + 2];
                const a: u32 = pixels[off + 3];
                if (r != 0) lit += 1;
                fb[py * stride + px] = (a << 24) | (r << 16) | (g << 8) | b;
            }
        }
        libc.print("GPU pixels: ");
        libc.printNum(lit);
        libc.print(" red of ");
        libc.printNum(RT_W * RT_H);
        libc.print("\n");
    } else {
        // CPU fallback
        for (0..RT_H) |py| {
            for (0..RT_W) |px| fb[py * stride + px] = 0xFF000000;
        }
        const x0: i32 = 160; const y0: i32 = 60;
        const x1i: i32 = 240; const y1i: i32 = 180;
        const x2i: i32 = 80;
        var y: i32 = y0;
        while (y <= y1i) : (y += 1) {
            const t: f32 = @as(f32, @floatFromInt(y - y0)) / @as(f32, @floatFromInt(y1i - y0));
            const lx: i32 = x0 + @as(i32, @intFromFloat(t * @as(f32, @floatFromInt(x2i - x0))));
            const rx: i32 = x0 + @as(i32, @intFromFloat(t * @as(f32, @floatFromInt(x1i - x0))));
            var x: i32 = lx;
            while (x <= rx) : (x += 1) {
                if (x >= 0 and x < @as(i32, RT_W))
                    fb[@as(usize, @intCast(y)) * stride + @as(usize, @intCast(x))] = 0xFFFF0000;
            }
        }
    }
    libc.present();
    libc.print("Displayed!\n");

    cs.reset();
    venus.encodeDestroyInstance(&cs, INSTANCE);
    _ = cs.submit();
    cleanup();
    while (true) libc.sleep(100);
}

// The host appends replies to the reply stream; seek back to 0 first so each
// checked command's reply lands where readReplyResult looks. The 0xFF fill
// tells "no reply" apart from any real command type (vkCreateInstance is 0).
fn beginChecked() void {
    for (0..1024) |i| reply_buf[i] = 0xFF;
    cs.reset();
    venus.encodeSeekReplyCommandStream(&cs, 0);
}
fn replyCmd() u32 {
    const p: *align(1) const volatile u32 = @ptrCast(reply_buf);
    return p.*;
}
// The host decodes commands after the submit returns and writes the reply
// later; poll for it. Generous timeout: emulated guests are slow.
fn submitAndWait() bool {
    if (!cs.submit()) return false;
    var waited_ms: u32 = 0;
    while (replyCmd() == 0xFFFF_FFFF and waited_ms < 30_000) : (waited_ms += 1) libc.sleep(1);
    return replyCmd() != 0xFFFF_FFFF;
}
fn setReplyFlag(at: usize) void {
    const p: *align(1) u32 = @ptrCast(cs.buf[at + 4 .. at + 8]);
    p.* = venus.CMD_FLAG_GENERATE_REPLY;
}

fn vkCmd(encodeFn: *const fn (*venus.CmdStream) void, name: []const u8) bool {
    beginChecked();
    encodeFn(&cs);
    return checkResult(name);
}
fn vkEnc(comptime encodeFn: anytype, args: anytype, name: []const u8) bool {
    beginChecked();
    const at = cs.pos;
    @call(.auto, encodeFn, .{&cs} ++ args);
    setReplyFlag(at);
    return checkResult(name);
}
fn fire(comptime encodeFn: anytype, args: anytype) void {
    cs.reset();
    @call(.auto, encodeFn, .{&cs} ++ args);
    _ = cs.submit();
}
fn requirements(comptime encodeFn: anytype, object: u64, name: []const u8) ?venus.MemoryRequirements {
    beginChecked();
    const at = cs.pos;
    encodeFn(&cs, DEVICE, object);
    const cmd: *align(1) const u32 = @ptrCast(cs.buf[at .. at + 4]);
    if (!submitAndWait() or replyCmd() != cmd.*) {
        libc.print("  "); libc.print(name); libc.print(" requirements: no reply\n");
        return null;
    }
    const req = venus.decodeMemoryRequirementsReply(reply_buf) orelse {
        libc.print("  "); libc.print(name); libc.print(" requirements: no reply\n");
        return null;
    };
    libc.print("  "); libc.print(name); libc.print(" requirements: size=");
    libc.printNum(@intCast(req.size)); libc.print(" types="); libc.printHex(req.type_bits); libc.print("\n");
    return req;
}
fn checkResult(name: []const u8) bool {
    const answered = submitAndWait();
    const result = venus.readReplyResult(reply_buf);
    libc.print("  "); libc.print(name);
    if (result == 0 and answered) { libc.print(" OK\n"); return true; }
    if (!answered) { libc.print(" NO REPLY\n"); return false; }
    libc.print(" ERR="); libc.printNum(@bitCast(result)); libc.print("\n");
    return false;
}
fn cleanup() void { libc.gpuCtxDestroy(); }
fn halt() noreturn { while (true) libc.sleep(1000); }
