// Venus Protocol Test — Vulkan init via virtio-gpu Venus wire protocol
// Tests: reply stream, vkCreateInstance, vkEnumeratePhysicalDevices,
//        vkCreateDevice, vkGetDeviceQueue

const libc = @import("libc");
const venus = @import("venus");

export fn _start() callconv(.c) noreturn {
    libc.print("=== Venus Protocol Test ===\n\n");

    // 1. Find Venus capset
    libc.print("Scanning capsets...\n");
    var found_venus = false;
    for (0..16) |i| {
        var info: [3]u32 = undefined;
        if (!libc.gpuGetCapsetInfo(@intCast(i), &info)) break;
        if (info[0] == 0 and info[2] == 0) break;
        if (info[0] == 4) {
            libc.print("  Venus capset found\n");
            found_venus = true;
        }
    }
    if (!found_venus) {
        libc.print("ERROR: No Venus capset!\n");
        halt();
    }

    // 2. Create Venus context
    libc.print("Creating Venus context...\n");
    const ctx_id = libc.gpuCtxCreate(4) orelse {
        libc.print("FAILED to create context!\n");
        halt();
    };
    _ = ctx_id;

    // 3. Set up reply stream
    libc.print("Setting up reply stream...\n");
    const reply = venus.setupReplyStream(4096) orelse {
        libc.print("FAILED to set up reply stream!\n");
        cleanup();
        halt();
    };
    libc.print("  Reply stream ready (res=");
    libc.printNum(reply.res_id);
    libc.print(")\n");

    // 4. vkCreateInstance (with reply)
    libc.print("\nvkCreateInstance...\n");
    var cs = venus.CmdStream{};
    const INSTANCE_ID: u64 = 100;
    cs.cmdHeader(venus.CMD_vkCreateInstance, venus.CMD_FLAG_GENERATE_REPLY);
    // pCreateInfo present
    cs.writePresent();
    // VkInstanceCreateInfo
    cs.writeU32(venus.VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO);
    cs.writeNull(); // pNext
    cs.writeU32(0); // flags
    // pApplicationInfo present
    cs.writePresent();
    // VkApplicationInfo
    cs.writeU32(venus.VK_STRUCTURE_TYPE_APPLICATION_INFO);
    cs.writeNull(); // pNext
    cs.writeString("ZigOS");
    cs.writeU32(1); // applicationVersion
    cs.writeString("ZigOS");
    cs.writeU32(1); // engineVersion
    cs.writeU32((1 << 22) | (2 << 12)); // VK_API_VERSION_1_2
    // No layers, no extensions
    cs.writeU32(0);
    cs.writeU64(0);
    cs.writeU32(0);
    cs.writeU64(0);
    // pAllocator = null
    cs.writeNull();
    // pInstance present + handle
    cs.writePresent();
    cs.writeU64(INSTANCE_ID);

    if (!cs.submit()) {
        libc.print("  FAILED submit!\n");
        cleanup();
        halt();
    }
    const result_ci = venus.readReplyResult(reply.buf);
    libc.print("  VkResult=");
    libc.printNum(@bitCast(result_ci));
    if (result_ci == 0) {
        libc.print(" (VK_SUCCESS)\n");
    } else {
        libc.print(" (ERROR)\n");
        cleanup();
        halt();
    }

    // 5. vkEnumeratePhysicalDevices (with reply)
    libc.print("vkEnumeratePhysicalDevices...\n");
    // Zero reply buffer for next command
    for (0..64) |i| reply.buf[i] = 0;
    cs.reset();
    const PHYS_DEV_ID: u64 = 101;
    cs.cmdHeader(venus.CMD_vkEnumeratePhysicalDevices, venus.CMD_FLAG_GENERATE_REPLY);
    cs.writeU64(INSTANCE_ID);
    // pPhysicalDeviceCount present
    cs.writePresent();
    cs.writeU32(1); // we expect 1 device
    // pPhysicalDevices array (size 1)
    cs.writeU64(1);
    cs.writeU64(PHYS_DEV_ID);

    if (!cs.submit()) {
        libc.print("  FAILED submit!\n");
        cleanup();
        halt();
    }
    const result_epd = venus.readReplyResult(reply.buf);
    libc.print("  VkResult=");
    libc.printNum(@bitCast(result_epd));
    if (result_epd == 0) {
        libc.print(" (VK_SUCCESS)\n");
    } else {
        libc.print("\n");
    }

    // 6. vkCreateDevice (with reply)
    libc.print("vkCreateDevice...\n");
    for (0..64) |i| reply.buf[i] = 0;
    cs.reset();
    const DEVICE_ID: u64 = 102;
    venus.encodeCreateDevice(&cs, PHYS_DEV_ID, 0, DEVICE_ID);
    // Patch the flags to include GENERATE_REPLY
    // The flags are at offset 4 (after cmd_type)
    const flags_ptr: *align(1) u32 = @ptrCast(cs.buf[4..8]);
    flags_ptr.* = venus.CMD_FLAG_GENERATE_REPLY;

    if (!cs.submit()) {
        libc.print("  FAILED submit!\n");
        cleanup();
        halt();
    }
    const result_cd = venus.readReplyResult(reply.buf);
    libc.print("  VkResult=");
    libc.printNum(@bitCast(result_cd));
    if (result_cd == 0) {
        libc.print(" (VK_SUCCESS)\n");
    } else {
        libc.print(" (ERROR)\n");
        // Try to understand the error
        if (result_cd == -3) libc.print("  VK_ERROR_INITIALIZATION_FAILED\n");
        if (result_cd == -1) libc.print("  VK_ERROR_OUT_OF_HOST_MEMORY\n");
        if (result_cd == -9) libc.print("  VK_ERROR_INCOMPATIBLE_DRIVER\n");
        if (result_cd == -6) libc.print("  VK_ERROR_FEATURE_NOT_PRESENT\n");
        if (result_cd == -7) libc.print("  VK_ERROR_TOO_MANY_OBJECTS\n");
    }

    // 7. vkGetDeviceQueue (only if device created OK)
    if (result_cd == 0) {
        libc.print("vkGetDeviceQueue...\n");
        for (0..64) |i| reply.buf[i] = 0;
        cs.reset();
        const QUEUE_ID: u64 = 103;
        venus.encodeGetDeviceQueue(&cs, DEVICE_ID, 0, 0, QUEUE_ID);
        // Patch reply flag
        const qf_ptr: *align(1) u32 = @ptrCast(cs.buf[4..8]);
        qf_ptr.* = venus.CMD_FLAG_GENERATE_REPLY;

        if (cs.submit()) {
            libc.print("  OK\n");
        } else {
            libc.print("  FAILED\n");
        }
    }

    // Cleanup
    libc.print("\nCleanup...\n");
    cs.reset();
    venus.encodeDestroyInstance(&cs, INSTANCE_ID);
    _ = cs.submit();

    cleanup();
    libc.print("\n=== Venus Test Complete ===\n");
    halt();
}

fn cleanup() void {
    libc.gpuCtxDestroy();
}

fn halt() noreturn {
    while (true) libc.sleep(1000);
}
