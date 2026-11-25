// ZigOS UEFI Bootloader
// Loads kernel.elf from the ESP, sets up page tables + GDT, jumps to kernel.
// Built with .uefi target → produces PE/COFF BOOTX64.EFI

const std = @import("std");
const uefi = std.os.uefi;
const BootServices = uefi.tables.BootServices;
const ConfigurationTable = uefi.tables.ConfigurationTable;
const GraphicsOutput = uefi.protocol.GraphicsOutput;
const SimpleFileSystem = uefi.protocol.SimpleFileSystem;
const File = uefi.protocol.File;
const menu = @import("menu.zig");
const nvram = @import("nvram.zig");
const error_screen = @import("error_screen.zig");

// The handoff to the kernel: what it is (lib/boot_protocol.zig, shared with
// the kernel), reading the image, and building what the kernel starts on.
const protocol = @import("boot_protocol");
const kernel_image = @import("kernel_image.zig");
const handoff = @import("handoff.zig");
const FramebufferInfo = protocol.FramebufferInfo;

// Output to serial COM1 (0x3F8) for debug — works before and after ExitBootServices
fn serialPut(c: u8) void {
    // Wait for transmit buffer empty
    while (asm volatile ("inb %[port], %[ret]"
        : [ret] "={al}" (-> u8),
        : [port] "N{dx}" (@as(u16, 0x3FD)),
    ) & 0x20 == 0) {}
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (c),
          [port] "N{dx}" (@as(u16, 0x3F8)),
    );
}

fn serialPrint(msg: []const u8) void {
    for (msg) |c| serialPut(c);
}

fn serialHex(val: u64) void {
    const hex = "0123456789ABCDEF";
    serialPrint("0x");
    var i: u6 = 60;
    var started = false;
    while (true) : (i -= 4) {
        const nibble: u4 = @truncate(val >> i);
        if (nibble != 0) started = true;
        if (started or i == 0) serialPut(hex[nibble]);
        if (i == 0) break;
    }
}

/// Re-program GOP to the most kernel-friendly mode before the framebuffer
/// descriptor is read out. Preference tiers:
///   3 — BGRA with stride == width: the kernel's gfx writes 0x00RRGGBB at
///       y*width+x, so this scans out with zero conversion (direct mode)
///   2 — BGRA, padded stride: kernel blits through its GUEST_FB back buffer
///   1 — RGBA, any stride: blit + R/B swap
/// Within a tier the largest area wins. Two hard caps, both kernel limits:
/// width*height*4 must fit the 8 MB GUEST_FB/BACK_BUFFER compositing regions,
/// and the area is capped at 1920x1080 (the desktop's window-math ceiling).
/// The CURRENT mode seeds the comparison, so SetMode (which blanks the panel
/// for a frame) only runs on a strict improvement — QEMU/OVMF's default
/// 1920x1080 BGRA packed mode is already tier-3 max and never re-sets.
fn pickBestGopMode(gop: *GraphicsOutput) void {
    const Rating = struct {
        const MAX_BYTES: u64 = protocol.MAX_FRAMEBUFFER_BYTES;
        const MAX_AREA: u64 = 1920 * 1080;

        const Score = struct { tier: u8, area: u64 };

        fn rate(info: anytype) Score {
            const w: u64 = info.horizontal_resolution;
            const h: u64 = info.vertical_resolution;
            const area = w * h;
            if (area == 0 or area > MAX_AREA or area * 4 > MAX_BYTES) return .{ .tier = 0, .area = 0 };
            const tier: u8 = switch (info.pixel_format) {
                .blue_green_red_reserved_8_bit_per_color => if (info.pixels_per_scan_line == info.horizontal_resolution) @as(u8, 3) else @as(u8, 2),
                .red_green_blue_reserved_8_bit_per_color => 1,
                else => 0,
            };
            return .{ .tier = tier, .area = if (tier == 0) 0 else area };
        }
    };

    const cur = Rating.rate(gop.mode.info);
    var best_tier: u8 = cur.tier;
    var best_area: u64 = cur.area;
    var best_mode: u32 = gop.mode.mode;

    var i: u32 = 0;
    while (i < gop.mode.max_mode) : (i += 1) {
        const info = gop.queryMode(i) catch continue;
        const r = Rating.rate(info);
        if (r.tier > best_tier or (r.tier == best_tier and r.area > best_area)) {
            best_tier = r.tier;
            best_area = r.area;
            best_mode = i;
        }
    }

    if (best_tier == 0 or best_mode == gop.mode.mode) return;
    serialPrint("[uefi] GOP SetMode ");
    serialHex(gop.mode.mode);
    serialPrint(" -> ");
    serialHex(best_mode);
    serialPut('\n');
    gop.setMode(best_mode) catch {
        serialPrint("[uefi] SetMode failed; keeping current mode\n");
    };
}

pub fn main() uefi.Status {
    const system_table = uefi.system_table;
    const image_handle = uefi.handle;
    // Init serial for debug output
    // Set 38400 baud, 8N1
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x00)),
          [port] "N{dx}" (@as(u16, 0x3F9)),
    ); // Disable interrupts
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x80)),
          [port] "N{dx}" (@as(u16, 0x3FB)),
    ); // DLAB on
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x03)),
          [port] "N{dx}" (@as(u16, 0x3F8)),
    ); // Divisor low (38400)
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x00)),
          [port] "N{dx}" (@as(u16, 0x3F9)),
    ); // Divisor high
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x03)),
          [port] "N{dx}" (@as(u16, 0x3FB)),
    ); // 8N1
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0xC7)),
          [port] "N{dx}" (@as(u16, 0x3FA)),
    ); // FIFO
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x0B)),
          [port] "N{dx}" (@as(u16, 0x3FC)),
    ); // RTS/DSR

    serialPrint("[uefi] ZigOS UEFI bootloader\n");

    const boot_services = system_table.boot_services orelse {
        serialPrint("[uefi] No boot services!\n");
        return .aborted;
    };

    // --- 1. Locate GOP ---
    serialPrint("[uefi] Locating GOP...\n");
    var fb_info = FramebufferInfo{
        .base = 0,
        .width = 0,
        .height = 0,
        .stride = 0,
        .format = .unknown,
    };
    var has_fb: u32 = 0;

    const gop_result = boot_services.locateProtocol(GraphicsOutput, null) catch null;
    if (gop_result) |gop| {
        pickBestGopMode(gop);
        const mode = gop.mode;
        const info = mode.info;
        fb_info.base = mode.frame_buffer_base;
        fb_info.width = info.horizontal_resolution;
        fb_info.height = info.vertical_resolution;
        fb_info.stride = info.pixels_per_scan_line;
        fb_info.format = switch (info.pixel_format) {
            .blue_green_red_reserved_8_bit_per_color => .bgra,
            .red_green_blue_reserved_8_bit_per_color => .rgba,
            else => .unknown,
        };
        has_fb = 1;
        serialPrint("[uefi] GOP: ");
        serialHex(fb_info.width);
        serialPut('x');
        serialHex(fb_info.height);
        serialPrint(" fb=");
        serialHex(fb_info.base);
        serialPut('\n');
    } else {
        serialPrint("[uefi] No GOP found\n");
    }

    // --- 1.5. Boot menu (only if GOP + keyboard available) ---
    // menu.show() handles "About" entry internally and never returns 0xFF —
    // it always returns a real boot mode (0/1/2). Esc returns 0 (default).
    //
    // Default-selection comes from NVRAM:
    //   - LastBootMode (0/1/2)        → which entry is highlighted
    //   - LastBootStatus == .crashed → force Safe (entry 2) regardless of mode
    //
    // The status check covers the recovery loop: a kernel that consistently
    // panics in CPU bring-up would otherwise need manual intervention every
    // boot. With this, the second consecutive boot lands in Safe mode.
    // RuntimeServices is mandatory in the UEFI spec — present on every
    // standards-compliant firmware. Type is non-nullable so no orelse here.
    const runtime_services = system_table.runtime_services;

    // Cmdline read once here so it's available when filling BootInfo
    // post-handoff. Persists across reboots via NVRAM.
    var cmdline_buf: [256]u8 = [_]u8{0} ** 256;
    const cmdline_len: usize = nvram.getCmdline(runtime_services, &cmdline_buf);
    if (cmdline_len > 0) {
        serialPrint("[nvram] cmdline=");
        var ci: usize = 0;
        while (ci < cmdline_len and ci < cmdline_buf.len) : (ci += 1) {
            if (cmdline_buf[ci] >= 0x20 and cmdline_buf[ci] < 0x7F) serialPut(cmdline_buf[ci]);
        }
        serialPut('\n');
    }

    // Read the boot history ring and decide:
    //   - which menu entry to highlight by default
    //   - whether to show the crash fingerprint banner
    //   - whether to escalate to Safe after a string of same-mode crashes
    //
    // The ring is the canonical source of truth post-Phase-2. Singletons
    // (LastBootMode/Status/CrashFp) are still written by the existing
    // kernel-side code so a brand-new kernel against an old NVRAM (or
    // vice-versa) keeps working — `historyMaybeFromSingletons` synthesizes
    // a one-entry ring on first read if the ring var is missing.
    var default_selection: u32 = 0;
    var crash_fp_buf: [256]u8 = undefined;
    var crash_fp_len: usize = 0;
    const ring_opt = nvram.historyRead(runtime_services);
    if (ring_opt) |ring| {
        const last_idx_opt = nvram.historyLastSlotIdx(&ring);
        if (last_idx_opt) |last_idx| {
            const last = ring.entries[last_idx];
            const last_status = std.enums.fromInt(nvram.BootStatus, last.outcome) orelse .unknown;
            serialPrint("[nvram] ring next=");
            serialHex(ring.next);
            serialPrint(" last_mode=");
            serialHex(last.mode);
            serialPrint(" last_status=");
            serialHex(@intFromEnum(last_status));
            serialPut('\n');

            // Recovery escalation: walk the most-recent entries; if 3 in a
            // row are crashed AND from the same mode, that mode is broken
            // — force Safe regardless of what the user picked last. One
            // crash is bad luck; three is a pattern.
            var consecutive: u32 = 0;
            const consec_mode: u32 = last.mode;
            const window: u32 = @min(@as(u32, @intCast(ring.next)), nvram.HISTORY_DEPTH);
            var w: u32 = 0;
            while (w < window) : (w += 1) {
                const slot: usize = @intCast((@as(u64, ring.next) -% (1 + w)) % nvram.HISTORY_DEPTH);
                const e = ring.entries[slot];
                if (e.outcome == @intFromEnum(nvram.BootStatus.crashed) and e.mode == consec_mode) {
                    consecutive += 1;
                } else break;
            }

            if (last_status == .crashed or last_status == .in_progress) {
                // Tiered fallback policy:
                //   GPU compositor (mode 9) crash → Normal (menu idx 0). The
                //   GPU path is opt-in; a CPU compositor desktop is the
                //   right next step, not Safe-no-SMP.
                //   Anything else → Safe (menu idx 2).
                //   3+ same-mode crashes → always Safe regardless of mode.
                if (consecutive >= 3) {
                    default_selection = 2; // Safe
                    serialPrint("[nvram] 3+ same-mode crashes in a row — locked to Safe\n");
                } else if (last.mode == 9) {
                    default_selection = 0; // Normal
                    serialPrint("[nvram] GPU compositor (mode 9) crashed — defaulting to Normal\n");
                } else {
                    default_selection = 2; // Safe
                    serialPrint("[nvram] previous boot didn't complete — defaulting to Safe\n");
                }
                if (last.crash_fp_len > 0) {
                    const n = @min(@as(usize, last.crash_fp_len), crash_fp_buf.len);
                    @memcpy(crash_fp_buf[0..n], last.crash_fp[0..n]);
                    crash_fp_len = n;
                } else {
                    // Fall back to the legacy singleton if the ring entry's
                    // fp slot is empty (kernel-side didn't push to ring yet).
                    crash_fp_len = nvram.getCrashFp(runtime_services, &crash_fp_buf);
                }
            } else {
                // Last boot succeeded — highlight that mode if it still
                // exists in the menu (mode→entry walk covers Tests-submenu
                // modes 3..7 which never appear in the main menu).
                for (menu.ENTRIES, 0..) |e, ei| {
                    if (e.boot_mode == last.mode) {
                        default_selection = @intCast(ei);
                        break;
                    }
                }
            }
        }
    } else {
        // No ring yet — first boot or NVRAM was reset. Fall back to the
        // singleton vars so behavior matches pre-Phase-2 builds during
        // the migration.
        const last_mode = nvram.getBootMode(runtime_services);
        const last_status = nvram.getBootStatus(runtime_services);
        serialPrint("[nvram] no ring; falling back to singletons last_mode=");
        serialHex(last_mode);
        serialPrint(" last_status=");
        serialHex(@intFromEnum(last_status));
        serialPut('\n');
        if (last_status == .crashed or last_status == .in_progress) {
            // Same tiered fallback as the ring path: GPU mode → Normal,
            // anything else → Safe. (No 3-in-a-row escalation here because
            // singletons don't carry that history.)
            if (last_mode == 9) {
                default_selection = 0;
                serialPrint("[nvram] mode 9 crashed (singleton) — defaulting to Normal\n");
            } else {
                default_selection = 2;
            }
            crash_fp_len = nvram.getCrashFp(runtime_services, &crash_fp_buf);
        } else {
            for (menu.ENTRIES, 0..) |e, ei| {
                if (e.boot_mode == last_mode) {
                    default_selection = @intCast(ei);
                    break;
                }
            }
        }
    }

    var boot_mode: u32 = 0;
    if (gop_result) |gop_for_menu| {
        if (system_table.con_in) |stin| {
            serialPrint("[uefi] Showing boot menu...\n");
            // menu.show returns the chosen boot_mode directly. Sentinel values
            // (Tests/About/Back) are resolved internally; only real boot-modes
            // (0..127) leak out. Tests-submenu boot-modes (3,4,...) ride the
            // same channel — kernel's boot_mode dispatch knows how to map them.
            const ring_ref: ?*const nvram.BootHistoryRing = if (ring_opt) |*r| r else null;
            boot_mode = menu.show(gop_for_menu, stin, boot_services, runtime_services, default_selection, crash_fp_buf[0..crash_fp_len], ring_ref);
            serialPrint("[uefi] boot_mode=");
            serialHex(boot_mode);
            serialPut('\n');
        } else {
            serialPrint("[uefi] No con_in — skipping menu\n");
        }
    }

    // Persist the user's choice + mark "in_progress". The kernel will flip
    // this to `success` after it reaches its "boot complete" milestone
    // (Phase 2). If we ever boot and find this still set to `in_progress`,
    // it means the previous kernel either crashed or wedged — we'll fall
    // back to Safe mode next time (logic above).
    nvram.setBootMode(runtime_services, boot_mode);
    nvram.setBootStatus(runtime_services, .in_progress);

    // Push a fresh entry to the boot history ring. Kernel will mutate this
    // slot in-place to record success / crash. We stamp the bootloader's
    // build_id now; kernel will stamp `kernel_build_id` later. Mismatch
    // between the two on a single entry surfaces in About as build skew.
    {
        const bo = @import("build_options");
        nvram.historyPush(runtime_services, boot_mode, bo.build_id);
    }

    // --- 2. kernel.elf, into memory the firmware gives us ---
    serialPrint("[uefi] Loading kernel.elf...\n");
    const root = openBootVolume(boot_services) catch |err| fail(gop_result, system_table.con_in, runtime_services, switch (err) {
        error.NoFilesystem => .no_filesystem,
        error.OpenVolume => .open_volume,
    });
    const image = kernel_image.load(boot_services, root) catch |err| fail(gop_result, system_table.con_in, runtime_services, switch (err) {
        error.Missing => .open_kernel_file,
        error.ShortRead => .read_kernel_file,
        error.NotElf => .invalid_elf_magic,
        error.WrongClass => .invalid_elf_class,
        error.BadSegments => .kernel_segments,
        error.OutOfMemory => .out_of_memory,
        error.NoEntrySymbol => .no_kmain_symbol,
    });
    root.close() catch {};
    serialPrint("[uefi] kernel image at ");
    serialHex(image.link_base +% image.phys_offset);
    serialPrint(" (link +");
    serialHex(image.phys_offset);
    serialPrint(", span ");
    serialHex(image.span);
    serialPrint("), entry ");
    serialHex(image.entry);
    serialPut('\n');

    // --- 3. Find RSDP from configuration table ---
    var rsdp_addr: u64 = 0;
    for (0..system_table.number_of_table_entries) |i| {
        const entry = system_table.configuration_table[i];
        if (std.mem.eql(u8, std.mem.asBytes(&entry.vendor_guid), std.mem.asBytes(&ConfigurationTable.acpi_20_table_guid))) {
            rsdp_addr = @intFromPtr(entry.vendor_table);
            serialPrint("[uefi] RSDP at ");
            serialHex(rsdp_addr);
            serialPut('\n');
            break;
        }
    }

    // --- 4. What the kernel starts on ---
    const boot_data = handoff.BootData.allocate(boot_services) catch
        fail(gop_result, system_table.con_in, runtime_services, .out_of_memory);
    boot_data.mapAddressSpace(image);

    const cmdline_bytes: u32 = @intCast(@min(cmdline_len, cmdline_buf.len));
    const boot_info = boot_data.info();
    boot_info.* = .{
        .memory_map = boot_data.regions(),
        .memory_map_count = 0, // adoptMemoryMap, once the map is final
        .has_framebuffer = has_fb,
        .framebuffer = fb_info,
        .pml4_phys = boot_data.pml4Phys(),
        .rsdp_addr = rsdp_addr,
        .boot_mode = boot_mode,
        .runtime_services_addr = @intFromPtr(runtime_services),
        .bootloader_build_id = @import("build_options").build_id,
        .cmdline_len = cmdline_bytes,
        .kernel_phys_offset = image.phys_offset,
        .boot_data_base = boot_data.base,
        .boot_data_size = handoff.BootData.SIZE,
    };
    @memcpy(boot_info.cmdline[0..cmdline_bytes], cmdline_buf[0..cmdline_bytes]);

    // --- 5. ExitBootServices ---
    const map_buffer = handoff.allocateMapBuffer(boot_services) catch
        fail(gop_result, system_table.con_in, runtime_services, .memory_map);
    serialPrint("[uefi] ExitBootServices...\n");
    const memory_map = handoff.exitBootServices(boot_services, image_handle, map_buffer) catch |err| {
        // A refused exit leaves boot services half down: no error screen.
        serialPrint(switch (err) {
            error.MemoryMap => "[uefi] getMemoryMap failed!\n",
            error.Refused => "[uefi] ExitBootServices failed!\n",
        });
        while (true) asm volatile ("hlt");
    };

    // === NO MORE UEFI CALLS AFTER THIS POINT ===
    const summary = boot_data.adoptMemoryMap(memory_map);
    serialPrint("[uefi] memory map: ");
    serialHex(summary.descriptors);
    serialPrint(" descriptors -> ");
    serialHex(summary.regions);
    serialPrint(" regions, usable ");
    serialHex(summary.usable_bytes >> 20);
    serialPrint(" MB, ACPI NVS ");
    serialHex(summary.acpi_nvs_bytes >> 10);
    serialPrint(" KB\n");
    if (summary.dropped > 0) {
        serialPrint("[uefi] WARNING: memory map truncated, ");
        serialHex(summary.dropped);
        serialPrint(" entries dropped (bump handoff.MAX_REGIONS)\n");
    }

    serialPrint("[uefi] Jumping to kernel at ");
    serialHex(image.entry);
    serialPut('\n');
    boot_data.enterKernel(image.entry);
}

/// The error screen, and the same line on serial for a run with no screen.
fn fail(gop: ?*GraphicsOutput, con_in: ?*uefi.protocol.SimpleTextInput, runtime_services: *uefi.tables.RuntimeServices, step: error_screen.Step) noreturn {
    serialPrint("[uefi] FATAL: ");
    serialPrint(error_screen.stepLabel(step));
    serialPut('\n');
    error_screen.show(gop, con_in, runtime_services, step, "");
}

/// The root of the volume this loader was started from. The first FAT volume
/// the firmware lists can be another install's (a target disk next to the
/// build ESP): its kernel.elf is not the one this BOOTX64.EFI was built with.
fn openBootVolume(boot_services: *BootServices) error{ NoFilesystem, OpenVolume }!*File {
    var filesystem: ?*SimpleFileSystem = null;
    if (boot_services.handleProtocol(uefi.protocol.LoadedImage, uefi.handle) catch null) |loaded_image| {
        if (loaded_image.device_handle) |own_device| {
            filesystem = boot_services.handleProtocol(SimpleFileSystem, own_device) catch null;
        }
    }
    if (filesystem == null) {
        // Firmware that refuses the by-handle open.
        serialPrint("[uefi] no fs on own device, falling back to locateProtocol\n");
        filesystem = boot_services.locateProtocol(SimpleFileSystem, null) catch null;
    }
    const found = filesystem orelse return error.NoFilesystem;
    return found.openVolume() catch error.OpenVolume;
}
