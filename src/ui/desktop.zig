const gfx = @import("gfx.zig");
const bga = @import("../driver.zig").bga;
const display = @import("display.zig");
const mouse = @import("../driver.zig").mouse;
const keyboard = @import("../driver.zig").keyboard;
const vga = @import("../driver.zig").vga;
const paging = @import("../mm/paging.zig");
const pmm = @import("../mm/pmm.zig");
const debug = @import("../debug/debug.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const xhci = @import("../driver.zig").xhci;
const process = @import("../proc/process.zig");
const events_mod = @import("events.zig");
pub const Event = events_mod.Event;
pub const EventKind = events_mod.EventKind;

const screen = @import("desktop/screen.zig");
pub const getBackBuffer = screen.getBackBuffer;
const adoptBackBuffer = screen.adoptBackBuffer;
const swCursorActive = screen.swCursorActive;
const eraseCursor = screen.eraseCursor;
const drawCursorOnScreen = screen.drawCursorOnScreen;
const bakeCursorToBackBuffer = screen.bakeCursorToBackBuffer;
const unbakeCursorFromBackBuffer = screen.unbakeCursorFromBackBuffer;
const blitWindowBounds = screen.blitWindowBounds;
const changeResolution = screen.changeResolution;

const input = @import("desktop/input.zig");
const frameButtons = input.frameButtons;
const pressReplayPending = input.pressReplayPending;
const pressTarget = input.pressTarget;
const publishMouseToFocused = input.publishMouseToFocused;

const manage = @import("desktop/manage.zig");
const toggleFullscreen = manage.toggleFullscreen;
const runLauncherResult = manage.runLauncherResult;
const handleMouseEvents = manage.handleMouseEvents;

const chrome = @import("desktop/chrome.zig");
pub const paddedWinRect = chrome.paddedWinRect;
const renderWindow = chrome.renderWindow;
pub const borderColor = chrome.borderColor;

const scene = @import("desktop/scene.zig");
const renderScene = scene.renderScene;
pub const occludersAbove = scene.occludersAbove;
pub const MENUBAR_REACH = scene.MENUBAR_REACH;
pub const DOCK_REACH = scene.DOCK_REACH;
const partialHitsOverlay = scene.partialHitsOverlay;
const renderRegions = scene.renderRegions;
const repaintZAboveOverlapping = scene.repaintZAboveOverlapping;
const windowCovered = scene.windowCovered;

const damage = @import("desktop/damage.zig");
const seedRegion = damage.seedRegion;
const seedRect = damage.seedRect;
const seedWindow = damage.seedWindow;
const wantRegion = damage.wantRegion;
const wantTextRow = damage.wantTextRow;
const DirtyKind = damage.DirtyKind;

const client = @import("desktop/client.zig");
const createWindow = client.createWindow;
pub const createGuiWindow = client.createGuiWindow;
pub const focusedShellSpawnedPid = client.focusedShellSpawnedPid;
pub const Standing = client.Standing;
pub const actsFor = client.actsFor;
pub const maySetWallpaper = client.maySetWallpaper;
const finishClose = client.finishClose;
pub const DestroyedGui = client.DestroyedGui;
pub const GuiOwner = client.GuiOwner;
pub const groupHasGuiWindow = client.groupHasGuiWindow;
pub const destroyGuiWindow = client.destroyGuiWindow;
pub const focusedPid = client.focusedPid;
pub const focusedSignalTarget = client.focusedSignalTarget;
pub const focusedTty = client.focusedTty;
pub const canReadConsole = client.canReadConsole;
pub const popEvent = client.popEvent;
pub const consoleReadable = client.consoleReadable;
pub const popCharEvent = client.popCharEvent;
pub const getMouseRelative = client.getMouseRelative;
pub const setCursorHidden = client.setCursorHidden;
pub const centerMouse = client.centerMouse;
pub const getWindowContentSize = client.getWindowContentSize;
pub const getWindowAllocSize = client.getWindowAllocSize;

const surface = @import("desktop/surface.zig");
pub const markGuiPresent = surface.markGuiPresent;
pub const snapshotGuiFb = surface.snapshotGuiFb;
pub const reclaimBackBuffers = surface.reclaimBackBuffers;
const guiContentHash = surface.guiContentHash;
const hasGuiWindows = surface.hasGuiWindows;

const emulator = @import("desktop/term/emulator.zig");
const putCharOnWindow = emulator.putCharOnWindow;

const cells = @import("desktop/term/cells.zig");
const FONT_H = cells.FONT_H;
const TERM_WIN_W = cells.TERM_WIN_W;

const term_view = @import("desktop/term/view.zig");
const renderTerminalRow = term_view.renderTerminalRow;
const termRowsPaintable = term_view.termRowsPaintable;
const repaintStaleRows = term_view.repaintStaleRows;

const session = @import("desktop/term/session.zig");
const termPrompt = session.termPrompt;
const spawnShellOnWindow = session.spawnShellOnWindow;
const handleKeyboard = session.handleKeyboard;

const notify = @import("desktop/notify.zig");
pub const showNotification = notify.showNotification;
pub const showNotificationFrom = notify.showNotificationFrom;

// DBG: input-pipeline diagnostic counters. Bumped from desktop's drain
// loop when chars get dropped. Read by manual klog dumps when input
// behavior is unexpected. Rate-limited so we don't flood the log.
var dbg_focus_drop_count: u64 = 0;
var dbg_event_queue_full: u64 = 0;
var dbg_last_focus_drop_log: u64 = 0;
var dbg_last_qfull_log: u64 = 0;

// --- Window management (storage, z-stack, focus, hit-testing) ---
const wm = @import("desktop/window.zig");
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const z_stack = &wm.z_stack;
const setFocused = wm.setFocused;
const cycleFocus = wm.cycleFocus;

// Persisted UI config (background, theme, dock position, …) — see
// desktop/config.zig. Re-exported so external callers (sysSetConfig,
// settings.elf-side notifications) keep using `desktop.conf.<field>`
// without learning the new path.
pub const conf = @import("desktop/config.zig");
pub var config_changed: bool = false;

// Dirty-region tracker for partial GPU flush — see desktop/dirty.zig.
// Aliased as `dirty_rects_mod` to avoid clashing with the local
// `dirty: DirtyKind` variable inside `run()`.
const dirty_rects_mod = @import("desktop/dirty.zig");
const addDirtyRect = dirty_rects_mod.add;
const markDirtyFull = dirty_rects_mod.markFull;
// Mode 9: requestRenderFromDirty has copied the rects into the compositor's
// own list before a frame resets them, so the reset needs no condition.
const resetDirtyRects = dirty_rects_mod.reset;

// --- Notification system ---
// Top-right toast notification — show()/tick()/render() in desktop/toast.zig.
const toast = @import("desktop/toast.zig");

// Top menu bar — render() in desktop/menubar.zig.
const menubar = @import("desktop/menubar.zig");

// Window animations (open/close/minimize/restore/fullscreen) — desktop/animations.zig.
const animations = @import("desktop/animations.zig");
const advanceAnimations = animations.advance;
const hasActiveAnimations = animations.hasActive;

// Bottom-centre dock pill, hover tooltip, click dispatch — desktop/dock.zig.
const dock = @import("desktop/dock.zig");

// Right-click context menu (state + render + hit-test) — desktop/context_menu.zig.
// Action dispatch (executeMenuItem) stays here because it reaches into
// createWindow/closeWindow/etc.
const context_menu = @import("desktop/context_menu.zig");

// Open-an-app panel; started apps are launched here (runLauncherResult).
const launcher = @import("desktop/launcher.zig");

// --- Async app launch queue ---
// requestAppLoad rejects if AP is mid-flight on a previous load. Without
// queueing, the click is silently dropped — user clicks shortcut, sees
// "loading" and nothing happens. Buffer up to 8 pending names; drain one
// per frame in the desktop main loop once the AP goes idle.
// Pending-app-launch ring — see desktop/launch_queue.zig.
const launch_queue = @import("desktop/launch_queue.zig");

// Compositor wake primitive — event-driven sleep / wake; replaces the
// legacy "wake every 80 ms" floor in shouldResumeDesktop. See module
// doc-comment for the model.
pub const wake = @import("desktop/wake.zig");

// Owners parked in sysWaitEvent.
const event_wait = @import("desktop/event_wait.zig");

// Frame-time percentiles ([frameperf] serial dump every ~30 s). Phase
// stamps live in the main loop; flush time is accumulated inside
// display.flush/flushRect.
const frameperf = @import("desktop/frameperf.zig");

// --- Colors / palette / terminal tunables (see theme.zig) ---
const theme = @import("theme.zig");

// --- Layout ---
// Spatial constants live in desktop/layout.zig so other extracted
// submodules (toast, dock, menubar, compositor, …) can share them
// without circular imports back into this file.
const layout = @import("desktop/layout.zig");
const MENUBAR_H = layout.MENUBAR_H;
const TASKBAR_H = layout.TASKBAR_H;
const TITLEBAR_H = layout.TITLEBAR_H;
const BORDER = layout.BORDER;

const TERM_ROWS = emulator.TERM_ROWS;

// --- Terminal escape / coloring (see theme.zig for the constant values) ---
const CURSOR_BLINK_HALF_TICKS = theme.CURSOR_BLINK_HALF_TICKS;

/// Free-running per-frame counter, incremented once per desktop main-loop
/// iteration. Used for any "every N frames" scheduling that doesn't need
/// to track real time. Wraps around silently — only relative differences
/// matter. (Cursor blink uses `process.tick_count` instead, since the loop
/// wakes irregularly.)
var frame_count: u32 = 0;

/// Last cursor blink phase (`tick_count / CURSOR_BLINK_HALF_TICKS`) we
/// marked dirty for. Used to avoid spamming dirty=.text_only every loop iter
/// when the phase hasn't actually flipped.
var last_blink_phase: u64 = 0;

// --- Scene rendering (to back buffer) ---

// ─── Region repaint ─────────────────────────────────────────────────────────
// Frames that change a few known spots — terminal output, a window drag, an
// overlay appearing or moving — repaint only those spots instead of the whole
// scene, and hand only those rects to the flush and the GPU compositor. Each
// seed rect grows to the closure of every alpha layer it touches (window
// shadows, icon cells, glass bands and overlays all blend over or read the
// pixels beneath them, so each must lie wholly on freshly restored wallpaper
// or its blend accumulates: the shadow-darkening bug class). Intersecting
// closures merge; each disjoint region is then painted in renderScene's
// order, pixel-identical to renderScene inside it, untouched outside.

// Boot splash extracted to desktop/splash.zig — the long animation
// loop is unrelated to anything else here.
const splash = @import("desktop/splash.zig");

// --- Cursor ---

// --- Event handling ---

// --- Launcher ---

// --- Context menu ---

// --- Dirty region helpers ---

// --- Main entry point ---

/// Kernel-task entry trampoline. process.createKernelTask plants this
/// function's address on the new task's kstack as the synthetic switchTo
/// ret target. switchTo's `ret` lands here; we call run() and trap if it
/// ever returns (it shouldn't — desktop loops forever).
pub fn taskEntry() callconv(.c) noreturn {
    // Phase 3 cutover: now that enterFirstTask has switched the BSP off
    // the boot stack onto desktop's heap-allocated kstack (high-VA in the
    // physmap window), retire the legacy PML4[0] low identity. Every
    // kernel-side access from this point on must go through the physmap
    // (PHYSMAP_BASE + phys, via `paging.physToVirt`) or the kernel image
    // window at -2 GB. The migration was completed in src/mm/heap.zig
    // (heap moved to the physmap), src/driver/gpu/vga.zig (VGA buffer), and the
    // driver/walker sweep done in Phase 2. Per-process address spaces own
    // their own PML4[0] independently, so user processes are unaffected.
    @import("../mm/paging.zig").dropLowIdentity();
    // The identity window was the last user-accessible memory the kernel
    // itself reached into; with it gone SMAP can go on. It is the last
    // entry of the BSP's per-CPU list; this also checks none was skipped.
    @import("../cpu/cpu_state.zig").completeBoot();
    // enterFirstTask cli'd before swapping us onto desktop's kstack —
    // re-enable IRQs now that RSP is on the high-VA kstack and the
    // legacy low identity is gone.
    asm volatile ("sti");
    // Now that we're a scheduled task with a current_pid, it's safe to
    // flip NVMe controllers into async I/O mode. Pre-enterFirstTask
    // reads (ext2 superblock + symbol/line table loads in main.zig)
    // used the sync polled path; post-this-line reads (every userspace
    // file load via vfs.loadFileFresh) go through submit-and-yield with
    // Q_DEPTH=16-way parallelism.
    // Boot is over — we're in steady-state preemptive multitasking now.
    // Flip the kernel-wide phase flag (paging's boot-only audit consults it).
    @import("../boot/boot_phase.zig").markComplete();
    @import("../driver.zig").nvme.enableAsync();
    run();
    asm volatile ("ud2");
    unreachable;
}

pub fn run() void {
    @import("../cpu/smp.zig").assertBSP("desktop.run");
    if (@import("../cpu/smp.zig").currentPid()) |p| desktop_pid = @intCast(p);
    debug.klog("[desktop] Starting graphical desktop...\n", .{});

    // Register the back-buffer reclaim callback with PMM. When an
    // allocation fails (typically photo / image decode demand-paging
    // into a region bigger than free PMM), handleUserPageFault calls
    // pmm.tryReclaim → us → free the back-buffer slots of every GUI
    // window. Apps lose tear-free presents until their next sysPresent
    // call (lazy realloc), but the system avoids OOM-killing the
    // user's working process.
    pmm.registerReclaim(reclaimBackBuffers);

    // Wipe the VGA text framebuffer to black before the mode switch.
    // Without this, the host display backend mid-transitions the legacy
    // text mode into virtio-gpu scanout — leftover boot-log glyphs from
    // the 80x25 buffer get partially upscaled / re-rendered against the
    // incoming graphical FB and look like colliding text. Better to flash
    // black for a few frames than to show garbled chars.
    // Drop the boot_screen + early framebuffer (BGA) before virtio-gpu
    // mode-set takes over. boot_screen.disable() unhooks vga.redirect_fn
    // so any final klog spew lands wherever it always did; the early_fb
    // handoff turns BGA off cleanly so the virtio mode-set sees the
    // device in a known state. UEFI's GOP framebuffer is replaced by
    // virtio_gpu.framebuffer below — no explicit teardown needed.
    @import("boot_screen.zig").disable();
    @import("early_fb.zig").release();
    @import("../driver.zig").vga.bg = .Black;
    @import("../driver.zig").vga.fg = .Black;
    @import("../driver.zig").vga.clear();
    @import("../driver.zig").vga.available = false;

    const virtio_gpu = @import("../driver.zig").virtio_gpu;
    const gop = @import("../driver.zig").gop_fb;

    // Device selection (virtio-gpu → BGA → GOP) lives in ui/scanout.zig so the
    // installer boots onto the same display the desktop would have picked.
    const so = @import("scanout.zig").bringUp() orelse {
        vga.fg = .LightRed;
        vga.print("No display available!\n", .{});
        vga.fg = .LightGray;
        return;
    };
    const disp_w = so.width;
    const disp_h = so.height;
    screen.display_is_gop = (so.kind == .gop);

    // Back-buffer policy:
    //   * virtio-gpu mode: composite directly into the device resource backing.
    //     The host doesn't see writes until TRANSFER_TO_HOST_2D + RESOURCE_FLUSH,
    //     so the backing IS already a back buffer — no separate alloc, no SSE
    //     memcpy of the full frame on every redraw. Saves ~8MB per .full /
    //     .drag re-render at 1920×1080.
    //   * BGA mode: live framebuffer, host scans out continuously, so we still
    //     need a separate back buffer to avoid tearing.
    // Mode 9 (GPU compositor) forces back-buffer mode even on virtio-gpu
    // so the compositor can sample the desktop's fully rendered scene
    // (windows + chrome + menubar + dock + cursor) without racing the
    // CPU compositor's writes against the GPU compositor's screen-FB
    // writes. Together with `gfx.skip_blit_to_screen = true` below, this
    // makes the compositor the sole writer of virtio-gpu's framebuffer.
    const force_back_buffer = (@import("../boot/boot_info.zig").boot_mode == 9);
    if (virtio_gpu.active and !force_back_buffer) {
        screen.backbuf = @as([*]volatile u32, @ptrCast(virtio_gpu.framebuffer));
        screen.bb_pages = 0;
        gfx.useFramebuffer(); // target := screen (= virtio-gpu resource backing)
        debug.klog("[desktop] Compositor: direct-to-resource (no back buffer)\n", .{});
    } else if (screen.display_is_gop and !gop.direct and !force_back_buffer) {
        // GOP blit mode: GUEST_FB only reaches the panel on flush — it IS a
        // back buffer already, the same shape as virtio's direct-to-resource.
        screen.backbuf = @as([*]volatile u32, @ptrCast(gop.framebuffer));
        screen.bb_pages = 0;
        gfx.useFramebuffer(); // target := screen (= GUEST_FB blit source)
        debug.klog("[desktop] Compositor: direct-to-GUEST_FB (no extra back buffer)\n", .{});
    } else {
        screen.bb_pages = (disp_w * disp_h * 4 + 4095) / 4096;
        if (paging.allocBackBuffer(screen.bb_pages)) |buf| {
            screen.backbuf = buf;
            gfx.setTarget(buf, disp_w, disp_h);
            debug.klog("[desktop] Back buffer: {d} pages (mode={d})\n", .{ screen.bb_pages, @import("../boot/boot_info.zig").boot_mode });
        } else {
            gfx.useFramebuffer();
            debug.klog("[desktop] WARNING: no back buffer\n", .{});
        }
    }
    if (force_back_buffer) {
        gfx.skip_blit_to_screen = true;
        @import("../driver.zig").virtio_gpu.skip_external_flush = true;
        debug.klog("[desktop] Mode 9: blit-to-screen + flush suppressed; GPU compositor owns screen FB\n", .{});
    }

    mouse.screen_w = @intCast(disp_w);
    mouse.screen_h = @intCast(disp_h);
    if (!xhci.hasUsbMouse()) {
        if (!mouse.init()) {
            debug.klog("[desktop] PS/2 mouse not detected — desktop runs without pointer\n", .{});
        }
        keyboard.reEnable();
    } else {
        debug.klog("[desktop] USB mouse active\n", .{});
    }

    // All hardware that auto-binds via pci.bindDevice has now had its init
    // attempt. Surface anything we ignored — typically a NIC variant whose
    // ID we don't match, an unfamiliar AHCI vendor, etc. On QEMU this should
    // be silent; on real HW it's the first place to look when a device
    // doesn't work.
    @import("../driver.zig").pci.logUnbound();

    // Spawn wallpaper.elf as a one-shot — reads /etc/zigos.conf, decodes
    // the configured image via stb_image, pushes pixels to the kernel via
    // sysSetWallpaper, exits. If no wallpaper is configured (or the file
    // is missing), it bails silently and the gradient stays. Fire-and-
    // forget: we don't await it so a slow decode doesn't block boot.
    if (@import("../fs/vfs.zig").loadFileFresh("wallpaper.elf")) |fresh| {
        if (elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, null)) |wpid| {
            @atomicStore(u8, &client.wallpaper_helper, @intCast(wpid), .monotonic);
            process.setName(@intCast(wpid), "wallpaper");
            debug.klog("[desktop] wallpaper.elf spawned pid={d}\n", .{wpid});
        }
    }

    // Reset window/z-stack/slot bookkeeping (alias `wm.window_count` follows).
    wm.z_count = 0;
    wm.window_count = 0;
    @memset(slot_used, false);
    setFocused(0);
    manage.dragging = false;
    input.prev_buttons = 0;
    // Clicks made before the desktop existed are not for it.
    for (&mouse.press_count) |*c| _ = @atomicRmw(u8, c, .Xchg, 0, .monotonic);
    input.press_backlog = .{ 0, 0, 0 };

    // Apply persisted UI config from /etc/zigos.conf (theme, dock, etc.).
    // Done before splash so the splash colors / theme reflect the user's
    // saved preference rather than the compile-time defaults.
    conf.load();

    // Boot splash
    splash.show(screen.backbuf != null);

    const win_w: u32 = TERM_WIN_W;
    const win_h: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
    const win_x: i32 = @intCast((disp_w - win_w) / 2);
    const win_y: i32 = @intCast(MENUBAR_H + (disp_h - MENUBAR_H - TASKBAR_H - win_h) / 2);

    const initial_term_idx = createWindow("Terminal", win_x, win_y, win_w, win_h);
    if (initial_term_idx) |idx| setFocused(idx);

    // (Idle process is now created earlier — in process.enterFirstTask,
    // before this kernel task itself was switched to. See task #235.)

    // Attach a shell to the initial Terminal.
    if (initial_term_idx) |idx| spawnShellOnWindow(idx);

    // Auto-launch vulkan cube disabled (SHM BAR not available under all boot modes)
    // {
    //     const staging: [*]align(4) u8 = @ptrFromInt(0x300000);
    //     if (@import("../fs/vfs.zig").loadFile("vulkan_cube.elf", staging)) |file_size| {
    //         if (elf_loader.loadAndStart(staging, file_size)) |pid| {
    //             process.setName(@intCast(pid), "vk_cube");
    //             debug.klog("[desktop] Auto-launched vulkan_cube PID={d}\n", .{pid});
    //         }
    //     }
    // }

    // Initial render
    const use_hw_cursor = @import("../driver.zig").virtio_gpu.hw_cursor_active;

    renderScene();
    if (screen.backbuf != null) {
        if (!use_hw_cursor) bakeCursorToBackBuffer();
        gfx.blitToScreen();
        if (!use_hw_cursor) unbakeCursorFromBackBuffer();
    }
    if (@import("../driver.zig").virtio_gpu.active) @import("../driver.zig").virtio_gpu.flush();

    active = true;

    // Mode 9: spawn the GPU compositor as a side-by-side kernel task. It
    // samples a window's published gui_fb back-buffer as a Vulkan texture
    // each frame and renders effect-warped output into a corner rect of
    // the desktop. Lower priority than desktop so it never preempts the
    // CPU compositor's blit-to-screen work.
    if (@import("../boot/boot_info.zig").boot_mode == 9) {
        const compositor = @import("gpu_compositor.zig");
        if (process.createKernelTask(@intFromPtr(&compositor.taskEntry), "gpu_comp", 0, .normal, 32 * 1024)) |pid| {
            debug.klog("[desktop] spawned GPU compositor task PID={d}\n", .{pid});
        } else {
            debug.klog("[desktop] failed to spawn GPU compositor\n", .{});
        }
    }

    while (true) {
        frame_count +%= 1;
        // Inject typematic repeats (held keys past the initial delay) into
        // the keyboard ring before we read from it. Cheap: returns immediately
        // unless a key is actually due for repeat.
        keyboard.pollRepeat(process.tick_count);
        // Reap stale zombies — internally rate-limited to once every 5 s,
        // so this is essentially free on every other call. Picks up
        // zombies whose parent never called waitpid (most often: shell
        // exec'd a child that exited but the shell got distracted).
        process.maybeReapZombies();
        // Yield to Ring 3 scheduler — processes run preemptively until
        // the timer decides the desktop needs attention (input, periodic
        // render). When NOTHING is due, parkOrYield blocks this task
        // instead, letting the BSP reach its idle PCB (hlt + tickless
        // stretch) — see the parking block comment near `parked`.
        last_desktop_tick = process.tick_count;
        parkOrYield();
        // Drain both wake channels now that this iteration is running, not
        // before the park: the park needs the self-wake the last iteration
        // asked for (the next animation or toast frame) as its deadline, and
        // a wake requested during that iteration must keep it from parking.
        // Requests made from here on re-arm for the next iteration.
        wake.consume();
        const ftrace = @import("../debug/ftrace.zig");
        ftrace.mark(.desk_wake, 0);
        // Mode 9: the GPU compositor reads the backbuf (or draws from it in
        // place) between our iterations, never during one.
        const gpu_comp = @import("gpu_compositor.zig");
        const source_wait_t0 = @import("../debug/perf.zig").rdtsc();
        const source_held = gpu_comp.beginDraw();
        defer if (source_held) gpu_comp.endDraw();
        frameperf.sourceWaited(@import("../debug/perf.zig").rdtsc() -% source_wait_t0);
        ftrace.mark(.desk_draw, 0);
        // Frame clock starts AFTER parkOrYield returns and the compositor
        // lets us in — parked/yielded time belongs to the scheduler, not to
        // this frame.
        frameperf.frameBegin();
        if (source_held) {
            if (gpu_comp.takeOfferedBackBuffer()) |nb| adoptBackBuffer(nb);
        }

        // Apply config changes from settings app
        if (config_changed) {
            config_changed = false;
            mouse.speed = conf.mouse_speed;
            if (conf.resolution == 1 and gfx.screen_w != 1920) {
                changeResolution(1920, 1080);
            } else if (conf.resolution == 0 and gfx.screen_w != 1280) {
                changeResolution(1280, 720);
            }
            showNotification("Settings applied!");
        }

        // Toast: advance to this tick. A step moves the pill; renderRegions
        // repaints its old and new rects. It asks to be woken for the next
        // slide step, or at the end of the hold.
        const toast_stepped = toast.tick(process.tick_count);
        if (toast.isActive()) wake.requestSelfWake(toast.nextWake(process.tick_count));

        // Reset mouse transfer ring if watchdog flagged it (must run outside IRQ)
        if (xhci.mouse_needs_reset) {
            xhci.resetMouseRing();
        }

        var dirty: DirtyKind = if (dirty_rects_mod.force_full_kind) .full else .none;
        // `force_full_kind` semantically means "the previous frame painted
        // something that won't be tracked by this frame's renderScene"
        // (animation completion, menu close, resolution change, etc.).
        // Mark the rect tracker full so the .full path falls back to full
        // blit instead of partial — partial would miss pixels where the
        // disappearing element used to live (closing-window halo, etc.).
        if (dirty_rects_mod.force_full_kind) markDirtyFull();
        dirty_rects_mod.force_full_kind = false;
        if (toast_stepped) wantRegion(&dirty);
        // The clock or a CPU/MEM bar moved: repaint the menubar.
        if (menubar.stale()) {
            seedRegion(0, 0, @intCast(gfx.screen_w), @as(i32, MENUBAR_H));
            wantRegion(&dirty);
        }

        // Cursor blink edge: when tick_count crosses a blink half-period
        // boundary and the focused window is a terminal, mark dirty so the
        // cursor cell repaints. Driven by ticks (real time) rather than
        // frame_count so the blink rate is independent of how often the
        // desktop loop wakes (~12.5Hz idle vs higher when busy).
        if (slot_used[wm.focused] and windows[wm.focused].term != null and !windows[wm.focused].minimized) {
            const curr_phase = process.tick_count / CURSOR_BLINK_HALF_TICKS;
            if (curr_phase != last_blink_phase) {
                last_blink_phase = curr_phase;
                wantTextRow(&dirty);
            }
            // Self-wake at the start of the next half-period so the blink
            // toggle fires on time even with no other compositor activity.
            const next_phase_tick = (curr_phase + 1) * CURSOR_BLINK_HALF_TICKS;
            wake.requestSelfWake(next_phase_tick);
        }

        // Bell flash: each terminal with a non-zero bell_phase counts down
        // one frame; while active, repaint the window so the red border
        // re-renders.
        var any_bell_active = false;
        for (z_stack[0..wm.z_count]) |wi| {
            if (windows[wi].term) |tt| {
                if (tt.bell_phase > 0) {
                    tt.bell_phase -= 1;
                    seedWindow(wi);
                    wantRegion(&dirty);
                    if (tt.bell_phase > 0) any_bell_active = true;
                }
            }
        }
        // Bell needs to count down on subsequent ticks even with no other
        // wake source. Pace at ~50 Hz (every 2 ticks) — the flash totals
        // only BELL_FLASH_FRAMES so this drains within ~10 wakeups.
        if (any_bell_active) wake.requestSelfWake(process.tick_count + 2);

        var cursor_moved = false;

        // Keyboard — route to focused window
        // When a GUI app is focused, leave keys in the buffer for the app's readChar
        // Global keyboard intercepts (work regardless of focused window type).
        // F-keys live in a separate desktop-only ring so a fullscreen GUI app
        // (DOOM) can't drain them in its readChar polling loop before this
        // intercept runs.
        if (keyboard.peekGlobal()) |pk| {
            if (pk == 0x99) { // F10 — toggle fullscreen
                _ = keyboard.popGlobal();
                if (slot_used[wm.focused] and windows[wm.focused].visible) {
                    toggleFullscreen(wm.focused);
                    dirty = .full;
                }
            } else if (pk == keyboard.KEY_SIGINT) {
                // Ctrl+C — post SIGINT to the focused window's process. Default
                // action terminates; apps that want to handle (shell forwarding
                // to a child, editor cancelling a search, etc.) install a
                // sigaction(SIGINT, ...) handler.
                _ = keyboard.popGlobal();
                if (slot_used[wm.focused] and windows[wm.focused].visible) {
                    // Terminal windows use shell_pid; GUI windows use owner_pid.
                    // Reading the wrong one earlier silently dropped Ctrl+C in
                    // every terminal because owner_pid stays 0xFF for them.
                    const fw = &windows[wm.focused];
                    const target: u8 = if (fw.term != null) fw.shell_pid else fw.owner_pid;
                    if (target != 0xFF) _ = @import("../proc/signals.zig").send(target, @import("../proc/signals.zig").SIGINT);
                }
            } else {
                // Drain unrecognized F-keys so the ring doesn't fill.
                _ = keyboard.popGlobal();
            }
        }
        if (keyboard.alt_held) {
            if (keyboard.peek()) |pk| {
                if (pk == 0x09) { // Alt+Tab
                    _ = keyboard.pop();
                    cycleFocus();
                    dirty = .full;
                }
            }
        }
        // Ctrl+Space or Alt+Space opens the launcher; open, it takes every
        // key until it closes.
        if (!launcher.active and (keyboard.ctrl_held or keyboard.alt_held)) {
            if (keyboard.peek()) |pk| {
                if (pk == ' ') {
                    _ = keyboard.pop();
                    context_menu.close();
                    launcher.open();
                    wantRegion(&dirty);
                }
            }
        }
        while (launcher.active) {
            const ch = keyboard.pop() orelse break;
            const res = launcher.key(ch);
            switch (res) {
                .none => {},
                // The selection or the query changed inside the same rect.
                .changed => {
                    if (launcher.rect()) |r| seedRect(r);
                    wantRegion(&dirty);
                },
                .closed => wantRegion(&dirty),
                .launch => dirty = .full,
            }
            runLauncherResult(res);
        }

        // Desktop is the sole drainer of `keyboard.buffer`. For every
        // popped key:
        //   - publish an event into the focused window's events queue
        //     (consumed by app via `sysPollEvent` / legacy `sysRead`);
        //   - if focused window is a terminal, also run the existing
        //     handleKeyboard path that writes the char into kb_pipe so
        //     the user-space shell keeps reading from fd 0 unchanged.
        // No focus → drop keystrokes silently. (Used to be: drop for
        // GUI focus, terminal-focus path drains via legacy.)
        const focus_ok = slot_used[wm.focused] and windows[wm.focused].visible and !windows[wm.focused].minimized;
        // DBG: when focus check fails AND there are pending keys, log so
        // we know chars are being dropped at the desktop drain. Rate-limit
        // to once per 100 ticks.
        if (!focus_ok and keyboard.hasData()) {
            dbg_focus_drop_count +%= 1;
            if (process.tick_count -% dbg_last_focus_drop_log >= 100) {
                dbg_last_focus_drop_log = process.tick_count;
                debug.klog("[kbd-drop] focus invalid (focused={d} slot_used={any} visible={any} minimized={any}) — drop_count={d}\n", .{
                    wm.focused,
                    slot_used[wm.focused],
                    if (slot_used[wm.focused]) windows[wm.focused].visible else false,
                    if (slot_used[wm.focused]) windows[wm.focused].minimized else false,
                    dbg_focus_drop_count,
                });
            }
        }
        if (focus_ok) {
            const w = &windows[wm.focused];
            const is_terminal = w.term != null;
            while (keyboard.pop()) |ch| {
                // Publish the event. Special key codes (KEY_UP, KEY_F1, ...)
                // are 0x80..0x9F per keyboard.zig; everything else is a
                // post-translation char.
                const kind: u8 = if (ch >= 0x80 and ch <= 0x9F)
                    @intFromEnum(EventKind.key_special)
                else
                    @intFromEnum(EventKind.key_char);
                const mods: u32 =
                    (@as(u32, @intFromBool(keyboard.shift_held)) << 0) |
                    (@as(u32, @intFromBool(keyboard.ctrl_held)) << 1) |
                    (@as(u32, @intFromBool(keyboard.alt_held)) << 2) |
                    (@as(u32, @intFromBool(keyboard.caps_lock)) << 3);
                const queued = w.events.tryPush(.{ .kind = kind, .a = ch, .b = mods });
                // Wake any io_uring OP_POLL waiters on a console fd. We
                // can't filter by which pid owns the focused window here
                // (fdpoll's wake walk does pollMaskConsole, which re-runs
                // the focus/visibility/owner check), so the broadcast
                // (.console, 0xFFFF) lets the matcher do its job.
                if (queued) {
                    @import("../ipc/fdpoll.zig").wakePollers(.console, 0xFFFF);
                }
                if (!queued) {
                    // Queue full, event dropped.
                    dbg_event_queue_full +%= 1;
                    if (process.tick_count -% dbg_last_qfull_log >= 100) {
                        dbg_last_qfull_log = process.tick_count;
                        const target_pid = if (is_terminal) w.shell_pid else w.owner_pid;
                        var t_state: u8 = 0xFF;
                        var t_assigned: u8 = 0xFF;
                        var t_vruntime: u64 = 0;
                        var t_wait: u8 = 0xFF;
                        if (target_pid < process.MAX_PROCS) {
                            const tp = &process.procs[target_pid];
                            t_state = @intFromEnum(tp.state);
                            t_assigned = tp.assigned_cpu;
                            t_vruntime = tp.vruntime;
                            t_wait = @intFromEnum(tp.wait_kind);
                        }
                        debug.klog("[kbd-drop] events FULL pid={d} term={any} drops={d} kb_drop={d} state={d} cpu={d} wait={d} vruntime={d}\n", .{
                            target_pid,
                            is_terminal,
                            dbg_event_queue_full,
                            @atomicLoad(u64, &keyboard.dbg_push_dropped, .monotonic),
                            t_state,
                            t_assigned,
                            t_wait,
                            t_vruntime,
                        });
                        // Per-CPU rq snapshot — see if shell is even in the rq
                        // and if any band has a stuck-huge floor (would explain
                        // CFS picker passing it over every time).
                        const smp_mod = @import("../cpu/smp.zig");
                        var ci: u8 = 0;
                        while (ci < smp_mod.MAX_CPUS) : (ci += 1) {
                            if (!smp_mod.cpus[ci].alive) continue;
                            const rq = &smp_mod.cpus[ci].runqueue;
                            debug.klog("[kbd-drop]  cpu{d}: nr_run={d} (i={d} n={d} bg={d}) min_vr i={d} n={d} bg={d} sched={d}\n", .{
                                ci,
                                rq.nr_runnable,
                                rq.interactive.count, rq.normal.count, rq.background.count,
                                rq.min_vruntime[2], rq.min_vruntime[1], rq.min_vruntime[0],
                                @atomicLoad(u64, &smp_mod.cpus[ci].schedule_count, .monotonic),
                            });
                        }
                    }
                }

                if (is_terminal) {
                    // ESC: a Linux program's key; our own shell has no use for it.
                    if (ch == 0x1B and !@import("../tty/tty.zig").hasLinuxProgram(w.tty)) continue;
                    if (ch == 0x14) { // Ctrl+T: spawn new terminal
                        // window_count is u8; widen before the multiply or `9 * 30 = 270`
        // overflows u8 arithmetic and Zig's runtime safety panics.
        const off: i32 = @intCast(@as(u32, wm.window_count) * 30);
                        const nw: u32 = TERM_WIN_W;
                        const nh: u32 = TERM_ROWS * FONT_H + TITLEBAR_H;
                        if (createWindow("Terminal", 80 + off, 40 + off, nw, nh)) |ni| {
                            setFocused(ni);
                            termPrompt(&windows[ni]);
                            dirty = .full;
                        }
                    } else {
                        const needs_full = handleKeyboard(w, ch);
                        if (needs_full) dirty = .full else wantTextRow(&dirty);
                    }
                }
            }
        }
        // Mouse
        if (mouse.moved) {
            cursor_moved = true;
            // Don't clear mouse.moved here — publishMouseToFocused below
            // reads it. handleMouseEvents clears it implicitly by acting
            // on cur position. Reset after we've published.
        }
        if (cursor_moved or mouse.buttons != input.prev_buttons or pressReplayPending() or mouse.wheel != 0) {
            const btn = frameButtons();
            const prev = input.prev_buttons;
            const moved = mouse.moved;
            mouse.moved = false;
            // handleMouseEvents drains the wheel; the focused app gets the
            // same notches.
            const wheel = mouse.wheel;
            const press_target = pressTarget();
            const mr = handleMouseEvents(btn);
            // After the desktop has acted: focus has settled, so the click
            // that focused a window reaches that window.
            publishMouseToFocused(prev, btn, moved, wheel, press_target);
            switch (mr) {
                .full => dirty = .full,
                .drag => switch (dirty) {
                    .full => {},
                    // A pending row (keypress / cursor blink) rides along with
                    // the drag's regions.
                    .text_only => {
                        damage.text_row_pending = true;
                        dirty = .drag;
                    },
                    else => dirty = .drag,
                },
                .region => wantRegion(&dirty),
                else => {},
            }
            if (cursor_moved and dirty == .none) dirty = .cursor_only;
        }

        // Dock hover tracking for tooltips. A tooltip that appears, moves or
        // vanishes is repainted by renderRegions.
        if (cursor_moved) switch (dock.updateHover(mouse.x, mouse.y, !context_menu.active)) {
            .none => {},
            .tooltip => wantRegion(&dirty),
            .item => {
                // The hover highlight is painted in the pill.
                if (dock.pillRect()) |r| seedRect(r);
                wantRegion(&dirty);
            },
        };

        // Drain stdout pipes for every shell-attached terminal window. The
        // shell process writes via libc.print → fwrite(1) → pipe.write into
        // out_pipe; we pull bytes back here non-blocking and feed them into
        // the window's text buffer. This is the desktop's side of the
        // "TTY-as-two-pipes" architecture: no kernel TTY primitive, just a
        // pair of generic byte streams plus this drain step.
        //
        // Drained bytes can change any rows (`ls`'s lines, a scroll, a
        // program addressing the cursor), so the window is only marked here;
        // the step below repaints whichever rows differ from what they show.
        //
        // A program that prints without pause (`yes`, a long build log)
        // refills the pipe as fast as it is drained here, so each window
        // gets a time slice per iteration: the frame is drawn and the
        // keyboard read in between, and the writer waits on the full pipe.
        {
            const pipe = @import("../proc/pipe.zig");
            const rdtsc = @import("../debug/perf.zig").rdtsc;
            const slice_cyc = @import("../irq/apic.zig").tscPerQuantumSane() * DRAIN_SLICE_MS / 10;
            var drain_buf: [256]u8 = undefined;
            var more = false;
            for (z_stack[0..wm.z_count]) |wi| {
                const w = &windows[wi];
                if (w.out_pipe == 0xFF) continue;
                const t0 = rdtsc();
                var taken: usize = 0;
                while (true) {
                    const got = pipe.tryRead(w.out_pipe, &drain_buf);
                    if (got == 0) break;
                    for (drain_buf[0..got]) |c| putCharOnWindow(w, c);
                    if (w.term) |t| t.rows_stale = true;
                    if (got < drain_buf.len) break;
                    taken += got;
                    // No calibrated clock yet: a byte count stands in.
                    const spent = if (slice_cyc != 0) rdtsc() -% t0 >= slice_cyc else taken >= DRAIN_SLICE_BYTES;
                    if (spent) {
                        more = true;
                        break;
                    }
                }
            }
            if (more) wake.requestWake();
        }

        // Terminals that got output: repaint the rows it changed. Where
        // rows cannot be painted on their own — something lies over the
        // window, it shows its scrollback, or this frame repaints regions
        // anyway — the whole window is repainted as a region.
        //
        // A keystroke or a blink edge in the focused terminal (.text_only)
        // goes the same way: its rows are compared with what they show, so
        // a key whose echo has not come yet draws nothing and presents no
        // frame of its own.
        {
            // The focused terminal is looked at for its text row alone.
            var row_only: u8 = 0xFF;
            if (dirty == .text_only and slot_used[wm.focused]) {
                if (windows[wm.focused].term) |t| {
                    if (!t.rows_stale) row_only = wm.focused;
                    t.rows_stale = true;
                }
            }
            const rows_alone = dirty == .none or dirty == .cursor_only or dirty == .gui_only or dirty == .text_only;
            var rows_painted = false;
            var text_row_done = false;
            for (z_stack[0..wm.z_count], 0..) |wi, z_pos| {
                const t = windows[wi].term orelse continue;
                if (!t.rows_stale) continue;
                t.rows_stale = false;
                if (rows_alone and termRowsPaintable(z_pos, wi)) {
                    if (repaintStaleRows(wi)) rows_painted = true;
                    if (wi == wm.focused) text_row_done = true;
                } else if (row_only == wi) {
                    // Not paintable on its own: the text-row path draws it.
                } else {
                    seedWindow(wi);
                    wantRegion(&dirty);
                }
            }
            if (rows_painted and dirty == .text_only and !text_row_done) {
                // The text row is still owed and a rows-only frame would
                // skip it.
                seedWindow(wm.focused);
                wantRegion(&dirty);
            } else if (rows_painted and (dirty == .none or dirty == .cursor_only or dirty == .text_only)) {
                dirty = .gui_only;
            } else if (dirty == .text_only and text_row_done) {
                // Nothing differed. A software pointer may still have moved.
                dirty = .cursor_only;
            }
        }

        // Check for async app loads completing on AP
        {
            const smp_mod = @import("../cpu/smp.zig");
            if (smp_mod.pollAppLoad()) |_| {
                dirty = .full;
                markDirtyFull();
            }
            // Try to submit a queued launch (no-op if AP still busy).
            launch_queue.drain();
        }

        // Advance window animations
        if (hasActiveAnimations()) {
            advanceAnimations(finishClose);
            dirty = .full;
            markDirtyFull();
            // Animations want a follow-up frame as long as any is still
            // ticking. Pace at 1 tick (~100 Hz upper bound; on 100 Hz
            // timer that's "every frame"). Animation totals are short
            // (~6 frames) so this drains in <100 ms.
            if (hasActiveAnimations()) wake.requestSelfWake(process.tick_count + 1);
        }

        // Auto-refresh: a GUI window whose app never calls sysPresent is read
        // from the app's live framebuffer, so it is re-composited on a
        // timer, at most every 5 ticks (~20 Hz) however often this loop
        // wakes. A window that presents is read from the snapshot
        // sysPresent took and is marked by it (markGuiPresent): nothing to
        // pick up here.
        gui_windows_active = hasGuiWindows();
        gui_autorefresh_active = false;
        if (gui_windows_active) {
            const AUTO_REFRESH_INTERVAL_TICKS: u64 = 5;
            for (z_stack[0..wm.z_count]) |gi| {
                const w = &windows[gi];
                if (w.gui_fb == null or !w.visible or w.has_presented) continue;
                gui_autorefresh_active = true;
                if (process.tick_count -% w.last_auto_refresh_tick >= AUTO_REFRESH_INTERVAL_TICKS) {
                    w.last_auto_refresh_tick = process.tick_count;
                    const h = guiContentHash(w);
                    if (h != w.auto_refresh_hash) {
                        w.auto_refresh_hash = h;
                        w.auto_refresh_settle = true;
                        w.gui_present_pending = true;
                    } else if (w.auto_refresh_settle) {
                        w.auto_refresh_settle = false;
                        w.gui_present_pending = true;
                    }
                }
            }
        }

        // Re-composite GUI windows that need it
        if (gui_windows_active) {
            for (z_stack[0..wm.z_count], 0..) |gi, z_pos| {
                if (windows[gi].gui_present_pending and windows[gi].visible) {
                    // Hidden whole behind another window: the frame stays
                    // pending until some of the window shows.
                    if (windowCovered(z_pos, gi)) continue;
                    windows[gi].gui_present_pending = false;
                    const w = &windows[gi];
                    w.content_seq +%= 1;
                    addDirtyRect(
                        if (w.x < 0) 0 else @intCast(w.x),
                        if (w.y < 0) 0 else @intCast(w.y),
                        w.width + BORDER * 2 + 4,
                        w.height + TITLEBAR_H + BORDER * 2 + 4,
                    );
                    if (screen.backbuf != null) {
                        renderWindow(gi);
                        // Re-paint any visible windows z-above `gi` that overlap
                        // its rect. renderWindow stamps pixels into the back
                        // buffer at the window's screen position regardless of
                        // z-order — without this loop, a background-spawned GUI
                        // updating its FB clobbers the focused terminal above
                        // it in the overlap area (visible as flicker on each
                        // cursor blink). renderScene's bottom→top iteration
                        // handles this correctly; `.gui_only` was the partial-
                        // render path that skipped it.
                        repaintZAboveOverlapping(gi);
                    }
                    if (dirty == .none or dirty == .cursor_only) dirty = .gui_only;
                }
            }
        }

        // Wake the focused window's owner out of sysWaitEvent while it has
        // events to read. Once per pass rather than at each push: covers
        // every push site and a window that just became readable.
        if (slot_used[wm.focused]) {
            const fw = &windows[wm.focused];
            if (fw.visible and !fw.minimized and !fw.events.isEmpty()) event_wait.notify(fw.owner_pid);
        }

        // Hardware cursor: just move, no framebuffer interaction
        if (use_hw_cursor) {
            const vgpu_cur = @import("../driver.zig").virtio_gpu;
            // App override (setCursorVisible(false) on the focused window) wins
            // over auto-hide heuristics — keeps DOOM-style FPS apps from
            // re-showing the cursor on every mouse move.
            if (slot_used[wm.focused]) {
                const fw = &windows[wm.focused];
                if (fw.cursor_hidden_by_app) {
                    // Explicit app override — Doom etc. set this and they
                    // want the cursor gone regardless of window state.
                    if (!vgpu_cur.cursor_hidden) vgpu_cur.hideCursor();
                } else if (fw.gui_fb == null and vgpu_cur.cursor_hidden) {
                    vgpu_cur.showCursor();
                    vgpu_cur.moveCursor(mouse.x, mouse.y);
                } else if (cursor_moved) {
                    vgpu_cur.moveCursor(mouse.x, mouse.y);
                }
            } else if (cursor_moved) {
                vgpu_cur.moveCursor(mouse.x, mouse.y);
            }
        }

        if ((dirty == .gui_only or dirty == .text_only) and partialHitsOverlay(dirty)) wantRegion(&dirty);

        // Render based on what changed
        frameperf.prepDone();
        if (screen.backbuf != null) {
            switch (dirty) {
                .full => {
                    renderScene();
                    // Reverted partial-blit optimization here while
                    // diagnosing a stale-pixel ghost on the cube window —
                    // full blit is the safe path. Re-enable once the
                    // ghost cause is found.
                    if (!use_hw_cursor) bakeCursorToBackBuffer();
                    gfx.blitToScreen();
                    if (!use_hw_cursor) unbakeCursorFromBackBuffer();
                    display.flush();
                    resetDirtyRects();
                },
                .drag, .region => {
                    // Tight path (hw cursor only): repaint just the closed
                    // regions and flush their rects. Falls back to the full-
                    // scene path when renderRegions' preconditions don't hold.
                    if (renderRegions(use_hw_cursor)) {
                        const dr_count = dirty_rects_mod.rectCount(); // can flip to full on cap overflow
                        if (dirty_rects_mod.isFull()) {
                            gfx.blitToScreen();
                            display.flush();
                        } else {
                            var bi: u8 = 0;
                            while (bi < dr_count) : (bi += 1) {
                                const r = dirty_rects_mod.getRect(bi);
                                gfx.blitRectToScreen(r[0], r[1], r[2], r[3]);
                            }
                            var fi: u8 = 0;
                            while (fi < dr_count) : (fi += 1) {
                                const r = dirty_rects_mod.getRect(fi);
                                display.flushRect(r[0], r[1], r[2], r[3]);
                            }
                        }
                        // Mode 9: rect snapshot → GPU compositor (no-op otherwise).
                        @import("gpu_compositor.zig").requestRenderFromDirty();
                        resetDirtyRects();
                    } else {
                        frameperf.regionFallback();
                        renderScene();
                        if (!use_hw_cursor) bakeCursorToBackBuffer();
                        gfx.blitToScreen();
                        if (!use_hw_cursor) unbakeCursorFromBackBuffer();
                        display.flush();
                        resetDirtyRects();
                    }
                },
                .gui_only => {
                    // GUI app content update — only blit the window's dirty rect
                    if (!use_hw_cursor) bakeCursorToBackBuffer();
                    const dr_count = dirty_rects_mod.rectCount();
                    if (dr_count > 0) {
                        var di: u8 = 0;
                        while (di < dr_count) : (di += 1) {
                            const r = dirty_rects_mod.getRect(di);
                            gfx.blitRectToScreen(r[0], r[1], r[2], r[3]);
                        }
                    } else {
                        gfx.blitToScreen();
                    }
                    if (!use_hw_cursor) unbakeCursorFromBackBuffer();
                    if (dr_count > 0) {
                        var di: u8 = 0;
                        while (di < dr_count) : (di += 1) {
                            const r = dirty_rects_mod.getRect(di);
                            display.flushRect(r[0], r[1], r[2], r[3]);
                        }
                    } else {
                        display.flush();
                    }
                    // Mode 9: hand the rect snapshot to the GPU compositor
                    // before the reset clears them. requestRenderFromDirty
                    // is a no-op when not in mode 9 (compositor task isn't up).
                    @import("gpu_compositor.zig").requestRenderFromDirty();
                    resetDirtyRects();
                },
                .text_only => {
                    const cw = &windows[wm.focused];
                    if (cw.term != null and cw.visible and !cw.minimized) {
                        renderTerminalRow(wm.focused);
                        const ct = cw.term.?;
                        const content_y = cw.y + @as(i32, TITLEBAR_H);
                        const ry = content_y + @as(i32, @intCast(@as(u32, ct.text_row) * FONT_H));
                        if (ry >= 0) {
                            const uy: u32 = @intCast(ry);
                            if (!use_hw_cursor) eraseCursor();
                            gfx.blitRectToScreen(if (cw.x < 0) 0 else @intCast(cw.x), uy, cw.width, FONT_H);
                            if (swCursorActive(use_hw_cursor)) drawCursorOnScreen();
                            // Partial flush: just the text row band
                            display.flushRect(0, uy, gfx.screen_w, FONT_H);
                            // Mode 9: terminal row → compositor.
                            const cwx: u32 = if (cw.x < 0) 0 else @intCast(cw.x);
                            @import("gpu_compositor.zig").requestRenderRect(cwx, uy, cw.width, FONT_H);
                        }
                    } else {
                        renderWindow(wm.focused);
                        if (!use_hw_cursor) eraseCursor();
                        blitWindowBounds(wm.focused);
                        if (swCursorActive(use_hw_cursor)) drawCursorOnScreen();
                        // Flush window region
                        {
                            const fy: u32 = if (cw.y < 0) 0 else @intCast(cw.y);
                            display.flushRect(0, fy, gfx.screen_w, cw.height + TITLEBAR_H + 8);
                        }
                        // Mode 9: window region → compositor.
                        const wy: u32 = if (cw.y < 0) 0 else @intCast(cw.y);
                        @import("gpu_compositor.zig").requestRenderRect(0, wy, gfx.screen_w, cw.height + TITLEBAR_H + 8);
                    }
                },
                .cursor_only => {
                    if (!use_hw_cursor) {
                        eraseCursor();
                        if (swCursorActive(use_hw_cursor)) drawCursorOnScreen();
                        // Software cursor: flush cursor bands
                        display.flush();
                    }
                    // Hardware cursor: nothing to flush (moveCursor already sent)
                },
                .none => {},
            }
        } else if (dirty != .none) {
            renderScene();
            if (swCursorActive(use_hw_cursor)) drawCursorOnScreen();
            display.flush();
        }
        // Any rendered frame consumed (region path) or superseded (full paths)
        // the vacated-region accumulator and the region seeds; both come with
        // dirty ∈ {.drag, .region, .full}, so no repaint is lost by clearing.
        damage.drag_accum_valid = false;
        damage.region_seed_count = 0;
        damage.text_row_pending = false;
        ftrace.mark(.desk_done, @intFromEnum(dirty));
        frameperf.frameEnd(switch (dirty) {
            .none => .none,
            .cursor_only => .cursor,
            .text_only => .text,
            .gui_only => .gui,
            .drag => .drag,
            .region => .region,
            .full => .full,
        }, process.tick_count);

    }
    active = false;

    vga.redirect_fn = null;
    session.redirect_win = null;
    if (screen.backbuf != null) {
        paging.freeBackBuffer(screen.bb_pages);
        screen.backbuf = null;
    }
    bga.disable();
    debug.klog("[desktop] Returned to text mode\n", .{});
}

// --- GUI app API (called from syscall handlers) ---

// --- Preemptive multitasking ---

pub var active: bool = false;

// --- Desktop parking (the BSP-spin fix, 2026-06-12) -----------------
//
// The desktop is an ordinary .interactive kernel task that historically
// NEVER blocked: its loop ran schedule(), and with no ready user task
// pickNext handed the CPU straight back — an eternal spin that burned
// ~98% of a host core at an idle desktop (measured via host-side
// pidstat; invisible to the in-OS meter because the spin owned the CPU
// it was sampled from). parkOrYield() makes the loop BLOCK on
// .desktop when nothing is due, so pickNext falls through to the idle
// PCB → hlt/mwait → the tickless BSP stretch finally engages.
//
// Wake paths, fastest first:
//   1. BSP idle loop (wakeIfDueFromIdle): checked BEFORE entering
//      mwait/hlt (with MONITOR already armed — no check→sleep window)
//      and again after an IRQ breaks the wait. µs latency on
//      keystrokes/mouse, and on any producer that fired while the BSP
//      was busy running a task.
//   2. wake.requestWake's monitor-word kick: a producer on ANY CPU
//      (AP app-load completion, a task's terminal-pipe write) bumps the
//      BSP's idle_monitor_word — pops an in-progress mwait instantly,
//      then path 1's post-wake check runs.
//   3. IRQ0 tick block due-check (irq0.zig): catches wake sources that
//      arrived while a USER task was running (no idle transition) —
//      ≤10ms; it retargets wake_tick to "now" and wakeExpired's
//      .desktop branch does the setState.
//   4. wakeExpired at wake_tick: the pending self-wake deadline
//      (animations, toast, the GUI auto-refresh floor) or the 1s
//      liveness backstop (menubar clock, zombie reaper).
//
// Paths 3 and 4 were DEAD until 2026-07-16: wakeExpired had no .desktop
// branch (only .gpu_io/.none honor wake_tick), so every wake funneled
// through path 1's post-IRQ check — which itself only ran after an IRQ
// broke the sleep. Net effect: launch-a-window / write-to-a-terminal
// while the desktop was parked drew NOTHING until the next mouse or
// keyboard IRQ. Path 2 didn't exist (idle_monitor_word had no writer).

/// PCB pid of the desktop task; captured at run() entry. null until then.
var desktop_pid: ?u8 = null;
/// True while the desktop task is blocked in parkOrYield. Read by the
/// IRQ0 due-check and the idle-loop waker (both BSP-local).
var parked: bool = false;

pub fn desktopParkedAndDue() bool {
    if (!@atomicLoad(bool, &parked, .acquire)) return false;
    return shouldResumeDesktop();
}

pub fn desktopPid() ?u8 {
    return desktop_pid;
}

/// Called from the BSP idle loop, both BEFORE sleeping (so a wake posted
/// while this CPU was busy isn't slept over) and right after an IRQ broke
/// hlt/mwait. Wakes the parked desktop in a lock-clean context
/// (sched.wake is NOT IRQ-safe, but idle-loop is). Returns true if it
/// woke the desktop — the pre-sleep caller then schedules instead of
/// entering mwait/hlt.
pub fn wakeIfDueFromIdle() bool {
    if (@import("../cpu/smp.zig").myCpu().cpu_id != 0) return false;
    if (!desktopParkedAndDue()) return false;
    if (desktop_pid) |dp| {
        @import("../proc/sched.zig").wake(dp);
        return true;
    }
    return false;
}

/// Liveness backstop when no self-wake is pending: 1 s. Covers slow
/// periodic housekeeping (menubar clock repaint, zombie reaping) if
/// every event-driven wake source goes quiet.
const PARK_BACKSTOP_TICKS: u64 = 100;

/// Self-wake floor while a visible GUI window is on auto-refresh: 10 Hz.
/// An app that never calls sysPresent is repainted by the loop's
/// auto-refresh, which only runs while the desktop is awake — parked for
/// good, it would freeze such a window at the frame last composited.
/// Windows that present wake the loop themselves, and terminals do through
/// pipe writes and keystrokes, so a desktop of those parks indefinitely.
const GUI_PARK_REFRESH_TICKS: u64 = 10;

/// The desktop loop's yield point. Anything due → plain yield (user
/// tasks run; the timer's force_yield/shouldResumeDesktop brings us
/// back, exactly as before). Nothing due → BLOCK until a wake path
/// fires. wake_tick is set BEFORE blockOn so a wakeExpired deadline
/// can't be missed; blockOn's wake_pending handshake covers racing
/// sched.wake() calls.
fn parkOrYield() void {
    if (shouldResumeDesktop()) {
        yieldToScheduler();
        return;
    }
    const cpu = @import("../cpu/smp.zig").myCpu();
    const me: usize = cpu.current_pid orelse {
        yieldToScheduler();
        return;
    };
    const sched = @import("../proc/sched.zig");
    const pcb = process.getPCB(me);
    // GUI refresh floor (see GUI_PARK_REFRESH_TICKS). Coalesces with any
    // earlier pending self-wake — the min wins. gui_autorefresh_active is
    // one iteration stale here (set mid-loop, read post-loop) — intentional:
    // worst case the floor starts/stops one ~100 ms cycle late when such a
    // window is first created/destroyed, then self-corrects.
    if (gui_autorefresh_active) wake.requestSelfWake(process.tick_count + GUI_PARK_REFRESH_TICKS);
    // Held key: the next auto-repeat is a tick deadline this loop must
    // wake for itself. Nothing else fires while a key stays down (USB HID
    // reports a press once), and with the BSP's tick stretched during
    // idle the IRQ0 due-check alone would pace repeats at 10 Hz.
    if (keyboard.nextRepeatTick(process.tick_count)) |t| wake.requestSelfWake(t);
    const self_due = wake.selfWakeAt();
    const deadline: u64 = if (self_due != 0) self_due else process.tick_count + PARK_BACKSTOP_TICKS;
    @atomicStore(u64, &pcb.wake_tick, deadline, .release);
    sched.registerWakeDeadline(deadline);
    @atomicStore(bool, &parked, true, .release);
    sched.blockOn(.desktop, 0);
    @atomicStore(bool, &parked, false, .release);
    // wake_tick is one-shot; clear so a stale deadline can't re-trip the
    // orphan-sleep diagnostics on a future unrelated park.
    @atomicStore(u64, &pcb.wake_tick, 0, .release);
}

// Desktop update interval: timer returns control every N ticks (~50fps at 100Hz)
var last_desktop_tick: u64 = 0;
const DESKTOP_INTERVAL: u64 = 8;
/// How long one loop iteration reads a terminal's output pipe before it
/// goes on to draw (see the drain step); the byte count is the same bound
/// for a boot with no calibrated clock.
const DRAIN_SLICE_MS: u64 = 4;
const DRAIN_SLICE_BYTES: usize = 16 * 1024;
var gui_windows_active: bool = false;
/// A visible GUI window is being re-composited on the auto-refresh timer.
var gui_autorefresh_active: bool = false;

/// Called by timer IRQ handler to decide when to return control to the desktop.
/// In event-driven mode, the floor wakeups (DESKTOP_INTERVAL + GUI 3-tick) are
/// dropped — the loop sleeps until an explicit wake.requestWake / requestSelfWake
/// fires, or input/config arrives. Flip wake.event_driven=false to restore the
/// legacy fixed-rate polling if a wake source is missed.
pub fn shouldResumeDesktop() bool {
    if (wake.isDue(process.tick_count)) return true;
    if (keyboard.hasData()) return true;
    if (keyboard.repeatDue(process.tick_count)) return true;
    if (mouse.moved) return true;
    if (config_changed) return true;
    if (!wake.event_driven) {
        // Legacy fallback: unconditional rate-based wake.
        if (process.tick_count - last_desktop_tick >= DESKTOP_INTERVAL) return true;
        if (toast.isActive()) return true;
        if (gui_windows_active and process.tick_count - last_desktop_tick >= 3) return true;
    }
    return false;
}

/// Yield to the scheduler. Calls process.schedule() which picks a ready
/// user task (via switchTo) and runs it; when this CPU's scheduler context
/// (i.e., this function's caller, desktop.run) is later resumed — by
/// force_yield in handleIRQ0, by sysExit, or by exhaustion of ready user
/// tasks — schedule() returns and we fall through to housekeeping below.
fn yieldToScheduler() void {
    // In the new (Linux-style) dispatch model, this is just process.schedule().
    // schedule() picks a ready user task and switchTo's to it; when this
    // task (the BSP scheduler context) is later resumed (force_yield path
    // in handleIRQ0, sysExit, no-ready-user fallback), schedule returns
    // and we fall through to the desktop main loop's housekeeping.
    process.schedule();

    // After scheduler context is back, restore kernel CR3. schedule() already
    // switched to kernel CR3 when handing back, but this is harmless and keeps
    // the contract explicit.
    //
    // We do NOT call keyboard.reEnable() here. It used to run every yield
    // (~28×/tick) and was the #1 source of "OURS"-class SMI stalls — caught
    // 2026-05-26 with hits up to 773 ms cli-held at reEnable+0x2ED. The
    // PS/2 config it writes is set once by initPS2() at boot and (if USB
    // keyboard wins) immediately masked by disableIRQ1(); reprogramming
    // the same config byte every yield serves no purpose. The one
    // legitimate post-mouse-init reEnable call still happens at desktop
    // startup (see line ~2765).
    asm volatile ("sti");
    @import("../cpu/mmu/pcid.zig").loadCr3(paging.getKernelPageDirPhys(), 0, @import("../cpu/smp.zig").myCpu().cpu_id);
}
