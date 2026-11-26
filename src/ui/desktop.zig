// The graphical desktop: the file the rest of the kernel calls it through.
//
// Here are the desktop task (taskEntry, run) and its parking while nothing
// is due. Everything else lives in desktop/ and is re-exported below under
// the names the kernel has always used:
//
//   window.zig   the window table, z-order, focus, hit-testing
//   client.zig   a window as its owner and the kernel see it
//   surface.zig  the pixels of a program's window
//   term/        a terminal window: emulator, cells, view, session
//   chrome.zig   a window as it is painted (corners.zig: its corners)
//   scene.zig    the back buffer: the whole scene, or its changed regions
//   damage.zig   what a frame has to repaint (dirty.zig: the rects flushed)
//   screen.zig   the surface drawn into, its way to the display, the pointer
//   input.zig    keys and the pointer's buttons: who is told what
//   manage.zig   what the pointer does to windows
//   launch.zig, notify.zig, and the parts of the shell: dock, menubar,
//   launcher, context_menu, shortcuts, toast, background, animations
//
// None of them imports this file.

const gfx = @import("gfx.zig");
const bga = @import("../driver.zig").bga;
const mouse = @import("../driver.zig").mouse;
const keyboard = @import("../driver.zig").keyboard;
const vga = @import("../driver.zig").vga;
const xhci = @import("../driver.zig").xhci;
const paging = @import("../mm/paging.zig");
const pmm = @import("../mm/pmm.zig");
const debug = @import("../debug/debug.zig");
const process = @import("../proc/process.zig");
const events_mod = @import("events.zig");

const wm = @import("desktop/window.zig");
const windows = &wm.windows;
const slot_used = &wm.slot_used;
const setFocused = wm.setFocused;
const layout = @import("desktop/layout.zig");
const MENUBAR_H = layout.MENUBAR_H;
const TASKBAR_H = layout.TASKBAR_H;
const TITLEBAR_H = layout.TITLEBAR_H;
const animations = @import("desktop/animations.zig");
const advanceAnimations = animations.advance;
const hasActiveAnimations = animations.hasActive;
// Named so as not to clash with run()'s `dirty`.
const dirty_rects_mod = @import("desktop/dirty.zig");
const markDirtyFull = dirty_rects_mod.markFull;
const event_wait = @import("desktop/event_wait.zig");
const frameperf = @import("desktop/frameperf.zig");
const launch_queue = @import("desktop/launch_queue.zig");
const menubar = @import("desktop/menubar.zig");
const splash = @import("desktop/splash.zig");
const toast = @import("desktop/toast.zig");

const client = @import("desktop/client.zig");
const createWindow = client.createWindow;
const finishClose = client.finishClose;
const surface = @import("desktop/surface.zig");
const hasGuiWindows = surface.hasGuiWindows;
const scene = @import("desktop/scene.zig");
const renderScene = scene.renderScene;
const partialHitsOverlay = scene.partialHitsOverlay;
const damage = @import("desktop/damage.zig");
const DirtyKind = damage.DirtyKind;
const seedRegion = damage.seedRegion;
const wantRegion = damage.wantRegion;
const screen = @import("desktop/screen.zig");
const adoptBackBuffer = screen.adoptBackBuffer;
const bakeCursorToBackBuffer = screen.bakeCursorToBackBuffer;
const unbakeCursorFromBackBuffer = screen.unbakeCursorFromBackBuffer;
const changeResolution = screen.changeResolution;
const input = @import("desktop/input.zig");
const manage = @import("desktop/manage.zig");
const notify = @import("desktop/notify.zig");
const emulator = @import("desktop/term/emulator.zig");
const TERM_ROWS = emulator.TERM_ROWS;
const cells = @import("desktop/term/cells.zig");
const FONT_H = cells.FONT_H;
const TERM_WIN_W = cells.TERM_WIN_W;
const term_view = @import("desktop/term/view.zig");
const session = @import("desktop/term/session.zig");
const spawnShellOnWindow = session.spawnShellOnWindow;

// --- What the kernel calls the desktop by ---

pub const Event = events_mod.Event;
pub const EventKind = events_mod.EventKind;
/// The persisted settings (wallpaper, theme, dock, pointer speed,
/// resolution): desktop.conf.<field>. A writer sets config_changed.
pub const conf = @import("desktop/config.zig");
pub var config_changed: bool = false;
/// How the desktop is woken (see the parking notes below).
pub const wake = @import("desktop/wake.zig");

pub const showNotification = notify.showNotification;
pub const showNotificationFrom = notify.showNotificationFrom;

pub const createGuiWindow = client.createGuiWindow;
pub const DestroyedGui = client.DestroyedGui;
pub const GuiOwner = client.GuiOwner;
pub const groupHasGuiWindow = client.groupHasGuiWindow;
pub const destroyGuiWindow = client.destroyGuiWindow;
pub const markGuiPresent = surface.markGuiPresent;
pub const snapshotGuiFb = surface.snapshotGuiFb;
pub const reclaimBackBuffers = surface.reclaimBackBuffers;

pub const focusedPid = client.focusedPid;
pub const focusedSignalTarget = client.focusedSignalTarget;
pub const focusedTty = client.focusedTty;
pub const focusedShellSpawnedPid = client.focusedShellSpawnedPid;
pub const canReadConsole = client.canReadConsole;
pub const consoleReadable = client.consoleReadable;
pub const popEvent = client.popEvent;
pub const popCharEvent = client.popCharEvent;
pub const getMouseRelative = client.getMouseRelative;
pub const setCursorHidden = client.setCursorHidden;
pub const centerMouse = client.centerMouse;
pub const getWindowContentSize = client.getWindowContentSize;
pub const getWindowAllocSize = client.getWindowAllocSize;

// For the GPU compositor (mode 9).
pub const getBackBuffer = screen.getBackBuffer;
pub const occludersAbove = scene.occludersAbove;

pub const Standing = client.Standing;

/// Whether task `pid` belongs to a program the user has in front of them
/// (client.actsFor). With no desktop there is one console and nobody to
/// take from: everything is allowed.
pub fn actsFor(pid: u8, standing: Standing) bool {
    return !active or client.actsFor(pid, standing);
}

/// set_wallpaper: a program on screen or the boot helper
/// (client.maySetWallpaper); anyone while there is no desktop.
pub fn maySetWallpaper(pid: u8) bool {
    return !active or client.maySetWallpaper(pid);
}

// --- The desktop task ---

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

    const so = screen.bringUp() orelse return;
    const disp_w = so.width;
    const disp_h = so.height;

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

    client.startWallpaperHelper();

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

        // Each step takes the frame's kind and returns it raised by what the
        // step found to repaint.
        dirty = term_view.blinkAndBell(dirty);
        dirty = input.keys(dirty);
        const cursor_moved = mouse.moved;
        dirty = input.pointer(dirty, cursor_moved);
        // Program output into the terminals' grids, then onto their rows.
        session.drainOutput();
        dirty = term_view.repaintStale(dirty);

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

        // GUI windows: the ones that never present are looked at for new
        // pixels, then every window with a frame pending goes into the back
        // buffer.
        gui_windows_active = hasGuiWindows();
        gui_autorefresh_active = gui_windows_active and surface.pollUnpresented();
        if (gui_windows_active) dirty = scene.recomposite(dirty);

        // Wake the focused window's owner out of sysWaitEvent while it has
        // events to read. Once per pass rather than at each push: covers
        // every push site and a window that just became readable.
        if (slot_used[wm.focused]) {
            const fw = &windows[wm.focused];
            if (fw.visible and !fw.minimized and !fw.events.isEmpty()) event_wait.notify(fw.owner_pid);
        }

        screen.placePointer(use_hw_cursor, cursor_moved);

        if ((dirty == .gui_only or dirty == .text_only) and partialHitsOverlay(dirty)) wantRegion(&dirty);

        // Render based on what changed
        frameperf.prepDone();
        scene.present(dirty, use_hw_cursor);
        damage.endFrame();
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

/// There is a desktop: true from its first frame on.
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
