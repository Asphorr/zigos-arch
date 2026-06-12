// Unified sound interface. Probe order: virtio-sound (modern) → AC97
// (1997-era) → PC speaker (last resort, beeps only). The audioWrite syscall
// dispatches via writeSamples below, so user-space apps get whichever
// streaming backend won the probe without caring which one it was.
//
// AC97 still owns the canned UI sound effects (startup / click / open / err
// / notify) — those are short hardcoded LFO/noise waveforms baked into
// ac97.zig and not worth re-implementing for virtio-sound. The streaming
// path (DOOM, future tone generators / .wav players) is what got modernized.

const virtio_snd = @import("virtio_sound.zig");
const hda = @import("hda.zig");
const ac97 = @import("ac97.zig");
const speaker = @import("speaker.zig");
const debug = @import("../debug/debug.zig");

var use_virtio: bool = false;
var use_hda: bool = false;
var use_ac97: bool = false;

pub fn init() void {
    if (virtio_snd.init()) {
        use_virtio = true;
        debug.klog("[sound] Using virtio-sound (streaming)\n", .{});
    }
    // HDA fills the gap between virtio-sound (modern QEMU only) and AC97
    // (legacy fallback). On real hardware it'll typically be the only
    // working modern audio path.
    if (hda.init()) {
        use_hda = true;
        if (!use_virtio) debug.klog("[sound] Using Intel HDA (streaming)\n", .{});
        _ = hda.selfTest();
    }
    // AC97 still gets initialized so the UI sound effects (startup/click/etc)
    // work even when a higher-priority streaming backend is in use.
    if (ac97.init()) {
        use_ac97 = true;
        if (!use_virtio and !use_hda) debug.klog("[sound] Using AC97 audio\n", .{});
    } else if (!use_virtio and !use_hda) {
        debug.klog("[sound] Falling back to PC speaker\n", .{});
    }
}

/// Stream raw S16 stereo samples. Probe-order dispatch:
/// virtio-sound → HDA → AC97. Silently no-op if no streaming backend.
pub fn writeSamples(src: [*]const i16, stereo_samples: u32) void {
    // Throttled flow diagnostic — every 64th call log frame count + peak
    // amplitude. Lets the audio path be verified from serial.log even with
    // QEMU `-audiodev none` (no host output): a non-zero peak proves real,
    // non-silent samples are reaching the device.
    {
        const D = struct {
            var calls: u32 = 0;
        };
        D.calls +%= 1;
        if (D.calls % 64 == 0) {
            var peak: u32 = 0;
            const n = stereo_samples *| 2;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const v: i32 = src[i];
                const a: u32 = @intCast(if (v < 0) -v else v);
                if (a > peak) peak = a;
            }
            debug.klog("[snd] writeSamples #{d} frames={d} peak={d}\n", .{ D.calls, stereo_samples, peak });
        }
    }
    if (use_virtio and virtio_snd.isReady()) {
        virtio_snd.writeSamples(src, stereo_samples);
        return;
    }
    if (use_hda and hda.isReady()) {
        hda.writeSamples(src, stereo_samples);
        return;
    }
    if (use_ac97) {
        ac97.writeSamples(src, stereo_samples);
        return;
    }
}

pub fn isReady() bool {
    return use_virtio or use_hda or use_ac97;
}

pub fn startup() void {
    if (use_ac97) ac97.startup() else speaker.startup();
}

pub fn click() void {
    if (use_ac97) ac97.click() else speaker.click();
}

pub fn open() void {
    if (use_ac97) ac97.open() else speaker.open();
}

pub fn close() void {
    if (use_ac97) ac97.close() else speaker.close();
}

pub fn err() void {
    if (use_ac97) ac97.err() else speaker.err();
}

pub fn notify() void {
    if (use_ac97) ac97.notify() else speaker.notify();
}

pub fn tick() void {
    // virtio-sound + HDA are IRQ-driven streamers — they don't need a periodic
    // tick. AC97 still owns the UI sound effects (LFO/noise generator) and
    // needs tick() to advance them. PC speaker is the bare-metal fallback.
    if (use_ac97) {
        ac97.tick();
    } else if (!use_virtio and !use_hda) {
        speaker.tick();
    }
}

/// True when the active backend needs the 10ms tick cadence RIGHT NOW
/// (something is audibly playing through a tick-pumped path). Gates the
/// BSP tickless-idle stretch: stretching while AC97 LFO effects or a
/// speaker note queue is live would distort audio. IRQ-driven backends
/// (virtio, HDA) never need it. Unlocked heuristic read — worst case is
/// one stretched-or-not arm decision, self-corrects next fire.
pub fn needsTick() bool {
    if (use_ac97) return ac97.isActive();
    if (!use_virtio and !use_hda) return speaker.isActive();
    return false;
}
