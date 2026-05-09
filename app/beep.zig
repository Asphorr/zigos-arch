// beep — generate a sine-wave tone via the audioWrite syscall.
//
// Usage:
//   beep                    400 ms tone at 440 Hz
//   beep <freq>             400 ms at <freq> Hz
//   beep <freq> <ms>        custom duration in ms
//
// Audio is 22050 Hz S16 stereo to match the kernel's configured PCM stream.
// Each sample is generated from a fixed-point phase accumulator so we don't
// pull in libm. Whether you actually hear the result depends on QEMU's
// -audiodev backend (audiodev=none silently discards; pa/pipewire/sdl
// produce real sound).

const libc = @import("libc");

const SAMPLE_RATE: u32 = 22050;

fn parseU32(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

/// Cheap sine via fifth-order Taylor on a wrapped phase. Input phase is in
/// 16.16 fixed point, units of 2π. Returns int16 in [-amp, amp] (~half scale
/// to leave headroom and avoid clipping if we ever mix). Accuracy is fine
/// for a beeper; nobody's going to A/B this against `aplay`.
fn fastSin(phase_q16: u32) i32 {
    // Reduce to [-π, π] in q16: 65536 == 2π.
    var p: i32 = @bitCast(phase_q16);
    p &= 0xFFFF;
    if (p >= 0x8000) p -= 0x10000;
    // Convert q16-of-2π to q16-of-π:  x ∈ [-π, π] becomes p/0x8000 * π.
    // We want sin(x). For our amplitude scale, use Bhaskara's approximation:
    //   sin(x) ≈ 16x(π - |x|) / (5π² − 4|x|(π − |x|))
    // Here x is treated as fraction of π (so x ∈ [-1, 1]).
    // p / 0x8000 ∈ [-1, 1] is our x.
    const x = p; // x in q15 of π
    var ax: i32 = if (x < 0) -x else x;
    if (ax > 0x8000) ax = 0x8000;
    const pi_minus = 0x8000 - ax;
    const num = ax * pi_minus; // q30
    // Approximation in fixed point: scale to roughly 0..0x4000 (sin in q15).
    // sin ≈ (4 * num) / 0x8000, then signed by x.
    var s: i32 = num >> 13;
    if (x < 0) s = -s;
    return s;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var freq: u32 = 440;
    var dur_ms: u32 = 400;
    const argc = libc.getArgc();
    if (argc >= 2) {
        var b: [16]u8 = undefined;
        const n = libc.getArgv(1, &b);
        if (n != 0 and n != 0xFFFFFFFF) {
            freq = parseU32(b[0..n]) orelse 440;
        }
    }
    if (argc >= 3) {
        var b: [16]u8 = undefined;
        const n = libc.getArgv(2, &b);
        if (n != 0 and n != 0xFFFFFFFF) {
            dur_ms = parseU32(b[0..n]) orelse 400;
        }
    }
    if (freq < 20) freq = 20;
    if (freq > 8000) freq = 8000;
    if (dur_ms > 5000) dur_ms = 5000;

    const total_samples = (SAMPLE_RATE * dur_ms) / 1000;
    libc.print("beep ");
    libc.printNum(freq);
    libc.print(" Hz, ");
    libc.printNum(dur_ms);
    libc.print(" ms (");
    libc.printNum(total_samples);
    libc.print(" samples)\n");

    // Pre-allocate a chunk's worth and submit in 1024-sample bursts (~46ms).
    const CHUNK: u32 = 1024;
    var buf: [CHUNK * 2]i16 = undefined;

    // Phase increment per sample, in q16 of 2π.
    const phase_inc: u32 = (freq * 0x10000) / SAMPLE_RATE;
    var phase: u32 = 0;
    const amp: i32 = 8000; // moderate volume — leaves plenty of headroom

    var emitted: u32 = 0;
    while (emitted < total_samples) {
        const want = if (total_samples - emitted < CHUNK) total_samples - emitted else CHUNK;
        var i: u32 = 0;
        while (i < want) : (i += 1) {
            const s = fastSin(phase);
            const sample: i16 = @intCast(@divTrunc(s * amp, 0x4000));
            buf[i * 2] = sample;
            buf[i * 2 + 1] = sample;
            phase +%= phase_inc;
        }
        // Tiny attack/release to stop ear-stabbing clicks at start/end.
        if (emitted < CHUNK) {
            // Linear ramp-in over the first chunk.
            var j: u32 = 0;
            while (j < want) : (j += 1) {
                const fade: i32 = @intCast((j * 256) / want);
                const l = @divTrunc(@as(i32, buf[j * 2]) * fade, 256);
                buf[j * 2] = @intCast(l);
                buf[j * 2 + 1] = @intCast(l);
            }
        }
        if (emitted + want >= total_samples) {
            // Linear ramp-out over the last chunk.
            var j: u32 = 0;
            while (j < want) : (j += 1) {
                const fade: i32 = @intCast(((want - 1 - j) * 256) / want);
                const l = @divTrunc(@as(i32, buf[j * 2]) * fade, 256);
                buf[j * 2] = @intCast(l);
                buf[j * 2 + 1] = @intCast(l);
            }
        }
        if (!libc.audioWrite(@ptrCast(&buf), want)) {
            libc.print("\x1b[31mbeep: audioWrite failed\x1b[0m\n");
            libc.exit();
        }
        emitted += want;
    }

    // Audio is queued; wait long enough for it to play.
    libc.sleep(dur_ms + 100);
    libc.exit();
}
