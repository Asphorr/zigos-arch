// Intel HDA (High Definition Audio) controller driver — Phase 1.
//
// Spec: Intel "High Definition Audio Specification" Rev 1.0a (2010).
// Targets ICH6/ICH9-class controllers (PCI class 04.03). On QEMU, expose
// via `-device intel-hda -device hda-duplex,audiodev=...`.
//
// Phase 1 scope (this file):
//   - PCI probe + BAR map + bus master enable
//   - Controller reset (GCTL.CRST toggle)
//   - CORB / RIRB ring setup (codec verb path)
//   - Codec discovery: vendor ID, audio function group, first DAC, first
//     output pin
//   - Self-test: program output stream descriptor with a 4 KB silence
//     buffer cycling on a 2-entry BDL, run for 100 ms, verify LPIB (link
//     position) advanced by ~19200 bytes (= 48 kHz × 2 ch × 2 B × 0.1 s).
//
// The self-test is hardware-independent: LPIB is driven by the
// controller's own clock, not by the host's audio backend. Works on QEMU
// even with `audiodev=none` (no actual sound out).
//
// Phase 2+ (later): IRQ-driven completion, real PCM streaming via
// writeSamples(), integration with sound.zig in front of/replacing AC97.

const pci = @import("pci.zig");
const pmm = @import("../mm/pmm.zig");
const paging = @import("../mm/paging.zig");
const debug = @import("../debug/debug.zig");
const hpet = @import("../time/hpet.zig");
const SpinLock = @import("../proc/spinlock.zig").SpinLock;
const iommu = @import("../cpu/iommu.zig");

var pci_bus: u8 = 0;
var pci_dev: u8 = 0;
var pci_func: u8 = 0;

// PCI class for HDA controllers (subclass 03 prog_if 0).
const HDA_CLASS: u8 = 0x04;
const HDA_SUBCLASS: u8 = 0x03;

// --- HDA controller register offsets (BAR0) ---
const REG_GCAP: u32 = 0x00;
const REG_GCTL: u32 = 0x08;
const REG_STATESTS: u32 = 0x0E;
const REG_CORBLBASE: u32 = 0x40;
const REG_CORBUBASE: u32 = 0x44;
const REG_CORBWP: u32 = 0x48;
const REG_CORBRP: u32 = 0x4A;
const REG_CORBCTL: u32 = 0x4C;
const REG_CORBSTS: u32 = 0x4D;
const REG_CORBSIZE: u32 = 0x4E;
const REG_RIRBLBASE: u32 = 0x50;
const REG_RIRBUBASE: u32 = 0x54;
const REG_RIRBWP: u32 = 0x58;
const REG_RINTCNT: u32 = 0x5A;
const REG_RIRBCTL: u32 = 0x5C;
const REG_RIRBSTS: u32 = 0x5D;
const REG_RIRBSIZE: u32 = 0x5E;

// Immediate Command Output Interface (ICOI). Single-shot verb path that
// bypasses the CORB/RIRB ring buffers — write verb to ICOI, kick ICB=1,
// poll IRV=1, read IRII for response. Optional per spec but implemented
// by QEMU's intel-hda emulation. Phase 1 uses this exclusively because
// the CORB DMA engine on QEMU intel-hda gets wedged after the first verb
// (CORBRP refuses to advance past 1 — diagnosed via ring-state dumps).
// Once we move to streaming we'll either fix the CORB issue or accept
// that real-HW Intel chips after ~2010 dropped ICOI and need rings.
const REG_ICOI: u32 = 0x60; // 32-bit, write verb here
const REG_IRII: u32 = 0x64; // 32-bit, read response here
const REG_ICIS: u32 = 0x68; // 16-bit: bit 0 ICB (busy), bit 1 IRV (response valid)
const ICIS_ICB: u16 = 1 << 0;
const ICIS_IRV: u16 = 1 << 1;

// Stream descriptors: 0x80 + idx*0x20. Layout same for in/out/bidir streams.
const SD_BASE: u32 = 0x80;
const SD_STRIDE: u32 = 0x20;
const SD_CTL: u32 = 0x00; // 24-bit, but we access as bytes (0x00..0x02)
const SD_LPIB: u32 = 0x04;
const SD_CBL: u32 = 0x08;
const SD_LVI: u32 = 0x0C;
const SD_FMT: u32 = 0x12;
const SD_BDPL: u32 = 0x18;
const SD_BDPU: u32 = 0x1C;

// GCTL bits
const GCTL_CRST: u32 = 1 << 0;

// CORBCTL / RIRBCTL bits
const CORBCTL_RUN: u8 = 1 << 1;
const RIRBCTL_DMAEN: u8 = 1 << 1;

// SD_CTL low byte bits
const SDCTL_SRST: u8 = 1 << 0;
const SDCTL_RUN: u8 = 1 << 1;

// CORB/RIRB pointer reset bits
const CORBRP_RST: u16 = 1 << 15;
const RIRBWP_RST: u16 = 1 << 15;

// --- Codec verb encoding ---
//
// 32-bit verb format:  CAd[31:28] | NID[27:20] | Verb[19:8] | Payload[7:0]
//                     (12-bit verb / 8-bit payload form)
// Long form:           CAd[31:28] | NID[27:20] | Verb[19:16] | Payload[15:0]
//                     (4-bit verb / 16-bit payload form, used by SET/GET
//                      converter format and amp gain/mute)
const VERB_GET_PARAMETER: u32 = 0xF00;
const VERB_SET_POWER_STATE: u32 = 0x705;
const VERB_SET_PIN_WIDGET_CONTROL: u32 = 0x707;
const VERB_SET_CHANNEL_STREAM_ID: u32 = 0x706;

// 4-bit verbs (long form)
const VERB_SET_CONVERTER_FORMAT_4BIT: u32 = 0x2;
const VERB_SET_AMP_GAIN_MUTE_4BIT: u32 = 0x3;

// GET_PARAMETER parameter IDs
const PARAM_VENDOR_ID: u32 = 0x00;
const PARAM_SUB_NODE_COUNT: u32 = 0x04;
const PARAM_FUNC_GROUP_TYPE: u32 = 0x05;
const PARAM_AUDIO_WIDGET_CAP: u32 = 0x09;
const PARAM_PIN_CAP: u32 = 0x0C;

// Function group types
const FG_AUDIO: u32 = 0x01;

// Widget types (bits 23..20 of audio widget cap)
const WIDGET_DAC: u32 = 0x0;
const WIDGET_PIN: u32 = 0x4;

// Pin widget control payload bits
const PIN_CTL_OUT_ENABLE: u8 = 1 << 6;
const PIN_CTL_HEADPHONE_AMP: u8 = 1 << 7;

// --- Driver state ---
var hba_virt: usize = 0;
var oss: u8 = 0;
var iss: u8 = 0;
var first_codec: u8 = 0xFF;
var afg_nid: u8 = 0;
var dac_nid: u8 = 0;
var pin_nid: u8 = 0;

var corb_virt: [*]volatile u32 = undefined;
var corb_size: u16 = 0;
var corb_wp: u16 = 0;

var rirb_virt: [*]volatile u64 = undefined;
var rirb_size: u16 = 0;
var rirb_rp: u16 = 0;

// --- Persistent output stream state (Phase 2) ---
// Allocated once during init via streamSetup(); writeSamples() reuses the
// same buffer/BDL/SD on every call. 64 KB cyclic buffer, two 32 KB BDL
// halves. Stream tag 1 (arbitrary, must match SET_CHANNEL_STREAM_ID).
const STREAM_PAGES: u32 = 16; // 64 KB
const STREAM_TAG: u8 = 1;
const STREAM_FMT: u16 = 0x0011; // 48 kHz × 2 ch × 16-bit (verified via GET_CONVERTER_FORMAT)

var stream_active: bool = false;
var stream_buf_phys: usize = 0;
var stream_buf_virt: [*]u8 = undefined;
var stream_buf_size: u32 = 0;
var stream_bdl_phys: usize = 0;
var stream_sd_idx: u8 = 0;

// Serializes writeSamples vs concurrent calls. AC97 uses IrqSave for its
// IRQ-driven tick(); HDA Phase 2 is polled-only with no IRQ handler, so
// a plain acquire is sufficient.
var lock: SpinLock = .{};

// --- MMIO accessors ---
inline fn r32(off: u32) u32 {
    return @as(*volatile u32, @ptrFromInt(hba_virt + off)).*;
}
inline fn w32(off: u32, val: u32) void {
    @as(*volatile u32, @ptrFromInt(hba_virt + off)).* = val;
}
inline fn r16(off: u32) u16 {
    return @as(*volatile u16, @ptrFromInt(hba_virt + off)).*;
}
inline fn w16(off: u32, val: u16) void {
    @as(*volatile u16, @ptrFromInt(hba_virt + off)).* = val;
}
inline fn r8(off: u32) u8 {
    return @as(*volatile u8, @ptrFromInt(hba_virt + off)).*;
}
inline fn w8(off: u32, val: u8) void {
    @as(*volatile u8, @ptrFromInt(hba_virt + off)).* = val;
}
inline fn sdOff(idx: u8, off: u32) u32 {
    return SD_BASE + @as(u32, idx) * SD_STRIDE + off;
}

fn busyWaitMs(ms: u32) void {
    // Approximate. ~10 cycles per pause iter; 3 GHz = 300K pauses/ms. We
    // use 250K to be conservative. Real timing tolerance handled in the
    // self-test by widening the LPIB advance acceptance band.
    var i: u32 = 0;
    const target = ms * 250_000;
    while (i < target) : (i += 1) {
        asm volatile ("pause" ::: .{ .memory = true });
    }
}

fn allocPage() ?usize {
    const p = pmm.allocFrame() orelse return null;
    const v: [*]u8 = @ptrFromInt(paging.physToVirt(p));
    @memset(v[0..4096], 0);
    return p;
}

// --- Verb dispatch via CORB/RIRB ---
//
// Submit one verb at a time. Each verb takes a single CORB slot and gets
// one RIRB response slot back. We poll RIRB.WP for advance — Phase 1 is
// polled-mode only; Phase 2 will wire MSI-X.

fn buildVerbShort(codec: u8, nid: u8, verb12: u32, payload8: u32) u32 {
    return (@as(u32, codec & 0x0F) << 28) |
        (@as(u32, nid) << 20) |
        ((verb12 & 0xFFF) << 8) |
        (payload8 & 0xFF);
}

fn buildVerbLong(codec: u8, nid: u8, verb4: u32, payload16: u32) u32 {
    return (@as(u32, codec & 0x0F) << 28) |
        (@as(u32, nid) << 20) |
        ((verb4 & 0xF) << 16) |
        (payload16 & 0xFFFF);
}

fn sendVerbRaw(verb: u32) ?u32 {
    // ICOI single-shot verb path. Sequence per HDA spec §3.3.36-38:
    //   1. Wait for ICB=0 (controller idle)
    //   2. Clear stale IRV (write 1 to bit 1)
    //   3. Write verb to ICOI
    //   4. Set ICB=1 to kick
    //   5. Poll IRV=1 for response
    //   6. Read response from IRII
    //   7. Clear IRV
    var spins: u32 = 0;
    while ((r16(REG_ICIS) & ICIS_ICB) != 0 and spins < 100_000) : (spins += 1) {
        asm volatile ("pause");
    }
    if ((r16(REG_ICIS) & ICIS_ICB) != 0) {
        debug.klog("[hda] ICOI busy at entry (verb=0x{X})\n", .{verb});
        return null;
    }

    w16(REG_ICIS, ICIS_IRV); // clear any stale response valid
    w32(REG_ICOI, verb);
    w16(REG_ICIS, ICIS_ICB); // kick

    spins = 0;
    while ((r16(REG_ICIS) & ICIS_IRV) == 0 and spins < 1_000_000) : (spins += 1) {
        asm volatile ("pause");
    }
    if ((r16(REG_ICIS) & ICIS_IRV) == 0) {
        debug.klog("[hda] ICOI timeout (verb=0x{X} icis=0x{X})\n", .{ verb, r16(REG_ICIS) });
        return null;
    }

    const resp = r32(REG_IRII);
    w16(REG_ICIS, ICIS_IRV); // clear IRV
    return resp;
}

fn getParameter(codec: u8, nid: u8, param: u32) ?u32 {
    return sendVerbRaw(buildVerbShort(codec, nid, VERB_GET_PARAMETER, param));
}

// --- Init ---

pub fn init() bool {
    const dev = pci.findByClassPartial(HDA_CLASS, HDA_SUBCLASS) orelse {
        debug.klog("[hda] No HDA-class device found\n", .{});
        return false;
    };
    debug.klog("[hda] Found {X:0>4}:{X:0>4} at bus={d} dev={d} func={d}\n", .{
        dev.vendor_id, dev.device_id, dev.bus, dev.dev, dev.func,
    });

    // Bus master + MEM (HDA is MMIO; INTx kept disabled — Phase 1 is polled).
    pci.bindDevice(dev);
    pci_bus = dev.bus;
    pci_dev = dev.dev;
    pci_func = dev.func;

    // IOMMU Phase 3: flip onto own SL page table before any DMA. CORB/
    // RIRB and stream buffers are mapped as they're allocated below.
    _ = iommu.enableIsolation(dev.bus, dev.dev, dev.func);

    const bar0 = pci.mapBar(dev, 0, 0x4000) orelse {
        debug.klog("[hda] mapBar failed\n", .{});
        return false;
    };
    hba_virt = bar0;
    debug.klog("[hda] BAR0 mapped at 0x{X}\n", .{bar0});

    // Controller reset: clear GCTL.CRST, wait for it to read 0; set, wait
    // for it to read 1. Per spec, codecs need a window after CRST=1
    // before STATESTS is valid.
    w32(REG_GCTL, 0);
    var spins: u32 = 0;
    while (r32(REG_GCTL) & GCTL_CRST != 0 and spins < 100_000) : (spins += 1) {
        asm volatile ("pause");
    }
    if (spins == 100_000) {
        debug.klog("[hda] reset clear timeout\n", .{});
        return false;
    }
    busyWaitMs(1);
    w32(REG_GCTL, GCTL_CRST);
    spins = 0;
    while (r32(REG_GCTL) & GCTL_CRST == 0 and spins < 100_000) : (spins += 1) {
        asm volatile ("pause");
    }
    if (spins == 100_000) {
        debug.klog("[hda] reset assert timeout\n", .{});
        return false;
    }
    busyWaitMs(2); // codec detect window

    // Decode capabilities.
    const gcap = r16(REG_GCAP);
    iss = @intCast((gcap >> 8) & 0x0F);
    oss = @intCast((gcap >> 12) & 0x0F);
    const bss: u8 = @intCast((gcap >> 3) & 0x1F);
    debug.klog("[hda] GCAP=0x{X:0>4} ISS={d} OSS={d} BSS={d}\n", .{ gcap, iss, oss, bss });
    if (oss == 0) {
        debug.klog("[hda] no output streams supported\n", .{});
        return false;
    }

    // Codec presence bitmap.
    const statests = r16(REG_STATESTS);
    debug.klog("[hda] STATESTS=0x{X:0>4}\n", .{statests});
    if (statests == 0) {
        debug.klog("[hda] no codecs detected\n", .{});
        return false;
    }
    var addr: u8 = 0;
    var bits = statests;
    while (bits & 1 == 0) : (bits >>= 1) addr += 1;
    first_codec = addr;
    debug.klog("[hda] first codec at address {d}\n", .{first_codec});

    if (!setupCorbRirb()) return false;

    // Proof of life: read codec vendor ID. If we get a nonzero answer the
    // CORB→codec→RIRB round trip works.
    const vid = getParameter(first_codec, 0, PARAM_VENDOR_ID) orelse {
        debug.klog("[hda] vendor ID query failed\n", .{});
        return false;
    };
    debug.klog("[hda] codec vendor=0x{X:0>4} device=0x{X:0>4}\n", .{
        @as(u16, @truncate(vid >> 16)),
        @as(u16, @truncate(vid)),
    });

    if (!discoverWidgets()) return false;

    if (!streamSetup()) {
        debug.klog("[hda] streamSetup failed\n", .{});
        return false;
    }

    debug.klog("[hda] init OK (afg={d} dac={d} pin={d}, stream ready)\n", .{ afg_nid, dac_nid, pin_nid });
    return true;
}

// Permanent stream/buffer/BDL setup. Programs the SD and codec once with
// 48 kHz × 2 ch × 16-bit. From here, writeSamples() just refills the
// buffer and toggles RUN; no need to re-program format or pin every call.
fn streamSetup() bool {
    stream_buf_phys = pmm.allocContiguous(STREAM_PAGES) orelse return false;
    stream_buf_virt = @ptrFromInt(paging.physToVirt(stream_buf_phys));
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, stream_buf_phys, STREAM_PAGES * 4096, .{});
    stream_buf_size = STREAM_PAGES * 4096;
    @memset(stream_buf_virt[0..stream_buf_size], 0);

    stream_bdl_phys = allocPage() orelse {
        pmm.freeContiguous(stream_buf_phys, STREAM_PAGES);
        return false;
    };
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, stream_bdl_phys, 4096, .{});
    const bdl: [*]volatile u64 = @ptrFromInt(paging.physToVirt(stream_bdl_phys));
    const half: u64 = stream_buf_size / 2;
    bdl[0] = @as(u64, stream_buf_phys);
    bdl[1] = half;
    bdl[2] = @as(u64, stream_buf_phys) + half;
    bdl[3] = half;

    stream_sd_idx = iss; // first output SD

    streamStop();

    w32(sdOff(stream_sd_idx, SD_CBL), stream_buf_size);
    w8(sdOff(stream_sd_idx, SD_LVI), 1);
    w16(sdOff(stream_sd_idx, SD_FMT), STREAM_FMT);
    w32(sdOff(stream_sd_idx, SD_BDPL), @truncate(stream_bdl_phys));
    w32(sdOff(stream_sd_idx, SD_BDPU), @truncate(stream_bdl_phys >> 32));
    // Stream tag in bits 23..20 of CTL (byte at offset +2).
    w8(sdOff(stream_sd_idx, SD_CTL) + 2, STREAM_TAG << 4);

    // Codec: route DAC into stream 1, set format, enable pin output, unmute amps.
    _ = sendVerbRaw(buildVerbShort(first_codec, dac_nid, VERB_SET_CHANNEL_STREAM_ID, STREAM_TAG << 4));
    _ = sendVerbRaw(buildVerbLong(first_codec, dac_nid, VERB_SET_CONVERTER_FORMAT_4BIT, STREAM_FMT));
    _ = sendVerbRaw(buildVerbShort(first_codec, pin_nid, VERB_SET_PIN_WIDGET_CONTROL, PIN_CTL_OUT_ENABLE | PIN_CTL_HEADPHONE_AMP));
    _ = sendVerbRaw(buildVerbLong(first_codec, dac_nid, VERB_SET_AMP_GAIN_MUTE_4BIT, 0xB07F));
    _ = sendVerbRaw(buildVerbLong(first_codec, pin_nid, VERB_SET_AMP_GAIN_MUTE_4BIT, 0xB07F));

    stream_active = true;
    return true;
}

fn streamStop() void {
    w8(sdOff(stream_sd_idx, SD_CTL) + 0, 0); // clear RUN/IOCE/etc; preserve byte+2 (stream tag)
    var spins: u32 = 0;
    while ((r8(sdOff(stream_sd_idx, SD_CTL)) & SDCTL_RUN) != 0 and spins < 10_000) : (spins += 1) {
        asm volatile ("pause");
    }
    // Stream reset to drop LPIB back to 0.
    w8(sdOff(stream_sd_idx, SD_CTL), SDCTL_SRST);
    spins = 0;
    while ((r8(sdOff(stream_sd_idx, SD_CTL)) & SDCTL_SRST) == 0 and spins < 10_000) : (spins += 1) {
        asm volatile ("pause");
    }
    w8(sdOff(stream_sd_idx, SD_CTL), 0);
    spins = 0;
    while ((r8(sdOff(stream_sd_idx, SD_CTL)) & SDCTL_SRST) != 0 and spins < 10_000) : (spins += 1) {
        asm volatile ("pause");
    }
    // Reapply the stream tag (it was zeroed by reset).
    w8(sdOff(stream_sd_idx, SD_CTL) + 2, STREAM_TAG << 4);
}

fn streamStart() void {
    w8(sdOff(stream_sd_idx, SD_CTL), SDCTL_RUN);
}

/// Public streaming API. Matches the AC97 / virtio-snd contract: i16 stereo
/// samples (= 2 i16 values per stereo frame), count is the number of
/// stereo frames. Each call replaces the buffer contents and (re)starts
/// playback — same one-shot model as ac97.writeSamples. For continuous
/// streaming, call back-to-back with chunks of similar length.
///
/// Calls are bounded by the buffer size: anything beyond ~170 ms at 48 kHz
/// stereo (= 64 KB) is silently truncated. Tail of buffer is zeroed so the
/// codec doesn't replay stale samples after the new ones.
pub fn writeSamples(src: [*]const i16, stereo_samples: u32) void {
    if (!stream_active or stereo_samples == 0) return;
    lock.acquire();
    defer lock.release();

    streamStop();

    const requested_bytes = stereo_samples * 4; // 2 ch × 2 bytes
    const bytes = @min(requested_bytes, stream_buf_size);
    const src_bytes: [*]const u8 = @ptrCast(src);
    @memcpy(stream_buf_virt[0..bytes], src_bytes[0..bytes]);
    if (bytes < stream_buf_size) {
        @memset(stream_buf_virt[bytes..stream_buf_size], 0);
    }

    streamStart();
}

pub fn isReady() bool {
    return stream_active;
}

fn setupCorbRirb() bool {
    const corb_phys = allocPage() orelse return false;
    corb_virt = @ptrFromInt(paging.physToVirt(corb_phys));
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, corb_phys, 4096, .{});

    const rirb_phys = allocPage() orelse return false;
    rirb_virt = @ptrFromInt(paging.physToVirt(rirb_phys));
    _ = iommu.dmaMap(pci_bus, pci_dev, pci_func, rirb_phys, 4096, .{});

    // Stop both rings before reconfiguring.
    w8(REG_CORBCTL, 0);
    w8(REG_RIRBCTL, 0);

    // Pick the largest size each ring supports. CORBSIZE/RIRBSIZE bits 6/5/4
    // advertise 256/16/2-entry capability; bits 1..0 select.
    const corbsize_cap = r8(REG_CORBSIZE);
    var corbsize_sel: u8 = 0;
    if (corbsize_cap & 0x40 != 0) {
        corbsize_sel = 0x02;
        corb_size = 256;
    } else if (corbsize_cap & 0x20 != 0) {
        corbsize_sel = 0x01;
        corb_size = 16;
    } else {
        corbsize_sel = 0x00;
        corb_size = 2;
    }
    w8(REG_CORBSIZE, corbsize_sel);
    w32(REG_CORBLBASE, @truncate(corb_phys));
    w32(REG_CORBUBASE, @truncate(corb_phys >> 32));

    // Reset CORB read pointer (HW-controlled). Toggle bit 15 and wait.
    w16(REG_CORBRP, CORBRP_RST);
    var spins: u32 = 0;
    while ((r16(REG_CORBRP) & CORBRP_RST) == 0 and spins < 100_000) : (spins += 1) {
        asm volatile ("pause");
    }
    w16(REG_CORBRP, 0);
    spins = 0;
    while ((r16(REG_CORBRP) & CORBRP_RST) != 0 and spins < 100_000) : (spins += 1) {
        asm volatile ("pause");
    }
    corb_wp = 0;
    w16(REG_CORBWP, 0);

    const rirbsize_cap = r8(REG_RIRBSIZE);
    var rirbsize_sel: u8 = 0;
    if (rirbsize_cap & 0x40 != 0) {
        rirbsize_sel = 0x02;
        rirb_size = 256;
    } else if (rirbsize_cap & 0x20 != 0) {
        rirbsize_sel = 0x01;
        rirb_size = 16;
    } else {
        rirbsize_sel = 0x00;
        rirb_size = 2;
    }
    w8(REG_RIRBSIZE, rirbsize_sel);
    w32(REG_RIRBLBASE, @truncate(rirb_phys));
    w32(REG_RIRBUBASE, @truncate(rirb_phys >> 32));
    w16(REG_RIRBWP, RIRBWP_RST);
    busyWaitMs(1);
    rirb_rp = 0;
    // Interrupt every response — only matters once we wire MSI-X.
    w16(REG_RINTCNT, 1);

    // Start the rings.
    w8(REG_CORBCTL, CORBCTL_RUN);
    w8(REG_RIRBCTL, RIRBCTL_DMAEN);

    debug.klog("[hda] CORB/RIRB ready ({d}/{d} entries)\n", .{ corb_size, rirb_size });
    return true;
}

fn discoverWidgets() bool {
    // Walk children of root NID 0 to find the audio function group.
    const root_snc = getParameter(first_codec, 0, PARAM_SUB_NODE_COUNT) orelse return false;
    const fg_start: u8 = @truncate((root_snc >> 16) & 0xFF);
    const fg_count: u8 = @truncate(root_snc & 0xFF);

    var fg_idx: u8 = 0;
    while (fg_idx < fg_count) : (fg_idx += 1) {
        const fg = fg_start + fg_idx;
        const ftype = getParameter(first_codec, fg, PARAM_FUNC_GROUP_TYPE) orelse continue;
        if ((ftype & 0xFF) == FG_AUDIO) {
            afg_nid = fg;
            break;
        }
    }
    if (afg_nid == 0) {
        debug.klog("[hda] no AFG found\n", .{});
        return false;
    }

    // Power up the AFG (D0).
    _ = sendVerbRaw(buildVerbShort(first_codec, afg_nid, VERB_SET_POWER_STATE, 0x00));

    // Walk the AFG's widgets to find DAC + output pin.
    const afg_snc = getParameter(first_codec, afg_nid, PARAM_SUB_NODE_COUNT) orelse return false;
    const w_start: u8 = @truncate((afg_snc >> 16) & 0xFF);
    const w_count: u8 = @truncate(afg_snc & 0xFF);
    debug.klog("[hda] AFG NID {d}: {d} widgets from NID {d}\n", .{ afg_nid, w_count, w_start });

    var w_idx: u8 = 0;
    while (w_idx < w_count) : (w_idx += 1) {
        const nid = w_start + w_idx;
        const cap = getParameter(first_codec, nid, PARAM_AUDIO_WIDGET_CAP) orelse continue;
        const wtype: u32 = (cap >> 20) & 0xF;
        switch (wtype) {
            WIDGET_DAC => {
                if (dac_nid == 0) {
                    dac_nid = nid;
                    debug.klog("[hda]   NID {d}: DAC\n", .{nid});
                }
            },
            WIDGET_PIN => {
                const pcap = getParameter(first_codec, nid, PARAM_PIN_CAP) orelse continue;
                if (pcap & (1 << 4) != 0 and pin_nid == 0) {
                    pin_nid = nid;
                    debug.klog("[hda]   NID {d}: output Pin\n", .{nid});
                }
            },
            else => {},
        }
    }

    if (dac_nid == 0 or pin_nid == 0) {
        debug.klog("[hda] missing DAC ({d}) or output pin ({d})\n", .{ dac_nid, pin_nid });
        return false;
    }
    return true;
}

// --- Self test (Phase 2) ---
//
// Generates a 1 kHz triangle wave at 48 kHz × 2 ch × 16-bit (~10 ms worth =
// 480 stereo samples), pushes it through the public writeSamples() API,
// and verifies LPIB advances. This exercises the same code path that
// userspace audio uses, so a passing selfTest is a real proof of the
// streaming API — not just direct register pokes.
pub fn selfTest() bool {
    if (!stream_active) {
        debug.klog("[hda] selfTest: stream not initialized\n", .{});
        return false;
    }

    // Generate ~50 ms of 1 kHz triangle wave (24000 stereo frames).
    // Inline tiny generator — no static buffer required.
    const tone_frames: u32 = 2400;
    var tone: [tone_frames * 2]i16 = undefined;
    var i: u32 = 0;
    while (i < tone_frames) : (i += 1) {
        // 1 kHz at 48 kHz sample rate → period = 48 frames.
        const phase = i % 48;
        const tri: i32 = if (phase < 24)
            @intCast(@as(i32, @intCast(phase)) * 1000 - 12000)
        else
            @intCast(36000 - @as(i32, @intCast(phase)) * 1000);
        tone[i * 2] = @intCast(tri); // L
        tone[i * 2 + 1] = @intCast(tri); // R
    }

    const lpib_before = r32(sdOff(stream_sd_idx, SD_LPIB));
    const t_start = hpet.readMicros();

    writeSamples(@as([*]const i16, &tone), tone_frames);

    // Watch DMA progress for 100 ms.
    var milestone: u32 = 25_000;
    while (hpet.readMicros() - t_start < 100_000) {
        const dt = hpet.readMicros() - t_start;
        if (dt >= milestone) {
            const lpib_now = r32(sdOff(stream_sd_idx, SD_LPIB));
            debug.klog("[hda] selfTest: t={d}us LPIB={d}\n", .{ dt, lpib_now });
            milestone += 25_000;
        }
        asm volatile ("pause");
    }

    const lpib_after = r32(sdOff(stream_sd_idx, SD_LPIB));
    const t_end = hpet.readMicros();
    const elapsed_us = t_end - t_start;
    const advance = lpib_after -% lpib_before;

    debug.klog("[hda] selfTest: elapsed={d} us, LPIB advance={d} bytes\n", .{ elapsed_us, advance });

    const ok = advance >= 1024 and advance < stream_buf_size;
    if (ok) {
        debug.klog("[hda] selfTest: PASS — writeSamples + DMA path functional\n", .{});
    } else {
        debug.klog("[hda] selfTest: FAIL — DMA didn't advance or buffer overran\n", .{});
    }
    return ok;
}
