// redteam — stateful kernel syscall fuzzer.
//
// V1 (random args) plateaued — it found shallow input-validation bugs and
// then stopped producing new ones. Real bugs hide in *sequences*: open→
// close→use, mmap→munmap→access, create_window→destroy→present. Random
// independent calls never construct those sequences because the chance of
// guessing a valid fd or addr from PRNG noise is ~0.
//
// V2 tracks live resources we allocate (fds, mmap regions, window ids) and
// biases args toward those values, so we exercise multi-step state machines.
// Also adds a small path dictionary for path-arg syscalls — random ptrs to
// unmapped memory just bounce off validateUserPtr; real strings actually
// reach the path parser.
//
// V3 sharpens the edges: a much wider boundary-value corpus (page-rounding,
// table-bound off-by-ones, ptr+len overflow), READ-ONLY pointer injection on
// write-target syscalls (the validateUserPtrWrite tripwire — a write to a
// mapped-but-RO page must EFAULT, never #PF in ring 0), near-valid handle
// mutation (fd±1 / region^page / single-bit flip), and — the big one —
// scripted combos every 12th iter that *construct* use-after-free, double-
// free, W^X, and range-spill sequences instead of hoping random ordering
// stumbles onto them. Each combo allocates and frees its own resources, so it
// can never wedge the fuzzer.
//
// V4 adds the BPF load path (sys#122 / app/zbpf): the kernel's eBPF verifier is
// a SECURITY BOUNDARY — untrusted userspace code cleared to run in ring 0 — so
// it is the highest-value target here. ~1-in-8 iters target sys#122 with a
// FRESHLY-GENERATED random eBPF program (curated-opcode mix + garbage, forward
// AND backward jumps, random regs/imm) wrapped in a real BpfAttr. The kernel
// must verify-or-reject every one without ever accepting an unsafe program or
// faulting in ring 0. Complements the off-target tools/bpf-test/fuzz_test.zig
// (which fuzzes verifier LOGIC on the host) by exercising the LIVE syscall path:
// user-ptr copy-in, the lock, verify, sandboxed run, copy-out.
//
// Tracked:
//   - file descriptors: sys#9 (open), sys#51 (pipe — both ends)
//   - mmap regions:     sys#57
//   - window ids:       sys#13
// Biased arg1:
//   - sys#4/10/11/12/29/42 (read/fread/fwrite/close/fsize/readdir): live fd
//   - sys#58/59 (munmap/mprotect): live region addr
//   - sys#14/16/24 (present/destroy_window/get_window_size): live wid
//   - sys#9/21/39/41/43/44/45/46 (open/listdir/chdir/mkdir/unlink/stat/...): path
// Post-syscall: success returns are added to the table; close/munmap/destroy
// remove their target so we don't keep using a stale handle forever.
//
// Usage:
//   redteam               — 1000 iterations
//   redteam <N>           — N iterations
//   redteam <N> <seed>    — deterministic replay (any non-zero seed)

const libc = @import("libc");

var state: u64 = 0;

fn rdtsc() u64 {
    var lo: u32 = undefined;
    var hi: u32 = undefined;
    asm volatile ("rdtsc"
        : [_] "={eax}" (lo),
          [_] "={edx}" (hi),
    );
    return (@as(u64, hi) << 32) | @as(u64, lo);
}

fn next() u32 {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return @truncate(state *% 0x2545F4914F6CDD1D);
}

fn spicyArg() u32 {
    return switch (next() % 40) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 0xFFFFFFFF, // -1
        5 => 0xFFFFFFFE,
        6 => 0x7FFFFFFF, // INT_MAX
        7 => 0x80000000, // high bit / INT_MIN
        8 => 0x80000001,
        // user-space landmarks
        9 => 0x500000, // own image / .text base (mapped, READ-ONLY)
        10 => 0x500001, // unaligned into .text
        11 => 0x4FFFFF, // one byte below the image
        12 => 0x4FF000, // page below the image (stack-guard neighbourhood)
        13 => 0x501000, // second image page
        14 => 0xC00000, // heap-ish
        15 => 0x10000000, // top of the user VA window
        16 => 0x0FFFFFFF, // just under the ceiling
        17 => 0x10000001, // just over the ceiling
        // page-rounding edges
        18 => 0x1000,
        19 => 0x0FFF,
        20 => 0x1001,
        21 => 0xFFFFF000,
        22 => 0xFFFFEFFF,
        // table-bound edges (MAX_FDS=16, MAX_PROCS=64, MAX_WINDOWS/NSIG/PIPES=32, FD_REMAP=8)
        23 => 8,
        24 => 16,
        25 => 17,
        26 => 32,
        27 => 33,
        28 => 64,
        29 => 65,
        30 => 255,
        31 => 256,
        32 => 4095,
        33 => 4096,
        // big lengths / counts
        34 => 0x40000000,
        35 => 0x20000000,
        36 => next() & 0xFFF, // small
        37 => @intCast(@intFromPtr(&ro_marker)), // own .rodata (mapped, READ-ONLY)
        else => next(), // full random
    };
}

// A genuinely-mapped, READ-ONLY user page: a `const` with a non-zero
// initializer lands in .rodata (PF_W==0), so the kernel maps it RO. Handing
// this to a *write-target* syscall must yield E_FAULT, never a ring-0 #PF —
// the live tripwire for the validateUserPtrWrite class.
const ro_marker: [16]u8 = .{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x13, 0x37, 0x73, 0x31, 0xAA, 0x55, 0x0F, 0xF0 };

// Read-only / range-edge pointers for hammering write-target syscalls.
fn roPtr() u32 {
    return switch (next() % 5) {
        0 => 0x500000, // own .text base
        1 => @intCast(@intFromPtr(&ro_marker)), // own .rodata
        2 => 0x500001, // unaligned .text
        3 => 0x4FF000, // page just below the image
        else => 0x10000000 - 8, // top of user VA — a write spills past it
    };
}

// A length that makes ptr+len overflow u32 or shoot past the user ceiling —
// probes range checks that forget the wraparound case.
fn overflowLen(ptr: u32) u32 {
    return switch (next() % 4) {
        0 => (0xFFFFFFFF -% ptr) +% (1 + (next() % 16)), // ptr +% len wraps past 2^32
        1 => 0xFFFFFFFF,
        2 => 0x40000000 + (next() & 0xFFFF), // huge
        else => 0x10000000, // exactly the user-window size
    };
}

// Bit-flip / off-by-one mutation of a known-valid handle or address — yields
// "near-valid" values that a sloppy bounds check waves through where neither a
// valid handle nor pure noise would reach.
fn nearValid(h: u32) u32 {
    const sh: u5 = @intCast(next() % 32);
    return switch (next() % 4) {
        0 => h +% 1,
        1 => h -% 1,
        2 => h ^ 0x1000, // adjacent page
        else => h ^ (@as(u32, 1) << sh), // random single-bit flip
    };
}

// === resource tracker ===

const MAX_FDS = 16;
const MAX_REGIONS = 8;
const MAX_WINDOWS = 4;

var live_fds: [MAX_FDS]u32 = undefined;
var n_fds: u32 = 0;

var region_addr: [MAX_REGIONS]u32 = undefined;
var n_regions: u32 = 0;

var live_wids: [MAX_WINDOWS]u32 = undefined;
var n_wids: u32 = 0;

// Set once the fuzzer successfully installs a wallpaper (sys#98 with a real
// buffer). Drives the exit-time restore: a fuzzed wallpaper is a tiny garbage
// image rendered centered on the desktop, so we clear it back to the gradient
// when the run ends (sysSetWallpaper(0,0,0) is the kernel's clear path). Stays
// false if the fuzzer never installed one, so we never wipe a wallpaper we
// didn't set. (2026-06-15)
var wallpaper_dirty: bool = false;

// Reserved buffers we pass to syscalls that write back ids/data.
var pipe_buf: [2]u32 = .{ 0, 0 };
var path_buf: [128]u8 = undefined;
var io_buf: [256]u8 = undefined;

// The redteam process creates real GUI windows (sys#13) to fuzz the window
// path — and that maps a LIVE, writable framebuffer at GUI_FB_BASE in our own
// address space that the compositor draws onto the desktop every frame. Hand a
// copy-OUT syscall (read/fread/stat-into-buf) a buffer pointer inside this span
// and the kernel dumps file/garbage bytes straight into the live FB → a band of
// "random pixels" smeared across the wallpaper that outlives the run (the random
// walk almost never tears its own window down: create_window returns
// GUI_FB_BASE, which our >=256 wid filter drops, so present/destroy never
// re-target it). We still WANT to fuzz window dims and handles — we just must
// never use the live FB as a scratch buffer. Redirect any copy-out pointer that
// lands in the span back to our own io_buf; the window itself is destroyed on
// exit (see _start). roPtr()'s landmarks all sit below this span, so the RO
// write-tripwire is untouched. (2026-06-15 — stop redteam painting the desktop.)
const GUI_FB_BASE: u32 = 0x08000000;
const GUI_FB_SPAN: u32 = 1920 * 1080 * 4; // widest FB the kernel will ever map

fn scrubFbPtr(p: u32) u32 {
    if (p >= GUI_FB_BASE and p < GUI_FB_BASE + GUI_FB_SPAN) {
        return @intCast(@intFromPtr(&io_buf));
    }
    return p;
}

// === sys_bpf (#122) program fuzzer ===
// Byte-identical to bpf/kernel.zig's BpfAttr and insn.Insn.
const BpfAttr = extern struct {
    ret: u64 = 0,
    prog: u32 = 0,
    prog_cnt: u32 = 0,
    ctx: u32 = 0,
    ctx_len: u32 = 0,
    ctx_writable: u32 = 0,
    flags: u32 = 0,
};
const FuzzInsn = extern struct { opcode: u8, regs: u8, offset: i16, imm: i32 };

const MAX_FUZZ_INSNS = 32;
var bpf_attr_buf: BpfAttr = .{};
var bpf_prog_buf: [MAX_FUZZ_INSNS]FuzzInsn = undefined;
var bpf_ctx_buf: [64]u8 align(8) = undefined;
var bpf_calls: u32 = 0;

// A spread of real RFC 9669 opcodes (so programs decode and reach deep into the
// verifier) — mov/alu imm+reg, ldx/st/stx at several widths, the jump family
// incl. ja, exit, call, ld_imm64, bswap. buildBpfAttr also injects fully-random
// opcodes ~1-in-8 so the structural-reject paths get hit too.
const FUZZ_OPCODES = [_]u8{
    0xb7, 0x07, 0x0f, 0xbf, 0xb4, 0x04, 0x0c, // mov/add imm+reg (alu64 + alu32)
    0x79, 0x71, 0x61, 0x69, // ldx dw/b/w/h
    0x7a, 0x62, 0x7b, 0x63, // st/stx dw+w
    0x05, 0x15, 0x1d, 0x25, 0x35, 0x55, 0xa5, 0xb5, // ja/jeq/jgt/jge/jne/jlt/jle
    0x95, 0x85, 0x18, 0x00, 0xd4, // exit, call, ld_imm64(+hi), bswap
};

/// Generate a random eBPF program + BpfAttr into the static buffers; return the
/// attr pointer. Programs are small (the verifier budget rejects huge unrolls
/// fast) with both forward and BACKWARD jumps so the M4 loop path is exercised.
fn buildBpfAttr() u32 {
    const cnt: u32 = 1 + (next() % MAX_FUZZ_INSNS);
    var k: u32 = 0;
    while (k < cnt) : (k += 1) {
        var op = FUZZ_OPCODES[next() % FUZZ_OPCODES.len];
        if ((next() % 8) == 0) op = @truncate(next()); // garbage opcode → structural reject
        const back = (next() % 2) == 0 and k > 0;
        const off: i16 = if (back)
            -@as(i16, @intCast(1 + (next() % k))) // backward = a loop
        else
            @as(i16, @intCast(next() % MAX_FUZZ_INSNS));
        bpf_prog_buf[k] = .{
            .opcode = op,
            .regs = @truncate(next()), // random nibbles — sometimes r11..r15 (BadRegister)
            .offset = off,
            .imm = @bitCast(next()),
        };
    }
    if ((next() % 10) < 6) bpf_prog_buf[cnt - 1] = .{ .opcode = 0x95, .regs = 0, .offset = 0, .imm = 0 }; // mostly end in EXIT

    const ctx_len: u32 = switch (next() % 5) {
        0 => 0,
        1 => 8,
        2 => 16,
        3 => next() % 65, // within bpf_ctx_buf
        else => 1 + (next() % 4096), // sometimes > MAX_USER_CTX → EINVAL bound test
    };
    bpf_attr_buf = .{
        .prog = @truncate(@intFromPtr(&bpf_prog_buf)),
        .prog_cnt = cnt,
        .ctx = @truncate(@intFromPtr(&bpf_ctx_buf)),
        .ctx_len = ctx_len,
        .ctx_writable = next() % 2,
        .flags = if ((next() % 16) == 0) next() else 0,
    };
    return @truncate(@intFromPtr(&bpf_attr_buf));
}

fn addFd(fd: u32) void {
    // Don't track absurd values that aren't real fds (sanity guard against
    // a syscall returning 0 = "ok" being misread as a fd).
    if (fd >= 256) return;
    if (n_fds < MAX_FDS) {
        live_fds[n_fds] = fd;
        n_fds += 1;
    } else {
        // Bounded: evict random slot. Keeps the table churning instead of
        // sticking on the first 16 fds forever.
        live_fds[next() % MAX_FDS] = fd;
    }
}

fn removeFd(fd: u32) void {
    var i: u32 = 0;
    while (i < n_fds) : (i += 1) {
        if (live_fds[i] == fd) {
            n_fds -= 1;
            live_fds[i] = live_fds[n_fds];
            return;
        }
    }
}

fn pickFd() u32 {
    if (n_fds == 0) {
        // Fallback: spicyArg() can return 0 = stdin, and reading stdin
        // blocks waiting for a keypress (silent freeze). Use a high
        // value that's deterministically not stdio.
        return next() | 0x10;
    }
    return live_fds[next() % n_fds];
}

fn addRegion(addr: u32) void {
    if (n_regions < MAX_REGIONS) {
        region_addr[n_regions] = addr;
        n_regions += 1;
    } else {
        region_addr[next() % MAX_REGIONS] = addr;
    }
}

fn removeRegion(addr: u32) void {
    var i: u32 = 0;
    while (i < n_regions) : (i += 1) {
        if (region_addr[i] == addr) {
            n_regions -= 1;
            region_addr[i] = region_addr[n_regions];
            return;
        }
    }
}

fn pickRegion() u32 {
    if (n_regions == 0) return spicyArg();
    return region_addr[next() % n_regions];
}

fn addWid(wid: u32) void {
    if (wid >= 256) return;
    if (n_wids < MAX_WINDOWS) {
        live_wids[n_wids] = wid;
        n_wids += 1;
    } else {
        live_wids[next() % MAX_WINDOWS] = wid;
    }
}

fn removeWid(wid: u32) void {
    var i: u32 = 0;
    while (i < n_wids) : (i += 1) {
        if (live_wids[i] == wid) {
            n_wids -= 1;
            live_wids[i] = live_wids[n_wids];
            return;
        }
    }
}

fn pickWid() u32 {
    if (n_wids == 0) return spicyArg();
    return live_wids[next() % n_wids];
}

// === path dictionary ===
// Mix of (a) real openable files so open() actually returns valid fds and
// fills live_fds — without this, the resource-bias path never fires — and
// (b) boundary cases the path parser is likely to mishandle.
const PATHS = [_][]const u8{
    // Fuzzer-OWNED scratch files (created by setupScratch() at startup). These
    // are the destructive-write targets: open/fwrite/truncate/unlink land on
    // DISPOSABLE files, never on real system binaries. This pool USED to list
    // /BUILD.ID, /KERNEL.SYM, /bin/echo|ls|cat|redteam.elf — and the fuzzer
    // fwrite'd into them through entirely legit syscalls, truncating its own
    // /bin/redteam.elf to size 0 ("shell can't find redteam"). That was the
    // root cause of the multi-session "ELF corruption" hunt — self-inflicted,
    // not a kernel race. (2026-06-04)
    "/fuzz0.dat",
    "/fuzz1.dat",
    "/fuzz2.dat",
    "/fuzz3.dat",
    // ETXTBSY canary: redteam's OWN running binary, kept on purpose. The fuzzer
    // WILL try to write/truncate it; the kernel's new ETXTBSY guard must reject
    // every such mutation (E_TXTBSY) and leave it byte-intact. If this file
    // ever corrupts on disk again, ETXTBSY has a hole.
    "/bin/redteam.elf",
    // Edge cases (path parser fuzz)
    "/",
    ".",
    "..",
    "/bin",
    "//bin//redteam.elf",
    "/../../..",
    "../../../../../etc",
    "a",
    "",
    "/.",
    "/./",
    "/bin/.",
    "very_long_path_that_might_overflow_the_kernel_buffer_if_anyone_forgot_a_bound_check_xxxxxxxxxxxxxxxx",
};

fn copyPath(p: []const u8) u32 {
    const n = if (p.len < path_buf.len - 1) p.len else path_buf.len - 1;
    var k: usize = 0;
    while (k < n) : (k += 1) path_buf[k] = p[k];
    path_buf[n] = 0;
    return @intCast(@intFromPtr(&path_buf));
}

fn pickPathPtr() u32 {
    return copyPath(PATHS[next() % PATHS.len]);
}

// The first N_REAL_PATHS entries of PATHS are real, openable files — combos
// that need a valid fd open from this subset so the sequence actually forms.
// = the 4 scratch files + the redteam.elf canary (all reliably openable).
const N_REAL_PATHS: u32 = 5;

// Scratch files the fuzzer creates and owns. Listed first in PATHS so the
// destructive path-arg syscalls hit these throwaway files instead of real
// binaries. setupScratch() creates each (O_CREATE) and seeds 256 bytes so
// reads return data and the open/read/write/truncate machinery is exercised.
const SCRATCH = [_][]const u8{ "/fuzz0.dat", "/fuzz1.dat", "/fuzz2.dat", "/fuzz3.dat" };

fn setupScratch() void {
    var seed: [256]u8 = undefined;
    for (&seed, 0..) |*b, k| b.* = @truncate(k);
    for (SCRATCH) |p| {
        const fd = libc.openFlags(p, libc.O_CREATE) orelse continue;
        _ = libc.syscall3(11, fd, @intCast(@intFromPtr(&seed)), seed.len); // sys#11 fwrite
        libc.close(fd);
    }
}
fn realPathPtr() u32 {
    return copyPath(PATHS[next() % N_REAL_PATHS]);
}

// === per-syscall arg shaping ===

fn isFdArg1(sys_no: u32) bool {
    return switch (sys_no) {
        4, 10, 11, 12, 29, 42 => true,
        else => false,
    };
}

fn isRegionArg1(sys_no: u32) bool {
    return switch (sys_no) {
        58, 59 => true,
        else => false,
    };
}

fn isWidArg1(sys_no: u32) bool {
    return switch (sys_no) {
        14, 16, 24 => true,
        else => false,
    };
}

fn isPathArg1(sys_no: u32) bool {
    return switch (sys_no) {
        9, 21, 39, 41, 43, 44, 45, 46 => true,
        else => false,
    };
}

// 70% bias toward a live resource if applicable, 30% spicy fallback. The
// fallback is important — sometimes the bug is "uses the wrong resource",
// which only triggers when arg is e.g. a *closed* fd or a freed addr, and
// pure-bias would never produce that.
fn smartArg1(sys_no: u32) u32 {
    // sys_bpf(cmd, ...): cmd 0 reaches the verify-and-run path; ~20% garbage
    // cmd exercises the cmd-validation reject.
    if (sys_no == 122) return if ((next() % 10) < 8) 0 else spicyArg();
    const bias = (next() % 10) < 7;
    if (bias) {
        if (isFdArg1(sys_no)) return pickFd();
        if (isRegionArg1(sys_no)) return pickRegion();
        if (isWidArg1(sys_no)) return pickWid();
        if (isPathArg1(sys_no)) return pickPathPtr();
    }
    // Near-valid mutation: 1-in-4, hand back a *slightly wrong* live handle
    // (fd±1, region^page, single-bit flip). Exercises off-by-one handle checks
    // that neither a valid handle nor pure noise would reach.
    if ((next() % 4) == 0) {
        if (isFdArg1(sys_no) and n_fds > 0) return nearValid(live_fds[next() % n_fds]);
        if (isRegionArg1(sys_no) and n_regions > 0) return nearValid(region_addr[next() % n_regions]);
        if (isWidArg1(sys_no) and n_wids > 0) return nearValid(live_wids[next() % n_wids]);
    }
    // Fallback: spicy random. For fd-arg syscalls, ensure the result is
    // never 0/1/2 (stdio fds — reading from 0 blocks for a keypress, and
    // writing to 1/2 spams the terminal).
    if (isFdArg1(sys_no)) return next() | 0x10;
    return spicyArg();
}

// For some syscalls we can also smarten arg2 (e.g. read/write buf). Use our
// io_buf so the kernel doesn't bounce off validateUserPtr.
fn smartArg2(sys_no: u32) u32 {
    return switch (sys_no) {
        // (fd, buf, len): 60% a real buffer (exercise the copy path), 20% a
        // READ-ONLY pointer (validateUserPtrWrite tripwire on read-INTO
        // syscalls — the kernel must EFAULT, not #PF), 20% spicy.
        4, 10, 11, 42 => blk: {
            const r = next() % 10;
            if (r < 6) break :blk @intCast(@intFromPtr(&io_buf));
            if (r < 8) break :blk roPtr();
            break :blk spicyArg();
        },
        // open(path, flags) — flags = O_RDONLY/WRONLY/RDWR plus modifiers.
        // Garbage flags don't matter to ZigOS's openFlags right now (it
        // ignores them mostly), but biasing toward 0..3 keeps the call
        // looking like a normal open and makes any future flag validation
        // exercise normal paths.
        9 => if ((next() % 10) < 8) (next() % 4) else spicyArg(),
        // sys_bpf(_, attr_ptr, _): ~80% a freshly-built random program+attr (so
        // the verifier actually runs on adversarial bytes), ~20% a spicy/garbage
        // pointer (the copy-in / validateUserPtr robustness angle).
        122 => if ((next() % 10) < 8) buildBpfAttr() else spicyArg(),
        // Default arg2 is often a write-back pointer (stat buf, size out,
        // etc.). 1-in-4, feed a read-only pointer so any write-target syscall
        // that skipped the writability check trips here instead of in prod.
        else => if ((next() % 4) == 0) roPtr() else spicyArg(),
    };
}

fn smartArg3(sys_no: u32) u32 {
    return switch (sys_no) {
        // (fd, buf, len): 60% a sane capped len (clean copy), 20% an
        // overflowing len (ptr+len wraps / shoots past the user ceiling —
        // probes the range check), 20% spicy. The overflow len is huge, so a
        // missed check walks straight off into unmapped memory and faults
        // LOUDLY rather than silently corrupting adjacent state.
        4, 10, 11, 42 => blk: {
            const r = next() % 10;
            if (r < 6) break :blk (next() % @as(u32, @intCast(io_buf.len + 1)));
            if (r < 8) break :blk overflowLen(@intCast(@intFromPtr(&io_buf)));
            break :blk spicyArg();
        },
        // sys_bpf attr_len: mostly the exact struct size (so the call proceeds),
        // ~20% spicy (the attr_len-validation reject).
        122 => if ((next() % 10) < 8) @sizeOf(BpfAttr) else spicyArg(),
        else => spicyArg(),
    };
}

// === post-syscall bookkeeping ===

fn isError(ret: u32) bool {
    return ret == 0xFFFFFFFF or ret >= 0xFFFFFF00;
}

fn postProcess(sys_no: u32, a1: u32, ret: u32) void {
    switch (sys_no) {
        9 => if (!isError(ret)) addFd(ret), // open returns fd
        12 => if (!isError(ret)) removeFd(a1), // close
        13 => if (!isError(ret)) addWid(ret), // create_window returns wid
        16 => if (!isError(ret)) removeWid(a1), // destroy_window
        // set_wallpaper: a success with a non-null buffer INSTALLED a (garbage)
        // wallpaper that renders centered on the desktop. Flag it so we restore
        // the gradient on exit. a1==0 is the clear path — don't flag that.
        98 => if (!isError(ret) and a1 != 0) {
            wallpaper_dirty = true;
        },
        // sys#51 (pipe) deliberately NOT tracked: a read on an empty pipe
        // with no writer blocks forever. Single-process fuzz can't make
        // useful progress on pipes — that's option-2 (multi-process race)
        // territory. The call still happens with a real pipe_buf so the
        // pipe-creation path is exercised; we just discard the resulting fds.
        57 => {
            // mmap returns user VA on success. Heuristic: it's in user
            // range and not an obvious errno bit pattern.
            if (ret >= 0x500000 and ret < 0x10000000) addRegion(ret);
        },
        58 => removeRegion(a1), // munmap
        else => {},
    }
}

// === blocked syscalls ===

fn isBlocked(sys_no: u32) bool {
    return switch (sys_no) {
        3 => true, // exit
        8 => true, // sleep — random u32 ms = up to ~50 days of sleep
        22 => true, // exec — replaces our image
        48 => true, // exit_status — calls destroyCurrentWithStatus(arg1), kills us
        50 => true, // kill — could whack ourselves or others
        52 => true, // exec_as
        54 => true, // usleep — same indefinite-sleep risk as sys#8
        62 => true, // sigreturn — outside a signal handler, kills us via DEAD000B
        64 => true, // sigsuspend — parks until signal; random fuzz won't deliver one
        65 => true, // pause — same indefinite-block as sigsuspend
        82 => true, // shutdown — kills the whole OS
        83 => true, // clone — thread spawn, complicates teardown
        86 => true, // exit_thread
        92 => true, // fork — risk of fuzz-bomb
        117 => true, // debug_crash — deliberate kernel-panic backdoor (now E_NOSYS-gated kernel-side too)
        // GPU passthrough (30-37, 87-89, 91) — the raw venus/virgl 3D/blob/
        // scanout interface. Same category as fork/exec/shutdown: fuzzing it
        // wrecks the *environment*, not the kernel. sys#31 submit_3d feeds
        // arbitrary bytes to the shared host renderer, sys#88 set_scanout_blob
        // repoints the live display, sys#34 create_blob had no size cap — random
        // fuzz here poisons the renderer + leaks host resources and permanently
        // kills the display (kernel survives). It's a trusted-app interface that
        // can't be made fuzz-safe without a full 3D command validator. Excluded
        // so runs complete; real GPU isolation (per-proc resource reclaim +
        // gating scanout/submit on display ownership) is a separate effort.
        // (2026-06-04 — found by this fuzzer killing the display output.)
        30, 31, 32, 33, 34, 35, 36, 37, 87, 88, 89, 91 => true,
        else => false,
    };
}

fn parseU32(s: []const u8) u32 {
    if (s.len == 0) return 0;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return 0;
        v = v *% 10 +% @as(u32, c - '0');
    }
    return v;
}

// Fix arg1 for syscalls whose "live" arg lives in arg2 (the only one we
// have right now is pipe — its only arg is a buffer for the two fds).
fn forceArg1(sys_no: u32) ?u32 {
    return switch (sys_no) {
        51 => @intCast(@intFromPtr(&pipe_buf)), // pipe: must be a real buffer
        else => null,
    };
}

// === scripted combos ===
// Syscall numbers the combos drive directly (mirror the dispatch table + the
// bias maps above). A wrong guess is harmless — it just yields an errno.
const SYS_OPEN = 9;
const SYS_FREAD = 10;
const SYS_CLOSE = 12;
const SYS_CREATE_WINDOW = 13;
const SYS_PRESENT = 14;
const SYS_DESTROY_WINDOW = 16;
const SYS_FSIZE = 29;
const SYS_STAT = 44;
const SYS_MMAP = 57;
const SYS_MUNMAP = 58;
const SYS_MPROTECT = 59;
const SYS_SET_WALLPAPER = 98;

fn isUserAddr(a: u32) bool {
    return a >= 0x500000 and a < 0x10000000;
}

// Construct the multi-step bugs random ordering almost never lines up: use-
// after-free, double-free, W^X, write-target-with-RO-pointer, range spill.
// Each branch allocates AND frees its own resources, so a combo can't wedge
// the fuzzer (no indefinite blocks: all fds are regular files, all mappings
// are ours). Returns the branch id for the trace.
fn combo() u32 {
    const which = next() % 6;
    switch (which) {
        0 => {
            // UAF + double-close on a file descriptor.
            const fd = libc.syscall3(SYS_OPEN, realPathPtr(), next() % 4, 0);
            if (!isError(fd) and fd >= 3 and fd < 256) {
                _ = libc.syscall3(SYS_CLOSE, fd, 0, 0);
                _ = libc.syscall3(SYS_FREAD, fd, @intCast(@intFromPtr(&io_buf)), 16); // read the freed fd
                _ = libc.syscall3(SYS_FSIZE, fd, 0, 0); // stat the freed fd
                _ = libc.syscall3(SYS_CLOSE, fd, 0, 0); // double close
            }
        },
        1 => {
            // Double-munmap of a fresh mapping.
            const len: u32 = 0x2000;
            const a = libc.syscall3(SYS_MMAP, 0, len, 0);
            if (isUserAddr(a)) {
                _ = libc.syscall3(SYS_MUNMAP, a, len, 0);
                _ = libc.syscall3(SYS_MUNMAP, a, len, 0); // double munmap
                removeRegion(a);
            }
        },
        2 => {
            // W^X probe: ask for write+exec on a fresh mapping — it must be
            // refused or split, never silently granted.
            const len: u32 = 0x1000;
            const a = libc.syscall3(SYS_MMAP, 0, len, 0);
            if (isUserAddr(a)) {
                _ = libc.syscall3(SYS_MPROTECT, a, len, 0x7); // PROT_READ|WRITE|EXEC
                _ = libc.syscall3(SYS_MPROTECT, a, len, 0x5); // PROT_READ|EXEC
                addRegion(a);
            }
        },
        3 => {
            // UAF + double-free on a window id.
            const w = libc.syscall3(SYS_CREATE_WINDOW, 64, 64, 0);
            if (!isError(w) and w < 256) {
                _ = libc.syscall3(SYS_DESTROY_WINDOW, w, 0, 0);
                _ = libc.syscall3(SYS_PRESENT, w, 0, 0); // present a destroyed window
                _ = libc.syscall3(SYS_DESTROY_WINDOW, w, 0, 0); // double destroy
            }
        },
        4 => {
            // validateUserPtrWrite tripwire: feed write-target syscalls a
            // READ-ONLY pointer (+ an overflowing length). A clean kernel
            // returns E_FAULT; a missed write site #PFs in ring 0.
            const ro = roPtr();
            _ = libc.syscall3(SYS_STAT, realPathPtr(), ro, overflowLen(ro)); // stat → statbuf = RO
            _ = libc.syscall3(SYS_FREAD, pickFd(), ro, overflowLen(ro)); // read → buf = RO
        },
        else => {
            // Range spill: a write that starts inside a live mapping but runs
            // off its end into the next (unmapped) page.
            const len: u32 = 0x1000;
            const a = libc.syscall3(SYS_MMAP, 0, len, 0);
            if (isUserAddr(a)) {
                _ = libc.syscall3(SYS_FREAD, pickFd(), a + len - 8, 64); // spills 56 B past the end
                _ = libc.syscall3(SYS_MUNMAP, a, len, 0);
            }
        },
    }
    return which;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    var iters: u32 = 1000;
    var seed: u64 = 0;

    if (libc.getArgc() >= 2) {
        var buf: [16]u8 = undefined;
        const n = libc.getArgv(1, &buf);
        if (n != 0xFFFFFFFF and n != 0) {
            const v = parseU32(buf[0..n]);
            if (v != 0) iters = v;
        }
    }
    if (libc.getArgc() >= 3) {
        var buf: [16]u8 = undefined;
        const n = libc.getArgv(2, &buf);
        if (n != 0xFFFFFFFF and n != 0) {
            seed = @as(u64, parseU32(buf[0..n]));
        }
    }

    state = if (seed != 0) seed else (rdtsc() | 1);

    libc.print("[redteam] starting stateful syscall fuzzer pid=");
    libc.printNum(libc.getpid());
    libc.print(" iters=");
    libc.printNum(iters);
    libc.print(" seed=0x");
    libc.printHex(@truncate(state >> 32));
    libc.printHex(@truncate(state));
    libc.print("\n");

    // Create the disposable scratch files the destructive syscalls target, so
    // the fuzzer never corrupts real binaries (see SCRATCH / PATHS). Done after
    // the banner, before the loop. (2026-06-04)
    setupScratch();

    var i: u32 = 0;
    var skipped: u32 = 0;
    var ok_count: u32 = 0;
    var err_count: u32 = 0;
    var biased: u32 = 0;

    while (i < iters) : (i += 1) {
        // Every 12th iteration, run a scripted UAF/double-free/W^X/overflow
        // sequence instead of a single random call — these construct the
        // multi-step bugs that independent random calls statistically miss.
        if (i != 0 and i % 12 == 0) {
            const c = combo();
            libc.klogFmt("[redteam] iter={d} COMBO#{d} live[fd={d} rg={d} wid={d}]\n", .{ i, c, n_fds, n_regions, n_wids });
            continue;
        }
        var sys_no: u32 = next() % 130;
        // Bias ~1-in-8 toward sys_bpf (#122) so the live verifier — the ring-0
        // security boundary — actually gets hammered, not visited ~0.8% of the time.
        if ((next() % 8) == 0) sys_no = 122;
        if (sys_no == 122) bpf_calls += 1;
        if (isBlocked(sys_no)) {
            skipped += 1;
            continue;
        }

        const a1 = forceArg1(sys_no) orelse smartArg1(sys_no);
        // a2 is the copy-out buffer for the read/write/stat/readdir family;
        // keep it out of the live window FB so a fuzzed read never paints
        // garbage onto the desktop (a3 stays untouched — it's a length, never a
        // buffer, and scrubbing it would muddy the overflow-len probes).
        const a2 = scrubFbPtr(smartArg2(sys_no));
        const a3 = smartArg3(sys_no);

        // Note for the report: did we use a tracked resource here?
        if (isFdArg1(sys_no) and n_fds > 0 and a1 == live_fds[0]) biased += 1;

        // Trace EVERY call to serial.log. If redteam parks, the last line
        // shows exactly which syscall caused it. Tiny payload (~60 bytes/iter
        // = ~60 KB for 1000 iters) — fine for diagnostic; remove later if
        // redteam itself becomes the regression test for normal ops.
        libc.klogFmt("[redteam] iter={d} sys#{d} a1=0x{x} a2=0x{x} a3=0x{x} live[fd={d} rg={d} wid={d}]\n", .{
            i, sys_no, a1, a2, a3, n_fds, n_regions, n_wids,
        });

        const ret = libc.syscall3(sys_no, a1, a2, a3);
        postProcess(sys_no, a1, ret);

        if (isError(ret)) {
            err_count += 1;
        } else {
            ok_count += 1;
        }

        if (i % 50 == 0) {
            libc.print("[redteam] iter=");
            libc.printNum(i);
            libc.print(" sys#");
            libc.printNum(sys_no);
            libc.print(" args=0x");
            libc.printHex(a1);
            libc.print(",0x");
            libc.printHex(a2);
            libc.print(",0x");
            libc.printHex(a3);
            libc.print(" ret=0x");
            libc.printHex(ret);
            libc.print(" live[fd=");
            libc.printNum(n_fds);
            libc.print(" rg=");
            libc.printNum(n_regions);
            libc.print(" wid=");
            libc.printNum(n_wids);
            libc.print("]\n");
        }
    }

    libc.print("[redteam] done: ");
    libc.printNum(iters);
    libc.print(" iters, ok=");
    libc.printNum(ok_count);
    libc.print(" err=");
    libc.printNum(err_count);
    libc.print(" skipped=");
    libc.printNum(skipped);
    libc.print(" final live[fd=");
    libc.printNum(n_fds);
    libc.print(" rg=");
    libc.printNum(n_regions);
    libc.print(" wid=");
    libc.printNum(n_wids);
    libc.print("] bpf_loads=");
    libc.printNum(bpf_calls);
    libc.print(" — kernel survived\n");

    // Tear down any GUI window the run left up. The random walk creates windows
    // (sys#13) but rarely destroys its OWN — create_window returns GUI_FB_BASE,
    // which addWid's >=256 filter drops, so the tracked-wid path never feeds it
    // back to present/destroy. sysDestroyWindow ignores its args and acts on
    // THIS pid's window, forcing a full desktop repaint underneath (safe no-op
    // if we own none). Without it the wallpaper keeps whatever we last presented.
    _ = libc.syscall3(SYS_DESTROY_WINDOW, 0, 0, 0);

    // Restore the desktop gradient if the run installed a wallpaper. A fuzzed
    // wallpaper is a small garbage image drawn centered on the screen (the
    // fuzzer feeds sys#98 a readable buffer — its own .text — with tiny dims);
    // sysSetWallpaper(0,0,0) is the kernel's clear path. Only fires if we
    // actually set one, so a real user wallpaper we never touched is left alone.
    if (wallpaper_dirty) _ = libc.syscall3(SYS_SET_WALLPAPER, 0, 0, 0);

    libc.exit();
}
