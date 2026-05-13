// babel — multi-architecture TUI emulator host.
//
// One window, one shell, several CPU backends. Each backend ("Core") owns
// its own state + step()/tickFrame() implementation. The host coordinates
// the window, the status bar, the scrolling text area, the prompt, and
// dispatches shell commands to the active backend.
//
// Current backends:
//   - subleq  — 1-instruction OISC, 16K cells, includes assembler+loader
//                for .subleq sources
//   - chip8   — 35-opcode 8-bit micro, 64×32 mono fb, 16-key pad, 60Hz
//                timers, loads raw .ch8 binaries
//
// Layout (640×400 window, 8×16 char grid → 80×25):
//   row 0           — status bar
//   rows 1..16      — chip8 fb (when chip8 backend; subleq draws text here)
//   rows text_row_start..24 — scrolling text/log area
//   row 24          — prompt
//
// `text_row_start` is 1 for subleq (full-window text) or 17 for chip8 (log
// below the fb).
//
// Shell commands:
//   help, list, use <name>, load <path>, sample <name>, run, stop,
//   step [N], reset, regs, mem <addr>, clear, keys on|off, quit

const std = @import("std");
const libc = @import("libc");
const gfx = @import("graphics");
const fa = @import("font_atlas");

const subleq_be = @import("babel_subleq.zig");
const chip8_be = @import("babel_chip8.zig");

// === Layout ===
const WIN_W: u32 = 640;
const WIN_H: u32 = 400;
const CHAR_W: u32 = 8;
const CHAR_H: u32 = 16;
const COLS: u32 = WIN_W / CHAR_W; // 80
const ROWS: u32 = WIN_H / CHAR_H; // 25
const STATUS_ROW: u32 = 0;
const PROMPT_ROW: u32 = ROWS - 1; // 24
const TEXT_ROW_END: u32 = PROMPT_ROW;

// CHIP-8 fb placement when chip8 backend is active. 64×32 scaled 8x →
// 512×256, horizontally centered. Vertically: starts at y=16 (below status
// row 0). 256 px → 16 char rows (rows 1..16 of the grid). Log area starts
// at row 17.
const CHIP8_FB_X: u32 = (WIN_W - chip8_be.FB_W * CHIP8_SCALE) / 2; // 64
const CHIP8_FB_Y: u32 = CHAR_H; // 16
const CHIP8_SCALE: u32 = 8;
const CHIP8_TEXT_START: u32 = 17;
const SUBLEQ_TEXT_START: u32 = 1;

// === Colors ===
const C_BG: u32 = 0x101018;
const C_TEXT: u32 = 0xCCCCCC;
const C_PROMPT_GLYPH: u32 = 0xFFD080;
const C_STATUS_BG: u32 = 0x2A2A3A;
const C_STATUS_FG: u32 = 0x88AACC;
const C_OUTPUT: u32 = 0x90EE90;
const C_ERROR: u32 = 0xFF6B6B;
const C_INFO: u32 = 0x88CCEE;
const C_HALT: u32 = 0xFFAA66;
const C_CHIP8_FG: u32 = 0xCFE4FF;
const C_CHIP8_BG: u32 = 0x0A0A14;

// === Text buffer ===
var screen: [ROWS * COLS]u8 = [_]u8{' '} ** (ROWS * COLS);
var screen_fg: [ROWS * COLS]u32 = [_]u32{C_TEXT} ** (ROWS * COLS);
var wr_row: u32 = SUBLEQ_TEXT_START;
var wr_col: u32 = 0;
var text_row_start: u32 = SUBLEQ_TEXT_START;

fn screenIndex(r: u32, c: u32) usize {
    return @as(usize, r) * @as(usize, COLS) + @as(usize, c);
}

fn scrollUp() void {
    var r: u32 = text_row_start;
    while (r + 1 < TEXT_ROW_END) : (r += 1) {
        const src = screenIndex(r + 1, 0);
        const dst = screenIndex(r, 0);
        @memcpy(screen[dst .. dst + COLS], screen[src .. src + COLS]);
        @memcpy(screen_fg[dst .. dst + COLS], screen_fg[src .. src + COLS]);
    }
    const last = screenIndex(TEXT_ROW_END - 1, 0);
    @memset(screen[last .. last + COLS], ' ');
    @memset(screen_fg[last .. last + COLS], C_TEXT);
    wr_row = TEXT_ROW_END - 1;
}

fn putChar(ch: u8, fg: u32) void {
    if (ch == '\n') {
        wr_row += 1;
        wr_col = 0;
        if (wr_row >= TEXT_ROW_END) scrollUp();
        return;
    }
    if (ch == '\r') {
        wr_col = 0;
        return;
    }
    if (ch < 32 or ch > 126) return;
    if (wr_col >= COLS) {
        wr_row += 1;
        wr_col = 0;
        if (wr_row >= TEXT_ROW_END) scrollUp();
    }
    const idx = screenIndex(wr_row, wr_col);
    screen[idx] = ch;
    screen_fg[idx] = fg;
    wr_col += 1;
}

fn putStr(s: []const u8, fg: u32) void {
    for (s) |ch| putChar(ch, fg);
}

fn putLine(s: []const u8, fg: u32) void {
    putStr(s, fg);
    putChar('\n', fg);
}

fn clearTextArea() void {
    var r: u32 = text_row_start;
    while (r < TEXT_ROW_END) : (r += 1) {
        const i = screenIndex(r, 0);
        @memset(screen[i .. i + COLS], ' ');
        @memset(screen_fg[i .. i + COLS], C_TEXT);
    }
    wr_row = text_row_start;
    wr_col = 0;
}

// === Prompt ===
var prompt_buf: [COLS]u8 = undefined;
var prompt_len: u32 = 0;

fn promptClear() void {
    prompt_len = 0;
}

fn promptAppend(ch: u8) void {
    if (prompt_len + 3 < COLS) {
        prompt_buf[prompt_len] = ch;
        prompt_len += 1;
    }
}

fn promptBackspace() void {
    if (prompt_len > 0) prompt_len -= 1;
}

// === Backends ===
const BackendKind = enum { subleq, chip8 };

var current_kind: BackendKind = .subleq;
var sl: subleq_be.Core = .{};
var c8: chip8_be.Core = .{};

// When true, mapped chars feed the chip8 keypad instead of the shell
// prompt. Toggle via `keys on|off` command. Default off so typing always
// works for shell commands.
var chip8_key_mode: bool = false;

fn switchBackend(new: BackendKind) void {
    current_kind = new;
    text_row_start = switch (new) {
        .subleq => SUBLEQ_TEXT_START,
        .chip8 => CHIP8_TEXT_START,
    };
    clearTextArea();
    showBanner();
}

fn showBanner() void {
    switch (current_kind) {
        .subleq => {
            putLine("=== Babel / SUBLEQ ===", C_INFO);
            putLine("OISC machine, 16K cells. 'help' for commands, 'list' for samples.", C_TEXT);
            putLine("Try: 'sample hello' then 'run', or 'load /share/hello.subleq'.", C_INFO);
        },
        .chip8 => {
            putLine("=== Babel / CHIP-8 ===", C_INFO);
            putLine("35 ops, 64x32 fb, 16-key pad (1234/qwer/asdf/zxcv).", C_TEXT);
            putLine("Try: 'sample bounce' then 'run'. 'keys on' to send keys to ROM.", C_INFO);
        },
    }
}

fn backendStatus(buf: []u8) []const u8 {
    return switch (current_kind) {
        .subleq => std.fmt.bufPrint(buf, " BABEL/SUBLEQ  {s}  PC={d}  cycles={d}", .{
            slStateLabel(),
            sl.pc,
            sl.cycles,
        }) catch buf[0..0],
        .chip8 => std.fmt.bufPrint(buf, " BABEL/CHIP-8  {s}  PC=0x{X:0>3}  cyc={d}  I=0x{X:0>3}  DT={d}  ST={d}  KEYS:{s}", .{
            c8StateLabel(),
            c8.pc,
            c8.cycles,
            c8.i_reg,
            c8.dt,
            c8.st,
            if (chip8_key_mode) "on" else "off",
        }) catch buf[0..0],
    };
}

fn slStateLabel() []const u8 {
    if (sl.halted) return "halted";
    if (sl.waiting_for_input) return "input?";
    if (sl.running) return "running";
    return "ready";
}

fn c8StateLabel() []const u8 {
    if (c8.halted) return "halted";
    if (c8.waiting_for_key) return "key?";
    if (c8.running) return "running";
    return "ready";
}

// === Rendering ===
fn drawStatus(canvas: *gfx.Canvas) void {
    canvas.fillRect(0, STATUS_ROW * CHAR_H, WIN_W, CHAR_H, C_STATUS_BG);
    var buf: [COLS]u8 = undefined;
    const txt = backendStatus(&buf);
    canvas.drawText16(2, STATUS_ROW * CHAR_H, txt, C_STATUS_FG, C_STATUS_BG);
}

fn drawTextArea(canvas: *gfx.Canvas) void {
    var r: u32 = text_row_start;
    while (r < TEXT_ROW_END) : (r += 1) {
        const y = r * CHAR_H;
        var c: u32 = 0;
        while (c < COLS) : (c += 1) {
            const idx = screenIndex(r, c);
            const ch = screen[idx];
            const fg = screen_fg[idx];
            canvas.drawChar16(c * CHAR_W, y, ch, fg, C_BG);
        }
    }
}

fn drawBackendArea(canvas: *gfx.Canvas) void {
    switch (current_kind) {
        .subleq => {},
        .chip8 => c8.render(canvas, CHIP8_FB_X, CHIP8_FB_Y, CHIP8_SCALE, C_CHIP8_FG, C_CHIP8_BG),
    }
}

fn drawPromptLine(canvas: *gfx.Canvas) void {
    const y = PROMPT_ROW * CHAR_H;
    canvas.fillRect(0, y, WIN_W, CHAR_H, C_BG);
    const wfk = (current_kind == .subleq and sl.waiting_for_input) or
        (current_kind == .chip8 and c8.waiting_for_key);
    const glyph: u8 = if (wfk) '?' else '>';
    canvas.drawChar16(0, y, glyph, C_PROMPT_GLYPH, C_BG);
    canvas.drawChar16(CHAR_W, y, ' ', C_PROMPT_GLYPH, C_BG);
    var i: u32 = 0;
    while (i < prompt_len) : (i += 1) {
        const x = (i + 2) * CHAR_W;
        canvas.drawChar16(x, y, prompt_buf[i], C_TEXT, C_BG);
    }
    const cx = (prompt_len + 2) * CHAR_W;
    if (cx < WIN_W) canvas.drawChar16(cx, y, '_', C_PROMPT_GLYPH, C_BG);
}

fn redraw(canvas: *gfx.Canvas) void {
    canvas.fillRect(0, 0, WIN_W, WIN_H, C_BG);
    drawStatus(canvas);
    drawBackendArea(canvas);
    drawTextArea(canvas);
    drawPromptLine(canvas);
    libc.present();
}

// === CHIP-8 keypad mapping ===
//   1 2 3 C        1 2 3 4
//   4 5 6 D    →   q w e r
//   7 8 9 E        a s d f
//   A 0 B F        z x c v
fn chip8KeyMap(ch: u8) ?u8 {
    return switch (ch) {
        '1' => 0x1,
        '2' => 0x2,
        '3' => 0x3,
        '4' => 0xC,
        'q', 'Q' => 0x4,
        'w', 'W' => 0x5,
        'e', 'E' => 0x6,
        'r', 'R' => 0xD,
        'a', 'A' => 0x7,
        's', 'S' => 0x8,
        'd', 'D' => 0x9,
        'f', 'F' => 0xE,
        'z', 'Z' => 0xA,
        'x', 'X' => 0x0,
        'c', 'C' => 0xB,
        'v', 'V' => 0xF,
        else => null,
    };
}

// === Shell ===
fn eqStr(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

fn parseInt(s: []const u8) ?i32 {
    if (s.len == 0) return null;
    var i: usize = 0;
    var neg = false;
    if (s[0] == '-') {
        neg = true;
        i = 1;
    }
    if (i == s.len) return null;
    var v: i64 = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] < '0' or s[i] > '9') return null;
        v = v * 10 + (s[i] - '0');
        if (v > 2_147_483_647) return null;
    }
    if (neg) v = -v;
    return @intCast(v);
}

fn cmdHelp() void {
    putLine("Commands:", C_INFO);
    putLine("  help                this list", C_TEXT);
    putLine("  list                show backends + built-in samples", C_TEXT);
    putLine("  use <backend>       switch backend: subleq | chip8", C_TEXT);
    putLine("  load <path>         load .subleq source or .ch8 binary", C_TEXT);
    putLine("  sample <name>       load built-in sample by name", C_TEXT);
    putLine("  run                 start running", C_TEXT);
    putLine("  stop                pause execution", C_TEXT);
    putLine("  step [N]            single-step N instructions (default 1)", C_TEXT);
    putLine("  reset               reset backend state", C_TEXT);
    putLine("  regs                dump registers / PC", C_TEXT);
    putLine("  mem <addr>          dump 8 cells/bytes at addr", C_TEXT);
    putLine("  clear               clear text area", C_TEXT);
    putLine("  keys on|off         (chip8) feed keys to ROM vs shell", C_TEXT);
    putLine("  quit                exit", C_TEXT);
}

fn cmdList() void {
    putLine("Backends:", C_INFO);
    putLine("  subleq    1-instruction OISC, 16K cells", C_TEXT);
    putLine("  chip8     35-op micro, 64x32 mono fb, 16-key pad", C_TEXT);
    putLine("Subleq samples:", C_INFO);
    for (subleq_be.SAMPLES) |s| {
        var buf: [80]u8 = undefined;
        const ln = std.fmt.bufPrint(&buf, "  sl/{s:<8}  {s} ({d} cells)", .{ s.name, s.desc, s.code.len }) catch continue;
        putLine(ln, C_TEXT);
    }
    putLine("CHIP-8 samples:", C_INFO);
    for (chip8_be.SAMPLES) |s| {
        var buf: [80]u8 = undefined;
        const ln = std.fmt.bufPrint(&buf, "  c8/{s:<8}  {s} ({d} bytes)", .{ s.name, s.desc, s.rom.len }) catch continue;
        putLine(ln, C_TEXT);
    }
}

fn cmdUse(name: []const u8) void {
    if (eqStr(name, "subleq") or eqStr(name, "sl")) {
        switchBackend(.subleq);
    } else if (eqStr(name, "chip8") or eqStr(name, "c8")) {
        switchBackend(.chip8);
    } else {
        putLine("unknown backend (try subleq | chip8).", C_ERROR);
    }
}

fn cmdSample(name: []const u8) void {
    // Accept "sl/hello", "c8/bounce", or bare "hello" (uses active backend).
    var prefix: ?BackendKind = null;
    var bare = name;
    if (name.len > 3 and name[0] == 's' and name[1] == 'l' and name[2] == '/') {
        prefix = .subleq;
        bare = name[3..];
    } else if (name.len > 3 and name[0] == 'c' and name[1] == '8' and name[2] == '/') {
        prefix = .chip8;
        bare = name[3..];
    }
    if (prefix) |p| {
        if (p != current_kind) switchBackend(p);
    }

    switch (current_kind) {
        .subleq => {
            for (subleq_be.SAMPLES) |s| {
                if (eqStr(s.name, bare)) {
                    if (sl.loadProgram(s.code)) {
                        var buf: [80]u8 = undefined;
                        const ln = std.fmt.bufPrint(&buf, "[sl] loaded '{s}' ({d} cells).", .{ s.name, s.code.len }) catch return;
                        putLine(ln, C_INFO);
                    } else putLine("program too large.", C_ERROR);
                    return;
                }
            }
            putLine("unknown subleq sample.", C_ERROR);
        },
        .chip8 => {
            for (chip8_be.SAMPLES) |s| {
                if (eqStr(s.name, bare)) {
                    if (c8.loadRom(s.rom)) {
                        var buf: [80]u8 = undefined;
                        const ln = std.fmt.bufPrint(&buf, "[c8] loaded '{s}' ({d} bytes).", .{ s.name, s.rom.len }) catch return;
                        putLine(ln, C_INFO);
                    } else putLine("ROM too large.", C_ERROR);
                    return;
                }
            }
            putLine("unknown chip8 sample.", C_ERROR);
        },
    }
}

// Tracks file extension to dispatch load: .subleq → subleq asm,
// .ch8 → chip8 raw bytes. Falls back to active backend's loader.
fn pathExtIs(path: []const u8, suffix: []const u8) bool {
    if (path.len < suffix.len) return false;
    return eqStr(path[path.len - suffix.len ..], suffix);
}

// 16 KB scratch buffer for file reads. Sized for the largest source file
// we'd assemble (subleq source max = MAX_SRC_SIZE) or chip8 ROM (max =
// MEM_SIZE - PROG_START = 3.5 KB). Reusing one buffer keeps the app's
// BSS footprint flat.
var file_scratch: [subleq_be.MAX_SRC_SIZE]u8 = undefined;

fn cmdLoad(path: []const u8) void {
    // Auto-detect backend from extension. If the file ext matches the
    // OTHER backend, switch to it before loading.
    if (pathExtIs(path, ".subleq") and current_kind != .subleq) switchBackend(.subleq);
    if (pathExtIs(path, ".ch8") and current_kind != .chip8) switchBackend(.chip8);

    const size = libc.fsize(path) orelse {
        putLine("load: file not found.", C_ERROR);
        return;
    };
    if (size == 0) {
        putLine("load: file is empty.", C_ERROR);
        return;
    }
    if (size > file_scratch.len) {
        putLine("load: file too large.", C_ERROR);
        return;
    }
    const fd = libc.open(path) orelse {
        putLine("load: open failed.", C_ERROR);
        return;
    };
    defer libc.close(fd);

    var total: u32 = 0;
    while (total < size) {
        const n = libc.fread(fd, file_scratch[total..size]);
        if (n == 0) break;
        total += n;
    }

    switch (current_kind) {
        .subleq => {
            sl.reset();
            const cells = subleq_be.assemble(file_scratch[0..total], &sl.mem) orelse {
                var buf: [128]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "asm error line {d}: {s}", .{ subleq_be.asm_err_line, subleq_be.asm_err_msg }) catch return;
                putLine(msg, C_ERROR);
                return;
            };
            sl.pc = 0;
            sl.cycles = 0;
            sl.halted = false;
            var buf: [120]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "[sl] loaded {s} ({d} cells, {d} labels).", .{ path, cells, subleq_be.asm_label_count }) catch return;
            putLine(msg, C_INFO);
        },
        .chip8 => {
            if (!c8.loadRom(file_scratch[0..total])) {
                putLine("ROM too large for chip8 memory.", C_ERROR);
                return;
            }
            var buf: [120]u8 = undefined;
            const msg = std.fmt.bufPrint(&buf, "[c8] loaded {s} ({d} bytes).", .{ path, total }) catch return;
            putLine(msg, C_INFO);
        },
    }
}

fn cmdRun() void {
    switch (current_kind) {
        .subleq => {
            if (sl.halted) {
                putLine("halted — load something first.", C_ERROR);
                return;
            }
            sl.running = true;
            putLine("[sl] running...", C_INFO);
        },
        .chip8 => {
            if (c8.halted) {
                putLine("halted — load something first.", C_ERROR);
                return;
            }
            c8.running = true;
            putLine("[c8] running... ('stop' to pause)", C_INFO);
        },
    }
}

fn cmdStop() void {
    switch (current_kind) {
        .subleq => {
            sl.running = false;
            putLine("[sl] stopped.", C_HALT);
        },
        .chip8 => {
            c8.running = false;
            putLine("[c8] stopped.", C_HALT);
        },
    }
}

fn cmdStep(count: u32) void {
    switch (current_kind) {
        .subleq => {
            if (sl.halted) {
                putLine("halted.", C_ERROR);
                return;
            }
            var n = count;
            while (n > 0) : (n -= 1) {
                const r = sl.step();
                switch (r) {
                    .ok => {},
                    .output => {},
                    .halt => {
                        putLine("[halted]", C_HALT);
                        return;
                    },
                    .fault => {
                        putLine("[fault]", C_ERROR);
                        return;
                    },
                    .input_needed => {
                        putLine("[input needed]", C_INFO);
                        return;
                    },
                }
            }
            drainSubleqOutput();
            var buf: [80]u8 = undefined;
            const ln = std.fmt.bufPrint(&buf, "[sl stepped {d}; PC={d} cycles={d}]", .{ count, sl.pc, sl.cycles }) catch return;
            putLine(ln, C_INFO);
        },
        .chip8 => {
            if (c8.halted) {
                putLine("halted.", C_ERROR);
                return;
            }
            var n = count;
            while (n > 0) : (n -= 1) {
                const r = c8.step();
                switch (r) {
                    .ok => {},
                    .halt => {
                        putLine("[halted]", C_HALT);
                        return;
                    },
                    .fault => {
                        putLine("[fault]", C_ERROR);
                        return;
                    },
                    .waiting_for_key => {
                        putLine("[waiting for key]", C_INFO);
                        return;
                    },
                }
            }
            var buf: [80]u8 = undefined;
            const ln = std.fmt.bufPrint(&buf, "[c8 stepped {d}; PC=0x{X:0>3} cyc={d}]", .{ count, c8.pc, c8.cycles }) catch return;
            putLine(ln, C_INFO);
        },
    }
}

fn cmdReset() void {
    switch (current_kind) {
        .subleq => {
            sl.reset();
            putLine("[sl] reset.", C_INFO);
        },
        .chip8 => {
            c8.reset();
            putLine("[c8] reset.", C_INFO);
        },
    }
}

fn cmdRegs() void {
    switch (current_kind) {
        .subleq => {
            var buf: [80]u8 = undefined;
            const ln = std.fmt.bufPrint(&buf, "PC={d}  cycles={d}  halted={any}", .{ sl.pc, sl.cycles, sl.halted }) catch return;
            putLine(ln, C_INFO);
            if (sl.pc < 0 or sl.pc >= @as(i32, @intCast(subleq_be.MEM_SIZE))) return;
            const center: usize = @intCast(sl.pc);
            const lo: usize = if (center >= 3) center - 3 else 0;
            const hi: usize = if (center + 9 < subleq_be.MEM_SIZE) center + 9 else subleq_be.MEM_SIZE;
            var i: usize = lo;
            while (i < hi) {
                var lbuf: [80]u8 = undefined;
                const marker: u8 = if (i == center) '>' else ' ';
                const a = sl.mem[i];
                const b = if (i + 1 < subleq_be.MEM_SIZE) sl.mem[i + 1] else 0;
                const c = if (i + 2 < subleq_be.MEM_SIZE) sl.mem[i + 2] else 0;
                const ln2 = std.fmt.bufPrint(&lbuf, " {c} [{d:>4}] {d:>6} {d:>6} {d:>6}", .{ marker, i, a, b, c }) catch break;
                putLine(ln2, C_TEXT);
                i += 3;
            }
        },
        .chip8 => {
            var buf: [128]u8 = undefined;
            const ln = std.fmt.bufPrint(&buf, "PC=0x{X:0>3} I=0x{X:0>3} SP={d} DT={d} ST={d} cyc={d}", .{
                c8.pc, c8.i_reg, c8.sp, c8.dt, c8.st, c8.cycles,
            }) catch return;
            putLine(ln, C_INFO);
            // V0..V7
            const r0 = std.fmt.bufPrint(&buf, "V0={X:0>2} V1={X:0>2} V2={X:0>2} V3={X:0>2} V4={X:0>2} V5={X:0>2} V6={X:0>2} V7={X:0>2}", .{
                c8.v[0], c8.v[1], c8.v[2], c8.v[3], c8.v[4], c8.v[5], c8.v[6], c8.v[7],
            }) catch return;
            putLine(r0, C_TEXT);
            const r1 = std.fmt.bufPrint(&buf, "V8={X:0>2} V9={X:0>2} VA={X:0>2} VB={X:0>2} VC={X:0>2} VD={X:0>2} VE={X:0>2} VF={X:0>2}", .{
                c8.v[8], c8.v[9], c8.v[10], c8.v[11], c8.v[12], c8.v[13], c8.v[14], c8.v[15],
            }) catch return;
            putLine(r1, C_TEXT);
        },
    }
}

fn cmdMem(addr: i32) void {
    switch (current_kind) {
        .subleq => {
            if (addr < 0 or addr >= @as(i32, @intCast(subleq_be.MEM_SIZE))) {
                putLine("addr out of range.", C_ERROR);
                return;
            }
            const start: usize = @intCast(addr);
            const end: usize = if (start + 8 < subleq_be.MEM_SIZE) start + 8 else subleq_be.MEM_SIZE;
            var buf: [120]u8 = undefined;
            var len: usize = 0;
            const hdr = std.fmt.bufPrint(buf[len..], "mem[{d}..{d}]:", .{ start, end }) catch return;
            len += hdr.len;
            var i = start;
            while (i < end) : (i += 1) {
                const cell = std.fmt.bufPrint(buf[len..], " {d}", .{sl.mem[i]}) catch break;
                len += cell.len;
            }
            putLine(buf[0..len], C_INFO);
        },
        .chip8 => {
            if (addr < 0 or addr >= @as(i32, chip8_be.MEM_SIZE)) {
                putLine("addr out of range.", C_ERROR);
                return;
            }
            const start: usize = @intCast(addr);
            const end: usize = if (start + 16 < chip8_be.MEM_SIZE) start + 16 else chip8_be.MEM_SIZE;
            var buf: [128]u8 = undefined;
            var len: usize = 0;
            const hdr = std.fmt.bufPrint(buf[len..], "mem[0x{X:0>3}..0x{X:0>3}]:", .{ start, end }) catch return;
            len += hdr.len;
            var i = start;
            while (i < end) : (i += 1) {
                const cell = std.fmt.bufPrint(buf[len..], " {X:0>2}", .{c8.mem[i]}) catch break;
                len += cell.len;
            }
            putLine(buf[0..len], C_INFO);
        },
    }
}

fn cmdClear() void {
    clearTextArea();
}

fn cmdKeys(rest: []const u8) void {
    if (eqStr(rest, "on")) {
        chip8_key_mode = true;
        putLine("keys: ON (chars feed CHIP-8 keypad; shell keys disabled)", C_INFO);
    } else if (eqStr(rest, "off")) {
        chip8_key_mode = false;
        putLine("keys: OFF (chars build shell commands)", C_INFO);
    } else {
        putLine("usage: keys on|off", C_ERROR);
    }
}

fn drainSubleqOutput() void {
    while (sl.popOutput()) |ch| putChar(ch, C_OUTPUT);
}

fn runCommand(line: []const u8) bool {
    var s = line;
    while (s.len > 0 and s[0] == ' ') s = s[1..];
    if (s.len == 0) return true;

    var i: usize = 0;
    while (i < s.len and s[i] != ' ') i += 1;
    const cmd = s[0..i];
    var rest = s[i..];
    while (rest.len > 0 and rest[0] == ' ') rest = rest[1..];

    if (eqStr(cmd, "help")) {
        cmdHelp();
    } else if (eqStr(cmd, "list")) {
        cmdList();
    } else if (eqStr(cmd, "use")) {
        if (rest.len == 0) putLine("usage: use <backend>", C_ERROR) else cmdUse(rest);
    } else if (eqStr(cmd, "load")) {
        if (rest.len == 0) putLine("usage: load <path>", C_ERROR) else cmdLoad(rest);
    } else if (eqStr(cmd, "sample")) {
        if (rest.len == 0) putLine("usage: sample <name>", C_ERROR) else cmdSample(rest);
    } else if (eqStr(cmd, "run")) {
        cmdRun();
    } else if (eqStr(cmd, "stop")) {
        cmdStop();
    } else if (eqStr(cmd, "step")) {
        const n: u32 = if (rest.len == 0) 1 else blk: {
            const v = parseInt(rest) orelse {
                putLine("step: bad count", C_ERROR);
                return true;
            };
            if (v <= 0) {
                putLine("step: count must be positive", C_ERROR);
                return true;
            }
            break :blk @intCast(v);
        };
        cmdStep(n);
    } else if (eqStr(cmd, "reset")) {
        cmdReset();
    } else if (eqStr(cmd, "regs")) {
        cmdRegs();
    } else if (eqStr(cmd, "mem")) {
        if (rest.len == 0) {
            putLine("usage: mem <addr>", C_ERROR);
        } else {
            const a = parseInt(rest) orelse {
                putLine("mem: bad addr", C_ERROR);
                return true;
            };
            cmdMem(a);
        }
    } else if (eqStr(cmd, "clear")) {
        cmdClear();
    } else if (eqStr(cmd, "keys")) {
        cmdKeys(rest);
    } else if (eqStr(cmd, "quit") or eqStr(cmd, "exit")) {
        return false;
    } else {
        var buf: [80]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "unknown command: '{s}'. try 'help'.", .{cmd}) catch return true;
        putLine(msg, C_ERROR);
    }
    return true;
}

// === Main loop ===

fn timeMs() u64 {
    const t = libc.gettimeofday();
    return @as(u64, t.sec) * 1000 + @as(u64, t.usec) / 1000;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const win = libc.createWindow(WIN_W, WIN_H) orelse libc.exit();
    var canvas = gfx.Canvas.init(win.fb, win.alloc_w, win.alloc_h);
    fa.ensureLoaded();

    sl.reset();
    c8.reset();
    showBanner();
    redraw(&canvas);

    var last_timer_ms: u64 = timeMs();
    var last_step_ms: u64 = last_timer_ms;

    while (true) {
        var did_work = false;

        // Drain window events.
        while (libc.pollEvent()) |ev| {
            did_work = true;
            const k = ev.kindOf();
            switch (k) {
                .key_char => {
                    const ch: u8 = @truncate(ev.a);

                    // Subleq input prompt mode — feed char straight to the program.
                    if (current_kind == .subleq and sl.waiting_for_input) {
                        sl.feedInput(ch);
                        putChar(ch, C_OUTPUT);
                        continue;
                    }

                    // CHIP-8 keypad capture mode — chars never reach the shell.
                    if (current_kind == .chip8 and chip8_key_mode) {
                        if (chip8KeyMap(ch)) |k8| c8.keyPressed(k8);
                        continue;
                    }

                    // Shell prompt editing.
                    if (ch == '\n' or ch == '\r') {
                        putChar('>', C_PROMPT_GLYPH);
                        putChar(' ', C_TEXT);
                        putStr(prompt_buf[0..prompt_len], C_TEXT);
                        putChar('\n', C_TEXT);
                        const keep = runCommand(prompt_buf[0..prompt_len]);
                        promptClear();
                        if (!keep) {
                            libc.destroyWindow();
                            libc.exit();
                        }
                    } else if (ch == 8 or ch == 127) {
                        promptBackspace();
                    } else if (ch >= 32 and ch <= 126) {
                        promptAppend(ch);
                    }
                },
                .close_request => {
                    libc.destroyWindow();
                    libc.exit();
                },
                else => {},
            }
        }

        // Step active backend.
        const now = timeMs();
        if (now - last_step_ms >= 8) {
            last_step_ms = now;
            switch (current_kind) {
                .subleq => {
                    if (sl.running) {
                        const r = sl.tickFrame(2000);
                        drainSubleqOutput();
                        switch (r) {
                            .halt => {
                                var buf: [80]u8 = undefined;
                                if (std.fmt.bufPrint(&buf, "[halt @ PC={d}  cycles={d}]", .{ sl.pc, sl.cycles })) |ln| {
                                    putLine(ln, C_HALT);
                                } else |_| {}
                            },
                            .fault => putLine("[fault]", C_ERROR),
                            .input_needed => putLine("[input needed — type one char]", C_INFO),
                            else => {},
                        }
                        did_work = true;
                    }
                },
                .chip8 => {
                    if (c8.running) {
                        // ~700 inst/sec target (chip8 spec sweet spot): we
                        // tick every 8ms, so 6 per tick = 750 Hz.
                        const r = c8.tickFrame(6);
                        switch (r) {
                            .halt => putLine("[c8 halt]", C_HALT),
                            .fault => putLine("[c8 fault]", C_ERROR),
                            .waiting_for_key => {},
                            else => {},
                        }
                        did_work = true;
                    }
                },
            }
        }

        // 60 Hz timer tick for chip8.
        if (now - last_timer_ms >= 16) {
            last_timer_ms = now;
            if (current_kind == .chip8) {
                c8.tickTimers();
                did_work = did_work or (c8.dt > 0) or (c8.st > 0);
            }
        }

        if (did_work) redraw(&canvas) else libc.sleep(5);
    }
}
