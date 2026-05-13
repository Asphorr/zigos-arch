// CHIP-8 backend for babel.
//
// 35 opcodes, 4 KB memory (program starts at 0x200), 16 V0-VF registers
// (u8), I register (u16), PC (u16), SP (u8), stack (16 entries), delay
// timer (DT) and sound timer (ST) — both u8 decrementing at 60 Hz —
// 64×32 mono framebuffer (XOR-blitted sprites), 16-key keypad.
//
// Built-in font: 16 sprites of 5 bytes each at 0x000..0x04F (digits 0..F).
//
// Reference: Cowgod's CHIP-8 Technical Reference v1.0.

const std = @import("std");

pub const MEM_SIZE: u16 = 4096;
pub const PROG_START: u16 = 0x200;
pub const FONT_BASE: u16 = 0x000;
pub const FB_W: u32 = 64;
pub const FB_H: u32 = 32;
pub const STACK_SIZE: u8 = 16;
pub const NUM_REGS: u8 = 16;
pub const NUM_KEYS: u8 = 16;

pub const StepResult = enum { ok, halt, fault, waiting_for_key };

// 16 hex digit sprites — each is 5 bytes (drawn as 4×5 pixels on screen).
const FONT_SPRITES: [80]u8 = .{
    0xF0, 0x90, 0x90, 0x90, 0xF0, // 0
    0x20, 0x60, 0x20, 0x20, 0x70, // 1
    0xF0, 0x10, 0xF0, 0x80, 0xF0, // 2
    0xF0, 0x10, 0xF0, 0x10, 0xF0, // 3
    0x90, 0x90, 0xF0, 0x10, 0x10, // 4
    0xF0, 0x80, 0xF0, 0x10, 0xF0, // 5
    0xF0, 0x80, 0xF0, 0x90, 0xF0, // 6
    0xF0, 0x10, 0x20, 0x40, 0x40, // 7
    0xF0, 0x90, 0xF0, 0x90, 0xF0, // 8
    0xF0, 0x90, 0xF0, 0x10, 0xF0, // 9
    0xF0, 0x90, 0xF0, 0x90, 0x90, // A
    0xE0, 0x90, 0xE0, 0x90, 0xE0, // B
    0xF0, 0x80, 0x80, 0x80, 0xF0, // C
    0xE0, 0x90, 0x90, 0x90, 0xE0, // D
    0xF0, 0x80, 0xF0, 0x80, 0xF0, // E
    0xF0, 0x80, 0xF0, 0x80, 0x80, // F
};

pub const Core = struct {
    mem: [MEM_SIZE]u8 = [_]u8{0} ** MEM_SIZE,
    v: [NUM_REGS]u8 = [_]u8{0} ** NUM_REGS,
    i_reg: u16 = 0,
    pc: u16 = PROG_START,
    sp: u8 = 0,
    stack: [STACK_SIZE]u16 = [_]u16{0} ** STACK_SIZE,
    dt: u8 = 0,
    st: u8 = 0,
    fb: [FB_W * FB_H]u8 = [_]u8{0} ** (FB_W * FB_H),

    cycles: u32 = 0,
    halted: bool = true, // boot in halted state until a ROM is loaded
    running: bool = false,

    // Each entry: cycle count beyond which the key is no longer "held". We
    // have no key-release events from libc; the auto-decay covers polled
    // input (EX9E/EXA1) for short bursts. Long-press games would need
    // press/release events; that's a future libc upgrade.
    key_held_until: [NUM_KEYS]u32 = [_]u32{0} ** NUM_KEYS,

    // Blocking wait for FX0A — step() returns waiting_for_key until host
    // calls keyPressed; that handler writes the key into V[waiting_reg]
    // and clears the flag.
    waiting_for_key: bool = false,
    waiting_reg: u8 = 0,

    // xorshift64 RNG state for CXKK.
    rng: u64 = 0x12345678ABCDEF00,

    /// Clear all state, load built-in font.
    pub fn reset(self: *Core) void {
        @memset(&self.mem, 0);
        @memset(&self.v, 0);
        self.i_reg = 0;
        self.pc = PROG_START;
        self.sp = 0;
        @memset(&self.stack, 0);
        self.dt = 0;
        self.st = 0;
        @memset(&self.fb, 0);
        self.cycles = 0;
        self.halted = true;
        self.running = false;
        @memset(&self.key_held_until, 0);
        self.waiting_for_key = false;
        self.waiting_reg = 0;
        @memcpy(self.mem[FONT_BASE..][0..FONT_SPRITES.len], &FONT_SPRITES);
    }

    /// Load a raw CHIP-8 program (bytes) starting at PROG_START. Resets
    /// state first. Returns false if the program doesn't fit.
    pub fn loadRom(self: *Core, rom: []const u8) bool {
        if (rom.len > @as(usize, MEM_SIZE) - @as(usize, PROG_START)) return false;
        self.reset();
        @memcpy(self.mem[PROG_START..][0..rom.len], rom);
        self.halted = false;
        return true;
    }

    fn rand(self: *Core) u8 {
        var x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        return @truncate(x & 0xFF);
    }

    /// Host calls this on any chip8-mapped key arrival. Stamps the held-until
    /// cycle and, if a blocking FX0A wait is in flight, unblocks it.
    pub fn keyPressed(self: *Core, k: u8) void {
        if (k >= NUM_KEYS) return;
        // ~30 cycles is roughly 30ms at our 1000 Hz default — enough for one
        // EX9E poll cycle in fast-paced games.
        self.key_held_until[k] = self.cycles + 30;
        if (self.waiting_for_key) {
            self.v[self.waiting_reg] = k;
            self.waiting_for_key = false;
        }
    }

    fn keyDown(self: *const Core, k: u8) bool {
        if (k >= NUM_KEYS) return false;
        return self.key_held_until[k] > self.cycles;
    }

    /// Fetch + decode + execute one opcode.
    pub fn step(self: *Core) StepResult {
        if (self.halted) return .halt;
        if (self.waiting_for_key) return .waiting_for_key;
        if (self.pc + 1 >= MEM_SIZE) {
            self.halted = true;
            return .fault;
        }
        const op_hi: u16 = self.mem[self.pc];
        const op_lo: u16 = self.mem[self.pc + 1];
        const op: u16 = (op_hi << 8) | op_lo;
        self.pc +%= 2;
        self.cycles +%= 1;

        const nnn: u16 = op & 0x0FFF;
        const n: u8 = @truncate(op & 0x000F);
        const x: u8 = @truncate((op >> 8) & 0x000F);
        const y: u8 = @truncate((op >> 4) & 0x000F);
        const kk: u8 = @truncate(op & 0x00FF);

        const high = (op >> 12) & 0xF;
        switch (high) {
            0x0 => {
                if (op == 0x00E0) {
                    @memset(&self.fb, 0);
                } else if (op == 0x00EE) {
                    if (self.sp == 0) {
                        self.halted = true;
                        return .fault;
                    }
                    self.sp -= 1;
                    self.pc = self.stack[self.sp];
                }
                // 0NNN SYS — no-op in modern interpreters.
            },
            0x1 => self.pc = nnn,
            0x2 => {
                if (self.sp >= STACK_SIZE) {
                    self.halted = true;
                    return .fault;
                }
                self.stack[self.sp] = self.pc;
                self.sp += 1;
                self.pc = nnn;
            },
            0x3 => if (self.v[x] == kk) {
                self.pc +%= 2;
            },
            0x4 => if (self.v[x] != kk) {
                self.pc +%= 2;
            },
            0x5 => if (n == 0 and self.v[x] == self.v[y]) {
                self.pc +%= 2;
            },
            0x6 => self.v[x] = kk,
            0x7 => self.v[x] = self.v[x] +% kk,
            0x8 => switch (n) {
                0x0 => self.v[x] = self.v[y],
                0x1 => self.v[x] |= self.v[y],
                0x2 => self.v[x] &= self.v[y],
                0x3 => self.v[x] ^= self.v[y],
                0x4 => {
                    const sum: u16 = @as(u16, self.v[x]) + @as(u16, self.v[y]);
                    self.v[x] = @truncate(sum & 0xFF);
                    self.v[0xF] = if (sum > 0xFF) 1 else 0;
                },
                0x5 => {
                    const vx = self.v[x];
                    const vy = self.v[y];
                    self.v[x] = vx -% vy;
                    self.v[0xF] = if (vx >= vy) 1 else 0;
                },
                0x6 => {
                    const lsb = self.v[x] & 1;
                    self.v[x] >>= 1;
                    self.v[0xF] = lsb;
                },
                0x7 => {
                    const vx = self.v[x];
                    const vy = self.v[y];
                    self.v[x] = vy -% vx;
                    self.v[0xF] = if (vy >= vx) 1 else 0;
                },
                0xE => {
                    const msb = (self.v[x] >> 7) & 1;
                    self.v[x] <<= 1;
                    self.v[0xF] = msb;
                },
                else => {},
            },
            0x9 => if (n == 0 and self.v[x] != self.v[y]) {
                self.pc +%= 2;
            },
            0xA => self.i_reg = nnn,
            0xB => self.pc = nnn +% self.v[0],
            0xC => self.v[x] = self.rand() & kk,
            0xD => {
                const xpos: u32 = @as(u32, self.v[x]) % FB_W;
                const ypos: u32 = @as(u32, self.v[y]) % FB_H;
                self.v[0xF] = 0;
                var row: u8 = 0;
                while (row < n) : (row += 1) {
                    if (@as(usize, self.i_reg) + row >= MEM_SIZE) break;
                    const sprite_byte = self.mem[self.i_reg + row];
                    var col: u8 = 0;
                    while (col < 8) : (col += 1) {
                        const px = xpos + col;
                        const py = ypos + row;
                        if (px >= FB_W or py >= FB_H) continue; // clip (no wrap)
                        const bit: u8 = @intCast((sprite_byte >> @as(u3, @intCast(7 - col))) & 1);
                        if (bit == 0) continue;
                        const idx: usize = py * FB_W + px;
                        if (self.fb[idx] != 0) self.v[0xF] = 1;
                        self.fb[idx] ^= 1;
                    }
                }
            },
            0xE => switch (kk) {
                0x9E => if (self.keyDown(self.v[x] & 0xF)) {
                    self.pc +%= 2;
                },
                0xA1 => if (!self.keyDown(self.v[x] & 0xF)) {
                    self.pc +%= 2;
                },
                else => {},
            },
            0xF => switch (kk) {
                0x07 => self.v[x] = self.dt,
                0x0A => {
                    self.waiting_for_key = true;
                    self.waiting_reg = x;
                    return .waiting_for_key;
                },
                0x15 => self.dt = self.v[x],
                0x18 => self.st = self.v[x],
                0x1E => self.i_reg +%= self.v[x],
                0x29 => self.i_reg = FONT_BASE + @as(u16, self.v[x] & 0xF) * 5,
                0x33 => {
                    if (@as(usize, self.i_reg) + 2 >= MEM_SIZE) {
                        self.halted = true;
                        return .fault;
                    }
                    const vx = self.v[x];
                    self.mem[self.i_reg] = vx / 100;
                    self.mem[self.i_reg + 1] = (vx / 10) % 10;
                    self.mem[self.i_reg + 2] = vx % 10;
                },
                0x55 => {
                    var i: u8 = 0;
                    while (i <= x) : (i += 1) {
                        if (@as(usize, self.i_reg) + i >= MEM_SIZE) break;
                        self.mem[self.i_reg + i] = self.v[i];
                    }
                },
                0x65 => {
                    var i: u8 = 0;
                    while (i <= x) : (i += 1) {
                        if (@as(usize, self.i_reg) + i >= MEM_SIZE) break;
                        self.v[i] = self.mem[self.i_reg + i];
                    }
                },
                else => {},
            },
            else => {},
        }
        return .ok;
    }

    /// Run up to `budget` instructions or until non-ok result. Returns the
    /// first non-ok result, or .ok if budget exhausted.
    pub fn tickFrame(self: *Core, budget: u32) StepResult {
        if (!self.running or self.halted) return .halt;
        var i: u32 = 0;
        while (i < budget) : (i += 1) {
            const r = self.step();
            if (r != .ok) {
                if (r == .halt or r == .fault) self.running = false;
                return r;
            }
        }
        return .ok;
    }

    /// Decrement DT and ST. Host calls this at 60 Hz, independent of CPU speed.
    pub fn tickTimers(self: *Core) void {
        if (self.dt > 0) self.dt -= 1;
        if (self.st > 0) self.st -= 1;
    }

    /// Draw the framebuffer scaled by `scale` to (x_off, y_off).
    pub fn render(self: *const Core, canvas: anytype, x_off: u32, y_off: u32, scale: u32, fg: u32, bg: u32) void {
        // Background rect first — single fillRect is much cheaper than 64×32
        // separate calls for unset pixels.
        canvas.fillRect(x_off, y_off, FB_W * scale, FB_H * scale, bg);
        var y: u32 = 0;
        while (y < FB_H) : (y += 1) {
            var x: u32 = 0;
            while (x < FB_W) : (x += 1) {
                if (self.fb[y * FB_W + x] != 0) {
                    canvas.fillRect(x_off + x * scale, y_off + y * scale, scale, scale, fg);
                }
            }
        }
    }
};

// === Built-in ROMs (small public-domain test programs) ===

// "letter A" — draws font sprite for hex digit A at (10, 10), then loops.
// Smallest useful test: 14 bytes, exercises CLS, LD imm, FX29, DXYN, JP.
pub const ROM_DIGIT_A: []const u8 = &[_]u8{
    0x00, 0xE0, // 0x200: CLS
    0x60, 0x0A, // 0x202: LD V0, 0x0A
    0xF0, 0x29, // 0x204: LD F, V0 — I = font sprite for 0xA
    0x60, 0x0A, // 0x206: LD V0, 10
    0x61, 0x0A, // 0x208: LD V1, 10
    0xD0, 0x15, // 0x20A: DRW V0, V1, 5
    0x12, 0x0C, // 0x20C: JP 0x20C — infinite loop
};

// Draws hex digits 0..F across two rows, then halts (infinite loop).
// Exercises ADD imm, SE/SNE, branch flow.
pub const ROM_DIGITS: []const u8 = &[_]u8{
    0x00, 0xE0, // 0x200: CLS
    0x62, 0x00, // 0x202: LD V2, 0     ; digit counter
    0x63, 0x02, // 0x204: LD V3, 2     ; x position
    0x64, 0x02, // 0x206: LD V4, 2     ; y position
    0xF2, 0x29, // 0x208: LD F, V2     ; I = font sprite for V2
    0xD3, 0x45, // 0x20A: DRW V3, V4, 5
    0x72, 0x01, // 0x20C: ADD V2, 1
    0x73, 0x06, // 0x20E: ADD V3, 6
    0x33, 0x32, // 0x210: SE V3, 50    ; skip if row full
    0x12, 0x08, // 0x212: JP 0x208     ; not yet — continue
    0x63, 0x02, // 0x214: LD V3, 2     ; reset x
    0x74, 0x07, // 0x216: ADD V4, 7    ; next row
    0x42, 0x10, // 0x218: SNE V2, 16   ; skip if V2 != 16
    0x12, 0x1E, // 0x21A: JP 0x21E     ; all done — halt
    0x12, 0x08, // 0x21C: JP 0x208     ; next digit
    0x12, 0x1E, // 0x21E: JP 0x21E     ; idle loop
};

// Bouncing diagonal — sprite "0" walks across the screen, bouncing on edges.
// Exercises CLS+DRW per frame, ADD V,V with VF carry, SE/JP branches.
pub const ROM_BOUNCE: []const u8 = &[_]u8{
    0x60, 0x00, // 0x200: LD V0, 0     ; x
    0x61, 0x00, // 0x202: LD V1, 0     ; y
    0x62, 0x01, // 0x204: LD V2, 1     ; dx
    0x63, 0x01, // 0x206: LD V3, 1     ; dy
    0x65, 0x00, // 0x208: LD V5, 0     ; font index 0
    0xF5, 0x29, // 0x20A: LD F, V5     ; I = font sprite for 0
    0x00, 0xE0, // 0x20C: CLS
    0xD0, 0x15, // 0x20E: DRW V0, V1, 5
    0x80, 0x24, // 0x210: ADD V0, V2   ; x += dx
    0x81, 0x34, // 0x212: ADD V1, V3   ; y += dy
    0x30, 0x3C, // 0x214: SE V0, 60    ; at right edge?
    0x12, 0x1A, // 0x216: JP 0x21A     ; no
    0x62, 0xFF, // 0x218: LD V2, -1    ; yes — flip dx
    0x30, 0x00, // 0x21A: SE V0, 0     ; at left edge?
    0x12, 0x20, // 0x21C: JP 0x220     ; no
    0x62, 0x01, // 0x21E: LD V2, 1     ; yes — flip dx
    0x31, 0x1B, // 0x220: SE V1, 27    ; at bottom edge?
    0x12, 0x26, // 0x222: JP 0x226     ; no
    0x63, 0xFF, // 0x224: LD V3, -1    ; yes — flip dy
    0x31, 0x00, // 0x226: SE V1, 0     ; at top edge?
    0x12, 0x2C, // 0x228: JP 0x22C     ; no
    0x63, 0x01, // 0x22A: LD V3, 1     ; yes — flip dy
    0x12, 0x0C, // 0x22C: JP 0x20C     ; loop back to CLS
};

// Keyboard test — show the most-recently-pressed key as a hex digit sprite.
// Press 1-9, 0, or A-F (mapped via host) to see the digit drawn.
pub const ROM_KEYTEST: []const u8 = &[_]u8{
    0x00, 0xE0, // 0x200: CLS
    0xF0, 0x0A, // 0x202: LD V0, K     ; block until key pressed
    0x00, 0xE0, // 0x204: CLS
    0xF0, 0x29, // 0x206: LD F, V0     ; I = font sprite for that key
    0x61, 0x1C, // 0x208: LD V1, 28    ; x = 28 (centered-ish)
    0x62, 0x0E, // 0x20A: LD V2, 14    ; y = 14
    0xD1, 0x25, // 0x20C: DRW V1, V2, 5
    0x12, 0x02, // 0x20E: JP 0x202     ; wait for next key
};

pub const Sample = struct {
    name: []const u8,
    desc: []const u8,
    rom: []const u8,
};

pub const SAMPLES: []const Sample = &[_]Sample{
    .{ .name = "digit", .desc = "Draws hex digit 'A' at (10,10)", .rom = ROM_DIGIT_A },
    .{ .name = "digits", .desc = "Draws all 16 hex digits 0..F", .rom = ROM_DIGITS },
    .{ .name = "bounce", .desc = "Bouncing '0' sprite", .rom = ROM_BOUNCE },
    .{ .name = "keytest", .desc = "Press a key to draw its hex digit", .rom = ROM_KEYTEST },
};
