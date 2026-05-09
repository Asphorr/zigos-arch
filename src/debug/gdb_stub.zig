const io = @import("../io.zig");
const serial = @import("serial.zig");
const process = @import("../proc/process.zig");
const elf_loader = @import("../proc/elf_loader.zig");
const debug = @import("debug.zig");

// --- COM2 serial port (0x2F8) for GDB communication ---

const COM2: u16 = 0x2F8;
const PKT_SIZE = 4096;

/// Set to true to halt at boot and wait for GDB to attach. Const because the
/// stub init runs before user can flip a runtime flag; if you want to debug
/// from boot, edit this and rebuild.
pub const wait_for_gdb = false;

/// Runtime flag. If true, ANY Ring 0 exception (kernel mode crash) drops into
/// the stub and waits for GDB even if one isn't attached yet. Default true so
/// the user can attach gdb post-mortem. Set to false to make crashes halt
/// without waiting (useful when running without a debugger nearby).
pub var attach_on_kernel_exception_flag: bool = true;

// --- Module state ---

var initialized: bool = false;
var no_ack_mode: bool = false;
var gdb_connected: bool = false; // true after first successful packet exchange
var resume_action: enum { none, cont, step } = .none;
var saved_frame: ?[*]u64 = null;
var stop_reason: u8 = 0;
var current_thread: u32 = 0;
var stepping_past_bp: ?u64 = null;
var pkt_buf: [PKT_SIZE]u8 = undefined;

// Software breakpoints
const MAX_SW_BP = 32;
const SwBreakpoint = struct {
    addr: u64 = 0,
    orig_byte: u8 = 0,
    active: bool = false,
};
var sw_breakpoints: [MAX_SW_BP]SwBreakpoint = [_]SwBreakpoint{.{}} ** MAX_SW_BP;

// Hardware breakpoints (DR0-DR3)
const HwBreakpoint = struct {
    addr: u64 = 0,
    kind: u8 = 0, // 0=exec, 1=write, 3=read/write
    len: u8 = 1,
    active: bool = false,
};
var hw_breakpoints: [4]HwBreakpoint = [_]HwBreakpoint{.{}} ** 4;

// GDB register index → exception frame offset
// Frame: [0]=R15 [1]=R14 [2]=R13 [3]=R12 [4]=R11 [5]=R10 [6]=R9 [7]=R8
//        [8]=RDI [9]=RSI [10]=RBP [11]=RBX [12]=RDX [13]=RCX [14]=RAX
//        [15]=int_no [16]=error_code
//        [17]=RIP [18]=CS [19]=RFLAGS [20]=RSP [21]=SS
const gdb_to_frame = [24]?u8{
    14, 11, 13, 12, 9, 8, 10, 20, // rax rbx rcx rdx rsi rdi rbp rsp
    7, 6, 5, 4, 3, 2, 1, 0, // r8-r15
    17, 19, 18, 21, // rip eflags cs ss
    null, null, null, null, // ds es fs gs (fixed values)
};

// --- Public API ---

pub fn init() void {
    initCom2();
    initialized = true;
    debug.klog("[gdb] COM2 initialized at 115200 baud\n", .{});

    if (wait_for_gdb) {
        debug.klog("[gdb] Waiting for GDB connection...\n", .{});
        asm volatile ("int $3");
    }
}

pub fn isActive() bool {
    return initialized;
}

/// True after GDB has completed at least one full packet exchange (qSupported).
pub fn isConnected() bool {
    return gdb_connected;
}

/// True if the kernel should drop into the stub on Ring 0 exceptions when no
/// GDB is currently attached. Reads the runtime flag.
pub fn attachOnKernelException() bool {
    return attach_on_kernel_exception_flag;
}

/// Insert a software breakpoint from kernel code
pub fn breakpoint() void {
    asm volatile ("int $3");
}

/// Check for Ctrl-C break from GDB (call from timer IRQ)
pub fn checkForBreak() void {
    if (!initialized) return;
    // Check if COM2 has data ready
    if (io.inb(COM2 + 5) & 1 != 0) {
        const c = io.inb(COM2);
        if (c == 0x03) {
            // Ctrl-C — break into debugger
            asm volatile ("int $3");
        }
    }
}

/// Main entry point — called from handleException for int 1/3
pub fn enterStub(frame: [*]u64, exc_num: u8) void {
    saved_frame = frame;
    stop_reason = exc_num;

    if (exc_num == 3) {
        // int 3: RIP points after 0xCC, adjust back
        frame[17] -= 1;

        // Check if this is a software breakpoint we set
        const bp_addr = frame[17];
        for (&sw_breakpoints) |*bp| {
            if (bp.active and bp.addr == bp_addr) {
                // Restore original byte
                const ptr: *u8 = @ptrFromInt(@as(usize, @intCast(bp_addr)));
                ptr.* = bp.orig_byte;
                break;
            }
        }
    } else if (exc_num == 1) {
        // Debug exception — check if stepping past a BP
        if (stepping_past_bp) |bp_addr| {
            // Re-insert the breakpoint
            const ptr: *u8 = @ptrFromInt(@as(usize, @intCast(bp_addr)));
            ptr.* = 0xCC;
            stepping_past_bp = null;
            // Clear TF
            frame[19] &= ~@as(u64, 1 << 8);
            // Don't report to GDB — silently continue
            resume_action = .cont;
            return;
        }
        // Clear TF
        frame[19] &= ~@as(u64, 1 << 8);
        // Check DR6 for hardware watchpoint
        clearDR6();
    }

    // Only send stop reply if GDB is already connected (not first break)
    // For first break, GDB will ask with '?' after connecting
    if (gdb_connected) {
        sendStopReply();
    }

    // Poll loop — handle GDB commands until continue/step
    resume_action = .none;
    while (resume_action == .none) {
        if (recvPacket()) |pkt| {
            handlePacket(pkt);
        }
    }

    // Prepare to resume
    if (resume_action == .step) {
        frame[19] |= (1 << 8); // Set TF for single step
    } else {
        frame[19] &= ~@as(u64, 1 << 8); // Clear TF

        // Check if RIP is on a software BP — need to step past it
        const rip = frame[17];
        for (&sw_breakpoints) |*bp| {
            if (bp.active and bp.addr == rip) {
                // Step one instruction past, then re-insert
                stepping_past_bp = rip;
                frame[19] |= (1 << 8); // Set TF
                break;
            }
        }
    }

    applyHwBreakpoints();
    saved_frame = null;
}

// --- COM2 I/O ---

fn initCom2() void {
    io.outb(COM2 + 1, 0x00); // Disable interrupts
    io.outb(COM2 + 3, 0x80); // Enable DLAB
    io.outb(COM2 + 0, 0x01); // Divisor 1 = 115200 baud
    io.outb(COM2 + 1, 0x00);
    io.outb(COM2 + 3, 0x03); // 8N1
    io.outb(COM2 + 2, 0xC7); // Enable FIFO
    io.outb(COM2 + 4, 0x0B); // RTS/DSR
}

fn com2Read() u8 {
    while (io.inb(COM2 + 5) & 1 == 0) {}
    return io.inb(COM2);
}

fn com2Write(b: u8) void {
    while (io.inb(COM2 + 5) & 0x20 == 0) {}
    io.outb(COM2, b);
}

fn com2WriteSlice(data: []const u8) void {
    for (data) |b| com2Write(b);
}

fn com2Drain() void {
    // Drain any pending bytes from COM2
    var i: u32 = 0;
    while (i < 256) : (i += 1) {
        if (io.inb(COM2 + 5) & 1 != 0) {
            _ = io.inb(COM2);
        } else break;
    }
}

// --- Packet framing ---

fn recvPacket() ?[]u8 {
    // Wait for '$' start marker
    while (true) {
        const c = com2Read();
        if (c == '$') break;
        if (c == 0x03) {
            // Ctrl-C break
            return null;
        }
        // Skip ACK/NAK (+/-)
    }

    // Read until '#'
    var len: usize = 0;
    var checksum: u8 = 0;
    while (len < pkt_buf.len) {
        const c = com2Read();
        if (c == '#') break;
        pkt_buf[len] = c;
        checksum +%= c;
        len += 1;
    }

    // Read 2-digit checksum
    const hi = hexVal(com2Read()) orelse {
        com2Write('-');
        return null;
    };
    const lo = hexVal(com2Read()) orelse {
        com2Write('-');
        return null;
    };
    const expected: u8 = (@as(u8, hi) << 4) | lo;

    if (checksum != expected) {
        if (!no_ack_mode) com2Write('-'); // NAK
        return null;
    }

    if (!no_ack_mode) com2Write('+'); // ACK
    return pkt_buf[0..len];
}

fn sendPacket(data: []const u8) void {
    var checksum: u8 = 0;
    for (data) |b| checksum +%= b;

    com2Write('$');
    com2WriteSlice(data);
    com2Write('#');
    com2Write(hexChar(checksum >> 4));
    com2Write(hexChar(checksum & 0x0F));

    if (no_ack_mode) return;

    // Wait for ACK with generous timeout for TCP latency
    var attempts: u32 = 0;
    while (attempts < 1_000_000) : (attempts += 1) {
        if (io.inb(COM2 + 5) & 1 != 0) {
            const c = io.inb(COM2);
            if (c == '+') return;
            if (c == '-') {
                // Retransmit
                com2Write('$');
                com2WriteSlice(data);
                com2Write('#');
                com2Write(hexChar(checksum >> 4));
                com2Write(hexChar(checksum & 0x0F));
                attempts = 0;
            }
            // Skip any other bytes (GDB might send a command before ACK)
        }
    }
}

fn sendStr(s: []const u8) void {
    sendPacket(s);
}

// --- Command dispatch ---

fn handlePacket(pkt: []const u8) void {
    if (pkt.len == 0) {
        sendStr("");
        return;
    }

    switch (pkt[0]) {
        '?' => handleQueryHalt(),
        'g' => handleReadRegs(),
        'G' => handleWriteRegs(pkt[1..]),
        'm' => handleReadMem(pkt[1..]),
        'M' => handleWriteMem(pkt[1..]),
        'c' => handleContinue(),
        's' => handleStep(),
        'Z' => handleSetBreakpoint(pkt),
        'z' => handleRemoveBreakpoint(pkt),
        'H' => handleThreadOp(pkt),
        'q' => handleQuery(pkt),
        'Q' => {
            if (startsWith(pkt, "QStartNoAckMode")) {
                sendStr("OK");
                no_ack_mode = true;
            } else {
                sendStr("");
            }
        },
        'D' => {
            // Detach — disable stub so it doesn't re-enter
            sendStr("OK");
            com2Drain();
            initialized = false;
            no_ack_mode = false;
            gdb_connected = false;
            resume_action = .cont;
        },
        'k' => {
            // Kill — just continue
            resume_action = .cont;
        },
        else => sendStr(""), // Unsupported
    }
}

// --- Command handlers ---

fn handleQueryHalt() void {
    // Map exception to signal
    const sig: u8 = switch (stop_reason) {
        1, 3 => 5, // SIGTRAP
        6 => 4, // SIGILL
        13, 14 => 11, // SIGSEGV
        else => 6, // SIGABRT
    };
    var reply: [3]u8 = undefined;
    reply[0] = 'S';
    reply[1] = hexChar(sig >> 4);
    reply[2] = hexChar(sig & 0x0F);
    sendPacket(&reply);
}

fn sendStopReply() void {
    var reply: [3]u8 = undefined;
    reply[0] = 'T';
    reply[1] = hexChar(5 >> 4); // SIGTRAP
    reply[2] = hexChar(5 & 0x0F);
    sendPacket(&reply);
}

fn handleReadRegs() void {
    const frame = saved_frame orelse {
        sendStr("E01");
        return;
    };

    // GDB x86_64 expects: 24 GPRs (8 bytes each) + x87 regs + SSE regs
    // 24 GPRs × 16 hex = 384 + FP/SSE zeros ≈ 1120 hex chars
    // Total: 24 GPRs (192 bytes) + 8×ST (80 bytes) + 7 FP ctrl (28 bytes)
    //        + 16×XMM (256 bytes) + MXCSR (4 bytes) = 560 bytes = 1120 hex
    var buf: [1120]u8 = undefined;
    @memset(&buf, '0'); // Zero-fill everything (FP/SSE = 0)
    var pos: usize = 0;

    // Write 24 GPRs
    for (0..24) |i| {
        const val: u64 = if (gdb_to_frame[i]) |idx|
            frame[idx]
        else switch (i) {
            20, 21 => 0x10, // ds, es
            else => 0, // fs, gs
        };

        // Little-endian: least significant byte first
        for (0..8) |byte_idx| {
            const b: u8 = @intCast((val >> @intCast(byte_idx * 8)) & 0xFF);
            buf[pos] = hexChar(b >> 4);
            buf[pos + 1] = hexChar(b & 0x0F);
            pos += 2;
        }
    }

    // Rest is already zero-filled (FP/SSE registers)
    sendPacket(&buf);
}

fn handleWriteRegs(data: []const u8) void {
    const frame = saved_frame orelse {
        sendStr("E01");
        return;
    };

    // Each register = 16 hex chars (8 bytes, little-endian)
    var reg_idx: usize = 0;
    var data_pos: usize = 0;
    while (reg_idx < 24 and data_pos + 16 <= data.len) : ({
        reg_idx += 1;
        data_pos += 16;
    }) {
        if (gdb_to_frame[reg_idx]) |frame_idx| {
            var val: u64 = 0;
            for (0..8) |byte_idx| {
                const hi = hexVal(data[data_pos + byte_idx * 2]) orelse continue;
                const lo = hexVal(data[data_pos + byte_idx * 2 + 1]) orelse continue;
                val |= @as(u64, (@as(u8, hi) << 4) | lo) << @intCast(byte_idx * 8);
            }
            frame[frame_idx] = val;
        }
    }
    sendStr("OK");
}

fn handleReadMem(args: []const u8) void {
    // Parse "addr,len"
    const comma = indexOf(args, ',') orelse {
        sendStr("E01");
        return;
    };
    const addr = parseHex64(args[0..comma]) orelse {
        sendStr("E01");
        return;
    };
    const len = parseHex64(args[comma + 1 ..]) orelse {
        sendStr("E01");
        return;
    };

    if (len == 0 or len > PKT_SIZE / 2) {
        sendStr("E01");
        return;
    }

    // Read memory and encode as hex
    var buf: [PKT_SIZE]u8 = undefined;
    var pos: usize = 0;
    const length: usize = @intCast(len);

    for (0..length) |i| {
        const byte_addr = addr + i;
        const b = readByte(byte_addr) orelse {
            sendStr("E14"); // EFAULT
            return;
        };
        buf[pos] = hexChar(b >> 4);
        buf[pos + 1] = hexChar(b & 0x0F);
        pos += 2;
    }

    sendPacket(buf[0..pos]);
}

fn handleWriteMem(args: []const u8) void {
    // Parse "addr,len:data"
    const comma = indexOf(args, ',') orelse {
        sendStr("E01");
        return;
    };
    const colon = indexOf(args, ':') orelse {
        sendStr("E01");
        return;
    };
    const addr = parseHex64(args[0..comma]) orelse {
        sendStr("E01");
        return;
    };
    const len = parseHex64(args[comma + 1 .. colon]) orelse {
        sendStr("E01");
        return;
    };

    const hex_data = args[colon + 1 ..];
    const length: usize = @intCast(len);

    for (0..length) |i| {
        if (i * 2 + 1 >= hex_data.len) break;
        const hi = hexVal(hex_data[i * 2]) orelse break;
        const lo = hexVal(hex_data[i * 2 + 1]) orelse break;
        const b: u8 = (@as(u8, hi) << 4) | lo;

        if (!writeByte(addr + i, b)) {
            sendStr("E14");
            return;
        }
    }
    sendStr("OK");
}

fn handleContinue() void {
    resume_action = .cont;
}

fn handleStep() void {
    resume_action = .step;
}

fn handleSetBreakpoint(pkt: []const u8) void {
    // Z<type>,<addr>,<kind>
    if (pkt.len < 5) {
        sendStr("E01");
        return;
    }
    const bp_type = pkt[1];
    const args = pkt[3..]; // skip "Z<type>,"
    const comma = indexOf(args, ',') orelse {
        sendStr("E01");
        return;
    };
    const addr = parseHex64(args[0..comma]) orelse {
        sendStr("E01");
        return;
    };

    switch (bp_type) {
        '0' => {
            // Software breakpoint
            for (&sw_breakpoints) |*bp| {
                if (!bp.active) {
                    const ptr: *u8 = @ptrFromInt(@as(usize, @intCast(addr)));
                    bp.addr = addr;
                    bp.orig_byte = ptr.*;
                    bp.active = true;
                    ptr.* = 0xCC;
                    sendStr("OK");
                    return;
                }
            }
            sendStr("E0A"); // No free slots
        },
        '1', '2', '3', '4' => {
            // Hardware breakpoint/watchpoint
            const kind: u8 = switch (bp_type) {
                '1' => 0, // exec
                '2' => 1, // write
                '3' => 3, // read/write
                '4' => 3, // access = read/write
                else => 0,
            };
            for (&hw_breakpoints) |*bp| {
                if (!bp.active) {
                    bp.addr = addr;
                    bp.kind = kind;
                    bp.len = 1;
                    bp.active = true;
                    sendStr("OK");
                    return;
                }
            }
            sendStr("E0A"); // No free slots
        },
        else => sendStr(""),
    }
}

fn handleRemoveBreakpoint(pkt: []const u8) void {
    if (pkt.len < 5) {
        sendStr("E01");
        return;
    }
    const bp_type = pkt[1];
    const args = pkt[3..];
    const comma = indexOf(args, ',') orelse {
        sendStr("E01");
        return;
    };
    const addr = parseHex64(args[0..comma]) orelse {
        sendStr("E01");
        return;
    };

    switch (bp_type) {
        '0' => {
            // Remove software breakpoint
            for (&sw_breakpoints) |*bp| {
                if (bp.active and bp.addr == addr) {
                    const ptr: *u8 = @ptrFromInt(@as(usize, @intCast(addr)));
                    ptr.* = bp.orig_byte;
                    bp.active = false;
                    sendStr("OK");
                    return;
                }
            }
            sendStr("E01");
        },
        '1', '2', '3', '4' => {
            for (&hw_breakpoints) |*bp| {
                if (bp.active and bp.addr == addr) {
                    bp.active = false;
                    sendStr("OK");
                    return;
                }
            }
            sendStr("E01");
        },
        else => sendStr(""),
    }
}

fn handleThreadOp(pkt: []const u8) void {
    // Hg<tid> or Hc<tid>
    if (pkt.len < 2) {
        sendStr("OK");
        return;
    }
    if (pkt.len >= 3) {
        const tid = parseHex64(pkt[2..]) orelse 0;
        current_thread = @intCast(tid);
    }
    sendStr("OK");
}

fn handleQuery(pkt: []const u8) void {
    if (startsWith(pkt, "qSupported")) {
        gdb_connected = true;
        sendStr("PacketSize=4096;swbreak+;hwbreak+;QStartNoAckMode+");
    } else if (startsWith(pkt, "qfThreadInfo")) {
        // List active threads (PIDs)
        var buf: [256]u8 = undefined;
        buf[0] = 'm';
        var pos: usize = 1;
        var first = true;
        for (0..process.MAX_PROCS) |i| {
            const pcb = process.getPCB(i);
            if (pcb.state != .unused) {
                if (!first and pos < buf.len - 1) {
                    buf[pos] = ',';
                    pos += 1;
                }
                // Thread ID = PID + 1 (GDB reserves 0)
                const tid = i + 1;
                const written = writeHexU32(&buf, pos, @intCast(tid));
                pos += written;
                first = false;
            }
        }
        if (first) {
            // No threads — report at least thread 1
            buf[1] = '1';
            pos = 2;
        }
        sendPacket(buf[0..pos]);
    } else if (startsWith(pkt, "qsThreadInfo")) {
        sendStr("l"); // End of thread list
    } else if (startsWith(pkt, "qAttached")) {
        sendStr("1"); // Attached to existing process
    } else if (startsWith(pkt, "qTStatus")) {
        sendStr(""); // No tracepoints
    } else {
        sendStr(""); // Unsupported query
    }
}

// --- Debug register management ---

fn applyHwBreakpoints() void {
    var dr7: u64 = 0;

    for (0..4) |i| {
        const bp = hw_breakpoints[i];
        if (bp.active) {
            // Set DRn address
            switch (i) {
                0 => asm volatile ("movq %[addr], %%dr0"
                    :
                    : [addr] "r" (bp.addr),
                ),
                1 => asm volatile ("movq %[addr], %%dr1"
                    :
                    : [addr] "r" (bp.addr),
                ),
                2 => asm volatile ("movq %[addr], %%dr2"
                    :
                    : [addr] "r" (bp.addr),
                ),
                3 => asm volatile ("movq %[addr], %%dr3"
                    :
                    : [addr] "r" (bp.addr),
                ),
                else => {},
            }

            // Enable local breakpoint (bit 2*i)
            dr7 |= @as(u64, 1) << @intCast(i * 2);

            // Set type in bits 16+4*i (2 bits)
            const type_val: u64 = bp.kind;
            dr7 |= type_val << @intCast(16 + i * 4);

            // Set length in bits 18+4*i (2 bits) — 0=1byte, 1=2byte, 3=4byte
            const len_val: u64 = switch (bp.len) {
                1 => 0,
                2 => 1,
                4 => 3,
                8 => 2,
                else => 0,
            };
            dr7 |= len_val << @intCast(18 + i * 4);
        }
    }

    asm volatile ("movq %[val], %%dr7"
        :
        : [val] "r" (dr7),
    );
}

fn clearDR6() void {
    asm volatile ("movq %[val], %%dr6"
        :
        : [val] "r" (@as(u64, 0)),
    );
}

// --- Memory access helpers ---
//
// GDB asks the stub to read/write arbitrary memory while debugging. If we just
// dereference the address blindly, an unmapped or non-canonical address takes
// down the kernel mid-debug session. We pre-validate via the page-table walker
// before each access so the stub stays alive when GDB pokes random places.

/// True if `addr` lands in a present, accessible page in the current address
/// space. Used to gate memory accesses from GDB so a bad address doesn't fault
/// the kernel out of the debugger.
fn isAccessible(addr: u64) bool {
    // Reject non-canonical addresses outright — touching them would #GP.
    const high = addr >> 47;
    if (high != 0 and high != 0x1FFFF) return false;

    const paging = @import("../mm/paging.zig");
    return paging.isMapped(addr);
}

fn readByte(addr: u64) ?u8 {
    if (!isAccessible(addr)) return null;
    const ptr: *const volatile u8 = @ptrFromInt(@as(usize, @intCast(addr)));
    return ptr.*;
}

fn writeByte(addr: u64, val: u8) bool {
    if (!isAccessible(addr)) return false;
    const ptr: *volatile u8 = @ptrFromInt(@as(usize, @intCast(addr)));
    ptr.* = val;
    return true;
}

// --- Hex helpers ---

fn hexVal(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

fn hexChar(v: anytype) u8 {
    const nibble: u8 = @intCast(@as(u4, @intCast(v & 0xF)));
    return if (nibble < 10) '0' + nibble else 'a' + nibble - 10;
}

fn parseHex64(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var result: u64 = 0;
    for (s) |c| {
        const d = hexVal(c) orelse return null;
        result = (result << 4) | d;
    }
    return result;
}

fn writeHexU32(buf: []u8, pos: usize, val: u32) usize {
    if (val == 0) {
        if (pos < buf.len) {
            buf[pos] = '0';
            return 1;
        }
        return 0;
    }
    var v = val;
    var digits: [8]u8 = undefined;
    var dlen: usize = 0;
    while (v > 0) : (v >>= 4) {
        digits[dlen] = hexChar(@as(u4, @intCast(v & 0xF)));
        dlen += 1;
    }
    // Write in reverse
    var written: usize = 0;
    var i: usize = dlen;
    while (i > 0) : (i -= 1) {
        if (pos + written < buf.len) {
            buf[pos + written] = digits[i - 1];
            written += 1;
        }
    }
    return written;
}

// --- String helpers ---

fn indexOf(s: []const u8, c: u8) ?usize {
    for (s, 0..) |ch, i| {
        if (ch == c) return i;
    }
    return null;
}

fn startsWith(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    return std.mem.eql(u8, s[0..prefix.len], prefix);
}

const std = @import("std");
