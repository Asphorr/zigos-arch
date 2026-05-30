const std = @import("std");
const vga = @import("ui/vga.zig");
const keyboard = @import("driver/keyboard.zig");
const vfs = @import("fs/vfs.zig");
const elf_loader = @import("proc/elf_loader.zig");
const pmm = @import("mm/pmm.zig");
const process = @import("proc/process.zig");
const fat32 = @import("fs/fat32.zig");
const heap = @import("mm/heap.zig");
const desktop = @import("ui/desktop.zig");
const symbols = @import("debug/symbols.zig");
const serial = @import("debug/serial.zig");

var buffer: [128]u8 = undefined;
var len: usize = 0;

pub fn start() void {
    printBanner();
    prompt();
    while (true) {
        asm volatile ("hlt");

        while (keyboard.pop()) |ch| {
            if (ch == '\n') {
                vga.print("\n", .{});
                execute(buffer[0..len]);
                len = 0;
                prompt();
            } else if (ch == '\x08') {
                if (len > 0) {
                    len -= 1;
                    vga.putChar('\x08');
                }
            } else if (len < buffer.len) {
                buffer[len] = ch;
                len += 1;
                vga.putChar(ch);
            }
        }
    }
}

fn printBanner() void {
    vga.fg = .LightCyan;
    vga.print("  ______            ___  ____\n", .{});
    vga.print(" |__  (_) __ _     / _ \\/ ___|\n", .{});
    vga.print("   / /| |/ _` |   | | | \\___ \\\n", .{});
    vga.print("  / /_| | (_| |   | |_| |___) |\n", .{});
    vga.print(" /____|_|\\__, |    \\___/|____/\n", .{});
    vga.print("         |___/\n", .{});
    vga.fg = .LightGray;
    vga.print(" x86 Hobby OS ", .{});
    vga.fg = .DarkGray;
    vga.print("| Zig 0.13 | 12,500+ lines\n", .{});
    vga.fg = .DarkGray;
    vga.print(" Type ", .{});
    vga.fg = .LightGreen;
    vga.print("help", .{});
    vga.fg = .DarkGray;
    vga.print(" for commands, ", .{});
    vga.fg = .LightGreen;
    vga.print("desktop", .{});
    vga.fg = .DarkGray;
    vga.print(" for GUI\n\n", .{});
    vga.fg = .LightGray;
}

fn prompt() void {
    vga.fg = .LightGreen;
    vga.print("root", .{});
    vga.fg = .DarkGray;
    vga.print("@", .{});
    vga.fg = .LightCyan;
    vga.print("zigos", .{});
    vga.fg = .DarkGray;
    vga.print("> ", .{});
    vga.fg = .White;
}

fn printSection(comptime title: []const u8) void {
    vga.fg = .Yellow;
    vga.print(title ++ "\n", .{});
    vga.fg = .LightGray;
}

fn printCmd(comptime name: []const u8, comptime desc: []const u8) void {
    vga.fg = .LightGreen;
    vga.print("  " ++ name, .{});
    const pad = if (name.len < 18) 18 - name.len else 1;
    vga.print(" " ** pad, .{});
    vga.fg = .LightGray;
    vga.print(desc ++ "\n", .{});
}

fn printOk(comptime msg: []const u8, args: anytype) void {
    vga.fg = .LightGreen;
    vga.print(msg, args);
    vga.fg = .LightGray;
}

fn printErr(comptime msg: []const u8, args: anytype) void {
    vga.fg = .LightRed;
    vga.print(msg, args);
    vga.fg = .LightGray;
}

pub fn execute(cmd: []const u8) void {
    if (cmd.len == 0) return;

    if (std.mem.eql(u8, cmd, "help")) {
        printSection("System");
        printCmd("clear", "Clear screen");
        printCmd("meminfo", "Memory statistics");
        printCmd("ps", "List running processes");
        printCmd("kill <pid>", "Kill process by PID");
        printCmd("uptime", "Show system uptime");
        printCmd("lsusb", "List USB devices");
        printCmd("neofetch", "System information");
        printCmd("crashlog", "View app crash log");
        printSection("Files");
        printCmd("ls", "List all files");
        printCmd("cat <file>", "View file contents");
        printCmd("mkfile <name>", "Create empty FAT16 file");
        printCmd("write <f> <data>", "Write text to file");
        printCmd("rm <file>", "Delete FAT16 file");
        printSection("Apps");
        printCmd("run <app.elf>", "Launch application");
        printCmd("desktop", "Launch graphical desktop");
        printSection("Network");
        printCmd("ping <ip>", "Ping an IP address");
        printCmd("nslookup <host>", "DNS lookup");
        printCmd("wget <url>", "HTTP GET request");
        printSection("Debug");
        printCmd("peek <addr> [n]", "Hex dump memory (default 64 bytes)");
        printCmd("poke <addr> <val>", "Write u32 to memory address");
        printCmd("stack [pid]", "Stack trace for process");
        printCmd("regs <pid>", "Show saved registers");
        printCmd("dump <pid>", "Full process info dump");
        printCmd("symbols [pid]", "List loaded debug symbols");
        printCmd("heap", "Heap stats + integrity check");
        printCmd("bt", "Kernel backtrace");
        printCmd("perf [reset]", "Per-CPU phase + per-syscall cycle counters");
    } else if (std.mem.eql(u8, cmd, "clear")) {
        vga.clear();
    } else if (std.mem.eql(u8, cmd, "ls")) {
        cmdLs();
    } else if (std.mem.eql(u8, cmd, "lsfat")) {
        fat32.listFiles();
    } else if (std.mem.eql(u8, cmd, "ps")) {
        cmdPs();
    } else if (std.mem.eql(u8, cmd, "meminfo")) {
        cmdMeminfo();
    } else if (std.mem.eql(u8, cmd, "uptime")) {
        cmdUptime();
    } else if (std.mem.eql(u8, cmd, "neofetch")) {
        cmdNeofetch();
    } else if (std.mem.eql(u8, cmd, "desktop")) {
        if (desktop.active) {
            printErr("Desktop is already running\n", .{});
            return;
        }
        desktop.run();
        vga.clear();
        printBanner();
    } else if (std.mem.eql(u8, cmd, "div0")) {
        var a: u32 = 1;
        var b: u32 = 0;
        _ = &a;
        _ = &b;
        asm volatile (
            \\xorl %%edx, %%edx
            \\divl %[divisor]
            :
            : [dividend] "{eax}" (a),
              [divisor] "r" (b),
            : .{ .eax = true, .edx = true }
        );
    } else if (std.mem.startsWith(u8, cmd, "run ")) {
        cmdRun(cmd[4..]);
    } else if (std.mem.startsWith(u8, cmd, "mkfile ")) {
        cmdMkfile(cmd[7..]);
    } else if (std.mem.startsWith(u8, cmd, "wrfile ") or std.mem.startsWith(u8, cmd, "write ")) {
        const args = if (std.mem.startsWith(u8, cmd, "write ")) cmd[6..] else cmd[7..];
        cmdWrite(args);
    } else if (std.mem.startsWith(u8, cmd, "rdfile ") or std.mem.startsWith(u8, cmd, "cat ")) {
        const name = if (std.mem.startsWith(u8, cmd, "cat ")) cmd[4..] else cmd[7..];
        cmdCat(name);
    } else if (std.mem.startsWith(u8, cmd, "rmfile ") or std.mem.startsWith(u8, cmd, "rm ")) {
        const name = if (std.mem.startsWith(u8, cmd, "rm ")) cmd[3..] else cmd[7..];
        cmdRm(name);
    } else if (std.mem.startsWith(u8, cmd, "kill ")) {
        cmdKill(cmd[5..]);
    } else if (std.mem.eql(u8, cmd, "crashlog")) {
        cmdCat("CRASHLOG");
    } else if (std.mem.eql(u8, cmd, "lsusb")) {
        cmdLsusb();
    } else if (std.mem.startsWith(u8, cmd, "ping ")) {
        const net = @import("net/net.zig");
        net.pingCommand(cmd[5..]);
    } else if (std.mem.startsWith(u8, cmd, "nslookup ")) {
        const net = @import("net/net.zig");
        net.nslookupCommand(cmd[9..]);
    } else if (std.mem.startsWith(u8, cmd, "wget ")) {
        const net = @import("net/net.zig");
        net.wgetCommand(cmd[5..]);
    } else if (std.mem.eql(u8, cmd, "echo") or std.mem.startsWith(u8, cmd, "echo ")) {
        if (cmd.len > 5) vga.print("{s}\n", .{cmd[5..]}) else vga.print("\n", .{});
    } else if (std.mem.eql(u8, cmd, "whoami")) {
        vga.print("root\n", .{});
    } else if (std.mem.eql(u8, cmd, "hostname")) {
        vga.print("zigos\n", .{});
    } else if (std.mem.eql(u8, cmd, "uname") or std.mem.eql(u8, cmd, "uname -a")) {
        vga.print("ZigOS 0.1.0 x86 i386\n", .{});
    } else if (std.mem.startsWith(u8, cmd, "peek ")) {
        cmdPeek(cmd[5..]);
    } else if (std.mem.startsWith(u8, cmd, "poke ")) {
        cmdPoke(cmd[5..]);
    } else if (std.mem.eql(u8, cmd, "stack") or std.mem.startsWith(u8, cmd, "stack ")) {
        cmdStack(if (cmd.len > 6) cmd[6..] else null);
    } else if (std.mem.startsWith(u8, cmd, "regs ")) {
        cmdRegs(cmd[5..]);
    } else if (std.mem.startsWith(u8, cmd, "dump ")) {
        cmdDump(cmd[5..]);
    } else if (std.mem.eql(u8, cmd, "symbols") or std.mem.startsWith(u8, cmd, "symbols ")) {
        cmdSymbols(if (cmd.len > 8) cmd[8..] else null);
    } else if (std.mem.eql(u8, cmd, "heap")) {
        cmdHeap();
    } else if (std.mem.eql(u8, cmd, "bt")) {
        cmdBt();
    } else if (std.mem.eql(u8, cmd, "perf")) {
        cmdPerf();
    } else if (std.mem.eql(u8, cmd, "perf reset")) {
        @import("debug/perf.zig").resetAll();
        vga.print("perf counters cleared\n", .{});
    } else if (std.mem.eql(u8, cmd, "ipi")) {
        cmdIpi();
    } else {
        printErr("Unknown command: {s}\n", .{cmd});
        vga.fg = .DarkGray;
        vga.print("Type 'help' for available commands\n", .{});
        vga.fg = .LightGray;
    }
}

// --- Command implementations ---

fn cmdLs() void {
    const ata = @import("driver/block.zig");
    const tarfs = @import("fs/tarfs.zig");

    printSection("TAR Archive (drive 0)");
    var lba: u32 = 0;
    var sec_buf: [512]u8 = undefined;
    var count: u32 = 0;
    while (lba < 8000) {
        ata.readSector(lba, &sec_buf);
        if (sec_buf[0] == 0) break;
        const name_len = std.mem.indexOfScalar(u8, sec_buf[0..100], 0) orelse 100;
        const size = tarfs.parseOctal(sec_buf[124..136]);
        const sectors: u32 = @intCast((size + 511) / 512);

        vga.fg = .LightCyan;
        vga.print("  {s}", .{sec_buf[0..name_len]});
        var pad: usize = if (name_len < 20) 20 - name_len else 1;
        while (pad > 0) : (pad -= 1) vga.putChar(' ');
        vga.fg = .DarkGray;
        printSize(size);
        vga.print("\n", .{});
        count += 1;
        lba += 1 + sectors;
    }

    if (fat32.isInitialized()) {
        printSection("FAT16 Disk (drive 2)");
        var fi: u32 = 0;
        while (fi < fat32.root_entry_count) : (fi += 1) {
            const de = fat32.readRootDirEntry(fi) orelse continue;
            if (de.name[0] == 0) break;
            if (de.name[0] == 0xE5) continue;
            if (de.attr & 0x0F == 0x0F) continue;
            if (de.attr & 0x08 != 0) continue;
            if (de.attr & 0x10 != 0) continue;

            // Format 8.3 name
            var name_buf: [13]u8 = undefined;
            var pos: u8 = 0;
            var base_end: u8 = 8;
            while (base_end > 0 and de.name[base_end - 1] == ' ') base_end -= 1;
            for (0..base_end) |j| { name_buf[pos] = de.name[j]; pos += 1; }
            var ext_end: u8 = 3;
            while (ext_end > 0 and de.name[8 + ext_end - 1] == ' ') ext_end -= 1;
            if (ext_end > 0) {
                name_buf[pos] = '.'; pos += 1;
                for (0..ext_end) |j| { name_buf[pos] = de.name[8 + j]; pos += 1; }
            }

            vga.fg = .LightGreen;
            vga.print("  {s}", .{name_buf[0..pos]});
            var fpad: usize = if (pos < 20) 20 - pos else 1;
            while (fpad > 0) : (fpad -= 1) vga.putChar(' ');
            vga.fg = .DarkGray;
            printSize(de.file_size);
            vga.print("\n", .{});
            count += 1;
        }
    }

    vga.fg = .DarkGray;
    vga.print("  {d} files total\n", .{count});
    vga.fg = .LightGray;
}

fn printSize(size: usize) void {
    if (size >= 1024 * 1024) {
        vga.print("{d} MB", .{size / (1024 * 1024)});
    } else if (size >= 1024) {
        vga.print("{d} KB", .{size / 1024});
    } else {
        vga.print("{d} B", .{size});
    }
}

fn cmdPs() void {
    vga.fg = .Yellow;
    vga.print("  PID  STATE     NAME\n", .{});
    vga.fg = .DarkGray;
    vga.print("  ---  --------  ----------------\n", .{});
    vga.fg = .LightGray;
    for (0..process.MAX_PROCS) |i| {
        const pcb = process.getPCB(i);
        if (pcb.state == .unused) continue;
        vga.print("  ", .{});
        vga.fg = .White;
        vga.print("{d}", .{i});
        if (i < 10) vga.print(" ", .{});
        vga.print("   ", .{});
        const state_str = switch (pcb.state) {
            .ready => "ready   ",
            .running => "running ",
            .sleeping => "sleeping",
            .unused => "unused  ",
            .zombie => "zombie  ",
            .loading => "loading ",
        };
        vga.fg = if (pcb.state == .running) .LightGreen else .LightGray;
        vga.print("{s}  ", .{state_str});
        vga.fg = .LightCyan;
        const name = process.getName(@intCast(i));
        if (name.len > 0) {
            vga.print("{s}", .{name});
        } else if (pcb.is_idle) {
            vga.print("[idle]", .{});
        } else {
            vga.print("[kernel]", .{});
        }
        vga.fg = .LightGray;
        vga.print("\n", .{});
    }
}

fn cmdMeminfo() void {
    const free = pmm.freeFrameCount();
    const total = free + 1024;
    const used = total - free;
    vga.fg = .Yellow;
    vga.print("Memory\n", .{});
    vga.fg = .LightGray;
    vga.print("  Total:  {d} KB\n", .{total * 4});
    vga.print("  Used:   ", .{});
    vga.fg = .LightRed;
    vga.print("{d} KB", .{used * 4});
    vga.fg = .LightGray;
    vga.print(" ({d}%)\n", .{used * 100 / total});
    vga.print("  Free:   ", .{});
    vga.fg = .LightGreen;
    vga.print("{d} KB\n", .{free * 4});
    vga.fg = .LightGray;
}

fn cmdUptime() void {
    const ticks = process.tick_count;
    const secs: u32 = @truncate(ticks / 100);
    const mins = secs / 60;
    const hrs = mins / 60;
    vga.print("up {d}h {d}m {d}s ({d} ticks)\n", .{ hrs, mins % 60, secs % 60, @as(u32, @truncate(ticks)) });
}

fn cmdNeofetch() void {
    const gfx = @import("ui/gfx.zig");
    const free = pmm.freeFrameCount();
    const total = free + 1024;

    vga.fg = .LightCyan;
    vga.print("       _____       ", .{});
    vga.fg = .White;
    vga.print("root@zigos\n", .{});
    vga.fg = .LightCyan;
    vga.print("      |__  /       ", .{});
    vga.fg = .DarkGray;
    vga.print("----------\n", .{});
    vga.fg = .LightCyan;
    vga.print("        / /        ", .{});
    vga.fg = .Yellow;
    vga.print("OS: ", .{});
    vga.fg = .LightGray;
    vga.print("ZigOS 0.1.0\n", .{});
    vga.fg = .LightCyan;
    vga.print("       / /_        ", .{});
    vga.fg = .Yellow;
    vga.print("Arch: ", .{});
    vga.fg = .LightGray;
    vga.print("x86 (i386)\n", .{});
    vga.fg = .LightCyan;
    vga.print("      /____| ig    ", .{});
    vga.fg = .Yellow;
    vga.print("Lang: ", .{});
    vga.fg = .LightGray;
    vga.print("Zig 0.13.0\n", .{});
    vga.fg = .LightCyan;
    vga.print("                   ", .{});
    vga.fg = .Yellow;
    vga.print("Mem: ", .{});
    vga.fg = .LightGray;
    vga.print("{d}/{d} KB\n", .{ (total - free) * 4, total * 4 });
    vga.print("                   ", .{});
    vga.fg = .Yellow;
    vga.print("Res: ", .{});
    vga.fg = .LightGray;
    vga.print("{d}x{d}\n", .{ gfx.screen_w, gfx.screen_h });
    vga.print("                   ", .{});
    vga.fg = .Yellow;
    vga.print("GPU: ", .{});
    vga.fg = .LightGray;
    if (@import("driver/virtio_gpu.zig").active) {
        vga.print("virtio-gpu\n", .{});
    } else {
        vga.print("BGA\n", .{});
    }
    vga.print("                   ", .{});
    vga.fg = .Yellow;
    vga.print("USB: ", .{});
    vga.fg = .LightGray;
    vga.print("xHCI 3.0\n", .{});
    vga.print("                   ", .{});
    vga.fg = .Yellow;
    vga.print("Net: ", .{});
    vga.fg = .LightGray;
    vga.print("virtio-net\n", .{});
    // Color bar
    vga.print("                   ", .{});
    for ([_]vga.Color{ .Black, .Red, .Green, .Brown, .Blue, .Magenta, .Cyan, .LightGray }) |c| {
        vga.fg = c;
        vga.bg = c;
        vga.print("  ", .{});
    }
    vga.bg = .Black;
    vga.fg = .LightGray;
    vga.print("\n", .{});
}

fn cmdRun(name: []const u8) void {
    if (name.len == 0) {
        printErr("Usage: run <app.elf>\n", .{});
        return;
    }
    if (desktop.active) {
        // Use async loading on AP to keep UI responsive
        const smp = @import("cpu/smp.zig");
        if (smp.cpu_count > 1 and smp.requestAppLoad(name)) {
            desktop.showNotification("Loading...");
            return;
        }
    }
    // Sync fallback (single core or AP busy)
    if (vfs.loadFileFresh(name)) |fresh| {
        if (desktop.active) {
            if (elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, null)) |pid| {
                const fname = name;
                var nlen: usize = fname.len;
                if (nlen >= 4 and fname[nlen - 4] == '.') nlen -= 4;
                process.setName(@intCast(pid), fname[0..nlen]);
                printOk("Started PID={d}\n", .{pid});
            } else {
                printErr("Failed to start process\n", .{});
            }
        } else {
            elf_loader.loadAndExecute(fresh.buf, fresh.size, fresh.pages, fresh.inode);
            printOk("\n[Process exited]\n", .{});
        }
    } else {
        printErr("File not found: {s}\n", .{name});
    }
}

fn cmdMkfile(name: []const u8) void {
    if (name.len == 0) { printErr("Usage: mkfile <name>\n", .{}); return; }
    if (fat32.createFile(name)) |_| {
        printOk("Created: {s}\n", .{name});
    } else {
        printErr("Failed to create: {s}\n", .{name});
    }
}

fn cmdWrite(args: []const u8) void {
    const space_pos = std.mem.indexOfScalar(u8, args, ' ') orelse {
        printErr("Usage: write <file> <data>\n", .{});
        return;
    };
    const name = args[0..space_pos];
    const data = args[space_pos + 1 ..];
    var handle = fat32.openFile(name) orelse fat32.createFile(name) orelse {
        printErr("Failed to open/create: {s}\n", .{name});
        return;
    };
    const written = fat32.writeFile(&handle, data.ptr, @intCast(data.len));
    fat32.closeFile(handle);
    printOk("Wrote {d} bytes to {s}\n", .{ written, name });
}

fn cmdCat(name: []const u8) void {
    if (name.len == 0) { printErr("Usage: cat <file>\n", .{}); return; }
    const handle = fat32.openFile(name) orelse {
        printErr("File not found: {s}\n", .{name});
        return;
    };
    var read_buf: [512]u8 = undefined;
    const bytes = fat32.readFile(handle, &read_buf, 512);
    if (bytes > 0) {
        vga.print("{s}\n", .{read_buf[0..bytes]});
    } else {
        vga.fg = .DarkGray;
        vga.print("(empty)\n", .{});
        vga.fg = .LightGray;
    }
}

fn cmdRm(name: []const u8) void {
    if (name.len == 0) { printErr("Usage: rm <file>\n", .{}); return; }
    if (fat32.deleteFile(name)) {
        printOk("Deleted: {s}\n", .{name});
    } else {
        printErr("File not found: {s}\n", .{name});
    }
}

fn cmdKill(pid_str: []const u8) void {
    const pid = std.fmt.parseInt(u8, pid_str, 10) catch {
        printErr("Usage: kill <pid>\n", .{});
        return;
    };
    if (pid >= process.MAX_PROCS) {
        printErr("Invalid PID: {d}\n", .{pid});
        return;
    }
    const pcb = process.getPCB(pid);
    if (pcb.state == .unused) {
        printErr("No process with PID {d}\n", .{pid});
    } else {
        process.killProcess(pid);
        printOk("Killed PID {d}\n", .{pid});
    }
}

fn cmdLsusb() void {
    const xhci_mod = @import("driver/xhci.zig");
    if (!xhci_mod.isInitialized()) {
        printErr("No xHCI controller found\n", .{});
        return;
    }
    printSection("USB (xHCI 3.0)");
    vga.print("  MMIO: 0x{X:0>8}\n", .{xhci_mod.getMmioBase()});
    vga.print("  Ports: {d}  Slots: {d}\n", .{ xhci_mod.getMaxPorts(), xhci_mod.getMaxSlots() });
    if (xhci_mod.hasUsbKeyboard()) {
        vga.fg = .LightGreen;
        vga.print("  + Keyboard\n", .{});
        vga.fg = .LightGray;
    }
    if (xhci_mod.hasUsbMouse()) {
        vga.fg = .LightGreen;
        vga.print("  + Mouse\n", .{});
        vga.fg = .LightGray;
    }
}

// --- Debug commands ---

fn parseHex(s: []const u8) ?u64 {
    var str = s;
    // Skip optional "0x" prefix
    if (str.len >= 2 and str[0] == '0' and (str[1] == 'x' or str[1] == 'X')) {
        str = str[2..];
    }
    if (str.len == 0) return null;
    var result: u64 = 0;
    for (str) |c| {
        const digit: u64 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => return null,
        };
        result = (result << 4) | digit;
    }
    return result;
}

fn parseDecimal(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var result: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        result = result * 10 + (c - '0');
    }
    return result;
}

fn cmdPeek(args: []const u8) void {
    // Parse: <addr> [count]
    var addr_end: usize = 0;
    while (addr_end < args.len and args[addr_end] != ' ') : (addr_end += 1) {}

    const addr = parseHex(args[0..addr_end]) orelse {
        printErr("Usage: peek <hex_addr> [count]\n", .{});
        return;
    };

    var count: u32 = 64;
    if (addr_end < args.len) {
        const count_str = std.mem.trimStart(u8, args[addr_end..], " ");
        if (count_str.len > 0) {
            count = parseDecimal(count_str) orelse 64;
        }
    }

    // Validate address range (identity-mapped kernel space)
    if (addr > 0xFFFFFFFF) {
        printErr("Address out of range\n", .{});
        return;
    }

    hexDump(@intCast(addr), count);
}

fn hexDump(addr: usize, count: u32) void {
    const ptr: [*]const u8 = @ptrFromInt(addr);
    var offset: u32 = 0;
    while (offset < count) {
        vga.fg = .DarkGray;
        vga.print("  {X:0>8}: ", .{addr + offset});
        // Hex bytes
        for (0..16) |i| {
            if (offset + @as(u32, @intCast(i)) < count) {
                vga.fg = .LightCyan;
                vga.print("{X:0>2} ", .{ptr[offset + @as(u32, @intCast(i))]});
            } else {
                vga.print("   ", .{});
            }
        }
        // ASCII
        vga.fg = .DarkGray;
        vga.print("|", .{});
        for (0..16) |i| {
            if (offset + @as(u32, @intCast(i)) < count) {
                const c = ptr[offset + @as(u32, @intCast(i))];
                vga.fg = .White;
                vga.putChar(if (c >= 0x20 and c < 0x7F) c else '.');
            }
        }
        vga.fg = .DarkGray;
        vga.print("|\n", .{});
        offset += 16;
    }
    vga.fg = .LightGray;
}

fn cmdPoke(args: []const u8) void {
    // Parse: <addr> <value>
    var addr_end: usize = 0;
    while (addr_end < args.len and args[addr_end] != ' ') : (addr_end += 1) {}

    const addr = parseHex(args[0..addr_end]) orelse {
        printErr("Usage: poke <hex_addr> <hex_value>\n", .{});
        return;
    };

    if (addr_end >= args.len) {
        printErr("Usage: poke <hex_addr> <hex_value>\n", .{});
        return;
    }

    const val_str = std.mem.trimStart(u8, args[addr_end..], " ");
    const value = parseHex(val_str) orelse {
        printErr("Invalid value\n", .{});
        return;
    };

    const ptr: *volatile u32 = @ptrFromInt(@as(usize, @intCast(addr)));
    ptr.* = @intCast(value & 0xFFFFFFFF);
    printOk("Wrote 0x{X:0>8} to 0x{X:0>8}\n", .{ @as(u32, @intCast(value & 0xFFFFFFFF)), @as(usize, @intCast(addr)) });
}

fn cmdStack(pid_str: ?[]const u8) void {
    if (pid_str) |s| {
        const pid = parseDecimal(s) orelse {
            printErr("Usage: stack [pid]\n", .{});
            return;
        };
        if (pid >= process.MAX_PROCS) {
            printErr("Invalid PID\n", .{});
            return;
        }
        const pcb = process.getPCB(pid);
        if (pcb.state == .unused) {
            printErr("Process {d} not running\n", .{pid});
            return;
        }

        printSection("Stack trace for PID ");
        vga.print("{d}\n", .{pid});

        // Read saved frame from kernel stack
        const frame: [*]const u64 = @ptrFromInt(pcb.kernel_esp);
        const saved_rip = frame[17];
        const saved_rbp: usize = @intCast(frame[10]);
        const saved_cs = frame[18];

        if (saved_cs & 3 != 0) {
            // User process — resolve with app symbols
            vga.fg = .LightCyan;
            vga.print("  RIP: ", .{});
            printSymAddr(saved_rip, false, pcb.sym_table);
            vga.fg = .LightGray;

            var rbp = saved_rbp;
            var depth: u32 = 0;
            while (rbp > 0x400000 and rbp < 0x600000 and depth < 10) : (depth += 1) {
                const f: [*]const usize = @ptrFromInt(rbp);
                const ret_addr: u64 = @intCast(f[1]);
                vga.print("  [{d}] ", .{depth});
                printSymAddr(ret_addr, false, pcb.sym_table);
                rbp = f[0];
            }
        } else {
            // Kernel context
            vga.fg = .LightCyan;
            vga.print("  RIP: ", .{});
            printSymAddr(saved_rip, true, null);
            vga.fg = .LightGray;
        }
    } else {
        // Kernel backtrace
        cmdBt();
    }
}

fn cmdRegs(pid_str: []const u8) void {
    const pid = parseDecimal(pid_str) orelse {
        printErr("Usage: regs <pid>\n", .{});
        return;
    };
    if (pid >= process.MAX_PROCS) {
        printErr("Invalid PID\n", .{});
        return;
    }
    const pcb = process.getPCB(pid);
    if (pcb.state == .unused) {
        printErr("Process {d} not running\n", .{pid});
        return;
    }

    const frame: [*]const u64 = @ptrFromInt(pcb.kernel_esp);

    printSection("Registers for PID ");
    vga.print("{d}\n", .{pid});
    vga.fg = .LightCyan;
    vga.print("  RAX={X:0>16} RBX={X:0>16}\n", .{ frame[14], frame[11] });
    vga.print("  RCX={X:0>16} RDX={X:0>16}\n", .{ frame[13], frame[12] });
    vga.print("  RSI={X:0>16} RDI={X:0>16}\n", .{ frame[9], frame[8] });
    vga.print("  RBP={X:0>16} RSP={X:0>16}\n", .{ frame[10], frame[20] });
    vga.print("  R8 ={X:0>16} R9 ={X:0>16}\n", .{ frame[7], frame[6] });
    vga.print("  R10={X:0>16} R11={X:0>16}\n", .{ frame[5], frame[4] });
    vga.print("  R12={X:0>16} R13={X:0>16}\n", .{ frame[3], frame[2] });
    vga.print("  R14={X:0>16} R15={X:0>16}\n", .{ frame[1], frame[0] });
    vga.fg = .DarkGray;
    vga.print("  RIP={X:0>16} CS={X:0>4} RFLAGS={X:0>16}\n", .{ frame[17], frame[18], frame[19] });
    vga.fg = .LightGray;
}

fn cmdDump(pid_str: []const u8) void {
    const pid = parseDecimal(pid_str) orelse {
        printErr("Usage: dump <pid>\n", .{});
        return;
    };
    if (pid >= process.MAX_PROCS) {
        printErr("Invalid PID\n", .{});
        return;
    }
    const pcb = process.getPCB(pid);

    printSection("Process ");
    vga.print("{d}\n", .{pid});

    const state_str: []const u8 = switch (pcb.state) {
        .unused => "unused",
        .loading => "loading",
        .ready => "ready",
        .running => "running",
        .sleeping => "sleeping",
        .zombie => "zombie",
    };

    vga.fg = .LightGray;
    vga.print("  State:      {s}\n", .{state_str});
    vga.print("  Name:       {s}\n", .{pcb.name[0..pcb.name_len]});
    vga.print("  KernelESP:  0x{X:0>16}\n", .{pcb.kernel_esp});
    vga.print("  KStackTop:  0x{X:0>16}\n", .{pcb.kernel_stack_top});
    vga.print("  PageDir:    0x{X:0>16}\n", .{pcb.page_dir_phys});
    vga.print("  UserBrk:    0x{X:0>8}\n", .{pcb.user_brk});
    vga.print("  Ticks:      {d}\n", .{pcb.ticks_used});
    if (pcb.gpu_has_ctx) {
        vga.print("  GPU Ctx:    {d}\n", .{pcb.gpu_ctx_id});
    }

    // Open file descriptors
    var open_fds: u32 = 0;
    for (pcb.fd_table, 0..) |fd, i| {
        if (fd.in_use) {
            if (open_fds == 0) {
                vga.fg = .Yellow;
                vga.print("  File Descriptors:\n", .{});
                vga.fg = .LightGray;
            }
            const fs_name: []const u8 = switch (fd.fs_type) {
                .console => "console",
                .fat32 => "fat32",
                .tarfs => "tarfs",
                .pipe => "pipe",
                .devfs => "devfs",
                .procfs => "procfs",
                .ext2 => "ext2",
                .tcp_sock => "tcp_sock",
                .tcp_listener => "tcp_listener",
            };
            vga.print("    fd={d} {s} offset={d}\n", .{ i, fs_name, fd.offset });
            open_fds += 1;
        }
    }

    // Symbol info
    if (pcb.sym_table) |st| {
        vga.fg = .LightGreen;
        vga.print("  Symbols:    {d} loaded\n", .{st.count});
        vga.fg = .LightGray;
    } else {
        vga.fg = .DarkGray;
        vga.print("  Symbols:    none\n", .{});
        vga.fg = .LightGray;
    }
}

fn cmdSymbols(arg: ?[]const u8) void {
    if (arg) |s| {
        // Try parsing as PID first
        if (parseDecimal(s)) |pid| {
            if (pid < process.MAX_PROCS) {
                const pcb = process.getPCB(pid);
                if (pcb.sym_table) |st| {
                    printSection("Symbols for PID ");
                    vga.print("{d}\n", .{pid});
                    symbols.listSymbols(st, null, true);
                    return;
                } else {
                    printErr("No symbols for PID {d}\n", .{pid});
                    return;
                }
            }
        }
        // Otherwise treat as filter string for kernel symbols
        printSection("Kernel Symbols (filter: ");
        vga.print("{s})\n", .{s});
        symbols.listKernelSymbols(s, true);
    } else {
        printSection("Kernel Symbols");
        symbols.listKernelSymbols(null, true);
    }
}

fn cmdHeap() void {
    heap.printDetailedStats(true);
}

fn cmdPerf() void {
    printSection("Performance counters");
    vga.print("(also dumped to serial)\n", .{});
    @import("debug/perf.zig").dumpAll();
}

fn cmdIpi() void {
    const vgpu = @import("driver/virtio_gpu.zig");
    const proc = @import("proc/process.zig");
    printSection("Wake-IPI delivery audit");
    vga.print("virtio-gpu MSI-X received per CPU:\n", .{});
    for (vgpu.virtio_gpu_irq_per_cpu, 0..) |c, i| {
        if (c == 0) continue;
        vga.print("  cpu{d}: {d}\n", .{ i, c });
    }
    vga.print("wake-IPIs sent from MSI-X handler: {d}\n", .{vgpu.virtio_gpu_wake_ipis_sent});
    vga.print("wake-only handler runs per CPU (no schedule, just irq):\n", .{});
    for (proc.wake_handler_runs, 0..) |c, i| {
        vga.print("  cpu{d}: {d}\n", .{ i, c });
    }
    vga.print("kick-vector handler runs per CPU (calls schedule):\n", .{});
    for (proc.kick_handler_runs, 0..) |c, i| {
        vga.print("  cpu{d}: {d}\n", .{ i, c });
    }
}

fn cmdBt() void {
    printSection("Kernel Backtrace");
    var rbp = asm volatile ("movq %%rbp, %[ret]"
        : [ret] "=r" (-> usize),
    );
    var depth: u32 = 0;
    while (rbp > 0x100000 and rbp < 0x4000000 and depth < 16) : (depth += 1) {
        const frame: [*]const usize = @ptrFromInt(rbp);
        const ret_addr: u64 = @intCast(frame[1]);
        vga.print("  [{d}] ", .{depth});
        printSymAddr(ret_addr, true, null);
        rbp = frame[0];
    }
    if (depth == 0) {
        vga.fg = .DarkGray;
        vga.print("  (no frames)\n", .{});
        vga.fg = .LightGray;
    }
}

fn printSymAddr(addr: u64, is_kernel: bool, app_table: ?*const symbols.SymTable) void {
    const result = if (is_kernel)
        symbols.resolveKernel(addr)
    else if (app_table) |t|
        symbols.resolveUser(t, addr)
    else
        null;

    if (result) |r| {
        vga.fg = .LightGreen;
        vga.print("{s}", .{r.name});
        vga.fg = .DarkGray;
        vga.print("+0x{X}", .{r.offset});
        vga.fg = .DarkGray;
        vga.print(" (0x{X:0>16})\n", .{addr});
    } else {
        vga.fg = .LightCyan;
        vga.print("0x{X:0>16}\n", .{addr});
    }
    vga.fg = .LightGray;
}
