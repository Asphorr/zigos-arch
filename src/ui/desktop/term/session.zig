// What a terminal window talks to: a user-space shell over two pipes and a
// tty, or the kernel's own command line (the Kernel Console), with its
// prompt, line editing and history. Keys go in here.

const std = @import("std");
const keyboard = @import("../../../driver.zig").keyboard;
const vga = @import("../../../driver.zig").vga;
const cli = @import("../../../cli.zig");
const debug = @import("../../../debug/debug.zig");
const elf_loader = @import("../../../proc/elf_loader.zig");
const tarfs = @import("../../../fs/tarfs.zig");
const process = @import("../../../proc/process.zig");
const wm = @import("../window.zig");
const Window = wm.Window;
const windows = &wm.windows;
const z_stack = &wm.z_stack;
const wake = @import("../wake.zig");
const layout = @import("../layout.zig");
const TITLEBAR_H = layout.TITLEBAR_H;
const KEY_UP = keyboard.KEY_UP;
const KEY_DOWN = keyboard.KEY_DOWN;

const emulator = @import("emulator.zig");
const cells = @import("cells.zig");
const notify = @import("../notify.zig");
const TERM_COLS = emulator.TERM_COLS;
const TERM_ROWS = emulator.TERM_ROWS;
const textIdx = emulator.textIdx;
const putCharOnWindow = emulator.putCharOnWindow;
const putStringOnWindow = emulator.putStringOnWindow;
const scrollWindow = emulator.scrollWindow;
const FONT_H = cells.FONT_H;
const showNotification = notify.showNotification;

/// Wire a Terminal window to a freshly-spawned user-space shell:
///   - kb_pipe: desktop → shell stdin   (shell holds read-side, desktop holds write-side)
///   - out_pipe: shell → desktop stdout (shell holds write-side, desktop holds read-side)
/// The desktop's main loop drains `out_pipe` non-blocking each frame and feeds
/// it into the window's text buffer via `putCharOnWindow`. Keyboard handler
/// pushes keystrokes into `kb_pipe`. No new kernel primitive is needed — pipes
/// already do everything a TTY did, and the back-channel into the desktop
/// (out_pipe drain step) is a desktop concern, not a kernel one.
pub fn spawnShellOnWindow(wi: u8) void {
    const pipe = @import("../../../proc/pipe.zig");
    const kb_pipe = pipe.alloc() orelse {
        showNotification("Pipe pool full");
        return;
    };
    const out_pipe = pipe.alloc() orelse {
        pipe.closeReader(kb_pipe);
        pipe.closeWriter(kb_pipe);
        showNotification("Pipe pool full");
        return;
    };

    const fresh = @import("../../../fs/vfs.zig").loadFileFresh("app.elf") orelse {
        putStringOnWindow(wi, "shell: app.elf not found\n");
        pipe.closeReader(kb_pipe);
        pipe.closeWriter(kb_pipe);
        pipe.closeReader(out_pipe);
        pipe.closeWriter(out_pipe);
        return;
    };
    const pid_or_null = elf_loader.loadAndStart(fresh.buf, fresh.size, fresh.pages, fresh.inode, null);
    const pid = pid_or_null orelse {
        putStringOnWindow(wi, "shell: load failed\n");
        pipe.closeReader(kb_pipe);
        pipe.closeWriter(kb_pipe);
        pipe.closeReader(out_pipe);
        pipe.closeWriter(out_pipe);
        return;
    };

    process.setName(@intCast(pid), "shell");
    const pcb = process.getPCB(pid);
    pcb.priority = .interactive;

    // The shell owns: kb_pipe read-side (fd 0), out_pipe write-side (one file
    // behind fd 1 and fd 2). The desktop owns: kb_pipe write-side, out_pipe
    // read-side. Refcounts are initialized to 1/1 by pipe.alloc(); each end
    // has exactly one owner, and the shell's go back when its files do.
    //
    // The two ends are the window's terminal (tty/tty.zig): a Linux
    // program the shell starts inherits them and finds a tty there.
    const file = @import("../../../fs/file.zig");
    const vfs_mod = @import("../../../fs/vfs.zig");
    const tty = @import("../../../tty/tty.zig");
    const term = tty.open(kb_pipe, out_pipe, @intCast(pid), @intCast(TERM_ROWS), @intCast(TERM_COLS));
    if (vfs_mod.newFile(.{ .kind = .pipe, .pipe_id = kb_pipe, .access = file.READ, .tty = term })) |f| file.assign(pcb, 0, f);
    if (vfs_mod.newFile(.{ .kind = .pipe, .pipe_id = out_pipe, .access = file.WRITE, .tty = term })) |f| {
        file.ref(f);
        file.assign(pcb, 1, f);
        file.assign(pcb, 2, f);
    }

    windows[wi].kb_pipe = kb_pipe;
    windows[wi].out_pipe = out_pipe;
    windows[wi].tty = term;
    windows[wi].shell_pid = @intCast(pid);
    // Event-driven compositor: out_pipe is drained by the desktop loop's
    // tryRead poll, not by a blocking read. Tell pipe.write to wake the
    // compositor when the shell writes to it; otherwise the desktop
    // sleeps through stdout bytes until something else (input, animation)
    // wakes it.
    pipe.setDesktopDrain(out_pipe);
}

var dbg_kbpipe_drop: u64 = 0;

var dbg_last_kbpipe_log: u64 = 0;

/// Returns true if full re-render needed (Enter/scroll/history), false for row-only.
pub fn handleKeyboard(w: *Window, ch: u8) bool {
    // Reset blink so the cursor stays visible right after a keystroke.
    if (w.term) |tt| tt.cursor_blink_anchor = process.tick_count;
    // Shell-attached terminal: keypresses go straight to the user-space shell
    // via its stdin pipe. The shell does its own echo, line editing, history,
    // prompt. PgUp/PgDn still scroll the kernel-side scrollback buffer (a
    // desktop affordance, not part of the shell's stdin contract).
    if (w.kb_pipe != 0xFF) {
        if (ch == keyboard.KEY_PGUP) {
            const content_h = w.height -| TITLEBAR_H;
            const max_rows: u16 = @intCast(content_h / FONT_H);
            const step = if (max_rows > 2) max_rows - 2 else 1;
            if (w.term) |tt| tt.scroll_view = @min(tt.scroll_view + step, tt.scroll_count);
            return true;
        } else if (ch == keyboard.KEY_PGDN) {
            const content_h = w.height -| TITLEBAR_H;
            const max_rows: u16 = @intCast(content_h / FONT_H);
            const step = if (max_rows > 2) max_rows - 2 else 1;
            if (w.term) |tt| tt.scroll_view -|= step;
            return true;
        }
        // Reset scroll on any other input — feels right for a shell.
        if (w.term) |tt| tt.scroll_view = 0;
        // Forward typeable bytes + line-editing keys to the shell's stdin.
        // The shell does its own readline (cursor moves, history, tab
        // completion), so arrows / Home / End / Delete must reach it.
        // Function keys (0x90+) stay desktop-only — they're global shortcuts.
        // PgUp / PgDn already returned above (kernel-side scrollback).
        const is_printable = ch >= 0x20 and ch <= 0x7E;
        const is_line_edit = ch == '\n' or ch == '\r' or ch == '\t' or ch == '\x08' or ch == 0x03 or ch == 0x1B;
        const is_nav = ch == keyboard.KEY_UP or ch == keyboard.KEY_DOWN or
            ch == keyboard.KEY_LEFT or ch == keyboard.KEY_RIGHT or
            ch == keyboard.KEY_HOME or ch == keyboard.KEY_END or
            ch == keyboard.KEY_DELETE;
        // A Linux program in the terminal gets every control key (^D, ^Z,
        // ^U...): its line discipline or the program itself knows them.
        const is_control = ch < 0x20 and @import("../../../tty/tty.zig").hasLinuxProgram(w.tty);
        if (!is_printable and !is_line_edit and !is_nav and !is_control) return false;
        const buf = [_]u8{ch};
        const written = @import("../../../proc/pipe.zig").tryWrite(w.kb_pipe, &buf);
        if (written == 0) {
            // pipe full / closed — char dropped before reaching shell
            dbg_kbpipe_drop +%= 1;
            if (process.tick_count -% dbg_last_kbpipe_log >= 100) {
                dbg_last_kbpipe_log = process.tick_count;
                debug.klog("[kbd-drop] kb_pipe write dropped pid={d} pipe_id={d} ch=0x{X} drops={d}\n", .{
                    w.shell_pid, w.kb_pipe, ch, dbg_kbpipe_drop,
                });
            }
        }
        return false;
    }

    const t = w.term orelse return false;
    if (ch == '\n') {
        t.scroll_view = 0;
        t.text_col = 0;
        t.text_row += 1;
        if (t.text_row >= TERM_ROWS) scrollWindow(w);
        if (t.cmd_len > 0) {
            const hi = t.history_count % 8;
            const safe_len = @min(t.cmd_len, 127);
            @memcpy(t.history[hi][0..safe_len], t.cmd_buf[0..safe_len]);
            t.history_len[hi] = safe_len;
            t.history_count +%= 1;
            t.history_idx = t.history_count;
            redirect_win = w;
            vga.redirect_fn = &desktopPutChar;
            cli.execute(t.cmd_buf[0..t.cmd_len]);
            vga.redirect_fn = null;
            redirect_win = null;
        }
        t.cmd_len = 0;
        termPrompt(w);
        return true;
    } else if (ch == '\x08') {
        if (t.cmd_len > 0) {
            t.cmd_len -= 1;
            if (t.text_col > 0) {
                t.text_col -= 1;
                if (textIdx(t.text_row, t.text_col)) |idx| t.text_buf[idx] = ' ';
            }
        }
        return false;
    } else if (ch == KEY_UP) {
        if (t.history_count > 0 and t.history_idx > 0) {
            t.history_idx -= 1;
            const hi = t.history_idx % 8;
            recallHistory(w, hi);
        }
        return true;
    } else if (ch == KEY_DOWN) {
        if (t.history_idx < t.history_count) {
            t.history_idx += 1;
            if (t.history_idx < t.history_count) {
                const hi = t.history_idx % 8;
                recallHistory(w, hi);
            } else {
                clearCurrentLine(w);
                t.cmd_len = 0;
            }
        }
        return true;
    } else if (ch == 0x09) {
        if (t.cmd_len >= 4 and std.mem.eql(u8, t.cmd_buf[0..4], "run ")) {
            const prefix = t.cmd_buf[4..t.cmd_len];
            var names: [8][32]u8 = undefined;
            var name_lens: [8]u8 = undefined;
            const count = tarfs.matchPrefix(prefix, &names, &name_lens);
            if (count == 1) {
                const name = names[0][0..name_lens[0]];
                if (name.len > prefix.len) {
                    const remaining = name[prefix.len..];
                    for (remaining) |c| {
                        if (t.cmd_len < 127 and t.text_col < TERM_COLS) {
                            t.cmd_buf[t.cmd_len] = c;
                            t.cmd_len += 1;
                            if (textIdx(t.text_row, t.text_col)) |ti| t.text_buf[ti] = c;
                            t.text_col += 1;
                        }
                    }
                }
            } else if (count > 1) {
                t.text_col = 0;
                t.text_row += 1;
                if (t.text_row >= TERM_ROWS) scrollWindow(w);
                var mi: u8 = 0;
                while (mi < count) : (mi += 1) {
                    for (names[mi][0..name_lens[mi]]) |c| {
                        if (t.text_col < TERM_COLS) {
                            if (textIdx(t.text_row, t.text_col)) |ti| t.text_buf[ti] = c;
                            t.text_col += 1;
                        }
                    }
                    if (t.text_col + 1 < TERM_COLS) {
                        if (textIdx(t.text_row, t.text_col)) |ti| t.text_buf[ti] = ' ';
                        t.text_col += 1;
                    }
                }
                t.text_col = 0;
                t.text_row += 1;
                if (t.text_row >= TERM_ROWS) scrollWindow(w);
                termPrompt(w);
                for (t.cmd_buf[0..t.cmd_len]) |c| {
                    if (t.text_col < TERM_COLS) {
                        if (textIdx(t.text_row, t.text_col)) |ti| t.text_buf[ti] = c;
                        t.text_col += 1;
                    }
                }
            }
        }
        return true;
    } else if (ch == keyboard.KEY_PGUP) {
        const content_h = w.height -| TITLEBAR_H;
        const max_rows: u16 = @intCast(content_h / FONT_H);
        const step = if (max_rows > 2) max_rows - 2 else 1;
        t.scroll_view = @min(t.scroll_view + step, t.scroll_count);
        return true;
    } else if (ch == keyboard.KEY_PGDN) {
        const content_h = w.height -| TITLEBAR_H;
        const max_rows: u16 = @intCast(content_h / FONT_H);
        const step = if (max_rows > 2) max_rows - 2 else 1;
        t.scroll_view -|= step;
        return true;
    } else if (ch >= 0x20 and ch < 0x7F) {
        t.scroll_view = 0;
        if (t.cmd_len < 127 and t.text_col < TERM_COLS) {
            t.cmd_buf[t.cmd_len] = ch;
            t.cmd_len += 1;
            if (textIdx(t.text_row, t.text_col)) |idx| t.text_buf[idx] = ch;
            t.text_col += 1;
        }
        return false;
    }
    return false;
}

fn recallHistory(w: *Window, hi: u8) void {
    const t = w.term orelse return;
    clearCurrentLine(w);
    const len = t.history_len[hi];
    t.cmd_len = len;
    @memcpy(t.cmd_buf[0..len], t.history[hi][0..len]);
    const prompt_len: u16 = 12;
    var col: u16 = 0;
    while (col < len) : (col += 1) {
        if (textIdx(t.text_row, prompt_len + col)) |idx| t.text_buf[idx] = t.cmd_buf[col];
    }
    t.text_col = prompt_len + @as(u16, len);
}

fn clearCurrentLine(w: *Window) void {
    const t = w.term orelse return;
    const prompt_len: u16 = 12;
    var col: u16 = prompt_len;
    while (col < TERM_COLS) : (col += 1) {
        if (textIdx(t.text_row, col)) |idx| t.text_buf[idx] = ' ';
    }
    t.text_col = prompt_len;
    t.cmd_len = 0;
}

// --- Redirect ---
pub var redirect_win: ?*Window = null;

fn desktopPutChar(c: u8) void {
    const w = redirect_win orelse return;
    putCharOnWindow(w, c);
}

pub fn termPrompt(w: *Window) void {
    const t = w.term orelse return;
    const prompt_str = "root@zigos> ";
    for (prompt_str) |ch| {
        if (t.text_col >= TERM_COLS) {
            t.text_col = 0;
            t.text_row += 1;
            if (t.text_row >= TERM_ROWS) scrollWindow(w);
        }
        if (textIdx(t.text_row, t.text_col)) |idx| t.text_buf[idx] = ch;
        t.text_col += 1;
    }
}

/// How long one loop iteration reads a terminal's output pipe before it
/// goes on to draw (see the drain step); the byte count is the same bound
/// for a boot with no calibrated clock.
pub const DRAIN_SLICE_MS: u64 = 4;
pub const DRAIN_SLICE_BYTES: usize = 16 * 1024;

/// Drain stdout pipes for every shell-attached terminal window. The
/// shell process writes via libc.print → fwrite(1) → pipe.write into
/// out_pipe; we pull bytes back here non-blocking and feed them into
/// the window's text buffer. This is the desktop's side of the
/// "TTY-as-two-pipes" architecture: no kernel TTY primitive, just a
/// pair of generic byte streams plus this drain step.
///
/// Drained bytes can change any rows (`ls`'s lines, a scroll, a
/// program addressing the cursor), so the window is only marked here;
/// term_view.repaintStale repaints whichever rows differ from what they show.
///
/// A program that prints without pause (`yes`, a long build log)
/// refills the pipe as fast as it is drained here, so each window
/// gets a time slice per pass: the frame is drawn and the keyboard
/// read in between, and the writer waits on the full pipe.
pub fn drainOutput() void {
    const pipe = @import("../../../proc/pipe.zig");
    const rdtsc = @import("../../../debug/perf.zig").rdtsc;
    const slice_cyc = @import("../../../irq/apic.zig").tscPerQuantumSane() * DRAIN_SLICE_MS / 10;
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
