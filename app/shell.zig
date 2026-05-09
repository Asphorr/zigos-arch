// ZigOS terminal shell. Reads commands from console, runs them as Ring 3
// children via libc.execAs.
//
// Single command:    "ls"               -> execAs("ls"), waitpid
// Single + args:     "cat foo.txt"      -> execAs("cat.elf foo.txt")
// Pipeline:          "ls | wc"          -> N forks, stdout→stdin chain
// Multi-pipe:        "yes | head | wc"  -> up to 4 commands per line
// Redirection:       "ls > out.txt"     -> stdout to file (truncate-create)
//                    "cat < foo.txt"    -> stdin from file
//                    "echo hi >> log"   -> stdout to file (append; uses O_APPEND)
//
// Built-ins:         help, clear, cd, pwd, q/exit
//
// Line editing:
//   left/right       move cursor within the current line
//   home/end         jump to start/end
//   delete           remove char at cursor
//   backspace        remove char before cursor
//   up/down          scroll through command history
//   tab              complete command (col 0) or filename (after a space)
//
// No quoting, no globbing yet — `echo "hi >"` will treat `>` as a redirect.
// Built-ins ignore redirects (running them in the parent shell makes that
// awkward; revisit if it becomes a real annoyance).

const libc = @import("libc");

const MAX_LINE: usize = 128;
const HISTORY_SIZE: usize = 32;
const MAX_PIPELINE: usize = 4;
const MAX_PATH: usize = 96;

/// Parsed form of one segment in a pipeline. `cmd` is what we'll exec
/// (with redirect tokens stripped); `in_path`/`out_path` are non-null when
/// the user wrote `<file` / `>file` / `>>file`.
const Command = struct {
    cmd: []const u8,
    in_path: ?[]const u8,
    out_path: ?[]const u8,
    out_append: bool,
};

// Working buffers for parsePipeline. Static rather than stack-locals because
// Command stores slices into them and the lifetime needs to survive the
// parser returning into runPipeline. 4 cmds × 128 + 8 paths × 96 ≈ 1.3 KB.
var pipeline_cmd_bufs: [MAX_PIPELINE][MAX_LINE]u8 = undefined;
var pipeline_in_paths: [MAX_PIPELINE][MAX_PATH]u8 = undefined;
var pipeline_out_paths: [MAX_PIPELINE][MAX_PATH]u8 = undefined;

// Keyboard ring pushes these for the kernel-level "special" keys; see
// src/keyboard.zig:142. Mirrored here so the shell doesn't need a kernel
// import. All <= 0x9F so they can't collide with printable ASCII (0x20..0x7E).
const KEY_UP: u8 = 0x80;
const KEY_DOWN: u8 = 0x81;
const KEY_LEFT: u8 = 0x82;
const KEY_RIGHT: u8 = 0x83;
const KEY_HOME: u8 = 0x84;
const KEY_END: u8 = 0x85;
const KEY_DELETE: u8 = 0x88;

// PIDs of the children currently running on the shell's behalf — read by the
// SIGINT handler so it can forward to them, mimicking a real terminal's
// foreground-process-group SIGINT delivery. 0 = none.
var fg_child_a: u32 = 0;
var fg_child_b: u32 = 0;

// Set by the SIGINT handler when ^C arrives. Main loop drains this between
// reads: discards the partial line, prints "^C\n", reprints the prompt.
// volatile-ish — the handler runs at an unpredictable point inside readChar
// or sleep, so the read in the main loop must observe writes made by the
// handler. Zig has no `volatile` for plain globals; access through a
// volatile-pointer in the handler+reader is the closest equivalent and is
// sufficient here because we're single-threaded (one app, no SMP races on
// process-local data).
var sigint_pending: bool = false;

// Command history ring. `hist_head` is the next slot to write; `hist_count`
// caps at HISTORY_SIZE once we've wrapped. `hist_view` tracks how far back
// the user has navigated (0 = most recent, null = editing the current line).
var hist_lines: [HISTORY_SIZE][MAX_LINE]u8 = undefined;
var hist_lens: [HISTORY_SIZE]usize = [_]usize{0} ** HISTORY_SIZE;
var hist_head: usize = 0;
var hist_count: usize = 0;
var hist_view: ?usize = null;

// Snapshot of the line the user was editing when they first pressed Up.
// Restored by the matching Down past hist_view==0.
var saved_line: [MAX_LINE]u8 = undefined;
var saved_len: usize = 0;

export fn handleSigint(signo: u32, info: *anyopaque, uc: *anyopaque) void {
    _ = signo;
    _ = info;
    _ = uc;
    // Forward to the foreground child(ren) so a `cmd | wc` pipeline dies as
    // a unit. SIGKILL would be safer (no chance the child traps SIGINT and
    // ignores), but SIGINT lets a child app (e.g. a hypothetical editor) run
    // its own cleanup. Bare apps without a handler still get default-action
    // termination, which is what we want.
    if (fg_child_a != 0) _ = libc.kill(fg_child_a, libc.SIGINT);
    if (fg_child_b != 0) _ = libc.kill(fg_child_b, libc.SIGINT);
    const sip: *volatile bool = &sigint_pending;
    sip.* = true;
}

fn drainSigint(len: *usize, pos: *usize) void {
    const sip: *volatile bool = &sigint_pending;
    if (!sip.*) return;
    sip.* = false;
    libc.print("^C\n");
    len.* = 0;
    pos.* = 0;
    hist_view = null;
    libc.print("\x1b[32m> \x1b[0m");
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    libc.clear();
    libc.print("\x1b[1;36m=== ZigOS Shell ===\x1b[0m\n");
    libc.print("Type \x1b[1mhelp\x1b[0m for the command list, \x1b[1mq\x1b[0m to quit.\n\n");

    // Install the SIGINT handler. SA_RESTART is intentionally NOT set —
    // we want waitpid in run* to bail with EINTR so the shell can observe
    // the interrupt + reprint the prompt. Without SA_RESTART, my kernel's
    // signal-on-syscall-return path returns the dispatcher's value (here
    // 0xFFFFFFFF for waitpid's interrupted case) to userland after the
    // handler runs — exactly the EINTR semantics we want.
    var act: libc.SigAction = .{ .handler = @intFromPtr(&handleSigint) };
    _ = libc.sigaction(libc.SIGINT, &act, null);

    libc.print("\x1b[32m> \x1b[0m");

    var buf: [MAX_LINE]u8 = undefined;
    var len: usize = 0;
    var pos: usize = 0;

    while (true) {
        const c = libc.readChar();
        drainSigint(&len, &pos);
        if (c == 0) {
            libc.sleep(10);
            drainSigint(&len, &pos);
            continue;
        }

        switch (c) {
            '\n' => {
                libc.printChar('\n');
                if (len == 0) {
                    libc.print("\x1b[32m> \x1b[0m");
                    pos = 0;
                    hist_view = null;
                    continue;
                }
                if ((len == 1 and buf[0] == 'q') or
                    (len == 4 and equals(buf[0..4], "exit")))
                {
                    libc.print("Goodbye!\n");
                    break;
                }
                historyPush(buf[0..len]);
                runLine(buf[0..len]);
                // run* may have been interrupted; clear any latched flag before
                // printing the next prompt (otherwise the next readChar would
                // print "^C\n>" immediately on a clean prompt).
                const sip: *volatile bool = &sigint_pending;
                sip.* = false;
                libc.print("\x1b[32m> \x1b[0m");
                len = 0;
                pos = 0;
                hist_view = null;
            },
            '\x08' => {
                if (pos > 0) {
                    for (pos..len) |i| buf[i - 1] = buf[i];
                    pos -= 1;
                    len -= 1;
                    redrawInputLine(buf[0..len], pos);
                }
            },
            '\t' => tryComplete(&buf, &len, &pos),
            KEY_LEFT => {
                if (pos > 0) {
                    pos -= 1;
                    libc.print("\x1b[D");
                }
            },
            KEY_RIGHT => {
                if (pos < len) {
                    pos += 1;
                    libc.print("\x1b[C");
                }
            },
            KEY_HOME => {
                if (pos > 0) {
                    pos = 0;
                    redrawInputLine(buf[0..len], pos);
                }
            },
            KEY_END => {
                if (pos < len) {
                    pos = len;
                    redrawInputLine(buf[0..len], pos);
                }
            },
            KEY_DELETE => {
                if (pos < len) {
                    var i: usize = pos;
                    while (i + 1 < len) : (i += 1) buf[i] = buf[i + 1];
                    len -= 1;
                    redrawInputLine(buf[0..len], pos);
                }
            },
            KEY_UP => historyUp(&buf, &len, &pos),
            KEY_DOWN => historyDown(&buf, &len, &pos),
            else => {
                // Printable ASCII only — drop everything else (function keys,
                // unmapped scancodes) so they can't poison the buffer.
                if (c >= 0x20 and c <= 0x7E and len < buf.len) {
                    // Insert at cursor: shift suffix right by one.
                    var i: usize = len;
                    while (i > pos) : (i -= 1) buf[i] = buf[i - 1];
                    buf[pos] = c;
                    pos += 1;
                    len += 1;
                    if (pos == len) {
                        // Fast path: cursor at end, just echo the char.
                        libc.printChar(c);
                    } else {
                        redrawInputLine(buf[0..len], pos);
                    }
                }
            },
        }
    }

    libc.exit();
}

fn equals(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

/// Trim ASCII spaces from both ends of `s`.
fn trim(s: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = s.len;
    while (start < end and s[start] == ' ') start += 1;
    while (end > start and s[end - 1] == ' ') end -= 1;
    return s[start..end];
}

/// Format a non-negative integer as decimal into `out`. Returns the slice
/// covering the formatted digits. Used to build `\x1b[<n>D` move sequences.
fn formatU32(out: []u8, n: u32) []const u8 {
    if (n == 0) {
        out[0] = '0';
        return out[0..1];
    }
    var tmp: [10]u8 = undefined;
    var i: usize = 0;
    var v = n;
    while (v > 0) : (i += 1) {
        tmp[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
    for (0..i) |j| out[j] = tmp[i - 1 - j];
    return out[0..i];
}

/// Repaint the current input line, then put the cursor at `pos`. Strategy:
/// `\r` returns to column 0, `\x1b[K` clears the line right of cursor (so a
/// shrinking line doesn't leave trailing garbage), reprint prompt + buf, then
/// step the cursor back from end-of-line by `len - pos`. This relies on the
/// line not having wrapped — TERM_COLS is 80 and prompts are 2 chars, so
/// up to 78 typed chars fit on one row, more than enough for any realistic
/// command.
fn redrawInputLine(line: []const u8, pos: usize) void {
    libc.printChar('\r');
    libc.print("\x1b[K");
    libc.print("\x1b[32m> \x1b[0m");
    libc.print(line);
    if (pos < line.len) {
        const back: u32 = @intCast(line.len - pos);
        libc.print("\x1b[");
        var nbuf: [10]u8 = undefined;
        libc.print(formatU32(&nbuf, back));
        libc.print("D");
    }
}

/// Push `line` onto the history ring. Skips empty lines and consecutive
/// duplicates so up-arrow doesn't have to scroll past `ls ls ls ls`.
fn historyPush(line: []const u8) void {
    if (line.len == 0) return;
    if (hist_count > 0) {
        const prev = (hist_head + HISTORY_SIZE - 1) % HISTORY_SIZE;
        if (hist_lens[prev] == line.len and equals(hist_lines[prev][0..line.len], line)) return;
    }
    @memcpy(hist_lines[hist_head][0..line.len], line);
    hist_lens[hist_head] = line.len;
    hist_head = (hist_head + 1) % HISTORY_SIZE;
    if (hist_count < HISTORY_SIZE) hist_count += 1;
}

/// Look up the line `view` steps back from most recent (0 = most recent).
/// Returns null if `view` is past the end of recorded history.
fn historyAt(view: usize) ?[]const u8 {
    if (view >= hist_count) return null;
    const idx = (hist_head + HISTORY_SIZE - 1 - view) % HISTORY_SIZE;
    return hist_lines[idx][0..hist_lens[idx]];
}

/// Up arrow: load the next-older entry into `buf`. Saves the user's current
/// in-progress line on the first transition into history so a matching Down
/// can restore it.
fn historyUp(buf: *[MAX_LINE]u8, len: *usize, pos: *usize) void {
    if (hist_view == null) {
        if (hist_count == 0) return;
        @memcpy(saved_line[0..len.*], buf[0..len.*]);
        saved_len = len.*;
        hist_view = 0;
    } else {
        if (hist_view.? + 1 >= hist_count) return;
        hist_view = hist_view.? + 1;
    }
    const h = historyAt(hist_view.?) orelse return;
    @memcpy(buf[0..h.len], h);
    len.* = h.len;
    pos.* = h.len;
    redrawInputLine(buf[0..len.*], pos.*);
}

/// Down arrow: walk back toward the most recent entry. Past the most recent
/// (hist_view == 0), restore the line the user was typing before they first
/// pressed Up.
fn historyDown(buf: *[MAX_LINE]u8, len: *usize, pos: *usize) void {
    if (hist_view == null) return;
    if (hist_view.? == 0) {
        hist_view = null;
        @memcpy(buf[0..saved_len], saved_line[0..saved_len]);
        len.* = saved_len;
        pos.* = saved_len;
        redrawInputLine(buf[0..len.*], pos.*);
        return;
    }
    hist_view = hist_view.? - 1;
    const h = historyAt(hist_view.?) orelse return;
    @memcpy(buf[0..h.len], h);
    len.* = h.len;
    pos.* = h.len;
    redrawInputLine(buf[0..len.*], pos.*);
}

/// Tab completion. Two contexts:
///   - command position (start of line, or just after `|`): match against
///     built-ins + .elf files in cwd, displaying the .elf without the suffix
///     since the shell auto-appends it on exec.
///   - file-arg position (anywhere else): match against any cwd entry as-is.
/// Single match expands inline; multiple matches print as a list and reprompt;
/// zero matches do nothing.
fn tryComplete(buf: *[MAX_LINE]u8, len: *usize, pos: *usize) void {
    // Find the start of the token under the cursor: scan back over non-space,
    // non-`|` chars.
    var token_start: usize = pos.*;
    while (token_start > 0 and buf[token_start - 1] != ' ' and buf[token_start - 1] != '|') {
        token_start -= 1;
    }
    const token = buf[token_start..pos.*];

    // Are we completing a command name? Yes iff everything before the token
    // is whitespace, optionally with a single `|` somewhere in it (for the
    // right-hand side of a pipeline).
    var is_command_pos = true;
    var i = token_start;
    while (i > 0) {
        i -= 1;
        if (buf[i] == ' ') continue;
        if (buf[i] == '|') break;
        is_command_pos = false;
        break;
    }

    var matches: [16][32]u8 = undefined;
    var match_lens: [16]u8 = undefined;
    var match_count: usize = 0;

    const builtins = [_][]const u8{ "help", "clear", "cd", "pwd", "exit", "q" };
    if (is_command_pos) {
        for (builtins) |b| {
            if (b.len < token.len) continue;
            if (!equals(b[0..token.len], token)) continue;
            if (match_count >= matches.len) break;
            @memcpy(matches[match_count][0..b.len], b);
            match_lens[match_count] = @intCast(b.len);
            match_count += 1;
        }
    }

    var entries: [64]libc.FileEntry = undefined;
    const n = libc.listdir(&entries);
    for (0..n) |j| {
        const e = entries[j];
        if (e.name_len == 0 or e.name_len > 32) continue;
        const ename = e.name[0..e.name_len];
        var disp_len: usize = e.name_len;
        if (is_command_pos) {
            // Only .elf binaries, with the extension stripped for display.
            if (e.name_len < 4) continue;
            if (!equals(e.name[e.name_len - 4 .. e.name_len], ".elf")) continue;
            disp_len = e.name_len - 4;
        }
        if (disp_len < token.len) continue;
        if (!equals(ename[0..token.len], token)) continue;
        if (match_count >= matches.len) break;
        @memcpy(matches[match_count][0..disp_len], ename[0..disp_len]);
        match_lens[match_count] = @intCast(disp_len);
        match_count += 1;
    }

    if (match_count == 0) return;

    if (match_count == 1) {
        const m = matches[0][0..match_lens[0]];
        const suffix_len = len.* - pos.*;
        const new_len = token_start + m.len + suffix_len;
        if (new_len > MAX_LINE) return;
        // Shift the post-cursor suffix to the new position. Going back-to-front
        // is safe whether m is longer or shorter than the token (the source
        // and destination ranges overlap in only one of those cases, and that
        // case is shifting right — handled correctly by the descending loop).
        if (m.len >= token.len) {
            var k: usize = suffix_len;
            while (k > 0) {
                k -= 1;
                buf[token_start + m.len + k] = buf[pos.* + k];
            }
        } else {
            for (0..suffix_len) |k| {
                buf[token_start + m.len + k] = buf[pos.* + k];
            }
        }
        @memcpy(buf[token_start .. token_start + m.len], m);
        len.* = new_len;
        pos.* = token_start + m.len;
        redrawInputLine(buf[0..len.*], pos.*);
        return;
    }

    // Multiple candidates — print them on a fresh line as a hint, then
    // reprompt with the unchanged input (mimicking bash's double-tab list).
    libc.printChar('\n');
    for (0..match_count) |k| {
        if (k > 0) libc.printChar(' ');
        libc.print(matches[k][0..match_lens[k]]);
    }
    libc.printChar('\n');
    redrawInputLine(buf[0..len.*], pos.*);
}

// --- Help registry ---
//
// Tree-shaped: bare `help` lists the top-level categories with one-line
// summaries; `help <category>` expands that category's entries. Adding
// a new command means appending one line to `help_entries` — never
// touching the printers.
//
// Categories are kept short (4-6) so the bare-help screen always fits
// without scrolling. If we cross 8 categories that's the trigger to
// re-bucket rather than silently let it grow into an unscannable wall.

const HelpCategory = struct {
    name: []const u8,
    summary: []const u8,
};

const HelpEntry = struct {
    category: []const u8,
    name: []const u8,
    summary: []const u8,
};

const help_categories = [_]HelpCategory{
    .{ .name = "builtins", .summary = "shell built-ins (help, clear, cd, pwd, exit)" },
    .{ .name = "tools",    .summary = "command-line utilities (ls, cat, echo, wc, grep, head)" },
    .{ .name = "syntax",   .summary = "pipelines and redirection" },
    .{ .name = "keys",     .summary = "input editing keys" },
};

const help_entries = [_]HelpEntry{
    .{ .category = "builtins", .name = "help [cat]",        .summary = "list categories, or expand one" },
    .{ .category = "builtins", .name = "clear",             .summary = "clear the screen" },
    .{ .category = "builtins", .name = "cd [path]",         .summary = "change directory (no arg = /)" },
    .{ .category = "builtins", .name = "pwd",               .summary = "print working directory" },
    .{ .category = "builtins", .name = "q, exit",           .summary = "leave the shell" },

    .{ .category = "tools",    .name = "ls",                .summary = "list files in the current directory" },
    .{ .category = "tools",    .name = "cat [file]",        .summary = "print a file (or stdin if no arg)" },
    .{ .category = "tools",    .name = "echo <text>",       .summary = "print text + newline" },
    .{ .category = "tools",    .name = "wc",                .summary = "count bytes/lines on stdin" },
    .{ .category = "tools",    .name = "grep <pattern>",    .summary = "filter stdin lines containing pattern" },
    .{ .category = "tools",    .name = "head [N]",          .summary = "first N lines from stdin (default 10)" },
    .{ .category = "tools",    .name = "pipetest",          .summary = "pipe round-trip self-test" },

    .{ .category = "syntax",   .name = "cmd1 | cmd2 | cmd3", .summary = "pipeline (up to 4 stages)" },
    .{ .category = "syntax",   .name = "cmd > file",         .summary = "redirect stdout to file (truncate)" },
    .{ .category = "syntax",   .name = "cmd >> file",        .summary = "redirect stdout to file (append)" },
    .{ .category = "syntax",   .name = "cmd < file",         .summary = "read stdin from file" },

    .{ .category = "keys",     .name = "left/right",         .summary = "move cursor by character" },
    .{ .category = "keys",     .name = "home/end",           .summary = "jump to start/end of line" },
    .{ .category = "keys",     .name = "del/backspace",      .summary = "delete character" },
    .{ .category = "keys",     .name = "up/down",            .summary = "navigate command history" },
    .{ .category = "keys",     .name = "tab",                .summary = "tab completion" },
};

/// Width of the left column (command name) when expanding a category.
/// Sized so the longest registered name still leaves a clean gap before
/// the summary. Recompute here if we add any name longer than ~22 chars.
const HELP_COL_W: usize = 22;

/// Bare `help`: print categories + a usage hint at the bottom. ANSI
/// bold for category names, dim for their summaries; matches what the
/// expanded view does for command names so the eye reads the two
/// screens consistently.
fn printHelpRoot() void {
    libc.print("\x1b[1mZigOS shell help\x1b[0m\n");
    libc.print("  Use \x1b[1mhelp <category>\x1b[0m to expand a section.\n\n");
    libc.print("\x1b[1mCategories\x1b[0m\n");
    for (help_categories) |cat| {
        libc.print("  \x1b[1m");
        libc.print(cat.name);
        libc.print("\x1b[0m");
        // Pad to column width
        var i: usize = cat.name.len;
        while (i < 12) : (i += 1) libc.printChar(' ');
        libc.print("\x1b[2m");
        libc.print(cat.summary);
        libc.print("\x1b[0m\n");
    }
}

/// `help <category>`: expand one category. Falls back to the root view
/// with a "no such category" hint if the name doesn't match.
fn printHelpCategory(name: []const u8) void {
    // Match category by name.
    var found: ?HelpCategory = null;
    for (help_categories) |cat| {
        if (equals(name, cat.name)) {
            found = cat;
            break;
        }
    }
    if (found == null) {
        libc.print("\x1b[31mhelp: no such category '");
        libc.print(name);
        libc.print("'\x1b[0m\n\n");
        printHelpRoot();
        return;
    }
    libc.print("\x1b[1m");
    libc.print(found.?.name);
    libc.print("\x1b[0m  \x1b[2m");
    libc.print(found.?.summary);
    libc.print("\x1b[0m\n");
    for (help_entries) |e| {
        if (!equals(e.category, name)) continue;
        libc.print("  \x1b[1m");
        libc.print(e.name);
        libc.print("\x1b[0m");
        var i: usize = e.name.len;
        while (i < HELP_COL_W) : (i += 1) libc.printChar(' ');
        libc.print("\x1b[2m");
        libc.print(e.summary);
        libc.print("\x1b[0m\n");
    }
}

/// Top-level `help` dispatcher. `arg` is the trimmed argument (empty for
/// bare `help`).
fn runHelp(arg: []const u8) void {
    if (arg.len == 0) {
        printHelpRoot();
    } else {
        printHelpCategory(arg);
    }
}

/// `cd [path]` built-in. With no argument, jumps to the default home (`/`,
/// the ext2 root); otherwise calls libc.chdir which the kernel validates
/// against the mount table. Errors print in red and the cwd is left
/// unchanged.
fn runCd(arg: []const u8) void {
    const target = if (arg.len == 0) "/" else arg;
    if (!libc.chdir(target)) {
        libc.print("\x1b[31mshell: cd: ");
        libc.print(target);
        libc.print("\x1b[0m\n");
    }
}

/// `pwd` built-in. Prints the canonical absolute cwd as the kernel stores it
/// (always ends with '/'). Bails out red if getCwd fails — should never happen
/// with a 256-byte buffer since pcb.cwd is also 256 bytes.
fn runPwd() void {
    var buf: [256]u8 = undefined;
    if (libc.getCwd(&buf)) |cwd| {
        libc.print(cwd);
        libc.printChar('\n');
    } else {
        libc.print("\x1b[31mshell: pwd failed\x1b[0m\n");
    }
}

/// Parse + dispatch one command line. Empty input is a no-op (caller already
/// re-prompts). Errors are reported inline; the shell does not exit on a
/// failed command.
fn runLine(line: []const u8) void {
    const trimmed = trim(line);
    if (trimmed.len == 0) return;

    // Shell built-ins (no .elf lookup, no waitpid). Redirects on built-ins
    // would need a sub-shell or temporary fd dup in the parent — neither is
    // worth it for what we have today.
    if (equals(trimmed, "help")) {
        runHelp("");
        return;
    }
    if (trimmed.len > 5 and trimmed[0] == 'h' and trimmed[1] == 'e' and trimmed[2] == 'l' and trimmed[3] == 'p' and trimmed[4] == ' ') {
        runHelp(trim(trimmed[5..]));
        return;
    }
    if (equals(trimmed, "clear")) {
        libc.print("\x1b[2J\x1b[H");
        return;
    }
    if (equals(trimmed, "pwd")) {
        runPwd();
        return;
    }
    if (equals(trimmed, "cd")) {
        runCd("");
        return;
    }
    if (trimmed.len > 3 and trimmed[0] == 'c' and trimmed[1] == 'd' and trimmed[2] == ' ') {
        runCd(trim(trimmed[3..]));
        return;
    }

    var commands: [MAX_PIPELINE]Command = undefined;
    var n: usize = 0;
    if (!parsePipeline(trimmed, &commands, &n)) return;
    runPipeline(commands[0..n]);
}

/// Split `line` on `|`, then for each segment extract `<` / `>` / `>>`
/// redirect tokens into the matching Command fields. On any parse error
/// prints the diagnostic in red and returns false; `n_out` is left untouched.
fn parsePipeline(line: []const u8, cmds: *[MAX_PIPELINE]Command, n_out: *usize) bool {
    var n: usize = 0;
    var seg_start: usize = 0;
    var i: usize = 0;
    while (i <= line.len) : (i += 1) {
        const at_end = i == line.len;
        const at_pipe = !at_end and line[i] == '|';
        if (!at_end and !at_pipe) continue;
        if (n >= MAX_PIPELINE) {
            libc.print("\x1b[31mshell: pipeline too long (max ");
            var nbuf: [4]u8 = undefined;
            libc.print(formatU32(&nbuf, MAX_PIPELINE));
            libc.print(")\x1b[0m\n");
            return false;
        }
        const seg = trim(line[seg_start..i]);
        if (seg.len == 0) {
            libc.print("\x1b[31mshell: empty command in pipeline\x1b[0m\n");
            return false;
        }
        if (!parseRedirects(seg, &cmds[n], n)) return false;
        n += 1;
        seg_start = i + 1;
        if (at_end) break;
    }
    n_out.* = n;
    return true;
}

/// Walk `seg` and split it into a clean command string + up to one `<`
/// redirect + up to one `>` / `>>` redirect. Tokens may sit flush against
/// the surrounding chars (`echo>foo`) or with spaces (`echo > foo`).
/// The cleaned cmd is written to `pipeline_cmd_bufs[idx]`; redirect targets
/// are copied into `pipeline_in_paths[idx]` / `pipeline_out_paths[idx]` so
/// the slices outlive the parser.
fn parseRedirects(seg: []const u8, cmd: *Command, idx: usize) bool {
    var cmd_buf = &pipeline_cmd_bufs[idx];
    var cmd_len: usize = 0;
    var in_path: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var out_append: bool = false;

    var i: usize = 0;
    while (i < seg.len) {
        const c = seg[i];
        if (c == '<' or c == '>') {
            const is_out = c == '>';
            i += 1;
            var append = false;
            if (is_out and i < seg.len and seg[i] == '>') {
                append = true;
                i += 1;
            }
            while (i < seg.len and seg[i] == ' ') i += 1;
            const start = i;
            while (i < seg.len and seg[i] != ' ' and seg[i] != '<' and seg[i] != '>') i += 1;
            const path = seg[start..i];
            if (path.len == 0) {
                libc.print("\x1b[31mshell: missing filename after ");
                libc.printChar(c);
                if (append) libc.printChar('>');
                libc.print("\x1b[0m\n");
                return false;
            }
            if (path.len > MAX_PATH - 1) {
                libc.print("\x1b[31mshell: redirect filename too long\x1b[0m\n");
                return false;
            }
            if (is_out) {
                if (out_path != null) {
                    libc.print("\x1b[31mshell: duplicate output redirect\x1b[0m\n");
                    return false;
                }
                @memcpy(pipeline_out_paths[idx][0..path.len], path);
                out_path = pipeline_out_paths[idx][0..path.len];
                out_append = append;
            } else {
                if (in_path != null) {
                    libc.print("\x1b[31mshell: duplicate input redirect\x1b[0m\n");
                    return false;
                }
                @memcpy(pipeline_in_paths[idx][0..path.len], path);
                in_path = pipeline_in_paths[idx][0..path.len];
            }
        } else {
            cmd_buf[cmd_len] = c;
            cmd_len += 1;
            i += 1;
        }
    }

    cmd.* = .{
        .cmd = trim(cmd_buf[0..cmd_len]),
        .in_path = in_path,
        .out_path = out_path,
        .out_append = out_append,
    };
    if (cmd.cmd.len == 0) {
        libc.print("\x1b[31mshell: redirect without command\x1b[0m\n");
        return false;
    }
    return true;
}

/// Append `.elf` to the command part of `line` (everything before the first
/// space) and re-glue with the args. Examples:
///   "ls"          -> "ls.elf"
///   "cat foo.txt" -> "cat.elf foo.txt"
///   "wc.elf"      -> "wc.elf"          (already has extension)
/// The kernel's sysExec splits the resulting string on the first space to
/// recover the binary name and the arg, so the shell's job is just to glue
/// the `.elf` onto the right token.
fn resolveBin(line: []const u8, buf: []u8) []const u8 {
    var sp: usize = line.len;
    for (line, 0..) |c, i| {
        if (c == ' ') {
            sp = i;
            break;
        }
    }
    const cmd = line[0..sp];
    const rest = line[sp..];
    const has_ext = cmd.len >= 4 and equals(cmd[cmd.len - 4 ..], ".elf");

    if (cmd.len + (if (has_ext) @as(usize, 0) else 4) + rest.len > buf.len) {
        return line;
    }
    var written: usize = 0;
    @memcpy(buf[0..cmd.len], cmd);
    written = cmd.len;
    if (!has_ext) {
        @memcpy(buf[written..][0..4], ".elf");
        written += 4;
    }
    if (rest.len > 0) {
        @memcpy(buf[written..][0..rest.len], rest);
        written += rest.len;
    }
    return buf[0..written];
}

/// Wait for `pid` and retry on EINTR. SIGINT delivered to the shell during
/// waitpid causes the kernel to return 0xFFFFFFFF (interrupted) BEFORE the
/// handler runs; the handler then forwards SIGINT to `pid`, the child dies,
/// and we re-call waitpid to actually reap. Without the loop the shell would
/// leak a zombie and (worse) think its child is still running.
fn waitpidIntr(pid: u32, status: *u32) void {
    while (true) {
        const r = libc.waitpid(pid, status);
        if (r != 0xFFFFFFFF) return;
        const limiter = struct {
            var n: u32 = 0;
        };
        limiter.n += 1;
        if (limiter.n > 16) {
            limiter.n = 0;
            return;
        }
    }
}

/// Open one redirect target. Returns the fd, or null on failure (with a
/// red error already printed). For `>`, we unlink first so the file ends
/// up empty rather than partially overwritten — the kernel has no O_TRUNC
/// today and we don't want the cmd's output to leak old tail bytes.
fn openRedirect(path: []const u8, is_out: bool, append: bool) ?u32 {
    if (is_out) {
        var flags: u32 = libc.O_CREATE;
        if (append) {
            flags |= libc.O_APPEND;
        } else {
            // Truncate semantics. unlink can fail if the file doesn't exist
            // yet — that's fine, O_CREATE will make a fresh empty one.
            _ = libc.unlink(path);
        }
        return libc.openFlags(path, flags) orelse {
            libc.print("\x1b[31mshell: cannot open ");
            libc.print(path);
            libc.print(" for writing\x1b[0m\n");
            return null;
        };
    }
    return libc.openFlags(path, 0) orelse {
        libc.print("\x1b[31mshell: cannot open ");
        libc.print(path);
        libc.print(" for reading\x1b[0m\n");
        return null;
    };
}

/// Run a 1..N command pipeline with optional per-cmd `<` / `>` / `>>`.
/// Strategy:
///   1. Open all redirect files up front (any failure aborts cleanly).
///   2. Allocate (n-1) inter-cmd pipes.
///   3. For each cmd, build its FdRemap from the redirect fds (priority) or
///      adjacent pipe ends, then execAs.
///   4. Parent closes ALL pipe + redirect fds so the kernel pipe-refcount
///      drop on child close actually fires.
///   5. waitpid each child in spawn order. Order doesn't matter — pids are
///      independent — but it keeps the SIGINT-cascading behavior simple.
fn runPipeline(cmds: []const Command) void {
    const n = cmds.len;
    if (n == 0) return;

    var in_fds: [MAX_PIPELINE]u32 = [_]u32{0xFF} ** MAX_PIPELINE;
    var out_fds: [MAX_PIPELINE]u32 = [_]u32{0xFF} ** MAX_PIPELINE;
    var pipe_r: [MAX_PIPELINE]u32 = [_]u32{0xFF} ** MAX_PIPELINE;
    var pipe_w: [MAX_PIPELINE]u32 = [_]u32{0xFF} ** MAX_PIPELINE;
    var pids: [MAX_PIPELINE]u32 = [_]u32{0} ** MAX_PIPELINE;

    var any_failed = false;

    for (cmds, 0..) |c, i| {
        if (c.in_path) |p| {
            in_fds[i] = openRedirect(p, false, false) orelse {
                any_failed = true;
                break;
            };
        }
        if (c.out_path) |p| {
            out_fds[i] = openRedirect(p, true, c.out_append) orelse {
                any_failed = true;
                break;
            };
        }
    }

    if (!any_failed) {
        if (n >= 2) {
            for (0..n - 1) |i| {
                const fds = libc.pipe() orelse {
                    libc.print("\x1b[31mshell: pipe alloc failed\x1b[0m\n");
                    any_failed = true;
                    break;
                };
                pipe_r[i] = fds[0];
                pipe_w[i] = fds[1];
            }
        }
    }

    if (!any_failed) {
        for (cmds, 0..) |c, i| {
            var name_buf: [MAX_LINE + 4]u8 = undefined;
            const resolved = resolveBin(c.cmd, &name_buf);

            var remap: [3]libc.FdRemap = undefined;
            var rcount: usize = 0;

            const child_in: u32 = if (in_fds[i] != 0xFF)
                in_fds[i]
            else if (i > 0)
                pipe_r[i - 1]
            else
                0xFF;
            if (child_in != 0xFF) {
                remap[rcount] = .{ .parent_fd = @truncate(child_in), .child_fd = 0 };
                rcount += 1;
            }

            const child_out: u32 = if (out_fds[i] != 0xFF)
                out_fds[i]
            else if (i + 1 < n)
                pipe_w[i]
            else
                0xFF;
            if (child_out != 0xFF) {
                remap[rcount] = .{ .parent_fd = @truncate(child_out), .child_fd = 1 };
                rcount += 1;
            }

            const pid = libc.execAs(resolved, remap[0..rcount]);
            if (pid == 0xFFFFFFFF) {
                libc.print("\x1b[31mshell: not found: ");
                libc.print(c.cmd);
                libc.print("\x1b[0m\n");
                for (0..i) |j| _ = libc.kill(pids[j], libc.SIGKILL);
                any_failed = true;
                break;
            }
            pids[i] = pid;
        }
    }

    // Always close every fd we opened so children's closes can drive the
    // kernel-side refcounts to zero. Pipe writer-count must reach zero for
    // the read end to see EOF; otherwise downstream cmds block forever.
    for (0..n) |i| {
        if (in_fds[i] != 0xFF) libc.close(in_fds[i]);
        if (out_fds[i] != 0xFF) libc.close(out_fds[i]);
    }
    if (n >= 2) {
        for (0..n - 1) |i| {
            if (pipe_r[i] != 0xFF) libc.close(pipe_r[i]);
            if (pipe_w[i] != 0xFF) libc.close(pipe_w[i]);
        }
    }

    if (any_failed) {
        // Reap any spawn-then-killed children from earlier in the loop.
        for (pids) |p| {
            if (p != 0) {
                var st: u32 = 0;
                _ = libc.waitpid(p, &st);
            }
        }
        return;
    }

    // SIGINT forwards to the source (cmd 0) and the sink (cmd n-1). For
    // n>=3 we rely on the cascade: killing the head closes its stdout
    // pipe, the next cmd sees EOF, exits, and so on down the chain.
    fg_child_a = pids[0];
    fg_child_b = if (n >= 2) pids[n - 1] else 0;
    for (0..n) |i| {
        var st: u32 = 0;
        waitpidIntr(pids[i], &st);
    }
    fg_child_a = 0;
    fg_child_b = 0;
}
