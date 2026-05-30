//! ZigOS visual-novel engine.
//!
//! Loads a converted DDLC script (tools/ddlc/rpyc_to_json.py output) and
//! interprets it: Say / Show / Hide / Scene / Menu / If / Python / Jump /
//! Call / Return / With are handled. UserStatement / RawMultipurpose /
//! Transform are still walked past.
//!
//! What works:
//!   - 1280×720 window with three render layers (BG + sprite + textbox).
//!   - JSON AST loader: opens /share/vn_script.json (the converted
//!     script-ch0.json from DDLC's scripts.rpa), finds the entry label,
//!     walks its block.
//!   - Character name resolution for DDLC's main 4: s/n/m/y → Sayori /
//!     Natsuki / Monika / Yuri. Plain `mc` → "" (treated as narration
//!     since the player is unnamed).
//!   - Click / Space / Enter / arrow-right advance; ESC quits.
//!
//! What lands in this iteration (Phase 4c):
//!   - Scene `bg <tag>` swaps the background pixmap. Falls back to a
//!     suffix-stripped base name (`club_day` → `club`) when the literal
//!     PNG isn't in the archive.
//!   - Show `<char> <pose>` swaps the on-screen sprite using offline-baked
//!     composites (tools/ddlc/compose_poses.py). One sprite at a time.
//!   - Hide `<char>` clears the sprite if that character is up.
//!   - Call/Return + 16-frame call stack — Menu items and If branches use
//!     Call frames so Return resumes at the right post-call statement.
//!   - Cross-label Jump and cross-chapter chaining (ch0 → ch3 on Return-
//!     at-top). Next-chapter file is loaded from /share/vn/script-chN.json.
//!   - Menu rendering with hover-highlight, click-to-pick.
//!   - If: always takes the first entry's block (no Python evaluator yet,
//!     so condition strings can't be evaluated).
//!   - Pixmap cache keyed by file path — repeat shows are decode-free.
//!
//! What's still a no-op:
//!   - With: the dissolve + wipeleft families animate (crossfade /
//!     horizontal wipe); other transition exprs fall back to a short
//!     dissolve. RawMultipurpose / Transform are still skipped.
//!   - Pose-level body+face layering at runtime: pose composites are
//!     pre-baked offline, so unrecognised pose tags fall back to default.
//!   - Audio: BGM and SFX hooks aren't wired to the audio stack.

const std = @import("std");
const libc = @import("libc");
const gfx = @import("graphics");
const ui = @import("ui");
const fa = @import("font_atlas");
const image = @import("image");
const json = @import("json");

const WIN_W: u32 = 1280;
const WIN_H: u32 = 720;

const SCRIPT_PATH: []const u8 = "/share/vn/script-ch0.json";
const ENTRY_LABEL: []const u8 = "ch0_main";

/// On-screen sprite slot. DDLC source sprites are 960×960 with the
/// character anchored to canvas-bottom (y=960 = floor/feet). We scale to
/// 720×720 and place at sy=0 so the character's feet align with the
/// window's bottom edge, and the textbox covers the legs the way DDLC
/// itself composes the scene.
const SPRITE_DST_H: u32 = 720;
const SPRITE_DST_W: u32 = 720;

// --- Render state -----------------------------------------------------------
//
// Show/Hide/Scene statements mutate `RenderState`; Say statements consume it.
// A slot stores only the (char, pose) IDENTITY — the decoded pixmap is
// resolved lazily at draw time from the path cache, at exactly the size the
// current on-stage count needs (720 solo / 540 multi). Each PNG therefore
// decodes once and stays cache-resident for the process, and a `Show`
// allocates nothing — so DDLC's per-expression-change Show storm can't churn
// the heap (the unbounded-growth crash that exhausted the 192 MB VM).
//
// Up to NUM_CHAR_SLOTS characters render at once (DDLC clubroom scenes have
// 2-3 girls on stage). Per-character horizontal placement is in drawSprite.
// Pose-level body+face composition is punted on — poses are pre-baked offline
// (tools/ddlc), and unrecognised tags fall back to <char>/default.

/// Path-keyed cache of decoded Pixels. Lifetime = process lifetime — sprites
/// and BGs decode once and stay resident (the engine never frees a cached
/// pixmap, so several slots can share one without lifetime tracking). Linear
/// scan; the working set is a few hundred entries (one per distinct
/// char/pose/size drawn, plus BGs and negative entries for missing poses),
/// still well below where a hashmap would pay off. Overflow past the cap
/// degrades gracefully to re-decoding (the pre-cache behaviour), not to
/// corruption.
const MAX_PIX_CACHE: usize = 256;
const MAX_PATH_LEN: usize = 96;
var cache_paths: [MAX_PIX_CACHE][MAX_PATH_LEN]u8 = undefined;
var cache_path_lens: [MAX_PIX_CACHE]usize = undefined;
var cache_pix: [MAX_PIX_CACHE]?image.Pixel = undefined;
var cache_count: usize = 0;

/// Slot index per main character. Show statements for unknown handles
/// (props, MC, etc.) are silently ignored at the engine level.
const CharSlot = enum(u8) {
    sayori = 0,
    natsuki = 1,
    yuri = 2,
    monika = 3,
};

const NUM_CHAR_SLOTS: usize = 4;

fn charSlotFor(name: []const u8) ?CharSlot {
    if (eql(name, "sayori")) return .sayori;
    if (eql(name, "natsuki")) return .natsuki;
    if (eql(name, "yuri")) return .yuri;
    if (eql(name, "monika")) return .monika;
    return null;
}

const SPRITE_ID_MAX: usize = 16;

/// A sprite slot holds only the (char, pose) IDENTITY, copied into fixed
/// buffers so it never borrows the script's transient pose buffer or the
/// parsed JSON tree (which `loadNextChapter` frees). drawSprite resolves it
/// to a cached pixmap at the size the current count needs — the solo PNG and
/// the `@540` multi bake are separate cache entries, so only the size that's
/// actually on stage gets decoded.
const SpriteSlot = struct {
    char_buf: [SPRITE_ID_MAX]u8,
    pose_buf: [SPRITE_ID_MAX]u8,
    char_len: u8,
    pose_len: u8,
    has_pose: bool,

    fn character(self: *const SpriteSlot) []const u8 {
        return self.char_buf[0..self.char_len];
    }
    fn pose(self: *const SpriteSlot) ?[]const u8 {
        return if (self.has_pose) self.pose_buf[0..self.pose_len] else null;
    }
};

const RenderState = struct {
    /// Current background pixmap (Scene statement). `null` until first Scene
    /// or when the file fails to load.
    bg: ?image.Pixel,
    /// Per-character sprite slots — DDLC scenes regularly have 2-3 girls
    /// on stage at once (Sayori + Natsuki + Yuri in the clubroom etc.).
    /// `null` means the slot is empty; Show fills it, Hide clears it.
    sprites: [NUM_CHAR_SLOTS]?SpriteSlot,
};

/// One line of dialogue — same shape whether sourced from the JSON AST or
/// (legacy) the hardcoded fallback. `who == null` is narration.
const Line = struct {
    who: ?[]const u8,
    what: []const u8,
};

/// A Menu choice surfaced to the player. `block` is the AST slice to run
/// (as a Call frame) when the option is picked. DDLC's first menu item is
/// often a prompt line with a null block — we filter those out into
/// `header` so it can be rendered as the menu's title.
const MAX_MENU_OPTIONS: usize = 6;
const MenuOption = struct {
    text: []const u8,
    block: []json.Value,
};
const MenuPrompt = struct {
    header: ?[]const u8,
    options: [MAX_MENU_OPTIONS]MenuOption,
    count: usize,
};

/// One step of script execution. The interpreter pauses on `say` for the
/// click-to-advance loop and on `menu` for the player to pick an option.
const Step = union(enum) {
    say: Line,
    menu: MenuPrompt,
    /// The poem minigame, played at each chapter transition. Carries no
    /// payload — the render loop owns the live PoemGame state.
    poem,
};

/// A scene/sprite transition requested by a Ren'Py `With` node. DDLC's main
/// route uses only two families (verified by inspecting script-ch*.json): a
/// crossfade (`dissolve_scene_{half,full}`) and a horizontal wipe
/// (`wipeleft`, `wipeleft_scene`). We map each custom transition name to one
/// of two effects + a frame count. `With None` / unknown-empty yields no
/// transition (instant cut — the historical behaviour).
const TransitionKind = enum { dissolve, wipe_left };
const Transition = struct {
    kind: TransitionKind,
    /// Animation length in ~16 ms frames. The loop sleeps 16 ms/frame, so
    /// 30 ≈ 0.5 s; `_half` and the bare (non-`_scene`) variants run shorter.
    frames: u32,

    fn fromExpr(expr: ?[]const u8) ?Transition {
        const e = expr orelse return null;
        if (e.len == 0 or eql(e, "None")) return null;
        if (std.mem.indexOf(u8, e, "dissolve") != null) {
            const frames: u32 = if (std.mem.indexOf(u8, e, "half") != null) 16 else 30;
            return .{ .kind = .dissolve, .frames = frames };
        }
        if (std.mem.indexOf(u8, e, "wipe") != null) {
            const frames: u32 = if (std.mem.indexOf(u8, e, "scene") != null) 26 else 20;
            return .{ .kind = .wipe_left, .frames = frames };
        }
        // Unknown named transition: a short dissolve reads better than a hard
        // cut and never looks broken.
        return .{ .kind = .dissolve, .frames = 18 };
    }
};

/// Hardcoded fallback script used when the JSON AST file is missing or
/// fails to parse. Keeps `vn.elf` bootable in dev without /share/vn_script.json.
const fallback_script = [_]Line{
    .{ .who = "MC", .what = "(/share/vn_script.json not found — running fallback.)" },
    .{ .who = "Sayori", .what = "Yeah! It's actually working! Click to read the next line." },
    .{ .who = null, .what = "...the wind picks up outside." },
    .{ .who = "MC", .what = "(Skeleton only — assets and scripting land next iteration.)" },
    .{ .who = "MC", .what = "Click once more to exit." },
};

// --- Script interpreter -----------------------------------------------------
//
// We walk the converted DDLC JSON AST directly (no separate Statement
// materialisation step). The tree shape is:
//
//   root = [header, body]
//   body = [Init|Label|...]
//   Label = { type:"Label", name:"...", block:[...] }
//
// A `Cursor` parks on body[i] or, when stepping into a Label, on
// label.block[j]. `Script.advanceToNextSay` runs the cursor forward
// applying side-effect-free skips for unsupported types, and stops on
// the next Say. It returns null when the script ends.

/// Resume frame for Call/Return. Captures the parent block + the next-statement
/// index so popping resumes after the call site, not before.
const Frame = struct {
    block: []json.Value,
    idx: usize,
};
const CALL_STACK_DEPTH: usize = 16;

const Script = struct {
    /// Parsed root JSON of the currently-active chapter. Replaced when
    /// chapter chaining loads the next file.
    root: json.Value,
    /// Cached pointer to the active chapter's body array (root[1]).
    body: []json.Value,
    /// Current cursor: index into `current_block` for the next statement.
    current_block: []json.Value,
    idx: usize,
    /// Call stack: a stack of (block, idx) frames pushed by Call / Menu-pick /
    /// If-enter, popped by Return. Empty stack at Return → chapter ended.
    call_stack: [CALL_STACK_DEPTH]Frame,
    call_depth: usize,
    /// Which `script-chN.json` we're currently playing — used by chapter
    /// chaining to figure out which file to load next. DDLC's main flow
    /// runs 0 → 1 → 2 → 3, so we just increment after each Return-at-top.
    chapter: u32,
    /// True once we've already redirected from `chN_main`'s end into
    /// `chN_end` for this chapter. Without this trampoline, the Menu nodes
    /// (which DDLC houses in `chN_end`) are unreachable: `chN_main` ends
    /// in a `Call nextscene` that resolves to a label defined in a Ren'Py
    /// helper file we don't bundle. So when the cursor exhausts and the
    /// call stack is empty, we treat that as "main done, run end now"
    /// before doing the chapter increment.
    visited_end: bool,
    /// Set by a `With` node during `advance`, consumed once by the render
    /// loop to play a crossfade/wipe before drawing the new state. Last
    /// `With` in one advance wins (multiple Shows between two Says collapse
    /// into a single transition to the final state).
    pending_transition: ?Transition = null,
    /// Set by `loadNextChapter`; consumed once by `advance` to return a
    /// `.poem` Step (the nightly poem) before the new chapter's first line.
    poem_pending: bool = false,

    pub fn loadFromFile(path: []const u8, entry_label: []const u8) ?Script {
        const data = readEntireFile(path, 16 * 1024 * 1024) orelse return null;
        // Don't free data: lib/json.zig's parser dups every string it
        // sees so the parsed Value owns its own storage.
        const root = json.parse(data) catch return null;

        const body_val = root.at(1) orelse return null;
        if (body_val != .array) return null;
        const body = body_val.array;

        const entry_block = findLabelBlock(body, entry_label) orelse return null;

        return .{
            .root = root,
            .body = body,
            .current_block = entry_block,
            .idx = 0,
            .call_stack = undefined,
            .call_depth = 0,
            .chapter = 0,
            .visited_end = false,
        };
    }

    /// Try to redirect into `chN_end` (where the Menus live) once the cursor
    /// runs out of statements in `chN_main`. Returns true if it switched into
    /// the end label; false if no such label exists or we already visited.
    fn tryEnterChapterEnd(self: *Script) bool {
        if (self.visited_end) return false;
        self.visited_end = true;
        var name_buf: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "ch{d}_end", .{self.chapter}) catch return false;
        const blk = findLabelBlock(self.body, name) orelse return false;
        self.current_block = blk;
        self.idx = 0;
        self.call_depth = 0;
        return true;
    }

    fn findLabelBlock(body: []json.Value, name: []const u8) ?[]json.Value {
        for (body) |stmt| {
            const t = (stmt.get("type") orelse continue).asString() orelse continue;
            if (!eql(t, "Label")) continue;
            const n = (stmt.get("name") orelse continue).asString() orelse continue;
            if (!eql(n, name)) continue;
            const blk = (stmt.get("block") orelse continue);
            if (blk != .array) continue;
            return blk.array;
        }
        return null;
    }

    /// Push the current cursor onto the call stack and switch into `block`.
    /// Silently no-ops when the stack is full (rather than crashing on a
    /// deeply-nested call chain — DDLC doesn't go anywhere near depth 16,
    /// so this is paranoid coverage).
    fn pushCall(self: *Script, block: []json.Value) void {
        if (self.call_depth >= CALL_STACK_DEPTH) return;
        self.call_stack[self.call_depth] = .{ .block = self.current_block, .idx = self.idx };
        self.call_depth += 1;
        self.current_block = block;
        self.idx = 0;
    }

    /// Pop a frame off the call stack and resume from where we were.
    /// Returns false when the stack was empty (caller should try chapter
    /// chaining or end the script).
    fn popReturn(self: *Script) bool {
        if (self.call_depth == 0) return false;
        self.call_depth -= 1;
        const frame = self.call_stack[self.call_depth];
        self.current_block = frame.block;
        self.idx = frame.idx;
        return true;
    }

    /// Player picked menu item `idx`. Splice its block into a Call frame —
    /// the cursor will run through it and Return back to whatever came
    /// after the Menu statement.
    pub fn selectMenuItem(self: *Script, menu: MenuPrompt, idx: usize) void {
        if (idx >= menu.count) return;
        self.pushCall(menu.options[idx].block);
    }

    /// Step the cursor forward, applying Scene/Show/Hide side-effects to
    /// `rs`, until the next Say or Menu — or until the script ends.
    pub fn advance(self: *Script, rs: *RenderState) ?Step {
        while (true) {
            // Empty block? Pop a frame, jump to chN_end if we haven't yet,
            // or chain to next chapter as a last resort.
            while (self.idx >= self.current_block.len) {
                if (self.popReturn()) continue;
                if (self.tryEnterChapterEnd()) continue;
                if (!self.loadNextChapter(rs)) return null;
            }
            // A chapter boundary was just crossed (loadNextChapter set this):
            // DDLC has the player write a poem the night before each new
            // chapter. Return it once; the render loop runs the minigame.
            if (self.poem_pending) {
                self.poem_pending = false;
                return .poem;
            }
            const stmt = self.current_block[self.idx];
            self.idx += 1;
            const t_val = stmt.get("type") orelse continue;
            const t = t_val.asString() orelse continue;

            if (eql(t, "Say")) {
                const what_val = stmt.get("what") orelse continue;
                const what = what_val.asString() orelse continue;
                const who_val = stmt.get("who");
                const who: ?[]const u8 = if (who_val) |wv| wv.asString() else null;
                return .{ .say = .{ .who = resolveSpeaker(who), .what = what } };
            } else if (eql(t, "Menu")) {
                if (buildMenu(stmt)) |m| return .{ .menu = m };
                // Malformed Menu — keep walking.
            } else if (eql(t, "If")) {
                // Evaluate each entry's condition under the current
                // PyState; the first True wins. `null` = no entry matched,
                // skip the whole If (the conventional fall-through).
                if (selectIfBlock(stmt)) |blk| self.pushCall(blk);
            } else if (eql(t, "Python")) {
                applyPython(stmt);
            } else if (eql(t, "Scene")) {
                applyScene(rs, stmt);
            } else if (eql(t, "Show")) {
                applyShow(rs, stmt);
            } else if (eql(t, "Hide")) {
                applyHide(rs, stmt);
            } else if (eql(t, "Jump")) {
                const tgt_val = stmt.get("target") orelse continue;
                const tgt = tgt_val.asString() orelse continue;
                if (findLabelBlock(self.body, tgt)) |blk| {
                    self.current_block = blk;
                    self.idx = 0;
                }
            } else if (eql(t, "Call")) {
                const lbl_val = stmt.get("label") orelse continue;
                const lbl = lbl_val.asString() orelse continue;
                if (findLabelBlock(self.body, lbl)) |blk| self.pushCall(blk);
            } else if (eql(t, "Return")) {
                if (self.popReturn()) continue;
                if (self.tryEnterChapterEnd()) continue;
                if (!self.loadNextChapter(rs)) return null;
            } else if (eql(t, "With")) {
                // Record the transition; the render loop snapshots the
                // current frame and animates into the new state on its next
                // pre-draw check. `null` (With None / unknown-empty) leaves
                // it a hard cut.
                const expr_val = stmt.get("expr");
                const expr: ?[]const u8 = if (expr_val) |ev| ev.asString() else null;
                if (Transition.fromExpr(expr)) |tr| self.pending_transition = tr;
            }
            // Other types still skip silently: UserStatement / Pass / Image /
            // Transform / Raw* etc.
        }
    }

    /// Try to replace the current root with the next chapter's JSON. Returns
    /// false when no more chapters can be loaded — caller treats that as
    /// end-of-script. The next chapter's `chN+1_main` becomes the entry.
    ///
    /// Frees the old chapter's parsed tree first via `json.Value.deinit`.
    /// Without that, each chapter transition leaks ~5–15 MB (the parsed
    /// AST + dup'd strings) — the previous root is unreachable from the
    /// engine but libc's heap doesn't know to reclaim its blocks. On a
    /// 192 MB VM the cumulative leak is the difference between smooth
    /// playback and NVMe swap thrashing.
    ///
    /// Evicts the decoded-pixmap cache for the same reason, applied to the
    /// stb-decoded image heap (see `evictPixmapCache`). That's why it takes
    /// `rs`: the cache's only live alias is `rs.bg`, which must be dropped in
    /// lockstep with the free, so eviction lives here rather than in the cache
    /// module. Sprite slots hold identity only, but are cleared too so the
    /// inter-chapter poem frame doesn't re-decode the old stage back into the
    /// just-emptied cache.
    fn loadNextChapter(self: *Script, rs: *RenderState) bool {
        var path_buf: [64]u8 = undefined;
        var label_buf: [32]u8 = undefined;
        // DDLC's main route is ch0 → ch1 → ch2 → ch3. Branching/ending
        // chapters (ch10/20/21/22/23) are reached via in-script Jump/Call,
        // not by linear increment.
        const next = self.chapter + 1;
        if (next > 3) return false;
        const path = std.fmt.bufPrint(&path_buf, "/share/vn/script-ch{d}.json", .{next}) catch return false;
        const label = std.fmt.bufPrint(&label_buf, "ch{d}_main", .{next}) catch return false;
        const data = readEntireFile(path, 16 * 1024 * 1024) orelse return false;
        const root = json.parse(data) catch return false;
        const body_val = root.at(1) orelse return false;
        if (body_val != .array) return false;
        const body = body_val.array;
        const entry_block = findLabelBlock(body, label) orelse return false;
        // Old root is now unreachable from anywhere in the engine:
        // current_block points into the new body, call_stack we're about
        // to clear, and no Step/MenuPrompt outlives this fn. Safe to free.
        self.root.deinit();
        self.root = root;
        self.body = body;
        self.current_block = entry_block;
        self.idx = 0;
        self.call_depth = 0;
        self.chapter = next;
        self.visited_end = false;
        // The previous chapter's pixmaps are now unreachable too: the main
        // route never moves backward, so its BGs/sprites won't be shown again.
        // Drop them so the new chapter starts against the full 256-slot budget
        // instead of inheriting an already-crowded cache. `rs.bg` aliases an
        // evicted pixmap, so clear it — the new chapter's opening `scene`
        // repopulates it before the next VN draw. Sprite slots are identity
        // only, but clearing them stops the inter-chapter poem frame from
        // re-decoding the old stage straight back into the just-emptied cache.
        const dropped = evictPixmapCache();
        rs.bg = null;
        rs.sprites = @splat(null);
        // Breadcrumb so a playthrough can prove eviction fired (and show how
        // full the cache got) rather than inferring it from flat memory —
        // userspace klog lands in serial.log, ~3 lines per main-route run.
        libc.klogFmt("[vn] entering chapter {d}: evicted {d} cached pixmaps (cap {d})\n", .{ next, dropped, MAX_PIX_CACHE });
        // The night between chapters is when the player writes a poem. Only
        // arm it if the word list actually loaded (else skip gracefully).
        self.poem_pending = poem_word_count > 0;
        return true;
    }
};

/// Pull a Menu's prompt header + selectable options out of its JSON node.
/// DDLC's first item is often `[prompt, "True", null]` — a header line with
/// no block — followed by the real choices.
fn buildMenu(stmt: json.Value) ?MenuPrompt {
    const items_val = stmt.get("items") orelse return null;
    if (items_val != .array) return null;
    const items = items_val.array;
    var out: MenuPrompt = .{
        .header = null,
        .options = undefined,
        .count = 0,
    };
    for (items) |item| {
        if (item != .array) continue;
        const tup = item.array;
        if (tup.len < 3) continue;
        const text = tup[0].asString() orelse continue;
        // tup[1] is the condition expression (skipped — see If for rationale).
        const block_val = tup[2];
        if (block_val == .null_) {
            // Header line.
            if (out.header == null) out.header = text;
            continue;
        }
        if (block_val != .array) continue;
        if (out.count >= MAX_MENU_OPTIONS) break;
        out.options[out.count] = .{ .text = text, .block = block_val.array };
        out.count += 1;
    }
    if (out.count == 0) return null;
    return out;
}

// --- Python evaluator -------------------------------------------------------
//
// Minimal interpreter for the subset of Ren'Py-flavored Python that DDLC's
// AST actually exercises in scope: simple-literal assignments
// (`ch1_choice = "natsuki"`, `help_sayori = True`, `s_name = "Sayori"`),
// equality/comparison conditions in If statements (`ch2_winner == "Sayori"`,
// `n_appeal > 1`, `True`, `<expr> and <expr>`, `not <expr>`), and the one
// list subscript ch3 routes on — `poemwinner[N]` (see `parseSubscript`).
// Other unsupported constructs (function calls, arithmetic, string `+`,
// `.method()`, eval, try/except, chained `[i][j]`) make the statement a
// silent no-op and the condition False — the engine falls through to the
// next If entry or to a Pass.
//
// The poem minigame writes `poemwinner[0..2]` and the `<g>_appeal` ints at
// each chapter transition, so ch3's opening If now genuinely branches to
// `ch3_start_{natsuki,yuri,none}` on the player's poem choices. DDLC's
// per-girl EXCLUSIVE scenes (ch1/ch2 `call expression nextscene`, ch3's
// `*_exclusive_2_ch3` calls) live in unbundled script files and still
// no-op — the route opens correctly but the optional flashback is skipped.

const MAX_PY_VARS: usize = 64;
const MAX_PY_NAME: usize = 32;
const MAX_PY_STR: usize = 64;

const PyValue = union(enum) {
    none_v,
    int_v: i64,
    bool_v: bool,
    str_v: struct { data: [MAX_PY_STR]u8, len: u8 },

    fn isTruthy(self: PyValue) bool {
        return switch (self) {
            .none_v => false,
            .int_v => |v| v != 0,
            .bool_v => |b| b,
            .str_v => |s| s.len > 0,
        };
    }

    fn eq(a: PyValue, b: PyValue) bool {
        switch (a) {
            .int_v => |av| return b == .int_v and b.int_v == av,
            .bool_v => |av| return b == .bool_v and b.bool_v == av,
            .str_v => |as| {
                if (b != .str_v) return false;
                const bs = b.str_v;
                if (as.len != bs.len) return false;
                for (as.data[0..as.len], bs.data[0..bs.len]) |x, y| if (x != y) return false;
                return true;
            },
            .none_v => return b == .none_v,
        }
    }
};

const PyVar = struct {
    name: [MAX_PY_NAME]u8,
    name_len: u8,
    value: PyValue,
};

var py_vars: [MAX_PY_VARS]PyVar = undefined;
var py_var_count: usize = 0;

// DDLC's `poemwinner` is a LIST — the winning girl of each night's poem,
// indexed by poem number (0 = the poem before ch1 … 2 = before ch3). ch3's
// opening routing reads `poemwinner[0]`/`poemwinner[1]` (plus the `_appeal`
// ints) to decide which girl's route the chapter opens on, and deeper guards
// read `poemwinner[2]`. Kept apart from `py_vars` because `PyValue` has no
// list variant; the parser resolves `poemwinner[N]` via `parseSubscript`.
var poem_winners: [3]PyValue = .{ .none_v, .none_v, .none_v };
var poems_done: usize = 0;

fn pyLookup(name: []const u8) ?*PyVar {
    var i: usize = 0;
    while (i < py_var_count) : (i += 1) {
        const v = &py_vars[i];
        if (v.name_len != name.len) continue;
        if (eql(v.name[0..v.name_len], name)) return v;
    }
    return null;
}

fn pyGet(name: []const u8) PyValue {
    if (pyLookup(name)) |v| return v.value;
    return .none_v;
}

fn pySet(name: []const u8, value: PyValue) void {
    if (name.len > MAX_PY_NAME) return;
    if (pyLookup(name)) |v| {
        v.value = value;
        return;
    }
    if (py_var_count >= MAX_PY_VARS) return;
    const v = &py_vars[py_var_count];
    @memcpy(v.name[0..name.len], name);
    v.name_len = @intCast(name.len);
    v.value = value;
    py_var_count += 1;
}

fn pyMakeStr(s: []const u8) PyValue {
    var out: PyValue = .{ .str_v = .{ .data = undefined, .len = 0 } };
    const n = if (s.len > MAX_PY_STR) MAX_PY_STR else s.len;
    @memcpy(out.str_v.data[0..n], s[0..n]);
    out.str_v.len = @intCast(n);
    return out;
}

// --- Tokenizer ---

const TokKind = enum {
    ident, int_lit, str_lit, end,
    op_eq, op_neq, op_lt, op_lte, op_gt, op_gte, op_assign,
    kw_and, kw_or, kw_not, kw_true, kw_false, kw_none,
    lparen, rparen, lbracket, rbracket, plus, minus, unknown,
};

const Tok = struct {
    kind: TokKind,
    s: []const u8,
    int_val: i64 = 0,
};

const Lex = struct {
    src: []const u8,
    pos: usize,

    fn peekChar(self: *Lex) ?u8 {
        return if (self.pos < self.src.len) self.src[self.pos] else null;
    }

    fn next(self: *Lex) Tok {
        while (self.pos < self.src.len and (self.src[self.pos] == ' ' or self.src[self.pos] == '\t')) {
            self.pos += 1;
        }
        if (self.pos >= self.src.len) return .{ .kind = .end, .s = "" };
        const c = self.src[self.pos];
        // String literal
        if (c == '"' or c == '\'') {
            const start = self.pos + 1;
            self.pos += 1;
            while (self.pos < self.src.len and self.src[self.pos] != c) self.pos += 1;
            const s = self.src[start..self.pos];
            if (self.pos < self.src.len) self.pos += 1;
            return .{ .kind = .str_lit, .s = s };
        }
        // Number
        if (c >= '0' and c <= '9') {
            const start = self.pos;
            var n: i64 = 0;
            while (self.pos < self.src.len and self.src[self.pos] >= '0' and self.src[self.pos] <= '9') {
                n = n * 10 + @as(i64, @intCast(self.src[self.pos] - '0'));
                self.pos += 1;
            }
            return .{ .kind = .int_lit, .s = self.src[start..self.pos], .int_val = n };
        }
        // Identifier / keyword
        if ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_') {
            const start = self.pos;
            while (self.pos < self.src.len) {
                const ch = self.src[self.pos];
                if ((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_') {
                    self.pos += 1;
                } else break;
            }
            const word = self.src[start..self.pos];
            if (eql(word, "and")) return .{ .kind = .kw_and, .s = word };
            if (eql(word, "or")) return .{ .kind = .kw_or, .s = word };
            if (eql(word, "not")) return .{ .kind = .kw_not, .s = word };
            if (eql(word, "True")) return .{ .kind = .kw_true, .s = word };
            if (eql(word, "False")) return .{ .kind = .kw_false, .s = word };
            if (eql(word, "None")) return .{ .kind = .kw_none, .s = word };
            return .{ .kind = .ident, .s = word };
        }
        // Operators
        const remain = self.src[self.pos..];
        if (remain.len >= 2 and remain[0] == '=' and remain[1] == '=') { self.pos += 2; return .{ .kind = .op_eq, .s = "==" }; }
        if (remain.len >= 2 and remain[0] == '!' and remain[1] == '=') { self.pos += 2; return .{ .kind = .op_neq, .s = "!=" }; }
        if (remain.len >= 2 and remain[0] == '<' and remain[1] == '=') { self.pos += 2; return .{ .kind = .op_lte, .s = "<=" }; }
        if (remain.len >= 2 and remain[0] == '>' and remain[1] == '=') { self.pos += 2; return .{ .kind = .op_gte, .s = ">=" }; }
        self.pos += 1;
        switch (c) {
            '=' => return .{ .kind = .op_assign, .s = "=" },
            '<' => return .{ .kind = .op_lt, .s = "<" },
            '>' => return .{ .kind = .op_gt, .s = ">" },
            '(' => return .{ .kind = .lparen, .s = "(" },
            ')' => return .{ .kind = .rparen, .s = ")" },
            '[' => return .{ .kind = .lbracket, .s = "[" },
            ']' => return .{ .kind = .rbracket, .s = "]" },
            '+' => return .{ .kind = .plus, .s = "+" },
            '-' => return .{ .kind = .minus, .s = "-" },
            else => return .{ .kind = .unknown, .s = self.src[self.pos - 1 .. self.pos] },
        }
    }
};

// --- Expression evaluator (precedence climbing) ---
// or < and < not < cmp < unary < primary
// Returns null on any parse/eval failure → caller treats as None / False.

const Parser = struct {
    lex: Lex,
    cur: Tok,
    failed: bool = false,

    fn init(src: []const u8) Parser {
        var p: Parser = .{ .lex = .{ .src = src, .pos = 0 }, .cur = undefined };
        p.cur = p.lex.next();
        return p;
    }

    fn advance(self: *Parser) void {
        self.cur = self.lex.next();
    }

    fn parseOr(self: *Parser) PyValue {
        var left = self.parseAnd();
        while (self.cur.kind == .kw_or) {
            self.advance();
            const right = self.parseAnd();
            left = .{ .bool_v = left.isTruthy() or right.isTruthy() };
        }
        return left;
    }

    fn parseAnd(self: *Parser) PyValue {
        var left = self.parseNot();
        while (self.cur.kind == .kw_and) {
            self.advance();
            const right = self.parseNot();
            left = .{ .bool_v = left.isTruthy() and right.isTruthy() };
        }
        return left;
    }

    fn parseNot(self: *Parser) PyValue {
        if (self.cur.kind == .kw_not) {
            self.advance();
            const v = self.parseNot();
            return .{ .bool_v = !v.isTruthy() };
        }
        return self.parseCmp();
    }

    fn parseCmp(self: *Parser) PyValue {
        const left = self.parsePrimary();
        switch (self.cur.kind) {
            .op_eq => { self.advance(); const r = self.parsePrimary(); return .{ .bool_v = PyValue.eq(left, r) }; },
            .op_neq => { self.advance(); const r = self.parsePrimary(); return .{ .bool_v = !PyValue.eq(left, r) }; },
            .op_lt, .op_lte, .op_gt, .op_gte => {
                const op = self.cur.kind;
                self.advance();
                const r = self.parsePrimary();
                if (left != .int_v or r != .int_v) {
                    self.failed = true;
                    return .{ .bool_v = false };
                }
                const a = left.int_v;
                const b = r.int_v;
                const result = switch (op) {
                    .op_lt => a < b,
                    .op_lte => a <= b,
                    .op_gt => a > b,
                    .op_gte => a >= b,
                    else => unreachable,
                };
                return .{ .bool_v = result };
            },
            else => return left,
        }
    }

    fn parsePrimary(self: *Parser) PyValue {
        switch (self.cur.kind) {
            .int_lit => { const v = self.cur.int_val; self.advance(); return .{ .int_v = v }; },
            .str_lit => { const s = self.cur.s; self.advance(); return pyMakeStr(s); },
            .kw_true => { self.advance(); return .{ .bool_v = true }; },
            .kw_false => { self.advance(); return .{ .bool_v = false }; },
            .kw_none => { self.advance(); return .none_v; },
            .ident => {
                const name = self.cur.s;
                self.advance();
                // Function call → unsupported; bail.
                if (self.cur.kind == .lparen) { self.failed = true; return .none_v; }
                // List subscript (`poemwinner[N]`) — the one indexable name.
                if (self.cur.kind == .lbracket) return self.parseSubscript(name);
                return pyGet(name);
            },
            .lparen => {
                self.advance();
                const inner = self.parseOr();
                if (self.cur.kind == .rparen) self.advance() else self.failed = true;
                return inner;
            },
            .minus => {
                self.advance();
                const v = self.parsePrimary();
                if (v == .int_v) return .{ .int_v = -v.int_v };
                self.failed = true;
                return .none_v;
            },
            else => {
                self.failed = true;
                return .none_v;
            },
        }
    }

    /// Resolve `<name>[<int>]`. `poemwinner` is the only list-indexable name
    /// in DDLC's bundled scripts (the per-poem winner list ch3 routes on).
    /// Every other subscript — and any chained `[i][j]` (DDLC's string-index
    /// `poemwinner[0][0]` in the unbundled exclusive-scene paths) — fails the
    /// parse, so the condition reads False / the assignment becomes a no-op,
    /// exactly as before subscripts were tokenized. The `[` is already cur.
    fn parseSubscript(self: *Parser, name: []const u8) PyValue {
        self.advance(); // consume '['
        if (self.cur.kind != .int_lit) {
            self.failed = true;
            return .none_v;
        }
        const idx = self.cur.int_val;
        self.advance();
        if (self.cur.kind != .rbracket) {
            self.failed = true;
            return .none_v;
        }
        self.advance();
        // Chained subscript (string indexing) is unsupported.
        if (self.cur.kind == .lbracket) {
            self.failed = true;
            return .none_v;
        }
        if (!eql(name, "poemwinner")) {
            self.failed = true;
            return .none_v;
        }
        // Out-of-range or not-yet-written → None, so the comparison just reads
        // False and the If falls through (the engine's normal catch-all path).
        if (idx < 0) return .none_v;
        const slot: usize = @intCast(idx);
        if (slot >= poem_winners.len) return .none_v;
        return poem_winners[slot];
    }
};

/// Evaluate a Ren'Py condition string. Returns false on any parse failure,
/// type error, or unsupported construct — the engine falls through to the
/// next If entry, which is the correct behavior for `True` catch-alls.
fn pyEvalCondition(src: []const u8) bool {
    // The literal "True" / "False" shortcuts spare the parser a lot of
    // walking on the most common Ren'Py condition.
    if (eql(src, "True")) return true;
    if (eql(src, "False")) return false;
    var p = Parser.init(src);
    const v = p.parseOr();
    if (p.failed) return false;
    if (p.cur.kind != .end) return false;
    return v.isTruthy();
}

/// Execute a PyCode source line. Only simple `name = literal` assignments
/// are supported; anything else is silently dropped. Multi-line PyCode
/// blocks (try/except / function calls / multiple statements) are split
/// on newlines and each line is tried independently — non-assignments
/// just produce no state change.
fn pyExec(src: []const u8) void {
    var line_start: usize = 0;
    var i: usize = 0;
    while (i <= src.len) : (i += 1) {
        if (i == src.len or src[i] == '\n') {
            const line = trimAscii(src[line_start..i]);
            line_start = i + 1;
            if (line.len == 0) continue;
            pyExecLine(line);
        }
    }
}

fn pyExecLine(line: []const u8) void {
    var p = Parser.init(line);
    if (p.cur.kind != .ident) return;
    const name = p.cur.s;
    p.advance();
    if (p.cur.kind != .op_assign) return;
    p.advance();
    const v = p.parseOr();
    if (p.failed) return;
    if (p.cur.kind != .end) return;
    pySet(name, v);
}

fn trimAscii(s: []const u8) []const u8 {
    var start: usize = 0;
    while (start < s.len and (s[start] == ' ' or s[start] == '\t' or s[start] == '\r')) start += 1;
    var end: usize = s.len;
    while (end > start and (s[end - 1] == ' ' or s[end - 1] == '\t' or s[end - 1] == '\r')) end -= 1;
    return s[start..end];
}

fn applyPython(stmt: json.Value) void {
    const code_val = stmt.get("code") orelse return;
    const state_val = code_val.get("_state") orelse return;
    if (state_val != .array) return;
    const state_arr = state_val.array;
    if (state_arr.len < 2) return;
    const src_val = state_arr[1];
    const src = src_val.asString() orelse return;
    pyExec(src);
}

/// Walk an If statement's `entries` and return the first block whose
/// condition evaluates True under the current PyState. Falls back to
/// `null` if no entry's condition is True — the engine then advances
/// past the If without taking any branch.
fn selectIfBlock(stmt: json.Value) ?[]json.Value {
    const entries_val = stmt.get("entries") orelse return null;
    if (entries_val != .array) return null;
    const entries = entries_val.array;
    for (entries) |entry| {
        if (entry != .array) continue;
        const tup = entry.array;
        if (tup.len < 2) continue;
        const cond_val = tup[0];
        const cond_str = cond_val.asString() orelse continue;
        if (!pyEvalCondition(cond_str)) continue;
        const block_val = tup[1];
        if (block_val != .array) continue;
        return block_val.array;
    }
    return null;
}


/// Pull the imspec[0] words out of a Show/Hide/Scene statement. The shape
/// is `imspec: [[word, word, ...], ...]` — we only care about the first
/// nested array (the visible-image identifier).
fn imspecWords(stmt: json.Value) ?[]json.Value {
    const imspec_val = stmt.get("imspec") orelse return null;
    if (imspec_val != .array) return null;
    const arr = imspec_val.array;
    if (arr.len == 0) return null;
    const head = arr[0];
    if (head != .array) return null;
    return head.array;
}

fn applyScene(rs: *RenderState, stmt: json.Value) void {
    const words = imspecWords(stmt) orelse return;
    if (words.len == 0) return;
    // First word is usually "bg"; remaining words form the scene tag.
    // For `scene bg residential_day` → words = ["bg", "residential_day"].
    const first = words[0].asString() orelse return;
    if (!eql(first, "bg")) return;
    if (words.len < 2) return;
    const tag = words[1].asString() orelse return;
    rs.bg = loadBg(tag);
}

fn applyShow(rs: *RenderState, stmt: json.Value) void {
    const words = imspecWords(stmt) orelse return;
    if (words.len == 0) return;
    const character = words[0].asString() orelse return;
    const slot = charSlotFor(character) orelse return;
    // Pose words are imspec[0][1..]; can be empty (e.g. `show sayori`).
    var pose_buf: [SPRITE_ID_MAX]u8 = undefined;
    var pose_len: usize = 0;
    var i: usize = 1;
    while (i < words.len) : (i += 1) {
        const w = words[i].asString() orelse continue;
        for (w) |c| {
            if (pose_len >= pose_buf.len) break;
            pose_buf[pose_len] = c;
            pose_len += 1;
        }
    }
    // Record identity only — the pixmap is resolved (and cached) lazily at
    // draw time, at the size the on-stage count needs. No allocation here, so
    // the per-expression Show storm doesn't churn the heap.
    var s: SpriteSlot = undefined;
    const clen = @min(character.len, SPRITE_ID_MAX);
    @memcpy(s.char_buf[0..clen], character[0..clen]);
    s.char_len = @intCast(clen);
    @memcpy(s.pose_buf[0..pose_len], pose_buf[0..pose_len]);
    s.pose_len = @intCast(pose_len);
    s.has_pose = pose_len != 0;
    rs.sprites[@intFromEnum(slot)] = s;
}

fn applyHide(rs: *RenderState, stmt: json.Value) void {
    const words = imspecWords(stmt) orelse return;
    if (words.len == 0) return;
    const character = words[0].asString() orelse return;
    const slot = charSlotFor(character) orelse return;
    // Identity only — nothing owned, so just clear the slot.
    rs.sprites[@intFromEnum(slot)] = null;
}

/// Resolve DDLC's short character handles ("s", "n", "m", "y") to the
/// display names players know. Plain "mc" (the player) is treated as
/// narration because DDLC asks the player to name themselves — we don't
/// model that yet. Unknown handles pass through verbatim.
fn resolveSpeaker(who: ?[]const u8) ?[]const u8 {
    const w = who orelse return null;
    if (eql(w, "s")) return "Sayori";
    if (eql(w, "n")) return "Natsuki";
    if (eql(w, "m")) return "Monika";
    if (eql(w, "y")) return "Yuri";
    if (eql(w, "mc")) return null; // narration / unnamed protagonist
    return w;
}

fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

// --- Layout constants --------------------------------------------------------

const TEXTBOX_HEIGHT: u32 = 220;
const TEXTBOX_MARGIN: u32 = 24;
const TEXTBOX_PADDING: u32 = 24;
const NAME_TAG_HEIGHT: u32 = 36;
const TEXTBOX_BG: u32 = 0x000000;
const TEXTBOX_BG_ALPHA: u8 = 192; // 75%
const TEXTBOX_BORDER: u32 = 0xFFE0EA; // pale pink
// Name-tag background — varies per speaker. DDLC reuses each character's
// signature accent color from their menu portraits. Narration / unknown
// speakers fall back to Sayori-pink (the original single-color choice).
const NAME_TAG_BG_DEFAULT: u32 = 0xE96B95;
const NAME_TAG_BG_SAYORI: u32 = 0xE96B95; // pink — matches DDLC menu accent
const NAME_TAG_BG_NATSUKI: u32 = 0xF0668E; // hot pink
const NAME_TAG_BG_YURI: u32 = 0xB695C0; // muted purple
const NAME_TAG_BG_MONIKA: u32 = 0x97C39A; // sage green
const TEXT_FG: u32 = 0xFFFFFF;
const NARRATION_FG: u32 = 0xE8E8E8;

fn nameTagBgFor(who: ?[]const u8) u32 {
    const w = who orelse return NAME_TAG_BG_DEFAULT;
    if (eql(w, "Sayori")) return NAME_TAG_BG_SAYORI;
    if (eql(w, "Natsuki")) return NAME_TAG_BG_NATSUKI;
    if (eql(w, "Yuri")) return NAME_TAG_BG_YURI;
    if (eql(w, "Monika")) return NAME_TAG_BG_MONIKA;
    return NAME_TAG_BG_DEFAULT;
}

/// Typewriter reveal speed: bytes added to `reveal_len` per ~16 ms frame.
/// 60 fps × this = chars/sec. DDLC's default text speed is ~50 chars/sec;
/// we run a bit faster so non-typewriter habits don't feel slow. Click
/// snaps to full reveal so impatient readers aren't punished.
const TYPEWRITER_BYTES_PER_TICK: usize = 2;

// --- Per-layer draw fns ------------------------------------------------------

fn drawBackground(canvas: *gfx.Canvas, w: u32, h: u32, tick: u32, rs: *const RenderState) void {
    if (rs.bg) |bg| {
        canvas.drawPixmapAlphaScaled(0, 0, w, h, bg.width, bg.height, bg.pixels);
        return;
    }
    // Fallback: procedural gradient when no Scene has been applied yet
    // (or the BG file failed to load). Tick-modulated so it's visible
    // the frame loop is alive even mid-statement.
    const t = (tick / 4) % 256;
    const top = (@as(u32, 0x60) + @as(u32, @intCast(t / 4))) << 8 | 0x202050;
    const bot: u32 = 0x101025;
    ui.verticalGradient(canvas, 0, 0, w, h, top, bot);
}

/// Read an entire file into a malloc'd byte slice. Sizes the allocation to
/// the file's actual size (+4 KB headroom), not to a max-bytes cap, so a
/// 100 KB PNG doesn't reserve 16 MB of user heap. Same pattern as
/// app/wallpaper.zig — could factor into libc later.
fn readEntireFile(path: []const u8, max_bytes: usize) ?[]u8 {
    var st: libc.FileStat = undefined;
    if (!libc.stat(path, &st)) return null;
    const want: usize = @as(usize, st.file_size);
    if (want == 0 or want > max_bytes) return null;
    const fd = libc.open(path) orelse return null;
    defer libc.close(fd);
    const cap: usize = want + 4096;
    const buf_ptr = libc.malloc(cap) orelse return null;
    const buf = buf_ptr[0..cap];
    var total: usize = 0;
    while (total < cap) {
        const remaining = cap - total;
        const chunk = if (remaining > 65536) 65536 else remaining;
        const n = libc.fread(fd, buf[total..][0..chunk]);
        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

/// Load a PNG into a Pixel via the per-process heap. Decoded pixels survive
/// for the lifetime of the process — DDLC's asset count is small enough to
/// keep BGs/sprites all resident once a proper cache lands. Silently
/// returns null when the file is missing (caller falls back to a
/// placeholder).
fn loadImage(path: []const u8) ?image.Pixel {
    // 32 MB cap: more than enough for any single PNG we'd want to ship.
    const file_data = readEntireFile(path, 32 * 1024 * 1024) orelse return null;
    defer libc.free(file_data.ptr);
    return image.decode(file_data, 4) catch null;
}

/// Linear-scan path cache. Returns the cached Pixel (which may itself be
/// null if a prior decode failed — we cache failures too to avoid hammering
/// fread on every advance).
fn cacheLookup(path: []const u8) ?*const ?image.Pixel {
    var i: usize = 0;
    while (i < cache_count) : (i += 1) {
        if (cache_path_lens[i] != path.len) continue;
        if (eql(cache_paths[i][0..path.len], path)) return &cache_pix[i];
    }
    return null;
}

fn cacheInsert(path: []const u8, pix: ?image.Pixel) ?image.Pixel {
    if (path.len > MAX_PATH_LEN or cache_count >= MAX_PIX_CACHE) return pix;
    const slot = cache_count;
    @memcpy(cache_paths[slot][0..path.len], path);
    cache_path_lens[slot] = path.len;
    cache_pix[slot] = pix;
    cache_count += 1;
    return pix;
}

/// Free every cached pixmap and reset the cache to empty. Called only at a
/// chapter boundary, where the previous chapter's BGs and sprites go off-screen
/// for good (DDLC's main route runs strictly forward, 0 -> 3, and never
/// revisits). Holding them resident would otherwise creep the 256-slot cache
/// toward the `cache_count >= MAX_PIX_CACHE` cliff in `cacheInsert`, past which
/// new loads silently stop caching and re-decode on every frame — the exact
/// per-frame churn this cache was built to kill. Decoded pixels are stb-owned,
/// so each is released via `Pixel.deinit` (-> stbi_image_free); a `null` slot
/// is a cached decode *failure* and owns nothing to free.
///
/// CAUTION: once this returns, any `image.Pixel` the engine still holds is
/// dangling. The sole such alias is `RenderState.bg` (sprite slots store only
/// identity), so the caller MUST drop it before the next draw — see
/// `loadNextChapter`. Freeing mid-chapter would UAF that alias, which is why
/// the cache is otherwise never deinit'd; a chapter boundary is the one point
/// where the alias is dropped in lockstep.
///
/// Returns how many entries were resident — a diagnostic the caller logs so a
/// playthrough can confirm eviction actually fired and watch that no single
/// chapter's working set crept toward the MAX_PIX_CACHE cliff.
fn evictPixmapCache() usize {
    const dropped = cache_count;
    var i: usize = 0;
    while (i < cache_count) : (i += 1) {
        if (cache_pix[i]) |pix| pix.deinit();
    }
    cache_count = 0;
    return dropped;
}

/// Resolve a "club_day"-style Scene tag to a file under /share/ddlc/bg/
/// and load it (cached). Falls back to the suffix-stripped base name when
/// the literal isn't present — DDLC's archive ships e.g. residential.png
/// even though the script says `bg residential_day`, expecting Ren'Py to
/// compose the time-of-day overlay.
fn loadBg(tag: []const u8) ?image.Pixel {
    var buf: [MAX_PATH_LEN]u8 = undefined;
    const candidates = [_]?[]const u8{
        tag,
        stripSuffix(tag, "_day"),
        stripSuffix(tag, "_night"),
        stripSuffix(tag, "_sunset"),
    };
    for (candidates) |maybe| {
        const cand = maybe orelse continue;
        if (cand.len == 0) continue;
        const path = std.fmt.bufPrint(&buf, "/share/ddlc/bg/{s}.png", .{cand}) catch continue;
        if (loadPathCached(path)) |pix| return pix;
    }
    return null;
}

/// Resolve a Show ("sayori", "3a") to a sprite file, with a fallback chain
/// to a per-character pre-composited default when the literal pose file
/// isn't in the archive. DDLC composes most poses from body+face layers
/// at runtime; we punt on layer composition for the MVP and rely on the
/// "3a"-style baked poses (`stage_vn_assets.py` only stages files whose
/// bounding box includes the head).
/// Resolve a (character, pose, size-suffix) to a cached pixmap. The explicit
/// pose file is tried first; a miss (or a pose-less `show`) falls back to the
/// per-character baked default. Every lookup goes through `loadPathCached`,
/// so each distinct path decodes exactly once and is reused on later frames
/// and Shows. `suffix` is "" for the 720 solo bake or "@540" for the multi
/// bake. The returned Pixel aliases cache-owned memory — never deinit it.
fn loadOneSize(character: []const u8, pose: ?[]const u8, buf: []u8, suffix: []const u8) ?image.Pixel {
    if (pose) |p| {
        if (p.len > 0) {
            const path = std.fmt.bufPrint(buf, "/share/ddlc/{s}/{s}{s}.png", .{ character, p, suffix }) catch return null;
            if (loadPathCached(path)) |pix| return pix;
        }
    }
    const default = defaultPose(character) orelse return null;
    const path = std.fmt.bufPrint(buf, "/share/ddlc/{s}/{s}{s}.png", .{ character, default, suffix }) catch return null;
    return loadPathCached(path);
}

/// Per-character composited default pose. `stage_vn_assets.py` bakes
/// `<char>/default.png` for every character we render — either a verbatim
/// copy of a pre-composited body+face PNG (sayori/monika/yuri), or an
/// alpha-blend of separate body+face layer files (natsuki, whose poses
/// are all runtime-composited in DDLC and have no baked counterpart).
fn defaultPose(character: []const u8) ?[]const u8 {
    if (eql(character, "sayori") or eql(character, "natsuki") or
        eql(character, "monika") or eql(character, "yuri"))
        return "default";
    return null;
}

fn loadPathCached(path: []const u8) ?image.Pixel {
    if (cacheLookup(path)) |slot| return slot.*;
    const pix = loadImage(path);
    _ = cacheInsert(path, pix);
    return pix;
}

fn stripSuffix(s: []const u8, suffix: []const u8) ?[]const u8 {
    if (s.len <= suffix.len) return null;
    if (!eql(s[s.len - suffix.len ..], suffix)) return null;
    return s[0 .. s.len - suffix.len];
}

/// Multi-character sprite size matches SPRITE_RES_MULTI in the asset
/// pipeline so we can blit 1:1 without runtime scaling.
const SPRITE_DST_W_MULTI: u32 = 540;
const SPRITE_DST_H_MULTI: u32 = 540;

fn drawSprite(canvas: *gfx.Canvas, w: u32, h: u32, rs: *const RenderState) void {
    // Compact occupied slots, preserving CharSlot order (sayori, natsuki,
    // yuri, monika) — roughly the canonical clubroom seating. Store by VALUE
    // (small identity struct): `|*slot|` on a loop-variable optional gives a
    // pointer into the per-iteration stack copy, aliasing every entry to the
    // last one (the Monika-clone bug, 2026-05-28).
    var present: [NUM_CHAR_SLOTS]SpriteSlot = undefined;
    var count: usize = 0;
    for (rs.sprites) |maybe| {
        if (maybe) |slot| {
            present[count] = slot;
            count += 1;
        }
    }
    if (count == 0) return;

    // Solo (count == 1): the 720 bake. Multi (>= 2): the 540 `@540` bake.
    // Both are LANCZOS-resampled offline and blitted 1:1 so the runtime
    // nearest-neighbor scaler never touches them. The pixmap is resolved from
    // the path cache here, at draw time, so only the size actually on stage is
    // ever decoded/resident and repeat frames are cache hits.
    const multi = count != 1;
    const dst_w: u32 = if (multi) SPRITE_DST_W_MULTI else SPRITE_DST_W;
    const dst_h: u32 = if (multi) SPRITE_DST_H_MULTI else SPRITE_DST_H;
    const suffix: []const u8 = if (multi) "@540" else "";
    const sy: u32 = h -| dst_h;
    // Even horizontal distribution: centers at i*(w/(count+1)) for i in
    // [1, count]. At 540 wide in a 1280 window, 2 fit fully (centers 426/853);
    // 3-4 overlap, but the alpha-0 margins around each body hide the bleed.
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var buf: [MAX_PATH_LEN]u8 = undefined;
        const sp = loadOneSize(present[i].character(), present[i].pose(), &buf, suffix) orelse continue;
        const center_x: u32 = @intCast(@as(u64, w) * (i + 1) / (count + 1));
        const sx: u32 = center_x -| dst_w / 2;
        canvas.drawPixmapAlphaScaled(sx, sy, dst_w, dst_h, sp.width, sp.height, sp.pixels);
    }
}

// --- Transitions -------------------------------------------------------------
//
// A `With` node animates from the last presented frame ("old") into a fresh
// render of the new RenderState ("new"). We snapshot the framebuffer's
// visible region into a packed heap buffer, then each frame redraw the new
// state and composite the old snapshot over it: a per-pixel alpha lerp for
// `dissolve`, or a moving column boundary for `wipe_left`. Only BG + sprite
// layers animate; the textbox is added by the normal draw once the
// transition completes (matching Ren'Py, which shows dialogue post-transition).

/// Snapshot the visible cur_w x cur_h region of the framebuffer (whose row
/// stride is canvas.width) into a packed (stride = cw) destination buffer.
fn captureFrame(canvas: *const gfx.Canvas, dst: [*]u32, cw: u32, ch: u32) void {
    const stride = canvas.width;
    var y: u32 = 0;
    while (y < ch) : (y += 1) {
        const fb_base = y * stride;
        const dst_base = y * cw;
        var x: u32 = 0;
        while (x < cw) : (x += 1) {
            dst[dst_base + x] = canvas.fb[fb_base + x];
        }
    }
}

/// Composite the `old` snapshot over the (already-drawn) new frame in the
/// framebuffer. `num`/`den` is the animation progress, num in 1..den.
fn compositeTransition(canvas: *gfx.Canvas, old: [*]const u32, cw: u32, ch: u32, kind: TransitionKind, num: u32, den: u32) void {
    const stride = canvas.width;
    switch (kind) {
        .dissolve => {
            // new weight ramps 0->256 as the old frame fades 256->0.
            const wn: u32 = num * 256 / den;
            const wo: u32 = 256 - wn;
            var y: u32 = 0;
            while (y < ch) : (y += 1) {
                const fb_base = y * stride;
                const old_base = y * cw;
                var x: u32 = 0;
                while (x < cw) : (x += 1) {
                    const np = canvas.fb[fb_base + x];
                    const op = old[old_base + x];
                    const r = (((np >> 16) & 0xFF) * wn + ((op >> 16) & 0xFF) * wo) >> 8;
                    const g = (((np >> 8) & 0xFF) * wn + ((op >> 8) & 0xFF) * wo) >> 8;
                    const b = ((np & 0xFF) * wn + (op & 0xFF) * wo) >> 8;
                    canvas.fb[fb_base + x] = (r << 16) | (g << 8) | b;
                }
            }
        },
        .wipe_left => {
            // Columns [0, x_div) still show the old frame; the boundary sweeps
            // left as progress grows, so the new frame is revealed from the
            // right edge inward.
            const x_div: u32 = cw * (den - num) / den;
            var y: u32 = 0;
            while (y < ch) : (y += 1) {
                const fb_base = y * stride;
                const old_base = y * cw;
                var x: u32 = 0;
                while (x < x_div) : (x += 1) {
                    canvas.fb[fb_base + x] = old[old_base + x];
                }
            }
        },
    }
}

/// Play a transition into the current RenderState. Snapshots the on-screen
/// frame, then animates `tr.frames` steps. A click/keypress skips to the end;
/// a close request aborts and returns true so the caller can quit. On OOM the
/// snapshot is skipped (the change just becomes a hard cut).
fn playTransition(canvas: *gfx.Canvas, cur_w: u32, cur_h: u32, rs: *const RenderState, tr: Transition, tick: *u32) bool {
    const px: usize = @as(usize, cur_w) * @as(usize, cur_h);
    const raw = libc.malloc(px * 4) orelse return false;
    defer libc.free(raw);
    const old: [*]u32 = @ptrCast(@alignCast(raw));
    captureFrame(canvas, old, cur_w, cur_h);

    var closed = false;
    var f: u32 = 0;
    while (f < tr.frames) : (f += 1) {
        var skip = false;
        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => closed = true,
                .key_char, .mouse_button => skip = true,
                else => {},
            }
        }
        if (closed) break;
        drawBackground(canvas, cur_w, cur_h, tick.*, rs);
        drawSprite(canvas, cur_w, cur_h, rs);
        compositeTransition(canvas, old, cur_w, cur_h, tr.kind, f + 1, tr.frames);
        libc.present();
        if (skip) break;
        libc.sleep(16);
        tick.* +%= 1;
    }
    return closed;
}

fn drawTextbox(
    canvas: *gfx.Canvas,
    w: u32,
    h: u32,
    line: Line,
    tick: u32,
    reveal_len: usize,
) void {
    const bx = TEXTBOX_MARGIN;
    const by = h -| TEXTBOX_HEIGHT -| TEXTBOX_MARGIN;
    const bw = w -| 2 * TEXTBOX_MARGIN;
    const bh = TEXTBOX_HEIGHT;

    // Body panel.
    canvas.fillRectAlpha(bx, by, bw, bh, TEXTBOX_BG, TEXTBOX_BG_ALPHA);
    ui.drawRect1px(canvas, bx, by, bw, bh, TEXTBOX_BORDER);

    // Name tag — only when there's a speaker.
    if (line.who) |who| {
        const tag_w = fa.default_24.measure(who) + 32;
        const tag_x = bx + 16;
        const tag_y = by -| NAME_TAG_HEIGHT + 6;
        canvas.fillRect(tag_x, tag_y, tag_w, NAME_TAG_HEIGHT, nameTagBgFor(who));
        ui.drawRect1px(canvas, tag_x, tag_y, tag_w, NAME_TAG_HEIGHT, TEXTBOX_BORDER);
        fa.drawText(
            canvas,
            @intCast(tag_x + 16),
            @intCast(tag_y + 6),
            who,
            TEXT_FG,
            &fa.default_24,
        );
    }

    // Body text — word-wrapped to the current reveal length. Wrapping uses
    // the FULL line.what so word boundaries don't shift as more text
    // reveals; we just stop drawing once we cross reveal_len.
    const text_x: i32 = @intCast(bx + TEXTBOX_PADDING);
    const text_y_start: i32 = @intCast(by + TEXTBOX_PADDING);
    const text_w_max: u32 = bw -| 2 * TEXTBOX_PADDING;
    const fg = if (line.who == null) NARRATION_FG else TEXT_FG;
    const draw_len = if (reveal_len > line.what.len) line.what.len else reveal_len;
    drawWrapped(canvas, line.what, draw_len, text_x, text_y_start, text_w_max, fg);

    // Blinking advance indicator ▶ — only show once the full line has been
    // revealed, so the player knows "click to advance" (vs "click to skip
    // the typing animation").
    const fully_revealed = reveal_len >= line.what.len;
    if (fully_revealed and (tick / 30) % 2 == 0) {
        const ix: i32 = @intCast(bx + bw -| 28);
        const iy: i32 = @intCast(by + bh -| 28);
        fa.drawText(canvas, ix, iy, "\xE2\x96\xBC", TEXTBOX_BORDER, &fa.default_24);
    }
}

// --- Menu UI -----------------------------------------------------------------
//
// DDLC's menus are short — typically 2–4 options. We stack them vertically
// in the middle of the screen with a header line above. Hover-highlight on
// hit-test, click-release to pick.

const MENU_BUTTON_H: u32 = 56;
const MENU_BUTTON_W: u32 = 640;
const MENU_BUTTON_GAP: u32 = 12;
const MENU_BUTTON_BG: u32 = 0x222222;
const MENU_BUTTON_BG_ALPHA: u8 = 220;
const MENU_BUTTON_HOVER: u32 = 0x603040;
const MENU_BUTTON_BORDER: u32 = 0xFFE0EA;
const MENU_HEADER_FG: u32 = 0xFFFFFF;
const MENU_OPT_FG: u32 = 0xFFFFFF;

fn menuLayout(w: u32, h: u32, count: usize) struct { x: u32, y_start: u32 } {
    const block_h: u32 = @as(u32, @intCast(count)) * (MENU_BUTTON_H + MENU_BUTTON_GAP) -| MENU_BUTTON_GAP;
    const y_start: u32 = (h -| block_h) / 2;
    const x: u32 = (w -| MENU_BUTTON_W) / 2;
    return .{ .x = x, .y_start = y_start };
}

fn drawMenu(canvas: *gfx.Canvas, w: u32, h: u32, menu: MenuPrompt, mx: u32, my: u32) void {
    // Dim the BG so the menu pops. 60% black overlay over the whole window.
    canvas.fillRectAlpha(0, 0, w, h, 0x000000, 153);

    const lay = menuLayout(w, h, menu.count);

    // Header above the buttons.
    if (menu.header) |hdr| {
        const text_w = fa.default_24.measure(hdr);
        const hx: u32 = (w -| text_w) / 2;
        const hy: u32 = lay.y_start -| (fa.default_24.line_height + 24);
        fa.drawText(canvas, @intCast(hx), @intCast(hy), hdr, MENU_HEADER_FG, &fa.default_24);
    }

    var i: usize = 0;
    while (i < menu.count) : (i += 1) {
        const opt = menu.options[i];
        const by: u32 = lay.y_start + @as(u32, @intCast(i)) * (MENU_BUTTON_H + MENU_BUTTON_GAP);
        const hovering = mx >= lay.x and mx < lay.x + MENU_BUTTON_W and my >= by and my < by + MENU_BUTTON_H;
        const bg = if (hovering) MENU_BUTTON_HOVER else MENU_BUTTON_BG;
        canvas.fillRectAlpha(lay.x, by, MENU_BUTTON_W, MENU_BUTTON_H, bg, MENU_BUTTON_BG_ALPHA);
        ui.drawRect1px(canvas, lay.x, by, MENU_BUTTON_W, MENU_BUTTON_H, MENU_BUTTON_BORDER);
        const text_w = fa.default_24.measure(opt.text);
        const tx: u32 = lay.x + (MENU_BUTTON_W -| text_w) / 2;
        const ty: u32 = by + (MENU_BUTTON_H -| fa.default_24.line_height) / 2;
        fa.drawText(canvas, @intCast(tx), @intCast(ty), opt.text, MENU_OPT_FG, &fa.default_24);
    }
}

/// Returns the index of the option under (mx, my), or null. Mouse coords
/// from libc events are window-relative, same coordinate space as drawMenu.
fn menuHitTest(w: u32, h: u32, menu: MenuPrompt, mx: u32, my: u32) ?usize {
    const lay = menuLayout(w, h, menu.count);
    if (mx < lay.x or mx >= lay.x + MENU_BUTTON_W) return null;
    var i: usize = 0;
    while (i < menu.count) : (i += 1) {
        const by: u32 = lay.y_start + @as(u32, @intCast(i)) * (MENU_BUTTON_H + MENU_BUTTON_GAP);
        if (my >= by and my < by + MENU_BUTTON_H) return i;
    }
    return null;
}

// --- Poem minigame -----------------------------------------------------------
//
// DDLC's signature mechanic: between chapters the player writes a poem by
// picking POEM_TARGET words from a shuffling grid. Every word carries an
// appeal rank (1-3) to Sayori / Natsuki / Yuri (data: /share/vn/poemwords.txt,
// staged from scripts.rpa by tools/ddlc/stage_vn_assets.py). The running
// per-girl tally decides `poemwinner`, written into the Python state so simple
// `if poemwinner == "natsuki"` branches resolve. (DDLC's real exclusive-scene
// routing uses dynamic eval() our interpreter can't run, so only equality
// branches wire through — the minigame itself is faithful.)

const POEM_WORD_MAX: usize = 24;
const MAX_POEM_WORDS: usize = 256;
const POEM_TARGET: u32 = 20;
const POEM_COLS: usize = 2;
const POEM_ROWS: usize = 9;
const POEM_OPTS: usize = POEM_COLS * POEM_ROWS;

const PoemWord = struct {
    text: [POEM_WORD_MAX]u8,
    len: u8,
    s: u8,
    n: u8,
    y: u8,
    fn word(self: *const PoemWord) []const u8 {
        return self.text[0..self.len];
    }
};

var poem_words: [MAX_POEM_WORDS]PoemWord = undefined;
var poem_word_count: usize = 0;
var poem_words_loaded: bool = false;

/// Parse /share/vn/poemwords.txt (`word,sPoint,nPoint,yPoint` per line; '#'
/// comments and blanks skipped). Called once at startup; on failure
/// poem_word_count stays 0 and the chapter-transition trigger skips the poem.
fn loadPoemWords() void {
    if (poem_words_loaded) return;
    poem_words_loaded = true;
    const data = readEntireFile("/share/vn/poemwords.txt", 64 * 1024) orelse return;
    defer libc.free(data.ptr);
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.splitScalar(u8, line, ',');
        const w = fields.next() orelse continue;
        const s_str = fields.next() orelse continue;
        const n_str = fields.next() orelse continue;
        const y_str = fields.next() orelse continue;
        if (w.len == 0 or w.len > POEM_WORD_MAX) continue;
        const s = std.fmt.parseInt(u8, std.mem.trim(u8, s_str, " \r\t"), 10) catch continue;
        const n = std.fmt.parseInt(u8, std.mem.trim(u8, n_str, " \r\t"), 10) catch continue;
        const y = std.fmt.parseInt(u8, std.mem.trim(u8, y_str, " \r\t"), 10) catch continue;
        if (poem_word_count >= MAX_POEM_WORDS) break;
        const pw = &poem_words[poem_word_count];
        @memcpy(pw.text[0..w.len], w);
        pw.len = @intCast(w.len);
        pw.s = s;
        pw.n = n;
        pw.y = y;
        poem_word_count += 1;
    }
}

/// xorshift64 — the engine has no entropy source, so the grid is seeded from
/// the frame counter when the poem opens. Enough to vary word order per run.
fn poemRng(state: *u64) u64 {
    var x = state.*;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state.* = x;
    return x;
}

fn poemIndexInList(list: []const usize, idx: usize) bool {
    for (list) |x| if (x == idx) return true;
    return false;
}

const PoemGame = struct {
    picks: u32,
    s_total: u32,
    n_total: u32,
    y_total: u32,
    rng: u64,
    options: [POEM_OPTS]usize, // word indices currently shown
    picked: [POEM_TARGET]usize, // chosen word indices (for the banner)

    fn init(seed: u32) PoemGame {
        var g: PoemGame = .{
            .picks = 0,
            .s_total = 0,
            .n_total = 0,
            .y_total = 0,
            .rng = (@as(u64, seed) *% 2654435761) | 1, // never 0 — xorshift dies on 0
            .options = undefined,
            .picked = undefined,
        };
        g.reroll();
        return g;
    }

    /// Refill `options` with POEM_OPTS distinct word indices for the next turn.
    fn reroll(self: *PoemGame) void {
        if (poem_word_count == 0) return;
        var i: usize = 0;
        while (i < POEM_OPTS) : (i += 1) {
            var idx = poemRng(&self.rng) % poem_word_count;
            var tries: u32 = 0;
            while (tries < 8 and poemIndexInList(self.options[0..i], idx)) : (tries += 1) {
                idx = poemRng(&self.rng) % poem_word_count;
            }
            self.options[i] = idx;
        }
    }

    fn done(self: *const PoemGame) bool {
        return self.picks >= POEM_TARGET;
    }

    /// Add the chosen word's appeal to the tallies, record it, refresh grid.
    fn pick(self: *PoemGame, opt: usize) void {
        if (self.done() or opt >= POEM_OPTS) return;
        const wi = self.options[opt];
        if (wi >= poem_word_count) return;
        const pw = &poem_words[wi];
        self.s_total += pw.s;
        self.n_total += pw.n;
        self.y_total += pw.y;
        if (self.picks < POEM_TARGET) self.picked[self.picks] = wi;
        self.picks += 1;
        if (!self.done()) self.reroll();
    }

    /// Highest tally wins; ties go to the later girl in s<n<y order (matches
    /// DDLC's stable-sort-take-last: Yuri > Natsuki > Sayori).
    fn winner(self: *const PoemGame) CharSlot {
        var best = self.s_total;
        var who: CharSlot = .sayori;
        if (self.n_total >= best) {
            best = self.n_total;
            who = .natsuki;
        }
        if (self.y_total >= best) {
            who = .yuri;
        }
        return who;
    }

    /// Write the result into Python state so story `if`s can read it.
    fn commit(self: *const PoemGame) void {
        const who = self.winner();
        const name: []const u8 = switch (who) {
            .sayori => "sayori",
            .natsuki => "natsuki",
            .yuri => "yuri",
            .monika => "monika",
        };
        pySet("poemwinner", pyMakeStr(name));
        // Append to the list ch3 routes on: poemwinner[poems_done]. Capped at
        // 3 — the main route runs exactly three poems (before ch1/ch2/ch3).
        if (poems_done < poem_winners.len) {
            poem_winners[poems_done] = pyMakeStr(name);
            poems_done += 1;
        }
        const key: []const u8 = switch (who) {
            .sayori => "s_appeal",
            .natsuki => "n_appeal",
            .yuri => "y_appeal",
            .monika => "m_appeal",
        };
        const prev: i64 = switch (pyGet(key)) {
            .int_v => |iv| iv,
            else => 0,
        };
        pySet(key, .{ .int_v = prev + 1 });
    }
};

// Poem-screen palette — a calm dusk-toned notebook, since we don't ship
// DDLC's poemgame background art.
const POEM_BG: u32 = 0x2A2438;
const POEM_BTN_BG: u32 = 0x453F5E;
const POEM_BTN_HOVER: u32 = 0x6A5A92;
const POEM_BORDER: u32 = 0xC9B8E0;
const POEM_FG: u32 = 0xF0EAF8;
const POEM_TITLE_FG: u32 = 0xFFE0EA;
const POEM_DIM_FG: u32 = 0xB0A8C8;

const PoemRect = struct { x: u32, y: u32, bw: u32, bh: u32 };

/// Layout for word-button `opt` (column-major: 0..ROWS-1 left, then right).
/// Shared by drawPoem and poemHitTest so they never disagree.
fn poemBtnRect(w: u32, h: u32, opt: usize) PoemRect {
    const top: u32 = 116;
    const margin: u32 = 80;
    const gap_x: u32 = 40;
    const bw: u32 = (w -| 2 * margin -| gap_x) / 2;
    const avail: u32 = h -| top -| 24;
    const rows_u: u32 = @intCast(POEM_ROWS);
    const stride: u32 = avail / rows_u;
    const col: u32 = @intCast(opt / POEM_ROWS);
    const row: u32 = @intCast(opt % POEM_ROWS);
    return .{
        .x = margin + col * (bw + gap_x),
        .y = top + row * stride,
        .bw = bw,
        .bh = stride -| 8,
    };
}

fn poemHitTest(w: u32, h: u32, g: *const PoemGame, mx: u32, my: u32) ?usize {
    var i: usize = 0;
    while (i < POEM_OPTS) : (i += 1) {
        if (g.options[i] >= poem_word_count) continue;
        const r = poemBtnRect(w, h, i);
        if (mx >= r.x and mx < r.x + r.bw and my >= r.y and my < r.y + r.bh) return i;
    }
    return null;
}

fn drawPoemResult(canvas: *gfx.Canvas, w: u32, h: u32, g: *const PoemGame) void {
    const who = g.winner();
    const name: []const u8 = switch (who) {
        .sayori => "Sayori",
        .natsuki => "Natsuki",
        .yuri => "Yuri",
        .monika => "Monika",
    };
    const cx: u32 = w / 2;
    const title = "Your poem is finished.";
    const tw = fa.default_24.measure(title);
    fa.drawText(canvas, @intCast(cx -| tw / 2), @intCast(h / 2 -| 60), title, POEM_TITLE_FG, &fa.default_24);
    var buf: [80]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "It resonated most with {s}.", .{name}) catch "It resonated most with someone.";
    const lw = fa.default_24.measure(line);
    fa.drawText(canvas, @intCast(cx -| lw / 2), @intCast(h / 2), line, nameTagBgFor(name), &fa.default_24);
    const hint = "(click to continue)";
    const hw = fa.default_16.measure(hint);
    fa.drawText(canvas, @intCast(cx -| hw / 2), @intCast(h / 2 + 64), hint, POEM_DIM_FG, &fa.default_16);
}

fn drawPoem(canvas: *gfx.Canvas, w: u32, h: u32, g: *const PoemGame, mx: u32, my: u32) void {
    // Opaque full-screen fill — covers the (stale) story scene behind us.
    canvas.fillRect(0, 0, w, h, POEM_BG);
    if (g.done()) {
        drawPoemResult(canvas, w, h, g);
        return;
    }

    // Title + N/20 counter.
    fa.drawText(canvas, 80, 28, "Write a Poem", POEM_TITLE_FG, &fa.default_24);
    var cbuf: [24]u8 = undefined;
    const counter = std.fmt.bufPrint(&cbuf, "{d} / {d}", .{ g.picks, POEM_TARGET }) catch "";
    const cw = fa.default_24.measure(counter);
    fa.drawText(canvas, @intCast(w -| 80 -| cw), 28, counter, POEM_FG, &fa.default_24);

    // The poem so far — picked words joined, clipped at the window edge.
    var banner: [256]u8 = undefined;
    var blen: usize = 0;
    var k: u32 = 0;
    while (k < g.picks and k < POEM_TARGET) : (k += 1) {
        const pword = poem_words[g.picked[k]].word();
        if (blen + pword.len + 1 >= banner.len) break;
        if (blen > 0) {
            banner[blen] = ' ';
            blen += 1;
        }
        @memcpy(banner[blen..][0..pword.len], pword);
        blen += pword.len;
    }
    if (blen > 0) fa.drawText(canvas, 80, 72, banner[0..blen], POEM_DIM_FG, &fa.default_16);

    // Word grid.
    var i: usize = 0;
    while (i < POEM_OPTS) : (i += 1) {
        const wi = g.options[i];
        if (wi >= poem_word_count) continue;
        const r = poemBtnRect(w, h, i);
        const hover = mx >= r.x and mx < r.x + r.bw and my >= r.y and my < r.y + r.bh;
        canvas.fillRect(r.x, r.y, r.bw, r.bh, if (hover) POEM_BTN_HOVER else POEM_BTN_BG);
        ui.drawRect1px(canvas, r.x, r.y, r.bw, r.bh, POEM_BORDER);
        const pword = poem_words[wi].word();
        const tw = fa.default_24.measure(pword);
        const tx = r.x + (r.bw -| tw) / 2;
        const ty = r.y + (r.bh -| fa.default_24.line_height) / 2;
        fa.drawText(canvas, @intCast(tx), @intCast(ty), pword, POEM_FG, &fa.default_24);
    }
}

/// Word-wrap `text` into lines that each measure ≤ `max_w` px in default_24,
/// drawing them in `color` from `(x, y_start)` downward. Returns nothing —
/// the layout is fully deterministic from the inputs.
fn drawWrapped(
    canvas: *gfx.Canvas,
    text: []const u8,
    draw_len: usize,
    x: i32,
    y_start: i32,
    max_w: u32,
    color: u32,
) void {
    const font = &fa.default_24;
    const line_h: u32 = font.line_height + 4;
    var y = y_start;
    var i: usize = 0;
    // Word-wrap against the FULL text so line breaks don't reflow as the
    // typewriter reveals more characters — the textbox stays stable, just
    // gradually fills in. Clip each segment to `draw_len` before rendering.
    while (i < text.len) {
        var end: usize = text.len;
        var last_break: usize = 0;
        var j: usize = i;
        while (j <= text.len) : (j += 1) {
            const slice = text[i..j];
            if (font.measure(slice) > max_w) {
                end = if (last_break > i) last_break else (if (j > i + 1) j - 1 else j);
                break;
            }
            if (j < text.len and text[j] == ' ') last_break = j;
        }
        // Clip the segment to the reveal cursor; once we cross it, stop
        // drawing any more lines.
        const seg_end = if (end > draw_len) draw_len else end;
        if (seg_end > i) {
            fa.drawText(canvas, x, y, text[i..seg_end], color, font);
        }
        if (end >= draw_len) return;
        y += @intCast(line_h);
        i = if (end < text.len and text[end] == ' ') end + 1 else end;
    }
}

// --- Main loop ---------------------------------------------------------------

export fn _start() linksection(".text.entry") callconv(.c) void {
    const win = libc.createWindowEx(WIN_W, WIN_H, WIN_W, WIN_H) orelse libc.exit();
    var canvas = gfx.Canvas.init(win.fb, win.alloc_w, win.alloc_h);
    _ = libc.getWindowAlloc();
    fa.ensureLoaded();
    loadPoemWords();

    // Dynamic present geometry. F10 maximize grows the FB allocation (the VA
    // stays valid; only the dims change) so we re-fetch each frame and:
    //   - rebind Canvas to the new alloc stride (Canvas.width doubles as
    //     stride; binding to the original 1280 against a 1920-wide FB makes
    //     rows trample mid-stride → the tearing the user reported).
    //   - clear-once to wipe the prior-layout garbage from the new pixels.
    //   - pass the visible (display) size to the draw helpers so layout
    //     anchors (bottom textbox, centered sprite) follow the new window.
    var cur_w: u32 = WIN_W;
    var cur_h: u32 = WIN_H;
    var cur_alloc_w: u32 = win.alloc_w;
    var cur_alloc_h: u32 = win.alloc_h;

    // Initial render state — empty until the script's first Scene/Show
    // populates it. Scripts that don't issue either will see the gradient
    // BG + "(sprite slot)" placeholder.
    var rs: RenderState = .{ .bg = null, .sprites = @splat(null) };

    var script: ScriptSource = blk: {
        if (Script.loadFromFile(SCRIPT_PATH, ENTRY_LABEL)) |s| break :blk .{ .json = s };
        break :blk .{ .fallback = .{ .idx = 0 } };
    };

    // The interpreter is paused on either a Say (showing a line, waiting
    // for click) or a Menu (showing options, waiting for selection).
    // `current_step` holds the active pause; null means the script ended.
    var current_step: Step = script.advance(&rs) orelse {
        libc.destroyWindow();
        libc.exit();
    };

    // Start from a clean black frame so the first scene's opening transition
    // (if any) dissolves in from black rather than from uninitialised
    // framebuffer garbage.
    canvas.clear(0xFF000000);

    var tick: u32 = 0;
    var prev_left: bool = false;
    var cur_btns: u32 = 0;
    var mouse_x: u32 = 0;
    var mouse_y: u32 = 0;

    // Typewriter state: reveal_len counts how many bytes of the active Say
    // line have been "typed" so far. Each frame we add TYPEWRITER_BYTES_PER_TICK
    // until we reach line.what.len. Clicking while incomplete snaps to full
    // reveal (DDLC convention); clicking on a fully-revealed line advances.
    var reveal_len: usize = 0;

    // Debug: F2 fast-forwards past Say lines until the next Menu (or script
    // end). Chapter 0 has 359 Says and zero Menus — without this, verifying
    // the menu picker requires clicking through all of ch0 first.
    var fastforward_to_menu: bool = false;

    // Poem minigame state — live only while `current_step == .poem`.
    // `poem_ready` guards one-time init when the step is first entered.
    var poem_game: PoemGame = undefined;
    var poem_ready: bool = false;

    while (true) {
        var should_quit = false;
        var advance_clicked = false;
        var click_released = false;

        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => should_quit = true,
                .key_char => {
                    const ch: u8 = @truncate(ev.a);
                    if (ch == 0x1B) {
                        // ESC cancels an in-progress fast-forward first;
                        // a second ESC (no FF running) quits the app.
                        if (fastforward_to_menu) {
                            fastforward_to_menu = false;
                        } else {
                            should_quit = true;
                        }
                    } else if (ch == ' ' or ch == '\r' or ch == '\n') {
                        advance_clicked = true;
                    } else if (ch == 'n' or ch == 'N') {
                        // Debug: fast-forward through Says to the next Menu.
                        // F-keys are owned by the desktop (F10=maximize) so
                        // we use a letter key instead.
                        fastforward_to_menu = true;
                    }
                },
                .mouse_button => {
                    cur_btns = ev.buttonsState();
                },
                .mouse_move => {
                    mouse_x = ev.a;
                    mouse_y = ev.b;
                },
                else => {},
            }
        }
        if (should_quit) break;

        // Snapshot whether we're fast-forwarding *this* frame before the
        // batch below may clear the flag — used to suppress scene
        // transitions while skipping.
        const was_ff = fastforward_to_menu;
        if (fastforward_to_menu) {
            // Drain Says in a small per-frame batch so the window stays
            // responsive (each `Show` decodes a 720x720 PNG = ~50ms; 4096
            // of those back-to-back would freeze the app for minutes). 32
            // hops/frame at ~16ms tick gives ~2k hops/sec — covers a full
            // chapter in well under a second worst case, with the event
            // poll + screen redraw running between batches so 'n' to ESC
            // remains live. ESC also clears the flag explicitly below.
            var hops: u32 = 0;
            ff: while (hops < 32) : (hops += 1) {
                const next = script.advance(&rs) orelse {
                    fastforward_to_menu = false;
                    break :ff;
                };
                current_step = next;
                switch (next) {
                    .menu => {
                        fastforward_to_menu = false;
                        reveal_len = 0;
                        break :ff;
                    },
                    .poem => {
                        // Stop fast-forwarding at a poem so the player writes it.
                        fastforward_to_menu = false;
                        reveal_len = 0;
                        break :ff;
                    },
                    .say => continue,
                }
            }
        }

        const left_now = (cur_btns & 1) != 0;
        if (!left_now and prev_left) {
            click_released = true;
            advance_clicked = true;
        }
        prev_left = left_now;

        // One-time init when the poem step is entered; reset once it's left.
        switch (current_step) {
            .poem => if (!poem_ready) {
                poem_game = PoemGame.init(tick);
                poem_ready = true;
            },
            else => poem_ready = false,
        }

        switch (current_step) {
            .say => |line| {
                const fully_revealed = reveal_len >= line.what.len;
                if (advance_clicked) {
                    if (!fully_revealed) {
                        // Snap to end of current line instead of advancing.
                        reveal_len = line.what.len;
                    } else {
                        current_step = script.advance(&rs) orelse break;
                        reveal_len = 0;
                    }
                } else if (!fully_revealed) {
                    reveal_len += TYPEWRITER_BYTES_PER_TICK;
                    if (reveal_len > line.what.len) reveal_len = line.what.len;
                }
            },
            .menu => |m| {
                if (click_released) {
                    if (menuHitTest(cur_w, cur_h, m, mouse_x, mouse_y)) |picked| {
                        script.selectMenuItem(m, picked);
                        current_step = script.advance(&rs) orelse break;
                        reveal_len = 0;
                    }
                } else if (advance_clicked and !click_released) {
                    // Keyboard advance picks option 0 as a default.
                    script.selectMenuItem(m, 0);
                    current_step = script.advance(&rs) orelse break;
                    reveal_len = 0;
                }
            },
            .poem => {
                if (poem_game.done()) {
                    // Result screen — any advance click commits + continues.
                    if (advance_clicked) {
                        poem_game.commit();
                        current_step = script.advance(&rs) orelse break;
                        reveal_len = 0;
                    }
                } else if (click_released) {
                    if (poemHitTest(cur_w, cur_h, &poem_game, mouse_x, mouse_y)) |opt| {
                        poem_game.pick(opt);
                    }
                }
            },
        }

        // Refresh geometry. On growth, rebind Canvas + wipe the new pixels
        // so margins don't show prior-layout junk before the next full
        // redraw covers them.
        const a = libc.getWindowAlloc();
        const s = libc.getWindowSize();
        if (a.w != 0 and s.w != 0 and s.h != 0) {
            if (a.w != cur_alloc_w or a.h != cur_alloc_h) {
                cur_alloc_w = a.w;
                cur_alloc_h = a.h;
                canvas = gfx.Canvas.init(win.fb, cur_alloc_w, cur_alloc_h);
                const total: usize = @as(usize, cur_alloc_w) * @as(usize, cur_alloc_h);
                var i: usize = 0;
                while (i < total) : (i += 1) win.fb[i] = 0xFF000000;
            }
            cur_w = s.w;
            cur_h = s.h;
        }

        // Play any pending scene transition before compositing the new frame.
        // The framebuffer still holds the previously presented (old) frame;
        // playTransition snapshots it and animates into the freshly-drawn new
        // state. Suppressed while fast-forwarding so skipping doesn't stutter
        // through a wipe at every scene change.
        if (script.takePendingTransition()) |tr| {
            if (!was_ff) {
                if (playTransition(&canvas, cur_w, cur_h, &rs, tr, &tick)) break;
            }
        }

        // --- Draw frame ---
        drawBackground(&canvas, cur_w, cur_h, tick, &rs);
        drawSprite(&canvas, cur_w, cur_h, &rs);
        switch (current_step) {
            .say => |line| drawTextbox(&canvas, cur_w, cur_h, line, tick, reveal_len),
            .menu => |m| drawMenu(&canvas, cur_w, cur_h, m, mouse_x, mouse_y),
            .poem => drawPoem(&canvas, cur_w, cur_h, &poem_game, mouse_x, mouse_y),
        }

        libc.present();
        libc.sleep(16);
        tick +%= 1;
    }

    libc.destroyWindow();
    libc.exit();
}

const ScriptSource = union(enum) {
    json: Script,
    fallback: struct { idx: usize },

    pub fn advance(self: *ScriptSource, rs: *RenderState) ?Step {
        switch (self.*) {
            .json => |*s| return s.advance(rs),
            .fallback => |*f| {
                if (f.idx >= fallback_script.len) return null;
                const line = fallback_script[f.idx];
                f.idx += 1;
                return .{ .say = line };
            },
        }
    }

    pub fn selectMenuItem(self: *ScriptSource, menu: MenuPrompt, idx: usize) void {
        switch (self.*) {
            .json => |*s| s.selectMenuItem(menu, idx),
            .fallback => {},
        }
    }

    pub fn takePendingTransition(self: *ScriptSource) ?Transition {
        switch (self.*) {
            .json => |*s| {
                const t = s.pending_transition;
                s.pending_transition = null;
                return t;
            },
            .fallback => return null,
        }
    }
};
