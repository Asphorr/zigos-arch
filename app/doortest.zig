// The desktop's side doors, tried from the wrong side.
//
// What is the user's — the key table, the clipboard, the pointer, the
// wallpaper — goes only to a program the user has in front of them
// (desktop.actsFor). Two processes make the same requests at once, one in
// front and one behind, and trade places between the two runs:
//
//   doortest       in front, this program: a child of the focused
//                  terminal's shell. Behind, an orphan: a daemon with no
//                  window.
//   doortest win   in front, the orphan: its new window takes the focus.
//                  Behind, this program: its terminal is still on screen
//                  but no longer the one typed into.
//
//   keys       both watch the key table while the test harness types: the
//              one in front sees keys go down, the other none.
//   clipboard  the one in front sets it and reads it back unchanged; the
//              other reads nothing and cannot replace it.
//   pointer    the focused window's owner may centre it, nobody else.
//   wallpaper  asked for with a width no picture may have, so nothing on
//              screen changes: "the size is wrong" is the answer behind the
//              door, any other error the one at it. A program with anything
//              on screen may ask, focused or not.
//
// One line each on the serial log — "<who> OK" for the one in front,
// "<who> refused" for the other — then "[doortest] done" ("win done"). The
// plain run ends with a notification kept on screen, for a screenshot to
// show the sender's name on the pill.

const libc = @import("libc");

const SECRET = "doortest-secret";
/// How long both sides watch the keys, in timer ticks (10 ms).
const WATCH_TICKS: u32 = 900;
/// From the end of the front's watch to its last look at the clipboard:
/// the other side has tried to replace it by then.
const SETTLE_MS: u32 = 2500;
/// Scancodes of the digit, letter and space keys.
const FIRST_KEY: u8 = 0x02;
const LAST_KEY: u8 = 0x39;

const EINVAL: u32 = @intFromEnum(libc.Errno.EINVAL);

/// set_wallpaper with a width past the limit: EINVAL from behind the door,
/// another error at it.
fn askWallpaper() u32 {
    const px = [_]u32{0};
    return libc.syscall3(98, @truncate(@intFromPtr(&px)), 5000, 1);
}

/// center_mouse, with its answer: 0 when the pointer moved.
fn centerPointer() u32 {
    return libc.syscall(28, 0, 0);
}

/// The number of looks that found a key down.
fn watchKeys() u32 {
    var seen: u32 = 0;
    const start = libc.uptime();
    while (libc.uptime() -% start < WATCH_TICKS) {
        var sc: u8 = FIRST_KEY;
        while (sc <= LAST_KEY) : (sc += 1) {
            if (libc.keyHeld(sc)) {
                seen += 1;
                break;
            }
        }
        libc.sleep(10);
    }
    return seen;
}

/// In front: all of it is given. `owns_focus` — the focused window is this
/// process's own, so the pointer is too.
fn front(who: []const u8, owns_focus: bool) void {
    const set = libc.setClipboard(SECRET);
    const keys = watchKeys();
    libc.sleep(SETTLE_MS);
    var buf: [64]u8 = undefined;
    const n = libc.getClipboard(&buf);
    var intact = set == SECRET.len and n == SECRET.len;
    if (intact) {
        for (SECRET, 0..) |ch, i| {
            if (buf[i] != ch) intact = false;
        }
    }
    const pointer = centerPointer();
    const paper = askWallpaper();
    const verdict: []const u8 = if (!intact)
        "FAIL (its clipboard did not hold)"
    else if (paper != EINVAL)
        "FAIL (kept from the wallpaper)"
    else if (owns_focus and pointer != 0)
        "FAIL (kept from the pointer)"
    else if (keys == 0)
        "INCONCLUSIVE (no key seen: nothing was typed, or the table is shut to it)"
    else
        "OK";
    libc.klogFmt("[doortest] {s} {s}: keys seen={d} clipboard set={d} read={d} pointer=0x{x} wallpaper=0x{x}\n", .{
        who, verdict, keys, set, n, pointer, paper,
    });
}

/// Behind: none of it. `on_screen` — something of this program's is still
/// visible, which is all the wallpaper asks.
fn behind(who: []const u8, on_screen: bool) void {
    const keys = watchKeys();
    var buf: [64]u8 = undefined;
    const read = libc.getClipboard(&buf);
    const wrote = libc.setClipboard("stolen");
    const pointer = centerPointer();
    const paper = askWallpaper();
    const paper_right = if (on_screen) paper == EINVAL else libc.isErr(paper) and paper != EINVAL;
    const refused = keys == 0 and read == 0 and libc.isErr(wrote) and libc.isErr(pointer) and paper_right;
    libc.klogFmt("[doortest] {s} {s}: keys seen={d} clipboard read={d} write=0x{x} pointer=0x{x} wallpaper=0x{x}\n", .{
        who, if (refused) "refused" else "LET IN", keys, read, wrote, pointer, paper,
    });
}

fn orphan(windowed: bool) noreturn {
    // Both parents have exited by now, and init has taken us.
    libc.sleep(500);
    if (!windowed) {
        behind("orphan", false);
        libc.exitWith(0);
    }
    // Nobody's child opening a window: it takes the focus.
    const win = libc.createWindow(320, 200) orelse {
        libc.klog("[doortest] focused window FAIL (no window)\n");
        libc.exitWith(1);
    };
    for (0..@as(usize, win.alloc_w) * win.alloc_h) |i| win.fb[i] = 0xFF2D6A8A;
    libc.present();
    front("focused window", true);
    // The window stays for the screenshot, then goes with the process.
    libc.sleep(4000);
    libc.exitWith(0);
}

fn wantWindow() bool {
    if (libc.getArgc() < 2) return false;
    var arg: [32]u8 = undefined;
    const n = libc.getArgv(1, &arg);
    return n == 3 and arg[0] == 'w' and arg[1] == 'i' and arg[2] == 'n';
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    const windowed = wantWindow();
    libc.klog(if (windowed) "[doortest] starting (win)\n" else "[doortest] starting\n");

    const c = libc.fork();
    if (c == 0xFFFFFFFF or c == 0xFFFFFFFA) {
        libc.klog("[doortest] FAIL: fork\n");
        libc.exitWith(1);
    }
    if (c == 0) {
        if (libc.daemon(true, true) != 0) libc.exitWith(1);
        orphan(windowed);
    }
    // The first of the orphan's two parents.
    _ = libc.waitpid(c, null);

    if (windowed) {
        // The orphan's window has the focus by now.
        libc.sleep(1500);
        behind("terminal behind", true);
        // Its line comes after its last look at the clipboard.
        libc.sleep(3000);
        libc.klog("[doortest] win done\n");
        libc.exitWith(0);
    }

    front("foreground", false);
    libc.klog("[doortest] done\n");

    // A pill lasts three seconds and the harness's screenshot comes when it
    // comes: keep one up for eight.
    libc.sleep(1500);
    for (0..4) |_| {
        libc.notify("door check");
        libc.sleep(2000);
    }
    libc.exitWith(0);
}
