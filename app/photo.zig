const libc = @import("libc");
const stb = @import("stb");
// Pull in the export fn shims (malloc/free/memcpy/...) that stb_image's
// C code calls. comptime-reference forces Zig to analyse the module so
// its `export fn` declarations land in our linked ELF.
comptime {
    _ = @import("stb_shims");
}

fn readEntireFile(path: []const u8) ?[]u8 {
    const fd = libc.open(path) orelse return null;
    defer libc.close(fd);

    const cap: usize = 16 * 1024 * 1024;
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

const default_path = "/share/zigos_test.png";

export fn _start() linksection(".text.entry") callconv(.c) void {
    var path_buf: [128]u8 = undefined;
    const path: []const u8 = blk: {
        const argc = libc.getArgc();
        if (argc >= 2) {
            const len = libc.getArgv(1, &path_buf);
            if (len != 0xFFFFFFFF and len > 0 and len < path_buf.len) {
                break :blk path_buf[0..len];
            }
        }
        @memcpy(path_buf[0..default_path.len], default_path);
        break :blk path_buf[0..default_path.len];
    };

    const file_data = readEntireFile(path) orelse libc.exit();

    var iw: c_int = 0;
    var ih: c_int = 0;
    var ich: c_int = 0;
    const pixels_opt = stb.stbi_load_from_memory(
        file_data.ptr,
        @intCast(file_data.len),
        &iw,
        &ih,
        &ich,
        4,
    );
    libc.free(file_data.ptr);

    if (pixels_opt == null or iw <= 0 or ih <= 0) libc.exit();
    const pixels = pixels_opt.?;
    const img_w: u32 = @intCast(iw);
    const img_h: u32 = @intCast(ih);

    const scr = libc.getScreenSize();
    const win_w: u32 = @min(img_w, scr.w);
    const win_h: u32 = @min(img_h, scr.h);

    const win = libc.createWindowEx(win_w, win_h, win_w, win_h) orelse libc.exit();

    // RGBA8 (stb byte order) → BGRA8 packed u32 (FB byte order on x86 LE).
    var y: u32 = 0;
    while (y < win_h) : (y += 1) {
        var x: u32 = 0;
        while (x < win_w) : (x += 1) {
            const src_idx: usize = (@as(usize, y) * img_w + x) * 4;
            const r: u32 = pixels[src_idx + 0];
            const g: u32 = pixels[src_idx + 1];
            const b: u32 = pixels[src_idx + 2];
            win.fb[y * win.alloc_w + x] = (r << 16) | (g << 8) | b;
        }
    }

    libc.present();

    while (true) {
        while (libc.pollEvent()) |ev| {
            switch (ev.kindOf()) {
                .close_request => {
                    libc.destroyWindow();
                    libc.exit();
                },
                .key_char => {
                    if (@as(u8, @truncate(ev.a)) == 0x1B) {
                        libc.destroyWindow();
                        libc.exit();
                    }
                },
                else => {},
            }
        }
        libc.sleep(20);
    }
}
