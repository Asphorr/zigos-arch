// One-shot helper: read /etc/zigos.conf, find the `wallpaper=` key, decode
// the referenced image via stb_image, and push it to the kernel via the
// sysSetWallpaper syscall. Spawned by the desktop at startup so a user's
// chosen wallpaper survives reboot.
//
// Pass `--clear` to skip decoding and just clear any installed wallpaper.

const libc = @import("libc");
const stb = @import("stb");
comptime {
    _ = @import("stb_shims");
}

const CONF_PATH = "/etc/zigos.conf";
const CONF_KEY = "wallpaper";

/// Allocate-and-read entire file. Returns the slice (caller frees) or null.
fn readEntireFile(path: []const u8, max_bytes: usize) ?[]u8 {
    const fd = libc.open(path) orelse return null;
    defer libc.close(fd);
    const buf_ptr = libc.malloc(max_bytes) orelse return null;
    const buf = buf_ptr[0..max_bytes];
    var total: usize = 0;
    while (total < max_bytes) {
        const remaining = max_bytes - total;
        const chunk = if (remaining > 65536) 65536 else remaining;
        const n = libc.fread(fd, buf[total..][0..chunk]);
        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

/// Search a /etc/zigos.conf-style buffer for `key=value`. Writes the trimmed
/// value into `out` and returns its length. 0 = key not found.
fn confLookup(text: []const u8, key: []const u8, out: []u8) usize {
    var i: usize = 0;
    while (i < text.len) {
        while (i < text.len and (text[i] == ' ' or text[i] == '\t' or
            text[i] == '\n' or text[i] == '\r')) i += 1;
        if (i >= text.len) break;
        if (text[i] == '#') {
            while (i < text.len and text[i] != '\n') i += 1;
            continue;
        }
        const k_start = i;
        while (i < text.len and text[i] != '=' and text[i] != '\n') i += 1;
        if (i >= text.len or text[i] != '=') {
            while (i < text.len and text[i] != '\n') i += 1;
            continue;
        }
        const k = text[k_start..i];
        i += 1;
        const v_start = i;
        while (i < text.len and text[i] != '\n' and text[i] != '\r') i += 1;
        const v = text[v_start..i];
        if (k.len == key.len) {
            var match = true;
            for (k, key) |ka, kb| {
                if (ka != kb) {
                    match = false;
                    break;
                }
            }
            if (match) {
                const copy_len = if (v.len > out.len) out.len else v.len;
                @memcpy(out[0..copy_len], v[0..copy_len]);
                return copy_len;
            }
        }
    }
    return 0;
}

fn decodeAndPush(path: []const u8) bool {
    const file_data = readEntireFile(path, 16 * 1024 * 1024) orelse return false;
    defer libc.free(file_data.ptr);

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
    if (pixels_opt == null or iw <= 0 or ih <= 0) return false;
    const pixels = pixels_opt.?;
    const w: u32 = @intCast(iw);
    const h: u32 = @intCast(ih);

    // Repack stb's RGBA bytes into FB-native B8G8R8A8 packed u32 in place.
    // Doing it in-place avoids a second N-MB allocation; we treat the
    // returned [*]u8 buffer as N u32 entries.
    const total: usize = @as(usize, w) * @as(usize, h);
    const dst_u32: [*]u32 = @ptrCast(@alignCast(pixels));
    var i: usize = 0;
    while (i < total) : (i += 1) {
        const r: u32 = pixels[i * 4 + 0];
        const g: u32 = pixels[i * 4 + 1];
        const b: u32 = pixels[i * 4 + 2];
        dst_u32[i] = (r << 16) | (g << 8) | b;
    }

    const ok = libc.setWallpaper(dst_u32, w, h);
    // stbi_image_free is just free() because we routed STBI_FREE → free.
    libc.free(@as([*]u8, @ptrCast(pixels)));
    return ok;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    // --clear flag: skip everything and just clear.
    var arg_buf: [32]u8 = undefined;
    const argc = libc.getArgc();
    if (argc >= 2) {
        const len = libc.getArgv(1, &arg_buf);
        if (len != 0xFFFFFFFF and len > 0 and len < arg_buf.len) {
            const flag = "--clear";
            if (len == flag.len) {
                var match = true;
                for (flag, 0..) |fc, i| {
                    if (arg_buf[i] != fc) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    _ = libc.setWallpaperClear();
                    libc.exit();
                }
            }
        }
    }

    // Read /etc/zigos.conf, look up `wallpaper=`.
    const conf = readEntireFile(CONF_PATH, 4096) orelse libc.exit();
    defer libc.free(conf.ptr);

    var path_buf: [128]u8 = undefined;
    const path_len = confLookup(conf, CONF_KEY, &path_buf);
    if (path_len == 0) libc.exit(); // no wallpaper configured — nothing to do

    const path = path_buf[0..path_len];
    if (path.len == 0) libc.exit();
    _ = decodeAndPush(path);
    libc.exit();
}
