// webnav — the browser's navigation primitives: URL normalization, relative
// href resolution, and a bounded back/forward history stack. All over fixed
// buffers (no allocator). Built on lib/http.zig's URL parser so the scheme/
// host/path split lives in exactly one place.

const http = @import("http");

pub const MAX_URL: usize = 1024;

/// Normalize a user-typed address into `out`: trim surrounding spaces and
/// prepend "https://" when no scheme is present. Returns a slice of `out`
/// (empty if the input was blank).
pub fn normalizeUrl(input: []const u8, out: []u8) []const u8 {
    var s: usize = 0;
    var e: usize = input.len;
    while (s < e and (input[s] == ' ' or input[s] == '\t')) s += 1;
    while (e > s and (input[e - 1] == ' ' or input[e - 1] == '\t')) e -= 1;
    const trimmed = input[s..e];
    if (trimmed.len == 0) return out[0..0];

    const has_scheme = (trimmed.len >= 7 and eqlLower(trimmed[0..7], "http://")) or
        (trimmed.len >= 8 and eqlLower(trimmed[0..8], "https://"));

    var p: usize = 0;
    if (!has_scheme) p = writeStr(out, p, "https://");
    p = writeStr(out, p, trimmed);
    return out[0..p];
}

/// Resolve `href` (possibly relative) against `base_url` into `out`. Handles
/// absolute URLs, protocol-relative (//host/…), root-relative (/path) and
/// path-relative hrefs. Returns null if `base_url` can't be parsed.
pub fn resolveHref(base_url: []const u8, href: []const u8, out: []u8) ?[]const u8 {
    // Already absolute?
    if (href.len >= 7 and eqlLower(href[0..7], "http://")) {
        return out[0..writeStr(out, 0, href)];
    }
    if (href.len >= 8 and eqlLower(href[0..8], "https://")) {
        return out[0..writeStr(out, 0, href)];
    }

    const base = http.parseUrl(base_url) catch return null;

    if (href.len >= 2 and href[0] == '/' and href[1] == '/') {
        // protocol-relative: //host/path
        var p: usize = 0;
        p = writeStr(out, p, if (base.scheme == .https) "https:" else "http:");
        p = writeStr(out, p, href);
        return out[0..p];
    }

    const scheme_str: []const u8 = if (base.scheme == .https) "https://" else "http://";
    var p: usize = 0;
    p = writeStr(out, p, scheme_str);
    p = writeStr(out, p, base.host);

    if (href.len > 0 and href[0] == '/') {
        p = writeStr(out, p, href);
    } else {
        // Relative to the current path's directory.
        var dir_end: usize = 0;
        var k: usize = 0;
        while (k < base.path.len) : (k += 1) {
            if (base.path[k] == '/') dir_end = k + 1;
        }
        p = writeStr(out, p, base.path[0..dir_end]);
        if (dir_end == 0) p = writeStr(out, p, "/");
        p = writeStr(out, p, href);
    }
    return out[0..p];
}

// ---------------------------------------------------------------------
// Bounded back/forward history.

pub const MAX_HISTORY: usize = 64;

pub const History = struct {
    bufs: [MAX_HISTORY][MAX_URL]u8 = undefined,
    lens: [MAX_HISTORY]u16 = [_]u16{0} ** MAX_HISTORY,
    count: usize = 0, // number of valid entries
    cur: usize = 0, // index of the current entry (valid when count > 0)

    fn store(self: *History, idx: usize, url: []const u8) void {
        const n = @min(url.len, MAX_URL);
        @memcpy(self.bufs[idx][0..n], url[0..n]);
        self.lens[idx] = @intCast(n);
    }

    pub fn current(self: *const History) []const u8 {
        if (self.count == 0) return "";
        return self.bufs[self.cur][0..self.lens[self.cur]];
    }

    /// Record a fresh navigation. Drops any forward entries (standard browser
    /// behavior) and advances `cur`. A no-op if `url` equals the current entry
    /// (avoids duplicate adjacent history from a reload).
    pub fn visit(self: *History, url: []const u8) void {
        if (url.len == 0) return;
        if (self.count > 0 and eql(self.current(), url)) return;

        if (self.count == 0) {
            self.store(0, url);
            self.count = 1;
            self.cur = 0;
            return;
        }

        if (self.cur + 1 < MAX_HISTORY) {
            self.cur += 1;
            self.store(self.cur, url);
            self.count = self.cur + 1; // truncate forward
        } else {
            // Full — slide the window down by one and append at the end.
            var i: usize = 1;
            while (i < MAX_HISTORY) : (i += 1) {
                const n = self.lens[i];
                @memcpy(self.bufs[i - 1][0..n], self.bufs[i][0..n]);
                self.lens[i - 1] = n;
            }
            self.store(MAX_HISTORY - 1, url);
            self.cur = MAX_HISTORY - 1;
            self.count = MAX_HISTORY;
        }
    }

    pub fn canBack(self: *const History) bool {
        return self.count > 0 and self.cur > 0;
    }
    pub fn canForward(self: *const History) bool {
        return self.count > 0 and self.cur + 1 < self.count;
    }

    /// Step back; returns the now-current URL, or null if already at the start.
    pub fn back(self: *History) ?[]const u8 {
        if (!self.canBack()) return null;
        self.cur -= 1;
        return self.current();
    }

    /// Step forward; returns the now-current URL, or null if at the end.
    pub fn forward(self: *History) ?[]const u8 {
        if (!self.canForward()) return null;
        self.cur += 1;
        return self.current();
    }
};

// ---------------------------------------------------------------------
// Small helpers.

fn lowerc(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}
fn eqlLower(a: []const u8, b_lower: []const u8) bool {
    if (a.len != b_lower.len) return false;
    for (a, b_lower) |ca, cb| {
        if (lowerc(ca) != cb) return false;
    }
    return true;
}
fn eql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (ca != cb) return false;
    }
    return true;
}
fn writeStr(buf: []u8, pos: usize, s: []const u8) usize {
    const n = @min(s.len, buf.len - pos);
    @memcpy(buf[pos..][0..n], s[0..n]);
    return pos + n;
}
