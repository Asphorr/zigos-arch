// HTTP/1.1 client built on top of libc's TLS + TCP socket syscalls.
//
// Usage:
//   var buf: [16 * 1024]u8 = undefined;
//   const resp = try http.get("https://example.com/", &buf);
//   // resp.status == 200, resp.body points into buf
//
// The caller owns the response buffer. Headers + body live INSIDE `buf` —
// they're slices, not copies. `buf` must stay alive as long as you read
// the response. Bigger sites need bigger buffers; ResponseTooLarge is
// returned if a body exceeds what you provided.
//
// What's supported:
//   - GET / POST / PUT / DELETE / HEAD
//   - http:// and https:// (TLS routed through kernel TlsConn API)
//   - Content-Length AND chunked transfer-encoding bodies
//   - Read-until-EOF body when the server omits both (HTTP/1.0 style)
//   - 30x redirect chasing (up to MAX_REDIRECTS hops, absolute URLs only;
//     relative Locations fall through to the caller as-is)
//   - Case-insensitive header lookup via Response.getHeader()
//
// What's NOT supported (deliberate scope cut for v1):
//   - Connection: keep-alive (we always send Connection: close + tear down)
//   - HTTP/2, HTTP/3
//   - gzip / deflate / brotli content-encodings
//   - Cookies, auth schemes other than Basic via manual Authorization header
//   - Streaming bodies — everything is materialized into `buf`
//
// All errors are returned via the `Error` set; the connection is closed
// on every exit path.

const std = @import("std");
const libc = @import("libc");

pub const Error = error{
    BadUrl,
    UnsupportedScheme,
    DnsFailure,
    ConnectFailure,
    TlsFailure,
    SendFailure,
    RecvFailure,
    BadResponse,
    BufferTooSmall,
    TooManyRedirects,
    TooManyHeaders,
    ResponseTooLarge,
    BadChunk,
    StreamClosed,
};

pub const MAX_HEADERS: usize = 32;
pub const MAX_REDIRECTS: u8 = 5;
pub const MAX_URL: usize = 1024;
const REQUEST_SCRATCH: usize = 4096;

pub const Method = enum {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,

    pub fn str(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .HEAD => "HEAD",
        };
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Scheme = enum { http, https };

pub const Url = struct {
    scheme: Scheme,
    host: []const u8,
    port: u16,
    path: []const u8,
};

pub const Request = struct {
    method: Method = .GET,
    url: []const u8,
    headers: []const Header = &.{},
    body: []const u8 = "",
    follow_redirects: bool = true,
};

pub const Response = struct {
    status: u16,
    status_text: []const u8,
    headers_buf: [MAX_HEADERS]Header,
    n_headers: u8,
    body: []const u8,

    pub fn headers(self: *const Response) []const Header {
        return self.headers_buf[0..self.n_headers];
    }

    pub fn getHeader(self: *const Response, name: []const u8) ?[]const u8 {
        for (self.headers_buf[0..self.n_headers]) |h| {
            if (eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }
};

// ---------------------------------------------------------------------
// URL parser. Recognizes:
//   http://host[:port][/path[?query]]
//   https://host[:port][/path[?query]]
// Path defaults to "/" when absent. Port defaults to 80 / 443 depending
// on scheme. Hostnames are NOT punycoded (caller's problem if non-ASCII).

pub fn parseUrl(url: []const u8) Error!Url {
    if (url.len == 0 or url.len > MAX_URL) return Error.BadUrl;

    var scheme: Scheme = undefined;
    var rest: []const u8 = undefined;
    if (std.mem.startsWith(u8, url, "http://")) {
        scheme = .http;
        rest = url[7..];
    } else if (std.mem.startsWith(u8, url, "https://")) {
        scheme = .https;
        rest = url[8..];
    } else return Error.UnsupportedScheme;

    if (rest.len == 0) return Error.BadUrl;

    // Split hostport / path on first '/'.
    var path_start: usize = rest.len;
    for (rest, 0..) |c, i| {
        if (c == '/') {
            path_start = i;
            break;
        }
    }
    const hostport = rest[0..path_start];
    const path: []const u8 = if (path_start < rest.len) rest[path_start..] else "/";

    // Split hostport on optional ':'. IPv6 literals would need [..]; not
    // supported in v1 since the resolver only does IPv4 anyway.
    var host = hostport;
    var port: u16 = if (scheme == .https) 443 else 80;
    for (hostport, 0..) |c, i| {
        if (c == ':') {
            host = hostport[0..i];
            port = parseU16(hostport[i + 1 ..]) orelse return Error.BadUrl;
            break;
        }
    }
    if (host.len == 0) return Error.BadUrl;

    return .{ .scheme = scheme, .host = host, .port = port, .path = path };
}

// ---------------------------------------------------------------------
// Transport: TCP for http, TLS for https. The slot id is a u8; we
// disambiguate by `is_tls` because TCP and TLS pools are independent.

const Conn = struct {
    is_tls: bool,
    slot: u8,

    fn open(url: Url) Error!Conn {
        const ip = libc.parseIp(url.host) orelse libc.resolve(url.host) orelse return Error.DnsFailure;
        if (url.scheme == .https) {
            const slot = libc.tlsConnect(ip, url.port, url.host) orelse return Error.TlsFailure;
            return .{ .is_tls = true, .slot = slot };
        } else {
            const slot = libc.tcpConnect(ip, url.port) orelse return Error.ConnectFailure;
            return .{ .is_tls = false, .slot = slot };
        }
    }

    fn send(self: Conn, data: []const u8) Error!void {
        if (self.is_tls) {
            // Kernel tlsSend caps payload at 16 KiB; chunk if needed.
            var off: usize = 0;
            while (off < data.len) {
                const want = @min(data.len - off, 16 * 1024);
                _ = libc.tlsSend(self.slot, data[off .. off + want]) orelse return Error.SendFailure;
                off += want;
            }
        } else {
            if (!libc.tcpSend(self.slot, data)) return Error.SendFailure;
        }
    }

    /// Block until at least one byte arrives, OR the peer closes (returns 0),
    /// OR the transport errors (Error.RecvFailure). TCP path polls because
    /// libc.tcpRecv is non-blocking; TLS path is already blocking.
    fn recv(self: Conn, buf: []u8) Error!usize {
        if (buf.len == 0) return 0;
        if (self.is_tls) {
            return libc.tlsRecv(self.slot, buf) orelse return Error.RecvFailure;
        }
        // TCP poll loop: tcpRecv returns 0 when there's nothing buffered.
        // Re-check peer status periodically; bail on EOF.
        var spins: u32 = 0;
        while (true) {
            const n = libc.tcpRecv(self.slot, buf);
            if (n > 0) return n;
            const status = libc.tcpStatus(self.slot);
            if ((status & libc.TCP_STATUS_PEER_CLOSED) != 0) {
                // One last drain attempt in case peer-close raced our recv.
                const n2 = libc.tcpRecv(self.slot, buf);
                if (n2 > 0) return n2;
                return 0;
            }
            spins += 1;
            // Back off after the first burst — early millis are cheap to spin.
            libc.usleep(if (spins < 32) 100 else 1000);
            // ~10s soft cap: 100us * 32 + 1ms * 9968 ≈ 10s.
            if (spins > 10_000) return Error.RecvFailure;
        }
    }

    fn close(self: Conn) void {
        if (self.is_tls) libc.tlsClose(self.slot) else libc.tcpClose(self.slot);
    }
};

// ---------------------------------------------------------------------
// Public entry points. `send` is the full version; `get`/`post` are
// thin convenience wrappers.

pub fn get(url: []const u8, buf: []u8) Error!Response {
    return send(.{ .url = url }, buf);
}

pub fn post(url: []const u8, content_type: []const u8, body: []const u8, buf: []u8) Error!Response {
    const hdrs = [_]Header{.{ .name = "Content-Type", .value = content_type }};
    return send(.{ .method = .POST, .url = url, .headers = &hdrs, .body = body }, buf);
}

pub fn send(req: Request, buf: []u8) Error!Response {
    // Redirects rewrite the URL; we keep a local stable copy so the next
    // sendOnce can safely reuse `buf` for its own response. Also: if the
    // caller passed a bare "host.com/path" with no scheme, default to
    // https — most real-world URLs are TLS now, and the alternative
    // (UnsupportedScheme) is a confusing first-touch failure.
    var url_storage: [MAX_URL]u8 = undefined;
    const has_scheme = std.mem.startsWith(u8, req.url, "http://") or std.mem.startsWith(u8, req.url, "https://");
    var current_len: usize = 0;
    if (!has_scheme) {
        const prefix = "https://";
        if (req.url.len + prefix.len > url_storage.len) return Error.BadUrl;
        @memcpy(url_storage[0..prefix.len], prefix);
        @memcpy(url_storage[prefix.len .. prefix.len + req.url.len], req.url);
        current_len = prefix.len + req.url.len;
    } else {
        if (req.url.len > url_storage.len) return Error.BadUrl;
        @memcpy(url_storage[0..req.url.len], req.url);
        current_len = req.url.len;
    }
    var current: []const u8 = url_storage[0..current_len];

    var redirects: u8 = 0;
    while (true) {
        const url = try parseUrl(current);
        const resp = try sendOnce(req.method, url, req.headers, req.body, buf);

        if (!req.follow_redirects) return resp;
        if (resp.status < 300 or resp.status >= 400) return resp;
        if (resp.status == 304) return resp; // Not Modified — not a redirect
        const loc = resp.getHeader("Location") orelse return resp;
        if (loc.len == 0) return resp;

        redirects += 1;
        if (redirects > MAX_REDIRECTS) return Error.TooManyRedirects;

        // Only chase absolute Locations. Relative ("/foo") and protocol-
        // relative ("//host/foo") locations need URL composition; v1
        // returns the 3xx response so the caller can decide.
        const is_abs = std.mem.startsWith(u8, loc, "http://") or std.mem.startsWith(u8, loc, "https://");
        if (!is_abs) return resp;
        if (loc.len > url_storage.len) return Error.TooManyRedirects;

        @memcpy(url_storage[0..loc.len], loc);
        current = url_storage[0..loc.len];
    }
}

// ---------------------------------------------------------------------
// Streaming API. For when the response body is large (multi-MB
// downloads), unknown ahead of time, or needs to be processed
// incrementally (parse-as-you-fetch).
//
// Usage:
//   var stream: http.Stream = undefined;
//   try http.openStream(.{ .url = "https://example.com/big.bin" }, &hdr_buf, &stream);
//   defer stream.close();
//   const r = stream.response();
//   if (r.status != 200) ... ;
//   var chunk: [4096]u8 = undefined;
//   while (true) {
//       const n = try stream.readChunk(&chunk);
//       if (n == 0) break;
//       // ... do something with chunk[0..n]
//   }
//
// Differences from send():
//   - No automatic redirect chasing. Caller inspects status; if 3xx,
//     pulls Location header, closes stream, opens a new one.
//   - Response.body field is always empty (body is delivered via
//     readChunk).
//   - header_buf must outlive the Stream — response.headers point
//     into it.

const STAGE_SIZE: usize = 8 * 1024;

const BodyMode = enum {
    content_length, // bounded by Content-Length header
    chunked, // Transfer-Encoding: chunked
    eof, // HTTP/1.0 style — body ends at conn close
    none, // HEAD / 204 / 304 — no body
};

const ChunkedState = enum {
    reading_size, // parsing "<hex>\r\n" line
    in_chunk_data, // delivering chunk payload bytes
    after_chunk_crlf, // skipping CRLF after a chunk's payload
    after_zero, // last chunk seen; consuming trailer lines until blank
    finished,
};

pub const Stream = struct {
    conn: Conn,
    response_data: Response,
    mode: BodyMode,

    /// Staging buffer holding unread bytes. Residual body bytes from
    /// the header recv get copied here at open; refilled from `conn`
    /// when empty. Sized to cover one max-size TLS record + a chunk
    /// size line, comfortably.
    stage: [STAGE_SIZE]u8,
    stage_pos: usize,
    stage_len: usize,

    cl_remaining: u64,
    chunked: ChunkedState,
    chunk_remaining: u32,

    eof_seen: bool,
    closed: bool,

    pub fn response(self: *const Stream) *const Response {
        return &self.response_data;
    }

    pub fn readChunk(self: *Stream, out: []u8) Error!usize {
        if (self.closed) return Error.StreamClosed;
        if (out.len == 0) return 0;
        return switch (self.mode) {
            .none => 0,
            .content_length => self.readClBody(out),
            .chunked => self.readChunkedBody(out),
            .eof => self.readEofBody(out),
        };
    }

    pub fn close(self: *Stream) void {
        if (self.closed) return;
        self.closed = true;
        self.conn.close();
    }

    // ---- Internals ----

    /// Ensure stage has at least one byte, recvving from conn if
    /// needed. Returns false on conn EOF (stage stays empty).
    fn fillStage(self: *Stream) Error!bool {
        if (self.stage_pos < self.stage_len) return true;
        if (self.eof_seen) return false;
        self.stage_pos = 0;
        const n = try self.conn.recv(self.stage[0..]);
        self.stage_len = n;
        if (n == 0) {
            self.eof_seen = true;
            return false;
        }
        return true;
    }

    /// Pop one byte from stage. Caller must ensure fillStage returned true.
    fn popByte(self: *Stream) u8 {
        const b = self.stage[self.stage_pos];
        self.stage_pos += 1;
        return b;
    }

    fn readClBody(self: *Stream, out: []u8) Error!usize {
        if (self.cl_remaining == 0) return 0;
        if (!try self.fillStage()) return Error.BadResponse; // EOF mid-body
        const stage_avail = self.stage_len - self.stage_pos;
        const want = @min(@min(out.len, stage_avail), @as(usize, @intCast(@min(self.cl_remaining, @as(u64, 0xFFFFFFFF)))));
        @memcpy(out[0..want], self.stage[self.stage_pos .. self.stage_pos + want]);
        self.stage_pos += want;
        self.cl_remaining -= want;
        return want;
    }

    fn readEofBody(self: *Stream, out: []u8) Error!usize {
        if (!try self.fillStage()) return 0;
        const stage_avail = self.stage_len - self.stage_pos;
        const want = @min(out.len, stage_avail);
        @memcpy(out[0..want], self.stage[self.stage_pos .. self.stage_pos + want]);
        self.stage_pos += want;
        return want;
    }

    /// Decode chunked body incrementally. Each call emits up to
    /// out.len bytes of decoded payload, walking through size lines
    /// and CRLF separators in between as needed. Returns 0 at the
    /// end-of-stream "0\r\n\r\n" terminator.
    fn readChunkedBody(self: *Stream, out: []u8) Error!usize {
        var written: usize = 0;
        while (written < out.len) {
            switch (self.chunked) {
                .reading_size => {
                    // Read hex digits until we see CR; then expect LF.
                    var size: u32 = 0;
                    var saw_digit = false;
                    while (true) {
                        if (!try self.fillStage()) return Error.BadChunk;
                        const c = self.popByte();
                        if (c == '\r') {
                            if (!try self.fillStage()) return Error.BadChunk;
                            if (self.popByte() != '\n') return Error.BadChunk;
                            break;
                        }
                        // ';' starts chunk extension — ignore until CR.
                        if (c == ';') {
                            while (true) {
                                if (!try self.fillStage()) return Error.BadChunk;
                                const x = self.popByte();
                                if (x == '\r') {
                                    if (!try self.fillStage()) return Error.BadChunk;
                                    if (self.popByte() != '\n') return Error.BadChunk;
                                    break;
                                }
                            }
                            break;
                        }
                        const d: ?u8 = if (c >= '0' and c <= '9')
                            c - '0'
                        else if (c >= 'a' and c <= 'f')
                            c - 'a' + 10
                        else if (c >= 'A' and c <= 'F')
                            c - 'A' + 10
                        else
                            null;
                        if (d) |dv| {
                            if (size > 0x0FFFFFFF) return Error.BadChunk;
                            size = size * 16 + dv;
                            saw_digit = true;
                        } else return Error.BadChunk;
                    }
                    if (!saw_digit) return Error.BadChunk;
                    if (size == 0) {
                        self.chunked = .after_zero;
                    } else {
                        self.chunk_remaining = size;
                        self.chunked = .in_chunk_data;
                    }
                },
                .in_chunk_data => {
                    if (!try self.fillStage()) return Error.BadChunk;
                    const stage_avail = self.stage_len - self.stage_pos;
                    const want = @min(@min(out.len - written, stage_avail), @as(usize, self.chunk_remaining));
                    @memcpy(out[written .. written + want], self.stage[self.stage_pos .. self.stage_pos + want]);
                    self.stage_pos += want;
                    written += want;
                    self.chunk_remaining -= @intCast(want);
                    if (self.chunk_remaining == 0) self.chunked = .after_chunk_crlf;
                    if (written == out.len) return written;
                },
                .after_chunk_crlf => {
                    if (!try self.fillStage()) return Error.BadChunk;
                    if (self.popByte() != '\r') return Error.BadChunk;
                    if (!try self.fillStage()) return Error.BadChunk;
                    if (self.popByte() != '\n') return Error.BadChunk;
                    self.chunked = .reading_size;
                },
                .after_zero => {
                    // Drain trailer headers (lines ending in CRLF) until a
                    // blank CRLF line marks end of message.
                    if (!try self.fillStage()) {
                        self.chunked = .finished;
                        return written;
                    }
                    const first = self.popByte();
                    if (first == '\r') {
                        if (!try self.fillStage()) {
                            self.chunked = .finished;
                            return written;
                        }
                        if (self.popByte() != '\n') return Error.BadChunk;
                        self.chunked = .finished;
                        return written;
                    }
                    // Non-blank — eat rest of line, then loop to read the next.
                    while (true) {
                        if (!try self.fillStage()) {
                            self.chunked = .finished;
                            return written;
                        }
                        const x = self.popByte();
                        if (x == '\r') {
                            if (!try self.fillStage()) {
                                self.chunked = .finished;
                                return written;
                            }
                            if (self.popByte() != '\n') return Error.BadChunk;
                            break;
                        }
                    }
                },
                .finished => return written,
            }
        }
        return written;
    }
};

pub fn openStream(req: Request, header_buf: []u8, stream: *Stream) Error!void {
    // Normalize URL same as send(): default to https:// when no scheme.
    var url_storage: [MAX_URL]u8 = undefined;
    const has_scheme = std.mem.startsWith(u8, req.url, "http://") or std.mem.startsWith(u8, req.url, "https://");
    var url_slice: []const u8 = undefined;
    if (!has_scheme) {
        const prefix = "https://";
        if (req.url.len + prefix.len > url_storage.len) return Error.BadUrl;
        @memcpy(url_storage[0..prefix.len], prefix);
        @memcpy(url_storage[prefix.len .. prefix.len + req.url.len], req.url);
        url_slice = url_storage[0 .. prefix.len + req.url.len];
    } else {
        if (req.url.len > url_storage.len) return Error.BadUrl;
        @memcpy(url_storage[0..req.url.len], req.url);
        url_slice = url_storage[0..req.url.len];
    }
    const url = try parseUrl(url_slice);

    var conn = try Conn.open(url);
    errdefer conn.close();

    try sendRequestLine(&conn, req.method, url, req.headers, req.body);

    // Recv until we see \r\n\r\n.
    var total: usize = 0;
    var header_end: usize = 0;
    {
        var scanned: usize = 0;
        while (true) {
            if (total >= header_buf.len) return Error.ResponseTooLarge;
            const n = try conn.recv(header_buf[total..]);
            if (n == 0) return Error.BadResponse;
            total += n;
            const scan_start: usize = if (scanned >= 3) scanned - 3 else 0;
            var i = scan_start;
            while (i + 4 <= total) : (i += 1) {
                if (header_buf[i] == '\r' and header_buf[i + 1] == '\n' and header_buf[i + 2] == '\r' and header_buf[i + 3] == '\n') {
                    header_end = i + 4;
                    break;
                }
            }
            if (header_end != 0) break;
            scanned = total;
        }
    }

    var resp: Response = .{
        .status = 0,
        .status_text = "",
        .headers_buf = undefined,
        .n_headers = 0,
        .body = "",
    };
    try parseStatusAndHeaders(header_buf[0..header_end], &resp);

    // Initialize the stream value in place.
    stream.* = .{
        .conn = conn,
        .response_data = resp,
        .mode = undefined,
        .stage = undefined,
        .stage_pos = 0,
        .stage_len = 0,
        .cl_remaining = 0,
        .chunked = .reading_size,
        .chunk_remaining = 0,
        .eof_seen = false,
        .closed = false,
    };

    // Copy any residual body bytes (the ones that landed past the
    // header terminator) into the stage so readChunk sees them first.
    const residual = total - header_end;
    if (residual > 0) {
        if (residual > stream.stage.len) {
            // Headers ate into a too-small header_buf — pathological.
            // Drop residual to keep semantics simple; caller will recv
            // body again from conn (and miss those bytes — error).
            return Error.ResponseTooLarge;
        }
        @memcpy(stream.stage[0..residual], header_buf[header_end..total]);
        stream.stage_len = residual;
    }

    // Decide body framing.
    if (req.method == .HEAD or resp.status == 204 or resp.status == 304) {
        stream.mode = .none;
        return;
    }
    const te = resp.getHeader("Transfer-Encoding");
    const is_chunked = te != null and containsIgnoreCase(te.?, "chunked");
    if (is_chunked) {
        stream.mode = .chunked;
        return;
    }
    if (resp.getHeader("Content-Length")) |v| {
        if (parseU64(stripSpaces(v))) |cl| {
            stream.mode = .content_length;
            stream.cl_remaining = cl;
            return;
        }
    }
    stream.mode = .eof;
}

fn parseU64(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var v: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v *% 10 +% (c - '0');
    }
    return v;
}

// ---------------------------------------------------------------------
// One HTTP exchange — open conn, send request, parse response. No
// retries, no redirect chasing — `send()` wraps this.

fn sendOnce(
    method: Method,
    url: Url,
    extra_headers: []const Header,
    body: []const u8,
    buf: []u8,
) Error!Response {
    var conn = try Conn.open(url);
    defer conn.close();

    try sendRequestLine(&conn, method, url, extra_headers, body);

    // ---- Receive headers ----
    var total: usize = 0;
    var header_end: usize = 0;
    {
        var scanned: usize = 0;
        while (true) {
            if (total >= buf.len) return Error.ResponseTooLarge;
            const n = try conn.recv(buf[total..]);
            if (n == 0) return Error.BadResponse;
            total += n;

            // Scan only newly-arrived bytes for the \r\n\r\n header terminator.
            // Back up 3 in case the boundary straddles a recv split.
            const scan_start: usize = if (scanned >= 3) scanned - 3 else 0;
            var i = scan_start;
            while (i + 4 <= total) : (i += 1) {
                if (buf[i] == '\r' and buf[i + 1] == '\n' and buf[i + 2] == '\r' and buf[i + 3] == '\n') {
                    header_end = i + 4;
                    break;
                }
            }
            if (header_end != 0) break;
            scanned = total;
        }
    }

    // ---- Parse status + headers ----
    var resp: Response = .{
        .status = 0,
        .status_text = "",
        .headers_buf = undefined,
        .n_headers = 0,
        .body = "",
    };
    try parseStatusAndHeaders(buf[0..header_end], &resp);

    // ---- Body framing ----
    // HEAD / 204 / 304 have no body — whatever raced in past the header
    // boundary is part of the *next* response on a keepalive conn, but
    // since we always send Connection: close we just leave it sliced.
    if (method == .HEAD or resp.status == 204 or resp.status == 304) {
        resp.body = buf[header_end..total];
        return resp;
    }

    const te = resp.getHeader("Transfer-Encoding");
    const is_chunked = te != null and containsIgnoreCase(te.?, "chunked");
    const cl_opt: ?u32 = if (resp.getHeader("Content-Length")) |v| parseU32(stripSpaces(v)) else null;

    if (is_chunked) {
        // Drain until terminating "0\r\n\r\n", then collapse chunk frames
        // out of the buffer so resp.body is a contiguous slice.
        const decoded_end = try drainAndDecodeChunked(&conn, buf, header_end, &total);
        resp.body = buf[header_end..decoded_end];
    } else if (cl_opt) |cl| {
        const body_end = header_end + cl;
        if (body_end > buf.len) return Error.ResponseTooLarge;
        while (total < body_end) {
            const n = try conn.recv(buf[total..body_end]);
            if (n == 0) return Error.BadResponse;
            total += n;
        }
        resp.body = buf[header_end..body_end];
    } else {
        // No framing — HTTP/1.0 style "body ends at EOF". Read until peer
        // closes or buffer fills.
        while (total < buf.len) {
            const n = try conn.recv(buf[total..]);
            if (n == 0) break;
            total += n;
        }
        resp.body = buf[header_end..total];
    }

    return resp;
}

// ---------------------------------------------------------------------
// Request formatter. Writes request line + headers + (optional) body
// into a scratch buffer, then ships the whole thing in one send. Keeps
// the wire payload contiguous so SLIRP doesn't split header from body.

fn sendRequestLine(
    conn: *Conn,
    method: Method,
    url: Url,
    extra_headers: []const Header,
    body: []const u8,
) Error!void {
    var scratch: [REQUEST_SCRATCH]u8 = undefined;
    var pos: usize = 0;

    try appendStr(&scratch, &pos, method.str());
    try appendStr(&scratch, &pos, " ");
    try appendStr(&scratch, &pos, url.path);
    try appendStr(&scratch, &pos, " HTTP/1.1\r\nHost: ");
    try appendStr(&scratch, &pos, url.host);
    if ((url.scheme == .http and url.port != 80) or (url.scheme == .https and url.port != 443)) {
        try appendStr(&scratch, &pos, ":");
        try appendU32(&scratch, &pos, url.port);
    }
    try appendStr(&scratch, &pos, "\r\nConnection: close\r\nUser-Agent: zigos-http/0.1\r\n");

    var saw_accept = false;
    var saw_content_length = false;
    for (extra_headers) |h| {
        if (eqlIgnoreCase(h.name, "Accept")) saw_accept = true;
        if (eqlIgnoreCase(h.name, "Content-Length")) saw_content_length = true;
        // Block obvious dupes that we always emit ourselves.
        if (eqlIgnoreCase(h.name, "Host")) continue;
        if (eqlIgnoreCase(h.name, "Connection")) continue;
        if (eqlIgnoreCase(h.name, "User-Agent")) continue;
        try appendStr(&scratch, &pos, h.name);
        try appendStr(&scratch, &pos, ": ");
        try appendStr(&scratch, &pos, h.value);
        try appendStr(&scratch, &pos, "\r\n");
    }
    if (!saw_accept) try appendStr(&scratch, &pos, "Accept: */*\r\n");
    if (body.len > 0 and !saw_content_length) {
        try appendStr(&scratch, &pos, "Content-Length: ");
        try appendU32(&scratch, &pos, @intCast(body.len));
        try appendStr(&scratch, &pos, "\r\n");
    }
    try appendStr(&scratch, &pos, "\r\n");

    // Send headers, then body. Splitting is fine — both go through the
    // same conn.send which guarantees full delivery.
    try conn.send(scratch[0..pos]);
    if (body.len > 0) try conn.send(body);
}

// ---------------------------------------------------------------------
// Status + header parser. Input is the header block including the
// terminating \r\n\r\n. Strict-ish about CRLF; LF-only would also work
// but breaks against pedantic servers, so we don't bother.

fn parseStatusAndHeaders(block: []const u8, resp: *Response) Error!void {
    // Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
    const line_end = std.mem.indexOfScalar(u8, block, '\r') orelse return Error.BadResponse;
    if (line_end + 1 >= block.len or block[line_end + 1] != '\n') return Error.BadResponse;
    const status_line = block[0..line_end];

    const sp1 = std.mem.indexOfScalar(u8, status_line, ' ') orelse return Error.BadResponse;
    const after_v = status_line[sp1 + 1 ..];
    const sp2_rel = std.mem.indexOfScalar(u8, after_v, ' ') orelse after_v.len;
    const status_str = after_v[0..sp2_rel];
    resp.status = parseU16(status_str) orelse return Error.BadResponse;
    if (sp2_rel < after_v.len) {
        resp.status_text = after_v[sp2_rel + 1 ..];
    }

    var pos = line_end + 2;
    while (pos < block.len) {
        // Empty line == end of headers.
        if (pos + 1 < block.len and block[pos] == '\r' and block[pos + 1] == '\n') break;

        const end = std.mem.indexOfScalarPos(u8, block, pos, '\r') orelse return Error.BadResponse;
        if (end + 1 >= block.len or block[end + 1] != '\n') return Error.BadResponse;
        const line = block[pos..end];
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return Error.BadResponse;
        if (resp.n_headers >= MAX_HEADERS) return Error.TooManyHeaders;
        const name = line[0..colon];
        var value = line[colon + 1 ..];
        value = stripSpaces(value);
        resp.headers_buf[resp.n_headers] = .{ .name = name, .value = value };
        resp.n_headers += 1;
        pos = end + 2;
    }
}

// ---------------------------------------------------------------------
// Chunked-transfer decoder. Walks the raw bytes already in `buf` plus
// any new ones we recv(), parsing "<hex>\r\n<data>\r\n" frames and
// shifting data leftward so the final body is one contiguous slice.
//
//   header   chunk_hdr  data  chunk_hdr  data  0\r\n\r\n   <- on wire
//   header   data  data                                    <- after decode
//
// Returns the new logical end (= header_end + total decoded body bytes).

fn drainAndDecodeChunked(
    conn: *Conn,
    buf: []u8,
    header_end: usize,
    total_ptr: *usize,
) Error!usize {
    var read_cursor: usize = header_end; // next raw byte to consume
    var write_cursor: usize = header_end; // next decoded byte to emit
    var saw_terminator = false;

    while (!saw_terminator) {
        // Need a chunk-size line: <hex>[;ext]\r\n
        const size_line_end = try waitForCrlf(conn, buf, read_cursor, total_ptr);

        // Parse hex up to the first non-hex char (could be ';' for extensions
        // we ignore, or '\r' if no extension).
        var size: u32 = 0;
        var i = read_cursor;
        var saw_digit = false;
        while (i < size_line_end) : (i += 1) {
            const c = buf[i];
            const d: ?u8 = if (c >= '0' and c <= '9')
                c - '0'
            else if (c >= 'a' and c <= 'f')
                c - 'a' + 10
            else if (c >= 'A' and c <= 'F')
                c - 'A' + 10
            else
                null;
            if (d) |dv| {
                if (size > 0x0FFFFFFF) return Error.BadChunk;
                size = size * 16 + dv;
                saw_digit = true;
            } else {
                break;
            }
        }
        if (!saw_digit) return Error.BadChunk;

        // Advance past size line + its CRLF.
        read_cursor = size_line_end + 2;

        if (size == 0) {
            // Last chunk. Read the trailing "\r\n" (optionally preceded by
            // trailer headers we ignore — wait for blank-line terminator).
            saw_terminator = true;
            // Hunt for the final \r\n\r\n or just \r\n if no trailers.
            // Simplest: wait until we see a blank CRLF line.
            while (true) {
                // Need at least 2 bytes for CRLF.
                while (read_cursor + 2 > total_ptr.*) {
                    if (total_ptr.* >= buf.len) return Error.ResponseTooLarge;
                    const n = try conn.recv(buf[total_ptr.*..]);
                    if (n == 0) break;
                    total_ptr.* += n;
                }
                if (read_cursor + 2 > total_ptr.*) break;
                if (buf[read_cursor] == '\r' and buf[read_cursor + 1] == '\n') {
                    read_cursor += 2;
                    break;
                }
                // Trailer line — skip to its CRLF and continue.
                const trailer_end = try waitForCrlf(conn, buf, read_cursor, total_ptr);
                read_cursor = trailer_end + 2;
            }
            break;
        }

        // Make sure we have `size + 2` bytes (data + trailing CRLF) buffered.
        const needed_end = read_cursor + size + 2;
        if (needed_end > buf.len) return Error.ResponseTooLarge;
        while (total_ptr.* < needed_end) {
            const n = try conn.recv(buf[total_ptr.*..]);
            if (n == 0) return Error.BadChunk;
            total_ptr.* += n;
        }

        // Move chunk data into the contiguous decoded region.
        if (write_cursor != read_cursor) {
            // Source and dest may overlap when chunks are big and headers
            // were small — memmove semantics needed.
            std.mem.copyForwards(u8, buf[write_cursor .. write_cursor + size], buf[read_cursor .. read_cursor + size]);
        }
        write_cursor += size;
        read_cursor += size;

        // Skip data-trailing CRLF.
        if (buf[read_cursor] != '\r' or buf[read_cursor + 1] != '\n') return Error.BadChunk;
        read_cursor += 2;
    }

    return write_cursor;
}

/// Block until `buf[start..]` contains a CRLF; return the index of the '\r'.
fn waitForCrlf(conn: *Conn, buf: []u8, start: usize, total_ptr: *usize) Error!usize {
    while (true) {
        // Scan what we already have.
        if (total_ptr.* > start + 1) {
            var i = start;
            while (i + 1 < total_ptr.*) : (i += 1) {
                if (buf[i] == '\r' and buf[i + 1] == '\n') return i;
            }
        }
        if (total_ptr.* >= buf.len) return Error.ResponseTooLarge;
        const n = try conn.recv(buf[total_ptr.*..]);
        if (n == 0) return Error.BadChunk;
        total_ptr.* += n;
    }
}

// ---------------------------------------------------------------------
// Tiny formatting helpers. Lifted here rather than imported to keep the
// dependency surface minimal — http.zig sees only libc + std.mem.

fn appendStr(buf: []u8, pos: *usize, s: []const u8) Error!void {
    if (pos.* + s.len > buf.len) return Error.ResponseTooLarge;
    @memcpy(buf[pos.* .. pos.* + s.len], s);
    pos.* += s.len;
}

fn appendU32(buf: []u8, pos: *usize, n: u32) Error!void {
    var tmp: [10]u8 = undefined;
    var v = n;
    var i: usize = tmp.len;
    if (v == 0) {
        i -= 1;
        tmp[i] = '0';
    } else {
        while (v != 0) {
            i -= 1;
            tmp[i] = @intCast('0' + (v % 10));
            v /= 10;
        }
    }
    try appendStr(buf, pos, tmp[i..]);
}

fn parseU16(s: []const u8) ?u16 {
    if (s.len == 0) return null;
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
        if (v > 65535) return null;
    }
    return @intCast(v);
}

fn parseU32(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    var v: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
        if (v > 0xFFFFFFFF) return null;
    }
    return @intCast(v);
}

fn stripSpaces(s: []const u8) []const u8 {
    var start: usize = 0;
    var end: usize = s.len;
    while (start < end and (s[start] == ' ' or s[start] == '\t')) start += 1;
    while (end > start and (s[end - 1] == ' ' or s[end - 1] == '\t')) end -= 1;
    return s[start..end];
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (lower(a[i]) != lower(b[i])) return false;
    }
    return true;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

inline fn lower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}
