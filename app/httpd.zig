// httpd — minimal HTTP/1.0 server. Serves files from a configurable doc-root.
//
// Usage:
//   httpd                       (port 8080, doc-root /share/)
//   httpd 8000                  (custom port, default doc-root)
//   httpd 8080 /home/me/site    (custom port + custom doc-root)
//
// One connection at a time, no concurrency, no chunked transfer, no keepalive,
// no MIME guessing beyond a small extension table. Good enough to render a
// hand-written HTML page in your host browser if you forward the QEMU port.
//
// To make pages reachable from the host machine, launch QEMU with a
// hostfwd, e.g. -netdev user,id=net0,hostfwd=tcp::8080-:8080 — then point a
// browser at http://localhost:8080/.

const libc = @import("libc");

const DEFAULT_PORT: u16 = 8080;
/// Default doc-root. Was "/fat/" in the FAT32-as-primary era; ext2 is now
/// the root mount and `share/index.html` is the sample page baked into the
/// disk image, so "/share/" matches what's actually there. Override with
/// argv[2] if you keep your site somewhere else.
const DEFAULT_DOC_ROOT = "/share/";
const REQUEST_BUF: usize = 4 * 1024;
const READ_TIMEOUT_ITERS: u32 = 100; // 100 × 30ms = 3s
const ACCEPT_IDLE_MS: u32 = 30;

/// Active doc-root (init from DEFAULT_DOC_ROOT, optionally overridden by
/// argv[2]). Stored as a slice into a small static buffer so it lives for
/// the entire process lifetime — handleConn just concatenates against it.
var doc_root_buf: [128]u8 = undefined;
var doc_root: []const u8 = undefined;

var should_quit: bool = false;

export fn handleSigint(signo: u32, info: *anyopaque, uc: *anyopaque) void {
    _ = signo;
    _ = info;
    _ = uc;
    const flag: *volatile bool = &should_quit;
    flag.* = true;
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

fn equals(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (x != y) return false;
    return true;
}

fn endsWith(s: []const u8, suffix: []const u8) bool {
    if (s.len < suffix.len) return false;
    return equals(s[s.len - suffix.len ..], suffix);
}

/// Identify the response Content-Type by file extension. Returning a
/// generic stream type for unknowns is safer than guessing — modern
/// browsers won't sniff into surprising things.
fn contentType(path: []const u8) []const u8 {
    if (endsWith(path, ".html") or endsWith(path, ".htm")) return "text/html";
    if (endsWith(path, ".txt") or endsWith(path, ".md")) return "text/plain";
    if (endsWith(path, ".css")) return "text/css";
    if (endsWith(path, ".js")) return "application/javascript";
    if (endsWith(path, ".json")) return "application/json";
    if (endsWith(path, ".png")) return "image/png";
    if (endsWith(path, ".jpg") or endsWith(path, ".jpeg")) return "image/jpeg";
    if (endsWith(path, ".gif")) return "image/gif";
    if (endsWith(path, ".svg")) return "image/svg+xml";
    return "application/octet-stream";
}

/// Format a small unsigned integer into `out` and return the populated slice.
/// Used for Content-Length headers; no allocator needed.
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

fn formatU64(out: []u8, n: u64) []const u8 {
    if (n == 0) {
        out[0] = '0';
        return out[0..1];
    }
    var tmp: [20]u8 = undefined;
    var i: usize = 0;
    var v = n;
    while (v > 0) : (i += 1) {
        tmp[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
    for (0..i) |j| out[j] = tmp[i - 1 - j];
    return out[0..i];
}

fn startsWith(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    return equals(s[0..prefix.len], prefix);
}

// --- JSON response builder ---
// Single-threaded server, so a static scratch buffer is fine. Each route
// resets it, writes its body, and the result lives until the next call.
// 8 KB is enough for all 32 process slots emitted as JSON; smaller routes
// are cheap to over-allocate.
var json_buf: [8192]u8 = undefined;
var json_len: usize = 0;

fn jsonReset() void {
    json_len = 0;
}

fn jsonStr(s: []const u8) void {
    if (json_len + s.len > json_buf.len) return;
    @memcpy(json_buf[json_len..][0..s.len], s);
    json_len += s.len;
}

fn jsonU32(n: u32) void {
    var nbuf: [12]u8 = undefined;
    jsonStr(formatU32(&nbuf, n));
}

fn jsonU64(n: u64) void {
    var nbuf: [20]u8 = undefined;
    jsonStr(formatU64(&nbuf, n));
}

fn jsonResult() []const u8 {
    return json_buf[0..json_len];
}

/// Drain the request line + headers from `conn`. We only care about the
/// first line (`GET /path HTTP/1.x`), so once we see `\r\n\r\n` we stop.
/// Also bails immediately when `should_quit` flips — so a client that
/// connected then went silent doesn't extend Ctrl+C latency by 3 s.
fn readRequest(conn: u8, buf: []u8) ?usize {
    var total: usize = 0;
    var iters: u32 = 0;
    while (iters < READ_TIMEOUT_ITERS) : (iters += 1) {
        const quit: *volatile bool = &should_quit;
        if (quit.*) return null;

        const n = libc.tcpRecv(conn, buf[total..]);
        if (n > 0) {
            total += n;
            if (total >= 4) {
                var i: usize = 0;
                while (i + 3 < total) : (i += 1) {
                    if (buf[i] == '\r' and buf[i + 1] == '\n' and
                        buf[i + 2] == '\r' and buf[i + 3] == '\n')
                    {
                        return total;
                    }
                }
            }
            if (total >= buf.len) return total;
        }
        const st = libc.tcpStatus(conn);
        if ((st & libc.TCP_STATUS_PEER_CLOSED) != 0 and n == 0) {
            return if (total > 0) total else null;
        }
        libc.sleep(30);
    }
    return null;
}

/// Extract the path from `GET /path HTTP/1.0`. Trailing `?query` is stripped
/// because we don't have any dynamic handling. Caller passes a buffer; we
/// write the path into it and return the slice.
fn parsePath(req: []const u8, out: []u8) ?usize {
    var i: usize = 0;
    // Method
    while (i < req.len and req[i] != ' ') i += 1;
    if (i + 1 >= req.len) return null;
    i += 1;
    const path_start = i;
    while (i < req.len and req[i] != ' ' and req[i] != '\r' and req[i] != '?') i += 1;
    const path_len = i - path_start;
    if (path_len == 0 or path_len > out.len) return null;
    @memcpy(out[0..path_len], req[path_start..i]);
    return path_len;
}

/// Reject paths that try to escape DOC_ROOT via "..", "//", or NUL bytes.
/// Returns false for anything we don't want to honor.
fn isSafePath(p: []const u8) bool {
    if (p.len == 0 or p[0] != '/') return false;
    var i: usize = 0;
    while (i < p.len) : (i += 1) {
        if (p[i] == 0) return false;
        if (p[i] == '/' and i + 1 < p.len and p[i + 1] == '/') return false;
        if (p[i] == '/' and i + 2 < p.len and p[i + 1] == '.' and p[i + 2] == '.') return false;
    }
    return true;
}

fn sendStatus(conn: u8, line: []const u8) void {
    _ = libc.tcpSend(conn, "HTTP/1.0 ");
    _ = libc.tcpSend(conn, line);
    _ = libc.tcpSend(conn, "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
}

fn sendNotFound(conn: u8) void {
    sendStatus(conn, "404 Not Found");
}

fn sendBadRequest(conn: u8) void {
    sendStatus(conn, "400 Bad Request");
}

/// Send a JSON body with HTTP/1.0 200 + Content-Length + close.
fn sendJsonResponse(conn: u8, body: []const u8) void {
    var len_buf: [16]u8 = undefined;
    const len_str = formatU32(&len_buf, @intCast(body.len));
    _ = libc.tcpSend(conn, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ");
    _ = libc.tcpSend(conn, len_str);
    _ = libc.tcpSend(conn, "\r\nConnection: close\r\n\r\n");
    _ = libc.tcpSend(conn, body);
}

/// Plain-text variant of sendJsonResponse for endpoints that don't benefit
/// from JSON wrapping (e.g. raw log dumps that the client renders into a
/// <pre>). Same Content-Length / no-store / CORS headers.
fn sendTextResponse(conn: u8, body: []const u8) void {
    var len_buf: [16]u8 = undefined;
    const len_str = formatU32(&len_buf, @intCast(body.len));
    _ = libc.tcpSend(conn, "HTTP/1.0 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ");
    _ = libc.tcpSend(conn, len_str);
    _ = libc.tcpSend(conn, "\r\nConnection: close\r\n\r\n");
    _ = libc.tcpSend(conn, body);
}

// --- API route bodies. Each rebuilds json_buf and returns the slice. ---

fn apiUptime() []const u8 {
    const ticks = libc.uptime();
    jsonReset();
    jsonStr("{\"ticks\":");
    jsonU32(ticks);
    jsonStr(",\"seconds\":");
    jsonU32(ticks / 100);
    jsonStr("}");
    return jsonResult();
}

fn apiMeminfo() []const u8 {
    const m = libc.meminfo();
    // PMM tracks 4KB pages.
    const free_bytes: u64 = @as(u64, m.free_frames) * 4096;
    const total_bytes: u64 = @as(u64, m.total_frames) * 4096;
    const used_pct: u32 = if (m.total_frames == 0) 0 else
        @intCast(((@as(u64, m.total_frames - m.free_frames)) * 100) / m.total_frames);
    jsonReset();
    jsonStr("{\"free_pages\":");
    jsonU32(m.free_frames);
    jsonStr(",\"total_pages\":");
    jsonU32(m.total_frames);
    jsonStr(",\"free_bytes\":");
    jsonU64(free_bytes);
    jsonStr(",\"total_bytes\":");
    jsonU64(total_bytes);
    jsonStr(",\"used_pct\":");
    jsonU32(used_pct);
    jsonStr("}");
    return jsonResult();
}

fn apiTime() []const u8 {
    const t = libc.gettimeofday();
    jsonReset();
    jsonStr("{\"sec\":");
    jsonU64(t.sec);
    jsonStr(",\"usec\":");
    jsonU32(t.usec);
    jsonStr("}");
    return jsonResult();
}

fn apiScreen() []const u8 {
    const s = libc.getScreenSize();
    jsonReset();
    jsonStr("{\"w\":");
    jsonU32(s.w);
    jsonStr(",\"h\":");
    jsonU32(s.h);
    jsonStr("}");
    return jsonResult();
}

fn apiProcs() []const u8 {
    var procs: [32]libc.ProcInfo = undefined;
    const n = libc.processList(&procs);

    jsonReset();
    jsonStr("{\"procs\":[");
    for (0..n) |i| {
        if (i > 0) jsonStr(",");
        const p = procs[i];
        jsonStr("{\"pid\":");
        jsonU32(p.pid);
        jsonStr(",\"ppid\":");
        jsonU32(p.parent_pid);
        jsonStr(",\"state\":\"");
        const state_name = switch (p.state) {
            libc.PROC_STATE_UNUSED => "unused",
            libc.PROC_STATE_READY => "ready",
            libc.PROC_STATE_RUNNING => "running",
            libc.PROC_STATE_SLEEPING => "sleep",
            libc.PROC_STATE_ZOMBIE => "zombie",
            else => "unknown",
        };
        jsonStr(state_name);
        jsonStr("\",\"priority\":\"");
        const prio_name = switch (p.priority) {
            libc.PROC_PRIO_BACKGROUND => "background",
            libc.PROC_PRIO_NORMAL => "normal",
            libc.PROC_PRIO_INTERACTIVE => "interactive",
            else => "unknown",
        };
        jsonStr(prio_name);
        jsonStr("\",\"cpu\":");
        jsonU32(p.last_cpu);
        jsonStr(",\"ticks\":");
        jsonU32(p.ticks_used);
        jsonStr(",\"tgid\":");
        jsonU32(p.tgid);
        jsonStr(",\"pgid\":");
        jsonU32(p.pgid);
        jsonStr(",\"sid\":");
        jsonU32(p.sid);
        jsonStr(",\"name\":\"");
        if (p.name_len > 0 and p.name_len <= 16) {
            jsonStr(p.name[0..p.name_len]);
        }
        jsonStr("\"}");
    }
    jsonStr("]}");
    return jsonResult();
}

fn apiAll() []const u8 {
    const ticks = libc.uptime();
    const m = libc.meminfo();
    const t = libc.gettimeofday();
    const s = libc.getScreenSize();
    const free_bytes: u64 = @as(u64, m.free_frames) * 4096;
    const total_bytes: u64 = @as(u64, m.total_frames) * 4096;
    const used_pct: u32 = if (m.total_frames == 0) 0 else
        @intCast(((@as(u64, m.total_frames - m.free_frames)) * 100) / m.total_frames);

    jsonReset();
    jsonStr("{\"uptime\":{\"ticks\":");
    jsonU32(ticks);
    jsonStr(",\"seconds\":");
    jsonU32(ticks / 100);
    jsonStr("},\"mem\":{\"free_pages\":");
    jsonU32(m.free_frames);
    jsonStr(",\"total_pages\":");
    jsonU32(m.total_frames);
    jsonStr(",\"free_bytes\":");
    jsonU64(free_bytes);
    jsonStr(",\"total_bytes\":");
    jsonU64(total_bytes);
    jsonStr(",\"used_pct\":");
    jsonU32(used_pct);
    jsonStr("},\"time\":{\"sec\":");
    jsonU64(t.sec);
    jsonStr(",\"usec\":");
    jsonU32(t.usec);
    jsonStr("},\"screen\":{\"w\":");
    jsonU32(s.w);
    jsonStr(",\"h\":");
    jsonU32(s.h);
    jsonStr("}}");
    return jsonResult();
}

/// Dispatch /api/* routes. `route` is the path segment after /api/.
/// Returns true if a route was matched (and a response sent), false to fall
/// through to file serving.
fn handleApi(conn: u8, route: []const u8) bool {
    if (equals(route, "uptime")) {
        sendJsonResponse(conn, apiUptime());
        return true;
    }
    if (equals(route, "meminfo")) {
        sendJsonResponse(conn, apiMeminfo());
        return true;
    }
    if (equals(route, "time")) {
        sendJsonResponse(conn, apiTime());
        return true;
    }
    if (equals(route, "screen")) {
        sendJsonResponse(conn, apiScreen());
        return true;
    }
    if (equals(route, "all")) {
        sendJsonResponse(conn, apiAll());
        return true;
    }
    if (equals(route, "procs")) {
        sendJsonResponse(conn, apiProcs());
        return true;
    }
    if (equals(route, "log")) {
        sendTextResponse(conn, apiLog());
        return true;
    }
    return false;
}

/// Drain a recent slice of the kernel klog ring into json_buf and return
/// it as plain text. We open /dev/kmsg fresh each request and read into
/// json_buf directly (saves one buffer); the client renders it as <pre>.
///
/// The kernel's stream cursor is per-fd, so opening + reading + closing
/// each request gives us "everything currently in the ring" each time.
/// Old bytes scroll out as new ones come in — same semantics as `dmesg`.
fn apiLog() []const u8 {
    json_len = 0;
    const fd = libc.open("/dev/kmsg") orelse return json_buf[0..0];
    defer libc.close(fd);

    // Drain into json_buf in chunks, leaving a small headroom in case the
    // kernel ring grew while we were reading.
    const cap: usize = json_buf.len - 64;
    while (json_len < cap) {
        const n = libc.fread(fd, json_buf[json_len..cap]);
        if (n == 0 or n == 0xFFFFFFFF) break;
        json_len += n;
    }
    return json_buf[0..json_len];
}

fn serveFile(conn: u8, doc_path: []const u8, ctype: []const u8) void {
    const size = libc.fsize(doc_path) orelse {
        sendNotFound(conn);
        return;
    };
    const buf_ptr = libc.malloc(size) orelse {
        sendStatus(conn, "500 Out of Memory");
        return;
    };
    defer libc.free(buf_ptr);
    const buf = buf_ptr[0..size];

    const fd = libc.open(doc_path) orelse {
        sendNotFound(conn);
        return;
    };
    defer libc.close(fd);

    var total: usize = 0;
    while (total < size) {
        const n = libc.fread(fd, buf[total..]);
        if (n == 0) break;
        total += n;
    }

    var len_buf: [16]u8 = undefined;
    const len_str = formatU32(&len_buf, @intCast(total));

    _ = libc.tcpSend(conn, "HTTP/1.0 200 OK\r\nContent-Type: ");
    _ = libc.tcpSend(conn, ctype);
    _ = libc.tcpSend(conn, "\r\nContent-Length: ");
    _ = libc.tcpSend(conn, len_str);
    _ = libc.tcpSend(conn, "\r\nConnection: close\r\n\r\n");
    _ = libc.tcpSend(conn, buf[0..total]);
}

fn handleConn(conn: u8) void {
    var req_buf: [REQUEST_BUF]u8 = undefined;
    const req_len = readRequest(conn, &req_buf) orelse {
        sendBadRequest(conn);
        return;
    };

    var path_buf: [128]u8 = undefined;
    const path_len = parsePath(req_buf[0..req_len], &path_buf) orelse {
        sendBadRequest(conn);
        return;
    };
    var path = path_buf[0..path_len];

    if (!isSafePath(path)) {
        sendBadRequest(conn);
        return;
    }

    // /api/* routes return JSON describing live kernel state. Anything else
    // falls through to FAT32 file serving below.
    if (startsWith(path, "/api/")) {
        if (handleApi(conn, path[5..])) return;
        sendNotFound(conn);
        return;
    }

    // Map / -> /index.html so the bare URL renders something.
    if (path.len == 1 and path[0] == '/') {
        @memcpy(path_buf[0..11], "/index.html");
        path = path_buf[0..11];
    }

    // Compose the on-disk path: doc_root (with trailing slash) + path[1..].
    var doc_buf: [192]u8 = undefined;
    if (doc_root.len + path.len > doc_buf.len) {
        sendBadRequest(conn);
        return;
    }
    @memcpy(doc_buf[0..doc_root.len], doc_root);
    @memcpy(doc_buf[doc_root.len..][0 .. path.len - 1], path[1..]);
    const doc_path = doc_buf[0 .. doc_root.len + path.len - 1];

    serveFile(conn, doc_path, contentType(path));
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    // Detect leading "-d" flag — if present, shift port/docroot indices by 1
    // so `httpd -d 8080 /share/` parses the same as `httpd 8080 /share/` for
    // the rest of this function. The actual daemonize() call happens once
    // we've parsed args, so a bad port still surfaces an error to the shell.
    var daemonize: bool = false;
    var arg_off: u32 = 0;
    if (libc.getArgc() >= 2) {
        var flag_buf: [4]u8 = undefined;
        const fl = libc.getArgv(1, &flag_buf);
        if (fl == 2 and flag_buf[0] == '-' and flag_buf[1] == 'd') {
            daemonize = true;
            arg_off = 1;
        }
    }

    var port: u16 = DEFAULT_PORT;
    if (libc.getArgc() >= 2 + arg_off) {
        var arg_buf: [16]u8 = undefined;
        const arg_len = libc.getArgv(1 + arg_off, &arg_buf);
        if (arg_len != 0 and arg_len != 0xFFFFFFFF) {
            port = parseU16(arg_buf[0..arg_len]) orelse {
                libc.print("\x1b[31mhttpd: bad port\x1b[0m\n");
                libc.exit();
            };
        }
    }

    // Doc-root: argv[2 + arg_off] if present, else DEFAULT_DOC_ROOT. Ensure
    // trailing slash so the simple `doc_root + path[1..]` concat works
    // without re-checking the boundary. Caller can pass either form.
    if (libc.getArgc() >= 3 + arg_off) {
        const arg_len = libc.getArgv(2 + arg_off, &doc_root_buf);
        if (arg_len != 0 and arg_len != 0xFFFFFFFF and arg_len < doc_root_buf.len - 1) {
            var n: usize = arg_len;
            if (doc_root_buf[n - 1] != '/') {
                doc_root_buf[n] = '/';
                n += 1;
            }
            doc_root = doc_root_buf[0..n];
        } else {
            @memcpy(doc_root_buf[0..DEFAULT_DOC_ROOT.len], DEFAULT_DOC_ROOT);
            doc_root = doc_root_buf[0..DEFAULT_DOC_ROOT.len];
        }
    } else {
        @memcpy(doc_root_buf[0..DEFAULT_DOC_ROOT.len], DEFAULT_DOC_ROOT);
        doc_root = doc_root_buf[0..DEFAULT_DOC_ROOT.len];
    }

    // Daemonize BEFORE binding the listen socket — otherwise the temporary
    // pre-fork process would acquire and then leak the bound port when it
    // exits as part of daemon()'s double-fork. After daemon() returns 0 we
    // are the detached grandchild; the shell sees the immediate child exit
    // 0 and returns immediately to its prompt.
    if (daemonize) {
        libc.print("httpd: detaching as daemon (port ");
        libc.printNum(port);
        libc.print(")\n");
        const drc = libc.daemon(true, true);
        if (drc != 0) {
            libc.print("\x1b[31mhttpd: daemon() failed\x1b[0m\n");
            libc.exit();
        }
    }

    var act: libc.SigAction = .{ .handler = @intFromPtr(&handleSigint) };
    _ = libc.sigaction(libc.SIGINT, &act, null);

    const lst = libc.tcpListen(port) orelse {
        libc.print("\x1b[31mhttpd: cannot bind port\x1b[0m\n");
        libc.exit();
    };

    libc.print("\x1b[32mhttpd\x1b[0m listening on port ");
    libc.printNum(port);
    libc.print(", serving ");
    libc.print(doc_root);
    libc.print(" — Ctrl+C to stop\n");

    while (true) {
        const quit: *volatile bool = &should_quit;
        if (quit.*) break;

        if (libc.tcpAccept(lst)) |conn| {
            libc.print("[httpd] accepted slot=");
            libc.printNum(conn);
            libc.printChar('\n');
            handleConn(conn);
            libc.tcpClose(conn);
        } else {
            libc.sleep(ACCEPT_IDLE_MS);
        }
    }

    libc.tcpUnlisten(lst);
    libc.print("\nhttpd: shutting down\n");
    libc.exit();
}
