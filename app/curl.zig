// curl — fetch a URL and dump the body to stdout. Streaming version;
// arbitrary response size, decoded one chunk at a time.
//
// Usage:
//   curl <url>          GET, body to stdout
//   curl -i <url>       include status line + headers in output
//   curl -L <url>       follow 3xx redirects (absolute Location only)
//
// Built on lib/http.zig streaming API. We hold a 16 KiB header_buf for
// the response head and a 4 KiB read window for the body; total
// footprint is ~28 KiB no matter how big the response.

const libc = @import("libc");
const http = @import("http");

const HEADER_BUF_SIZE: usize = 16 * 1024;
const BODY_CHUNK: usize = 4096;
const MAX_FOLLOWS: u8 = 5;

var header_buf: [HEADER_BUF_SIZE]u8 = undefined;
var url_storage: [http.MAX_URL]u8 = undefined;

fn copyArg(idx: u32, buf: []u8) ?[]u8 {
    const n = libc.getArgv(idx, buf);
    if (n == 0 or n == 0xFFFFFFFF) return null;
    return buf[0..n];
}

fn streq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |c, i| if (c != b[i]) return false;
    return true;
}

fn errorName(err: http.Error) []const u8 {
    return switch (err) {
        error.BadUrl => "bad URL",
        error.UnsupportedScheme => "scheme not http/https",
        error.DnsFailure => "DNS lookup failed",
        error.ConnectFailure => "TCP connect failed",
        error.TlsFailure => "TLS handshake failed",
        error.SendFailure => "send failed",
        error.RecvFailure => "receive failed",
        error.BadResponse => "malformed response",
        error.BufferTooSmall => "buffer too small",
        error.TooManyRedirects => "too many redirects",
        error.TooManyHeaders => "too many headers",
        error.ResponseTooLarge => "response headers exceed buffer",
        error.BadChunk => "bad chunked encoding",
        error.StreamClosed => "stream closed",
    };
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    if (libc.getArgc() < 2) {
        libc.print("\x1b[31mcurl: missing URL\x1b[0m\n");
        libc.print("usage: curl [-i] [-L] <url>\n");
        libc.exit();
    }

    var show_headers = false;
    var follow = false;
    var url_arg: ?[]u8 = null;

    var i: u32 = 1;
    while (i < libc.getArgc()) : (i += 1) {
        var argbuf: [http.MAX_URL]u8 = undefined;
        const arg = copyArg(i, &argbuf) orelse continue;
        if (streq(arg, "-i") or streq(arg, "--include")) {
            show_headers = true;
        } else if (streq(arg, "-L") or streq(arg, "--location")) {
            follow = true;
        } else {
            if (arg.len > url_storage.len) {
                libc.print("\x1b[31mcurl: URL too long\x1b[0m\n");
                libc.exit();
            }
            @memcpy(url_storage[0..arg.len], arg);
            url_arg = url_storage[0..arg.len];
        }
    }

    const initial_url = url_arg orelse {
        libc.print("\x1b[31mcurl: missing URL\x1b[0m\n");
        libc.exit();
    };

    // Redirect loop. Re-opens a fresh stream per hop because TLS conns
    // and chunked decoders aren't resumable.
    var current_url: []const u8 = initial_url;
    var follows: u8 = 0;
    var stream: http.Stream = undefined;

    while (true) {
        http.openStream(.{ .url = current_url }, &header_buf, &stream) catch |err| {
            libc.print("\x1b[31mcurl: ");
            libc.print(errorName(err));
            libc.print("\x1b[0m\n");
            libc.exit();
        };

        const resp = stream.response();
        if (follow and resp.status >= 300 and resp.status < 400 and resp.status != 304) {
            const loc = resp.getHeader("Location") orelse {
                break;
            };
            // Only absolute redirects in v1 — relative ones need URL
            // composition.
            const is_abs = (loc.len >= 7 and (loc[0] == 'h' or loc[0] == 'H'));
            if (!is_abs or loc.len > url_storage.len) {
                break;
            }
            follows += 1;
            if (follows > MAX_FOLLOWS) {
                stream.close();
                libc.print("\x1b[31mcurl: too many redirects\x1b[0m\n");
                libc.exit();
            }
            // Save loc into url_storage; header_buf gets reused next hop.
            @memcpy(url_storage[0..loc.len], loc);
            current_url = url_storage[0..loc.len];
            stream.close();
            continue;
        }
        break;
    }

    defer stream.close();
    const resp = stream.response();

    if (show_headers) {
        libc.print("HTTP/1.1 ");
        libc.printNum(resp.status);
        libc.printChar(' ');
        libc.print(resp.status_text);
        libc.print("\r\n");
        for (resp.headers()) |h| {
            libc.print(h.name);
            libc.print(": ");
            libc.print(h.value);
            libc.print("\r\n");
        }
        libc.print("\r\n");
    }

    var total: usize = 0;
    var last_byte: u8 = 0;
    var chunk: [BODY_CHUNK]u8 = undefined;
    while (true) {
        const n = stream.readChunk(&chunk) catch |err| {
            libc.print("\n\x1b[31mcurl: ");
            libc.print(errorName(err));
            libc.print("\x1b[0m\n");
            libc.exit();
        };
        if (n == 0) break;
        _ = libc.fwrite(1, chunk[0..n]);
        last_byte = chunk[n - 1];
        total += n;
    }
    if (total > 0 and last_byte != '\n') libc.printChar('\n');

    libc.print("\x1b[2m--- ");
    libc.printNum(@intCast(total));
    libc.print(" bytes, status ");
    libc.printNum(resp.status);
    libc.print(" ---\x1b[0m\n");
    libc.exit();
}
