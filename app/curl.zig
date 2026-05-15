// curl — fetch a URL and dump the body to stdout.
//
// Usage:
//   curl <url>
//   curl -i <url>      (include headers in output)
//   curl -L <url>      (follow redirects — default on)
//   curl --no-follow <url>  (return the 3xx response itself)
//
// Built on lib/http.zig, which routes to TLS for https:// and plain
// TCP for http://. The whole response materializes into a 64 KiB
// buffer; bigger payloads return ResponseTooLarge.

const libc = @import("libc");
const http = @import("http");

const BUF_SIZE: usize = 64 * 1024;
var resp_buf: [BUF_SIZE]u8 = undefined;

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
        error.ResponseTooLarge => "response exceeds 64 KiB buffer",
        error.BadChunk => "bad chunked encoding",
    };
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    if (libc.getArgc() < 2) {
        libc.print("\x1b[31mcurl: missing URL\x1b[0m\n");
        libc.print("usage: curl [-i] [--no-follow] <url>\n");
        libc.exit();
    }

    var show_headers = false;
    var follow = true;
    var url_arg: ?[]u8 = null;
    var url_buf: [http.MAX_URL]u8 = undefined;

    var i: u32 = 1;
    while (i < libc.getArgc()) : (i += 1) {
        var argbuf: [http.MAX_URL]u8 = undefined;
        const arg = copyArg(i, &argbuf) orelse continue;
        if (streq(arg, "-i") or streq(arg, "--include")) {
            show_headers = true;
        } else if (streq(arg, "-L") or streq(arg, "--location")) {
            follow = true;
        } else if (streq(arg, "--no-follow")) {
            follow = false;
        } else {
            if (arg.len > url_buf.len) {
                libc.print("\x1b[31mcurl: URL too long\x1b[0m\n");
                libc.exit();
            }
            @memcpy(url_buf[0..arg.len], arg);
            url_arg = url_buf[0..arg.len];
        }
    }

    const url = url_arg orelse {
        libc.print("\x1b[31mcurl: missing URL\x1b[0m\n");
        libc.exit();
    };

    const resp = http.send(.{
        .method = .GET,
        .url = url,
        .follow_redirects = follow,
    }, &resp_buf) catch |err| {
        libc.print("\x1b[31mcurl: ");
        libc.print(errorName(err));
        libc.print("\x1b[0m\n");
        libc.exit();
    };

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

    _ = libc.fwrite(1, resp.body);
    if (resp.body.len > 0 and resp.body[resp.body.len - 1] != '\n') libc.printChar('\n');

    libc.print("\x1b[2m--- ");
    libc.printNum(@intCast(resp.body.len));
    libc.print(" bytes, status ");
    libc.printNum(resp.status);
    libc.print(" ---\x1b[0m\n");
    libc.exit();
}
