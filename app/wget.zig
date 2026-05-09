// wget — fetch a URL and print the HTTP response to stdout.
//
// Usage:
//   wget http://example.com/             — print the full response
//   wget http://example.com/ > page.html — save to a file
//   wget http://example.com/ | head      — preview the first lines
//
// The response includes the status line + headers + body verbatim. Filtering
// for the body (or the status code) is the caller's job — that's what the
// shell's pipe + redirect machinery is for.

const libc = @import("libc");

const RESPONSE_BUF_SIZE: usize = 32 * 1024;

export fn _start() linksection(".text.entry") callconv(.c) void {
    if (libc.getArgc() < 2) {
        libc.print("\x1b[31mwget: missing URL\x1b[0m\n");
        libc.print("usage: wget <url>\n");
        libc.exit();
    }

    var url_buf: [512]u8 = undefined;
    const url_len = libc.getArgv(1, &url_buf);
    if (url_len == 0 or url_len == 0xFFFFFFFF) {
        libc.print("\x1b[31mwget: empty URL\x1b[0m\n");
        libc.exit();
    }
    const url = url_buf[0..url_len];

    const buf_ptr = libc.malloc(RESPONSE_BUF_SIZE) orelse {
        libc.print("\x1b[31mwget: out of memory\x1b[0m\n");
        libc.exit();
    };
    const buf = buf_ptr[0..RESPONSE_BUF_SIZE];

    const n = libc.httpGet(url, buf) orelse {
        libc.print("\x1b[31mwget: request failed (network down? bad URL?)\x1b[0m\n");
        libc.free(buf_ptr);
        libc.exit();
    };

    _ = libc.fwrite(1, buf[0..n]);
    libc.free(buf_ptr);
    libc.exit();
}
