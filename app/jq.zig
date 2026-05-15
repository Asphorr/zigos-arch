// jq — fetch a URL (or read /tmp blob), parse JSON, pretty-print or
// extract one path.
//
// Usage:
//   jq <url>              dump the whole tree
//   jq <url> <path>       walk path, print value
//
// Path syntax (minimal):
//   .foo         object key "foo"
//   .foo.bar     object key "foo", then key "bar"
//   .foo[3]      object key "foo", then array index 3
//   [3]          top-level array index 3
//
// No streaming — the full body must fit in the 64 KiB response buffer
// and the entire JSON tree lives in malloc'd heap until we exit.

const libc = @import("libc");
const http = @import("http");
const json = @import("json");

const BUF_SIZE: usize = 64 * 1024;
var resp_buf: [BUF_SIZE]u8 = undefined;

fn copyArg(idx: u32, buf: []u8) ?[]u8 {
    const n = libc.getArgv(idx, buf);
    if (n == 0 or n == 0xFFFFFFFF) return null;
    return buf[0..n];
}

fn dumpValue(v: json.Value, indent: u32) void {
    switch (v) {
        .null_ => libc.print("null"),
        .bool_ => |b| libc.print(if (b) "true" else "false"),
        .int => |n| {
            if (n < 0) {
                libc.printChar('-');
                libc.printNum(@intCast(-n));
            } else {
                libc.printNum(@intCast(n));
            }
        },
        .number => |f| {
            // No float-to-string in libc; print as int + ".???" approximation.
            const i: i64 = @intFromFloat(f);
            if (i < 0) {
                libc.printChar('-');
                libc.printNum(@intCast(-i));
            } else {
                libc.printNum(@intCast(i));
            }
            // Drop the fractional digits for now — real fmt comes when we
            // teach libc.printNum about floats.
            libc.print(".?");
        },
        .string => |s| {
            libc.printChar('"');
            libc.print(s);
            libc.printChar('"');
        },
        .array => |items| {
            if (items.len == 0) {
                libc.print("[]");
                return;
            }
            libc.print("[\n");
            for (items, 0..) |it, i| {
                printIndent(indent + 1);
                dumpValue(it, indent + 1);
                if (i + 1 < items.len) libc.printChar(',');
                libc.printChar('\n');
            }
            printIndent(indent);
            libc.printChar(']');
        },
        .object => |fields| {
            if (fields.len == 0) {
                libc.print("{}");
                return;
            }
            libc.print("{\n");
            for (fields, 0..) |f, i| {
                printIndent(indent + 1);
                libc.printChar('"');
                libc.print(f.name);
                libc.print("\": ");
                dumpValue(f.value, indent + 1);
                if (i + 1 < fields.len) libc.printChar(',');
                libc.printChar('\n');
            }
            printIndent(indent);
            libc.printChar('}');
        },
    }
}

fn printIndent(n: u32) void {
    var i: u32 = 0;
    while (i < n) : (i += 1) libc.print("  ");
}

/// Walk `value` along `path` ("." separated keys with optional [N]
/// array indices). Returns null if any step misses.
fn queryPath(value: json.Value, path: []const u8) ?json.Value {
    var v = value;
    var i: usize = 0;
    while (i < path.len) {
        const c = path[i];
        if (c == '.') {
            i += 1;
            const start = i;
            while (i < path.len and path[i] != '.' and path[i] != '[') : (i += 1) {}
            const key = path[start..i];
            if (key.len == 0) continue; // ".." or trailing "."
            v = v.get(key) orelse return null;
        } else if (c == '[') {
            i += 1;
            const start = i;
            while (i < path.len and path[i] != ']') : (i += 1) {}
            if (i >= path.len) return null;
            const idx_s = path[start..i];
            i += 1; // skip ']'
            var idx: usize = 0;
            for (idx_s) |dc| {
                if (dc < '0' or dc > '9') return null;
                idx = idx * 10 + (dc - '0');
            }
            v = v.at(idx) orelse return null;
        } else {
            return null;
        }
    }
    return v;
}

export fn _start() linksection(".text.entry") callconv(.c) void {
    if (libc.getArgc() < 2) {
        libc.print("\x1b[31mjq: missing URL\x1b[0m\n");
        libc.print("usage: jq <url> [path]\n");
        libc.print("  path: .foo.bar  /  [0]  /  .users[2].name\n");
        libc.exit();
    }

    var url_buf: [http.MAX_URL]u8 = undefined;
    const url = copyArg(1, &url_buf) orelse libc.exit();

    var path_buf: [256]u8 = undefined;
    var path_opt: ?[]const u8 = null;
    if (libc.getArgc() >= 3) {
        const p = copyArg(2, &path_buf) orelse libc.exit();
        path_opt = p;
    }

    const resp = http.get(url, &resp_buf) catch {
        libc.print("\x1b[31mjq: http GET failed\x1b[0m\n");
        libc.exit();
    };

    if (resp.status < 200 or resp.status >= 300) {
        libc.print("\x1b[31mjq: HTTP ");
        libc.printNum(resp.status);
        libc.print(" ");
        libc.print(resp.status_text);
        libc.print("\x1b[0m\n");
        libc.exit();
    }

    var tree = json.parse(resp.body) catch {
        libc.print("\x1b[31mjq: JSON parse failed\x1b[0m\n");
        libc.exit();
    };
    defer tree.deinit();

    const target = if (path_opt) |p| (queryPath(tree, p) orelse {
        libc.print("\x1b[31mjq: path not found\x1b[0m\n");
        libc.exit();
    }) else tree;

    dumpValue(target, 0);
    libc.printChar('\n');
    libc.exit();
}
