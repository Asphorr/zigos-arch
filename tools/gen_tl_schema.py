#!/usr/bin/env python3
"""Generate a compact TL *skip* table (Zig) for the transitive closure of a set
of root types, from a tdesktop api.tl schema.

MTProto TL has no length prefixes, so to walk a Vector<Message> we must consume
each element byte-exactly — which means knowing the field layout of every nested
type (media, service actions, web pages, polls, ...). Hand-coding 150+ of those
is madness; instead we emit a data table (ctor_id -> field layout) and let one
generic walker in dialogs.zig skip any object. Hand-written parsers still do the
*extraction* of the handful of fields we actually display.

Usage: gen_tl_schema.py <api.tl> <out.zig>
"""
import re
import sys

SCHEMA = sys.argv[1] if len(sys.argv) > 1 else "/tmp/api_dev.tl"
OUT = sys.argv[2] if len(sys.argv) > 2 else "lib/mtproto/tl_schema.zig"

# Roots = every type our hand-written parsers hand off to the generic skipper.
ROOTS = [
    "MessageFwdHeader", "MessageReplyHeader", "MessageMedia", "ReplyMarkup",
    "MessageEntity", "MessageReplies", "MessageReactions", "RestrictionReason",
    "FactCheck", "SuggestedPost", "MessageAction", "PeerNotifySettings",
    "DraftMessage", "ChatPhoto", "ChatAdminRights", "ChatBannedRights",
    "InputChannel", "EmojiStatus", "PeerColor", "Username", "RecentStory",
    "Photo", "Document", "WebPage",
]

# Primitives read by fixed/known rules (Bool = read the 4-byte ctor; both
# boolTrue/boolFalse carry no payload). 'true' is a zero-byte flag marker.
PRIM = {
    "int": "int", "long": "long", "double": "double", "bytes": "bytes",
    "string": "bytes", "int128": "int128", "int256": "int256", "Bool": "boolean",
}

ctors_by_type = {}   # ResultType -> [ (name, id, [tokens]) ]
ctor_line = re.compile(r'^([a-zA-Z0-9_.]+)#([0-9a-fA-F]+)\s*(.*?)\s*=\s*([a-zA-Z0-9_.<>%]+);\s*$')

warnings = []

def load():
    section_types = True
    with open(SCHEMA, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            s = line.strip()
            if s == "---functions---":
                section_types = False
                continue
            if s == "---types---":
                section_types = True
                continue
            if not section_types or not s or s.startswith("//"):
                continue
            m = ctor_line.match(s)
            if not m:
                continue
            name, hid, fieldpart, result = m.groups()
            # drop generic decls like {X:Type}
            fieldpart = re.sub(r'\{[^}]*\}', ' ', fieldpart)
            tokens = fieldpart.split()
            ctors_by_type.setdefault(result, []).append((name, int(hid, 16), tokens))

# --- resolve a field's inner type into (kind, elem_kind, [referenced types]) ---
def resolve_inner(inner):
    mv = re.match(r'^[Vv]ector<(.+)>$', inner)
    if mv:
        ek, _eelem, refs = resolve_inner(mv.group(1))
        if ek == "vector":
            warnings.append(f"nested vector: {inner}")
            ek = "boxed"  # fallback; will desync if actually hit (none expected)
        return ("vector", ek, refs)
    if inner == "true":
        return ("tru", "tru", [])
    if inner in PRIM:
        return (PRIM[inner], "tru", [])
    if inner.startswith("%"):
        warnings.append(f"bare %type: {inner}")
        return ("boxed", "tru", [inner[1:]])
    if re.match(r'^[A-Za-z][A-Za-z0-9_.]*$', inner):
        return ("boxed", "tru", [inner])
    warnings.append(f"unparsed inner type: {inner}")
    return ("boxed", "tru", [])

# parse one ctor's tokens -> ([Field dicts], set(referenced types))
def parse_ctor(name, tokens):
    fields = []
    refs = set()
    flagregs = {}   # flag field name -> register (1 or 2)
    for tok in tokens:
        if ':' not in tok:
            warnings.append(f"{name}: odd token {tok}")
            continue
        fname, ftype = tok.split(':', 1)
        if ftype == '#':
            reg = len(flagregs) + 1
            if reg > 2:
                warnings.append(f"{name}: >2 flag words")
                reg = 2
            flagregs[fname] = reg
            fields.append({"gw": 0, "gb": 0, "kind": "flags1" if reg == 1 else "flags2", "elem": "tru"})
            continue
        gw, gb = 0, 0
        inner = ftype
        mg = re.match(r'^([a-zA-Z0-9_]+)\.(\d+)\?(.+)$', ftype)
        if mg:
            flagname, bit, inner = mg.group(1), int(mg.group(2)), mg.group(3)
            gw = flagregs.get(flagname, 1)
            gb = bit
        kind, elem, r = resolve_inner(inner)
        for t in r:
            refs.add(t)
        fields.append({"gw": gw, "gb": gb, "kind": kind, "elem": elem})
    return fields, refs

def main():
    load()
    # transitive closure over types
    seen = set()
    queue = list(ROOTS)
    out_ctors = {}   # id -> (name, fields)
    while queue:
        t = queue.pop()
        if t in seen:
            continue
        seen.add(t)
        for (name, cid, tokens) in ctors_by_type.get(t, []):
            fields, refs = parse_ctor(name, tokens)
            out_ctors[cid] = (name, fields)
            for rt in refs:
                if rt not in seen and rt not in PRIM and rt != "Bool":
                    queue.append(rt)

    missing = [t for t in seen if t not in ctors_by_type and t not in PRIM and t != "Bool"]
    items = sorted(out_ctors.items())  # by id, for binary search

    lines = []
    lines.append("//! AUTO-GENERATED by tools/gen_tl_schema.py from api.tl (layer 225).")
    lines.append("//! A compact skip table: ctor id -> field layout, for the transitive")
    lines.append("//! closure of Telegram's nested message/media/action types. The generic")
    lines.append("//! walker in dialogs.zig reads a ctor off the wire, looks it up here, and")
    lines.append("//! consumes its fields byte-exactly. DO NOT EDIT — regenerate instead.")
    lines.append("")
    lines.append("pub const Kind = enum(u8) {")
    lines.append("    flags1, flags2, tru, int, long, double, int128, int256, bytes, boolean, boxed, vector")
    lines.append("};")
    lines.append("")
    lines.append("pub const Field = struct { gw: u8, gb: u8, kind: Kind, elem: Kind };")
    lines.append("pub const Ctor = struct { id: u32, fields: []const Field };")
    lines.append("")
    lines.append(f"// {len(items)} constructors in the closure ({len(ROOTS)} roots).")
    lines.append("pub const ctors = [_]Ctor{")
    for cid, (name, fields) in items:
        if fields:
            fs = ", ".join(
                f".{{ .gw = {f['gw']}, .gb = {f['gb']}, .kind = .{f['kind']}, .elem = .{f['elem']} }}"
                for f in fields
            )
            fexpr = "&.{ " + fs + " }"
        else:
            fexpr = "&.{}"
        lines.append(f"    .{{ .id = 0x{cid:08x}, .fields = {fexpr} }}, // {name}")
    lines.append("};")
    lines.append("")
    lines.append("/// Binary search the (id-sorted) table.")
    lines.append("pub fn fieldsFor(id: u32) ?[]const Field {")
    lines.append("    var lo: usize = 0;")
    lines.append("    var hi: usize = ctors.len;")
    lines.append("    while (lo < hi) {")
    lines.append("        const mid = lo + (hi - lo) / 2;")
    lines.append("        const c = ctors[mid];")
    lines.append("        if (c.id == id) return c.fields;")
    lines.append("        if (c.id < id) lo = mid + 1 else hi = mid;")
    lines.append("    }")
    lines.append("    return null;")
    lines.append("}")
    lines.append("")

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[gen] {len(items)} ctors emitted -> {OUT}")
    if missing:
        print(f"[gen] {len(missing)} referenced types with no constructors (treated as opaque/empty):")
        print("      " + ", ".join(sorted(missing)))
    if warnings:
        uniq = sorted(set(warnings))
        print(f"[gen] {len(uniq)} warnings:")
        for w in uniq[:40]:
            print("      " + w)

if __name__ == "__main__":
    main()
