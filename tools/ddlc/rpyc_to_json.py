#!/usr/bin/env python3
"""Convert a Ren'Py .rpyc file (or every .rpyc in a .rpa archive) to a
JSON representation of its AST.

Approach: same StubUnpickler we used for source-text recon — Ren'Py's
AST classes get replaced by `Stub` instances that just remember the
class name + state dict, so we never run any of Ren'Py's __init__ or
__setstate__ code. Then a small visitor walks the resulting tree and
emits a JSON-friendly dict for each node.

Output schema is intentionally close to Ren'Py's AST shape (we don't
flatten control flow into a stream of statements yet — that's the
engine's job; here we just preserve the structure). Each node looks
like:

  {"type": "Say", "who": "s", "what": "Hi!", "with": null, ...}

where unrecognised fields pass through directly. PyExpr (a str-subclass)
becomes its plain string. Stubs we don't know how to flatten emit as
  {"type": "<ClassName>", "_state": <state>}
so the consumer can decide whether to handle them later or skip.

Usage:
    python rpyc_to_json.py <input.rpyc> <output.json>
    python rpyc_to_json.py <archive.rpa> <output_dir/>

In archive mode, each .rpyc entry yields a same-named .json under
output_dir/, mirroring the in-archive path.
"""

import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recon import rpa_open, rpyc_extract_script_pickle  # type: ignore
from python_sample import Stub, StrStub, StubUnpickler  # type: ignore


def to_jsonable(obj, seen=None, depth=0):
    """Convert a tree of stubs + primitives into a JSON-serialisable shape.

    Cycle guard via `id()` set since Ren'Py occasionally aliases nodes
    (e.g., a shared transform object). Depth cap prevents runaways.
    """
    if seen is None:
        seen = set()
    if depth > 80:
        return {"__truncated__": True}

    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, StrStub):
        # PyExpr — the str payload IS the source.
        return str(obj)
    if isinstance(obj, str):
        return obj
    if isinstance(obj, bytes):
        # Latin-1 round-trips any byte; JSON can hold the result safely.
        return {"__bytes__": obj.decode("latin-1")}

    oid = id(obj)
    if oid in seen:
        return {"__cycle__": True}
    seen.add(oid)

    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v, seen, depth + 1) for v in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            key = k if isinstance(k, str) else repr(k)
            out[key] = to_jsonable(v, seen, depth + 1)
        return out
    if isinstance(obj, Stub):
        # Class-name-tagged node + every attribute the unpickler set.
        node = {"type": obj._class_name}
        # __dict__ holds whatever __setstate__ stuffed in plus any direct
        # attribute assignments.
        for k, v in obj.__dict__.items():
            if k.startswith("_args") or k.startswith("_kwargs"):
                # Constructor args from positional/keyword call — usually
                # noise (Ren'Py reconstructs from __setstate__).
                continue
            node[k] = to_jsonable(v, seen, depth + 1)
        return node

    # Unknown leaf type — represent as its repr so it's still inspectable.
    return {"__repr__": repr(obj)}


def convert_rpyc(content: bytes):
    """Decode a .rpyc blob, return the JSON-shaped top-level structure or
    None if the file isn't a recognisable .rpyc."""
    script = rpyc_extract_script_pickle(content)
    if script is None:
        return None
    obj = StubUnpickler(io.BytesIO(script)).load()
    return to_jsonable(obj)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])

    # Single-file mode: input is a .rpyc, output is a .json.
    if src.suffix.lower() == ".rpyc":
        content = src.read_bytes()
        tree = convert_rpyc(content)
        if tree is None:
            print(f"# not a recognisable .rpyc: {src}", file=sys.stderr)
            return 1
        dst.write_text(json.dumps(tree, indent=2, ensure_ascii=False))
        print(f"wrote {dst} ({dst.stat().st_size} bytes)")
        return 0

    # Archive mode: iterate the .rpa, write a .json per .rpyc.
    if src.suffix.lower() == ".rpa":
        dst.mkdir(parents=True, exist_ok=True)
        count = 0
        failed = 0
        for name, content in rpa_open(src):
            if not name.endswith(".rpyc"):
                continue
            try:
                tree = convert_rpyc(content)
            except Exception as e:
                print(f"# fail {name}: {e}", file=sys.stderr)
                failed += 1
                continue
            if tree is None:
                failed += 1
                continue
            json_name = name[: -len(".rpyc")] + ".json"
            out = dst / json_name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(tree, indent=2, ensure_ascii=False), encoding="utf-8")
            count += 1
        print(f"# converted {count} scripts, failed {failed}")
        return 0

    print(f"# unrecognised input: {src} (expected .rpyc or .rpa)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
