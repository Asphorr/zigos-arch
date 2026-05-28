#!/usr/bin/env python3
"""Sample DDLC's Python source code by partially-unpickling the .rpyc
scripts with safe class stubs. Each AST node becomes a `Stub` instance
that remembers its class name + init args; after unpickling we walk
the tree looking for PyCode/PyExpr nodes whose `source` field holds
the actual Python source text.

No game logic runs. The Stub class accepts any positional/keyword args
and refuses operator overloading, so a pickle stream of arbitrary depth
loads safely.
"""

import io
import pickle
import sys
import zlib
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from recon import rpa_open, rpyc_extract_script_pickle


class Stub:
    """Catch-all class returned by Unpickler.find_class. Stores the class
    identity + whatever attributes pickle sets via __setstate__ / __dict__."""
    __slots__ = ("_qualname", "__dict__")
    _class_name = None
    _module_name = None

    def __init__(self, *args, **kwargs):
        self._args = args
        self._kwargs = kwargs

    # Pickle uses __setstate__ when present; otherwise it sets __dict__.
    # Standard Python objects with __slots__ + __dict__ are pickled as a
    # 2-tuple (slots_state, dict_state); we want whichever member is a dict
    # (or both, since slot state can be a dict too).
    def __setstate__(self, state):
        if isinstance(state, dict):
            self.__dict__.update(state)
        elif isinstance(state, tuple) and len(state) == 2:
            for part in state:
                if isinstance(part, dict):
                    self.__dict__.update(part)
        else:
            self.__dict__["_state"] = state

    # Some Ren'Py nodes are pickled with __reduce_ex__ + __new__; allow that.
    def __reduce_ex__(self, protocol):
        return (Stub, ())

    def __repr__(self):
        return f"<{self._qualname}>"


class StrStub(str):
    """Stub for AST node types that subclass str (PyExpr). The string IS
    the source code; __dict__ holds the filename/linenumber state."""
    _qualname = ""
    _class_name = ""
    _module_name = ""

    def __new__(cls, value: str = "", *args, **kwargs):
        return super().__new__(cls, value)

    def __setstate__(self, state):
        if isinstance(state, dict):
            for k, v in state.items():
                object.__setattr__(self, k, v)


# Hand-curated set of (module, name) entries that are str subclasses in
# Ren'Py — pickle for these MUST preserve the string payload via __new__.
STR_SUBCLASSES = {
    ("renpy.ast", "PyExpr"),
}


def make_class(module: str, name: str) -> type:
    """Per-(module, name) Stub subclass so isinstance checks work."""
    base = StrStub if (module, name) in STR_SUBCLASSES else Stub
    return type(name, (base,), {"_qualname": f"{module}.{name}", "_class_name": name, "_module_name": module})


class StubUnpickler(pickle.Unpickler):
    _class_cache: dict[tuple[str, str], type] = {}

    def find_class(self, module: str, name: str) -> type:
        key = (module, name)
        cls = self._class_cache.get(key)
        if cls is None:
            cls = make_class(module, name)
            self._class_cache[key] = cls
        return cls

    def persistent_load(self, pid):
        # Ren'Py doesn't use persistent ids in script pickles; return a stub.
        return f"<persistent:{pid}>"


def walk(obj, sink):
    """DFS over the pickle tree, yielding each AST-stub node to `sink`."""
    seen = set()
    stack = [obj]
    while stack:
        node = stack.pop()
        nid = id(node)
        if nid in seen:
            continue
        seen.add(nid)
        is_stub = isinstance(node, (Stub, StrStub)) and getattr(node, "_class_name", "")
        if is_stub:
            sink(node)
            for v in node.__dict__.values():
                if v is not None and not isinstance(v, (int, float, bool, bytes, str)):
                    stack.append(v)
            # Also recurse into _state if it's a tuple/list/dict.
            st = node.__dict__.get("_state")
            if isinstance(st, (list, tuple)):
                for v in st:
                    stack.append(v)
            elif isinstance(st, dict):
                for v in st.values():
                    stack.append(v)
        elif isinstance(node, (list, tuple)):
            for v in node:
                stack.append(v)
        elif isinstance(node, dict):
            for k, v in node.items():
                stack.append(k)
                stack.append(v)


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} path/to/scripts.rpa", file=sys.stderr)
        return 1
    rpa = Path(sys.argv[1])

    py_sources: list[tuple[str, str]] = []  # (file, source)
    expr_sources: list[tuple[str, str]] = []
    user_statements: Counter[str] = Counter()
    with_transitions: Counter[str] = Counter()

    for name, content in rpa_open(rpa):
        if not (name.endswith(".rpyc") or name.endswith(".rpymc")):
            continue
        script = rpyc_extract_script_pickle(content)
        if script is None:
            continue
        try:
            obj = StubUnpickler(io.BytesIO(script)).load()
        except Exception as e:
            print(f"# fail: {name}: {e}", file=sys.stderr)
            continue

        def sink(node):
            cn = node._class_name
            if cn == "PyCode":
                # _state = (version, source_PyExpr, location, mode)
                st = node.__dict__.get("_state")
                if isinstance(st, tuple) and len(st) >= 2 and isinstance(st[1], str):
                    py_sources.append((name, str(st[1])))
            elif cn == "PyExpr":
                # PyExpr extends str via StrStub — the source IS the value.
                py_sources.append((name, str(node)))
                expr_sources.append((name, str(node)))
            elif cn == "UserStatement":
                line = node.__dict__.get("line")
                if isinstance(line, str):
                    # Just the leading keyword (e.g., "play music", "window auto").
                    head = line.strip().split(None, 2)
                    head_str = " ".join(head[:2]) if len(head) >= 2 else (head[0] if head else "")
                    user_statements[head_str] += 1
            elif cn == "With":
                exp = node.__dict__.get("expr")
                if isinstance(exp, str):
                    with_transitions[exp.strip()] += 1

        walk(obj, sink)

    # Print summary.
    print(f"# total PyCode source blocks: {len(py_sources)}")
    print(f"# total PyExpr source strings: {len(expr_sources)}")
    print(f"# distinct UserStatement heads: {len(user_statements)}")
    print(f"# distinct With transitions: {len(with_transitions)}")
    print()

    # Distribution of PyCode block sizes.
    print(f"# PyCode size distribution (lines):")
    bins = [0, 1, 2, 5, 10, 20, 50, 100, 1000]
    counts = [0] * (len(bins) - 1)
    for _, src in py_sources:
        lc = src.count("\n") + 1
        for i in range(len(bins) - 1):
            if bins[i] < lc <= bins[i + 1]:
                counts[i] += 1
                break
    for i in range(len(bins) - 1):
        print(f"  {bins[i]:>4}-{bins[i+1]:<4}: {counts[i]:>4}")
    print()

    print(f"# UserStatement heads (top 20):")
    for stmt, n in user_statements.most_common(20):
        print(f"  {n:>5}  {stmt}")
    print()

    print(f"# With transitions (top 20):")
    for tr, n in with_transitions.most_common(20):
        print(f"  {n:>5}  {tr}")
    print()

    # Unique source-text frequencies — many PyCode blocks repeat
    # (every ATL "pause 0.5" is a separate PyCode node but same source).
    uniq_py: Counter[str] = Counter()
    for _, src in py_sources:
        uniq_py[src] += 1
    print(f"# distinct PyCode source strings: {len(uniq_py)}")
    print(f"# top 30 most-repeated:")
    for src, n in uniq_py.most_common(30):
        snippet = src.replace("\n", " | ")
        if len(snippet) > 80:
            snippet = snippet[:80] + "..."
        print(f"  {n:>5}  {snippet}")
    print()

    # Big PyCode blocks (>= 10 lines).
    print(f"# PyCode blocks >= 10 lines (the heavy Python):")
    big = sorted(set((s, fn) for fn, s in py_sources if s.count("\n") >= 10), key=lambda p: -len(p[0]))
    for src, fn in big[:8]:
        head = src.splitlines()[:6]
        print(f"--- in {fn} ({src.count(chr(10))+1} lines, {len(src)} bytes) ---")
        for ln in head:
            print(f"  {ln}")
        print(f"  ... ({src.count(chr(10))-5} more lines)")
        print()

    # Unique PyExpr (eval-context, usually conditions + ATL params).
    uniq_expr_set = set(e for _, e in expr_sources if e.strip())
    print(f"# distinct PyExpr expressions: {len(uniq_expr_set)}")
    print(f"# sample (40 random-ish):")
    for e in sorted(uniq_expr_set, key=lambda s: (len(s), s))[:40]:
        print(f"  {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
