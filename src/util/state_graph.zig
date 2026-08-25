//! state_graph — a lifecycle's legal transitions as a comptime table.
//!
//! Every state machine in this kernel documents its edges in prose ("loader
//! transitions loading→ready", "the ONLY legitimate transition out of a
//! terminal state is...") and enforces, at best, the two edges someone got
//! burned by. The kill-vs-wake campaigns were month-long hunts for
//! transitions the prose forbids and the code permitted — a wake reviving a
//! zombie, a killer absorbing into a half-loaded slot.
//!
//! `StateGraph(S, edges)` turns the prose into an object:
//!
//!   - the edge list is DATA, reviewable in one screen next to the enum;
//!   - `legal(from, to)` is one table load — cheap enough to run on every
//!     transition in ReleaseSafe, forever;
//!   - `assertEdge(.a, .b)` is a comptime fact-check for call sites that
//!     know both ends statically — a refactor that breaks the claim breaks
//!     the BUILD;
//!   - `assertSane(entry)` proves at comptime that the graph itself is
//!     coherent: every state is reachable from `entry`, so a typo'd edge
//!     list (orphaned state, one-way trap that shouldn't be) cannot compile.
//!
//! What this deliberately is NOT: an enforcement gate. Concurrency truth
//! stays with the CAS that claims each transition; the graph names which
//! claimed transitions were ever supposed to exist. Callers decide whether
//! an illegal one warns (detection), absorbs, or fails — policy stays at
//! the call site, the FACTS live here.

const std = @import("std");

pub fn StateGraph(comptime S: type, comptime edges: []const [2]S) type {
    const info = @typeInfo(S).@"enum";
    const n = info.fields.len;
    comptime {
        // The table is indexed by enum value; demand density so a sparse
        // enum can't silently alias two states onto one row.
        for (info.fields) |f| std.debug.assert(f.value < n);
    }
    const table: [n][n]bool = comptime blk: {
        var t: [n][n]bool = .{.{false} ** n} ** n;
        for (edges) |e| {
            std.debug.assert(e[0] != e[1]); // self-loops are setState no-ops, not edges
            t[@intFromEnum(e[0])][@intFromEnum(e[1])] = true;
        }
        break :blk t;
    };

    return struct {
        pub const state_count = n;

        /// One load: is `from → to` an edge the design admits?
        pub inline fn legal(from: S, to: S) bool {
            return table[@intFromEnum(from)][@intFromEnum(to)];
        }

        /// Comptime fact-check for a call site that knows both ends: states
        /// the claim next to the code, fails the build if the edge list ever
        /// stops backing it.
        pub fn assertEdge(comptime from: S, comptime to: S) void {
            comptime {
                if (!table[@intFromEnum(from)][@intFromEnum(to)]) {
                    @compileError("state_graph: " ++ @tagName(from) ++ " -> " ++
                        @tagName(to) ++ " is not an edge of this graph");
                }
            }
        }

        /// Comptime coherence proof: every state reachable from `entry`.
        /// An unreachable state means the edge list has a typo — better a
        /// compile error naming the state than a lifecycle nothing enters.
        pub fn assertSane(comptime entry: S) void {
            comptime {
                var seen: [n]bool = .{false} ** n;
                seen[@intFromEnum(entry)] = true;
                // Fixed-point over a ≤n-step frontier expansion.
                var pass: usize = 0;
                while (pass < n) : (pass += 1) {
                    for (0..n) |from| {
                        if (!seen[from]) continue;
                        for (0..n) |to| {
                            if (table[from][to]) seen[to] = true;
                        }
                    }
                }
                for (info.fields) |f| {
                    if (!seen[f.value]) {
                        @compileError("state_graph: state ." ++ f.name ++
                            " is unreachable from ." ++ @tagName(entry));
                    }
                }
            }
        }
    };
}

// ------------------------------ self-proof ----------------------------------
comptime {
    const T = enum(u8) { a, b, c };
    const G = StateGraph(T, &.{ .{ .a, .b }, .{ .b, .c }, .{ .c, .a } });
    std.debug.assert(G.legal(.a, .b));
    std.debug.assert(!G.legal(.b, .a));
    std.debug.assert(!G.legal(.a, .c));
    G.assertEdge(.a, .b);
    G.assertSane(.a);
}
