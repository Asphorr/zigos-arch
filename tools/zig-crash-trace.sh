#!/usr/bin/env bash
# zig-crash-trace — run a Zig command and, if it crashes, point at the .zig
# source file Zig was working on when it died.
#
# How: runs the Zig command under strace tracking `openat` of .zig files.
# When the Zig binary crashes (any non-zero exit), we replay the strace
# log and print the last 20 .zig files Zig opened. The last one Zig was
# parsing/analyzing when it died is almost always in that tail.
#
# We also attempt a gdb backtrace of the actual zig binary in case it
# has any symbols at all (Zig releases ship stripped, but the prebuilt
# tarballs sometimes have line markers that help).
#
# Usage:
#   tools/zig-crash-trace.sh -- /opt/zig-x86_64-linux-0.15.2/zig build
#   tools/zig-crash-trace.sh -- /opt/zig-x86_64-linux-0.15.2/zig build-exe ...
#
# Output structure:
#   [trace] last 20 .zig files opened (chronological)
#   [trace] crash signal / exit code
#   [trace] gdb backtrace (if available)
#   [trace] suggestion: likely culprit
#
# Exits with the same code as the underlying command.

set -u

if [ "${1:-}" != "--" ]; then
    cat <<'EOF' >&2
zig-crash-trace: missing `--` separator before the Zig command.

Usage:
  tools/zig-crash-trace.sh -- /path/to/zig build
  tools/zig-crash-trace.sh -- /path/to/zig build-exe ...
EOF
    exit 2
fi
shift

if ! command -v strace >/dev/null 2>&1; then
    echo "zig-crash-trace: strace not found; install with apt install strace" >&2
    exit 2
fi

TRACE=$(mktemp /tmp/zig-crash-trace.XXXXXX)
STDERR_LOG=$(mktemp /tmp/zig-crash-stderr.XXXXXX)
trap 'rm -f "$TRACE" "$STDERR_LOG"' EXIT

# We capture openat() syscalls only — keeps the trace small even for big
# kernel builds. -f follows forks (zig spawns clang/lld as child processes).
# -y resolves fd back to path. We grep for .zig before writing to keep the
# trace under a few MB.
echo "[trace] starting: $*" >&2
strace -f -e trace=openat -o "$TRACE" "$@" 2> "$STDERR_LOG"
EXIT=$?

if [ "$EXIT" -eq 0 ]; then
    echo "[trace] command succeeded, no crash to report"
    exit 0
fi

# ----- Diagnostics -----
echo ""
echo "============================================================"
echo "[trace] command exited with status $EXIT"
case "$EXIT" in
    139) echo "[trace] exit 139 = SIGSEGV (segmentation fault inside Zig)" ;;
    134) echo "[trace] exit 134 = SIGABRT (Zig assert / @panic)" ;;
    132) echo "[trace] exit 132 = SIGILL (illegal instruction)" ;;
    137) echo "[trace] exit 137 = SIGKILL (OOM killer? check dmesg)" ;;
    1)   echo "[trace] exit 1 = ordinary error — likely a real compile error, not a Zig crash" ;;
    *)   echo "[trace] unusual exit code; check Zig stderr above" ;;
esac
echo "============================================================"
echo ""

# Last .zig files opened, in order. We extract from openat trace lines and
# filter to absolute paths under the project (skipping stdlib).
echo "[trace] Last 20 .zig files opened (chronological):"
grep -E 'openat\(.*\.zig"' "$TRACE" \
    | grep -oE '"[^"]+\.zig"' \
    | tail -20 \
    | sed 's|^|    |'
echo ""

# Most-recently opened unique files (for when zig revisits the same file
# many times, e.g. comptime-heavy modules).
echo "[trace] Last 10 *unique* .zig files (most recent first):"
grep -E 'openat\(.*\.zig"' "$TRACE" \
    | grep -oE '"[^"]+\.zig"' \
    | tac \
    | awk '!seen[$0]++' \
    | head -10 \
    | sed 's|^|    |'
echo ""

# If the project has src/ or lib/ or boot/ directories, filter to those —
# usually the user cares about their code, not /tmp staging or stdlib.
PROJECT_HINT=""
for hint in src lib boot uefi app; do
    if grep -qE "\"[^\"]*/$hint/[^\"]+\.zig\"" "$TRACE"; then
        PROJECT_HINT="$PROJECT_HINT|/$hint/"
    fi
done
if [ -n "$PROJECT_HINT" ]; then
    PROJECT_HINT="${PROJECT_HINT#|}"
    echo "[trace] Last 10 project files (src/lib/boot/uefi/app):"
    grep -E 'openat\(.*\.zig"' "$TRACE" \
        | grep -oE '"[^"]+\.zig"' \
        | grep -E "$PROJECT_HINT" \
        | tac \
        | awk '!seen[$0]++' \
        | head -10 \
        | sed 's|^|    |'
    echo ""
fi

# Last syscalls executed by zig before dying — can show malloc-of-death,
# read of giant file, etc.
echo "[trace] Last 5 syscalls before exit:"
tail -8 "$TRACE" | head -5 | sed 's|^|    |'
echo ""

# If we got a SIGSEGV and zig has debug info, try to get a backtrace.
# Most prebuilt zig binaries are stripped, so this is best-effort.
if [ "$EXIT" -eq 139 ]; then
    ZIG_BIN="$1"
    if [ -x "$ZIG_BIN" ] && command -v gdb >/dev/null 2>&1; then
        # Check if binary has debug info (file output mentions 'not stripped' or has DWARF).
        if file "$ZIG_BIN" 2>/dev/null | grep -q "not stripped"; then
            echo "[trace] Zig binary has symbols — running gdb for backtrace..."
            gdb --batch --quiet \
                -ex "set pagination off" \
                -ex "run" \
                -ex "bt 30" \
                --args "$@" 2>&1 | tail -40 | sed 's|^|    |'
        else
            echo "[trace] Zig binary is stripped — gdb backtrace unavailable."
            echo "[trace] (Build Zig from source with debug info if you need this.)"
        fi
        echo ""
    fi
fi

# Concise summary: what to look at first.
echo "============================================================"
LAST_PROJECT=$(grep -E 'openat\(.*\.zig"' "$TRACE" \
    | grep -oE '"[^"]+\.zig"' \
    | { [ -n "$PROJECT_HINT" ] && grep -E "$PROJECT_HINT" || cat; } \
    | tail -1 \
    | tr -d '"')
if [ -n "$LAST_PROJECT" ]; then
    echo "[trace] Suspected culprit: $LAST_PROJECT"
    echo "[trace] (last project .zig Zig opened before crashing)"
else
    echo "[trace] No project file pinpointed; see lists above."
fi
echo "============================================================"

# Show stderr from zig if any (sometimes zig prints something useful before dying).
if [ -s "$STDERR_LOG" ]; then
    echo ""
    echo "[trace] Zig stderr (last 30 lines):"
    tail -30 "$STDERR_LOG" | sed 's|^|    |'
fi

exit $EXIT
