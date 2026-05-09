#!/bin/bash
# crash_db.sh — out-of-the-box crash database for ZigOS serial logs.
#
# Run by run-uefi(-ext2).sh after every QEMU exit. Greps the just-finished
# serial.log for [crash-fp] lines (emitted by kdbg.crashSummary), appends one
# CSV row per crash to crashes/db.csv, and prints a "seen N times before"
# header for any fingerprint we've recorded previously.
#
# The point: stop forcing the user to type `addr2line`, `grep PANIC`, or
# `nm | grep ${SOMESYMBOL}` after every crash. The serial.log already has
# everything resolved (kernel-side via KERNEL.SYM); this script just keeps a
# host-side log so regressions across boots stand out.
#
# CSV columns: utc_ts, log_path, build_id, vec, cpu, rip_sym, cr2
#
# Dup detection key: vec + rip_sym + cr2 (build_id intentionally NOT part of
# the key so the same logical bug across rebuilds groups together).
set -u
LOG=${1:-serial.log}
DB=crashes/db.csv

[ -f "$LOG" ] || exit 0
mkdir -p crashes

if ! grep -q '^\[crash-fp\]' "$LOG" 2>/dev/null; then
    exit 0
fi

# Initialize DB header on first ever run.
if [ ! -f "$DB" ]; then
    echo "utc_ts,log_path,build_id,vec,cpu,rip_sym,cr2" > "$DB"
fi

# Stable absolute path resolution — db.csv stays grep-able regardless of cwd.
ABS_LOG=$(readlink -f "$LOG" 2>/dev/null || echo "$LOG")

# Process each [crash-fp] line. Format from kdbg.crashSummary:
#   [crash-fp] build=0x68B7A1F4 vec=14 cpu=0 rip_sym=handleIRQ0+0x33BC cr2=0x18D5126174
#
# awk extracts each key=value into a CSV row. utc_ts comes from `date -u`
# at processing time (close enough — these are post-mortem rows).
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# We collect new rows then print them; this lets us also count duplicates
# per fingerprint in the existing DB and emit a single banner per crash.
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

grep '^\[crash-fp\]' "$LOG" | while IFS= read -r line; do
    build=$(echo "$line"   | grep -oE 'build=0x[0-9A-Fa-f]+'  | cut -d= -f2)
    vec=$(echo "$line"     | grep -oE 'vec=[0-9]+'           | cut -d= -f2)
    cpu=$(echo "$line"     | grep -oE 'cpu=[0-9]+'           | cut -d= -f2)
    rip_sym=$(echo "$line" | sed -nE 's/.*rip_sym=([^ ]+) cr2=.*/\1/p')
    cr2=$(echo "$line"     | grep -oE 'cr2=0x[0-9A-Fa-f]+'   | cut -d= -f2)

    # Append fresh row.
    printf '%s,%s,%s,%s,%s,%s,%s\n' \
        "$NOW" "$ABS_LOG" "$build" "$vec" "$cpu" "$rip_sym" "$cr2" >> "$DB"

    # Dup count = rows with same (vec, rip_sym, cr2), excluding the one we
    # just appended. Read DB freshly each time so multi-crash logs see
    # previous crashes from THIS log too.
    seen=$(awk -F, -v v="$vec" -v r="$rip_sym" -v c="$cr2" '
        NR>1 && $4==v && $6==r && $7==c { count++ }
        END { print count+0 }
    ' "$DB")
    # Subtract the just-added row so the count means "previously seen".
    seen=$((seen - 1))

    if [ "$seen" -ge 1 ]; then
        echo "[crash-db] DUPLICATE fingerprint vec=$vec $rip_sym cr2=$cr2 (seen $seen time(s) before)" >&2
    else
        echo "[crash-db] NEW crash recorded: vec=$vec $rip_sym cr2=$cr2 (build=$build)" >&2
    fi
done
