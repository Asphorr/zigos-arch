#!/bin/bash
# nvme_freeze_test — prove the NVMe driver survives a host-side stall.
#
# Runs the boot-16 disk self-test and, right as mkfs starts, SIGSTOPs the
# QEMU process for 1.5 s, then resumes it. That is an exact simulation of
# the host stalls this machine actually suffers (SMI bursts, nested-Hyper-V
# vCPU deschedules): guest TSC keeps counting, vCPUs and the device model
# do not run, and the in-flight command's completion arrives only when the
# world resumes.
#
# Expected result since 2026-09-16 (steal-aware time, time/pause.zig): the
# wait that spans the freeze measures it as host pause, not as guest time —
#   [nvme] host pause absorbed: ~5400 Mcyc paused, <200 Mcyc guest-run on qid=1 (IF=0)
#   [disktest] PASS
# and NO "slow completion ... host stall?" line for the frozen wait. (Any
# "slow completion: N Mcyc guest-run ... (0 Mcyc host-paused)" line is a
# genuinely slow emulated write — the big FAT/zeroing pours do take
# ~0.5 s of real QEMU time — not a misread pause.) The freeze lands at a
# random point of the pour, so a run may miss every wait; the script
# says so ("freeze fell between waits") rather than claiming a pass.
#
# History. Since the 2026-08-22 soft/hard deadline split the expectation
# was two WALL-clock diagnostics + PASS:
#   [nvme] slow completion on qid=1: >2000 Mcyc and still waiting (host stall?)
#   [nvme] slow completion: ~5000 Mcyc on qid=1 (host stall?)
# Before the split this scenario reproduced the 2026-07-26 failure bit for
# bit: waitCompletion timeout (csts=0x1), mkfs FAIL — a LATE completion
# misread as a lost one.
#
# Run on the VM: bash tools/nvme_freeze_test.sh   (from the repo root)
cd "$(dirname "$(readlink -f "$0")")/.."

pkill -f "[r]un-disk-selftest" 2>/dev/null
pkill -f "[q]emu-system-x86_64" 2>/dev/null
sleep 1
rm -f serial-disktest.log

./run-disk-selftest.sh 240 > nvme-freeze-run.log 2>&1 &

# The runner rebuilds first, so QEMU can take minutes to appear. pgrep by
# exact argv[0]: `pgrep -x` can't work here (comm is truncated to 15 chars)
# and a bare `pgrep -f` also matches the `timeout` wrapper in front of it —
# freezing THAT leaves QEMU running and the test silently passes.
QPID=""
for i in $(seq 1 3000); do
    QPID=$(pgrep -af "qemu-system-x86_64" 2>/dev/null | awk '$2 ~ /qemu-system-x86_64$/ {print $1; exit}')
    [ -n "$QPID" ] && break
    sleep 0.1
done
if [ -z "$QPID" ]; then echo "NO-QEMU-AFTER-BUILD"; tail -5 nvme-freeze-run.log; exit 1; fi
echo "qemu up: pid=$QPID"

# Freeze on the phase-3 banner — printed just before mkfs.fat32 begins, so
# the STOP lands inside the pour's waitCompletion with high probability.
HIT=0
for i in $(seq 1 6000); do
    if grep -aq "disktest\] 3: mkfs" serial-disktest.log 2>/dev/null; then HIT=1; break; fi
    sleep 0.02
done
if [ "$HIT" = "0" ]; then echo "NO-PHASE3-LINE (boot failed?)"; kill "$QPID"; exit 1; fi

echo "--- freeze: guest at: $(tail -c 200 serial-disktest.log | tail -1 | tr -d '\r')"
kill -STOP "$QPID"
sleep 1.5
kill -CONT "$QPID"
echo "--- unfroze: guest at: $(tail -c 200 serial-disktest.log | tail -1 | tr -d '\r')"

sleep 8
echo "=== verdict lines ==="
grep -a -E "timeout|LATE|lost|slow completion|host pause absorbed|expected phase|\[smi\] stall|\[disktest\] (PASS|FAIL)|kernel-side" serial-disktest.log | head -40
echo "=== verdict ==="
if grep -aq "host pause absorbed" serial-disktest.log; then
    echo "PAUSE-ABSORBED: a wait spanned the freeze and subtracted it"
elif grep -aqE "slow completion: [0-9]{4,} Mcyc guest-run" serial-disktest.log; then
    echo "PAUSE-MISREAD: a wait counted the freeze as guest time (regression)"
else
    echo "INCONCLUSIVE: freeze fell between waits — rerun"
fi
grep -aq "\[disktest\] PASS" serial-disktest.log && echo "DISKTEST: PASS" || echo "DISKTEST: FAIL"
pkill -f "[r]un-disk-selftest" 2>/dev/null
pkill -f "[q]emu-system-x86_64" 2>/dev/null
exit 0
