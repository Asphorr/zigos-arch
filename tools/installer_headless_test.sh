#!/bin/bash
# installer_headless_test — drive the graphical installer end to end with no
# display and report what landed on install.img.
#
# Recipe proven 2026-08-22: the boot menu needs 4x `down` + `ret` to pick
# "Install ZigOS to disk..." (a second `ret` skips the confirm modal), then
# three `sendkey ret` walk intro → destination → layout and start the
# install; the serial log carries every phase. The copy phase moves
# ~215 MiB, so the wait is generous. See run-installer.sh for the -headless
# socket layout (HMP monitor at installer-mon.sock).
#
# Run on the VM: bash tools/installer_headless_test.sh
cd "$(dirname "$(readlink -f "$0")")/.."

pkill -f "[q]emu-system-x86_64" 2>/dev/null
sleep 1
rm -f serial-installer.log installer-done.ppm

./run-installer.sh -headless > installer-run.log 2>&1 &

# The runner rebuilds first — QEMU can take minutes to appear. pgrep by
# exact argv[0]; -x can't match (comm truncates at 15 chars) and bare -f
# also catches wrapper processes.
QPID=""
for i in $(seq 1 3000); do
    QPID=$(pgrep -af "qemu-system-x86_64" 2>/dev/null | awk '$2 ~ /qemu-system-x86_64$/ {print $1; exit}')
    [ -n "$QPID" ] && break
    sleep 0.1
done
if [ -z "$QPID" ]; then echo "NO-QEMU-AFTER-BUILD"; tail -5 installer-run.log; exit 1; fi
echo "qemu up: pid=$QPID"

mon() { printf '%s\n' "$1" | timeout 5 socat - UNIX-CONNECT:installer-mon.sock >/dev/null 2>&1; }

# Boot menu: wait for it, walk down to "Install ZigOS to disk...", enter,
# skip the ~1.4s confirm modal with a second enter.
for i in $(seq 1 1200); do
    grep -aq "Showing boot menu" serial-installer.log 2>/dev/null && break
    sleep 0.1
done
sleep 2
for i in 1 2 3 4; do mon "sendkey down"; sleep 0.4; done
mon "sendkey ret"; sleep 0.6
mon "sendkey ret"

# Installer up: first frame painted, then walk its three screens.
for i in $(seq 1 1200); do
    grep -aq "graphical installer" serial-installer.log 2>/dev/null && break
    sleep 0.1
done
sleep 3 # let the first frame paint before typing at it

mon "sendkey ret"; sleep 1.5
mon "sendkey ret"; sleep 1.5
mon "sendkey ret"
echo "install started: $(date +%T)"

# Terminal states: the verify phase's closing line, or any FAIL.
DONE=0
for i in $(seq 1 6000); do
    if grep -aqE "installation steps complete|\[installer\] FAIL" serial-installer.log 2>/dev/null; then DONE=1; break; fi
    sleep 0.1
done
echo "install finished ($([ "$DONE" = "1" ] && echo terminal-line-seen || echo TIMEOUT)): $(date +%T)"
sleep 2
mon "screendump installer-done.ppm"
sleep 1

echo "=== verdict lines ==="
grep -aE "\[installer\]|\[nvram\]|\[esp-populate\]|\[populate\]" serial-installer.log | tail -30
echo "=== teardown ==="
pkill -f "[q]emu-system-x86_64" 2>/dev/null
exit 0
