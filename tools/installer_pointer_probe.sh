#!/bin/bash
# installer_pointer_probe — does the installer's guest cursor follow QMP abs
# pointer events? Distinguishes "tablet path broken in the installer" from
# "SDL never delivered events" for the 2026-08-22 windowed-run report of a
# dead mouse. Screendumps before/after two moves; identical dumps = the
# guest cursor never moved.
#
# Run on the VM: bash tools/installer_pointer_probe.sh
cd "$(dirname "$(readlink -f "$0")")/.."

pkill -f "[q]emu-system-x86_64" 2>/dev/null
sleep 1
rm -f serial-installer.log ptr-*.ppm

./run-installer.sh -headless > installer-run.log 2>&1 &

QPID=""
for i in $(seq 1 3000); do
    QPID=$(pgrep -af "qemu-system-x86_64" 2>/dev/null | awk '$2 ~ /qemu-system-x86_64$/ {print $1; exit}')
    [ -n "$QPID" ] && break
    sleep 0.1
done
if [ -z "$QPID" ]; then echo "NO-QEMU-AFTER-BUILD"; tail -5 installer-run.log; exit 1; fi
echo "qemu up: pid=$QPID"

mon() { printf '%s\n' "$1" | timeout 5 socat - UNIX-CONNECT:installer-mon.sock >/dev/null 2>&1; }
# Every QMP connection gets its own capabilities handshake.
qmp() {
    { printf '{"execute":"qmp_capabilities"}\n'; sleep 0.3
      printf '%s\n' "$1"; sleep 0.3; } \
        | timeout 5 socat - UNIX-CONNECT:installer-qmp.sock 2>/dev/null
}
move() {
    qmp "{\"execute\":\"input-send-event\",\"arguments\":{\"events\":[{\"type\":\"abs\",\"data\":{\"axis\":\"x\",\"value\":$1}},{\"type\":\"abs\",\"data\":{\"axis\":\"y\",\"value\":$2}}]}}" >/dev/null
}

for i in $(seq 1 1200); do
    grep -aq "Showing boot menu" serial-installer.log 2>/dev/null && break
    sleep 0.1
done
sleep 2
for i in 1 2 3 4; do mon "sendkey down"; sleep 0.4; done
mon "sendkey ret"; sleep 0.6
mon "sendkey ret"

for i in $(seq 1 1200); do
    grep -aq "graphical installer" serial-installer.log 2>/dev/null && break
    sleep 0.1
done
sleep 3

mon "screendump ptr-0.ppm"; sleep 1
move 4000 4000;   sleep 1
mon "screendump ptr-1.ppm"; sleep 1
move 28000 28000; sleep 1
mon "screendump ptr-2.ppm"; sleep 1

echo "=== verdict ==="
ls -la ptr-*.ppm
if cmp -s ptr-0.ppm ptr-1.ppm && cmp -s ptr-1.ppm ptr-2.ppm; then
    echo "POINTER-DEAD: all three dumps identical - guest cursor never moved"
else
    cmp -s ptr-0.ppm ptr-1.ppm && echo "move1: NO change" || echo "move1: frame changed"
    cmp -s ptr-1.ppm ptr-2.ppm && echo "move2: NO change" || echo "move2: frame changed"
    echo "POINTER-ALIVE: guest cursor follows QMP abs events"
fi
pkill -f "[q]emu-system-x86_64" 2>/dev/null
exit 0
