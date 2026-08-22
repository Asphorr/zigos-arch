#!/bin/bash
# installer_layout_smoke — boot to the installer's destination screen, park
# the pointer on the fourth disk card and screendump. Eyeball evidence for
# the 2026-08-22 UI round: all four cards inside the pane, desktop cursor
# sprite, hover/selection drawn. Assumes zig-out is already built (does NOT
# rebuild; run-installer.sh rebuilds cheaply from a warm cache).
#
# Run on the VM: bash tools/installer_layout_smoke.sh
cd "$(dirname "$(readlink -f "$0")")/.."

pkill -f "[q]emu-system-x86_64" 2>/dev/null
sleep 1
rm -f serial-installer.log layout-smoke.ppm

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
qmp() {
    { printf '{"execute":"qmp_capabilities"}\n'; sleep 0.3
      printf '%s\n' "$1"; sleep 0.3; } \
        | timeout 5 socat - UNIX-CONNECT:installer-qmp.sock >/dev/null 2>&1
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

# intro -> destination, then hover the fourth card. Fixed geometry at
# 1920x1080: panel at (520,260), contentX 770, card 3 at x=1220 y=396;
# card center (1290,455) -> abs (22016,13804).
mon "sendkey ret"; sleep 1.5
qmp '{"execute":"input-send-event","arguments":{"events":[{"type":"abs","data":{"axis":"x","value":22016}},{"type":"abs","data":{"axis":"y","value":13804}}]}}'
sleep 1.5
mon "screendump layout-smoke.ppm"; sleep 1

ls -la layout-smoke.ppm
pkill -f "[q]emu-system-x86_64" 2>/dev/null
exit 0
