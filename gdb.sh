#!/bin/bash
# Attach GDB to a running QEMU instance launched by run-debug.sh.
#
# Two stub options:
#   :1234  QEMU's built-in gdbstub. Works always, sees raw CPU state, no kernel
#          cooperation. Best for: kernel hangs, paging crashes, unmapped RIPs,
#          inspecting CPU registers, setting hardware watchpoints from outside.
#   :1235  Our in-kernel stub (gdb_stub.zig over COM2-as-TCP). Best for: kernel-
#          aware queries (process list, current_pid, PCB inspection). Requires
#          the kernel to be healthy enough to service the stub.
#
# Defaults to :1234 because it works even when the kernel is hung. Pass
# `--in-kernel` to use :1235 instead.
#
# Usage:
#   ./gdb.sh                # connect to QEMU's stub on :1234
#   ./gdb.sh --in-kernel    # connect to our stub on :1235

cd ~/zigos-arch

PORT=1234
STUB_NAME="QEMU's gdbstub"
if [ "$1" == "--in-kernel" ]; then
  PORT=1235
  STUB_NAME="in-kernel stub (COM2 over TCP)"
  shift
fi

KERNEL=zig-out/bin/kernel.elf
if [ ! -f "$KERNEL" ]; then
  echo "ERROR: $KERNEL not found. Run 'zig build' first." >&2
  exit 1
fi

echo "[gdb.sh] Attaching to $STUB_NAME on :$PORT (kernel symbols from $KERNEL)"

# -q quiet startup, -ex commands run before user prompt.
exec gdb -q "$KERNEL" \
  -ex "set architecture i386:x86-64" \
  -ex "set disassembly-flavor att" \
  -ex "source tools/kernel.gdbinit" \
  -ex "target remote :$PORT" \
  "$@"
