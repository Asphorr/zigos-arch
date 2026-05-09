#!/bin/bash
# All-in-one wrapper for hunting the iretq frame corruption bug via GDB.
#
# What this does (you don't need to do these by hand):
#   1. Starts QEMU in the background with -s gdbstub on :1234.
#   2. Starts GDB and runs tools/iretq-hunt.gdb, which:
#        a. Watches procs[2].kernel_stack_top — fires when paint loads.
#        b. Automatically swaps to a hw watchpoint on the iretq CS slot.
#        c. Stops with full context (regs, bt, code) when corruption hits.
#
# Your job:
#   1. Run `./debug-iretq.sh`.
#   2. When QEMU's desktop appears, click the "paint" icon (paint loads).
#   3. Click in the paint window 5-10 times until GDB stops in your terminal.
#   4. Copy GDB's output — that's the writer's RIP + context.
#
# To exit cleanly: Ctrl-C in GDB (or `quit`), then `kill %1` for QEMU.

cd ~/zigos-arch

# Kill any lingering QEMU first to avoid disk.tar lock issues.
pkill -9 -f qemu-system-x86_64 2>/dev/null
sleep 1

echo "[debug-iretq] Starting QEMU in background..."
./run-debug.sh > /tmp/qemu-debug-iretq.log 2>&1 &
QEMU_PID=$!

# Trap to clean up QEMU when we exit GDB.
trap "echo '[debug-iretq] Cleaning up QEMU (pid=$QEMU_PID)...'; kill $QEMU_PID 2>/dev/null; pkill -f qemu-system-x86_64 2>/dev/null" EXIT

# Wait briefly for QEMU to start its gdbstub.
sleep 2

echo "[debug-iretq] Starting GDB with auto-hunt script..."
echo "[debug-iretq] When QEMU window appears: click 'paint' icon, then click in window."
echo ""

# gdb.sh sources tools/kernel.gdbinit; we additionally source iretq-hunt.gdb.
gdb -q zig-out/bin/kernel.elf \
  -ex "set architecture i386:x86-64" \
  -ex "set disassembly-flavor att" \
  -ex "source tools/kernel.gdbinit" \
  -ex "target remote :1234" \
  -ex "source tools/iretq-hunt.gdb"
