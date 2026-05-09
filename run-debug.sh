#!/bin/bash
# QEMU launcher for ZigOS in DEBUG mode (TCG accelerator).
#
# WHY TCG (not KVM):
#   KVM virtualizes guest debug-register writes via KVM_SET_GUEST_DEBUG when
#   `-s` (gdbstub) is active, OR — observed empirically — appears to leave
#   guest DR usage in an unstable state under SMP that triple-faults. TCG
#   emulates the CPU in software, so guest DR0-DR3 + DR7 writes actually fire
#   #DB on matches. Both kernel-side `watch.zig` and GDB-attached hw
#   watchpoints work as the architecture describes.
#
# COST: TCG is ~30-50x slower than KVM. Boot takes ~1-2 minutes. Click
# response in QEMU is laggy. Use this only when you need debug-register
# functionality — for normal testing, use run-usb.sh (KVM).
#
# Usage:
#   ./run-debug.sh                       # boot normally; gdb can attach via :1234 or :1235
#   ./run-debug.sh --halt                # halt at boot — connect gdb, then 'continue'
#
# Two GDB stubs available simultaneously:
#   :1234   QEMU's gdbstub (always works, even on kernel hang)
#   :1235   Our in-kernel stub via COM2 (kernel-aware queries; requires healthy kernel)
#
#   ./gdb.sh                # connect to :1234 (QEMU stub)
#   ./gdb.sh --in-kernel    # connect to :1235 (in-kernel stub)
#
# Both stubs cooperate fine under TCG. Hardware watchpoints from GDB also
# work (no KVM virtualization layer to fight with).

cd ~/zigos-arch

HALT_ARG=""
if [ "$1" == "--halt" ]; then
  HALT_ARG="-S"
  shift
  echo "[run-debug] TCG mode + --halt. CPU halted at boot. Run ./gdb.sh in another terminal, then 'continue'."
else
  echo "[run-debug] TCG mode (slow but proper DR semantics). Boot takes ~1-2min. gdbstub on :1234, in-kernel stub on :1235."
fi

LD_LIBRARY_PATH=/usr/local/lib/x86_64-linux-gnu \
VK_ICD_FILENAMES=/usr/share/vulkan/icd.d/lvp_icd.json \
~/qemu-9.2.0/build/qemu-system-x86_64 \
  -m 64 -accel kvm -cpu host -smp 2 -no-reboot \
  -device virtio-vga-gl,blob=true,venus=true,hostmem=256M \
  -display gtk,gl=on,show-cursor=on,grab-on-hover=on \
  -device qemu-xhci,id=xhci -device usb-kbd -device usb-tablet \
  -device virtio-net-pci,netdev=net0 -netdev user,id=net0,hostfwd=tcp::8080-:8080 \
  -audiodev none,id=snd0 -machine pcspk-audiodev=snd0 -device AC97,audiodev=snd0 \
  -device virtio-sound-pci,audiodev=snd0 \
  -drive file=disk.tar,format=raw,index=0,if=ide \
  -drive file=disk.img,format=raw,index=2,if=ide \
  -serial file:serial.log \
  -serial tcp:127.0.0.1:1235,server,nowait \
  -s $HALT_ARG \
  -kernel zig-out/bin/kernel32.elf "$@" 2> >(tee /tmp/qemu-debug.stderr.log >&2)
