#!/bin/bash
# mode_battery — headless acceptance for the self-test boot modes.
#
# For each mode: build with -Dboot-mode=N, boot the disk-selftest QEMU
# topology with the serial port on a file, wait for the mode's verdict
# line (or a timeout), kill QEMU, print PASS/FAIL. Same QEMU line as
# run-disk-selftest.sh so a mode that passes here passes there.
#
#   12  [pmmstress] ✓ ALL CLEAN          (src/test/stress_pmm.zig)
#   14  [pgcache] PASS                    (src/test/page_cache_selftest.zig)
#   16  [disktest] PASS                   (src/test/disk_selftest.zig)
#
# Any other mode runs with a generic "PASS"/"FAIL" grep — extend the table
# below when a new self-test grows a verdict line. Exit status = number of
# failed modes. The last serial log of each mode stays in serial-modeN.log.
#
# Run on the VM, from the repo root:  bash tools/mode_battery.sh 12 14 16
cd "$(dirname "$(readlink -f "$0")")/.."

ZIG=/opt/zig-x86_64-linux-0.15.2/zig
TIMEOUT=${TIMEOUT:-180}
MODES=("$@")
[ ${#MODES[@]} -eq 0 ] && MODES=(12 14 16)

pass_marker() {
    case "$1" in
        12) echo '\[pmmstress\] ✓ ALL CLEAN' ;;
        14) echo '\[pgcache\] PASS' ;;
        16) echo '\[disktest\] PASS' ;;
        *)  echo 'PASS' ;;
    esac
}
fail_marker() {
    case "$1" in
        12) echo '\[pmmstress\] ✗|\[pmmstress\] FAIL' ;;
        14) echo '\[pgcache\] FAIL' ;;
        16) echo '\[disktest\] FAIL' ;;
        *)  echo 'FAIL' ;;
    esac
}

failed=0
for mode in "${MODES[@]}"; do
    echo "=== mode $mode: build ==="
    if ! "$ZIG" build -Doptimize=ReleaseSafe -Dboot-mode="$mode" > "build-mode$mode.log" 2>&1; then
        echo "[battery] mode $mode: BUILD FAILED"; grep -nE "error:" "build-mode$mode.log" | head -5
        failed=$((failed + 1)); continue
    fi
    cp -f /usr/share/OVMF/OVMF_VARS_4M.fd "ovmf_vars-battery.fd"
    [ -f swap.img ] || dd if=/dev/zero of=swap.img bs=1M count=128 status=none
    if [ "$mode" = "16" ]; then rm -f install.img; dd if=/dev/zero of=install.img bs=1M count=256 status=none; fi
    [ -f install.img ] || dd if=/dev/zero of=install.img bs=1M count=256 status=none
    log="serial-mode$mode.log"; rm -f "$log"
    echo "=== mode $mode: boot (timeout ${TIMEOUT}s) ==="
    qemu-system-x86_64 \
        -m 256 -accel kvm -cpu host -smp 2 -no-reboot \
        -vga std -display none \
        -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
        -drive if=pflash,format=raw,file=ovmf_vars-battery.fd \
        -drive file=disk.tar,format=raw,if=none,id=nvm_tar \
        -device nvme,drive=nvm_tar,serial=zigos-tarfs \
        -drive file=fat:rw:zig-out/esp,if=none,id=esp \
        -device ide-hd,drive=esp,bus=ide.0,bootindex=0 \
        -drive file=ext2.img,format=raw,if=none,id=nvm_ext2 \
        -device nvme,drive=nvm_ext2,serial=zigos-ext2 \
        -drive file=swap.img,format=raw,if=none,id=nvm_swap \
        -device nvme,drive=nvm_swap,serial=zigos-swap \
        -drive file=install.img,format=raw,if=none,id=nvm_install \
        -device nvme,drive=nvm_install,serial=zigos-install \
        -serial "file:$log" &
    qpid=$!
    verdict=""
    for ((t = 0; t < TIMEOUT; t++)); do
        sleep 1
        if grep -aqE "$(pass_marker "$mode")" "$log" 2>/dev/null; then verdict=PASS; break; fi
        if grep -aqE "$(fail_marker "$mode")" "$log" 2>/dev/null; then verdict=FAIL; break; fi
        if grep -aqE "!!! WATCHDOG|KERNEL PANIC|\[panic\]|OFF-GRAPH" "$log" 2>/dev/null; then verdict=CRASH; break; fi
        kill -0 "$qpid" 2>/dev/null || { verdict=EXITED; break; }
    done
    [ -z "$verdict" ] && verdict=TIMEOUT
    kill "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null
    echo "[battery] mode $mode: $verdict (${t}s)"
    grep -aE "$(pass_marker "$mode")|$(fail_marker "$mode")|\[smi\] stall|\[pause\]|\[watchdog\]|slow completion|timeout" "$log" | cut -c1-200 | tail -12
    [ "$verdict" = "PASS" ] || failed=$((failed + 1))
done
echo "[battery] done: $failed failed of ${#MODES[@]}"
exit $failed
