@echo off
cd /d D:\zigos-sse2
wsl -e bash -c "cd /mnt/d/zigos-sse2 && zig build -Doptimize=ReleaseSafe 2>&1"
if %errorlevel% neq 0 (
    echo Build failed!
    pause
    exit /b 1
)
echo Build OK.
set /p confirm=Launch QEMU? (y/n):
if /i "%confirm%"=="y" (
    qemu-system-i386 -m 64 -accel whpx,kernel-irqchip=off -vga virtio -display sdl,gl=on -device qemu-xhci,id=xhci -device usb-kbd -device usb-mouse -device virtio-net-pci,netdev=net0 -netdev user,id=net0 -audiodev sdl,id=snd0 -machine pcspk-audiodev=snd0 -device AC97,audiodev=snd0 -drive file=disk.tar,format=raw,index=0,if=ide -drive file=D:/zigos/disk.img,format=raw,index=2,if=ide -serial file:D:/zigos-sse2/serial.log -kernel zig-out/bin/kernel.elf
)
