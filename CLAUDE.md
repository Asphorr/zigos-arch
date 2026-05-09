# ZigOS — x86_64 Hobby OS in Zig

## Quick Reference

### Build & Deploy (one command)
```bash
ssh -i ~/.ssh/hyperv_vm -o StrictHostKeyChecking=no feroupc@172.23.151.76 "cd ~/zigos-sse2 && bash deploy.sh"
```

### Sync files from Windows to VM
```bash
scp -i ~/.ssh/hyperv_vm -o StrictHostKeyChecking=no <local-files> feroupc@172.23.151.76:~/zigos-sse2/<dest>/
```

### Check serial log
```bash
ssh -i ~/.ssh/hyperv_vm -o StrictHostKeyChecking=no feroupc@172.23.151.76 "tail -30 ~/zigos-sse2/serial.log"
```

### Check for crashes
```bash
ssh -i ~/.ssh/hyperv_vm -o StrictHostKeyChecking=no feroupc@172.23.151.76 "grep 'CRASH\|Exception\|DOOM exit' ~/zigos-sse2/serial.log"
```

## Architecture
- **x86_64 long mode**, Zig 0.15.2 freestanding, Multiboot2
- VM: Ubuntu on Hyper-V (172.23.151.76), QEMU 9.2 with KVM
- Build produces ELF64, objcopy to ELF32 for QEMU Multiboot loading
- 64MB RAM, 1920x1080 virtio-GPU display, USB (xHCI), AC97 audio, virtio-net

## Project Layout
```
src/           — Kernel source (Zig)
  ├── main.zig, boot.asm    — Entry points
  ├── idt.zig, process.zig  — Interrupts, scheduling
  ├── virtio_gpu.zig         — GPU driver (2D scanout + 3D/Venus)
  ├── desktop.zig            — Window manager + compositor
  ├── gfx.zig                — Graphics primitives, SSE2 blit
  ├── ata.zig, fat32.zig     — Disk I/O (DMA + FAT32)
  ├── xhci.zig               — USB 3.0 driver
  ├── ac97.zig               — Audio driver
  ├── syscall.zig            — Syscall handlers (int 0x80)
  └── pci.zig, pmm.zig, vmm.zig, paging.zig — Hardware

app/           — User-space apps (Zig)
  ├── doom_real.zig          — DOOM platform layer (C FFI)
  ├── vulkan_cube.zig        — Spinning cube (Venus/Vulkan)
  ├── vulkan_triangle.zig    — Static triangle (Venus/Vulkan)
  └── app.zig, calc.zig, paint.zig, editor.zig, ...

lib/           — User-space libraries
  ├── libc.zig               — Syscall wrappers, malloc, graphics API
  ├── venus.zig              — Venus wire protocol encoder (~40 functions)
  └── virgl.zig              — VirGL command encoder

doom_src/      — Chocolate DOOM C source (51 files)
  ├── z_zone.c               — Zone allocator (REWRITTEN — malloc-backed)
  ├── doomfeatures.h         — Feature flags (FEATURE_SOUND enabled)
  └── i_sound.c              — Sound interface
```

## Coding Rules
- **Idiomatic Zig** — `for (0..N) |i|`, `@intFromBool`, `@memset`, `const` over `var`
- **extern struct** for C FFI — field order MUST match C exactly, count all fields
- **Venus wire protocol** — always verify CMD IDs against virglrenderer headers on VM at `/home/feroupc/virglrenderer/src/venus/venus-protocol/`
- **Column-major matrices** for GLSL push constants — multiply: `r[col*4+row] = sum(a[k*4+row] * b[col*4+k])`
- **DOOM exports** — `memcpy`/`memset` must use manual loops (NOT @memcpy — causes self-recursion)

## Common Pitfalls
- **QEMU Multiboot + ELF64**: Must objcopy to ELF32 after linking
- **Venus VkClearColorValue**: float32 array needs `writeU64(4)` size prefix before 4 floats
- **Music module struct**: Must include ALL fields (UnRegisterSong was missing → shifted vtable → crash)
- **Zone allocator**: Original DOOM allocator is broken — use our malloc-backed replacement
- **USB F-keys**: xHCI hidUsageToAscii must output KEY_F1+ codes, not just set key_state
- **QEMU GTK steals F11**: Use F10 for OS fullscreen
- **SHM blob overlap**: All Venus blobs map to offset 0 — multiple GPU contexts can interfere

## Syscalls (int 0x80, EAX=num)
| # | Name | Args |
|---|------|------|
| 1 | print | ptr, len |
| 5 | sbrk | increment |
| 9 | open | name_ptr |
| 10 | fread | fd, buf, len |
| 13 | createWindow | w, h |
| 14 | present | — |
| 15 | getMouse | buf_ptr (5 u32s) |
| 26 | keyHeld | scancode |
| 29 | fsize | name_ptr |
| 30-37 | GPU 3D | various |
| 38 | audioWrite | samples_ptr, num_stereo |

## Testing Checklist
After kernel changes, verify:
- [ ] Desktop boots, windows work
- [ ] Terminal accepts commands
- [ ] DOOM launches and plays (with sound)
- [ ] Vulkan cube renders and animates
- [ ] Fullscreen (F10) works
- [ ] No crashes in serial log
