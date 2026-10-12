# Host GPU for Venus under WSL2 (Mesa dzn)

ZigOS's Venus clients (the mode-9 GPU compositor, `vulkan_triangle`) can run
on the Windows host's GPU through WSL2's GPU paravirtualization:

    guest virtio-gpu (Venus) -> QEMU -> virglrenderer (vkr, render server
    in-process) -> Mesa dzn (Vulkan on D3D12) -> /dev/dxg -> host GPU driver

Tested with an RTX 3050 on Windows 10 (WSL2, Ubuntu 24.04), QEMU under TCG:
Windows 10's WSL2 has no nested virtualization, so there is no KVM.

Upstream virglrenderer and QEMU cannot do this as is; the two patches here
fill the gaps. Nothing in them is ZigOS-specific.

## Patches

`virglrenderer-host-ptr.patch` — base: virglrenderer `main` at `c8e3fc3`.

vkr exports host-visible memory as an fd so the VMM can map it into the
guest. dzn cannot export host-visible memory at all (D3D12 forbids
CPU-visible shared heaps). With the render server built into QEMU
(`-Drender-server-mode=thread`) no fd is needed: the blob can be the
driver's own `vkMapMemory` pointer.

- New `VIRGL_RESOURCE_HOST_PTR` resource type. `virgl_renderer_resource_map`
  returns the pointer, and fd export is refused. The render protocol passes
  the pointer only when the server runs in-process.
- At allocation, each memory type is probed once with a 64 KB exportable
  allocation. Host-visible memory the driver cannot export is allocated
  without export, and its blob becomes the mapping (MAPPABLE blobs only, no
  CROSS_DEVICE).
- The guest can free memory that QEMU still maps into the guest. Such memory
  is kept until the resource is destroyed or the device goes away. The freed
  range is then backfilled with anonymous pages, so a late access reads zeros
  instead of faulting.

On drivers that can export, nothing changes.

`qemu-11.1-scanout-host-ptr.patch` — base: QEMU 11.1.0 release tarball.

`SET_SCANOUT_BLOB` required a dma-buf. When there is none but the blob is
mapped, QEMU now wraps the mapping in a pixman surface without copying it.
`RESOURCE_FLUSH` uploads just the flushed rect to the display, and a scanout
is disabled when its blob is unmapped.

## Build (Ubuntu 24.04 on WSL2)

```sh
sudo apt-get install build-essential git meson ninja-build pkg-config \
    python3-mako python3-yaml python3-packaging python3-ply python3-venv \
    bison flex glslang-tools libdrm-dev libexpat1-dev zlib1g-dev libzstd-dev \
    libepoxy-dev libvulkan-dev libgbm-dev libglib2.0-dev libpixman-1-dev \
    libslirp-dev libsdl2-dev ovmf python3-tomli wget xz-utils \
    nasm dosfstools mtools genext2fs
sudo pip install --break-system-packages meson   # Mesa 26.2 needs a newer meson (used 1.10.1)

P=$HOME/gpupv/install
export PKG_CONFIG_PATH=$P/lib/x86_64-linux-gnu/pkgconfig:$P/lib/pkgconfig
cd $HOME/gpupv

# Mesa 26.2.4, dzn only (meson fetches DirectX-Headers as a subproject)
git clone --depth 1 --branch mesa-26.2.4 https://gitlab.freedesktop.org/mesa/mesa.git
(cd mesa && meson setup build -Dbuildtype=release -Dprefix=$P -Dplatforms= \
    -Dgallium-drivers= -Dvulkan-drivers=microsoft-experimental -Dopengl=false \
    -Dgles1=disabled -Dgles2=disabled -Degl=disabled -Dglx=disabled \
    -Dgbm=disabled -Dllvm=disabled -Dvideo-codecs= && ninja -C build install)

# virglrenderer, render server in-process
git clone https://gitlab.freedesktop.org/virgl/virglrenderer.git
(cd virglrenderer && git checkout c8e3fc3 \
    && git apply /path/to/zigos-arch/tools/host-gpu/virglrenderer-host-ptr.patch \
    && meson setup build -Dbuildtype=release -Dprefix=$P -Dvenus=true \
       -Dplatforms=egl -Drender-server-mode=thread -Drender-server-worker=thread \
    && ninja -C build install)

# QEMU 11.1.0
wget https://download.qemu.org/qemu-11.1.0.tar.xz && tar xf qemu-11.1.0.tar.xz
(cd qemu-11.1.0 && patch -p1 < /path/to/zigos-arch/tools/host-gpu/qemu-11.1-scanout-host-ptr.patch \
    && ./configure --prefix=$P --target-list=x86_64-softmmu --enable-opengl \
       --enable-virglrenderer --enable-sdl --enable-slirp --disable-docs --disable-werror \
    && ninja -C build qemu-system-x86_64)
```

Then build ZigOS in WSL with Zig 0.15.2 (`zig build -Doptimize=ReleaseSafe`)
and run `tools/host-gpu/run-wsl-dzn.sh`. `GPUPV`, `PREFIX` and `QEMU`
override the paths above. In the boot menu, pick "GPU Compositor
(experimental)" to get mode 9.

The vkr log should say `memory type N: host-visible export unavailable,
mapping via host pointers`. The ZigOS log should show `[gpu-comp] ...
sources=staged (GPU upload)` and `scanout: single mapped buffer, damage
flush`. `vulkan_triangle` reads back `9600 red of 76800` pixels.

## QEMU flags

Each of these works around a TCG problem ZigOS hits:

- `-accel tcg,thread=single -icount shift=auto,sleep=on`: under MTTCG the
  guest TSC calibrates far too high (13 GHz seen), so deadlines never expire
  (e.g. hda self-test hangs).
- `-cpu max,phys-bits=39`: with the default physical address width, PCI
  BARs land above the kernel's 512 GB physmap (#PF in msix).
- `monitor=off`: TCG advertises MWAIT interrupt-break but its MWAIT raises
  #GP when ECX is non-zero.
- `x2apic=off`: with icount, QEMU aborts on the x2APIC timer MSR read ("Bad
  icount read").
- `SDL_VIDEODRIVER=wayland GALLIUM_DRIVER=d3d12`: WSLg's X11 has no DRI3, so
  GL would fall back to software rendering.

## Limitations

- TCG only: a handful of frames per second, bound by guest CPU emulation,
  not the GPU.
- WSLg presents the QEMU window by copying it (`[WARN:COPY MODE]` in the
  title).
- Lavapipe under WSL crashes QEMU in vkr's gbm fallback (`gbm_bo_create`; no
  DRM device). Test the Lavapipe path on a Linux host with KVM instead.
- There, use the SDL display: `egl-headless` crashes QEMU on the dma-buf
  scanout, with or without these patches.
