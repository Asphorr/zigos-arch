//! Device drivers, by class. Code outside src/driver/ reaches them through
//! here, so a driver can move inside the tree without touching its users.

// Buses and transports.
pub const pci = @import("driver/bus/pci.zig");
pub const virtio = @import("driver/bus/virtio.zig");

// Block devices.
pub const block = @import("driver/block.zig");
pub const nvme = @import("driver/block/nvme.zig");
pub const ahci = @import("driver/block/ahci.zig");
pub const ata = @import("driver/block/ata.zig");

// Network cards.
pub const nic = @import("driver/nic.zig");
pub const e1000 = @import("driver/nic/e1000.zig");
// @"": i225 is also a primitive type, a 225-bit integer. `.i225` reads it.
pub const @"i225" = @import("driver/nic/i225.zig");
pub const virtio_net = @import("driver/nic/virtio_net.zig");

// Display.
pub const gpu = @import("driver/gpu.zig");
pub const gop_fb = @import("driver/gop_fb.zig");
pub const virtio_gpu = @import("driver/virtio_gpu.zig");

// Sound.
pub const sound = @import("driver/sound.zig");
pub const ac97 = @import("driver/ac97.zig");
pub const hda = @import("driver/hda.zig");
pub const virtio_sound = @import("driver/virtio_sound.zig");
pub const speaker = @import("driver/speaker.zig");

// Input.
pub const keyboard = @import("driver/keyboard.zig");
pub const mouse = @import("driver/mouse.zig");

// USB.
pub const xhci = @import("driver/xhci.zig");

// Consoles.
pub const virtio_console = @import("driver/virtio_console.zig");
