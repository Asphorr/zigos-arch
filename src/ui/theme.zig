// Theme: all named UI colors + the ANSI 16-color palette in one place.
//
// Single-consumer (desktop.zig); split out so the values are easy to tweak
// without scrolling past 100 KB of layout/render code, and so a future
// "theme presets" feature can swap them at runtime by re-pointing one
// module reference instead of editing scattered literals.
//
// Cell attribute encoding (per `attr_buf` byte in TerminalData):
//   bits 0..3 : fg palette index (0..15)
//   bit 4     : bold (also brightens — palette[idx | 8])
//   bit 5     : inverse (swap fg/bg)
//   bits 6..7 : reserved (italic/underline next pass)

// --- Window chrome (macOS-inspired) ---
pub const BG_TOP_DEFAULT: u32 = 0x1B2838;
pub const BG_BOTTOM_DEFAULT: u32 = 0x2D5F8A;
pub const TITLEBAR_FOCUSED: u32 = 0xE8E8E8;
pub const TITLEBAR_UNFOCUSED: u32 = 0xD0D0D0;
pub const TITLEBAR_TEXT_F: u32 = 0x4A4A4A;
pub const TITLEBAR_TEXT_U: u32 = 0x9A9A9A;
pub const WINDOW_BG: u32 = 0x1E1E1E;
pub const WINDOW_BORDER: u32 = 0xBBBBBB;
pub const WINDOW_SHADOW: u32 = 0x0A0A0A;
pub const TERM_FG: u32 = 0xCCCCCC;

// --- Traffic-light buttons ---
pub const BTN_CLOSE: u32 = 0xFF5F57;
pub const BTN_MINIMIZE: u32 = 0xFEBC2E;
pub const BTN_MAXIMIZE: u32 = 0x28C840;

// --- Dock ---
pub const DOCK_BG: u32 = 0x2A2A2A;
pub const DOCK_BORDER: u32 = 0x505050;
pub const DOCK_TEXT: u32 = 0xCCCCCC;
pub const DOCK_ACTIVE: u32 = 0x4488CC;

// --- ANSI 16-color palette (indices 0..7 = normal, 8..15 = bright) ---
pub const ANSI_PALETTE: [16]u32 = .{
    0x000000, 0xCC3333, 0x33CC33, 0xCCCC33, // black red green yellow
    0x3366CC, 0xCC33CC, 0x33CCCC, 0xCCCCCC, // blue magenta cyan white
    0x666666, 0xFF6666, 0x66FF66, 0xFFFF66, // bright versions
    0x6699FF, 0xFF66FF, 0x66FFFF, 0xFFFFFF,
};

pub const ATTR_DEFAULT: u8 = 0x07;
pub const ATTR_BOLD: u8 = 0x10;
pub const ATTR_INVERSE: u8 = 0x20;

// --- Terminal behavior tunables ---
pub const TAB_WIDTH: u8 = 8;
pub const BELL_FLASH_FRAMES: u8 = 12;
/// Cursor blink half-period in 100Hz timer ticks (~300ms). Driven by
/// `process.tick_count` so the rate is independent of how often the desktop
/// loop wakes.
pub const CURSOR_BLINK_HALF_TICKS: u64 = 30;
pub const BELL_FLASH_COLOR: u32 = 0xFF4444;
