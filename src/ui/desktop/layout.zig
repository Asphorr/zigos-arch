// Spatial constants for the desktop chrome — menubar, dock, window
// titlebar / border / corner-button radius. Imported by every extracted
// desktop submodule (toast, dock, menubar, compositor, …) so they can
// reference layout values without reaching back into desktop.zig and
// creating a circular import.
//
// Terminal-specific constants (TERM_COLS, FONT_W/H, ANSI_PALETTE, …)
// belong with the terminal submodule and stay in desktop.zig until that
// extraction lands.

pub const MENUBAR_H: u32 = 28; // top menu bar height
pub const TASKBAR_H: u32 = 64; // dock height (including margin)
pub const TITLEBAR_H: u32 = 34;
pub const BORDER: u32 = 1;
pub const BTN_RADIUS: u32 = 7;

pub const DOCK_ICON_SIZE: u32 = 32;
pub const DOCK_ICON_PAD: u32 = 6;
pub const DOCK_PILL_PAD: u32 = 10;
pub const DOCK_MARGIN_BOTTOM: u32 = 6;
