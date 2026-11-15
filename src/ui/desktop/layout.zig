// Spatial constants for the desktop chrome — menubar, dock, window
// titlebar / border / corner-button radius. Imported by every extracted
// desktop submodule (toast, dock, menubar, compositor, …) so they can
// reference layout values without reaching back into desktop.zig and
// creating a circular import.
//
// Terminal-specific constants (TERM_COLS, FONT_W/H, ANSI_PALETTE, …)
// belong with the terminal submodule and stay in desktop.zig until that
// extraction lands.

pub const MENUBAR_H: u32 = 26; // top menu bar height
pub const TASKBAR_H: u32 = 64; // dock band height (pill plus margins)
pub const TITLEBAR_H: u32 = 32;
pub const BORDER: u32 = 1;

// Traffic lights: three discs of BTN_RADIUS, the first centered BTN_FIRST_X
// from the window's left edge, BTN_PITCH apart. Hit-testing (window.zig)
// and painting (desktop.zig) both place them from these.
pub const BTN_RADIUS: u32 = 6;
pub const BTN_FIRST_X: i32 = 19;
pub const BTN_PITCH: i32 = 20;

pub const DOCK_ICON_SIZE: u32 = 32;
pub const DOCK_ICON_PAD: u32 = 10; // gap between icons
pub const DOCK_PILL_PAD: u32 = 10; // pill edge to the first/last icon
pub const DOCK_PILL_H: u32 = 52;
pub const DOCK_PILL_RADIUS: u32 = 16;
pub const DOCK_MARGIN_BOTTOM: u32 = 8; // pill bottom to the screen edge

// Accent for selection and hover across the chrome (menus, dock, icons).
pub const ACCENT: u32 = 0x0A84FF;
