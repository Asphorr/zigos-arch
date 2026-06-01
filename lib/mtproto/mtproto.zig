//! MTProto client library bundle (imported as the "mtproto" module).
//!
//! The pure pieces (tl/ige/factor/rsa/rsa_key/kdf/dh) are `zig test`-validated
//! off-target against the official core.telegram.org sample; transport and
//! auth are the live, network-touching pieces.

pub const tl = @import("tl.zig");
pub const ige = @import("ige.zig");
pub const factor = @import("factorize.zig");
pub const rsa = @import("rsa_pad.zig");
pub const rsa_key = @import("rsa_key.zig");
pub const kdf = @import("kdf.zig");
pub const dh = @import("dh.zig");
pub const session = @import("session.zig");
pub const api = @import("api.zig");
pub const dialogs = @import("dialogs.zig");
pub const qr = @import("qr.zig");
pub const transport = @import("transport.zig");
pub const auth = @import("auth.zig");
