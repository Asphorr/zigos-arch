// Test stub for driver/nic.zig.
//
// The real NIC driver puts frames on the wire and drains an RX ring. Here we
// instead CAPTURE every transmitted frame into a FIFO so the harness — which
// plays the role of the remote peer — can inspect exactly what the stack sent
// (SYN-ACKs, data segments, retransmissions). Inbound frames are injected
// directly via net.handleRxFrame(), so recv() always returns null.
const FRAME_MAX = 1600;
const TX_CAP = 512;

var tx_buf: [TX_CAP][FRAME_MAX]u8 = undefined;
var tx_len: [TX_CAP]usize = [_]usize{0} ** TX_CAP;
var tx_head: usize = 0; // next slot to write
var tx_tail: usize = 0; // next slot to read

pub var mac_addr: [6]u8 = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };

pub fn init() bool {
    return true;
}
pub fn isReady() bool {
    return true;
}
pub fn name() []const u8 {
    return "test0";
}
pub fn getMac() [6]u8 {
    return mac_addr;
}

pub fn send(data: []const u8) bool {
    if (data.len > FRAME_MAX) return false;
    const i = tx_head % TX_CAP;
    @memcpy(tx_buf[i][0..data.len], data);
    tx_len[i] = data.len;
    tx_head += 1;
    return true;
}

pub fn recv() ?[]volatile u8 {
    return null;
}
pub fn rxRelease() void {}

// --- harness inspection API (not part of the real nic interface) ---

/// Number of captured-but-unread TX frames.
pub fn txCount() usize {
    return tx_head - tx_tail;
}

/// Pop the oldest captured TX frame, or null if none. The returned slice
/// aliases the static capture buffer; read it before TX_CAP further sends.
pub fn txPop() ?[]u8 {
    if (tx_tail == tx_head) return null;
    const i = tx_tail % TX_CAP;
    tx_tail += 1;
    return tx_buf[i][0..tx_len[i]];
}

/// Discard all captured frames.
pub fn txClear() void {
    tx_tail = tx_head;
}
