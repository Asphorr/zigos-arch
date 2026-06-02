// Test stub: identity phys<->virt so an OperationRegion placed at a real test
// buffer's "physical" address (= its address, via virtToPhys) round-trips back
// to that buffer. isMapped is permissive (any non-null address) — the harness
// only ever points regions at real, live Zig buffers.
pub const PHYSMAP_SIZE: u64 = 0x1000_0000_0000;
pub const PHYSMAP_BASE: u64 = 0;
pub inline fn physToVirt(phys: u64) u64 {
    return phys;
}
pub inline fn virtToPhys(virt: u64) ?u64 {
    return virt;
}
pub fn isMapped(va: u64) bool {
    return va != 0;
}
