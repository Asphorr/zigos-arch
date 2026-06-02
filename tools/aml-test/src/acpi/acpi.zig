// Minimal stub of acpi.zig for the AML native test harness. aml.zig drives
// walkBody() directly in selfTestExtended(), so the table getters can all be
// empty — only the types and zero-returning getters need to exist to compile.
pub const SdtHeader = extern struct {
    signature: [4]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
};
pub const Gas = extern struct { addr_space: u8, bit_width: u8, bit_offset: u8, access_size: u8, address: u64 align(1) };
pub const Hpet = extern struct { id: u32 align(1) = 0, address: Gas = undefined, num: u8 = 0, tick: u16 align(1) = 0, prot: u8 = 0 };
pub const SleepTypes = struct { a: u8, b: u8 };
pub fn getDsdt() ?*align(1) const SdtHeader { return null; }
pub fn ssdtCount() usize { return 0; }
pub fn getSsdt(i: usize) ?*align(1) const SdtHeader { _ = i; return null; }
pub fn getHpet() ?*align(1) const Hpet { return null; }
pub fn getS5SleepTypes() ?SleepTypes { return null; }
