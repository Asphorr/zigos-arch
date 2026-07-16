// Faultable user-memory copy — copyFromUser / copyToUser / strnlenUser.
//
// Kernel-mode access to user memory has had NO fault recovery in this tree:
// the #PF handler services lazy/COW faults for ring 3 only, so a kernel
// `@memcpy` into a user buffer whose page went away (swap eviction by a
// sibling thread, munmap from another thread, a hostile pointer that dodged
// validation) is an instant autopsy panic. The whole safety story rested on
// validateUserPtr* prefaulting the range at syscall entry and the pages
// staying resident for the syscall's duration — a guarantee a blocking
// syscall (pipe read parked for seconds) simply does not have.
//
// This module replaces the bare memcpy with *faultable* copies: the copy
// instruction is a registered exception-table site (see extable.zig), and a
// kernel-mode #PF (or #GP for a non-canonical address) at that site is
// recovered by redirecting the saved RIP to a fixup landing pad. The copy
// reports how many bytes it moved instead of panicking; the caller decides
// whether to fault the page in and retry, or fail with EFAULT.
//
// ── Two layers ──────────────────────────────────────────────────────────
//   copyFromUserRaw / copyToUserRaw / strnlenUserRaw
//       Single attempt, never blocks, never panics on a bad page. Safe in
//       ANY context — under spinlocks, with IRQs off, in IRQ handlers.
//       Returns partial progress; the fault is reported, not resolved.
//   copyFromUser / copyToUser / strnlenUser
//       Raw attempt + fault-in retry (prefaultUserRange /
//       ensureUserRangeWritable, which may do swap-in DISK I/O and block).
//       BLOCKABLE CONTEXT ONLY: current-process syscall path, no spinlocks
//       held, IRQs on. This is the layer that makes swap eviction
//       transparent to syscalls.
//
// ── How the recovery works (msr.zig's extable pattern, generalized) ─────
// The accessor publishes (fault_rip, fixup_rip) into module globals via
// `leaq Nf(%rip)` on every entry — idempotent, so the entry is live before
// its own faulting instruction can execute, with no registration step and
// no locks. exception.zig consults extable.fixupRip(saved_rip) on any
// kernel-mode #PF/#GP; on a match it rewrites the saved RIP to the fixup
// and returns. `rep movsb` is restartable: at fault time RCX holds exactly
// the bytes NOT yet copied, so the fixup (which is simply the instruction
// after the rep) reads the partial progress straight out of RCX. The
// success path falls through to the same label with RCX=0 — one landing
// pad serves both outcomes, and rem>0 <=> faulted.
//
// The site addresses are link-time invariants ONLY because the inner
// functions are `noinline`: inlining would duplicate a site into every
// caller, and concurrent callers of different instances would cross-stomp
// the published globals — a fault at instance A while instance B's
// addresses are published would miss the table and panic.
//
// ── SMAP ────────────────────────────────────────────────────────────────
// The raw primitives bracket the copy with STAC/CLAC but PRESERVE the
// ambient AC state: validateUserPtr STACs for the remainder of the syscall
// (doSyscall's defer CLACs on exit), and blindly CLACing here would close
// that window under a caller that still has direct user derefs ahead.
//
// ── Caveats ─────────────────────────────────────────────────────────────
// * The asm copy bypasses KASAN instrumentation of the kernel-side buffer
//   (same as Linux's usercopy; the user side was never instrumented).
// * These primitives do not replace pointer VALIDATION — the retry layer
//   range-checks against user space, but permission semantics (writable,
//   aligned) remain the validateUserPtr*/UserPtr(T) contract. What this
//   adds is crash-proofness when a validated page stops being resident.

const std = @import("std");
const debug = @import("../../debug/debug.zig");
const protect = @import("protect.zig");
const process = @import("../../proc/process.zig");
const memmap = @import("../../mm/memmap.zig");

// Published fault/fixup instruction addresses — one pair per asm site.
// Zero until the site first runs; republished (idempotently) on entry.
var copy_fault_rip: u64 = 0;
var copy_fixup_rip: u64 = 0;
var scan_fault_rip: u64 = 0;
var scan_fixup_rip: u64 = 0;

/// Consulted (via extable.fixupRip) by the kernel-mode #PF/#GP hook.
/// Returns the fixup RIP if `rip` is one of this module's fault sites.
pub fn fixupRip(rip: u64) ?u64 {
    if (copy_fault_rip != 0 and rip == copy_fault_rip) return copy_fixup_rip;
    if (scan_fault_rip != 0 and rip == scan_fault_rip) return scan_fixup_rip;
    return null;
}

/// The one copy site — shared by both directions (the fault recovery does
/// not care which side of the copy is user memory). Returns bytes REMAINING
/// (0 = complete; >0 = faulted after `len - rem` bytes). noinline is
/// load-bearing — see the header.
///
/// Register discipline mirrors msr.zig's working recipe for this toolchain
/// (Zig 0.15.2 + LLVM 20): generic `r` inputs moved into rsi/rdi/rcx inside
/// the asm, generic `=r` output, `=m` address publishes, explicit clobbers.
/// Register-specific outputs alongside `=m` publishes + internal labels are
/// the known miscompile shape (msr.zig doc has the details). `cld` per the
/// boot.asm lesson: never trust inherited DF around rep string ops.
noinline fn copyRawInner(dst: usize, src: usize, len: usize) usize {
    var rem: usize = undefined;
    asm volatile (
        \\ leaq 1f(%rip), %r8
        \\ movq %r8, %[frip]
        \\ leaq 2f(%rip), %r8
        \\ movq %r8, %[fxup]
        \\ movq %[src], %rsi
        \\ movq %[dst], %rdi
        \\ movq %[len], %rcx
        \\ cld
        \\1: rep movsb
        \\2: movq %rcx, %[rem]
        : [rem] "=r" (rem),
          [frip] "=m" (copy_fault_rip),
          [fxup] "=m" (copy_fixup_rip),
        : [dst] "r" (dst),
          [src] "r" (src),
          [len] "r" (len),
        : .{ .rsi = true, .rdi = true, .rcx = true, .r8 = true, .cc = true, .memory = true }
    );
    return rem;
}

/// The one scan site — `repne scasb` hunting a NUL. Returns (rem, found):
///   found=true  → NUL hit; scanned length = max - rem - 1 (NUL consumed).
///   found=false, rem=0 → no NUL within max.
///   found=false, rem>0 → faulted before a NUL (rem bytes unscanned).
/// The fault path lands on `sete` with the fault-time flags restored by
/// iretq. A rep-string fault leaves flags reflecting the LAST COMPLETED
/// iteration (SDM): mid-string that's a non-match (ZF=0 — a match would
/// have stopped the scan), and a fault on the FIRST byte leaves the
/// pre-rep flags — which is why the `orq $1, %r8` below force-clears ZF
/// before the scan (the xor sets it; without the clear, a first-byte
/// fault would read as found=true with rem==max and underflow the length
/// math). So found=false is guaranteed on every fault path. Caller must
/// reject max==0 (a zero-count rep never runs and never touches flags).
noinline fn strnlenInner(ptr: usize, max: usize) struct { rem: usize, found: bool } {
    var rem: usize = undefined;
    var found: usize = undefined;
    asm volatile (
        \\ leaq 1f(%rip), %r8
        \\ movq %r8, %[frip]
        \\ leaq 2f(%rip), %r8
        \\ movq %r8, %[fxup]
        \\ movq %[ptr], %rdi
        \\ movq %[max], %rcx
        \\ xorl %eax, %eax
        \\ orq $1, %r8
        \\ cld
        \\1: repne scasb
        \\2: sete %al
        \\ movzbq %al, %rax
        \\ movq %rax, %[found]
        \\ movq %rcx, %[rem]
        : [rem] "=r" (rem),
          [found] "=r" (found),
          [frip] "=m" (scan_fault_rip),
          [fxup] "=m" (scan_fixup_rip),
        : [ptr] "r" (ptr),
          [max] "r" (max),
        : .{ .rax = true, .rdi = true, .rcx = true, .r8 = true, .cc = true, .memory = true }
    );
    return .{ .rem = rem, .found = found != 0 };
}

/// Copy `dst.len` bytes from user VA `user_src` into kernel `dst`. Single
/// attempt: returns bytes actually copied (== dst.len on success); a bad
/// page truncates instead of panicking. Safe in any context.
pub fn copyFromUserRaw(dst: []u8, user_src: usize) usize {
    if (dst.len == 0) return 0;
    const had_ac = protect.readAC();
    protect.allowUserAccess();
    const rem = copyRawInner(@intFromPtr(dst.ptr), user_src, dst.len);
    if (!had_ac) protect.disallowUserAccess();
    return dst.len - rem;
}

/// Copy `src.len` bytes from kernel `src` to user VA `user_dst`. Single
/// attempt, partial on fault. Safe in any context. NOTE: does not break
/// COW or check writability — a present-but-RO page faults and truncates;
/// use the retry layer (or validateUserPtrWrite beforehand) for real
/// syscall write-outs.
pub fn copyToUserRaw(user_dst: usize, src: []const u8) usize {
    if (src.len == 0) return 0;
    const had_ac = protect.readAC();
    protect.allowUserAccess();
    const rem = copyRawInner(user_dst, @intFromPtr(src.ptr), src.len);
    if (!had_ac) protect.disallowUserAccess();
    return src.len - rem;
}

/// Length of the NUL-terminated user string at `user_ptr`, scanning at most
/// `max` bytes. Returns the length excluding the NUL; `max` if no NUL found
/// within max (caller maps to ENAMETOOLONG); null on fault. Single attempt,
/// safe in any context. This is the primitive the sysOpen page-crossing
/// class wants — the scan itself is fault-tolerant, so no per-page
/// revalidation dance.
pub fn strnlenUserRaw(user_ptr: usize, max: usize) ?usize {
    if (max == 0) return 0;
    const had_ac = protect.readAC();
    protect.allowUserAccess();
    const r = strnlenInner(user_ptr, max);
    if (!had_ac) protect.disallowUserAccess();
    if (r.found) return max - r.rem - 1;
    if (r.rem == 0) return max;
    return null;
}

/// Retry cap for the fault-in layer. A retry only recurs if a page got
/// re-evicted (or re-CoWed) in the window between fault-in and the copy
/// resuming — each iteration makes byte progress or fails fault-in, so
/// this bounds pathological eviction races, not normal operation (which
/// takes 0 or 1 retries).
const MAX_FAULT_RETRIES: u8 = 4;

/// Copy from user with fault-in retry: on a partial copy, page the missing
/// range back in (swap-in, lazy alloc — MAY BLOCK on disk I/O) and resume
/// where the copy stopped. Returns false if the range is not user space or
/// a page cannot be made present (EFAULT at the caller).
/// BLOCKABLE CONTEXT ONLY: current-process syscall path, no spinlocks, IRQs on.
pub fn copyFromUser(dst: []u8, user_src: usize) bool {
    if (dst.len == 0) return true;
    if (!memmap.userDataRangeOk(user_src, dst.len)) return false;
    var done: usize = 0;
    var tries: u8 = 0;
    while (true) {
        done += copyFromUserRaw(dst[done..], user_src + done);
        if (done == dst.len) return true;
        tries += 1;
        if (tries > MAX_FAULT_RETRIES) return false;
        process.prefaultUserRange(user_src + done, dst.len - done);
        if (!process.allCurrentUserPagesMapped(user_src + done, dst.len - done)) return false;
    }
}

/// Copy to user with fault-in retry (also breaks COW / rejects genuinely
/// read-only targets via ensureUserRangeWritable). Same contract as
/// copyFromUser: blockable context only; false → EFAULT.
pub fn copyToUser(user_dst: usize, src: []const u8) bool {
    if (src.len == 0) return true;
    if (!memmap.userDataRangeOk(user_dst, src.len)) return false;
    var done: usize = 0;
    var tries: u8 = 0;
    while (true) {
        done += copyToUserRaw(user_dst + done, src[done..]);
        if (done == src.len) return true;
        tries += 1;
        if (tries > MAX_FAULT_RETRIES) return false;
        if (!process.ensureUserRangeWritable(user_dst + done, src.len - done)) return false;
    }
}

/// strnlenUserRaw with fault-in retry. null → EFAULT. Blockable context
/// only. On a fault the whole window is faulted in and rescanned from the
/// start (the raw API doesn't report the partial scan distance) —
/// path-sized maxima (~100 bytes) make the rescan cost nil.
pub fn strnlenUser(user_ptr: usize, max: usize) ?usize {
    if (max == 0) return 0;
    if (!memmap.userDataRangeOk(user_ptr, max)) return null;
    var tries: u8 = 0;
    while (true) {
        if (strnlenUserRaw(user_ptr, max)) |len| return len;
        tries += 1;
        if (tries > MAX_FAULT_RETRIES) return null;
        process.prefaultUserRange(user_ptr, max);
        if (!process.allCurrentUserPagesMapped(user_ptr, max)) return null;
    }
}

/// Boot self-test: prove the #PF fixup recovers a faulting user copy, does
/// not over-fire on a valid one, and that the scan site discriminates its
/// three outcomes. Requires the IDT (with the extable hook) to be live.
/// The "bad" VA is the top of the canonical user half — never mapped in the
/// boot address space; if a host surprise makes it readable we log
/// "not exercised" rather than failing, mirroring msr.selfTest.
pub fn selfTest() void {
    const BAD: usize = 0x0000_7FFF_FFFF_0000;
    var buf: [16]u8 = undefined;

    const got = copyFromUserRaw(buf[0..], BAD);
    if (got == 0) {
        debug.klog("[usercopy] fault fixup VERIFIED — copy from 0x{X} recovered at 0 bytes\n", .{BAD});
    } else {
        debug.klog("[usercopy] fixup present but NOT exercised — 0x{X} readable ({d} bytes)\n", .{ BAD, got });
    }

    // Over-fire guard: a kernel->kernel copy through the SAME site must
    // complete and carry the right bytes.
    const src = [_]u8{ 0xA5, 0x5A, 0xC3, 0x3C } ** 4;
    var dst = [_]u8{0} ** 16;
    _ = &dst; // mutated through the laundered address below — invisible to the compiler
    const n = copyRawInner(@intFromPtr(&dst), @intFromPtr(&src), 16);
    if (n != 0 or !std.mem.eql(u8, dst[0..], src[0..])) {
        debug.klog("[usercopy] WARNING: valid copy truncated/corrupt (rem={d}) — fixup OVER-FIRING\n", .{n});
    }

    // Scan site: NUL find, no-NUL saturation, and fault recovery (the
    // fault case also proves the first-byte ZF clear — see strnlenInner).
    const s = "zigos\x00padpad";
    const l1 = strnlenUserRaw(@intFromPtr(s), 12);
    const l2 = strnlenUserRaw(@intFromPtr(s), 3);
    const l3 = strnlenUserRaw(BAD, 8);
    if (l1 != 5 or l2 != 3 or l3 != null) {
        debug.klog("[usercopy] WARNING: strnlen outcomes wrong (got {?d}/{?d}/{?d}, want 5/3/null)\n", .{ l1, l2, l3 });
    }
}
