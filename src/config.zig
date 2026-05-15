// Per-feature kernel limits — single source of truth, so a future tuning
// pass (or a pre-1.0 build-flag conversion) lives in one place.
//
// These are *kernel* limits — userspace constants like MAX_LINE in shell
// stay in their own module because they're argued only locally.
//
// Comptime invariants are at the bottom; if a future change makes one
// inconsistent (e.g. shrinking MAX_PROCS below 2 so SMP can't have an idle
// per CPU), it's a build error rather than a confusing runtime panic.

const std = @import("std");

// --- Process / scheduler ---
pub const MAX_PROCS: u32 = 32;
pub const MAX_FDS: u32 = 16;
/// Lazy-region table size per PCB. Used by stack (1) + sbrk heap (1) + ELF
/// PT_LOAD segments (~3) + mmap (1+ per call). 8 was tight once mmap was
/// added — bumped to 16 so a few back-to-back mmaps don't immediately
/// exhaust the table on a freshly-loaded process.
pub const MAX_LAZY_REGIONS: u8 = 16;

/// Per-process kernel stack body size. Plus KSTACK_GUARD_SIZE below it.
pub const KSTACK_SIZE: usize = 64 * 1024; // 64 KB — std.crypto.Certificate.rsa modpow uses Modulus(4096) Fe arrays (512 B each, several live in flight) + AEAD scratch + cert chain walk; deep TLS syscalls peak well past 16 KB. 32 KB still wasn't enough — hex-dump after a second crash showed RSA modulus bytes (0xCAAF53D8...) sitting on the kstack where doSyscall's saved RIP should have been. Was 16 KB. Linux uses 16 KB but offloads crypto to worker threads with their own kstacks — a cleaner future fix.
/// Bottom 4 KB of each kernel-stack slot is unmapped so a stack overflow
/// page-faults instead of silently corrupting the next slot.
pub const KSTACK_GUARD_SIZE: usize = 4 * 1024;
pub const KSTACK_SLOT_SIZE: usize = KSTACK_SIZE + KSTACK_GUARD_SIZE;

// --- Pipes ---
pub const MAX_PIPES: u8 = 32;
pub const PIPE_BUF_SIZE: u32 = 4096;

// --- Desktop / windowing ---
pub const MAX_WINDOWS: u32 = 32;
pub const SCROLL_LINES: u32 = 200;

// --- Syscall ABI surface ---
/// Maximum fd remaps that sysExecAs accepts in one call. The shell needs 2
/// for `cmd1 | cmd2` (stdin and stdout). 8 leaves headroom for future
/// `cmd > file` style builtins without touching the syscall ABI.
pub const FD_REMAP_MAX: usize = 8;

// --- Process argv ---
/// Maximum argv slots a process exposes. argv[0] is always the program name
/// (without the `.elf` extension); argv[1..argc] are user-supplied args parsed
/// out of the exec string by splitting on spaces. 8 covers `cmd a b c d e f g`
/// which is more than the shell's MAX_LINE can usefully hold anyway.
pub const MAX_ARGS: u8 = 8;
/// Per-arg byte cap. Long enough for typical filenames and short flags
/// (e.g. "kernel32.elf" = 12 bytes), short enough that `[MAX_ARGS][MAX_ARG_LEN]`
/// in every PCB stays under 256 bytes.
pub const MAX_ARG_LEN: u8 = 32;

// --- Signals ---
/// Total signal slots. Linux's _NSIG is 64 (for rt-signals 33..63); we cap at
/// 32 because the per-PCB pending/mask are u32 bitmasks. Standard POSIX uses
/// 1..31. Bumping to 64 means widening pending/mask to u64 and the asm-side
/// signal-frame magic constant — defer until we genuinely need rt-signals.
pub const NSIG: u32 = 32;

// --- Sanity ---
comptime {
    if (MAX_PROCS < 2) @compileError("MAX_PROCS must be >= 2 (idle + at least one user process)");
    if (MAX_FDS < 3) @compileError("MAX_FDS must be >= 3 (stdin/stdout/stderr)");
    if (KSTACK_GUARD_SIZE % 4096 != 0) @compileError("KSTACK_GUARD_SIZE must be a multiple of 4096");
    if (KSTACK_SIZE % 4096 != 0) @compileError("KSTACK_SIZE must be a multiple of 4096");
    if (MAX_PIPES < 2) @compileError("MAX_PIPES must be >= 2 (at least kb_pipe + out_pipe per terminal)");
    if (PIPE_BUF_SIZE % 4096 != 0) @compileError("PIPE_BUF_SIZE must be a multiple of 4096 (page-sized backing)");
    if (FD_REMAP_MAX < 2) @compileError("FD_REMAP_MAX must be >= 2 (shell pipelines need stdin + stdout)");
    if (MAX_ARGS < 2) @compileError("MAX_ARGS must be >= 2 (program name + at least one user arg)");
    if (MAX_ARG_LEN < 16) @compileError("MAX_ARG_LEN must be >= 16 (typical filename length)");
}
