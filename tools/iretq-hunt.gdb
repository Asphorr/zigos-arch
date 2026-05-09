# Auto-script for the iretq frame corruption bug.
# Sourced by debug-iretq.sh.
#
# Strategy: instead of a hardware watchpoint (which conflicts with KVM
# gdbstub), break on the kernel's panic() function. iretqValidate calls
# @panic when it detects iretq frame corruption — GDB stops there with
# full kernel state preserved (registers, kstack, page tables intact).
#
# We don't catch the writer at the moment of write, but we get vastly
# more diagnostic context than the kdbg autopsy printout: interactive
# memory inspection, manual stack walk, full register state, the ability
# to peek at any address.
#
# Workflow once GDB stops:
#   (gdb) bt              — full backtrace, see who called panic
#   (gdb) frame 4         — jump to handleIRQ0's frame (adjust number)
#   (gdb) info args       — see what handleIRQ0 was passed
#   (gdb) info locals     — see local variables
#   (gdb) x/16gx $rsp     — examine kstack contents
#   (gdb) x/40i $pc-80    — disasm around current point
#
# All steps are automated up to "GDB stops"; user inspects interactively.

set pagination off
set confirm off

# Step 1: Break on the kernel's panic function. The symbol Zig generates is
# `builtin.panic__struct_NNN.panic` — we use a wildcard since the struct ID
# changes between builds. main.zig:240 is the source location.
#
# This breakpoint also catches OTHER panics (heap canary trips, asserts, etc.)
# but those are also useful — and post-mortem we can see msg to know which.
rbreak ^builtin\.panic__struct_.*\.panic$

# Step 2: When ANY panic fires, automatically dump the most useful state.
# hook-stop runs after every gdb stop (breakpoint, watch, signal, ctrl-C).
define hook-stop
  printf "\n========== KERNEL STOPPED ==========\n"
  printf "--- panic msg (rdi=ptr, rsi=len) ---\n"
  if $rsi > 0 && $rsi < 256
    x/s $rdi
  end
  printf "\n--- registers ---\n"
  info reg rip rsp rbp rax rbx rcx rdx rsi rdi r8 r9 r10 r11
  printf "\n--- backtrace ---\n"
  bt 20
  printf "\n--- top of kstack (32 qwords from RSP) ---\n"
  x/32gx $rsp
  printf "\n--- code at RIP ---\n"
  x/8i $rip
  printf "\n=====================================\n"
  printf "(gdb) prompt is yours — try: frame N, x/40gx <addr>, etc.\n"
end

printf "[hunt] Breakpoint set on kernel panic. Boot proceeds normally.\n"
printf "[hunt] Click paint icon, then click in window 5+ times until panic.\n"
printf "[hunt] When GDB stops, full state will dump automatically.\n"
continue
