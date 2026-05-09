# Kernel-aware GDB extensions for ZigOS.
#
# Sourced by gdb.sh. Defines convenience commands that understand our PCB /
# kstack / iretq frame layout. Built around plain `printf` + `x` so they work
# without DWARF (i.e. against ReleaseSafe builds). With a Debug build you also
# get full Zig source-level info on top of these.

set print pretty on
set pagination off
set confirm off

# Note: do NOT add `handle SIGINT pass nostop` here — it confuses Ctrl-C-to-pause
# against QEMU's gdb stub. Default behavior (stop on SIGINT) is what we want.

# ---------------------------------------------------------------------------
# kproclist  — print state of every PCB
# Usage: kproclist
# ---------------------------------------------------------------------------
define kproclist
  printf "=== CPU state ===\n"
  set $c = 0
  while $c < 2
    printf "cpu%d  current=", $c
    if 'cpu.smp.cpus'[$c].current_pid.some
      printf "%d", 'cpu.smp.cpus'[$c].current_pid.data
    else
      printf "null"
    end
    printf "  idle="
    if 'cpu.smp.cpus'[$c].idle_pid.some
      printf "%d", 'cpu.smp.cpus'[$c].idle_pid.data
    else
      printf "null"
    end
    printf "\n"
    set $c = $c + 1
  end
  printf "\n=== Live PCBs ===\n"
  set $i = 0
  while $i < 16
    # Compare state byte directly — 0 means .unused
    set $st_byte = *(unsigned char *)&'proc.process.procs'[$i].state
    if $st_byte != 0
      printf "PID %2d  state=", $i
      output 'proc.process.procs'[$i].state
      printf "  name=\""
      output 'proc.process.procs'[$i].name
      printf "\"  kstack_top=0x%lx  kernel_esp=0x%lx  is_idle=", \
        'proc.process.procs'[$i].kernel_stack_top, \
        'proc.process.procs'[$i].kernel_esp
      output 'proc.process.procs'[$i].is_idle
      printf "  pinned_cpu="
      output 'proc.process.procs'[$i].pinned_cpu
      printf "  tgid=%d\n", 'proc.process.procs'[$i].tgid
    end
    set $i = $i + 1
  end
end
document kproclist
List every live PCB (state != .unused) with key fields, plus per-CPU current/idle.
DWARF-based — survives PCB field reordering by Zig.
end

# ---------------------------------------------------------------------------
# kiretq <pid>  — dump the iretq frame at the top of pid's kstack
# Layout: [kernel_stack_top - 40 .. kernel_stack_top) = RIP CS RFLAGS RSP SS
# Useful when iretq is faulting and we want to see what's actually on the stack.
# ---------------------------------------------------------------------------
define kiretq
  set $pid = $arg0
  set $top = 'proc.process.procs'[$pid].kernel_stack_top
  if $top == 0
    printf "PID %d has no kernel_stack_top set\n", $pid
  else
    printf "iretq frame at top of PID %d's kstack (top=0x%lx):\n", $pid, $top
    printf "  RIP    @ 0x%lx = 0x%lx\n", $top - 40, *(unsigned long *)($top - 40)
    printf "  CS     @ 0x%lx = 0x%lx\n", $top - 32, *(unsigned long *)($top - 32)
    printf "  RFLAGS @ 0x%lx = 0x%lx\n", $top - 24, *(unsigned long *)($top - 24)
    printf "  RSP    @ 0x%lx = 0x%lx\n", $top - 16, *(unsigned long *)($top - 16)
    printf "  SS     @ 0x%lx = 0x%lx\n", $top - 8, *(unsigned long *)($top - 8)
  end
end
document kiretq
Dump the iretq frame at the top of a PCB's kernel stack.
Usage: kiretq <pid>
end

# ---------------------------------------------------------------------------
# kstack <pid> [qwords]  — hex-dump the top of pid's kstack
# Default 32 qwords (256 bytes) so you see iretq frame + 15 GPRs + a bit more.
# ---------------------------------------------------------------------------
define kstack
  set $pid = $arg0
  set $n = 32
  if $argc > 1
    set $n = $arg1
  end
  set $top = 'proc.process.procs'[$pid].kernel_stack_top
  if $top == 0
    printf "PID %d has no kernel_stack_top set\n", $pid
  else
    printf "Top %d qwords of PID %d's kstack (top=0x%lx, growing down):\n", $n, $pid, $top
    set $i = 0
    while $i < $n
      set $a = $top - 8 - $i * 8
      printf "  [top-%3d]  0x%016lx = 0x%016lx\n", $i * 8 + 8, $a, *(unsigned long *)$a
      set $i = $i + 1
    end
  end
end
document kstack
Hex-dump the top N qwords of a PCB's kernel stack (default 32).
Usage: kstack <pid> [qwords]
end

# ---------------------------------------------------------------------------
# kwatch-iretq <pid>  — set conditional hw write-watch on iretq CS slot
# Fires ONLY when CS is overwritten with a value != 0x08. Legitimate writes
# happen every timer IRQ (CPU pushes CS=0x08 in iretq frame); without the
# condition, GDB stops at every IRQ and the kernel can't make progress.
# Corruption writes 0x00 (or whatever wild value) — those trigger the stop.
# ---------------------------------------------------------------------------
define kwatch-iretq
  set $pid = $arg0
  set $pcb = &'proc.process.procs'[$pid]
  set $top = *((unsigned long *)$pcb + 2)
  if $top == 0
    printf "PID %d has no kernel_stack_top set\n", $pid
  else
    set $cs_addr = $top - 32
    watch *(unsigned long *)($cs_addr) if *(unsigned long *)($cs_addr) != 8
    printf "Conditional watchpoint set on PID %d's iretq CS slot (0x%lx). Fires only when CS != 0x08.\n", $pid, $cs_addr
  end
end
document kwatch-iretq
Set a hardware write-watch on a PCB's iretq frame CS slot. Stops gdb the moment
the slot gets clobbered, so the writer's RIP is visible in the saved regs.
Usage: kwatch-iretq <pid>
end

# ---------------------------------------------------------------------------
# kbt  — backtrace at current $rip (alias to bt for muscle memory)
# ---------------------------------------------------------------------------
define kbt
  bt
end

# ---------------------------------------------------------------------------
# kwatch-wildrip <pid>  — conditional HW watchpoint on the iretq RIP slot.
# Fires ONLY when the slot is written with a wild value (< 0x1000) — i.e.
# the corruption pattern we're hunting. Legitimate IRQ writes always store
# a valid kernel/user RIP (much larger), so they don't trigger.
# x86 has only 4 HW watchpoint slots total — use sparingly.
# ---------------------------------------------------------------------------
define kwatch-wildrip
  set $pid = $arg0
  set $top = 'proc.process.procs'[$pid].kernel_stack_top
  if $top == 0
    printf "PID %d has no kernel_stack_top set\n", $pid
  else
    set $rip_addr = $top - 40
    watch *(unsigned long *)($rip_addr) if *(unsigned long *)($rip_addr) < 0x1000
    printf "Conditional HW watch on PID %d's iretq RIP slot (0x%lx). Fires when RIP value < 0x1000.\n", $pid, $rip_addr
  end
end
document kwatch-wildrip
Set HW watchpoint on PCB's iretq RIP slot. Only fires when written with a
wild value (< 0x1000) — catches the writer of the wild-RIP bug without
halting on every legitimate IRQ.
Usage: kwatch-wildrip <pid>
end

# ---------------------------------------------------------------------------
# Help footer
# ---------------------------------------------------------------------------
printf "ZigOS kernel.gdbinit loaded. Custom commands:\n"
printf "  kproclist                — list live PCBs\n"
printf "  kiretq <pid>             — dump iretq frame at kstack top\n"
printf "  kstack <pid> [qwords]    — hex dump kstack top\n"
printf "  kwatch-iretq <pid>       — watchpoint on CS slot\n"
printf "  kwatch-wildrip <pid>     — watchpoint on RIP slot, fires on wild values\n"
printf "  kbt                      — backtrace\n"
printf "Type 'help <cmd>' for details. Type 'continue' to resume.\n"
