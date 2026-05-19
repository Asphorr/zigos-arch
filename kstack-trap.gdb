## kstack-trap.gdb — dynamic kesp+48 watchpoint for pid 2 + pid 3.
##
## Strategy:
##   1. Software bp on `movq %rsp, (%rdi)` in switchTo (the save insn).
##   2. On hit, $rdi = &PCB[N].kernel_esp, $rsp = the value about to be saved.
##      Decode N from ($rdi - procs - 8) / sizeof(PCB).
##   3. If N in {2, 3}, delete prior hw-watch for that pid, arm a new
##      `awatch *(uint64_t*)($rsp+48)` with `if value==0` filter (the
##      bug signature is "saved RIP slot becomes 0").
##   4. Continue. When the watch fires, GDB stops — inspect $rip + bt.
##
## Symbols (verify with `nm zig-out/bin/kernel.elf`):
##   procs:    0xffffffff80404450  (proc.process.procs)
##   PCB_SIZE: 0xBC0               (= 3008, derived from span/MAX_PROCS=32)
##   KESP_OFF: 8                   (state:u8 → 7B pad → kernel_esp:usize)
##   SAVE_INSN: 0xffffffff80194aff (movq %rsp, (%rdi))
##
## Usage:
##   # Terminal 1: launch QEMU with gdbstub
##   ./run-uefi-ext2-iommu.sh -s
##   # Terminal 2:
##   gdb zig-out/bin/kernel.elf
##   (gdb) source kstack-trap.gdb
##   # Then in the VM: trigger netstat. When watch fires, gdb stops.

set pagination off
set confirm off
set print pretty on

set $PROCS_BASE = 0xffffffff80404450
set $PCB_SIZE   = 0xBC0
set $KESP_OFF   = 8
set $SAVE_INSN  = 0xffffffff80194aff

# Per-pid current hw-watch breakpoint numbers (0 = none armed).
set $watch_pid2 = 0
set $watch_pid3 = 0

# Set to 1 to log every save for pid 2/3 — noisy but useful for first run.
set $log_saves = 0

target remote :1234

# --------- save-instruction hook ---------
break *$SAVE_INSN
commands
  silent
  set $kesp_ptr = (unsigned long)$rdi
  set $kesp_new = (unsigned long)$rsp
  set $delta = $kesp_ptr - ($PROCS_BASE + $KESP_OFF)
  set $pid = (int)($delta / $PCB_SIZE)
  set $rem = $delta - (unsigned long)$pid * $PCB_SIZE
  if $rem == 0
    if $pid == 2
      if $watch_pid2 != 0
        delete $watch_pid2
        set $watch_pid2 = 0
      end
      set $wva2 = $kesp_new + 48
      awatch *(unsigned long *)$wva2 if *(unsigned long *)$wva2 == 0
      set $watch_pid2 = $bpnum
      if $log_saves
        printf "[save pid2] kesp=0x%lx watch=*0x%lx bp#%d\n", $kesp_new, $wva2, $watch_pid2
      end
    end
    if $pid == 3
      if $watch_pid3 != 0
        delete $watch_pid3
        set $watch_pid3 = 0
      end
      set $wva3 = $kesp_new + 48
      awatch *(unsigned long *)$wva3 if *(unsigned long *)$wva3 == 0
      set $watch_pid3 = $bpnum
      if $log_saves
        printf "[save pid3] kesp=0x%lx watch=*0x%lx bp#%d\n", $kesp_new, $wva3, $watch_pid3
      end
    end
  end
  cont
end

printf "kesp+48 trap armed for pid 2 + pid 3 (zero-write filter).\n"
printf "Trigger netstat to repro. On hit: bt; info reg rip rsp; x/16gx $rsp\n"
cont
