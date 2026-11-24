; AP startup trampoline: INIT-SIPI-SIPI starts an application processor here.
; smp.zig copies, arms and sends it; the climb itself is trampoline.inc.

%define TRAMPOLINE       ap_trampoline   ; ap_trampoline_{start,params,end}
%define TRAMPOLINE_BASE  0x8000          ; SIPI vector 0x08

%include "trampoline.inc"
