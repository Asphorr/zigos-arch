# TCP/IP stack native test harness

Drives [`src/net/net.zig`](../../src/net/net.zig)'s TCP state machine under
`zig test`, off-target, in sub-seconds — no QEMU boot, no NIC, no nested-virt.

## Why this exists

`net.zig` is a real hand-rolled stack (Ethernet → ARP → IPv4 → ICMP/UDP/TCP)
that works on QEMU user-net — but the **sender** is fire-and-forget: it keeps
only the single most-recent segment for retransmission and has no RTT estimation
or congestion control, so one lost segment mid-stream kills the connection. That
failure is invisible on a lossless link. This harness makes it **visible and
deterministic** so the reliability rework can be proven, the way QEMU never
could.

The model: `net.zig` is the system-under-test (one TCP endpoint); this harness
plays the remote peer + the wire + the clock.

| piece | how |
|-------|-----|
| outbound frames | captured by the `nic` stub (`txPop`/`txCount`) — the harness sees every segment the stack emits |
| inbound frames  | hand-built and injected via `net.handleRxFrame` — the harness scripts the peer |
| the clock       | `process.tick_count` is advanced by hand to fire retransmit timers on demand |

Connections are brought up via the **passive path** (`tcpListen` → SYN →
SYN-ACK → ACK → `tcpAccept`), which is fully test-driven; `tcpConnect` blocks on
a poll deadline and isn't used here. Inbound frames aren't checksum-validated by
`net.zig` (`handleIPv4Packet` checks only version + length), so the scripted peer
leaves checksums zero.

## Run it

```sh
tools/net-test/run.sh                                          # `zig` from PATH
ZIG=~/Загрузки/zig-x86_64-linux-0.15.2/zig tools/net-test/run.sh
```

`run.sh` copies the live `net.zig` in on each run (the copy at
`src/net/net.zig` here is gitignored), so it always tests current source. Expect:

```
All N tests passed.
EXIT=0
```

## The scenarios (`test.zig`)

| test | proves / pins |
|------|---------------|
| passive open | SYN → SYN-ACK → ACK → ESTABLISHED, `accept()` hands the slot out |
| inbound data | payload reaches `tcpRecv`, an ACK covering it is emitted |
| out-of-order | OOO data is **buffered and reassembled** when the gap fills; the gap yields duplicate ACKs — proves task #1001 |
| send segmentation | `tcpSend` splits at `peer_mss` with contiguous seqs |
| loss recovery | on loss the RTO resends the **first unacked** segment from the send ring (the right bytes), and the ring drains on full ACK — proves task #999 |
| flow control | a small advertised window throttles in-flight bytes; a window-update ACK flushes the buffered remainder — proves task #999 |
| RTO adapts | a measured round trip sets the retransmit timeout (≈3×RTT), not a fixed 300 ticks — proves task #1000 (Jacobson/Karn) |
| slow start | the opening burst is bounded by cwnd, then grows on ACKs until the whole payload is out — proves task #1002 |
| fast retransmit | three duplicate ACKs resend the missing segment immediately, before any RTO — proves task #1002 |

Every test **proves a fix** — the full TCP reliability + congestion rework is in:
correct retransmission and flow control (#999), an RTT-estimated RTO (#1000),
out-of-order reassembly with duplicate ACKs (#1001), and Reno congestion control —
slow start and fast retransmit (#1002).

## The stubs

| stub | fakes |
|------|-------|
| `src/driver/nic.zig`    | captures TX frames into a FIFO; `recv()` returns null (RX is injected) |
| `src/proc/process.zig`  | `tick_count` virtual clock + `kernelSleepMs` that advances it |
| `src/debug/debug.zig`   | `klog` → silenced (`VERBOSE=true` to trace) |
| `src/ui/vga.zig`        | `print` + `fg` color enum (only the CLI helpers touch these) |
| `src/cpu/ipc/fdpoll.zig`| `wakePollers` no-op (no tasks to wake in the harness) |
