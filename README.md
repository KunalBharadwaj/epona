# User-Space TCP/IP Stack (C++20)

A TCP/IP network stack that runs entirely in user space. Our own C++20 code
handles Ethernet framing, ARP, IPv4, ICMP, UDP and TCP over a **TAP** device,
with an HTTP/1.1 server on top. The Linux kernel does no TCP/IP — it only moves
raw Ethernet frames between our file descriptor and the wire.

> One-line pitch: *I implemented TCP/IP from the wire up — I didn't just call
> `socket()`, I built what sits underneath it.*

## Architecture

A layered pipeline driven by a single-threaded **epoll** event loop, with two
shared services cutting across layers: **timers** (retransmit, TIME-WAIT) and a
recycled **buffer pool** (keeps the hot path allocation-free).

```
app/       udp_echo, tcp_echo, http_server (HTTP/1.1 + keep-alive)   <-- built
tcp/       TCB, RFC 793 state machine, 4-tuple table, sockets-like API, <-- built
           RTO retransmit, Reno congestion control, flow control, reassembly
udp/       UDP + port demux (shared transport checksum)          <-- built
ip/        IPv4 + ICMP + pseudo-header checksum                  <-- built
eth/       Ethernet framing + ARP                                <-- built
net/       TAP device, event loop (epoll + timers), packet buffers  <-- built
```

## Milestones

| #  | Goal                                             | Status      |
|----|--------------------------------------------------|-------------|
| 0  | TAP device + packet plumbing + event loop        | ✅ done     |
| 1  | Ethernet + ARP + IPv4 + ICMP (`ping` replies)    | ✅ done     |
| 2  | UDP (pseudo-header checksum) + echo app           | ✅ done     |
| 3  | TCP connection lifecycle (state machine)         | ✅ done     |
| 4  | Reliability & performance (RTO, windows, Reno)   | ✅ done     |
| 5  | HTTP/1.1 server on top (curl + browser)          | ✅ done     |

## Build

Requires: a C++20 compiler (g++ 11+ / clang 14+), CMake 3.20+, and network
access on first configure (to fetch GoogleTest). AddressSanitizer + UBSan are
on by default.

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure   # run unit tests
```

## Run

The TAP device needs `CAP_NET_ADMIN` to create. Set it up once (as a persistent
device owned by you, so the stack itself then runs **unprivileged**):

```bash
# Create a persistent TAP device owned by your user
sudo ip tuntap add dev tap0 mode tap user "$USER"

# Give it an address on 10.0.0.0/24 (the host side); the stack owns 10.0.0.2
sudo ip addr add 10.0.0.1/24 dev tap0
sudo ip link set tap0 up
```

Run the stack (no root needed):

```bash
./build/tcpstack tap0
```

From another terminal:

```bash
ping 10.0.0.2                        # steady replies — ARP + ICMP
printf 'hello\n' | nc -u -w1 10.0.0.2 7777   # UDP echo
printf 'hello\n' | nc -q1 10.0.0.2 7777      # TCP echo (clean handshake + teardown)
curl http://10.0.0.2:8080/           # HTTP/1.1 server — or open it in a browser
tcpdump -i tap0 -n                   # or: sudo tshark -i tap0 -n
```

The HTTP server speaks HTTP/1.1 with keep-alive: `GET /` serves an HTML page,
`GET /hello` plain text, unknown paths 404, non-GET/HEAD 405, all with correct
`Content-Length`. A real browser pointed at `http://10.0.0.2:8080/` renders the
page — served from the Ethernet frame up by code in this repo.

On Ctrl-C the stack prints counters (ARP cache size, ICMP replies, checksum
errors, TCP connections, retransmits). Teardown when done:

```bash
sudo ip link del tap0
```

## TCP reliability & congestion control (Milestone 4)

The TCP implementation behaves like real TCP under loss and varying speed:

- **Send buffer** holding unacknowledged bytes, so segments can be retransmitted.
- **Retransmission timer** with an RTO from the **Jacobson/Karels** estimator
  (smoothed RTT + variance), **exponential backoff**, and **Karn's algorithm**
  (no RTT sample from a retransmitted segment).
- **Fast retransmit / fast recovery** on three duplicate ACKs.
- **Flow control**: never send past the peer's advertised receive window, with
  a zero-window **persist** probe so a closed window can't deadlock.
- **Congestion control (TCP Reno)**: slow start, AIMD congestion avoidance,
  and window inflation/deflation during fast recovery. We always send the
  minimum of the flow-control and congestion windows.
- **Receive reassembly**: out-of-order segments are buffered and delivered in
  order once the gap is filled (the OOO buffer has headroom beyond the
  advertised window, which stays stable so our duplicate ACKs trigger the
  peer's fast retransmit).

Testing under loss (`tc qdisc add dev tap0 root netem loss 10%`):

```bash
head -c 1000000 /dev/urandom > /tmp/send.dat
nc -q2 10.0.0.2 7777 < /tmp/send.dat > /tmp/recv.dat
cmp /tmp/send.dat /tmp/recv.dat && echo "identical despite loss"
```

Data integrity holds under injected loss: a multi-MB echo round-trips
byte-for-byte. Set `TCPSTACK_TRACE=1` to log every segment
(seq/ack/flags/len with timestamps) for debugging these dynamics.

## Selective acknowledgement (SACK, RFC 2018)

Cumulative ACKs tell a sender only *how far* the contiguous stream has arrived,
not *which* later segments made it across a gap. Under loss that forces
one-loss-per-round-trip recovery and, for the peer (Linux), spurious
retransmission of data we already hold. SACK fixes both:

- **Negotiation** — we advertise `SACK-permitted` on our SYN/SYN-ACK and only
  enable SACK if the peer did too (`TCPSTACK_NOSACK=1` turns it off, used for
  the before/after below).
- **Receiver** — out-of-order runs are reported as up to three SACK blocks
  (most-recent first) on every duplicate ACK, so the peer retransmits only the
  holes.
- **Sender** — peer SACK blocks are merged and clamped to `(snd_una, snd_nxt)`;
  fast retransmit then resends only the first un-SACKed hole instead of the
  whole window.

## Performance & benchmarking

Numbers below are from the non-sanitized Release build (`build-rel/`) driven by
`bench/bench.cpp`, measured against a kernel-TCP loopback echo server as a
reference floor. Reproduce with:

```bash
cmake -S . -B build-rel -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DTCPSTACK_SANITIZE=OFF -DBUILD_TESTING=OFF && cmake --build build-rel
sudo ip tuntap add dev tap0 mode tap user $USER
sudo ip addr add 10.0.0.1/24 dev tap0 && sudo ip link set tap0 up
./build-rel/tcpstack tap0 &                 # our stack: 10.0.0.2
./build-rel/bench server 9999 &             # kernel loopback baseline
./build-rel/bench 10.0.0.2 7777 latency 3000 64
./build-rel/bench 10.0.0.2 7777 throughput 100000000
./build-rel/bench 10.0.0.2 7777 connrate 2000
```

**No loss.** 64-byte request/response latency (3000 round-trips):

| percentile | our stack (via TAP) | kernel loopback |
|-----------:|--------------------:|----------------:|
| p50        | 77 µs               | 14 µs           |
| p90        | 119 µs              | 15 µs           |
| p99        | 139 µs              | 19 µs           |
| p99.9      | 273 µs              | 77 µs           |

Our latency floor is ~5× loopback: every packet crosses the user/kernel
boundary twice (write/read on the TAP fd) on top of our own processing, where
loopback stays inside the kernel.

| metric                        | our stack        | kernel loopback  |
|-------------------------------|------------------|------------------|
| bulk throughput (one-way)     | ~200–320 MB/s    | ~1.2–2.6 GB/s    |
| connection setup rate         | ~60 000 conn/s   | ~37 000 conn/s¹  |

¹ The loopback baseline is a single-threaded `accept()` loop, so it is a floor,
not a tuned server; the comparison just shows our setup path is not a
bottleneck.

Absolute throughput and latency swing with machine state (CPU frequency, load):
across sessions, kernel loopback itself ranged ~1.2–2.6 GB/s. What stays stable
is the *same-run ratio* — our stack lands roughly 5–8× below kernel loopback —
so the trustworthy performance claims below are same-session comparisons, not
absolute headline figures.

**Under loss — what SACK buys.** On a link shaped with
`tc qdisc add dev tap0 root netem delay 20ms loss 5%`, a 256 KB echo (median of
5 runs):

| mode                       | throughput (one-way) | peer retransmits / transfer |
|----------------------------|---------------------:|----------------------------:|
| SACK off (`TCPSTACK_NOSACK`)| ~0.3 MB/s           | ~68                         |
| SACK on                    | ~1.4 MB/s            | ~0.4                        |

A ~256 KB stream is ~180 segments with ~9 losses to recover. Without SACK the
Linux peer retransmitted **~68 segments per transfer** — re-sending whole
windows of data we already had — and spent most of its time in cumulative-ACK
recovery. With SACK it retransmits essentially only the lost segments, for
~4–5× the throughput.

**A measurement caveat (kept honest):** at a harsher `loss 10%` with *no* added
delay, completion time is dominated not by SACK but by the **RTO floor**. On a
sub-millisecond-RTT link any segment that is dropped *and* whose retransmit is
also dropped costs a ≥200 ms timeout that dwarfs the whole transfer — a
tail-loss event SACK cannot help (the last segment has no later ACKs to select
it). Both modes then show multi-second, high-variance stalls. Adding a
realistic 20 ms RTT (above) is what lets SACK's one-RTT hole-filling show up as
a clean, repeatable win instead of being buried under RTO noise.

**Profile-driven optimization — the send buffer.** Rather than optimize on a
hunch, I recorded the stack under a bulk echo with `perf`. The frame path was
already allocation-free (packet buffers are stack arrays, the RX buffer is
reused), so the interesting result was a function, not a malloc:
`TcpConnection::try_send()` was **~20% of CPU self-time**, almost all of it a
per-byte copy out of the send buffer — which was a `std::deque<std::byte>`.
`std::deque::operator[]` is not free: each access recomputes a block index and
chases the deque's block-map pointer across non-contiguous storage, so building
every outbound segment walked the structure byte by byte.

Replacing it with a contiguous ring buffer ([`send_ring.hpp`](src/tcp/send_ring.hpp),
unit-tested for wrap-around and growth) makes segment extraction one or two
`memcpy`s, and the ring only grows (doubling) when the outstanding window does —
so the steady-state hot path allocates nothing. Re-profiling confirmed the fix:

| | `try_send` self-time | one-way throughput (same machine, median of 5) |
|-----------------|---------------------:|-----------------------------------------------:|
| `std::deque`    | ~19.6%               | ~136 MB/s                                      |
| contiguous ring | ~1.8%                | ~189 MB/s (**+39%**)                           |

After the change the remaining user-space hot spots are the work that *should*
dominate — building segment headers and the one's-complement transport checksum
over the payload — not a data-structure accident.

## Known limitations

These are deliberate scope cuts, not accidents — naming them is part of knowing
where the edges are. Each is a reasonable next piece of work.

- **No window scaling / timestamps / PAWS.** The advertised receive window is a
  constant 65535 (a deliberate trick so our duplicate ACKs aren't mistaken for
  window updates), which caps throughput on high bandwidth-delay-product links
  and means the window doesn't reflect real buffer occupancy.
- **Out-of-order reassembly is keyed by raw sequence number.** The OOO buffer is
  a `std::map<uint32_t, …>` ordered numerically, so a connection that wraps the
  32-bit sequence space *while* holding out-of-order segments across the wrap
  would mis-order them. Correct for any transfer under 4 GiB without a wrap;
  the proper fix is to order in sequence space (as `seq.hpp` already does for
  comparisons).
- **Congestion control is simplified Reno.** Slow start, AIMD, and fast
  retransmit/recovery are implemented, but not NewReno's partial-ACK
  retransmission; recovery leans on the SACK path instead.
- **SACK recovery is receiver-complete, sender-partial.** We emit correct SACK
  blocks and the peer benefits fully; our own retransmit resends the first
  un-SACKed hole rather than implementing full RFC 6675 pipe/rescue.
- **Predictable initial sequence numbers.** The ISS is derived from the clock,
  not RFC 6528's keyed hash — fine for a trusted TAP link, not for a hostile
  network.
- **No SYN-flood defense.** Every inbound SYN allocates a TCB immediately; there
  are no SYN cookies and no cap on concurrent half-open connections.
- **ARP has no pending-packet queue and no cache eviction.** The first datagram
  to an unresolved next hop is dropped (TCP's retransmit covers it, at the cost
  of one RTO), and expired cache entries linger until overwritten rather than
  being swept.
- **Single-threaded, single connection-table.** One epoll thread drives
  everything; there is no sharding or lock-free hand-off for multi-core scaling.
