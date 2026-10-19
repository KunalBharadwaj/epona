# User-Space TCP/IP Stack (C++20)

A TCP/IP stack that runs entirely in user space. The C++20 code in this repo
handles Ethernet framing, ARP, IPv4, ICMP, UDP and TCP over a TAP device, with
an HTTP/1.1 server on top. The Linux kernel does no TCP/IP here; it only moves
raw Ethernet frames between a file descriptor and the wire. The point of the
project was to implement what sits underneath `socket()` rather than call it.

## Architecture

A layered pipeline driven by a single-threaded epoll event loop. Two services
cut across the layers: a timer wheel (retransmit, TIME-WAIT, persist) and the
packet buffers. The frame path does no heap allocation (outbound buffers are
stack-local, inbound frames reuse one long-lived buffer).

```
app/   udp_echo, tcp_echo, http_server (HTTP/1.1 + keep-alive)
tcp/   TCB, RFC 793 state machine, 4-tuple table, send/recv API,
       RTO retransmit, Reno congestion control, flow control, reassembly, SACK
udp/   UDP + port demux (shared transport checksum)
ip/    IPv4 + ICMP + pseudo-header checksum
eth/   Ethernet framing + ARP
net/   TAP device, event loop (epoll + timers), packet buffers
```

Each layer talks to the one below through a narrow sink interface
(`EthSender`, `Ipv4Sender`), so every layer can be unit-tested against a
capturing fake with no real sockets involved.

## Build

Requires a C++20 compiler (g++ 11+ or clang 14+), CMake 3.20+, and network
access on the first configure to fetch GoogleTest. AddressSanitizer and UBSan
are on by default.

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

There are 65 unit tests covering byte order, checksums, each header
parser/builder, the TCP state machine, congestion control, reassembly, SACK,
and the send ring.

## Run

Creating the TAP device needs `CAP_NET_ADMIN`. Set it up once as a persistent
device owned by your user, so the stack itself then runs unprivileged:

```bash
sudo ip tuntap add dev tap0 mode tap user "$USER"
sudo ip addr add 10.0.0.1/24 dev tap0   # host side; the stack owns 10.0.0.2
sudo ip link set tap0 up
```

Run the stack (no root needed):

```bash
./build/tcpstack tap0
```

From another terminal:

```bash
ping 10.0.0.2                                # ARP + ICMP
printf 'hello\n' | nc -u -w1 10.0.0.2 7777   # UDP echo
printf 'hello\n' | nc -q1 10.0.0.2 7777      # TCP echo
curl http://10.0.0.2:8080/                   # HTTP/1.1 server (also works in a browser)
```

The HTTP server speaks HTTP/1.1 with keep-alive: `GET /` serves an HTML page,
`GET /hello` plain text, unknown paths return 404, non-GET/HEAD return 405, and
every response carries a correct `Content-Length`. A browser pointed at
`http://10.0.0.2:8080/` renders the page, served from the Ethernet frame up by
code in this repo.

On Ctrl-C the stack prints counters (ARP cache size, ICMP replies, checksum
errors, TCP connection and retransmit totals). Tear down the device when done:

```bash
sudo ip link del tap0
```

## TCP reliability and congestion control

The TCP code implements the parts that make it behave under loss and changing
link conditions:

- A send buffer of unacknowledged bytes, so segments can be retransmitted.
- A retransmission timer with an RTO from the Jacobson/Karels estimator
  (smoothed RTT plus variance), exponential backoff, and Karn's algorithm (no
  RTT sample taken from a retransmitted segment).
- Fast retransmit and fast recovery on three duplicate ACKs.
- Flow control that never sends past the peer's advertised window, with a
  zero-window persist probe so a closed window cannot deadlock.
- TCP Reno congestion control: slow start, AIMD congestion avoidance, and
  window inflation/deflation during fast recovery. Sends are limited to the
  minimum of the flow-control and congestion windows.
- Receive reassembly: out-of-order segments are buffered and delivered in order
  once the gap is filled. The reassembly buffer has headroom past the advertised
  window, and the advertised window stays constant so duplicate ACKs are not
  mistaken for window updates.

Set `TCPSTACK_TRACE=1` to log every segment (seq/ack/flags/len with timestamps),
which is how most of the loss-recovery behavior above was debugged.

## Selective acknowledgement (RFC 2018)

A cumulative ACK tells a sender only how far the contiguous stream has arrived,
not which later segments crossed a gap. Under loss that forces one-loss-per-RTT
recovery and makes the peer retransmit data already received. SACK addresses
both:

- Negotiation: the stack advertises `SACK-permitted` on its SYN/SYN-ACK and
  enables SACK only if the peer did too. `TCPSTACK_NOSACK=1` turns it off, which
  is used for the before/after measurement below.
- Receiver: out-of-order runs are reported as up to three SACK blocks
  (most-recent first) on each duplicate ACK, so the peer resends only the holes.
- Sender: incoming SACK blocks are merged and clamped to `(snd_una, snd_nxt)`,
  and fast retransmit resends the first un-SACKed hole rather than the whole
  window.

## Performance and benchmarking

The numbers below come from the non-sanitized Release build (`build-rel/`)
driven by `bench/bench.cpp`, measured against a kernel-TCP loopback echo server
as a reference floor:

```bash
cmake -S . -B build-rel -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DTCPSTACK_SANITIZE=OFF -DBUILD_TESTING=OFF && cmake --build build-rel
./build-rel/tcpstack tap0 &                 # the stack: 10.0.0.2
./build-rel/bench server 9999 &             # kernel loopback baseline
./build-rel/bench 10.0.0.2 7777 latency 3000 64
./build-rel/bench 10.0.0.2 7777 throughput 100000000
./build-rel/bench 10.0.0.2 7777 connrate 2000
```

With no loss, 64-byte request/response latency over 3000 round-trips:

| percentile | this stack (via TAP) | kernel loopback |
|-----------:|---------------------:|----------------:|
| p50        | 77 µs                | 14 µs           |
| p90        | 119 µs               | 15 µs           |
| p99        | 139 µs               | 19 µs           |
| p99.9      | 273 µs               | 77 µs           |

The latency floor is about 5x loopback, which is the cost of crossing the
user/kernel boundary twice per packet (a read and a write on the TAP fd) on top
of the stack's own processing; loopback stays inside the kernel.

| metric                    | this stack     | kernel loopback |
|---------------------------|----------------|-----------------|
| bulk throughput (one-way) | ~200-320 MB/s  | ~1.2-2.6 GB/s   |
| connection setup rate     | ~60,000 conn/s | ~37,000 conn/s  |

The connection-rate baseline is a single-threaded `accept()` loop, so it is a
floor rather than a tuned server; the comparison only shows the setup path is
not a bottleneck. Absolute throughput and latency move around with CPU frequency
and machine load (loopback itself ranged 1.2-2.6 GB/s across runs), so the
comparisons here are same-session ratios rather than fixed headline figures. The
stack lands roughly 5-8x below kernel loopback.

### What SACK buys under loss

On a link shaped with `tc qdisc add dev tap0 root netem delay 20ms loss 5%`, a
256 KB echo (median of 5 runs):

| mode                        | throughput (one-way) | peer retransmits / transfer |
|-----------------------------|----------------------|-----------------------------|
| SACK off (`TCPSTACK_NOSACK`) | ~0.3 MB/s           | ~68                         |
| SACK on                     | ~1.4 MB/s            | ~0.4                        |

A 256 KB stream is about 180 segments with roughly 9 losses to recover. Without
SACK the Linux peer retransmitted around 68 segments per transfer, resending
whole windows of data already delivered, and spent most of the time in
cumulative-ACK recovery. With SACK it resends essentially only the lost
segments, for 4-5x the throughput.

One caveat worth recording: at a harsher `loss 10%` with no added delay,
completion time is dominated by the RTO floor, not by SACK. On a
sub-millisecond-RTT link, any segment that is dropped and whose retransmit is
also dropped costs a 200 ms-plus timeout that dwarfs the transfer, and a
tail-loss cannot be fast-retransmitted at all. Both modes then stall for seconds
with high variance. Adding a realistic 20 ms RTT is what lets SACK's one-RTT
hole filling show up as a repeatable win instead of being buried under RTO
noise.

### Profiling the send path

The send buffer started as a `std::deque<std::byte>`. A `perf` recording of a
bulk echo showed `TcpConnection::try_send()` at about 20% of CPU self-time,
almost all of it a per-byte copy out of that deque. `std::deque::operator[]`
recomputes a block index and follows the deque's block-map pointer on every
access, so building each outbound segment walked non-contiguous storage one byte
at a time.

Replacing it with a contiguous ring buffer (`src/tcp/send_ring.hpp`, unit-tested
for wrap-around and growth) makes segment extraction one or two `memcpy`s, and
the ring only grows when the outstanding window does, so the steady-state path
allocates nothing.

| send buffer     | `try_send` self-time | one-way throughput (same machine, median of 5) |
|-----------------|----------------------|------------------------------------------------|
| `std::deque`    | ~19.6%               | ~136 MB/s                                      |
| contiguous ring | ~1.8%                | ~189 MB/s (+39%)                               |

After the change the top self-time costs are building segment headers and the
one's-complement transport checksum over the payload, which is the work that
should dominate.

## Known limitations

These are scope cuts rather than oversights; each is a reasonable next step.

- No window scaling, timestamps, or PAWS. The advertised window is a constant
  65,535 (kept constant so duplicate ACKs are not read as window updates), which
  caps throughput on high bandwidth-delay links and means the window does not
  reflect real buffer occupancy.
- Out-of-order reassembly is keyed by raw sequence number in a
  `std::map<uint32_t, ...>`, so a connection that wraps the 32-bit sequence
  space while holding out-of-order segments across the wrap would mis-order
  them. Correct for any transfer under 4 GiB without a wrap. The fix is to order
  in sequence space, as `seq.hpp` already does for comparisons.
- Congestion control is simplified Reno: slow start, AIMD, and fast
  retransmit/recovery are present, but not NewReno's partial-ACK retransmission;
  recovery leans on the SACK path.
- SACK recovery is complete on the receiver side but partial on the sender side:
  it resends the first un-SACKed hole rather than implementing full RFC 6675
  pipe/rescue.
- Initial sequence numbers come from the clock, not the keyed hash in RFC 6528.
  Fine for a trusted TAP link, not for a hostile network.
- No SYN-flood defense: every inbound SYN allocates a TCB immediately, with no
  SYN cookies and no cap on half-open connections.
- ARP has no pending-packet queue (the first datagram to an unresolved next hop
  is dropped and recovered by a TCP retransmit) and expired cache entries are
  not swept.
- Single-threaded with one connection table; no sharding for multi-core scaling.
