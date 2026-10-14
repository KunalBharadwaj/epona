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

**Performance note (honest):** data integrity holds under injected loss (a
multi-MB echo round-trips byte-for-byte). At 0% loss the echo sustains ~hundreds
of KB/s–MB/s; at a *pathological* 10% loss, throughput drops sharply because
recovery becomes RTO-dominated — the peer (Linux) falls back to timer-based
retransmission rather than fast-retransmitting off our duplicate ACKs when
losses are bursty. Closing that gap is what **SACK** (selective acknowledgement)
is for, and is the natural next enhancement. Set `TCPSTACK_TRACE=1` to log every
segment (seq/ack/flags/len with timestamps) for debugging these dynamics.
