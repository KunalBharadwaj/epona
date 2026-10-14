# User-Space TCP/IP Stack (C++20)

A TCP/IP network stack built from scratch in C++20, running entirely in user
space over a **TAP** device. The Linux kernel only moves raw Ethernet frames;
every protocol above that — Ethernet, ARP, IPv4, ICMP, UDP, TCP — is our code.

Each layer is a small module behind a narrow interface, driven by a single
epoll event loop, and unit-tested in isolation.

## Milestones

| #  | Goal                                             | Status  |
|----|--------------------------------------------------|---------|
| 0  | TAP device + packet plumbing + event loop        | ✅ done |
| 1  | Ethernet + ARP + IPv4 + ICMP (`ping` replies)    | ✅ done |
| 2  | UDP (pseudo-header checksum) + echo app           | ✅ done |
| 3  | TCP connection lifecycle (RFC 793 state machine) | planned |
| 4  | Reliability & performance (RTO, windows, Reno)   | planned |
| 5  | HTTP/1.1 server                                  | planned |

## Build

Requires a C++20 compiler (g++ 11+ / clang 14+), CMake 3.20+, and network access
on first configure (to fetch GoogleTest). AddressSanitizer + UBSan are on by
default.

```bash
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

## Run

The TAP device needs `CAP_NET_ADMIN` to create. Set it up once as a persistent
device owned by you, so the stack itself runs unprivileged:

```bash
sudo ip tuntap add dev tap0 mode tap user "$USER"
sudo ip addr add 10.0.0.1/24 dev tap0
sudo ip link set tap0 up

./build/tcpstack tap0
```

From another terminal:

```bash
ping 10.0.0.2                         # ARP + ICMP
printf 'hi\n' | nc -u -w1 10.0.0.2 7777   # UDP echo
tcpdump -i tap0 -n                    # or: sudo tshark -i tap0 -n
```
