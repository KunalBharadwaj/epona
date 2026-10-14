# User-Space TCP/IP Stack (C++20)

A TCP/IP network stack built from scratch in C++20, running entirely in user
space over a **TAP** device. The Linux kernel only moves raw Ethernet frames;
every protocol above that — Ethernet, ARP, IPv4, ICMP, UDP, TCP — is our code.

Built in milestones; this is **Milestone 0: the TUN/TAP device and packet
plumbing**. It opens a TAP device, reads raw frames under a single epoll event
loop, and hexdumps them — proving the pipe works before any protocol lands.

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

./build/tcpstack tap0        # then `ping 10.0.0.2` and watch the hexdump
```
