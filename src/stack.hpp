#pragma once
//
// The Stack ties every layer together and connects them to the device and the
// event loop. It owns the per-layer objects and wires the inbound dispatch
// chain:  device -> Ethernet -> {ARP | IPv4 -> ICMP}.
//
#include "eth/arp.hpp"
#include "eth/ethernet.hpp"
#include "ip/icmp.hpp"
#include "ip/ipv4.hpp"
#include "net/buffer.hpp"
#include "net/event_loop.hpp"
#include "net/tap_device.hpp"

namespace stack {

class Stack {
public:
    Stack(net::TapDevice& device, net::EventLoop& loop,
          eth::MacAddr local_mac, ip::Ipv4Addr local_ip);

    // Register the device fd with the event loop so frames start flowing.
    void start();

    // Accessors (stats, tests, and later milestones wiring UDP/TCP).
    eth::EthernetLayer& ethernet() noexcept { return eth_; }
    eth::Arp&           arp()      noexcept { return arp_; }
    ip::Ipv4Layer&      ipv4()     noexcept { return ipv4_; }
    ip::Icmp&           icmp()     noexcept { return icmp_; }

private:
    void on_readable();

    net::TapDevice& device_;
    net::EventLoop& loop_;

    eth::EthernetLayer eth_;
    eth::Arp           arp_;
    ip::Ipv4Layer      ipv4_;
    ip::Icmp           icmp_;

    net::PacketBuffer rx_;
};

} // namespace stack
