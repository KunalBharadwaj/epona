#pragma once
//
// Test doubles that capture what a layer tries to send downward, so each layer
// can be exercised in isolation without a real device.
//
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "eth/eth_sender.hpp"
#include "ip/ipv4_sender.hpp"

namespace testing_fakes {

inline std::vector<std::byte> to_vec(std::span<const std::byte> s) {
    return {s.begin(), s.end()};
}

// Captures frames an upper layer (ARP / IPv4) hands to Ethernet.
struct CapturingEthSender : eth::EthSender {
    eth::MacAddr mac;
    struct Frame {
        eth::MacAddr          dst;
        std::uint16_t         ethertype;
        std::vector<std::byte> payload;
    };
    std::vector<Frame> frames;

    explicit CapturingEthSender(eth::MacAddr m) : mac(m) {}

    void send_frame(const eth::MacAddr& dst, std::uint16_t ethertype,
                    std::span<const std::byte> payload) override {
        frames.push_back({dst, ethertype, to_vec(payload)});
    }
    const eth::MacAddr& local_mac() const override { return mac; }
};

// Captures datagrams ICMP/UDP/TCP hand to IPv4.
struct CapturingIpv4Sender : ip::Ipv4Sender {
    ip::Ipv4Addr ip;
    bool         resolvable = true; // flip to simulate an unresolved next hop
    struct Datagram {
        ip::Ipv4Addr           dst;
        ip::IpProto            proto;
        std::vector<std::byte> payload;
    };
    std::vector<Datagram> datagrams;

    explicit CapturingIpv4Sender(ip::Ipv4Addr a) : ip(a) {}

    bool send_ipv4(ip::Ipv4Addr dst, ip::IpProto proto,
                   std::span<const std::byte> payload) override {
        if (!resolvable) return false;
        datagrams.push_back({dst, proto, to_vec(payload)});
        return true;
    }
    ip::Ipv4Addr local_ip() const override { return ip; }
};

} // namespace testing_fakes
