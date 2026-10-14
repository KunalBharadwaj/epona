#pragma once
//
// ARP (RFC 826): maps IPv4 addresses to MAC addresses.
//
// The host must learn our stack's MAC before it will send us IP packets, so the
// core job is: when someone broadcasts "who has 10.0.0.2?", reply "that's me,
// here's my MAC." We also keep a cache (with aging) and can send our own
// requests to resolve a next-hop MAC for outbound traffic.
//
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>

#include "eth/eth_sender.hpp"
#include "eth/mac.hpp"
#include "ip/ipv4_address.hpp"
#include "net/event_loop.hpp"

namespace eth {

inline constexpr std::size_t   kArpPacketSize = 28; // IPv4-over-Ethernet
inline constexpr std::uint16_t kArpHwEthernet = 1;
inline constexpr std::uint16_t kArpProtoIpv4  = 0x0800;
inline constexpr std::uint16_t kArpOpRequest  = 1;
inline constexpr std::uint16_t kArpOpReply    = 2;

// IP -> MAC cache with time-based expiry.
class ArpCache {
public:
    void insert(ip::Ipv4Addr ip, const MacAddr& mac) {
        table_[ip.value] = Entry{mac, net::Clock::now() + kTtl};
    }

    std::optional<MacAddr> lookup(ip::Ipv4Addr ip) const {
        auto it = table_.find(ip.value);
        if (it == table_.end()) return std::nullopt;
        if (net::Clock::now() >= it->second.expires) return std::nullopt;
        return it->second.mac;
    }

    std::size_t size() const noexcept { return table_.size(); }

private:
    static constexpr net::Duration kTtl = std::chrono::seconds(60);
    struct Entry { MacAddr mac; net::TimePoint expires; };
    std::unordered_map<std::uint32_t, Entry> table_;
};

class Arp {
public:
    Arp(EthSender& eth, ip::Ipv4Addr local_ip)
        : eth_(eth), local_ip_(local_ip) {}

    // Handle an inbound ARP packet (Ethernet payload). `src_mac` is the frame
    // source, used only as a sanity cross-check.
    void receive(std::span<const std::byte> payload, const MacAddr& src_mac);

    // Resolve `target` to a MAC. On a cache miss, broadcasts a request and
    // returns nullopt — the caller should drop the packet and rely on retry.
    std::optional<MacAddr> resolve(ip::Ipv4Addr target);

    // Broadcast "who has `target`?"
    void send_request(ip::Ipv4Addr target);

    ArpCache&       cache()       noexcept { return cache_; }
    const ArpCache& cache() const noexcept { return cache_; }

private:
    void send_reply(const MacAddr& to_mac, ip::Ipv4Addr to_ip);

    EthSender&   eth_;
    ip::Ipv4Addr local_ip_;
    ArpCache     cache_;
};

} // namespace eth
