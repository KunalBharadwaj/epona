#pragma once
//
// IPv4 (RFC 791): addressing, the 20-byte header, and its checksum.
//
// Inbound: parse + verify the header checksum (a wrong one means silent drops,
// so we check it and count failures), then demux on the protocol field to
// ICMP / UDP / TCP.
// Outbound: build a header with a correct checksum, TTL, the don't-fragment
// bit set (we never fragment), resolve the next-hop MAC via ARP, and send down.
//
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>

#include "eth/arp.hpp"
#include "eth/eth_sender.hpp"
#include "eth/mac.hpp"
#include "ip/ipv4_address.hpp"
#include "ip/ipv4_sender.hpp"

namespace ip {

inline constexpr std::size_t  kIpv4MinHeader = 20;
inline constexpr std::uint8_t kIpv4Version   = 4;
inline constexpr std::uint8_t kDefaultTtl    = 64;
inline constexpr std::uint16_t kFlagDontFragment = 0x4000;

// A parsed, demuxed datagram handed to a transport layer.
struct Ipv4Datagram {
    Ipv4Addr                   src;
    Ipv4Addr                   dst;
    std::uint8_t               protocol = 0;
    std::span<const std::byte> payload;
};

class Ipv4Layer : public Ipv4Sender {
public:
    Ipv4Layer(eth::EthSender& eth, eth::Arp& arp, Ipv4Addr local_ip)
        : eth_(eth), arp_(arp), local_ip_(local_ip) {}

    using Handler = std::function<void(const Ipv4Datagram&)>;
    void set_icmp_handler(Handler h) { on_icmp_ = std::move(h); }
    void set_udp_handler(Handler h)  { on_udp_  = std::move(h); }
    void set_tcp_handler(Handler h)  { on_tcp_  = std::move(h); }

    // Inbound datagram (Ethernet payload). `src_mac` lets us learn the sender's
    // IP->MAC so our replies resolve without a round trip.
    void receive(std::span<const std::byte> packet, const eth::MacAddr& src_mac);

    // Ipv4Sender interface.
    bool send_ipv4(Ipv4Addr dst, IpProto proto,
                   std::span<const std::byte> payload) override;
    Ipv4Addr local_ip() const override { return local_ip_; }

    // Counters, handy for tests and a future stats page.
    std::uint64_t checksum_errors() const noexcept { return checksum_errors_; }

private:
    eth::EthSender& eth_;
    eth::Arp&       arp_;
    Ipv4Addr        local_ip_;

    Handler on_icmp_;
    Handler on_udp_;
    Handler on_tcp_;

    std::uint16_t next_id_         = 0;
    std::uint64_t checksum_errors_ = 0;
};

} // namespace ip
