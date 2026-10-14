#pragma once
//
// ICMP (RFC 792): for Milestone 1 we only answer echo requests (ping).
//
// An echo request (type 8) becomes an echo reply (type 0) with the identifier,
// sequence number and payload copied verbatim and the ICMP checksum recomputed.
// Everything else is ignored for now.
//
#include <cstdint>

#include "ip/ipv4.hpp"
#include "ip/ipv4_sender.hpp"

namespace ip {

inline constexpr std::uint8_t kIcmpEchoReply   = 0;
inline constexpr std::uint8_t kIcmpEchoRequest = 8;
inline constexpr std::size_t  kIcmpMinSize     = 8; // type,code,cksum,id,seq

class Icmp {
public:
    explicit Icmp(Ipv4Sender& ip) : ip_(ip) {}

    void receive(const Ipv4Datagram& dg);

    std::uint64_t echo_replies_sent() const noexcept { return echo_replies_; }
    std::uint64_t checksum_errors()   const noexcept { return checksum_errors_; }

private:
    Ipv4Sender&   ip_;
    std::uint64_t echo_replies_    = 0;
    std::uint64_t checksum_errors_ = 0;
};

} // namespace ip
