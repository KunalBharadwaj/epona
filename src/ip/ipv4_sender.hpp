#pragma once
//
// The downward interface ICMP (and later UDP/TCP) use to send a payload via
// IPv4. IPv4 fills in the header, computes the checksum, resolves the next-hop
// MAC through ARP, and hands the frame to Ethernet.
//
#include <cstddef>
#include <cstdint>
#include <span>

#include "ip/ipv4_address.hpp"

namespace ip {

// IP protocol numbers we care about (IANA).
enum class IpProto : std::uint8_t {
    Icmp = 1,
    Tcp  = 6,
    Udp  = 17,
};

struct Ipv4Sender {
    virtual ~Ipv4Sender() = default;

    // Wrap `payload` in an IPv4 header (protocol `proto`) addressed to `dst`
    // and send it down. Returns false if the next hop could not be resolved
    // yet (an ARP request is kicked off and the packet is dropped).
    virtual bool send_ipv4(Ipv4Addr dst, IpProto proto,
                           std::span<const std::byte> payload) = 0;

    virtual Ipv4Addr local_ip() const = 0;
};

} // namespace ip
