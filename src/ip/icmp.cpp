#include "ip/icmp.hpp"

#include "net/buffer.hpp"
#include "net/checksum.hpp"

namespace ip {

void Icmp::receive(const Ipv4Datagram& dg) {
    std::span<const std::byte> msg = dg.payload;
    if (msg.size() < kIcmpMinSize) return;

    // Verify the ICMP checksum (covers the whole message). A valid one sums to 0.
    if (net::internet_checksum(msg) != 0) {
        ++checksum_errors_;
        return;
    }

    std::uint8_t type = std::to_integer<std::uint8_t>(msg[0]);
    if (type != kIcmpEchoRequest) return; // only ping for now

    // Build the reply by copying the request and flipping it to a reply: the
    // identifier, sequence and payload must come back unchanged.
    net::PacketBuffer buf;
    auto out = buf.capacity_span();
    if (msg.size() > out.size()) return;
    std::copy(msg.begin(), msg.end(), out.begin());

    out[0] = std::byte{kIcmpEchoReply}; // type 8 -> 0
    out[1] = std::byte{0};              // code
    out[2] = std::byte{0};              // checksum field zeroed before recompute
    out[3] = std::byte{0};

    auto reply = out.subspan(0, msg.size());
    std::uint16_t cksum = net::internet_checksum(reply);
    reply[2] = std::byte{static_cast<std::uint8_t>(cksum >> 8)};
    reply[3] = std::byte{static_cast<std::uint8_t>(cksum & 0xFF)};

    if (ip_.send_ipv4(dg.src, IpProto::Icmp, reply)) {
        ++echo_replies_;
    }
}

} // namespace ip
