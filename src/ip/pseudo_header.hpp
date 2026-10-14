#pragma once
//
// The transport-layer (UDP/TCP) checksum over the IPv4 pseudo-header.
//
// UDP and TCP checksums don't just cover their own segment — they also cover a
// 12-byte "pseudo-header" synthesised from the IP layer:
//
//     +--------+--------+--------+--------+
//     |           source IP address       |
//     +--------+--------+--------+--------+
//     |        destination IP address     |
//     +--------+--------+--------+--------+
//     |  zero  | proto  |  transport len  |
//     +--------+--------+--------+--------+
//
// This ties the segment to its addresses and protocol, so a misdelivered packet
// fails the check. The guide calls getting this wrong "the classic bug" — so
// it's one shared helper, written once, that both UDP and TCP call.
//
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "ip/ipv4_address.hpp"
#include "ip/ipv4_sender.hpp" // IpProto
#include "net/buffer.hpp"
#include "net/checksum.hpp"

namespace ip {

// Checksum `segment` (the full UDP/TCP header+payload) with its pseudo-header.
// To build:  zero the segment's checksum field first, then store the result.
// To verify: run it over the segment with the checksum in place; a valid
//            segment yields 0.
inline std::uint16_t transport_checksum(Ipv4Addr src, Ipv4Addr dst, IpProto proto,
                                        std::span<const std::byte> segment) noexcept {
    std::array<std::byte, 12> ph{};
    net::NetWriter w(ph);
    w.u32(src.value);
    w.u32(dst.value);
    w.u8(0);
    w.u8(static_cast<std::uint8_t>(proto));
    w.u16(static_cast<std::uint16_t>(segment.size())); // transport length

    // Pseudo-header is 12 bytes (even), so the segment stays 16-bit aligned.
    std::uint32_t sum = net::checksum_partial(ph);
    sum = net::checksum_partial(segment, sum);
    return net::checksum_fold(sum);
}

} // namespace ip
