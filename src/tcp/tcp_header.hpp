#pragma once
//
// The TCP segment header (RFC 793 §3.1).
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-------------------------------+-------------------------------+
//   |          source port          |       destination port        |
//   +---------------------------------------------------------------+
//   |                        sequence number                        |
//   +---------------------------------------------------------------+
//   |                    acknowledgment number                      |
//   +-------+-----------+-------------------------------------------+
//   | offs  |  reserved |C E U A P R S F|           window          |
//   +-------------------------------+-------------------------------+
//   |           checksum            |         urgent pointer        |
//   +-------------------------------+-------------------------------+
//   |                    options (if offset > 5) ...                |
//   +---------------------------------------------------------------+
//
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "net/buffer.hpp"

namespace tcp {

inline constexpr std::size_t kTcpMinHeader = 20;

// Control-bit flags (the classic low six; we ignore ECN/CWR for now).
namespace flag {
inline constexpr std::uint8_t FIN = 0x01;
inline constexpr std::uint8_t SYN = 0x02;
inline constexpr std::uint8_t RST = 0x04;
inline constexpr std::uint8_t PSH = 0x08;
inline constexpr std::uint8_t ACK = 0x10;
inline constexpr std::uint8_t URG = 0x20;
} // namespace flag

struct TcpHeader {
    std::uint16_t src_port    = 0;
    std::uint16_t dst_port    = 0;
    std::uint32_t seq         = 0;
    std::uint32_t ack         = 0;
    std::uint8_t  data_offset = 0; // header length in BYTES
    std::uint8_t  flags       = 0;
    std::uint16_t window      = 0;
    std::uint16_t checksum    = 0;
    std::uint16_t urgent      = 0;

    bool has(std::uint8_t f) const noexcept { return (flags & f) != 0; }

    // Parse a header from the front of a segment. Returns nullopt if the
    // segment is too short or the data offset is impossible.
    static std::optional<TcpHeader> parse(std::span<const std::byte> seg) {
        if (seg.size() < kTcpMinHeader) return std::nullopt;
        net::NetReader r(seg);
        TcpHeader h;
        h.src_port = r.u16();
        h.dst_port = r.u16();
        h.seq      = r.u32();
        h.ack      = r.u32();
        std::uint8_t off_byte = r.u8();
        h.data_offset = static_cast<std::uint8_t>((off_byte >> 4) * 4);
        h.flags    = r.u8();
        h.window   = r.u16();
        h.checksum = r.u16();
        h.urgent   = r.u16();
        if (!r.ok()) return std::nullopt;
        if (h.data_offset < kTcpMinHeader || h.data_offset > seg.size())
            return std::nullopt;
        return h;
    }
};

} // namespace tcp
