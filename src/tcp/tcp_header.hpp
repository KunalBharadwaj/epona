#pragma once
//
// The TCP segment header (RFC 793 §3.1) plus the options we care about: MSS,
// SACK-permitted, and SACK blocks (RFC 2018).
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
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

#include "net/buffer.hpp"

namespace tcp {

inline constexpr std::size_t kTcpMinHeader = 20;
inline constexpr std::size_t kMaxSackBlocks = 4;

// Control-bit flags (the classic low six; we ignore ECN/CWR for now).
namespace flag {
inline constexpr std::uint8_t FIN = 0x01;
inline constexpr std::uint8_t SYN = 0x02;
inline constexpr std::uint8_t RST = 0x04;
inline constexpr std::uint8_t PSH = 0x08;
inline constexpr std::uint8_t ACK = 0x10;
inline constexpr std::uint8_t URG = 0x20;
} // namespace flag

// TCP option kinds.
namespace opt {
inline constexpr std::uint8_t kEnd           = 0;
inline constexpr std::uint8_t kNop           = 1;
inline constexpr std::uint8_t kMss           = 2;
inline constexpr std::uint8_t kSackPermitted = 4;
inline constexpr std::uint8_t kSack          = 5;
} // namespace opt

struct SackBlock { std::uint32_t left = 0; std::uint32_t right = 0; };

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

    // Parsed options.
    std::uint16_t mss            = 0;      // 0 = absent
    bool          sack_permitted = false;
    std::array<SackBlock, kMaxSackBlocks> sack_blocks{};
    std::uint8_t  sack_count     = 0;

    bool has(std::uint8_t f) const noexcept { return (flags & f) != 0; }

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

        h.parse_options(seg);
        return h;
    }

private:
    static std::uint32_t rd32(std::span<const std::byte> s, std::size_t o) {
        return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(s[o]))     << 24) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(s[o + 1])) << 16) |
               (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(s[o + 2])) << 8)  |
                static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(s[o + 3]));
    }

    void parse_options(std::span<const std::byte> seg) {
        std::size_t p = kTcpMinHeader;
        const std::size_t end = data_offset;
        while (p < end) {
            std::uint8_t kind = std::to_integer<std::uint8_t>(seg[p]);
            if (kind == opt::kEnd) break;
            if (kind == opt::kNop) { ++p; continue; }
            if (p + 1 >= end) break;
            std::uint8_t len = std::to_integer<std::uint8_t>(seg[p + 1]);
            if (len < 2 || p + len > end) break; // malformed -> stop

            if (kind == opt::kMss && len == 4) {
                mss = static_cast<std::uint16_t>(
                    (std::to_integer<std::uint8_t>(seg[p + 2]) << 8) |
                     std::to_integer<std::uint8_t>(seg[p + 3]));
            } else if (kind == opt::kSackPermitted && len == 2) {
                sack_permitted = true;
            } else if (kind == opt::kSack) {
                std::uint8_t nblocks = static_cast<std::uint8_t>((len - 2) / 8);
                for (std::uint8_t b = 0; b < nblocks && sack_count < kMaxSackBlocks; ++b) {
                    std::size_t bo = p + 2 + static_cast<std::size_t>(b) * 8;
                    sack_blocks[sack_count++] = SackBlock{rd32(seg, bo), rd32(seg, bo + 4)};
                }
            }
            p += len;
        }
    }
};

} // namespace tcp
