#pragma once
//
// The Internet checksum (RFC 1071): the one's-complement sum of 16-bit words.
//
// Used by the IPv4 header, ICMP, and (over a pseudo-header) by UDP and TCP. A
// wrong checksum means the peer drops the packet with no error, so this lives
// in one place and is unit-tested thoroughly.
//
// Two properties we rely on:
//   * To build a checksum: sum the data with the checksum field zeroed, fold
//     the carries, take the one's complement, store that.
//   * To verify: sum the whole thing *including* the stored checksum; a valid
//     packet sums to 0 (0xFFFF before complement).
//
#include <cstddef>
#include <cstdint>
#include <span>

namespace net {

// Accumulate the unfolded 32-bit sum over `data`, continuing from `sum`.
// Words are big-endian (network order). A trailing odd byte is padded with a
// zero low byte, correct only when `data` is the final chunk of the message,
// which is how every caller uses it (pseudo-headers are always even-length, so
// chaining stays 16-bit aligned).
constexpr std::uint32_t checksum_partial(std::span<const std::byte> data,
                                         std::uint32_t sum = 0) noexcept {
    std::size_t i = 0;
    for (; i + 1 < data.size(); i += 2) {
        sum += (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[i])) << 8) |
                static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[i + 1]));
    }
    if (i < data.size()) { // leftover odd byte -> high byte of a padded word
        sum += static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[i])) << 8;
    }
    return sum;
}

// Fold carries into 16 bits and take the one's complement.
constexpr std::uint16_t checksum_fold(std::uint32_t sum) noexcept {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFF);
}

// One-shot checksum over a single span. The returned value is a host-order
// uint16 to be written into the header field in network byte order (NetWriter
// ::u16 does that), and a valid message re-checksums to 0.
constexpr std::uint16_t internet_checksum(std::span<const std::byte> data,
                                          std::uint32_t init = 0) noexcept {
    return checksum_fold(checksum_partial(data, init));
}

} // namespace net
