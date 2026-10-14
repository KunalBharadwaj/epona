#pragma once
//
// A 48-bit Ethernet MAC address.
//
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>

namespace eth {

struct MacAddr {
    std::array<std::byte, 6> octets{};

    bool operator==(const MacAddr&) const = default;

    static MacAddr broadcast() noexcept {
        MacAddr m;
        m.octets.fill(std::byte{0xFF});
        return m;
    }

    // Build from a raw 6-byte span (e.g. straight out of a frame).
    static MacAddr from_bytes(std::span<const std::byte> src) noexcept {
        MacAddr m;
        for (std::size_t i = 0; i < 6 && i < src.size(); ++i) m.octets[i] = src[i];
        return m;
    }

    std::span<const std::byte> bytes() const noexcept { return octets; }

    bool is_broadcast() const noexcept { return *this == broadcast(); }

    // Multicast/group bit = least-significant bit of the first octet.
    bool is_multicast() const noexcept {
        return (std::to_integer<unsigned>(octets[0]) & 0x01) != 0;
    }

    std::string to_string() const {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                      std::to_integer<unsigned>(octets[0]),
                      std::to_integer<unsigned>(octets[1]),
                      std::to_integer<unsigned>(octets[2]),
                      std::to_integer<unsigned>(octets[3]),
                      std::to_integer<unsigned>(octets[4]),
                      std::to_integer<unsigned>(octets[5]));
        return std::string(buf);
    }
};

} // namespace eth
