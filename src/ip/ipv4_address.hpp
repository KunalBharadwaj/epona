#pragma once
//
// A 32-bit IPv4 address, stored in host byte order.
//
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>

namespace ip {

struct Ipv4Addr {
    std::uint32_t value = 0; // host order, e.g. 10.0.0.2 == 0x0A000002

    constexpr bool operator==(const Ipv4Addr&) const = default;

    // Parse dotted-quad "a.b.c.d". Returns nullopt on malformed input.
    static std::optional<Ipv4Addr> parse(std::string_view s) {
        std::uint32_t parts[4];
        int idx = 0;
        std::uint32_t cur = 0;
        int digits = 0;
        for (char c : s) {
            if (c >= '0' && c <= '9') {
                cur = cur * 10 + static_cast<std::uint32_t>(c - '0');
                if (cur > 255) return std::nullopt;
                ++digits;
            } else if (c == '.') {
                if (digits == 0 || idx >= 3) return std::nullopt;
                parts[idx++] = cur;
                cur = 0;
                digits = 0;
            } else {
                return std::nullopt;
            }
        }
        if (digits == 0 || idx != 3) return std::nullopt;
        parts[idx] = cur;
        return Ipv4Addr{(parts[0] << 24) | (parts[1] << 16) |
                        (parts[2] << 8) | parts[3]};
    }

    std::string to_string() const {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                      (value >> 24) & 0xFF, (value >> 16) & 0xFF,
                      (value >> 8) & 0xFF, value & 0xFF);
        return std::string(buf);
    }
};

} // namespace ip
