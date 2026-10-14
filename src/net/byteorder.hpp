#pragma once
//
// Network byte-order helpers.
//
// Everything on the wire is big-endian ("network byte order"). Our CPU is
// almost certainly little-endian, so every multi-byte integer we read off a
// packet or write into one has to be swapped. The guide calls this out as the
// single most common source of silent bugs, so we isolate it here, make it
// constexpr, and unit-test it.
//
// We implement the swaps ourselves with <bit> (C++20) instead of pulling in
// htons/htonl from <arpa/inet.h> — it keeps the stack honest about what byte
// order means and it's a nice thing to be able to explain in an interview.
// (std::byteswap would do this for us, but that's C++23.)
//
#include <bit>
#include <concepts>
#include <cstdint>

namespace net {

// Reverse the bytes of any unsigned integer at compile time.
template <std::unsigned_integral T>
constexpr T byteswap(T value) noexcept {
    if constexpr (sizeof(T) == 1) {
        return value;
    } else if constexpr (sizeof(T) == 2) {
        return static_cast<T>((value >> 8) | (value << 8));
    } else if constexpr (sizeof(T) == 4) {
        return static_cast<T>(
            ((value & 0x0000'00FFu) << 24) |
            ((value & 0x0000'FF00u) << 8)  |
            ((value & 0x00FF'0000u) >> 8)  |
            ((value & 0xFF00'0000u) >> 24));
    } else { // sizeof(T) == 8
        return static_cast<T>(
            ((value & 0x0000'0000'0000'00FFull) << 56) |
            ((value & 0x0000'0000'0000'FF00ull) << 40) |
            ((value & 0x0000'0000'00FF'0000ull) << 24) |
            ((value & 0x0000'0000'FF00'0000ull) << 8)  |
            ((value & 0x0000'00FF'0000'0000ull) >> 8)  |
            ((value & 0x0000'FF00'0000'0000ull) >> 24) |
            ((value & 0x00FF'0000'0000'0000ull) >> 40) |
            ((value & 0xFF00'0000'0000'0000ull) >> 56));
    }
}

// Host <-> network conversions. On a big-endian host these are no-ops.
template <std::unsigned_integral T>
constexpr T hton(T value) noexcept {
    if constexpr (std::endian::native == std::endian::big) {
        return value;
    } else {
        return byteswap(value);
    }
}

template <std::unsigned_integral T>
constexpr T ntoh(T value) noexcept {
    return hton(value); // swap is symmetric
}

// Convenience names matching the classic POSIX spelling.
constexpr std::uint16_t hton16(std::uint16_t v) noexcept { return hton(v); }
constexpr std::uint32_t hton32(std::uint32_t v) noexcept { return hton(v); }
constexpr std::uint16_t ntoh16(std::uint16_t v) noexcept { return ntoh(v); }
constexpr std::uint32_t ntoh32(std::uint32_t v) noexcept { return ntoh(v); }

} // namespace net
