#include "net/checksum.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>

using namespace net;

namespace {
std::byte B(unsigned v) { return std::byte{static_cast<unsigned char>(v)}; }
}

// Canonical IPv4-header example (checksum field zeroed) -> 0xB861.
TEST(Checksum, KnownIpv4Header) {
    std::array<std::byte, 20> hdr{
        B(0x45), B(0x00), B(0x00), B(0x73), B(0x00), B(0x00), B(0x40), B(0x00),
        B(0x40), B(0x11), B(0x00), B(0x00), B(0xc0), B(0xa8), B(0x00), B(0x01),
        B(0xc0), B(0xa8), B(0x00), B(0xc7)};
    EXPECT_EQ(internet_checksum(hdr), 0xB861);
}

// With the correct checksum in place, a valid header re-sums to 0.
TEST(Checksum, ValidHeaderVerifiesToZero) {
    std::array<std::byte, 20> hdr{
        B(0x45), B(0x00), B(0x00), B(0x73), B(0x00), B(0x00), B(0x40), B(0x00),
        B(0x40), B(0x11), B(0xb8), B(0x61), B(0xc0), B(0xa8), B(0x00), B(0x01),
        B(0xc0), B(0xa8), B(0x00), B(0xc7)};
    EXPECT_EQ(internet_checksum(hdr), 0);
}

TEST(Checksum, OddLengthPadsLastByte) {
    std::array<std::byte, 3> data{B(0x12), B(0x34), B(0x56)};
    // 0x1234 + 0x5600 = 0x6834 -> ~ = 0x97CB
    EXPECT_EQ(internet_checksum(data), 0x97CB);
}

TEST(Checksum, CarryFoldsAround) {
    std::array<std::byte, 4> data{B(0xff), B(0xff), B(0xff), B(0xff)};
    // 0xFFFF + 0xFFFF = 0x1FFFE -> fold -> 0xFFFF -> ~ = 0x0000
    EXPECT_EQ(internet_checksum(data), 0x0000);
}
