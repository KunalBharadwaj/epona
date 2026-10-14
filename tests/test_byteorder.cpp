#include "net/byteorder.hpp"

#include <gtest/gtest.h>

using namespace net;

// Compile-time sanity: byteswap must be constexpr and correct.
static_assert(byteswap<std::uint16_t>(0x0102) == 0x0201);
static_assert(byteswap<std::uint32_t>(0x01020304) == 0x04030201);
static_assert(byteswap<std::uint64_t>(0x0102030405060708ull) == 0x0807060504030201ull);

TEST(ByteOrder, Swap16) {
    EXPECT_EQ(byteswap<std::uint16_t>(0xABCD), 0xCDAB);
}

TEST(ByteOrder, Swap32) {
    EXPECT_EQ(byteswap<std::uint32_t>(0xDEADBEEF), 0xEFBEADDE);
}

TEST(ByteOrder, Swap64) {
    EXPECT_EQ(byteswap<std::uint64_t>(0x1122334455667788ull), 0x8877665544332211ull);
}

TEST(ByteOrder, HostNetworkRoundTrip) {
    EXPECT_EQ(ntoh16(hton16(0x1234)), 0x1234);
    EXPECT_EQ(ntoh32(hton32(0xCAFEBABE)), 0xCAFEBABE);
}

TEST(ByteOrder, PortNumberLooksRightOnTheWire) {
    // Port 80 (0x0050) on the wire is bytes {0x00, 0x50}. After hton on a
    // little-endian host the in-memory u16 holds 0x5000.
    std::uint16_t net = hton16(80);
    if constexpr (std::endian::native == std::endian::little) {
        EXPECT_EQ(net, 0x5000);
    } else {
        EXPECT_EQ(net, 0x0050);
    }
}
