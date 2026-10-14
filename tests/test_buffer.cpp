#include "net/buffer.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>

using namespace net;

namespace {
std::byte B(unsigned v) { return std::byte{static_cast<unsigned char>(v)}; }
}

TEST(NetReader, ReadsBigEndianIntegers) {
    std::array<std::byte, 7> raw{B(0xAA), B(0x12), B(0x34),
                                 B(0xDE), B(0xAD), B(0xBE), B(0xEF)};
    NetReader r(raw);
    EXPECT_EQ(r.u8(), 0xAA);
    EXPECT_EQ(r.u16(), 0x1234);
    EXPECT_EQ(r.u32(), 0xDEADBEEF);
    EXPECT_TRUE(r.ok());
    EXPECT_EQ(r.remaining(), 0u);
}

TEST(NetReader, BytesSpanAdvancesCursor) {
    std::array<std::byte, 6> mac{B(1), B(2), B(3), B(4), B(5), B(6)};
    NetReader r(mac);
    auto got = r.bytes(6);
    ASSERT_EQ(got.size(), 6u);
    EXPECT_EQ(std::to_integer<int>(got[0]), 1);
    EXPECT_EQ(std::to_integer<int>(got[5]), 6);
    EXPECT_EQ(r.remaining(), 0u);
}

TEST(NetReader, OverrunSetsNotOk) {
    std::array<std::byte, 2> raw{B(0), B(1)};
    NetReader r(raw);
    (void)r.u32();           // only 2 bytes available
    EXPECT_FALSE(r.ok());
}

TEST(NetWriter, WritesBigEndianAndReadsBack) {
    std::array<std::byte, 7> buf{};
    NetWriter w(buf);
    w.u8(0xAA);
    w.u16(0x1234);
    w.u32(0xDEADBEEF);
    ASSERT_TRUE(w.ok());
    EXPECT_EQ(w.offset(), 7u);

    // On the wire the most significant byte comes first.
    EXPECT_EQ(std::to_integer<unsigned>(buf[0]), 0xAAu);
    EXPECT_EQ(std::to_integer<unsigned>(buf[1]), 0x12u);
    EXPECT_EQ(std::to_integer<unsigned>(buf[2]), 0x34u);
    EXPECT_EQ(std::to_integer<unsigned>(buf[3]), 0xDEu);
    EXPECT_EQ(std::to_integer<unsigned>(buf[6]), 0xEFu);

    NetReader r(buf);
    EXPECT_EQ(r.u8(), 0xAA);
    EXPECT_EQ(r.u16(), 0x1234);
    EXPECT_EQ(r.u32(), 0xDEADBEEF);
}

TEST(NetWriter, OverrunSetsNotOk) {
    std::array<std::byte, 3> buf{};
    NetWriter w(buf);
    w.u32(0x11223344);
    EXPECT_FALSE(w.ok());
}
