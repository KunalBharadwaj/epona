#include "eth/mac.hpp"
#include "ip/ipv4_address.hpp"

#include <gtest/gtest.h>

using ip::Ipv4Addr;
using eth::MacAddr;

TEST(Ipv4Addr, ParsesDottedQuad) {
    auto a = Ipv4Addr::parse("10.0.0.2");
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->value, 0x0A000002u);
    EXPECT_EQ(a->to_string(), "10.0.0.2");
}

TEST(Ipv4Addr, RoundTrips) {
    for (const char* s : {"0.0.0.0", "255.255.255.255", "192.168.1.100", "1.2.3.4"}) {
        auto a = Ipv4Addr::parse(s);
        ASSERT_TRUE(a.has_value()) << s;
        EXPECT_EQ(a->to_string(), s);
    }
}

TEST(Ipv4Addr, RejectsMalformed) {
    EXPECT_FALSE(Ipv4Addr::parse("10.0.0").has_value());
    EXPECT_FALSE(Ipv4Addr::parse("10.0.0.256").has_value());
    EXPECT_FALSE(Ipv4Addr::parse("10.0.0.1.2").has_value());
    EXPECT_FALSE(Ipv4Addr::parse("a.b.c.d").has_value());
    EXPECT_FALSE(Ipv4Addr::parse("").has_value());
    EXPECT_FALSE(Ipv4Addr::parse("10..0.1").has_value());
}

TEST(MacAddr, BroadcastAndFormat) {
    EXPECT_TRUE(MacAddr::broadcast().is_broadcast());
    EXPECT_TRUE(MacAddr::broadcast().is_multicast());
    EXPECT_EQ(MacAddr::broadcast().to_string(), "ff:ff:ff:ff:ff:ff");

    MacAddr m;
    m.octets = {std::byte{0x0a}, std::byte{0x00}, std::byte{0x00},
                std::byte{0x00}, std::byte{0x00}, std::byte{0x02}};
    EXPECT_EQ(m.to_string(), "0a:00:00:00:00:02");
    EXPECT_FALSE(m.is_multicast()); // 0x0a low bit clear
    EXPECT_FALSE(m.is_broadcast());
}
