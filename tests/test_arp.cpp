#include "eth/arp.hpp"

#include <gtest/gtest.h>

#include <array>

#include "eth/ethernet.hpp"
#include "fakes.hpp"
#include "net/buffer.hpp"

using namespace eth;
using ip::Ipv4Addr;
using testing_fakes::CapturingEthSender;

namespace {
MacAddr mac(std::initializer_list<unsigned> v) {
    MacAddr m; std::size_t i = 0;
    for (unsigned b : v) m.octets[i++] = std::byte{static_cast<unsigned char>(b)};
    return m;
}
}

TEST(Arp, RepliesToRequestForOurIp) {
    const MacAddr  our_mac  = mac({0x0a, 0, 0, 0, 0, 0x02});
    const MacAddr  host_mac = mac({0x0a, 0, 0, 0, 0, 0x01});
    const Ipv4Addr our_ip   = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host_ip  = Ipv4Addr::parse("10.0.0.1").value();

    CapturingEthSender eth(our_mac);
    Arp arp(eth, our_ip);

    // Build "who has 10.0.0.2? tell 10.0.0.1".
    std::array<std::byte, kArpPacketSize> req{};
    net::NetWriter w(req);
    w.u16(kArpHwEthernet);
    w.u16(kArpProtoIpv4);
    w.u8(6); w.u8(4);
    w.u16(kArpOpRequest);
    w.bytes(host_mac.bytes()); w.u32(host_ip.value); // sender
    w.bytes(MacAddr{}.bytes()); w.u32(our_ip.value); // target (unknown MAC)

    arp.receive(req, host_mac);

    ASSERT_EQ(eth.frames.size(), 1u);
    EXPECT_EQ(eth.frames[0].ethertype, kEtherTypeArp);
    EXPECT_EQ(eth.frames[0].dst, host_mac);

    // Parse the reply.
    net::NetReader r(eth.frames[0].payload);
    EXPECT_EQ(r.u16(), kArpHwEthernet);
    EXPECT_EQ(r.u16(), kArpProtoIpv4);
    EXPECT_EQ(r.u8(), 6);
    EXPECT_EQ(r.u8(), 4);
    EXPECT_EQ(r.u16(), kArpOpReply);
    EXPECT_EQ(MacAddr::from_bytes(r.bytes(6)), our_mac);  // sha = us
    EXPECT_EQ(r.u32(), our_ip.value);                     // spa = us
    EXPECT_EQ(MacAddr::from_bytes(r.bytes(6)), host_mac); // tha = requester
    EXPECT_EQ(r.u32(), host_ip.value);                    // tpa = requester

    // And we learned the requester's mapping.
    auto cached = arp.cache().lookup(host_ip);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(*cached, host_mac);
}

TEST(Arp, IgnoresRequestForOtherIp) {
    const MacAddr  our_mac  = mac({0x0a, 0, 0, 0, 0, 0x02});
    const MacAddr  host_mac = mac({0x0a, 0, 0, 0, 0, 0x01});
    const Ipv4Addr our_ip   = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr other    = Ipv4Addr::parse("10.0.0.9").value();
    const Ipv4Addr host_ip  = Ipv4Addr::parse("10.0.0.1").value();

    CapturingEthSender eth(our_mac);
    Arp arp(eth, our_ip);

    std::array<std::byte, kArpPacketSize> req{};
    net::NetWriter w(req);
    w.u16(kArpHwEthernet); w.u16(kArpProtoIpv4); w.u8(6); w.u8(4);
    w.u16(kArpOpRequest);
    w.bytes(host_mac.bytes()); w.u32(host_ip.value);
    w.bytes(MacAddr{}.bytes()); w.u32(other.value); // not our IP

    arp.receive(req, host_mac);
    EXPECT_TRUE(eth.frames.empty()); // no reply
}
