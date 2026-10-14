#include "ip/ipv4.hpp"

#include <gtest/gtest.h>

#include <array>
#include <optional>
#include <vector>

#include "eth/arp.hpp"
#include "eth/ethernet.hpp"
#include "fakes.hpp"
#include "net/buffer.hpp"
#include "net/checksum.hpp"

using namespace ip;
using eth::MacAddr;
using testing_fakes::CapturingEthSender;

namespace {
std::byte B(unsigned v) { return std::byte{static_cast<unsigned char>(v)}; }

MacAddr mac(std::initializer_list<unsigned> v) {
    MacAddr m; std::size_t i = 0;
    for (unsigned b : v) m.octets[i++] = std::byte{static_cast<unsigned char>(b)};
    return m;
}

// Build a valid IPv4 packet (header checksum filled in) carrying `payload`.
std::vector<std::byte> build_ipv4(Ipv4Addr src, Ipv4Addr dst, std::uint8_t proto,
                                  std::span<const std::byte> payload) {
    std::vector<std::byte> pkt(kIpv4MinHeader + payload.size());
    net::NetWriter w(pkt);
    w.u8(0x45);
    w.u8(0);
    w.u16(static_cast<std::uint16_t>(pkt.size()));
    w.u16(0);
    w.u16(0x4000);
    w.u8(64);
    w.u8(proto);
    w.u16(0); // checksum placeholder
    w.u32(src.value);
    w.u32(dst.value);
    w.bytes(payload);
    std::uint16_t c = net::internet_checksum(std::span<const std::byte>(pkt.data(), kIpv4MinHeader));
    pkt[10] = B(c >> 8);
    pkt[11] = B(c & 0xFF);
    return pkt;
}
} // namespace

TEST(Ipv4, ParsesAndDispatchesToIcmp) {
    const Ipv4Addr our  = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host = Ipv4Addr::parse("10.0.0.1").value();

    CapturingEthSender eth(mac({0x0a, 0, 0, 0, 0, 0x02}));
    eth::Arp arp(eth, our);
    Ipv4Layer ipv4(eth, arp, our);

    std::array<std::byte, 4> payload{B(1), B(2), B(3), B(4)};
    std::optional<Ipv4Datagram> got;
    ipv4.set_icmp_handler([&](const Ipv4Datagram& dg) { got = dg; });

    auto pkt = build_ipv4(host, our, static_cast<std::uint8_t>(IpProto::Icmp), payload);
    ipv4.receive(pkt, mac({0x0a, 0, 0, 0, 0, 0x01}));

    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->src, host);
    EXPECT_EQ(got->dst, our);
    EXPECT_EQ(got->protocol, static_cast<std::uint8_t>(IpProto::Icmp));
    ASSERT_EQ(got->payload.size(), payload.size());
    EXPECT_EQ(got->payload[0], B(1));
    EXPECT_EQ(got->payload[3], B(4));

    // Receiving also learned the sender's IP->MAC.
    EXPECT_TRUE(arp.cache().lookup(host).has_value());
}

TEST(Ipv4, DropsPacketWithBadChecksum) {
    const Ipv4Addr our  = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host = Ipv4Addr::parse("10.0.0.1").value();

    CapturingEthSender eth(mac({0x0a, 0, 0, 0, 0, 0x02}));
    eth::Arp arp(eth, our);
    Ipv4Layer ipv4(eth, arp, our);

    bool called = false;
    ipv4.set_icmp_handler([&](const Ipv4Datagram&) { called = true; });

    std::array<std::byte, 2> payload{B(0xAA), B(0xBB)};
    auto pkt = build_ipv4(host, our, static_cast<std::uint8_t>(IpProto::Icmp), payload);
    pkt[11] = B(static_cast<unsigned>(std::to_integer<unsigned>(pkt[11]) ^ 0xFF)); // corrupt

    ipv4.receive(pkt, mac({0x0a, 0, 0, 0, 0, 0x01}));
    EXPECT_FALSE(called);
    EXPECT_EQ(ipv4.checksum_errors(), 1u);
}

TEST(Ipv4, BuildsValidOutboundHeader) {
    const Ipv4Addr our  = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host = Ipv4Addr::parse("10.0.0.1").value();
    const MacAddr  host_mac = mac({0x0a, 0, 0, 0, 0, 0x01});

    CapturingEthSender eth(mac({0x0a, 0, 0, 0, 0, 0x02}));
    eth::Arp arp(eth, our);
    arp.cache().insert(host, host_mac); // pre-resolve so send succeeds
    Ipv4Layer ipv4(eth, arp, our);

    std::array<std::byte, 3> payload{B(0xDE), B(0xAD), B(0xBE)};
    ASSERT_TRUE(ipv4.send_ipv4(host, IpProto::Icmp, payload));

    ASSERT_EQ(eth.frames.size(), 1u);
    EXPECT_EQ(eth.frames[0].ethertype, eth::kEtherTypeIpv4);
    EXPECT_EQ(eth.frames[0].dst, host_mac);

    const auto& f = eth.frames[0].payload;
    // Header checksum must verify.
    EXPECT_EQ(net::internet_checksum(std::span<const std::byte>(f.data(), kIpv4MinHeader)), 0);

    net::NetReader r(f);
    EXPECT_EQ(r.u8(), 0x45);
    r.u8();
    EXPECT_EQ(r.u16(), kIpv4MinHeader + payload.size()); // total length
    r.u16();
    EXPECT_EQ(r.u16(), kFlagDontFragment);
    EXPECT_EQ(r.u8(), kDefaultTtl);
    EXPECT_EQ(r.u8(), static_cast<std::uint8_t>(IpProto::Icmp));
    r.u16();                        // checksum
    EXPECT_EQ(r.u32(), our.value);  // src
    EXPECT_EQ(r.u32(), host.value); // dst
}

TEST(Ipv4, SendFailsWhenNextHopUnresolved) {
    const Ipv4Addr our  = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host = Ipv4Addr::parse("10.0.0.1").value();

    CapturingEthSender eth(mac({0x0a, 0, 0, 0, 0, 0x02}));
    eth::Arp arp(eth, our); // empty cache
    Ipv4Layer ipv4(eth, arp, our);

    std::array<std::byte, 1> payload{B(0)};
    EXPECT_FALSE(ipv4.send_ipv4(host, IpProto::Icmp, payload));
    // The failed send should have emitted exactly one ARP request.
    ASSERT_EQ(eth.frames.size(), 1u);
    EXPECT_EQ(eth.frames[0].ethertype, eth::kEtherTypeArp);
}
