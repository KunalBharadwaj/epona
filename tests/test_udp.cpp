#include "udp/udp.hpp"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include "app/udp_echo.hpp"
#include "fakes.hpp"
#include "ip/pseudo_header.hpp"
#include "net/buffer.hpp"

using namespace udp;
using ip::Ipv4Addr;
using ip::IpProto;
using testing_fakes::CapturingIpv4Sender;

namespace {
std::byte B(unsigned v) { return std::byte{static_cast<unsigned char>(v)}; }

std::vector<std::byte> str_bytes(std::string_view s) {
    std::vector<std::byte> v;
    for (char c : s) v.push_back(std::byte{static_cast<unsigned char>(c)});
    return v;
}

// Build a UDP segment (header + data) with a valid checksum.
std::vector<std::byte> build_udp(Ipv4Addr src, Ipv4Addr dst, std::uint16_t sport,
                                 std::uint16_t dport, std::span<const std::byte> data) {
    std::vector<std::byte> seg(kUdpHeaderSize + data.size());
    net::NetWriter w(seg);
    w.u16(sport);
    w.u16(dport);
    w.u16(static_cast<std::uint16_t>(seg.size()));
    w.u16(0);
    w.bytes(data);
    std::uint16_t c = ip::transport_checksum(src, dst, IpProto::Udp, seg);
    if (c == 0) c = 0xFFFF;
    seg[6] = B(c >> 8);
    seg[7] = B(c & 0xFF);
    return seg;
}
} // namespace

TEST(Udp, DeliversToBoundPort) {
    const Ipv4Addr our  = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host = Ipv4Addr::parse("10.0.0.1").value();

    CapturingIpv4Sender ip(our);
    Udp udp(ip);

    std::optional<std::string> got;
    std::uint16_t got_sport = 0;
    udp.bind(7777, [&](Ipv4Addr, std::uint16_t sport, std::span<const std::byte> d) {
        got = std::string(reinterpret_cast<const char*>(d.data()), d.size());
        got_sport = sport;
    });

    auto data = str_bytes("hello");
    auto seg  = build_udp(host, our, 40000, 7777, data);
    ip::Ipv4Datagram dg{host, our, static_cast<std::uint8_t>(IpProto::Udp), seg};
    udp.receive(dg);

    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, "hello");
    EXPECT_EQ(got_sport, 40000);
    EXPECT_EQ(udp.datagrams_received(), 1u);
}

TEST(Udp, IgnoresUnboundPortAndBadChecksum) {
    const Ipv4Addr our  = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host = Ipv4Addr::parse("10.0.0.1").value();

    CapturingIpv4Sender ip(our);
    Udp udp(ip);
    bool called = false;
    udp.bind(7777, [&](Ipv4Addr, std::uint16_t, std::span<const std::byte>) { called = true; });

    // Right port, corrupted checksum -> dropped.
    auto data = str_bytes("x");
    auto seg  = build_udp(host, our, 1, 7777, data);
    seg[7] = B(std::to_integer<unsigned>(seg[7]) ^ 0xFF);
    udp.receive({host, our, static_cast<std::uint8_t>(IpProto::Udp), seg});
    EXPECT_FALSE(called);
    EXPECT_EQ(udp.checksum_errors(), 1u);

    // Valid, but nobody bound to port 9999.
    auto seg2 = build_udp(host, our, 1, 9999, data);
    udp.receive({host, our, static_cast<std::uint8_t>(IpProto::Udp), seg2});
    EXPECT_FALSE(called);
}

TEST(Udp, SendBuildsVerifiableSegment) {
    const Ipv4Addr our  = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host = Ipv4Addr::parse("10.0.0.1").value();

    CapturingIpv4Sender ip(our);
    Udp udp(ip);

    auto data = str_bytes("pong");
    ASSERT_TRUE(udp.send(7777, host, 40000, data));

    ASSERT_EQ(ip.datagrams.size(), 1u);
    EXPECT_EQ(ip.datagrams[0].dst, host);
    EXPECT_EQ(ip.datagrams[0].proto, IpProto::Udp);

    const auto& seg = ip.datagrams[0].payload;
    // Receiver-side verification: pseudo-header checksum over our own output
    // (src/dst swapped to the receiver's perspective) must validate to 0.
    EXPECT_EQ(ip::transport_checksum(our, host, IpProto::Udp, seg), 0);

    net::NetReader r(seg);
    EXPECT_EQ(r.u16(), 7777);   // src port
    EXPECT_EQ(r.u16(), 40000);  // dst port
    EXPECT_EQ(r.u16(), kUdpHeaderSize + data.size());
}

TEST(Udp, EchoAppBouncesDataBack) {
    const Ipv4Addr our  = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host = Ipv4Addr::parse("10.0.0.1").value();

    CapturingIpv4Sender ip(our);
    Udp udp(ip);
    app::UdpEcho echo(udp, 7777);

    auto data = str_bytes("roundtrip");
    auto seg  = build_udp(host, our, 55555, 7777, data);
    udp.receive({host, our, static_cast<std::uint8_t>(IpProto::Udp), seg});

    ASSERT_EQ(ip.datagrams.size(), 1u);
    EXPECT_EQ(ip.datagrams[0].dst, host); // echoed back to sender
    EXPECT_EQ(echo.echoed(), 1u);

    // The echoed payload matches, and reply ports are swapped (7777 -> 55555).
    net::NetReader r(ip.datagrams[0].payload);
    EXPECT_EQ(r.u16(), 7777);   // src = our echo port
    EXPECT_EQ(r.u16(), 55555);  // dst = original sender port
    r.u16(); r.u16();           // length, checksum
    std::string payload(reinterpret_cast<const char*>(r.rest().data()), r.rest().size());
    EXPECT_EQ(payload, "roundtrip");
}
