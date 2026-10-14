#include "ip/icmp.hpp"

#include <gtest/gtest.h>

#include <vector>

#include "fakes.hpp"
#include "net/buffer.hpp"
#include "net/checksum.hpp"

using namespace ip;
using testing_fakes::CapturingIpv4Sender;

namespace {
std::byte B(unsigned v) { return std::byte{static_cast<unsigned char>(v)}; }

// Build an ICMP echo request with a valid checksum.
std::vector<std::byte> echo_request(std::uint16_t id, std::uint16_t seq,
                                    std::span<const std::byte> data) {
    std::vector<std::byte> msg(8 + data.size());
    net::NetWriter w(msg);
    w.u8(kIcmpEchoRequest);
    w.u8(0);
    w.u16(0); // checksum placeholder
    w.u16(id);
    w.u16(seq);
    w.bytes(data);
    std::uint16_t c = net::internet_checksum(msg);
    msg[2] = B(c >> 8);
    msg[3] = B(c & 0xFF);
    return msg;
}
} // namespace

TEST(Icmp, EchoRequestProducesEchoReply) {
    const Ipv4Addr our  = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host = Ipv4Addr::parse("10.0.0.1").value();

    CapturingIpv4Sender ip(our);
    Icmp icmp(ip);

    std::array<std::byte, 4> data{B('p'), B('i'), B('n'), B('g')};
    auto req = echo_request(0x1234, 0x0007, data);

    Ipv4Datagram dg{host, our, static_cast<std::uint8_t>(IpProto::Icmp), req};
    icmp.receive(dg);

    ASSERT_EQ(ip.datagrams.size(), 1u);
    EXPECT_EQ(ip.datagrams[0].dst, host);              // reply goes back to sender
    EXPECT_EQ(ip.datagrams[0].proto, IpProto::Icmp);

    const auto& reply = ip.datagrams[0].payload;
    ASSERT_EQ(reply.size(), req.size());
    EXPECT_EQ(reply[0], B(kIcmpEchoReply));            // type flipped to 0
    EXPECT_EQ(reply[1], B(0));                         // code
    EXPECT_EQ(net::internet_checksum(reply), 0);       // checksum valid

    // Identifier, sequence and payload echoed unchanged.
    net::NetReader r(reply);
    r.u8(); r.u8(); r.u16();        // type, code, checksum
    EXPECT_EQ(r.u16(), 0x1234);     // id
    EXPECT_EQ(r.u16(), 0x0007);     // seq
    EXPECT_EQ(r.u8(), static_cast<std::uint8_t>('p'));
    EXPECT_EQ(r.u8(), static_cast<std::uint8_t>('i'));
    EXPECT_EQ(icmp.echo_replies_sent(), 1u);
}

TEST(Icmp, IgnoresNonEchoAndBadChecksum) {
    const Ipv4Addr our  = Ipv4Addr::parse("10.0.0.2").value();
    const Ipv4Addr host = Ipv4Addr::parse("10.0.0.1").value();

    CapturingIpv4Sender ip(our);
    Icmp icmp(ip);

    // Corrupt checksum -> dropped.
    std::array<std::byte, 0> none{};
    auto req = echo_request(1, 1, none);
    req[3] = B(static_cast<unsigned>(std::to_integer<unsigned>(req[3]) ^ 0xFF));
    Ipv4Datagram dg{host, our, static_cast<std::uint8_t>(IpProto::Icmp), req};
    icmp.receive(dg);

    EXPECT_TRUE(ip.datagrams.empty());
    EXPECT_EQ(icmp.checksum_errors(), 1u);
}
