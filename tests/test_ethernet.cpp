#include "eth/ethernet.hpp"

#include <gtest/gtest.h>

#include <optional>
#include <vector>

#include "net/buffer.hpp"

using namespace eth;

namespace {
std::byte B(unsigned v) { return std::byte{static_cast<unsigned char>(v)}; }
MacAddr mac(std::initializer_list<unsigned> v) {
    MacAddr m; std::size_t i = 0;
    for (unsigned b : v) m.octets[i++] = std::byte{static_cast<unsigned char>(b)};
    return m;
}
}

TEST(Ethernet, DemuxesByEtherType) {
    const MacAddr our  = mac({0x0a, 0, 0, 0, 0, 0x02});
    const MacAddr host = mac({0x0a, 0, 0, 0, 0, 0x01});

    EthernetLayer eth(our, [](std::span<const std::byte>) {});

    std::optional<std::vector<std::byte>> ipv4_payload;
    MacAddr seen_src;
    eth.set_ipv4_handler([&](std::span<const std::byte> p, const MacAddr& src) {
        ipv4_payload = std::vector<std::byte>(p.begin(), p.end());
        seen_src = src;
    });
    bool arp_called = false;
    eth.set_arp_handler([&](std::span<const std::byte>, const MacAddr&) { arp_called = true; });

    // Frame: dst=our, src=host, ethertype=IPv4, payload = {0xAB,0xCD}.
    std::vector<std::byte> frame;
    for (auto b : our.octets)  frame.push_back(b);
    for (auto b : host.octets) frame.push_back(b);
    frame.push_back(B(0x08)); frame.push_back(B(0x00)); // 0x0800
    frame.push_back(B(0xAB)); frame.push_back(B(0xCD));

    eth.receive(frame);

    ASSERT_TRUE(ipv4_payload.has_value());
    EXPECT_FALSE(arp_called);
    EXPECT_EQ(seen_src, host);
    ASSERT_EQ(ipv4_payload->size(), 2u);
    EXPECT_EQ((*ipv4_payload)[0], B(0xAB));
    EXPECT_EQ((*ipv4_payload)[1], B(0xCD));
}

TEST(Ethernet, SendPrependsHeader) {
    const MacAddr our  = mac({0x0a, 0, 0, 0, 0, 0x02});
    const MacAddr dst  = mac({0x0a, 0, 0, 0, 0, 0x01});

    std::vector<std::byte> out;
    EthernetLayer eth(our, [&](std::span<const std::byte> f) {
        out.assign(f.begin(), f.end());
    });

    std::array<std::byte, 2> payload{B(0x11), B(0x22)};
    eth.send_frame(dst, kEtherTypeArp, payload);

    ASSERT_EQ(out.size(), kEthHeaderSize + payload.size());
    net::NetReader r(out);
    EXPECT_EQ(MacAddr::from_bytes(r.bytes(6)), dst);  // dst first
    EXPECT_EQ(MacAddr::from_bytes(r.bytes(6)), our);  // then src
    EXPECT_EQ(r.u16(), kEtherTypeArp);
    EXPECT_EQ(r.u8(), 0x11);
    EXPECT_EQ(r.u8(), 0x22);
}
