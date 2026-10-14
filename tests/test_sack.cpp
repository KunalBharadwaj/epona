#include "tcp/tcp.hpp"

#include <gtest/gtest.h>

#include <vector>

#include "fakes.hpp"
#include "ip/pseudo_header.hpp"
#include "net/buffer.hpp"
#include "tcp/tcp_header.hpp"

using namespace tcp;
using ip::Ipv4Addr;
using ip::IpProto;
using testing_fakes::CapturingIpv4Sender;

namespace {
const Ipv4Addr kOur  = Ipv4Addr::parse("10.0.0.2").value();
const Ipv4Addr kPeer = Ipv4Addr::parse("10.0.0.1").value();
constexpr std::uint16_t kSrv = 7777;
constexpr std::uint16_t kCli = 50000;

std::byte B(unsigned v) { return std::byte{static_cast<unsigned char>(v)}; }

// Build a segment FROM the peer with explicit option bytes (len multiple of 4).
std::vector<std::byte> mk(std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                          const std::vector<std::uint8_t>& opts,
                          std::span<const std::byte> data = {}) {
    std::size_t hlen = kTcpMinHeader + opts.size();
    std::vector<std::byte> s(hlen + data.size());
    net::NetWriter w(s);
    w.u16(kCli); w.u16(kSrv); w.u32(seq); w.u32(ack);
    w.u8(static_cast<std::uint8_t>((hlen / 4) << 4));
    w.u8(flags); w.u16(64240); w.u16(0); w.u16(0);
    for (std::uint8_t b : opts) w.u8(b);
    w.bytes(data);
    std::uint16_t c = ip::transport_checksum(kPeer, kOur, IpProto::Tcp, s);
    s[16] = B(c >> 8); s[17] = B(c & 0xFF);
    return s;
}

ip::Ipv4Datagram dg(std::span<const std::byte> s) {
    return {kPeer, kOur, static_cast<std::uint8_t>(IpProto::Tcp), s};
}

std::vector<std::uint8_t> sack_perm() { return {opt::kSackPermitted, 2, opt::kNop, opt::kNop}; }

TcpHeader last(const CapturingIpv4Sender& ip) {
    return TcpHeader::parse(ip.datagrams.back().payload).value();
}

std::vector<std::byte> bytes(std::size_t n, unsigned fill) {
    return std::vector<std::byte>(n, B(fill));
}
} // namespace

TEST(Sack, HeaderParsesSackPermittedAndBlocks) {
    // A SYN with SACK-permitted.
    auto syn = mk(100, 0, flag::SYN, sack_perm());
    auto h1 = TcpHeader::parse(syn).value();
    EXPECT_TRUE(h1.sack_permitted);
    EXPECT_EQ(h1.sack_count, 0);

    // An ACK carrying one SACK block [2000, 3460).
    std::vector<std::uint8_t> opt = {opt::kNop, opt::kNop, opt::kSack, 10,
                                     0x00, 0x00, 0x07, 0xD0,   // 2000
                                     0x00, 0x00, 0x0D, 0x84};  // 3460
    auto seg = mk(100, 200, flag::ACK, opt);
    auto h2 = TcpHeader::parse(seg).value();
    ASSERT_EQ(h2.sack_count, 1);
    EXPECT_EQ(h2.sack_blocks[0].left, 2000u);
    EXPECT_EQ(h2.sack_blocks[0].right, 3460u);
}

TEST(Sack, SynAckOffersSackOnlyWhenPeerDid) {
    {
        CapturingIpv4Sender ip{kOur}; net::EventLoop loop; Tcp t{ip, loop};
        t.listen(kSrv, [](TcpConnection&) {});
        t.receive(dg(mk(100, 0, flag::SYN, sack_perm())));  // peer offers SACK
        EXPECT_TRUE(last(ip).sack_permitted);               // we offer it back
    }
    {
        CapturingIpv4Sender ip{kOur}; net::EventLoop loop; Tcp t{ip, loop};
        t.listen(kSrv, [](TcpConnection&) {});
        t.receive(dg(mk(100, 0, flag::SYN, {})));            // peer: no SACK
        EXPECT_FALSE(last(ip).sack_permitted);               // we don't either
    }
}

TEST(Sack, ReceiverEmitsSackBlocksForOutOfOrderData) {
    CapturingIpv4Sender ip{kOur}; net::EventLoop loop; Tcp t{ip, loop};
    t.listen(kSrv, [](TcpConnection&) {});
    // Handshake with SACK.
    t.receive(dg(mk(100, 0, flag::SYN, sack_perm())));
    std::uint32_t our = last(ip).seq;
    t.receive(dg(mk(101, our + 1, flag::ACK, {})));

    // Deliver an out-of-order segment (gap at 101): seq 1561, 100 bytes.
    // rcv_nxt is 101; send bytes starting at 1561 -> buffered, SACK should
    // report [1561, 1661).
    t.receive(dg(mk(1561, our + 1, flag::ACK | flag::PSH, {}, bytes(100, 0xAB))));
    auto h = last(ip);
    ASSERT_GE(h.sack_count, 1);
    EXPECT_EQ(h.sack_blocks[0].left, 1561u);
    EXPECT_EQ(h.sack_blocks[0].right, 1661u);
    EXPECT_EQ(h.ack, 101u); // cumulative ack still points at the gap
}

TEST(Sack, SenderRetransmitsOnlyTheHoleNotSackedData) {
    CapturingIpv4Sender ip{kOur}; net::EventLoop loop; Tcp t{ip, loop};
    TcpConnection* conn = nullptr;
    t.listen(kSrv, [&](TcpConnection& c) { conn = &c; });
    t.receive(dg(mk(100, 0, flag::SYN, sack_perm())));
    std::uint32_t our = last(ip).seq;
    t.receive(dg(mk(101, our + 1, flag::ACK, {})));
    ASSERT_NE(conn, nullptr);

    conn->send(bytes(4380, 0xCC));            // 3 segments: data starts at our+1
    std::uint32_t seg0 = our + 1;
    std::uint32_t seg1 = our + 1 + 1460;      // this one we'll say the peer SACKed
    std::uint32_t seg2 = our + 1 + 2920;

    // Peer SACKs the middle segment [seg1, seg1+1460) via three dup ACKs
    // (cumulative ack stays at seg0 = the hole).
    std::vector<std::uint8_t> opt = {opt::kNop, opt::kNop, opt::kSack, 10,
        static_cast<std::uint8_t>(seg1 >> 24), static_cast<std::uint8_t>(seg1 >> 16),
        static_cast<std::uint8_t>(seg1 >> 8),  static_cast<std::uint8_t>(seg1),
        static_cast<std::uint8_t>((seg1 + 1460) >> 24), static_cast<std::uint8_t>((seg1 + 1460) >> 16),
        static_cast<std::uint8_t>((seg1 + 1460) >> 8),  static_cast<std::uint8_t>((seg1 + 1460))};
    for (int i = 0; i < 3; ++i) t.receive(dg(mk(101, seg0, flag::ACK, opt)));

    EXPECT_EQ(conn->fast_retransmits(), 1u);
    // We must retransmit the hole (seg0) and NOT the SACKed middle segment.
    int seg0_rx = 0, seg1_rx = 0;
    for (const auto& d : ip.datagrams) {
        auto h = TcpHeader::parse(d.payload).value();
        if (d.payload.size() <= h.data_offset) continue;      // skip pure ACKs/SYN
        if (h.seq == seg0) ++seg0_rx;
        if (h.seq == seg1) ++seg1_rx;
    }
    EXPECT_EQ(seg0_rx, 2);   // original send + 1 retransmit
    EXPECT_EQ(seg1_rx, 1);   // original send only; never retransmitted (SACKed)
    (void)seg2;
}
