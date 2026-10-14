#include "tcp/tcp.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "app/tcp_echo.hpp"
#include "fakes.hpp"
#include "ip/pseudo_header.hpp"
#include "net/buffer.hpp"
#include "net/event_loop.hpp"
#include "tcp/seq.hpp"
#include "tcp/tcp_header.hpp"

using namespace tcp;
using ip::Ipv4Addr;
using ip::IpProto;
using testing_fakes::CapturingIpv4Sender;

namespace {

const Ipv4Addr kOur    = Ipv4Addr::parse("10.0.0.2").value();
const Ipv4Addr kPeer   = Ipv4Addr::parse("10.0.0.1").value();
constexpr std::uint16_t kSrvPort = 7777;
constexpr std::uint16_t kCliPort = 50000;

std::byte B(unsigned v) { return std::byte{static_cast<unsigned char>(v)}; }

std::vector<std::byte> sbytes(std::string_view s) {
    std::vector<std::byte> v;
    for (char c : s) v.push_back(std::byte{static_cast<unsigned char>(c)});
    return v;
}

// Build a TCP segment as seen coming FROM the peer TO us, with a valid checksum.
std::vector<std::byte> seg(std::uint16_t sport, std::uint16_t dport,
                           std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                           std::span<const std::byte> data = {},
                           std::uint16_t window = 64240) {
    std::vector<std::byte> s(kTcpMinHeader + data.size());
    net::NetWriter w(s);
    w.u16(sport); w.u16(dport); w.u32(seq); w.u32(ack);
    w.u8(static_cast<std::uint8_t>((kTcpMinHeader / 4) << 4));
    w.u8(flags); w.u16(window); w.u16(0); w.u16(0);
    w.bytes(data);
    std::uint16_t c = ip::transport_checksum(kPeer, kOur, IpProto::Tcp, s);
    s[16] = B(c >> 8); s[17] = B(c & 0xFF);
    return s;
}

// Total application-data bytes across all captured segments.
std::size_t total_data_sent(const CapturingIpv4Sender& ip) {
    std::size_t n = 0;
    for (const auto& d : ip.datagrams) {
        auto h = TcpHeader::parse(d.payload).value();
        n += d.payload.size() - h.data_offset;
    }
    return n;
}

// How many captured data segments start at sequence `seq` (detects retransmits).
int count_segments_at(const CapturingIpv4Sender& ip, std::uint32_t seq) {
    int n = 0;
    for (const auto& d : ip.datagrams) {
        auto h = TcpHeader::parse(d.payload).value();
        if (h.seq == seq && d.payload.size() > h.data_offset) ++n;
    }
    return n;
}

std::vector<std::byte> big(std::size_t n) {
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = std::byte{static_cast<unsigned char>(i & 0xFF)};
    return v;
}

ip::Ipv4Datagram dg(std::span<const std::byte> s) {
    return {kPeer, kOur, static_cast<std::uint8_t>(IpProto::Tcp), s};
}

// Parse the Nth-from-last captured segment (0 = last).
TcpHeader hdr_from_back(const CapturingIpv4Sender& ip, std::size_t back = 0) {
    const auto& p = ip.datagrams[ip.datagrams.size() - 1 - back].payload;
    return TcpHeader::parse(p).value();
}
} // namespace

// --- a fixture that drives a passive-open echo connection to ESTABLISHED ---
class TcpEstablished : public ::testing::Test {
protected:
    CapturingIpv4Sender ip{kOur};
    net::EventLoop      loop;
    Tcp                 t{ip, loop, std::chrono::milliseconds(20)};
    TcpConnection*      conn = nullptr;
    std::uint32_t       our_isn = 0;  // our stack's ISS
    std::uint32_t       cli_isn = 1000;

    void handshake() {
        // Capture the connection and wire echo semantics (as TcpEcho does).
        t.listen(kSrvPort, [&](TcpConnection& c) {
            conn = &c;
            c.on_data  = [](TcpConnection& cc, std::span<const std::byte> d) { cc.send(d); };
            c.on_close = [](TcpConnection& cc) { cc.close(); };
        });
        // Client SYN.
        t.receive(dg(seg(kCliPort, kSrvPort, cli_isn, 0, flag::SYN)));
        auto synack = hdr_from_back(ip);
        ASSERT_TRUE(synack.has(flag::SYN) && synack.has(flag::ACK));
        ASSERT_EQ(synack.ack, cli_isn + 1);
        our_isn = synack.seq;
        // Client ACK completes the handshake.
        t.receive(dg(seg(kCliPort, kSrvPort, cli_isn + 1, our_isn + 1, flag::ACK)));
        ASSERT_NE(conn, nullptr);
        ASSERT_EQ(conn->state(), State::Established);
    }
};

TEST_F(TcpEstablished, ThreeWayHandshake) {
    handshake();
    EXPECT_EQ(t.accepted(), 1u);
    EXPECT_EQ(t.connection_count(), 1u);
}

TEST_F(TcpEstablished, EchoesData) {
    handshake();
    auto payload = sbytes("hello tcp");
    t.receive(dg(seg(kCliPort, kSrvPort, cli_isn + 1, our_isn + 1,
                     flag::ACK | flag::PSH, payload)));

    // Somewhere in the responses our stack echoed the bytes back.
    bool found = false;
    for (const auto& d : ip.datagrams) {
        auto h = TcpHeader::parse(d.payload).value();
        auto body = std::span<const std::byte>(d.payload).subspan(h.data_offset);
        if (body.size() == payload.size() &&
            std::equal(body.begin(), body.end(), payload.begin())) {
            found = true;
            EXPECT_EQ(h.ack, cli_isn + 1 + payload.size()); // acks the received data
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(TcpEstablished, PassiveClose) {
    handshake();
    // Peer closes first: send FIN. Echo app responds by closing too.
    t.receive(dg(seg(kCliPort, kSrvPort, cli_isn + 1, our_isn + 1, flag::FIN | flag::ACK)));

    // We should have sent our own FIN and be in LAST-ACK.
    ASSERT_EQ(conn->state(), State::LastAck);
    bool sent_fin = false;
    for (const auto& d : ip.datagrams)
        if (TcpHeader::parse(d.payload)->has(flag::FIN)) sent_fin = true;
    EXPECT_TRUE(sent_fin);

    // Peer acks our FIN -> connection is removed.
    std::uint32_t our_fin_seq = conn->snd_nxt();
    t.receive(dg(seg(kCliPort, kSrvPort, cli_isn + 2, our_fin_seq, flag::ACK)));
    EXPECT_EQ(t.connection_count(), 0u);
}

TEST_F(TcpEstablished, ActiveCloseGoesThroughTimeWait) {
    handshake();
    // We initiate the close.
    conn->close();
    EXPECT_EQ(conn->state(), State::FinWait1);
    std::uint32_t our_fin_seq = conn->snd_nxt() - 1;

    // Peer acks our FIN.
    t.receive(dg(seg(kCliPort, kSrvPort, cli_isn + 1, our_fin_seq + 1, flag::ACK)));
    EXPECT_EQ(conn->state(), State::FinWait2);

    // Peer sends its FIN -> we ack and enter TIME-WAIT.
    t.receive(dg(seg(kCliPort, kSrvPort, cli_isn + 1, our_fin_seq + 1, flag::FIN | flag::ACK)));
    EXPECT_EQ(conn->state(), State::TimeWait);
    EXPECT_EQ(t.connection_count(), 1u);

    // Run the loop long enough for the 20ms TIME-WAIT timer to free the TCB.
    loop.add_timer(std::chrono::milliseconds(60), [&] { loop.stop(); });
    loop.run();
    EXPECT_EQ(t.connection_count(), 0u);
}

// --- behaviours that don't need the fixture ---

TEST(Tcp, RstForSegmentToUnknownConnection) {
    CapturingIpv4Sender ip{kOur};
    net::EventLoop loop;
    Tcp t{ip, loop};

    // A stray ACK with no matching connection and no listener.
    t.receive(dg(seg(kCliPort, 9999, 500, 500, flag::ACK)));
    ASSERT_EQ(ip.datagrams.size(), 1u);
    auto h = TcpHeader::parse(ip.datagrams[0].payload).value();
    EXPECT_TRUE(h.has(flag::RST));
    EXPECT_EQ(h.seq, 500u); // mirrors their ack
}

TEST(Tcp, SynToClosedPortIsReset) {
    CapturingIpv4Sender ip{kOur};
    net::EventLoop loop;
    Tcp t{ip, loop};
    t.listen(kSrvPort, [](TcpConnection&) {});

    // SYN to a different, unlistened port.
    t.receive(dg(seg(kCliPort, 1234, 42, 0, flag::SYN)));
    ASSERT_EQ(ip.datagrams.size(), 1u);
    auto h = TcpHeader::parse(ip.datagrams[0].payload).value();
    EXPECT_TRUE(h.has(flag::RST));
    EXPECT_TRUE(h.has(flag::ACK));
    EXPECT_EQ(h.ack, 43u); // seq + 1 (SYN consumes a sequence number)
}

TEST(Tcp, ActiveOpenHandshake) {
    CapturingIpv4Sender ip{kOur};
    net::EventLoop loop;
    Tcp t{ip, loop};

    bool opened = false;
    TcpConnection* c = t.connect(kPeer, kSrvPort, kCliPort);
    ASSERT_NE(c, nullptr);
    c->on_open = [&](TcpConnection&) { opened = true; };

    // Our SYN went out (no ACK yet).
    ASSERT_EQ(ip.datagrams.size(), 1u);
    auto syn = TcpHeader::parse(ip.datagrams[0].payload).value();
    ASSERT_TRUE(syn.has(flag::SYN));
    EXPECT_FALSE(syn.has(flag::ACK));
    std::uint32_t our_isn = syn.seq;

    // Peer replies SYN-ACK.
    std::uint32_t peer_isn = 7000;
    t.receive(dg(seg(kSrvPort, kCliPort, peer_isn, our_isn + 1, flag::SYN | flag::ACK)));

    EXPECT_EQ(c->state(), State::Established);
    EXPECT_TRUE(opened);
    // And we acked their SYN.
    auto ack = TcpHeader::parse(ip.datagrams.back().payload).value();
    EXPECT_TRUE(ack.has(flag::ACK));
    EXPECT_EQ(ack.ack, peer_isn + 1);
}

TEST(Tcp, ChecksumErrorIsDropped) {
    CapturingIpv4Sender ip{kOur};
    net::EventLoop loop;
    Tcp t{ip, loop};
    t.listen(kSrvPort, [](TcpConnection&) {});

    auto s = seg(kCliPort, kSrvPort, 1, 0, flag::SYN);
    s[17] = B(std::to_integer<unsigned>(s[17]) ^ 0xFF); // corrupt checksum
    t.receive(dg(s));
    EXPECT_TRUE(ip.datagrams.empty());
    EXPECT_EQ(t.checksum_errors(), 1u);
}

// ===========================================================================
// Milestone 4: reliability & performance
// ===========================================================================
namespace {
constexpr std::size_t kMssT = 1460;

// Drive a passive open to ESTABLISHED (listener already set). Returns our ISN.
std::uint32_t do_handshake(Tcp& t, CapturingIpv4Sender& ip,
                           std::uint32_t cli, std::uint16_t win) {
    t.receive(dg(seg(kCliPort, kSrvPort, cli, 0, flag::SYN, {}, win)));
    auto sa = TcpHeader::parse(ip.datagrams.back().payload).value();
    std::uint32_t our = sa.seq;
    t.receive(dg(seg(kCliPort, kSrvPort, cli + 1, our + 1, flag::ACK, {}, win)));
    return our;
}
} // namespace

TEST(TcpReno, FlowControlLimitsToPeerWindow) {
    CapturingIpv4Sender ip{kOur}; net::EventLoop loop; Tcp t{ip, loop};
    TcpConnection* conn = nullptr;
    t.listen(kSrvPort, [&](TcpConnection& c) { conn = &c; });
    do_handshake(t, ip, 1000, /*win=*/2000);
    ASSERT_NE(conn, nullptr);

    conn->send(big(5000));
    // Must never send past the peer's advertised 2000-byte window.
    EXPECT_LE(total_data_sent(ip), 2000u);
    EXPECT_GT(total_data_sent(ip), 0u);
}

TEST(TcpReno, InitialCwndLimitsBurstThenGrows) {
    CapturingIpv4Sender ip{kOur}; net::EventLoop loop; Tcp t{ip, loop};
    TcpConnection* conn = nullptr;
    t.listen(kSrvPort, [&](TcpConnection& c) { conn = &c; });
    std::uint32_t our = do_handshake(t, ip, 1000, 64240);

    conn->send(big(40000));
    // Initial congestion window is IW10 (10*MSS), so that's the first burst.
    EXPECT_EQ(total_data_sent(ip), 10u * kMssT);

    // Ack the first segment; slow start opens cwnd and more goes out.
    t.receive(dg(seg(kCliPort, kSrvPort, 1001,
                     our + 1 + static_cast<std::uint32_t>(kMssT), flag::ACK, {}, 64240)));
    EXPECT_GT(total_data_sent(ip), 10u * kMssT);
    EXPECT_GT(conn->cwnd(), 10u * kMssT);
}

TEST(TcpReno, FastRetransmitOnThreeDupAcks) {
    CapturingIpv4Sender ip{kOur}; net::EventLoop loop; Tcp t{ip, loop};
    TcpConnection* conn = nullptr;
    t.listen(kSrvPort, [&](TcpConnection& c) { conn = &c; });
    std::uint32_t our = do_handshake(t, ip, 1000, 64240);

    conn->send(big(20000));
    std::uint32_t first = our + 1;
    ASSERT_EQ(count_segments_at(ip, first), 1);

    // Three duplicate ACKs (acking snd_una, no data) trigger fast retransmit.
    for (int i = 0; i < 3; ++i)
        t.receive(dg(seg(kCliPort, kSrvPort, 1001, our + 1, flag::ACK, {}, 64240)));

    EXPECT_EQ(conn->fast_retransmits(), 1u);
    EXPECT_EQ(count_segments_at(ip, first), 2);     // original + retransmit
    EXPECT_LT(conn->ssthresh(), 64u * 1024u);        // halved on loss
}

TEST(TcpReno, RetransmitsOnRtoTimeout) {
    CapturingIpv4Sender ip{kOur}; net::EventLoop loop; Tcp t{ip, loop};
    TcpConnection* conn = nullptr;
    t.listen(kSrvPort, [&](TcpConnection& c) { conn = &c; });
    std::uint32_t our = do_handshake(t, ip, 1000, 64240);

    conn->send(big(kMssT));
    std::uint32_t first = our + 1;
    ASSERT_EQ(count_segments_at(ip, first), 1);

    // No ACK ever arrives; the ~1s initial RTO should fire a retransmit.
    loop.add_timer(std::chrono::milliseconds(1300), [&] { loop.stop(); });
    loop.run();

    EXPECT_GE(conn->retransmits(), 1u);
    EXPECT_EQ(count_segments_at(ip, first), 2);
    EXPECT_EQ(conn->cwnd(), static_cast<std::uint32_t>(kMssT)); // collapsed to 1 MSS
}

TEST(TcpReno, ReassemblesOutOfOrderData) {
    CapturingIpv4Sender ip{kOur}; net::EventLoop loop; Tcp t{ip, loop};
    std::string got;
    t.listen(kSrvPort, [&](TcpConnection& c) {
        c.on_data = [&](TcpConnection&, std::span<const std::byte> d) {
            got.append(reinterpret_cast<const char*>(d.data()), d.size());
        };
    });
    std::uint32_t our = do_handshake(t, ip, 1000, 64240);

    auto a = sbytes("hello");  // seq 1001..1005
    auto b = sbytes("world");  // seq 1006..1010

    // Deliver the second chunk first: it must be buffered, not delivered.
    t.receive(dg(seg(kCliPort, kSrvPort, 1006, our + 1, flag::ACK | flag::PSH, b, 64240)));
    EXPECT_EQ(got, "");

    // Now the gap filler arrives: both chunks come out in order.
    t.receive(dg(seg(kCliPort, kSrvPort, 1001, our + 1, flag::ACK | flag::PSH, a, 64240)));
    EXPECT_EQ(got, "helloworld");
}
