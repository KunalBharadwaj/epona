#include "tcp/tcp.hpp"

#include <array>

#include "ip/pseudo_header.hpp"
#include "net/buffer.hpp"
#include "tcp/tcp_trace.hpp"

namespace tcp {

void Tcp::listen(std::uint16_t port, AcceptCallback on_accept) {
    listeners_[port] = std::move(on_accept);
}

TcpConnection* Tcp::connect(ip::Ipv4Addr dst_ip, std::uint16_t dst_port,
                            std::uint16_t src_port) {
    FourTuple tuple{ip_.local_ip(), dst_ip, src_port, dst_port};
    if (conns_.count(tuple)) return nullptr;
    auto conn = std::make_unique<TcpConnection>(*this, tuple);
    TcpConnection* raw = conn.get();
    conns_.emplace(tuple, std::move(conn));
    raw->active_open();
    return raw;
}

void Tcp::notify_accept(TcpConnection& c) {
    ++accepted_;
    auto it = listeners_.find(c.tuple().local_port);
    if (it != listeners_.end() && it->second) it->second(c);
}

void Tcp::receive(const ip::Ipv4Datagram& dg) {
    auto parsed = TcpHeader::parse(dg.payload);
    if (!parsed) return;
    const TcpHeader& h = *parsed;

    // Verify the checksum over the pseudo-header + whole segment.
    if (ip::transport_checksum(dg.src, dg.dst, ip::IpProto::Tcp, dg.payload) != 0) {
        ++checksum_errors_;
        return;
    }

    FourTuple tuple{dg.dst, dg.src, h.dst_port, h.src_port};
    std::span<const std::byte> data = dg.payload.subspan(h.data_offset);
    trace_seg("IN ", h.src_port, h.dst_port, h.seq, h.ack, h.flags, data.size());

    auto it = conns_.find(tuple);
    if (it != conns_.end()) {
        it->second->on_segment(h, data);
        if (it->second->finished()) conns_.erase(it);
        return;
    }

    // No connection. A SYN to a listening port opens one passively.
    if (h.has(flag::SYN) && !h.has(flag::ACK) && listeners_.count(h.dst_port)) {
        auto conn = std::make_unique<TcpConnection>(*this, tuple);
        TcpConnection* raw = conn.get();
        conns_.emplace(tuple, std::move(conn));
        raw->passive_open(h);
        return;
    }

    // Anything else that isn't itself a reset gets a RST so the peer gives up.
    if (!h.has(flag::RST)) send_rst_for(dg, h);
}

void Tcp::send_rst_for(const ip::Ipv4Datagram& dg, const TcpHeader& h) {
    std::span<const std::byte> data = dg.payload.subspan(h.data_offset);
    std::uint32_t seg_len = static_cast<std::uint32_t>(data.size()) +
                            (h.has(flag::SYN) ? 1u : 0u) +
                            (h.has(flag::FIN) ? 1u : 0u);

    std::uint32_t seq, ack;
    std::uint8_t  flags;
    if (h.has(flag::ACK)) {
        // Mirror their ack as our seq; no ack needed (RFC 793 §3.4).
        seq = h.ack; ack = 0; flags = flag::RST;
    } else {
        seq = 0; ack = h.seq + seg_len; flags = flag::RST | flag::ACK;
    }

    std::array<std::byte, kTcpMinHeader> seg{};
    net::NetWriter w(seg);
    w.u16(h.dst_port); // our port
    w.u16(h.src_port); // their port
    w.u32(seq);
    w.u32(ack);
    w.u8(static_cast<std::uint8_t>((kTcpMinHeader / 4) << 4));
    w.u8(flags);
    w.u16(0); // window
    w.u16(0); // checksum placeholder
    w.u16(0); // urgent

    std::uint16_t cksum = ip::transport_checksum(dg.dst, dg.src, ip::IpProto::Tcp, seg);
    seg[16] = std::byte{static_cast<std::uint8_t>(cksum >> 8)};
    seg[17] = std::byte{static_cast<std::uint8_t>(cksum & 0xFF)};

    ip_.send_ipv4(dg.src, ip::IpProto::Tcp, seg);
}

} // namespace tcp
