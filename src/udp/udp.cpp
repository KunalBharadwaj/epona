#include "udp/udp.hpp"

#include "ip/pseudo_header.hpp"
#include "net/buffer.hpp"

namespace udp {

void Udp::receive(const ip::Ipv4Datagram& dg) {
    std::span<const std::byte> seg = dg.payload;
    if (seg.size() < kUdpHeaderSize) return;

    net::NetReader r(seg);
    std::uint16_t src_port = r.u16();
    std::uint16_t dst_port = r.u16();
    std::uint16_t length   = r.u16();
    std::uint16_t checksum = r.u16();
    if (!r.ok()) return;

    // `length` covers header+data and must fit within the datagram.
    if (length < kUdpHeaderSize || length > seg.size()) return;
    std::span<const std::byte> udp_segment = seg.subspan(0, length);

    // Checksum is optional in IPv4 UDP: 0 means "not computed". When present,
    // verify it over the pseudo-header + segment (valid -> 0).
    if (checksum != 0) {
        if (ip::transport_checksum(dg.src, dg.dst, ip::IpProto::Udp, udp_segment) != 0) {
            ++checksum_errors_;
            return;
        }
    }

    ++datagrams_rx_;

    auto it = bindings_.find(dst_port);
    if (it == bindings_.end()) return; // nothing listening (a real stack sends ICMP port-unreachable)

    std::span<const std::byte> data = udp_segment.subspan(kUdpHeaderSize);
    it->second(dg.src, src_port, data);
}

bool Udp::send(std::uint16_t src_port, ip::Ipv4Addr dst_ip,
               std::uint16_t dst_port, std::span<const std::byte> data) {
    net::PacketBuffer buf;
    net::NetWriter w(buf.capacity_span());

    std::uint16_t length = static_cast<std::uint16_t>(kUdpHeaderSize + data.size());
    w.u16(src_port);
    w.u16(dst_port);
    w.u16(length);
    w.u16(0); // checksum placeholder
    w.bytes(data);
    if (!w.ok()) return false;

    buf.set_size(w.offset());
    auto seg = buf.bytes();

    std::uint16_t cksum =
        ip::transport_checksum(ip_.local_ip(), dst_ip, ip::IpProto::Udp, seg);
    // RFC 768: a computed checksum of 0 is transmitted as all-ones so it isn't
    // mistaken for "no checksum".
    if (cksum == 0) cksum = 0xFFFF;
    seg[6] = std::byte{static_cast<std::uint8_t>(cksum >> 8)};
    seg[7] = std::byte{static_cast<std::uint8_t>(cksum & 0xFF)};

    return ip_.send_ipv4(dst_ip, ip::IpProto::Udp, seg);
}

} // namespace udp
