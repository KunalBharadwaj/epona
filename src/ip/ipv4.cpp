#include "ip/ipv4.hpp"

#include "eth/ethernet.hpp"
#include "net/buffer.hpp"
#include "net/checksum.hpp"

namespace ip {

void Ipv4Layer::receive(std::span<const std::byte> packet,
                        const eth::MacAddr& src_mac) {
    net::NetReader r(packet);
    std::uint8_t ver_ihl = r.u8();
    if (!r.ok()) return;

    std::uint8_t version = ver_ihl >> 4;
    std::size_t  ihl     = static_cast<std::size_t>(ver_ihl & 0x0F) * 4;
    if (version != kIpv4Version || ihl < kIpv4MinHeader || ihl > packet.size())
        return;

    r.u8();                               // DSCP/ECN (ignored)
    std::uint16_t total_len = r.u16();
    r.u16();                              // identification (ignored on rx)
    r.u16();                              // flags + fragment offset (ignored)
    r.u8();                               // TTL (ignored on rx)
    std::uint8_t  protocol = r.u8();
    r.u16();                              // header checksum (verified below)
    Ipv4Addr      src{r.u32()};
    Ipv4Addr      dst{r.u32()};
    if (!r.ok()) return;

    // Verify the header checksum over exactly the header (ihl bytes). A valid
    // header re-sums to 0.
    if (net::internet_checksum(packet.subspan(0, ihl)) != 0) {
        ++checksum_errors_;
        return;
    }

    // total_len bounds the real payload; Ethernet may have zero-padded a small
    // frame, so trust the IP length, not the frame length.
    if (total_len < ihl || total_len > packet.size()) return;
    std::span<const std::byte> payload = packet.subspan(ihl, total_len - ihl);

    // Learn sender's IP->MAC so replies go straight out without an ARP round trip.
    if (src.value != 0) arp_.cache().insert(src, src_mac);

    // Only accept datagrams addressed to us (or broadcast). Drop the rest.
    if (!(dst == local_ip_)) return;

    Ipv4Datagram dg{src, dst, protocol, payload};
    switch (static_cast<IpProto>(protocol)) {
    case IpProto::Icmp: if (on_icmp_) on_icmp_(dg); break;
    case IpProto::Udp:  if (on_udp_)  on_udp_(dg);  break;
    case IpProto::Tcp:  if (on_tcp_)  on_tcp_(dg);  break;
    default: break; // unsupported protocol
    }
}

bool Ipv4Layer::send_ipv4(Ipv4Addr dst, IpProto proto,
                          std::span<const std::byte> payload) {
    // Resolve the next hop. On-link only for now (no routing/gateway yet).
    auto dst_mac = arp_.resolve(dst);
    if (!dst_mac) return false; // ARP request sent; drop and let the caller retry

    net::PacketBuffer buf;
    net::NetWriter w(buf.capacity_span());

    std::uint16_t total_len =
        static_cast<std::uint16_t>(kIpv4MinHeader + payload.size());

    w.u8(static_cast<std::uint8_t>((kIpv4Version << 4) | (kIpv4MinHeader / 4)));
    w.u8(0);                      // DSCP/ECN
    w.u16(total_len);
    w.u16(next_id_++);            // identification
    w.u16(kFlagDontFragment);     // DF set, fragment offset 0
    w.u8(kDefaultTtl);
    w.u8(static_cast<std::uint8_t>(proto));
    w.u16(0);                     // checksum placeholder, patched below
    w.u32(local_ip_.value);
    w.u32(dst.value);
    w.bytes(payload);
    if (!w.ok()) return false;

    buf.set_size(w.offset());

    // Patch the header checksum (over the 20-byte header only).
    auto frame = buf.bytes();
    std::uint16_t cksum = net::internet_checksum(frame.subspan(0, kIpv4MinHeader));
    frame[10] = std::byte{static_cast<std::uint8_t>(cksum >> 8)};
    frame[11] = std::byte{static_cast<std::uint8_t>(cksum & 0xFF)};

    eth_.send_frame(*dst_mac, eth::kEtherTypeIpv4, frame);
    return true;
}

} // namespace ip
