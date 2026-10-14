#include "eth/arp.hpp"

#include "eth/ethernet.hpp"
#include "net/buffer.hpp"

namespace eth {

namespace {
// Serialize an ARP packet into `w`.
void write_arp(net::NetWriter& w, std::uint16_t oper,
               const MacAddr& sha, ip::Ipv4Addr spa,
               const MacAddr& tha, ip::Ipv4Addr tpa) {
    w.u16(kArpHwEthernet);
    w.u16(kArpProtoIpv4);
    w.u8(6);  // hlen
    w.u8(4);  // plen
    w.u16(oper);
    w.bytes(sha.bytes());
    w.u32(spa.value);
    w.bytes(tha.bytes());
    w.u32(tpa.value);
}
} // namespace

void Arp::receive(std::span<const std::byte> payload, const MacAddr& /*src_mac*/) {
    net::NetReader r(payload);
    std::uint16_t htype = r.u16();
    std::uint16_t ptype = r.u16();
    std::uint8_t  hlen  = r.u8();
    std::uint8_t  plen  = r.u8();
    std::uint16_t oper  = r.u16();
    MacAddr       sha   = MacAddr::from_bytes(r.bytes(6));
    ip::Ipv4Addr  spa{r.u32()};
    MacAddr       tha   = MacAddr::from_bytes(r.bytes(6));
    ip::Ipv4Addr  tpa{r.u32()};

    if (!r.ok()) return;
    // We only speak IPv4-over-Ethernet ARP.
    if (htype != kArpHwEthernet || ptype != kArpProtoIpv4 || hlen != 6 || plen != 4)
        return;

    // Learn the sender's mapping regardless of op — cheap and useful.
    if (spa.value != 0) cache_.insert(spa, sha);

    if (oper == kArpOpRequest && tpa == local_ip_) {
        // Someone wants our MAC. Reply directly to them.
        send_reply(sha, spa);
    }
    // oper == reply: the insert above already recorded what we asked for.
    (void)tha;
}

void Arp::send_reply(const MacAddr& to_mac, ip::Ipv4Addr to_ip) {
    std::array<std::byte, kArpPacketSize> pkt{};
    net::NetWriter w(pkt);
    write_arp(w, kArpOpReply,
              eth_.local_mac(), local_ip_, // sender = us
              to_mac, to_ip);              // target = requester
    eth_.send_frame(to_mac, kEtherTypeArp, std::span<const std::byte>(pkt.data(), w.offset()));
}

void Arp::send_request(ip::Ipv4Addr target) {
    std::array<std::byte, kArpPacketSize> pkt{};
    net::NetWriter w(pkt);
    write_arp(w, kArpOpRequest,
              eth_.local_mac(), local_ip_, // sender = us
              MacAddr{}, target);          // target hw addr unknown (zeros)
    eth_.send_frame(MacAddr::broadcast(), kEtherTypeArp,
                    std::span<const std::byte>(pkt.data(), w.offset()));
}

std::optional<MacAddr> Arp::resolve(ip::Ipv4Addr target) {
    if (auto mac = cache_.lookup(target)) return mac;
    send_request(target); // kick off resolution; caller drops this packet
    return std::nullopt;
}

} // namespace eth
