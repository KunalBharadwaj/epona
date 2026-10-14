#include "eth/ethernet.hpp"

#include <array>

#include "net/buffer.hpp"

namespace eth {

void EthernetLayer::receive(std::span<const std::byte> frame) {
    net::NetReader r(frame);
    EthHeader h;
    h.dst       = MacAddr::from_bytes(r.bytes(6));
    h.src       = MacAddr::from_bytes(r.bytes(6));
    h.ethertype = r.u16();
    if (!r.ok()) return; // runt frame, drop

    // A real NIC filters by destination MAC; a TAP already hands us only frames
    // for our interface (plus broadcast/multicast), so we accept and demux.
    std::span<const std::byte> payload = r.rest();

    switch (h.ethertype) {
    case kEtherTypeArp:
        if (on_arp_) on_arp_(payload, h.src);
        break;
    case kEtherTypeIpv4:
        if (on_ipv4_) on_ipv4_(payload, h.src);
        break;
    default:
        break; // unknown ethertype (e.g. IPv6 0x86DD) — ignore
    }
}

void EthernetLayer::send_frame(const MacAddr& dst, std::uint16_t ethertype,
                               std::span<const std::byte> payload) {
    net::PacketBuffer buf;
    net::NetWriter w(buf.capacity_span());
    w.bytes(dst.bytes());
    w.bytes(local_mac_.bytes());
    w.u16(ethertype);
    w.bytes(payload);
    if (!w.ok()) return; // oversized frame, drop

    buf.set_size(w.offset());
    if (frame_out_) frame_out_(buf.bytes());
}

} // namespace eth
