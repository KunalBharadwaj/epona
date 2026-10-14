#pragma once
//
// Ethernet (layer 2): framing + ethertype demux.
//
// Inbound: parse the 14-byte header (dst MAC, src MAC, ethertype) and dispatch
// on the ethertype to ARP (0x0806) or IPv4 (0x0800).
// Outbound: prepend a header and push the full frame to the device.
//
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>

#include "eth/eth_sender.hpp"
#include "eth/mac.hpp"

namespace eth {

inline constexpr std::size_t   kEthHeaderSize = 14;
inline constexpr std::uint16_t kEtherTypeIpv4 = 0x0800;
inline constexpr std::uint16_t kEtherTypeArp  = 0x0806;

// Parsed view of an Ethernet header.
struct EthHeader {
    MacAddr       dst;
    MacAddr       src;
    std::uint16_t ethertype = 0;
};

class EthernetLayer : public EthSender {
public:
    // `frame_out` injects a fully-built frame onto the wire (the device write).
    using FrameOut = std::function<void(std::span<const std::byte>)>;

    EthernetLayer(MacAddr local_mac, FrameOut frame_out)
        : local_mac_(local_mac), frame_out_(std::move(frame_out)) {}

    // Upper-layer dispatch hooks, wired by the Stack. Each receives the payload
    // (header stripped) and the frame's source MAC.
    using Handler = std::function<void(std::span<const std::byte>, const MacAddr& src)>;
    void set_arp_handler(Handler h)  { on_arp_  = std::move(h); }
    void set_ipv4_handler(Handler h) { on_ipv4_ = std::move(h); }

    // Parse one inbound frame and dispatch it.
    void receive(std::span<const std::byte> frame);

    // EthSender interface (used by ARP / IPv4 to send down).
    void send_frame(const MacAddr& dst, std::uint16_t ethertype,
                    std::span<const std::byte> payload) override;
    const MacAddr& local_mac() const override { return local_mac_; }

private:
    MacAddr  local_mac_;
    FrameOut frame_out_;
    Handler  on_arp_;
    Handler  on_ipv4_;
};

} // namespace eth
