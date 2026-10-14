#pragma once
//
// The downward interface ARP and IPv4 use to hand a payload to the Ethernet
// layer for framing. Keeping it abstract lets those layers be unit-tested with
// a fake sender that just captures frames.
//
#include <cstddef>
#include <cstdint>
#include <span>

#include "eth/mac.hpp"

namespace eth {

struct EthSender {
    virtual ~EthSender() = default;

    // Frame `payload` with the given ethertype to destination `dst` and send it.
    virtual void send_frame(const MacAddr& dst, std::uint16_t ethertype,
                            std::span<const std::byte> payload) = 0;

    // Our own MAC, so upper layers can fill sender-hardware-address fields.
    virtual const MacAddr& local_mac() const = 0;
};

} // namespace eth
