#pragma once
//
// A trivial UDP echo service: whatever lands on the bound port is sent straight
// back to the sender. This is the Milestone 2 "done when" demo — `nc -u` a line
// and get the same line back.
//
#include <cstdint>
#include <span>

#include "udp/udp.hpp"

namespace app {

class UdpEcho {
public:
    UdpEcho(udp::Udp& udp, std::uint16_t port) : udp_(udp), port_(port) {
        udp_.bind(port_, [this](ip::Ipv4Addr src, std::uint16_t src_port,
                                std::span<const std::byte> data) {
            // Reply from the port they contacted, back to where it came from.
            udp_.send(port_, src, src_port, data);
            ++echoed_;
        });
    }

    std::uint16_t port()   const noexcept { return port_; }
    std::uint64_t echoed() const noexcept { return echoed_; }

private:
    udp::Udp&     udp_;
    std::uint16_t port_;
    std::uint64_t echoed_ = 0;
};

} // namespace app
