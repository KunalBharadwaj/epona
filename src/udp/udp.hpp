#pragma once
//
// UDP (RFC 768): an 8-byte header and a port demux. Deliberately built before
// TCP because it exercises the transport checksum (over the pseudo-header) and
// port-based delivery with no state machine in the way — so when TCP misbehaves
// later, these pieces are already trusted.
//
//   src port (2) | dst port (2) | length (2) | checksum (2) | payload...
//
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <unordered_map>

#include "ip/ipv4.hpp"
#include "ip/ipv4_address.hpp"
#include "ip/ipv4_sender.hpp"

namespace udp {

inline constexpr std::size_t kUdpHeaderSize = 8;

// Called when a datagram arrives on a bound port. `data` is the payload only.
using Handler = std::function<void(ip::Ipv4Addr src_ip, std::uint16_t src_port,
                                   std::span<const std::byte> data)>;

class Udp {
public:
    explicit Udp(ip::Ipv4Sender& ip) : ip_(ip) {}

    // Register a receiver for `port`. Replaces any previous binding.
    void bind(std::uint16_t port, Handler h) { bindings_[port] = std::move(h); }
    void unbind(std::uint16_t port)          { bindings_.erase(port); }

    // Inbound datagram from IPv4.
    void receive(const ip::Ipv4Datagram& dg);

    // Send `data` from `src_port` to `dst_ip:dst_port`. Returns false if the
    // datagram could not be sent down (next hop unresolved).
    bool send(std::uint16_t src_port, ip::Ipv4Addr dst_ip,
              std::uint16_t dst_port, std::span<const std::byte> data);

    std::uint64_t datagrams_received() const noexcept { return datagrams_rx_; }
    std::uint64_t checksum_errors()    const noexcept { return checksum_errors_; }

private:
    ip::Ipv4Sender&                              ip_;
    std::unordered_map<std::uint16_t, Handler>   bindings_;
    std::uint64_t datagrams_rx_    = 0;
    std::uint64_t checksum_errors_ = 0;
};

} // namespace udp
