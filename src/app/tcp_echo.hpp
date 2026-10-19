#pragma once
//
// A TCP echo service: accept connections on a port and echo back every byte
// received, closing when the peer closes. `nc 10.0.0.2 <port>`, type a line,
// get it back, Ctrl-D for a clean teardown.
//
#include <cstdint>
#include <span>

#include "tcp/tcp.hpp"

namespace app {

class TcpEcho {
public:
    TcpEcho(tcp::Tcp& tcp, std::uint16_t port) : port_(port) {
        tcp.listen(port_, [this](tcp::TcpConnection& conn) {
            ++connections_;
            conn.on_data = [](tcp::TcpConnection& c, std::span<const std::byte> d) {
                c.send(d); // echo it straight back
            };
            conn.on_close = [](tcp::TcpConnection& c) {
                c.close(); // peer closed its side -> close ours (passive close)
            };
        });
    }

    std::uint16_t port()        const noexcept { return port_; }
    std::uint64_t connections() const noexcept { return connections_; }

private:
    std::uint16_t port_;
    std::uint64_t connections_ = 0;
};

} // namespace app
