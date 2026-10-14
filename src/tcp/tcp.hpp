#pragma once
//
// The TCP manager: owns every connection (keyed by 4-tuple), the set of
// listening ports, and the inbound dispatch from IPv4. It also synthesises RST
// segments for traffic that matches no connection, so peers fail fast instead
// of hanging.
//
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>

#include "ip/ipv4.hpp"
#include "ip/ipv4_sender.hpp"
#include "net/event_loop.hpp"
#include "tcp/tcp_connection.hpp"

namespace tcp {

// Default TIME-WAIT duration (Linux uses ~60s; it's 2*MSL with MSL=30s).
inline constexpr net::Duration kDefaultTimeWait = std::chrono::seconds(60);

class Tcp {
public:
    using AcceptCallback = std::function<void(TcpConnection&)>;

    Tcp(ip::Ipv4Sender& ip, net::EventLoop& loop,
        net::Duration time_wait = kDefaultTimeWait)
        : ip_(ip), loop_(loop), time_wait_(time_wait) {}

    // Passively open: accept connections arriving on `port`. `on_accept` fires
    // when a connection reaches ESTABLISHED.
    void listen(std::uint16_t port, AcceptCallback on_accept);

    // Actively open a connection to `dst_ip:dst_port` from `src_port`. Returns
    // the connection (its on_open fires when ESTABLISHED), or nullptr if the
    // 4-tuple is already in use.
    TcpConnection* connect(ip::Ipv4Addr dst_ip, std::uint16_t dst_port,
                           std::uint16_t src_port);

    // Inbound TCP segment from IPv4.
    void receive(const ip::Ipv4Datagram& dg);

    // ----- services used by TcpConnection -----
    ip::Ipv4Sender& ip()        noexcept { return ip_; }
    net::EventLoop& loop()      noexcept { return loop_; }
    net::Duration   time_wait() const noexcept { return time_wait_; }
    void            remove(const FourTuple& t) { conns_.erase(t); }
    void            notify_accept(TcpConnection& c);
    void            note_retransmit()      noexcept { ++retransmits_; }
    void            note_fast_retransmit() noexcept { ++fast_retransmits_; }
    void            note_ooo()             noexcept { ++ooo_segments_; }
    void            note_dup_ack_sent()    noexcept { ++dup_acks_sent_; }
    void            note_rx_retransmit()   noexcept { ++rx_retransmits_; }

    // ----- stats -----
    std::size_t   connection_count() const noexcept { return conns_.size(); }
    std::uint64_t accepted()      const noexcept { return accepted_; }
    std::uint64_t checksum_errors() const noexcept { return checksum_errors_; }
    std::uint64_t retransmits()   const noexcept { return retransmits_; }
    std::uint64_t fast_retransmits() const noexcept { return fast_retransmits_; }
    std::uint64_t ooo_segments()  const noexcept { return ooo_segments_; }
    std::uint64_t dup_acks_sent() const noexcept { return dup_acks_sent_; }
    std::uint64_t rx_retransmits() const noexcept { return rx_retransmits_; }

private:
    void send_rst_for(const ip::Ipv4Datagram& dg, const TcpHeader& h);

    ip::Ipv4Sender& ip_;
    net::EventLoop& loop_;
    net::Duration   time_wait_;

    std::unordered_map<FourTuple, std::unique_ptr<TcpConnection>, FourTupleHash> conns_;
    std::unordered_map<std::uint16_t, AcceptCallback> listeners_;

    std::uint64_t accepted_         = 0;
    std::uint64_t checksum_errors_  = 0;
    std::uint64_t retransmits_      = 0;
    std::uint64_t fast_retransmits_ = 0;
    std::uint64_t ooo_segments_     = 0;
    std::uint64_t dup_acks_sent_    = 0;
    std::uint64_t rx_retransmits_   = 0;
};

} // namespace tcp
