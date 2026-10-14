#pragma once
//
// Optional per-segment tracing, enabled by setting TCPSTACK_TRACE=1. Used only
// for debugging the reliability behaviour; off by default and zero-cost then.
//
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "tcp/tcp_header.hpp"

namespace tcp {

inline bool trace_enabled() {
    static const bool on = (std::getenv("TCPSTACK_TRACE") != nullptr);
    return on;
}

inline void trace_seg(const char* dir, std::uint16_t sport, std::uint16_t dport,
                      std::uint32_t seq, std::uint32_t ack, std::uint8_t flags,
                      std::size_t len) {
    if (!trace_enabled()) return;
    static const auto t0 = std::chrono::steady_clock::now();
    double ms = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();
    char f[7];
    f[0] = (flags & flag::URG) ? 'U' : '.';
    f[1] = (flags & flag::ACK) ? 'A' : '.';
    f[2] = (flags & flag::PSH) ? 'P' : '.';
    f[3] = (flags & flag::RST) ? 'R' : '.';
    f[4] = (flags & flag::SYN) ? 'S' : '.';
    f[5] = (flags & flag::FIN) ? 'F' : '.';
    f[6] = '\0';
    std::fprintf(stderr, "%8.1f %s %5u->%-5u seq=%u ack=%u %s len=%zu\n",
                 ms, dir, sport, dport, seq, ack, f, len);
}

} // namespace tcp
