//
// The full stack. Bring up tap0 (see README), run this, then from the host:
//     ping 10.0.0.2                              # ARP + ICMP
//     printf 'hi\n' | nc -u -w1 10.0.0.2 7777    # UDP echo
//     printf 'hi\n' | nc -q1 10.0.0.2 7777       # TCP echo
//     curl http://10.0.0.2:8080/                 # HTTP/1.1 server
//
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include "app/http_server.hpp"
#include "app/tcp_echo.hpp"
#include "app/udp_echo.hpp"
#include "ip/ipv4_address.hpp"
#include "net/event_loop.hpp"
#include "net/tap_device.hpp"
#include "stack.hpp"

namespace {

net::EventLoop* g_loop = nullptr;

void on_sigint(int) {
    if (g_loop) g_loop->stop();
}

// Install `on_sigint` for `sig` WITHOUT SA_RESTART, so a signal interrupts a
// blocked epoll_wait with EINTR instead of transparently restarting it, only
// then does the loop get to re-check its stopped flag and exit. (glibc's
// std::signal() uses BSD semantics and sets SA_RESTART, which would leave an
// idle loop unresponsive to Ctrl-C.)
void install_handler(int sig) {
    struct sigaction sa{};
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // no SA_RESTART
    ::sigaction(sig, &sa, nullptr);
}

void make_nonblocking(int fd) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

} // namespace

int main(int argc, char** argv) {
    const char* ifname = (argc > 1) ? argv[1] : "tap0";

    // Our stack's identity on the wire. The host owns 10.0.0.1; we own .2.
    const eth::MacAddr  local_mac{{std::byte{0x0a}, std::byte{0x00}, std::byte{0x00},
                                   std::byte{0x00}, std::byte{0x00}, std::byte{0x02}}};
    const ip::Ipv4Addr  local_ip = ip::Ipv4Addr::parse("10.0.0.2").value();

    // Line-buffer stdout so the banner and per-event logs show up promptly even
    // when redirected to a file.
    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    try {
        net::TapDevice tap(ifname);
        make_nonblocking(tap.fd());

        net::EventLoop loop;
        g_loop = &loop;
        install_handler(SIGINT);
        install_handler(SIGTERM); // clean shutdown on `kill` too

        stack::Stack stack(tap, loop, local_mac, local_ip);
        stack.start();

        // Echo services on 7777 (UDP + TCP) and an HTTP/1.1 server on 8080.
        constexpr std::uint16_t kEchoPort = 7777;
        constexpr std::uint16_t kHttpPort = 8080;
        app::UdpEcho    udp_echo(stack.udp(), kEchoPort);
        app::TcpEcho    tcp_echo(stack.tcp(), kEchoPort);
        app::HttpServer http(stack.tcp(), kHttpPort);

        std::printf("tcpstack up on '%s'\n", tap.name().c_str());
        std::printf("  MAC %s   IP %s\n", local_mac.to_string().c_str(),
                    local_ip.to_string().c_str());
        std::printf("  try:  ping %s\n", local_ip.to_string().c_str());
        std::printf("        nc -u %s %u      (UDP echo)\n",
                    local_ip.to_string().c_str(), kEchoPort);
        std::printf("        nc %s %u         (TCP echo)\n",
                    local_ip.to_string().c_str(), kEchoPort);
        std::printf("        curl http://%s:%u/   (HTTP server)\n",
                    local_ip.to_string().c_str(), kHttpPort);
        std::printf("  Ctrl-C to quit.\n\n");

        loop.run();

        std::printf("\nhttp: %llu requests over %llu connections\n",
                    static_cast<unsigned long long>(http.requests()),
                    static_cast<unsigned long long>(http.connections()));
        std::printf("arp entries: %zu | icmp replies: %llu | udp echoed: %llu | "
                    "tcp conns: %llu (open now: %zu)\n"
                    "tcp retransmits: %llu (rto) + %llu (fast)\n"
                    "rx: ooo %llu, dup-acks-sent %llu, peer-retransmits %llu | "
                    "checksum errors: ip %llu / udp %llu / tcp %llu\n",
                    stack.arp().cache().size(),
                    static_cast<unsigned long long>(stack.icmp().echo_replies_sent()),
                    static_cast<unsigned long long>(udp_echo.echoed()),
                    static_cast<unsigned long long>(tcp_echo.connections()),
                    stack.tcp().connection_count(),
                    static_cast<unsigned long long>(stack.tcp().retransmits()),
                    static_cast<unsigned long long>(stack.tcp().fast_retransmits()),
                    static_cast<unsigned long long>(stack.tcp().ooo_segments()),
                    static_cast<unsigned long long>(stack.tcp().dup_acks_sent()),
                    static_cast<unsigned long long>(stack.tcp().rx_retransmits()),
                    static_cast<unsigned long long>(stack.ipv4().checksum_errors()),
                    static_cast<unsigned long long>(stack.udp().checksum_errors()),
                    static_cast<unsigned long long>(stack.tcp().checksum_errors()));
        std::printf("shutting down.\n");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
