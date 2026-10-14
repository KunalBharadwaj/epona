//
// Milestone 2 -- adds UDP on top of the Milestone 1 stack.
//
// Bring up tap0 (see README), run this, then from the host:
//     ping 10.0.0.2                              # ARP + ICMP
//     printf 'hi\n' | nc -u -w1 10.0.0.2 7777    # UDP echo
//
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <unistd.h>

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

void make_nonblocking(int fd) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

} // namespace

int main(int argc, char** argv) {
    const char* ifname = (argc > 1) ? argv[1] : "tap0";

    const eth::MacAddr  local_mac{{std::byte{0x0a}, std::byte{0x00}, std::byte{0x00},
                                   std::byte{0x00}, std::byte{0x00}, std::byte{0x02}}};
    const ip::Ipv4Addr  local_ip = ip::Ipv4Addr::parse("10.0.0.2").value();

    std::setvbuf(stdout, nullptr, _IOLBF, 0);

    try {
        net::TapDevice tap(ifname);
        make_nonblocking(tap.fd());

        net::EventLoop loop;
        g_loop = &loop;
        std::signal(SIGINT, on_sigint);
        std::signal(SIGTERM, on_sigint);

        stack::Stack stack(tap, loop, local_mac, local_ip);
        stack.start();

        constexpr std::uint16_t kEchoPort = 7777;
        app::UdpEcho udp_echo(stack.udp(), kEchoPort);

        std::printf("tcpstack up on '%s'\n", tap.name().c_str());
        std::printf("  MAC %s   IP %s\n", local_mac.to_string().c_str(),
                    local_ip.to_string().c_str());
        std::printf("  try:  ping %s\n", local_ip.to_string().c_str());
        std::printf("        nc -u %s %u      (UDP echo)\n",
                    local_ip.to_string().c_str(), kEchoPort);
        std::printf("  Ctrl-C to quit.\n\n");

        loop.run();

        std::printf("\narp entries: %zu | icmp replies: %llu | udp echoed: %llu | "
                    "checksum errors: ip %llu / udp %llu\n",
                    stack.arp().cache().size(),
                    static_cast<unsigned long long>(stack.icmp().echo_replies_sent()),
                    static_cast<unsigned long long>(udp_echo.echoed()),
                    static_cast<unsigned long long>(stack.ipv4().checksum_errors()),
                    static_cast<unsigned long long>(stack.udp().checksum_errors()));
        std::printf("shutting down.\n");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
