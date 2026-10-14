//
// Milestone 1 -- Ethernet + ARP + IPv4 + ICMP.
//
// The stack now answers. Bring up tap0 (see README), run this, then from the
// host:
//     ping 10.0.0.2        # steady replies
//     tcpdump -i tap0 -n    # watch the ARP exchange + ICMP echo/reply pairs
//
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <unistd.h>

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
        std::signal(SIGINT, on_sigint);
        std::signal(SIGTERM, on_sigint); // clean shutdown on `kill` too

        stack::Stack stack(tap, loop, local_mac, local_ip);
        stack.start();

        std::printf("tcpstack up on '%s'\n", tap.name().c_str());
        std::printf("  MAC %s   IP %s\n", local_mac.to_string().c_str(),
                    local_ip.to_string().c_str());
        std::printf("  try:  ping %s     (Ctrl-C to quit)\n\n",
                    local_ip.to_string().c_str());

        loop.run();

        std::printf("\narp entries: %zu | icmp replies: %llu | "
                    "ip checksum errors: %llu\n",
                    stack.arp().cache().size(),
                    static_cast<unsigned long long>(stack.icmp().echo_replies_sent()),
                    static_cast<unsigned long long>(stack.ipv4().checksum_errors()));
        std::printf("shutting down.\n");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
