//
// Milestone 0 -- TUN/TAP device & packet plumbing.
//
// Goal: open a TAP device, read raw frames into a buffer under one event loop,
// and hexdump whatever the kernel hands us. No protocols yet -- this just proves
// the pipe works end to end.
//
// Run (after creating + configuring the interface, see README):
//     ./tcpstack tap0
//
// Then from another terminal `ping 10.0.0.2` (it won't reply until Milestone 1)
// and watch the raw IP/ARP frames appear in the dump.
//
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <functional>
#include <unistd.h>

#include "net/buffer.hpp"
#include "net/event_loop.hpp"
#include "net/hexdump.hpp"
#include "net/tap_device.hpp"

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

    try {
        net::TapDevice tap(ifname);
        std::printf("opened TAP device '%s' (fd=%d)\n", tap.name().c_str(), tap.fd());
        std::printf("bring it up, then send traffic to its subnet. Ctrl-C to quit.\n\n");

        make_nonblocking(tap.fd());

        net::EventLoop loop;
        g_loop = &loop;
        std::signal(SIGINT, on_sigint);

        net::PacketBuffer frame;

        // When the device is readable, drain every frame currently queued
        // (level-triggered epoll will wake us again if more arrive).
        loop.add_readable(tap.fd(), [&] {
            for (;;) {
                std::size_t n = tap.receive(frame.capacity_span());
                if (n == 0) break; // EAGAIN: nothing left to read right now
                frame.set_size(n);
                std::printf("== frame in (%zu bytes) ==\n", n);
                net::hexdump(frame.bytes());
                std::printf("\n");
            }
        });

        // A heartbeat timer, purely to prove the timer path works. It
        // reschedules itself every 5s -- the same self-rescheduling pattern
        // the retransmission timer will use later.
        net::TimerId heartbeat = 0;
        std::function<void()> tick = [&] {
            std::printf("[heartbeat] loop alive, waiting for frames...\n");
            heartbeat = loop.add_timer(std::chrono::seconds(5), tick);
        };
        heartbeat = loop.add_timer(std::chrono::seconds(5), tick);

        loop.run();
        std::printf("\nshutting down.\n");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
