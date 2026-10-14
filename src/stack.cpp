#include "stack.hpp"

namespace stack {

Stack::Stack(net::TapDevice& device, net::EventLoop& loop,
             eth::MacAddr local_mac, ip::Ipv4Addr local_ip)
    : device_(device),
      loop_(loop),
      eth_(local_mac, [this](std::span<const std::byte> frame) {
          device_.send(frame);
      }),
      arp_(eth_, local_ip),
      ipv4_(eth_, arp_, local_ip),
      icmp_(ipv4_) {
    // Inbound dispatch wiring.
    eth_.set_arp_handler([this](std::span<const std::byte> p, const eth::MacAddr& src) {
        arp_.receive(p, src);
    });
    eth_.set_ipv4_handler([this](std::span<const std::byte> p, const eth::MacAddr& src) {
        ipv4_.receive(p, src);
    });
    ipv4_.set_icmp_handler([this](const ip::Ipv4Datagram& dg) {
        icmp_.receive(dg);
    });
}

void Stack::start() {
    loop_.add_readable(device_.fd(), [this] { on_readable(); });
}

void Stack::on_readable() {
    // Drain every frame currently queued; level-triggered epoll re-wakes us if
    // more arrive after we return.
    for (;;) {
        std::size_t n = device_.receive(rx_.capacity_span());
        if (n == 0) break; // EAGAIN
        rx_.set_size(n);
        eth_.receive(rx_.bytes());
    }
}

} // namespace stack
