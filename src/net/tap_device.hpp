#pragma once
//
// TAP device: our "network card".
//
// A TAP device is a virtual layer-2 interface. We open /dev/net/tun and issue
// the TUNSETIFF ioctl asking for TAP mode (IFF_TAP) with no packet-info prefix
// (IFF_NO_PI). From then on the kernel does NO protocol work for us -- read()
// returns a full Ethernet frame exactly as it came off the "wire", and write()
// injects one. Everything above this fd is our code.
//
// (TUN mode would give bare IP packets; we chose TAP so we implement Ethernet
// and ARP ourselves, which is the richer layer-2 story.)
//
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace net {

class TapDevice {
public:
    // Open a TAP device with the requested name (e.g. "tap0"). If the name is
    // empty the kernel picks one. Throws std::system_error on failure.
    explicit TapDevice(std::string_view requested_name = "tap0");

    ~TapDevice();

    // Non-copyable, movable.
    TapDevice(const TapDevice&)            = delete;
    TapDevice& operator=(const TapDevice&) = delete;
    TapDevice(TapDevice&& other) noexcept;
    TapDevice& operator=(TapDevice&& other) noexcept;

    int fd() const noexcept { return fd_; }

    // The actual interface name the kernel assigned (what you run `ip` against).
    const std::string& name() const noexcept { return name_; }

    // Read one frame into `out`. Returns the number of bytes read, or 0 if the
    // fd was not actually readable (EAGAIN). Throws on a hard error.
    std::size_t receive(std::span<std::byte> out);

    // Write one full frame. Throws on error.
    void send(std::span<const std::byte> frame);

private:
    void close_fd() noexcept;

    int         fd_ = -1;
    std::string name_;
};

} // namespace net
