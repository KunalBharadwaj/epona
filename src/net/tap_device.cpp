#include "net/tap_device.hpp"

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace net {

TapDevice::TapDevice(std::string_view requested_name) {
    // 1. Open the clone device. O_RDWR so we can read and inject frames.
    fd_ = ::open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
        throw std::system_error(
            errno, std::generic_category(),
            "open(/dev/net/tun) failed -- is the tun module loaded?");
    }

    // 2. Ask the kernel to attach us to a TAP interface.
    //    IFF_TAP   -> layer 2, we get full Ethernet frames.
    //    IFF_NO_PI -> no 4-byte packet-info prefix in front of each frame.
    ifreq ifr{};
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (!requested_name.empty()) {
        // IFNAMSIZ includes the NUL terminator; truncate defensively.
        std::size_t n = std::min(requested_name.size(),
                                 static_cast<std::size_t>(IFNAMSIZ - 1));
        std::memcpy(ifr.ifr_name, requested_name.data(), n);
        ifr.ifr_name[n] = '\0';
    }

    if (::ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        int err = errno;
        close_fd();
        throw std::system_error(
            err, std::generic_category(),
            "ioctl(TUNSETIFF) failed -- need CAP_NET_ADMIN "
            "(run under sudo or grant the capability)");
    }

    name_ = ifr.ifr_name;
}

TapDevice::~TapDevice() {
    close_fd();
}

TapDevice::TapDevice(TapDevice&& other) noexcept
    : fd_(std::exchange(other.fd_, -1)), name_(std::move(other.name_)) {}

TapDevice& TapDevice::operator=(TapDevice&& other) noexcept {
    if (this != &other) {
        close_fd();
        fd_   = std::exchange(other.fd_, -1);
        name_ = std::move(other.name_);
    }
    return *this;
}

std::size_t TapDevice::receive(std::span<std::byte> out) {
    ssize_t n = ::read(fd_, out.data(), out.size());
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        throw std::system_error(errno, std::generic_category(), "read(tap) failed");
    }
    return static_cast<std::size_t>(n);
}

void TapDevice::send(std::span<const std::byte> frame) {
    ssize_t n = ::write(fd_, frame.data(), frame.size());
    if (n < 0) {
        throw std::system_error(errno, std::generic_category(), "write(tap) failed");
    }
    // A short write on a TAP device would mean a truncated frame; treat as fatal.
    if (static_cast<std::size_t>(n) != frame.size()) {
        throw std::runtime_error("write(tap) wrote a truncated frame");
    }
}

void TapDevice::close_fd() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

} // namespace net
