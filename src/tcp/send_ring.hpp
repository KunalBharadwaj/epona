#pragma once
//
// A contiguous ring buffer for TCP's send buffer (unacknowledged + unsent
// bytes). It replaces a std::deque<std::byte>, which profiling showed was the
// hot spot: building each outbound segment copied bytes one at a time through
// std::deque::operator[], and every access recomputes a block index and chases
// the deque's block-map pointer across non-contiguous storage.
//
// This ring keeps the live bytes in one allocation and extracts a segment with
// one or two memcpys. It grows (doubling) only when the window of outstanding
// data does, so after warm-up the hot path performs no allocation at all.
//
#include <cstddef>
#include <cstring>
#include <span>
#include <vector>

namespace tcp {

class SendRing {
public:
    std::size_t size() const noexcept { return size_; }
    bool        empty() const noexcept { return size_ == 0; }

    // Append application bytes at the tail.
    void append(std::span<const std::byte> d) {
        if (d.empty()) return;
        ensure(size_ + d.size());
        std::size_t tail  = (head_ + size_) % buf_.size();
        std::size_t first = std::min(d.size(), buf_.size() - tail);
        std::memcpy(buf_.data() + tail, d.data(), first);
        if (d.size() > first)
            std::memcpy(buf_.data(), d.data() + first, d.size() - first);
        size_ += d.size();
    }

    // Copy `n` bytes starting `off` bytes from the front into `dst`.
    void copy_out(std::size_t off, std::byte* dst, std::size_t n) const {
        if (n == 0) return;
        std::size_t pos   = (head_ + off) % buf_.size();
        std::size_t first = std::min(n, buf_.size() - pos);
        std::memcpy(dst, buf_.data() + pos, first);
        if (n > first)
            std::memcpy(dst + first, buf_.data(), n - first);
    }

    // The byte `off` bytes from the front (used by the zero-window persist probe).
    std::byte at(std::size_t off) const { return buf_[(head_ + off) % buf_.size()]; }

    // Drop `n` acknowledged bytes from the front.
    void pop_front(std::size_t n) noexcept {
        if (n == 0) return; // also guards the empty ring (buf_.size() == 0)
        head_ = (head_ + n) % buf_.size();
        size_ -= n;
    }

private:
    void ensure(std::size_t need) {
        if (need <= buf_.size()) return;
        std::size_t cap = buf_.empty() ? 64 * 1024 : buf_.size() * 2;
        while (cap < need) cap *= 2;
        std::vector<std::byte> nb(cap);
        copy_out(0, nb.data(), size_); // linearize the live bytes into the new ring
        buf_.swap(nb);
        head_ = 0;
    }

    std::vector<std::byte> buf_;   // ring storage; buf_.size() is the capacity
    std::size_t            head_ = 0; // offset of the oldest live byte
    std::size_t            size_ = 0; // number of live bytes
};

} // namespace tcp
