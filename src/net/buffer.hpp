#pragma once
//
// Packet buffers and the cursor types every layer uses to parse/build headers.
//
// The guide is explicit: don't pass raw char* around. We give the stack one
// owning buffer type (PacketBuffer) plus two lightweight, non-owning cursors:
//
//   NetReader  -- reads big-endian integers and byte ranges off the front of a
//                 frame, bounds-checked, as we parse UP the layers (Eth -> IP
//                 -> TCP ...). Each layer slices its header then hands the rest
//                 to the next.
//
//   NetWriter  -- writes big-endian integers into a buffer as we build headers
//                 DOWN the layers on the way out.
//
// Bounds checks never throw on the data path: a malformed packet just sets the
// cursor's failure flag, which the caller checks once after parsing and drops
// the frame. That keeps the hot path exception-free.
//
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

#include "net/byteorder.hpp"

namespace net {

// Largest frame we handle. A standard Ethernet MTU is 1500 bytes of payload;
// 1518 covers the 14-byte header + payload + FCS. We round up for headroom.
inline constexpr std::size_t kMaxFrameSize = 2048;

// An owning, fixed-capacity frame buffer. Milestone 0 uses these directly off
// the stack / a vector; later milestones recycle them through a buffer pool so
// the hot path never calls malloc.
class PacketBuffer {
public:
    PacketBuffer() = default;

    std::span<std::byte>       bytes()       noexcept { return {storage_.data(), len_}; }
    std::span<const std::byte> bytes() const noexcept { return {storage_.data(), len_}; }

    // Full capacity span, for reading raw data in from the device.
    std::span<std::byte> capacity_span() noexcept {
        return {storage_.data(), storage_.size()};
    }

    std::size_t size() const noexcept { return len_; }
    void set_size(std::size_t n) noexcept { len_ = n; }
    void clear() noexcept { len_ = 0; }

    static constexpr std::size_t capacity() noexcept { return kMaxFrameSize; }

private:
    std::array<std::byte, kMaxFrameSize> storage_{};
    std::size_t len_ = 0;
};

// ---------------------------------------------------------------------------
// NetReader: bounds-checked big-endian reader over a byte span.
// ---------------------------------------------------------------------------
class NetReader {
public:
    explicit NetReader(std::span<const std::byte> data) noexcept : data_(data) {}

    std::size_t offset()    const noexcept { return pos_; }
    std::size_t remaining() const noexcept { return data_.size() - pos_; }
    bool        ok()        const noexcept { return ok_; }

    std::uint8_t u8() noexcept {
        if (!can_read(1)) return 0;
        return std::to_integer<std::uint8_t>(data_[pos_++]);
    }

    std::uint16_t u16() noexcept {
        if (!can_read(2)) return 0;
        std::uint16_t v;
        std::memcpy(&v, data_.data() + pos_, 2);
        pos_ += 2;
        return ntoh16(v);
    }

    std::uint32_t u32() noexcept {
        if (!can_read(4)) return 0;
        std::uint32_t v;
        std::memcpy(&v, data_.data() + pos_, 4);
        pos_ += 4;
        return ntoh32(v);
    }

    // A view of the next n bytes (e.g. a 6-byte MAC), advancing the cursor.
    std::span<const std::byte> bytes(std::size_t n) noexcept {
        if (!can_read(n)) return {};
        auto s = data_.subspan(pos_, n);
        pos_ += n;
        return s;
    }

    // Everything left unparsed -- the payload handed to the next layer up.
    std::span<const std::byte> rest() const noexcept {
        return data_.subspan(pos_);
    }

    void skip(std::size_t n) noexcept {
        if (can_read(n)) pos_ += n;
    }

private:
    bool can_read(std::size_t n) noexcept {
        if (pos_ + n > data_.size()) { ok_ = false; return false; }
        return true;
    }

    std::span<const std::byte> data_;
    std::size_t pos_ = 0;
    bool ok_ = true;
};

// ---------------------------------------------------------------------------
// NetWriter: big-endian writer over a mutable byte span.
// ---------------------------------------------------------------------------
class NetWriter {
public:
    explicit NetWriter(std::span<std::byte> out) noexcept : out_(out) {}

    std::size_t offset() const noexcept { return pos_; }
    bool        ok()     const noexcept { return ok_; }

    void u8(std::uint8_t v) noexcept {
        if (!can_write(1)) return;
        out_[pos_++] = std::byte{v};
    }

    void u16(std::uint16_t v) noexcept {
        if (!can_write(2)) return;
        std::uint16_t n = hton16(v);
        std::memcpy(out_.data() + pos_, &n, 2);
        pos_ += 2;
    }

    void u32(std::uint32_t v) noexcept {
        if (!can_write(4)) return;
        std::uint32_t n = hton32(v);
        std::memcpy(out_.data() + pos_, &n, 4);
        pos_ += 4;
    }

    void bytes(std::span<const std::byte> src) noexcept {
        if (src.empty()) return; // nothing to copy (and avoids memcpy(,nullptr,0))
        if (!can_write(src.size())) return;
        std::memcpy(out_.data() + pos_, src.data(), src.size());
        pos_ += src.size();
    }

    // Reserve n bytes (e.g. a checksum field) and return a span to patch later.
    std::span<std::byte> reserve(std::size_t n) noexcept {
        if (!can_write(n)) return {};
        auto s = out_.subspan(pos_, n);
        pos_ += n;
        return s;
    }

private:
    bool can_write(std::size_t n) noexcept {
        if (pos_ + n > out_.size()) { ok_ = false; return false; }
        return true;
    }

    std::span<std::byte> out_;
    std::size_t pos_ = 0;
    bool ok_ = true;
};

} // namespace net
