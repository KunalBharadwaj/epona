#pragma once
//
// 32-bit sequence-number arithmetic (RFC 793 §3.3).
//
// Sequence numbers wrap around 2^32, so you can never compare them with plain
// < or >. The trick: compute the difference as a *signed* 32-bit value. As long
// as the two numbers are within 2^31 of each other (always true in practice),
// the sign of (a - b) tells you their order correctly across the wrap.
//
#include <cstdint>

namespace tcp {

inline bool seq_lt(std::uint32_t a, std::uint32_t b) noexcept {
    return static_cast<std::int32_t>(a - b) < 0;
}
inline bool seq_leq(std::uint32_t a, std::uint32_t b) noexcept {
    return static_cast<std::int32_t>(a - b) <= 0;
}
inline bool seq_gt(std::uint32_t a, std::uint32_t b) noexcept {
    return seq_lt(b, a);
}
inline bool seq_geq(std::uint32_t a, std::uint32_t b) noexcept {
    return seq_leq(b, a);
}

// Is `x` in the half-open window (lo, hi]  (modulo 2^32)?
inline bool seq_in_range_hi(std::uint32_t lo, std::uint32_t x, std::uint32_t hi) noexcept {
    return seq_lt(lo, x) && seq_leq(x, hi);
}

} // namespace tcp
