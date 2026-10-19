#include "tcp/send_ring.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <numeric>
#include <vector>

using tcp::SendRing;

namespace {
std::byte B(unsigned v) { return std::byte{static_cast<unsigned char>(v)}; }

// A deterministic byte pattern so we can verify exact bytes after wrap/grow.
std::vector<std::byte> pattern(std::size_t n, unsigned seed) {
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = B((i + seed) & 0xFF);
    return v;
}

std::vector<std::byte> drain(const SendRing& r, std::size_t off, std::size_t n) {
    std::vector<std::byte> out(n);
    r.copy_out(off, out.data(), n);
    return out;
}
} // namespace

TEST(SendRing, EmptyInvariants) {
    SendRing r;
    EXPECT_TRUE(r.empty());
    EXPECT_EQ(r.size(), 0u);
}

TEST(SendRing, AppendCopyOutAndPop) {
    SendRing r;
    auto p = pattern(1000, 7);
    r.append(p);
    EXPECT_EQ(r.size(), 1000u);
    EXPECT_FALSE(r.empty());

    EXPECT_EQ(drain(r, 0, 1000), p);                 // full
    EXPECT_EQ(drain(r, 100, 50),
              std::vector<std::byte>(p.begin() + 100, p.begin() + 150)); // slice
    EXPECT_EQ(r.at(250), p[250]);

    r.pop_front(400);
    EXPECT_EQ(r.size(), 600u);
    EXPECT_EQ(drain(r, 0, 600),
              std::vector<std::byte>(p.begin() + 400, p.end())); // front advanced
}

TEST(SendRing, WrapAroundIsContiguousToCaller) {
    // Default capacity is 64 KiB. Push the head past the midpoint, then append
    // enough that the tail wraps around the physical end of the ring.
    SendRing r;
    r.append(pattern(40 * 1024, 1));
    r.pop_front(40 * 1024);          // head is now at 40 KiB, size 0
    EXPECT_EQ(r.size(), 0u);

    auto p = pattern(40 * 1024, 99); // tail = 40 KiB, wraps at 64 KiB
    r.append(p);
    EXPECT_EQ(r.size(), 40u * 1024);
    EXPECT_EQ(drain(r, 0, p.size()), p);             // reassembled across the wrap
    EXPECT_EQ(r.at(30 * 1024), p[30 * 1024]);
}

TEST(SendRing, GrowsPreservingLiveBytesAndOrder) {
    SendRing r;
    auto a = pattern(50 * 1024, 3);
    r.append(a);
    r.pop_front(10 * 1024);          // head offset so growth must linearize
    auto b = pattern(90 * 1024, 200); // forces capacity beyond 64 KiB
    r.append(b);

    std::vector<std::byte> expected(a.begin() + 10 * 1024, a.end());
    expected.insert(expected.end(), b.begin(), b.end());
    EXPECT_EQ(r.size(), expected.size());
    EXPECT_EQ(drain(r, 0, expected.size()), expected);
}

TEST(SendRing, InterleavedAppendPopStaysConsistent) {
    SendRing r;
    unsigned next_write = 0, next_read = 0;
    std::size_t live = 0;
    for (int round = 0; round < 500; ++round) {
        std::vector<std::byte> chunk(123);
        for (auto& x : chunk) x = B(next_write++);
        r.append(chunk);
        live += chunk.size();
        if (round % 2 == 0) {
            std::size_t n = 70;
            std::vector<std::byte> got(n);
            r.copy_out(0, got.data(), n);
            for (std::size_t i = 0; i < n; ++i)
                ASSERT_EQ(got[i], B(static_cast<unsigned char>(next_read + i))) << round;
            r.pop_front(n);
            next_read += n;
            live -= n;
        }
        ASSERT_EQ(r.size(), live) << round;
    }
}
