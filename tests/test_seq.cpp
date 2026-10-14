#include "tcp/seq.hpp"

#include <gtest/gtest.h>

using namespace tcp;

TEST(Seq, BasicOrdering) {
    EXPECT_TRUE(seq_lt(1, 2));
    EXPECT_TRUE(seq_gt(2, 1));
    EXPECT_TRUE(seq_leq(5, 5));
    EXPECT_TRUE(seq_geq(5, 5));
    EXPECT_FALSE(seq_lt(2, 1));
}

TEST(Seq, WrapsAroundCorrectly) {
    // Just below the wrap vs just above: 0xFFFFFFFF precedes 0x00000001.
    EXPECT_TRUE(seq_lt(0xFFFFFFFFu, 0x00000001u));
    EXPECT_TRUE(seq_gt(0x00000001u, 0xFFFFFFFFu));
    // A full half-space apart is the boundary.
    EXPECT_TRUE(seq_lt(0u, 0x7FFFFFFFu));
}

TEST(Seq, HalfOpenWindow) {
    // (100, 200]
    EXPECT_TRUE(seq_in_range_hi(100, 150, 200));
    EXPECT_TRUE(seq_in_range_hi(100, 200, 200)); // hi inclusive
    EXPECT_FALSE(seq_in_range_hi(100, 100, 200)); // lo exclusive
    EXPECT_FALSE(seq_in_range_hi(100, 201, 200));
}
