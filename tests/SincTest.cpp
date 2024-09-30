#include "comparison.h"
#include <cmath>
#include <gtest/gtest.h>

TEST(SincTest, ZeroInput) {
    const int N = 32;
    EXPECT_DOUBLE_EQ(Sinc<N>::scaled_sinc(0.0), 1.0);
    EXPECT_DOUBLE_EQ(Sinc<N>::scaled_sinc_j(0.0, 0), 1.0);
}

TEST(ScaledSincTest, EvenFunction) {
    const int N = 32;
    double x = 0.5;
    EXPECT_DOUBLE_EQ(Sinc<N>::scaled_sinc(x), Sinc<N>::scaled_sinc(-x));

    int j = 1;
    EXPECT_NEAR(Sinc<N>::scaled_sinc_j(x, j), Sinc<N>::scaled_sinc_j(-x, -j),
                1e-6);
}

TEST(ScaledSincJTest, Periodicity) {
    const int N = 32;
    double x = 1.5; // An arbitrary value
    int j = 10;     // An arbitrary shift

    // Test periodicity: f(x, j) should equal f(x + 2048, j)
    EXPECT_NEAR(Sinc<N>::scaled_sinc_j(x, j),
                Sinc<N>::scaled_sinc_j(x + 2048, j), 1e-6);

    // Test periodicity: f(x, j) should equal f(x - 2048, j)
    EXPECT_NEAR(Sinc<N>::scaled_sinc_j(x, j),
                Sinc<N>::scaled_sinc_j(x - 2048, j), 1e-6);

    // Test the specific case you mentioned: f(1, j) should equal f(-2047, j)
    EXPECT_NEAR(Sinc<N>::scaled_sinc_j(1, j), Sinc<N>::scaled_sinc_j(-2047, j),
                1e-6);

    // Test with different j values
    for (int test_j = -5; test_j <= 5; ++test_j) {
        EXPECT_NEAR(Sinc<N>::scaled_sinc_j(x, test_j),
                    Sinc<N>::scaled_sinc_j(x + 2048, test_j), 1e-6);
        EXPECT_NEAR(Sinc<N>::scaled_sinc_j(x, test_j),
                    Sinc<N>::scaled_sinc_j(x - 2048, test_j), 1e-6);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
