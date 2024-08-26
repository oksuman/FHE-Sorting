#include <gtest/gtest.h>
#include <cmath>
#include "comparison.h"

TEST(SincTest, ZeroInput) {
    EXPECT_DOUBLE_EQ(scaled_sinc(0.0), 1.0);
    EXPECT_DOUBLE_EQ(scaled_sinc_j(0.0, 0), 1.0);
}

TEST(ScaledSincTest, EvenFunction) {
    double x = 0.5;
    EXPECT_DOUBLE_EQ(scaled_sinc(x), scaled_sinc(-x));

    int j = 1;
    EXPECT_NEAR(scaled_sinc_j(x, j), scaled_sinc_j(-x, -j), 1e-6);
}

TEST(ScaledSincTest, PeriodicityCheck) {
    double x = 1.0 / (2048.0);  // This should correspond to the first zero of sinc
    EXPECT_NEAR(scaled_sinc(x), 0.0, 1e-6);

    int j = 0;
    EXPECT_NEAR(scaled_sinc_j(x, j), 0.0, 1e-6);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
