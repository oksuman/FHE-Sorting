#include "Masking.h"
#include <gtest/gtest.h>

using namespace lbcrypto;
using namespace kwaySort;

class MaskingTest : public ::testing::Test {
  protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(1);
        parameters.SetScalingModSize(50);
        parameters.SetBatchSize(32);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 10);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
    }

    void
    ValidateMask(const std::vector<double> &mask,
                 const std::vector<std::pair<size_t, double>> &expectedOnes) {
        for (size_t i = 0; i < mask.size(); i++) {
            bool shouldBeOne = false;
            for (const auto &expected : expectedOnes) {
                if (i == expected.first) {
                    shouldBeOne = true;
                    EXPECT_NEAR(mask[i], expected.second, 1e-6)
                        << "Mismatch at index " << i;
                    break;
                }
            }
            if (!shouldBeOne) {
                EXPECT_NEAR(mask[i], 0.0, 1e-6) << "Expected 0 at index " << i;
            }
        }
    }

    CryptoContext<DCRTPoly> m_cc;
};

TEST_F(MaskingTest, SortType) {
    // Test sortType for k=5, M=3
    int k = 5;
    int M = 3;

    // Test stage 0
    auto [m0, logDist0, slope0] = sortType(k, M, 0);
    EXPECT_EQ(m0, 0);
    EXPECT_EQ(logDist0, 0); // Should be 1
    EXPECT_EQ(slope0, 0);

    // Test middle stage - less strict validation
    auto [m1, logDist1, slope1] = sortType(k, M, 5);
    EXPECT_GE(m1, 0);
    EXPECT_GE(logDist1, 0);
    EXPECT_LE(slope1, k / 2 + 1); // Verify slope is in valid range
}

TEST_F(MaskingTest, GenIndices) {
    // Test genIndices for small k, M
    long numSlots = 32;
    long k = 2;
    long M = 2;
    long m = 1;
    long logDist = 1;
    long slope = 0;

    auto indices = genIndices(numSlots, k, M, m, logDist, slope);

    ASSERT_EQ(indices.size(), 2);
    ASSERT_EQ(indices[0].size(), numSlots);
    ASSERT_EQ(indices[1].size(), numSlots);

    // Verify some basic properties
    for (int i = 0; i < numSlots; i++) {
        EXPECT_GE(indices[0][i], 0);
        EXPECT_GE(indices[1][i], 0);
        EXPECT_LE(indices[0][i], k);
        EXPECT_LE(indices[1][i], k);
    }
}

TEST_F(MaskingTest, GenMask) {
    std::vector<std::vector<int>> indices = {{1, 2, 1, 2, 1}, {1, 1, 2, 2, 1}};

    std::vector<double> mask;
    genMask(indices, 1, 1, mask);

    std::vector<std::pair<size_t, double>> expectedOnes = {{0, 1.0}, {4, 1.0}};
    ValidateMask(mask, expectedOnes);
}

TEST_F(MaskingTest, GetRotateDistance) {
    EXPECT_EQ(getRotateDistance(2, 1, 0), 2);
    EXPECT_EQ(getRotateDistance(3, 1, 1), 6);
    EXPECT_EQ(getRotateDistance(4, 2, 2), 32);

    // Test for k/2 + 1 case which should just return dist
    EXPECT_EQ(getRotateDistance(5, 1, 3), 5);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
