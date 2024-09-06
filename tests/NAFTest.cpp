#include "rotation.h"
#include <array>
#include <cstdint>
#include <gtest/gtest.h>

class NAFComputerTest : public ::testing::Test {
  protected:
    void SetUp() override {}
    void TearDown() override {}

    bool checkNonAdjacency(
        const std::array<int8_t, NAFComputer<32>::MAX_NAF_SIZE> &naf) {
        bool lastNonZero = false;
        for (int8_t digit : naf) {
            if (digit != 0) {
                if (lastNonZero)
                    return false;
                lastNonZero = true;
            } else {
                lastNonZero = false;
            }
        }
        return true;
    }

    int fromNAF(const std::array<int8_t, NAFComputer<32>::MAX_NAF_SIZE> &naf) {
        int result = 0;
        for (int i = NAFComputer<32>::MAX_NAF_SIZE - 1; i >= 0; --i) {
            result = result * 2 + naf[i];
        }
        return result;
    }
};

TEST_F(NAFComputerTest, NonAdjacencyRule) {
    for (int num = -128; num <= 128; ++num) {
        auto naf = NAFComputer<32>::computeNAF(num);
        EXPECT_TRUE(checkNonAdjacency(naf))
            << "Number: " << num << " failed non-adjacency check";
    }
}

TEST_F(NAFComputerTest, EncoderDecoder) {
    for (int num = -128; num <= 128; ++num) {
        auto naf = NAFComputer<32>::computeNAF(num);
        int decoded = fromNAF(naf);
        EXPECT_EQ(num, decoded)
            << "Number: " << num << " failed encoding/decoding";
    }
}

TEST_F(NAFComputerTest, SpecificCases) {
    std::vector<std::pair<int, std::array<int8_t, 8>>> test_cases = {
        {7, {-1, 0, 0, 1, 0, 0, 0, 0}},
    };

    for (const auto &[num, expected_naf] : test_cases) {
        auto computed_naf = NAFComputer<32>::computeNAF(num);
        for (size_t i = 0; i < 8; ++i) {
            EXPECT_EQ(computed_naf[i], expected_naf[i])
                << "Number: " << num << " at index " << i;
        }
    }
}
