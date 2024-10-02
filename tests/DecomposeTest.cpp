#include "rotation.h"
#include <array>
#include <cstdint>
#include <gtest/gtest.h>

class DecomposerTest : public ::testing::Test {
  protected:
    std::unique_ptr<Decomposer<128>> decomposer;

    void SetUp() override {
        decomposer = std::make_unique<Decomposer<128>>(
            std::vector<int>{1, 2, 4, 8, 16, 32, 64});
    }

    int compose(const std::vector<Step> &steps) {
        int result = 0;
        for (const auto &step : steps) {
            result += step.stepSize;
        }
        return result;
    }

    void testDecomposition(int number, DecomposeAlgo algo) {
        auto steps = decomposer->decompose(number, 128, algo);
        int recomposed = compose(steps);

        ::testing::AssertionResult result =
            (number == recomposed) ? ::testing::AssertionSuccess()
                                   : ::testing::AssertionFailure()
                                         << "Decomposition failed for "
                                         << number << " using "
                                         << algoToString(algo) << "\n"
                                         << "Original: " << number << "\n"
                                         << "Recomposed: " << recomposed << "\n"
                                         << "Steps: " << stepsToString(steps);

        EXPECT_TRUE(result);
    }

    std::string algoToString(DecomposeAlgo algo) {
        switch (algo) {
        case DecomposeAlgo::NAF:
            return "NAF";
        case DecomposeAlgo::BNAF:
            return "BNAF";
        case DecomposeAlgo::BINARY:
            return "Binary";
        default:
            return "Unknown";
        }
    }

    std::string stepsToString(const std::vector<Step> &steps) {
        std::stringstream ss;
        ss << "[";
        for (const auto &step : steps) {
            ss << "(" << (int)step.value << ", " << step.stepSize << "), ";
        }
        ss << "]";
        return ss.str();
    }
};

TEST_F(DecomposerTest, DecomposeComposeMatch) {
    std::vector<int> testNumbers = {1,  2,  3,  4,  7,  8,   15, 16,
                                    31, 32, 63, 64, 65, 127, 128};

    for (int num : testNumbers) {
        SCOPED_TRACE("Testing number: " + std::to_string(num));
        testDecomposition(num, DecomposeAlgo::NAF);
        testDecomposition(num, DecomposeAlgo::BNAF);
        testDecomposition(num, DecomposeAlgo::BINARY);
    }
}

// TEST_F(DecomposerTest, NegativeNumbers) {
//     std::vector<int> testNumbers = {-1, -2, -3, -4, -7, -8, -15, -16, -31,
//     -32, -63, -64, -65, -127, -128};
//
//     for (int num : testNumbers) {
//         SCOPED_TRACE("Testing number: " + std::to_string(num));
//         testDecomposition(num, DecomposeAlgo::NAF);
//         testDecomposition(num, DecomposeAlgo::BNAF);
//     }
// }
