#include "rotation.h"
#include <array>
#include <cstdint>
#include <gtest/gtest.h>

class DecomposerTest : public ::testing::Test {
  protected:
    std::unique_ptr<Decomposer<128>> decomposer;

    void SetUp() override { decomposer = std::make_unique<Decomposer<128>>(); }

    int compose(const std::vector<Step> &steps) {
        int result = 0;
        for (const auto &step : steps) {
            result += step.value * step.stepSize;
        }
        return result;
    }

    void testDecomposer(DecomposeAlgo algo, int start, int end,
                        std::function<bool(const std::vector<Step> &)>
                            additionalCheck = nullptr) {
        for (int num = start; num <= end; ++num) {
            auto steps = decomposer->decompose(num, algo);
            int recomposed = compose(steps);
            EXPECT_EQ(num, recomposed)
                << "Number: " << num
                << " failed decompose/compose for algorithm "
                << static_cast<int>(algo);
            if (additionalCheck) {
                EXPECT_TRUE(additionalCheck(steps))
                    << "Number: " << num
                    << " failed additional check for algorithm "
                    << static_cast<int>(algo);
            }
        }
    }

    bool checkNonAdjacency(const std::vector<Step> &steps) {
        if (steps.empty())
            return true;
        int lastStepSize = steps[0].stepSize;
        for (size_t i = 1; i < steps.size(); ++i) {
            int currentStepSize = steps[i].stepSize;
            if (currentStepSize == lastStepSize / 2 ||
                currentStepSize == lastStepSize * 2)
                return false;
            lastStepSize = currentStepSize;
        }
        return true;
    }

    bool checkBinary(const std::vector<Step> &steps) {
        for (const auto &step : steps) {
            if (step.value != 1 || (step.stepSize & (step.stepSize - 1)) != 0) {
                return false;
            }
        }
        return true;
    }

    bool isPowerOfTwo(int n) { return n > 0 && (n & (n - 1)) == 0; }
};

TEST_F(DecomposerTest, DecomposeComposeMatch) {
    testDecomposer(DecomposeAlgo::NAF, -256, 256);
    testDecomposer(DecomposeAlgo::BINARY, 0, 256);
}

TEST_F(DecomposerTest, NAFProperties) {
    testDecomposer(DecomposeAlgo::NAF, -256, 256,
                   [this](const std::vector<Step> &steps) {
                       return checkNonAdjacency(steps);
                   });
}

TEST_F(DecomposerTest, BinaryProperties) {
    testDecomposer(
        DecomposeAlgo::BINARY, 0, 256,
        [this](const std::vector<Step> &steps) { return checkBinary(steps); });
}

TEST_F(DecomposerTest, PowerOfTwoSingleStep) {
    for (int i = 0; i <= 8; ++i) {
        int powerOfTwo = 1 << i;

        // Test NAF decomposition
        auto nafSteps = decomposer->decompose(powerOfTwo, DecomposeAlgo::NAF);
        EXPECT_EQ(nafSteps.size(), 1) << "NAF decomposition of " << powerOfTwo
                                      << " should have single step";
        EXPECT_EQ(nafSteps[0].value, 1)
            << "NAF decomposition of " << powerOfTwo << " should have value 1";
        EXPECT_EQ(nafSteps[0].stepSize, powerOfTwo)
            << "NAF decomposition of " << powerOfTwo
            << " should have correct step size";

        // Test Binary decomposition
        auto binarySteps =
            decomposer->decompose(powerOfTwo, DecomposeAlgo::BINARY);
        EXPECT_EQ(binarySteps.size(), 1)
            << "Binary decomposition of " << powerOfTwo
            << " should have single step";
        EXPECT_EQ(binarySteps[0].value, 1)
            << "Binary decomposition of " << powerOfTwo
            << " should have value 1";
        EXPECT_EQ(binarySteps[0].stepSize, powerOfTwo)
            << "Binary decomposition of " << powerOfTwo
            << " should have correct step size";
    }
}
