#include <gtest/gtest.h>
#include "sort.h"
#include "comparison.h"
#include <algorithm>
#include <random>

class ArraySortTest : public ::testing::Test {
protected:
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;
    std::unique_ptr<arraySort> sorter;

    void SetUp() override {
        // Set up the crypto context
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(50);
        parameters.SetScalingModSize(59);
        parameters.SetBatchSize(2048);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 12);

        cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);

        keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);

        std::vector<int> rotations;
        for (int i = 1; i <= 32; i++) rotations.push_back(i);
        for (int i = 1; i <= 32; i++) rotations.push_back(-i);
        for (int i = 1; i <= 63; i++) rotations.push_back(i * 32);
        cc->EvalRotateKeyGen(keyPair.secretKey, rotations);

        // Initialize arraySort
        sorter = std::make_unique<arraySort>(cc, keyPair.publicKey);
    }

    std::vector<double> generateRandomInput(int size, double min, double max) {
        std::vector<double> input(size);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(min, max);
        for (int i = 0; i < size; ++i) {
            input[i] = dis(gen);
        }
        return input;
    }

    void runSortTest(const std::vector<double>& input) {
        // Create a copy for comparison
        std::vector<double> expected = input;
        std::sort(expected.begin(), expected.end());

        // Encrypt and sort
        sorter->encryptInput(input);
        sorter->eval();

        // Decrypt the result
        std::vector<double> result = sorter->getPlaintextOutput(keyPair.secretKey);

        // Verify the result
        ASSERT_EQ(result.size(), expected.size());
        
        double maxError = 0.0;
        int largeErrorCount = 0;
        for (size_t i = 0; i < result.size(); ++i) {
            double error = std::abs(result[i] - expected[i]);
            maxError = std::max(maxError, error);
            if (error > 0.1) {
                largeErrorCount++;
            }
        }

        // Print statistics
        std::cout << "Maximum error: " << maxError << std::endl;
        std::cout << "Number of errors larger than 0.1: " << largeErrorCount << std::endl;

        // Assert on the quality of the sort
        EXPECT_LT(maxError, 1.0);  // Maximum error should be less than 1
        EXPECT_LT(largeErrorCount, result.size() * 0.05);  // Less than 5% of elements should have large errors
    }
};

TEST_F(ArraySortTest, SortSmallRandomArray) {
    const int arraySize = 8;  // Smaller size for quicker testing
    std::vector<double> input = generateRandomInput(arraySize, 0, 255);
    runSortTest(input);
}

// Additional test cases for edge cases
TEST_F(ArraySortTest, SortAlreadySortedArray) {
    std::vector<double> input = generateRandomInput(16, 0, 255);
    std::sort(input.begin(), input.end());
    runSortTest(input);
}

TEST_F(ArraySortTest, SortReverseSortedArray) {
    std::vector<double> input = generateRandomInput(16, 0, 255);
    std::sort(input.begin(), input.end(), std::greater<double>());
    runSortTest(input);
}

TEST_F(ArraySortTest, SortArrayWithDuplicates) {
    std::vector<double> input(16, 42.0);  // All elements are the same
    runSortTest(input);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
