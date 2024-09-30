#include <algorithm>
#include <gtest/gtest.h>
#include <vector>

#include "encryption.h"
#include "sort_algo.h"
#include "utils.h"

using namespace lbcrypto;

class DirectSortTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Set up the CryptoContext
        CCParams<CryptoContextCKKSRNS> parameters;
        // TODO: check optimal level
        parameters.SetMultiplicativeDepth(MultDepth);
        parameters.SetScalingModSize(39);
        parameters.SetBatchSize(array_length);
        parameters.SetSecurityLevel(HEStd_NotSet);
        constexpr usint ringDim = 1 << 16;
        parameters.SetRingDim(ringDim);
        assert(ringDim / 2 > array_length * array_length &&
               "Ring dimension should be higher than the square of array "
               "length due to SIMD batching.");

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        // Generate keys
        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        rotations = {-1, -2, -4,  -8,  -16, -32,  1,    2,    4,    8,    16,
                     32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384};

        // Generate the rotation keys
        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);

        // Create DirectSort object

        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
    }

    static constexpr int array_length = 128;
    static constexpr int MultDepth = 48;
    std::vector<int> rotations;
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
};

TEST_F(DirectSortTest, ConstructRank) {

    std::vector<double> inputArray = getVectorWithMinDiff(array_length);

    std::cout << inputArray << "\n";

    // Encrypt the input array
    auto ctxt = m_enc->encryptInput(inputArray);
    auto directSort = std::make_unique<DirectSort<array_length>>(
        m_cc, m_publicKey, rotations, m_enc);

    // Construct rank using DirectSort
    auto ctxtRank = directSort->constructRank(ctxt);

    // Decrypt the result
    Plaintext result;
    m_cc->Decrypt(m_privateKey, ctxtRank, &result);
    std::vector<double> decryptedRanks = result->GetRealPackedValue();

    // Calculate the expected ranks
    std::vector<double> expectedRanks(array_length);
    for (int i = 0; i < array_length; ++i) {
        expectedRanks[i] =
            std::count_if(inputArray.begin(), inputArray.end(),
                          [&](double val) { return val < inputArray[i]; });
    }

    // Compare the results
    for (int i = 0; i < array_length; ++i) {
        ASSERT_NEAR(decryptedRanks[i], expectedRanks[i], 0.000001)
            << "Mismatch at index " << i << ": expected " << expectedRanks[i]
            << ", got " << decryptedRanks[i];
    }

    // Print the input array and the calculated ranks
    std::cout << "Input array: ";
    for (const auto &val : inputArray) {
        std::cout << val << " ";
    }
    std::cout << std::endl;

    std::cout << "Calculated ranks: ";
    for (const auto &rank : decryptedRanks) {
        std::cout << rank << " ";
    }
    std::cout << std::endl;
}

TEST_F(DirectSortTest, RotationIndexCheck) {
    // Generate a random permutation for the input array

    std::vector<double> inputArray = getVectorWithMinDiff(array_length);

    // Calculate the rank array
    std::vector<double> rankArray(array_length);
    for (size_t i = 0; i < array_length; ++i) {
        rankArray[i] =
            std::count_if(inputArray.begin(), inputArray.end(),
                          [&](double val) { return val < inputArray[i]; });
    }

    // Encrypt input arrays
    auto ctxtInput = m_enc->encryptInput(inputArray);
    auto ctxRank = m_enc->encryptInput(rankArray);

    // Create DirectSort object
    auto directSort = std::make_unique<DirectSort<array_length>>(
        m_cc, m_publicKey, rotations, m_enc);

    // Call rotationIndexCheck
    auto ctxtResult = directSort->rotationIndexCheck(ctxRank, ctxtInput);

    // Decrypt the result
    Plaintext result;
    m_cc->Decrypt(m_privateKey, ctxtResult, &result);
    std::vector<double> outputArray = result->GetRealPackedValue();

    // Expected sorted array
    std::vector<double> expectedArray = inputArray;
    std::sort(expectedArray.begin(), expectedArray.end());

    // Compare results
    for (size_t i = 0; i < array_length; ++i) {
        ASSERT_NEAR(outputArray[i], expectedArray[i], 0.01)
            << "Mismatch at index " << i << ": expected " << expectedArray[i]
            << ", got " << outputArray[i];
    }

    // Print arrays for visualization
    std::cout << "Input array: " << inputArray << std::endl;
    std::cout << "Rank array: " << rankArray << std::endl;
    std::cout << "Output array: " << outputArray << std::endl;
    std::cout << "Expected array: " << expectedArray << std::endl;

    // Check the level of the result
    std::cout << "Result level: " << ctxtResult->GetLevel() << std::endl;
}

TEST_F(DirectSortTest, DirectSort) {

    std::vector<double> inputArray = getVectorWithMinDiff(array_length);
    std::cout << inputArray << "\n";

    // Encrypt the input array
    auto ctxt = m_enc->encryptInput(inputArray);
    auto directSort = std::make_unique<DirectSort<array_length>>(
        m_cc, m_publicKey, rotations, m_enc);

    Ciphertext<DCRTPoly> ctxt_out = directSort->sort(ctxt);

    EXPECT_EQ(ctxt_out->GetLevel() + 1, MultDepth)
        << "Use the level + 1 returned by the result for best performance";

    // Decrypt the result
    Plaintext result;
    m_cc->Decrypt(m_privateKey, ctxt_out, &result);
    std::vector<double> output_array = result->GetRealPackedValue();

    auto expected = inputArray;
    std::sort(expected.begin(), expected.end());
    double maxError = 0.0;
    int largeErrorCount = 0;
    for (size_t i = 0; i < output_array.size(); ++i) {
        double error = std::abs(output_array[i] - expected[i]);
        maxError = std::max(maxError, error);
        if (error >= 0.01) {
            largeErrorCount++;
        }
    }

    // Print statistics
    std::cout << "Maximum error: " << maxError << std::endl;
    std::cout << "Number of errors larger than 0.02: " << largeErrorCount
              << std::endl;

    // Print the input array and the calculated ranks
    std::cout << "Input array: ";
    for (const auto &val : inputArray) {
        std::cout << val << " ";
    }
    std::cout << std::endl;

    std::cout << "Output: ";
    for (const auto &rank : output_array) {
        std::cout << rank << " ";
    }
    std::cout << std::endl;

    ASSERT_LT(maxError, 0.01);
}
