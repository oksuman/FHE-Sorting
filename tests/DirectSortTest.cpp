#include <algorithm>
#include <gtest/gtest.h>
#include <random>
#include <vector>

#include "ciphertext-fwd.h"
#include "comparison.h"
#include "constants.h"
#include "encryption.h"
#include "key/privatekey-fwd.h"
#include "lattice/hal/lat-backend.h"
#include "sign.h"
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
        parameters.SetScalingModSize(59);
        parameters.SetBatchSize(array_length);
        parameters.SetSecurityLevel(HEStd_NotSet);
        constexpr usint ringDim = 1 << 17;
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

        rotations = {-1, -2, -4, -8, -16, -32, 1, 2, 4, 8, 16, 32, 64, 512};

        // Generate the rotation keys
        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);

        // Create DirectSort object

        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
    }

    static constexpr int array_length = 4;
    static constexpr int MultDepth = 40;
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
        EXPECT_NEAR(decryptedRanks[i], expectedRanks[i], 0.1)
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
        if (error > 0.1) {
            largeErrorCount++;
        }
    }

    // Print statistics
    std::cout << "Maximum error: " << maxError << std::endl;
    std::cout << "Number of errors larger than 0.1: " << largeErrorCount
              << std::endl;

    // Assert on the quality of the sort
    EXPECT_LT(maxError, 1.0); // Maximum error should be less than 1

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
}
