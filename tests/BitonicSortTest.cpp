#include "constants.h"
#include "openfhe.h"
#include "utils.h"
#include <gtest/gtest.h>
#include <random>
#include <vector>

#include "encryption.h"
#include "sort_algo.h"

class BitonicSortTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Set up the CryptoContext
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(MultDepth);
        parameters.SetScalingModSize(59);
        parameters.SetBatchSize(array_length);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 12);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        // Generate keys
        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        for (int i = 1; i < array_length; i *= 2) {
            rotations.push_back(i);
            rotations.push_back(-i);
        }

        // Generate the rotation keys
        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);

        // Bootstrapping
        m_cc->Enable(FHE);
        std::vector<uint32_t> levelBudget = {3, 3};
        m_cc->EvalBootstrapSetup(levelBudget, {0, 0} /*giant-baby step param*/,
                                 array_length);
        m_cc->EvalBootstrapKeyGen(keyPair.secretKey, array_length);

        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
    }

    static constexpr int array_length = 4;
    static constexpr int MultDepth = 58;
    std::vector<int> rotations;
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
};

TEST_F(BitonicSortTest, SortCorrectness) {
    std::vector<double> inputArray = getVectorWithMinDiff(
        array_length, 0 /*min*/, 255 /*max*/, 0.01 /*precision*/);
    std::cout << "Input array: " << inputArray << std::endl;

    // Encrypt the input array
    auto ctxt = m_enc->encryptInput(inputArray);
    auto bitonicSort = std::make_unique<BitonicSort<array_length>>(
        m_cc, m_publicKey, rotations, m_enc);

    // Sort the array
    Ciphertext<DCRTPoly> ctxt_out = bitonicSort->sort(ctxt);

    // Decrypt the result
    Plaintext result;
    m_cc->Decrypt(m_privateKey, ctxt_out, &result);
    std::vector<double> output_array = result->GetRealPackedValue();

    // Sort the input array for comparison
    auto expected = inputArray;
    std::sort(expected.begin(), expected.end());

    // Compare results
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
    EXPECT_LT(maxError, 1.0);      // Maximum error should be less than 1
    EXPECT_EQ(largeErrorCount, 0); // No large errors

    std::cout << "Sorted array: " << output_array << std::endl;
}
