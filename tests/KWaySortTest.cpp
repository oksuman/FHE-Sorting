#include <algorithm>
#include <gtest/gtest.h>
#include <memory>
#include <random>
#include <vector>

#include "encryption.h"
#include "kway_adapter.h"
#include "utils.h"

using namespace lbcrypto;
using namespace kwaySort;

class KWaySortTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Set up the CryptoContext
        CCParams<CryptoContextCKKSRNS> parameters;
        KWayAdapter<array_length>::getSizeParameters(parameters, rotations);

        parameters.SetSecurityLevel(HEStd_NotSet);
        constexpr usint ringDim = 1 << 10;
        parameters.SetRingDim(ringDim);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);
        m_cc->Enable(FHE);

        // Generate keys
        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        // Generate rotation and multiplication keys
        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);

        // Setup bootstrapping
        std::vector<uint32_t> levelBudget = {5, 5};
        std::vector<uint32_t> bsgsDim = {0, 0};
        m_cc->EvalBootstrapSetup(levelBudget, bsgsDim, array_length);
        m_cc->EvalBootstrapKeyGen(m_privateKey, array_length);

        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
        m_multDepth = parameters.GetMultiplicativeDepth();
    }

    static constexpr int array_length = 128;
    std::vector<int> rotations;
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
    int m_multDepth;
};

TEST_F(KWaySortTest, Sort128Elements) {
    // Generate random input array with minimum difference
    std::vector<double> inputArray =
        getVectorWithMinDiff(array_length, 0, 1, 1.0 / array_length);

    std::cout << "Input array: " << inputArray << std::endl;

    // Encrypt input
    auto ctxt = m_enc->encryptInput(inputArray);

    // Create KWayAdapter with k=2 (binary sorting)
    auto kwaySorter = std::make_unique<KWayAdapter<array_length>>(
        m_cc, m_publicKey, m_privateKey, m_enc, 2 /*k-way number*/, 7 /*M*/
    );

    // Sort using k-way algorithm
    auto Cfg = SignConfig(CompositeSignConfig(3, 2, 5));
    Ciphertext<DCRTPoly> ctxt_out =
        kwaySorter->sort(ctxt, SignFunc::CompositeSign, Cfg);

    // Decrypt result
    Plaintext result;
    m_cc->Decrypt(m_privateKey, ctxt_out, &result);
    std::vector<double> outputArray = result->GetRealPackedValue();

    // Calculate expected sorted array
    auto expected = inputArray;
    std::sort(expected.begin(), expected.end());

    // Calculate error metrics
    double maxError = 0.0;
    int largeErrorCount = 0;
    for (size_t i = 0; i < outputArray.size(); ++i) {
        double error = std::abs(outputArray[i] - expected[i]);
        maxError = std::max(maxError, error);
        if (error >= 0.01) {
            largeErrorCount++;
        }
    }

    // Print results
    std::cout << "Output array: " << outputArray << std::endl;
    std::cout << "Expected array: " << expected << std::endl;
    std::cout << "Maximum error: " << maxError
              << ", log2: " << std::log2(maxError) << std::endl;
    std::cout << "Number of errors >= 0.01: " << largeErrorCount << std::endl;

    // Verify sorting accuracy
    ASSERT_LT(maxError, 0.01) << "Maximum error exceeds threshold";
    ASSERT_EQ(largeErrorCount, 0) << "Found errors larger than 0.01";
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
