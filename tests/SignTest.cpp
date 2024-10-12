#include "sign.h"
#include "encryption.h"
#include "openfhe.h"
#include "sort.h"
#include <gtest/gtest.h>

using namespace lbcrypto;

class ArraySortTest : public ::testing::Test {
  protected:
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;

    void SetUp() override {
        // Set up the crypto context
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(30);
        parameters.SetScalingModSize(50);
        parameters.SetBatchSize(8);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 12);

        cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);

        keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);

        m_enc = std::make_shared<DebugEncryption>(cc, keyPair);

        comp = std::make_unique<Comparison>(m_enc);
    }

    std::shared_ptr<Encryption> m_enc;
    std::unique_ptr<Comparison> comp;
};

TEST_F(ArraySortTest, CompositeSignTest) {
    // Prepare input
    std::vector<double> input = {0.5, -0.3, 0.1, -0.7, 0.0, 0.8, -0.9, 0.2};

    // Encrypt input
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);
    auto encrypted_input = cc->Encrypt(keyPair.publicKey, plaintext);

    // Parameters for compositeSign
    int dg = 3;
    int df = 3;

    // Apply compositeSign
    auto result = compositeSign<4>(encrypted_input, cc, dg, df);

    // Decrypt the result
    Plaintext decryptedResult;
    cc->Decrypt(keyPair.secretKey, result, &decryptedResult);
    std::vector<double> output = decryptedResult->GetRealPackedValue();

    // Expected results (approximate)
    std::vector<double> expected = {1.0, -1.0, 1.0, -1.0, 0.0, 1.0, -1.0, 1.0};

    ASSERT_EQ(output.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        EXPECT_NEAR(output[i], expected[i], 0.1);

        // Additional checks
        if (input[i] > 0) {
            EXPECT_GT(output[i], 0);
        } else if (input[i] < 0) {
            EXPECT_LT(output[i], 0);
        } else {
            EXPECT_NEAR(output[i], 0, 0.1);
        }
    }
}

TEST_F(ArraySortTest, VerySmallElementsTest) {
    // The required accuracy is 0.02
    std::vector<double> input = {0.02,  -0.02,  0.01, -0.01,
                                 0.009, -0.009, 1,    -1};
    ASSERT_EQ(input.size(), cc->GetEncodingParams()->GetBatchSize());

    // Encrypt input
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);
    auto encrypted_input = cc->Encrypt(keyPair.publicKey, plaintext);

    // Parameters for compositeSign
    int dg = 3;
    int df = 3;

    // Apply compositeSign
    auto result = compositeSign<4>(encrypted_input, cc, dg, df);

    // Decrypt the result
    Plaintext decryptedResult;
    cc->Decrypt(keyPair.secretKey, result, &decryptedResult);
    std::vector<double> output = decryptedResult->GetRealPackedValue();

    // Expected results (approximate)
    std::vector<double> expected = {1.0, -1.0, 1.0, -1.0, 1.0, -1.0, 1.0, -1.0};

    ASSERT_EQ(output.size(), expected.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        std::cout << "Checking " << input[i] << "\n";
        EXPECT_NEAR(output[i], expected[i], 0.1);

        // Additional checks
        if (input[i] > 0) {
            EXPECT_GT(output[i], 0);
        } else if (input[i] < 0) {
            EXPECT_LT(output[i], 0);
        } else {
            EXPECT_NEAR(output[i], 0, 0.1);
        }
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
