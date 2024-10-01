#include "sign.h"
#include "encryption.h"
#include "openfhe.h"
#include "sort.h"
#include <gtest/gtest.h>

using namespace lbcrypto;

class SignTest : public ::testing::Test {
  protected:
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;

    void SetUp() override {
        // Set up the crypto context
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(30);
        parameters.SetScalingModSize(35);
        parameters.SetBatchSize(8);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 17);

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

TEST_F(SignTest, CompositeSignTest) {
    // Prepare input
    std::vector<double> input = {0.5, -0.3, 0.1, -0.7, 0.0, 0.8, -0.9, 0.2};

    // Encrypt input
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);
    auto encrypted_input = cc->Encrypt(keyPair.publicKey, plaintext);

    // Parameters for compositeSign
    int dg = 3;
    int df = 3;

    // Apply compositeSign
    auto result = compositeSign(encrypted_input, cc, dg, df);

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

TEST_F(SignTest, VerySmallElementsTest) {
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
    auto result = compositeSign(encrypted_input, cc, dg, df);

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

TEST_F(SignTest, VerySmallElementsTestMinimax) {
    // The required accuracy is 0.02
    std::vector<double> input = {0.01 / 255, -0.01 / 255, 0.01, -0.01,
                                 0.009,      -0.009,      1,    -1};
    ASSERT_EQ(input.size(), cc->GetEncodingParams()->GetBatchSize());

    // Encrypt input
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(input);
    auto encrypted_input = cc->Encrypt(keyPair.publicKey, plaintext);

    std::vector<int> degrees = {13, 13, 13, 13, 27};
    std::vector<std::vector<double>> coeffs = {
        {0, 0.637521624232179, 0, -0.214410085609765, 0, 0.131025092314809, 0, -0.096334661466356, 0, 0.078106902680506, 0, -0.067687481130277, 0, 0.531756561506267},
        {0, 0.639589760068116, 0, -0.215094255700719, 0, 0.131429310051565, 0, -0.096616513955493, 0, 0.078318761329921, 0, -0.067853009038948, 0, 0.530203990608004},
        {0, 0.662043033261071, 0, -0.222514602957091, 0, 0.135804057342459, 0, -0.099656460988517, 0, 0.080592085370209, 0, -0.069615920073568, 0, 0.513326796143351},
        {0, 1.046504392380398, 0, -0.348118160418968, 0, 0.208015553193116, 0, -0.147673474293600, 0, 0.113925320686963, 0, -0.092273857896572, 0, 0.077145433705809},
        {0, 1.258972382040490, 0, -0.383395863493761, 0, 0.191771130371970, 0, -0.103942850907721, 0, 0.055620046045078, 0, -0.028224005949209, 0, 0.013245914915556, 0, -0.005631044864086, 0, 0.002121918531639, 0, -0.000690115007953, 0, 0.000186624983631, 0, -0.000039558557172, 0, 0.000005888811044, 0, -0.000000467069802}
    };
    std::vector<double> interval_bound = {
        1.00,  
        1.9994, 
        1.9929,  
        1.9252, 
        1.2164  
    };
    MinimaxSignConfig config(degrees, coeffs, interval_bound);

    // Apply compositeSign
    // auto result = sign(encrypted_input, cc, SignFunc::MinimaxSign,
    // SignConfig(config));
    auto result = minimaxSign(encrypted_input, cc, config);

    std::cout << "Result level: " << result->GetLevel() << "\n";

    // Decrypt the result
    Plaintext decryptedResult;
    cc->Decrypt(keyPair.secretKey, result, &decryptedResult);
    std::vector<double> output = decryptedResult->GetRealPackedValue();

    // Expected results (approximate)
    std::vector<double> expected = {1.0, -1.0, 1.0, -1.0, 1.0, -1.0, 1.0, -1.0};

    std::cout << "Obtained result: " << output << "\n";
    std::cout << "Expected result: " << expected << "\n";

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
