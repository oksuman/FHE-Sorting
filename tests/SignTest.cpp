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
        parameters.SetMultiplicativeDepth(59);
        parameters.SetScalingModSize(59);
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

    std::vector<int> degrees = {7, 7, 7, 13, 13, 27};
    std::vector<std::vector<double>> coeffs = {
        {
            0,
            0.639085028771546,
            0,
            -0.219824302408022,
            0,
            0.141450315105013,
            0,
            -0.560620554854071,
        },
        {
            0,
            0.639360910483311,
            0,
            -0.219913850303762,
            0,
            0.141501004286425,
            0,
            -0.560422828775413,
        },
        {
            0,
            0.640995555494780,
            0,
            -0.220444289629960,
            0,
            0.141801067852694,
            0,
            -0.559251053205863,
        },
        {
            0,
            0.658768822547799,
            0,
            -0.221429454178234,
            0,
            0.135166228077564,
            0,
            -0.099217351391485,
            0,
            0.080265448859416,
            0,
            -0.069360047195550,
            0,
            0.515804381583946,
        },
        {
            0,
            0.847610272136297,
            0,
            -0.283170189616444,
            0,
            0.170743232087551,
            0,
            -0.123020194788625,
            0,
            0.097051963801292,
            0,
            -0.081244654023919,
            0,
            0.372027031594664,
        },
        {
            0, 1.266277633441173,  0, -0.403933219726391, 0, 0.221820308131117,
            0, -0.138518127967010, 0, 0.089788045037979,  0, -0.058194457592534,
            0, 0.036925010039798,  0, -0.022586558503619, 0, 0.013132034793017,
            0, -0.007142927159322, 0, 0.003559003972027,  0, -0.001572153465569,
            0, 0.000579443579588,  0, -0.000156339337296,
        },
    };
    MinimaxSignConfig config(degrees, coeffs);

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
