#include "comparison.h"
#include "encryption.h"
#include "openfhe.h"
#include <gtest/gtest.h>
#include <memory>

using namespace lbcrypto;

class CompareTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Set up crypto context
        CCParams<CryptoContextCKKSRNS> parameters;
        usint scalingModSize = 59;
        uint32_t multDepth = 50;
        int N = 4;
        uint32_t batchSize = N;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scalingModSize);
        parameters.SetBatchSize(batchSize);
        parameters.SetRingDim(1 << 12);
        parameters.SetSecurityLevel(HEStd_NotSet);

        cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);

        keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        enc = std::make_shared<Encryption>(cc, keys.publicKey);
        comp = std::make_unique<Comparison>(enc);
    }

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keys;
    std::shared_ptr<Encryption> enc;
    std::unique_ptr<Comparison> comp;
};

TEST_F(CompareTest, CompareVectors) {
    std::vector<double> a = {1.0, 5.0, 3.0, 4.0};
    std::vector<double> b = {2.0, 4.0, 3.0, 3.0};

    auto cA = enc->encryptInput(a);
    auto cB = enc->encryptInput(b);

    auto result = comp->compare(cc, cA, cB);

    Plaintext ptResult;
    cc->Decrypt(keys.secretKey, result, &ptResult);

    std::vector<double> expected = {0.0, 1.0, 0.5, 1.0};
    auto resultValues = ptResult->GetRealPackedValue();

    ASSERT_EQ(resultValues.size(), expected.size());
    for (size_t i = 0; i < expected.size(); i++) {
        EXPECT_NEAR(resultValues[i], expected[i], 0.1);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
