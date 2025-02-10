#include "EvalUtils.h"
#include "openfhe.h"
#include <gtest/gtest.h>

using namespace lbcrypto;

class EvalUtilsTest : public ::testing::Test {
  protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        usint scalingModSize = 59;
        uint32_t multDepth = 50;
        int N = 16;
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
        cc->Enable(FHE);

        keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        cc->EvalRotateKeyGen(keys.secretKey, {1, 2, 4, 8, -1, -2, -4, -8});

        auto slots = cc->GetEncodingParams()->GetBatchSize();
        cc->EvalBootstrapSetup({3, 3}, {0, 0}, slots);
        cc->EvalBootstrapKeyGen(keys.secretKey, slots);

        m_enc = std::make_shared<DebugEncryption>(cc, keys);
        // Evaluator class used in kWaySort
        evaluator = std::make_unique<kwaySort::EvalUtils>(
            cc, m_enc, keys.publicKey, keys.secretKey);
    }

    void VerifyResults(const Ciphertext<DCRTPoly> &result,
                       const std::vector<double> &expected,
                       double tolerance = 0.1) {
        Plaintext ptResult;
        cc->Decrypt(keys.secretKey, result, &ptResult);
        auto resultValues = ptResult->GetRealPackedValue();

        for (size_t i = 0; i < expected.size(); i++) {
            EXPECT_NEAR(resultValues[i], expected[i], tolerance);
        }
    }

    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keys;
    std::unique_ptr<kwaySort::EvalUtils> evaluator;
    std::shared_ptr<DebugEncryption> m_enc;
};

TEST_F(EvalUtilsTest, MultByIntPositive) {
    std::vector<double> input = {1.0, 2.0, 3.0, 4.0};
    long coeff = 3;

    auto ptxt = cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = cc->Encrypt(keys.publicKey, ptxt);

    Ciphertext<DCRTPoly> result;
    evaluator->multByInt(ctxt, coeff, result);

    std::vector<double> expected = {3.0, 6.0, 9.0, 12.0};
    VerifyResults(result, expected);
}

TEST_F(EvalUtilsTest, MultByIntNegative) {
    std::vector<double> input = {1.0, 2.0, 3.0, 4.0};
    long coeff = -2;

    auto ptxt = cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = cc->Encrypt(keys.publicKey, ptxt);

    Ciphertext<DCRTPoly> result;
    evaluator->multByInt(ctxt, coeff, result);

    std::vector<double> expected = {-2.0, -4.0, -6.0, -8.0};
    VerifyResults(result, expected);
}

TEST_F(EvalUtilsTest, MultAndSquare) {
    std::vector<double> input1 = {1.0, 2.0, 3.0, 4.0};
    std::vector<double> input2 = {2.0, 3.0, 4.0, 5.0};

    auto ptxt1 = cc->MakeCKKSPackedPlaintext(input1);
    auto ptxt2 = cc->MakeCKKSPackedPlaintext(input2);
    auto ctxt1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto ctxt2 = cc->Encrypt(keys.publicKey, ptxt2);

    Ciphertext<DCRTPoly> multResult;
    evaluator->multAndKillImage(ctxt1, ctxt2, multResult);
    std::vector<double> expectedMult = {2.0, 6.0, 12.0, 20.0};
    VerifyResults(multResult, expectedMult);

    Ciphertext<DCRTPoly> squareResult;
    evaluator->squareAndKillImage(ctxt1, squareResult);
    std::vector<double> expectedSquare = {1.0, 4.0, 9.0, 16.0};
    VerifyResults(squareResult, expectedSquare);
}

TEST_F(EvalUtilsTest, Rotation) {
    std::vector<double> input(16);
    for (size_t i = 0; i < input.size(); i++) {
        input[i] = i + 1;
    }

    auto ptxt = cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = cc->Encrypt(keys.publicKey, ptxt);

    Ciphertext<DCRTPoly> leftResult;
    evaluator->leftRotate(ctxt, 3, leftResult);
    std::vector<double> expectedLeft = {4,  5,  6,  7,  8,  9, 10, 11,
                                        12, 13, 14, 15, 16, 1, 2,  3};
    VerifyResults(leftResult, expectedLeft);

    Ciphertext<DCRTPoly> rightResult;
    evaluator->rightRotate(ctxt, 2, rightResult);
    std::vector<double> expectedRight = {15, 16, 1, 2,  3,  4,  5,  6,
                                         7,  8,  9, 10, 11, 12, 13, 14};
    VerifyResults(rightResult, expectedRight);
}

TEST_F(EvalUtilsTest, EvalPoly) {
    std::vector<double> input = {0.1, 0.2, 0.3, 0.4};
    std::vector<long> coeffs = {0, 1, 0, -2,
                                0, 3, 0, -4}; // x - 2x³ + 3x⁵ - 4x⁷

    auto ptxt = cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = cc->Encrypt(keys.publicKey, ptxt);

    Ciphertext<DCRTPoly> result;
    evaluator->evalPoly(ctxt, coeffs, 0, result);

    std::vector<double> expected(4);
    for (size_t i = 0; i < input.size(); i++) {
        double x = input[i];
        expected[i] = x - 2 * x * x * x + 3 * x * x * x * x * x -
                      4 * x * x * x * x * x * x * x;
    }
    VerifyResults(result, expected, 0.01);
}

TEST_F(EvalUtilsTest, ApproxComp) {
    std::vector<double> input1 = {0.3, 0.7, 0.5, 0.1};
    std::vector<double> input2 = {0.4, 0.6, 0.5, 0.2};

    auto ptxt1 = cc->MakeCKKSPackedPlaintext(input1);
    auto ptxt2 = cc->MakeCKKSPackedPlaintext(input2);
    auto ctxt1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto ctxt2 = cc->Encrypt(keys.publicKey, ptxt2);

    auto result = ctxt1;
    evaluator->approxComp(result, ctxt2, 2, 3);

    std::vector<double> expected = {0.0, 1.0, 0.5, 0.0};
    VerifyResults(result, expected, 0.2);
}

TEST_F(EvalUtilsTest, Bootstrapping) {
    std::vector<double> input = {0.1, 0.2, 0.3, 0.4};

    auto ptxt = cc->MakeCKKSPackedPlaintext(input, 1, 40 /*level*/, nullptr,
                                            16 /*slots=*/);
    auto ctxt = cc->Encrypt(keys.publicKey, ptxt);

    long initLevel = ctxt->GetLevel();

    // If level is higher than 2, should trigger bootstrapping
    evaluator->checkLevelAndBoot(ctxt, 2, 5, false);
    long newLevel = ctxt->GetLevel();

    // After bootstrapping, level should be lower
    EXPECT_LT(newLevel, initLevel);

    std::vector<double> expected = input;
    VerifyResults(ctxt, expected, 0.2);
}

TEST_F(EvalUtilsTest, BootstrappingTwoCiphertexts) {
    std::vector<double> input1 = {0.1, 0.2, 0.3, 0.4};
    std::vector<double> input2 = {0.5, 0.6, 0.7, 0.8};

    // Encrypt inputs at a different high levels
    auto ptxt1 = cc->MakeCKKSPackedPlaintext(input1, 1, 40, nullptr, 16);
    auto ptxt2 = cc->MakeCKKSPackedPlaintext(input2, 1, 35, nullptr, 16);

    auto ctxt1 = cc->Encrypt(keys.publicKey, ptxt1);
    auto ctxt2 = cc->Encrypt(keys.publicKey, ptxt2);

    long initLevel1 = ctxt1->GetLevel();
    long initLevel2 = ctxt2->GetLevel();

    // Initial levels are different
    EXPECT_NE(initLevel1, initLevel2);

    // Bootstrapping and level equalisation of two ct
    evaluator->checkLevelAndBoot2(ctxt1, ctxt2, 2, 5, false);

    long newLevel1 = ctxt1->GetLevel();
    long newLevel2 = ctxt2->GetLevel();

    // Levels are now the same
    EXPECT_EQ(newLevel1, newLevel2);

    VerifyResults(ctxt1, input1, 0.2);
    VerifyResults(ctxt2, input2, 0.2);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
