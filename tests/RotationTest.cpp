#include "rotation.h"
#include "cryptocontext.h"
#include "encryption.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include <gtest/gtest.h>
#include <memory>
#include <random>
#include <vector>

using namespace lbcrypto;
std::vector<double> getVectorWithMinDiff(int N) {
    assert(N < 255 * 100 &&
           "N should be less than or equal to 25500 to ensure all values are "
           "unique and have a minimum difference of 0.01.");
    std::vector<double> result(N);
    std::vector<int> integers(25500); // 25500 = 255 * 100
    std::iota(integers.begin(), integers.end(),
              0); // Fill with values from 0 to 25499
    std::shuffle(integers.begin(), integers.end(),
                 std::mt19937{std::random_device{}()}); // Shuffle the integers
    for (int i = 0; i < N; ++i) {
        result[i] =
            integers[i] * 0.01; // Scale to have minimum difference of 0.01
    }
    return result;
}

class RotationComposerTest : public ::testing::Test {
  protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(45);
        parameters.SetScalingModSize(59);
        parameters.SetBatchSize(array_length);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 17);
        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        auto keyPair = m_cc->KeyGen();

        rotations = {-1, -2, -4, -8, -16, -32, 1, 2, 4, 8, 16, 32, 64, 512};

        m_cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
        m_cc->EvalMultKeyGen(keyPair.secretKey);

        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
        m_rotator = std::make_unique<RotationComposer<array_length>>(
            m_cc, m_enc, rotations, DecomposeAlgo::NAF);
    }

    static constexpr int array_length = 128;
    std::vector<int> rotations;
    CryptoContext<DCRTPoly> m_cc;
    std::shared_ptr<DebugEncryption> m_enc;
    std::unique_ptr<RotationComposer<array_length>> m_rotator;
};

TEST_F(RotationComposerTest, RotateVector) {

    std::vector<double> input = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
    auto ctxt = m_enc->encryptInput(input);

    auto rotated = m_rotator->rotate(ctxt, -4);
    auto result = m_enc->getPlaintext(rotated);

    auto expected = m_enc->getPlaintext(m_cc->EvalRotate(ctxt, -4));
    for (size_t i = 0; i < 8; ++i) {
        EXPECT_NEAR(result[i], expected[i], 1e-6);
    }
}

TEST_F(RotationComposerTest, RotateTreeVector) {
    std::vector<double> input = {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0};
    auto ctxt = m_enc->encryptInput(input);
    m_rotator->buildRotationTree(-4, 4);

    std::vector<std::vector<double>> expectedResults = {
        {5.0, 6.0, 7.0, 8.0, 1.0, 2.0, 3.0, 4.0}, // -4
        {6.0, 7.0, 8.0, 1.0, 2.0, 3.0, 4.0, 5.0}, // -3
        {7.0, 8.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0}, // -2
        {8.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0}, // -1
        {1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0}, //  0
        {2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 1.0}, //  1
        {3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 1.0, 2.0}, //  2
        {4.0, 5.0, 6.0, 7.0, 8.0, 1.0, 2.0, 3.0}, //  3
        {5.0, 6.0, 7.0, 8.0, 1.0, 2.0, 3.0, 4.0}  //  4
    };

    for (int rotation = -4; rotation <= 4; ++rotation) {
        SCOPED_TRACE("Rotation: " + std::to_string(rotation));

        auto rotated = m_rotator->treeRotate(ctxt, rotation);
        auto result = m_enc->getPlaintext(rotated);

        const auto &expected = expectedResults[rotation + 4];

        for (size_t i = 0; i < 8; ++i) {
            EXPECT_NEAR(result[i], expected[i], 1e-6)
                << "Mismatch at index " << i << " for rotation " << rotation;
        }
    }
}

TEST_F(RotationComposerTest, RotateForwardAndBackward) {
    auto input_vector = getVectorWithMinDiff(array_length);
    auto ciphertext = m_enc->encryptInput(input_vector);

    const double epsilon = 1e-5;

    for (int rotation = -128; rotation <= 128; ++rotation) {
        SCOPED_TRACE("Testing rotation: " + std::to_string(rotation));

        auto rotated = m_rotator->rotate(ciphertext, rotation);
        auto rotated_back = m_rotator->rotate(rotated, -rotation);

        auto decrypted_result = m_enc->getPlaintext(rotated_back);

        for (size_t i = 0; i < array_length; i++) {
            EXPECT_NEAR(input_vector[i], decrypted_result[i], epsilon)
                << "Mismatch at index " << i << " for rotation " << rotation;
        }
    }
}

TEST_F(RotationComposerTest, RotateLargerThanNWithMask) {
    const int N = array_length;
    const int squareArrayLength = N * N;
    auto input_vector = getVectorWithMinDiff(N);
    auto ciphertext = m_enc->encryptInput(input_vector);
    const double epsilon = 1e-5;
    auto rotator = std::make_unique<RotationComposer<N>>(m_cc, m_enc, rotations,
                                                         DecomposeAlgo::NAF);

    // Expand the input to N*N
    std::vector<double> expanded_input(squareArrayLength);
    for (int i = 0; i < squareArrayLength; i++) {
        expanded_input[i] = input_vector[i % N];
    }

    auto expanded_plaintext =
        m_cc->MakeCKKSPackedPlaintext(expanded_input, 1, 0, nullptr, N * N);
    auto expanded_ciphertext =
        m_cc->Encrypt(m_enc->m_PublicKey, expanded_plaintext);
    expanded_ciphertext->SetSlots(squareArrayLength);

    // Test for both i=1 (rotation 8192) and i=6 (rotation 256)
    for (int i : {1, 6}) {
        auto summed = expanded_ciphertext->Clone();
        int rotation = squareArrayLength / (1 << i);

        auto rotated = rotator->rotate(summed, rotation);
        m_cc->EvalAddInPlace(summed, rotated);

        auto decrypted = m_enc->getPlaintext(summed);
        std::vector<double> expected(squareArrayLength);
        for (int j = 0; j < squareArrayLength; j++) {
            expected[j] = expanded_input[j]; // Original value
            int rotated_index = (j + rotation) % squareArrayLength;
            expected[j] += expanded_input[rotated_index]; // Rotated value
        }

        for (int j = 0; j < squareArrayLength; j++) {
            ASSERT_NEAR(expected[j], decrypted[j], epsilon * (i + 1))
                << "Mismatch at index " << j << " for log rotation " << i;
        }
    }
}
