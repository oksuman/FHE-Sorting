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

class OptimizedRotatorTest : public ::testing::Test {
  protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(45);
        parameters.SetScalingModSize(59);
        parameters.SetBatchSize(array_length);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 12);
        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        auto keyPair = m_cc->KeyGen();

        std::vector<int> rotations;
        for (int i = -array_length; i <= array_length; i++) {
            rotations.push_back(i);
        }

        m_cc->EvalRotateKeyGen(keyPair.secretKey, rotations);
        m_cc->EvalMultKeyGen(keyPair.secretKey);

        m_enc = std::make_shared<Encryption>(m_cc, keyPair);
        m_rotator =
            std::make_unique<OptimizedRotator<array_length>>(m_cc, m_enc);
    }

    static constexpr int array_length = 128;
    CryptoContext<DCRTPoly> m_cc;
    std::shared_ptr<Encryption> m_enc;
    std::unique_ptr<OptimizedRotator<array_length>> m_rotator;
};

TEST_F(OptimizedRotatorTest, RotateForwardAndBackward) {
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
