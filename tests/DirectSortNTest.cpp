#include <algorithm>
#include <cmath>
#include <gtest/gtest.h>
#include <random>
#include <vector>

#include "encryption.h"
#include "sign.h"
#include "sort_algo.h"
#include "utils.h"

#include "comparison.h"
#include "encryption.h"
#include "openfhe.h"
#include "sort_algo.h"
#include <gtest/gtest.h>

using namespace lbcrypto;

template <size_t N> class DirectSortTest : public ::testing::Test {
  protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        DirectSort<N>::getSizeParameters(parameters, rotations);
        parameters.SetSecurityLevel(HEStd_NotSet);
        constexpr int maxSlotRequirement = 2 * N * N;
        auto logRingDim = ((int)log2(maxSlotRequirement) + 1);
        parameters.SetRingDim(1 << logRingDim);
        std::cout << "Ring Dimension 2^" << logRingDim << "\n";

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);
        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
        m_multDepth = parameters.GetMultiplicativeDepth();
    }

    std::vector<int> rotations;
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
    int m_multDepth;
};

template <typename T>
class DirectSortTestFixture : public DirectSortTest<T::value> {};

TYPED_TEST_SUITE_P(DirectSortTestFixture);

TYPED_TEST_P(DirectSortTestFixture, SortTest) {
    constexpr size_t N = TypeParam::value;
    // std::vector<double> inputArray = getVectorWithMinDiff(N, 0, 255, 0.01);
    std::vector<double> inputArray(N);
    std::generate(inputArray.begin(), inputArray.end(), []() {
        return static_cast<long double>(std::rand()) / RAND_MAX;
    });

    std::cout << "Input array size: " << N << std::endl;
    std::cout << "Multiplicative depth: " << this->m_multDepth << std::endl;

    auto ctxt = this->m_enc->encryptInput(inputArray);

    auto directSort = std::make_unique<DirectSort<N>>(
        this->m_cc, this->m_publicKey, this->rotations, this->m_enc);
    auto Cfg = SignConfig(CompositeSignConfig(4, 3, 3));
    Ciphertext<DCRTPoly> ctxt_out =
        directSort->sort(ctxt, SignFunc::CompositeSign, Cfg);

    EXPECT_EQ(ctxt_out->GetLevel(), this->m_multDepth)
        << "Use the level returned by the result for best performance";

    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxt_out, &result);
    std::vector<double> output_array = result->GetRealPackedValue();

    auto expected = inputArray;
    std::sort(expected.begin(), expected.end());

    double maxError = 0.0;
    int largeErrorCount = 0;
    for (size_t i = 0; i < output_array.size(); ++i) {
        double error = std::abs(output_array[i] - expected[i]);
        maxError = std::max(maxError, error);
        if (error >= 0.01) {
            largeErrorCount++;
        }
    }

    std::cout << "Maximum error: " << maxError
              << ", log2: " << std::log2(maxError) << "\n";
    std::cout << "Number of errors larger than 0.01: " << largeErrorCount
              << "\n";

    ASSERT_LT(maxError, 0.01);
}

REGISTER_TYPED_TEST_SUITE_P(DirectSortTestFixture, SortTest);

using TestSizes = ::testing::Types<
    std::integral_constant<size_t, 4>, std::integral_constant<size_t, 8>,
    std::integral_constant<size_t, 16>, std::integral_constant<size_t, 32>,
    std::integral_constant<size_t, 64>, std::integral_constant<size_t, 128>,
    std::integral_constant<size_t, 256>, std::integral_constant<size_t, 512>,
    std::integral_constant<size_t, 1024>>;

INSTANTIATE_TYPED_TEST_SUITE_P(DirectSort, DirectSortTestFixture, TestSizes);
