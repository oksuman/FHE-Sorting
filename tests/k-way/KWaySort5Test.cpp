#include <algorithm>
#include <gtest/gtest.h>
#include <memory>
#include <random>
#include <vector>

#include "../utils.h"
#include "encryption.h"
#include "kway_adapter.h"

using namespace lbcrypto;
using namespace kwaySort;

template <size_t N> class KWaySortTest : public ::testing::Test {
  protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        std::vector<uint32_t> levelBudget;
        KWayAdapter<N>::getSizeParameters(parameters, rotations, levelBudget);

        parameters.SetSecurityLevel(HEStd_128_classic);
        constexpr usint ringDim = 1 << 17;
        parameters.SetRingDim(ringDim);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);
        m_cc->Enable(FHE);

        m_numSlots = m_cc->GetEncodingParams()->GetBatchSize();

        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);

        std::vector<uint32_t> bsgsDim = {0, 0};
        m_cc->EvalBootstrapSetup(levelBudget, bsgsDim, m_numSlots);
        m_cc->EvalBootstrapKeyGen(m_privateKey, m_numSlots);

        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
        m_multDepth = parameters.GetMultiplicativeDepth();
        m_scaleMod = parameters.GetScalingModSize();
    }

    std::vector<int> rotations;
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
    int m_multDepth;
    int m_scaleMod;
    int m_numSlots;
};

template <typename T>
class KWaySortTestFixture : public KWaySortTest<T::value> {};

using TestSizes = ::testing::Types<
    std::integral_constant<size_t, 25>,   // For k=5, M=2
    std::integral_constant<size_t, 125>,  // For k=5, M=3
    std::integral_constant<size_t, 625>   // For k=5, M=4
>;

TYPED_TEST_SUITE(KWaySortTestFixture, TestSizes);

TYPED_TEST(KWaySortTestFixture, SortTest) {
    constexpr size_t N = TypeParam::value;

    int k = 5;
    int M, d_f, d_g;
    
    switch (N) {
    case 25:
        M = 2;
        d_g = 3;
        d_f = 2;
        break;
    case 125:
        M = 3;
        d_g = 3;
        d_f = 2;
        break;
    case 625:
        M = 4;
        d_g = 4;
        d_f = 2;
        break;
    default:
        FAIL() << "Unsupported array size for k=5: " << N;
        break;
    }
    std::cout << "Sign Configuration: CompositeSign(3, k=" << k 
        << ", M=" << M
        << ", d_g=" << d_g
        << ", d_f=" << d_f << ")" << std::endl;


    std::vector<double> inputArray =
        getVectorWithMinDiff(N, 0, 1, (1.0 - 1e-8) / N);
    std::cout << "Input array size: " << N << std::endl;
    std::cout << "Using Ring Dimension: " << this->m_cc->GetRingDimension()
              << std::endl;
    std::cout << "Multiplicative depth: " << this->m_multDepth << std::endl;
    std::cout << "Scaling Mod: " << this->m_scaleMod << std::endl;

    auto ctxt = this->m_enc->encryptInput(inputArray);

    auto kwaySorter = std::make_unique<KWayAdapter<N>>(
        this->m_cc, this->m_publicKey, this->m_privateKey, this->m_enc,
        k, M
    );

    auto Cfg = SignConfig(CompositeSignConfig(3, d_f, d_g), this->m_multDepth);
    auto start = std::chrono::high_resolution_clock::now();
    Ciphertext<DCRTPoly> ctxt_out =
        kwaySorter->sort(ctxt, SignFunc::CompositeSign, Cfg);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Result Level: " << ctxt_out->GetLevel() << std::endl;

    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxt_out, &result);
    std::vector<double> outputArray = result->GetRealPackedValue();

    auto expected = inputArray;
    std::sort(expected.begin(), expected.end());

    double maxError = 0.0;
    double totalError = 0.0;
    int largeErrorCount = 0;
    int effectiveOutputSize = std::pow(k, M);

    for (int i = 0; i < effectiveOutputSize; ++i) {
        double error = std::abs(outputArray[i] - expected[i]);
        maxError = std::max(maxError, error);
        totalError += error;
        if (error >= 0.01) {
            largeErrorCount++;
        }
    }

    double avgError = totalError / effectiveOutputSize;

    std::cout << "\nPerformance Analysis:" << std::endl;
    std::cout << "Execution time: " << duration.count() << " ms" << std::endl;
    std::cout << "\nError Analysis:" << std::endl;
    std::cout << "Maximum error: " << maxError
              << " (log2: " << std::log2(maxError) << ")" << std::endl;
    std::cout << "Average error: " << avgError
              << " (log2: " << std::log2(avgError) << ")" << std::endl;
    std::cout << "Number of errors >= 0.01: " << largeErrorCount << std::endl;

    ASSERT_LT(maxError, 0.01) << "Maximum error exceeds threshold";
    ASSERT_EQ(largeErrorCount, 0) << "Found errors larger than 0.01";
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}