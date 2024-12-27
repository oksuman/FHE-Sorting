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
        // Set up the CryptoContext
        CCParams<CryptoContextCKKSRNS> parameters;
        KWayAdapter<N>::getSizeParameters(parameters, rotations);

        parameters.SetSecurityLevel(HEStd_NotSet);
        constexpr usint ringDim = 1 << 12;
        parameters.SetRingDim(ringDim);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);
        m_cc->Enable(FHE);

        // N is not equal to number of slots when k=3,5
        m_numSlots = m_cc->GetEncodingParams()->GetBatchSize();

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
        m_cc->EvalBootstrapSetup(levelBudget, bsgsDim, m_numSlots);
        m_cc->EvalBootstrapKeyGen(m_privateKey, m_numSlots);

        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
        m_multDepth = parameters.GetMultiplicativeDepth();
    }

    std::vector<int> rotations;
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
    int m_multDepth;
    int m_numSlots;
};

template <typename T>
class KWaySortTestFixture : public KWaySortTest<T::value> {};

using TestSizes =
    ::testing::Types<std::integral_constant<size_t, 81>,  // For k=3, M=4
                     std::integral_constant<size_t, 125>, // For k=5, M=3
                     std::integral_constant<size_t, 128>  // For k=2, M=7
                     >;

TYPED_TEST_SUITE(KWaySortTestFixture, TestSizes);

TYPED_TEST(KWaySortTestFixture, SortTest) {
    constexpr size_t N = TypeParam::value;

    // Configure k and M based on array size
    int k, M, d_f, d_g;
    if constexpr (N == 128) {
        k = 2;
        M = 7;
        d_f = 2;
        d_g = 5;
        std::cout << "Testing configuration: k=2, M=7, N=128" << std::endl;
    } else if constexpr (N == 81) {
        k = 3;
        M = 4;
        d_f = 2;
        d_g = 5;
        std::cout << "Testing configuration: k=3, M=4, N=81" << std::endl;
    } else if constexpr (N == 125) {
        k = 5;
        M = 3;
        d_f = 2;
        d_g = 5;
        std::cout << "Testing configuration: k=5, M=3, N=125" << std::endl;
    } else {
        FAIL() << "Unsupported array size: " << N;
    }

    // Generate random input array with minimum difference
    std::vector<double> inputArray = getVectorWithMinDiff(N, 0, 1, 1.0 / N);
    std::cout << "Input array: " << inputArray << std::endl;

    // Encrypt input
    auto ctxt = this->m_enc->encryptInput(inputArray);

    // Create KWayAdapter with specified parameters
    auto kwaySorter = std::make_unique<KWayAdapter<N>>(
        this->m_cc, this->m_publicKey, this->m_privateKey, this->m_enc,
        k,   // k-way factor
        M,   // M parameter
        d_f, // d_f parameter
        d_g  // d_g parameter
    );

    // Sort using k-way algorithm
    auto Cfg = SignConfig(CompositeSignConfig(3, 3, 6));
    Ciphertext<DCRTPoly> ctxt_out =
        kwaySorter->sort(ctxt, SignFunc::CompositeSign, Cfg);

    // Decrypt result
    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxt_out, &result);
    std::vector<double> outputArray = result->GetRealPackedValue();

    // Calculate expected sorted array
    auto expected = inputArray;
    std::sort(expected.begin(), expected.end());

    // Calculate error metrics
    double maxError = 0.0;
    int largeErrorCount = 0;
    int effectiveOutputSize = std::pow(k, M);
    for (size_t i = 0; i < effectiveOutputSize; ++i) {
        double error = std::abs(outputArray[i] - expected[i]);
        maxError = std::max(maxError, error);
        if (error >= 0.01) {
            largeErrorCount++;
            std::cout << "Large error at index " << i
                      << ": expected=" << expected[i]
                      << ", got=" << outputArray[i] << ", error=" << error
                      << std::endl;
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
