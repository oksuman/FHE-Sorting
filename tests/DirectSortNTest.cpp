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
        // parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetSecurityLevel(HEStd_128_classic);
        // constexpr int maxSlotRequirement = 2 * N * N;
        // auto logRingDim = ((int)log2(maxSlotRequirement) + 1);
        // auto logRingDim = 17;
        // parameters.SetRingDim(1 << logRingDim);

        // std::cout << "Ring Dimension 2^" << logRingDim << "\n";

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

TYPED_TEST_P(DirectSortTestFixture, ConstructRank) {
    constexpr size_t N = TypeParam::value;

    std::vector<double> inputArray =
        getVectorWithMinDiff(N, 0, 1, 1 / (double)N);

    std::cout << "Input array: " << inputArray << "\n";

    // Encrypt the input array
    auto ctxt = this->m_enc->encryptInput(inputArray);
    auto directSort = std::make_unique<DirectSort<N>>(
        this->m_cc, this->m_publicKey, this->rotations, this->m_enc);

    SignConfig Cfg;
    if (N < 256)
        Cfg = SignConfig(CompositeSignConfig(3, 3, 6));
    else
        Cfg = SignConfig(CompositeSignConfig(3, 4, 10));

    // Construct rank using DirectSort
    auto ctxtRank =
        directSort->constructRankGeneral(ctxt, SignFunc::CompositeSign, Cfg);

    // Decrypt the result
    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxtRank, &result);
    std::vector<double> decryptedRanks = result->GetRealPackedValue();

    // Calculate the expected ranks
    std::vector<double> expectedRanks(N);
    for (size_t i = 0; i < N; ++i) {
        expectedRanks[i] =
            std::count_if(inputArray.begin(), inputArray.end(),
                          [&](double val) { return val < inputArray[i]; });
    }

    // Compare the results
    for (size_t i = 0; i < N; ++i) {
        ASSERT_NEAR(decryptedRanks[i], expectedRanks[i], 0.0001)
            << "Mismatch at index " << i << ": expected " << expectedRanks[i]
            << ", got " << decryptedRanks[i];
    }

    // Print the input array and the calculated ranks
    std::cout << "Input array: " << inputArray << std::endl;
    std::cout << "Calculated ranks: " << decryptedRanks << std::endl;
}

TYPED_TEST_P(DirectSortTestFixture, RotationIndexCheck) {
    constexpr size_t N = TypeParam::value;

    std::vector<double> inputArray =
        getVectorWithMinDiff(N, 0, 1, 1 / (double)N);
    std::cout << "Input array: " << inputArray << std::endl;

    // Calculate the rank array
    std::vector<double> rankArray(N);
    for (size_t i = 0; i < N; ++i) {
        rankArray[i] =
            std::count_if(inputArray.begin(), inputArray.end(),
                          [&](double val) { return val < inputArray[i]; });
    }
    std::cout << "Rank Array: " << rankArray << std::endl;

    // Encrypt input arrays
    auto ctxtInput = this->m_enc->encryptInput(inputArray);
    auto ctxRank = this->m_enc->encryptInput(rankArray);

    // Create DirectSort object
    auto directSort = std::make_unique<DirectSort<N>>(
        this->m_cc, this->m_publicKey, this->rotations, this->m_enc);

    // Call rotationIndexCheck
    auto ctxtResult = directSort->rotationIndexCheckGeneral(ctxRank, ctxtInput);

    // Decrypt the result
    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxtResult, &result);
    std::vector<double> outputArray = result->GetRealPackedValue();

    // Expected sorted array
    std::vector<double> expectedArray = inputArray;
    std::sort(expectedArray.begin(), expectedArray.end());

    // Print arrays for visualization
    std::cout << "Input array: " << inputArray << std::endl;
    std::cout << "Rank array: " << rankArray << std::endl;
    std::cout << "Output array: " << outputArray << std::endl;
    std::cout << "Expected array: " << expectedArray << std::endl;

    // Check the level of the result
    std::cout << "Result level: " << ctxtResult->GetLevel() << std::endl;

    // Compare results
    for (size_t i = 0; i < N; ++i) {
        ASSERT_NEAR(outputArray[i], expectedArray[i], 0.01)
            << "Mismatch at index " << i << ": expected " << expectedArray[i]
            << ", got " << outputArray[i];
    }
}
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

    SignConfig Cfg;
    if (N < 128)
        Cfg = SignConfig(CompositeSignConfig(3, 6, 3));
    else if (N == 128)
        Cfg = SignConfig(CompositeSignConfig(3, 8, 3));
    else
        Cfg = SignConfig(CompositeSignConfig(3, 9, 4));

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

REGISTER_TYPED_TEST_SUITE_P(DirectSortTestFixture, SortTest, ConstructRank,
                            RotationIndexCheck);

using TestSizes = ::testing::Types<
    // std::integral_constant<size_t, 4>, std::integral_constant<size_t, 8>,
    // std::integral_constant<size_t, 16>, std::integral_constant<size_t, 32>,
    // std::integral_constant<size_t, 64>, std::integral_constant<size_t, 128>,
    std::integral_constant<size_t, 256>, std::integral_constant<size_t, 512>,
    std::integral_constant<size_t, 1024>>;

INSTANTIATE_TYPED_TEST_SUITE_P(DirectSort, DirectSortTestFixture, TestSizes);
