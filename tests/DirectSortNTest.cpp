#include <algorithm>   
#include <cmath>
#include <gtest/gtest.h>
#include <iomanip>
#include <random>
#include <vector>

#include "openfhe.h"

#include "comparison.h"
#include "encryption.h"
#include "sign.h"
#include "sort_algo.h"
#include "utils.h"


using namespace lbcrypto;

template <size_t N> class DirectSortTest : public ::testing::Test {
  protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        DirectSort<N>::getSizeParameters(parameters, rotations);

        parameters.SetSecurityLevel(HEStd_NotSet);
        // parameters.SetSecurityLevel(HEStd_128_classic);
        auto logRingDim = 13;
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
    Cfg = SignConfig(CompositeSignConfig(3, 6, 3));

    // Construct rank using DirectSort
    auto ctxtRank =
        directSort->constructRank(ctxt, SignFunc::CompositeSign, Cfg);

    // Decrypt the result
    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxtRank, &result);
    std::vector<double> decryptedRanks = result->GetRealPackedValue();
    std::cout << "Calculated ranks: " << decryptedRanks << std::endl;

    // Calculate the expected ranks
    std::vector<double> expectedRanks(N);
    for (size_t i = 0; i < N; ++i) {
        expectedRanks[i] =
            std::count_if(inputArray.begin(), inputArray.end(),
                          [&](double val) { return val < inputArray[i]; });
    }

    double maxError = 0.0;
    double sumLogError = 0.0;
    double maxAbsError = 0.0;
    int errorCount = 0;

    for (size_t i = 0; i < N; ++i) {
        double error = std::abs(decryptedRanks[i] - expectedRanks[i]);
        double logError = error > 0 ? std::log2(error)
                                    : -std::numeric_limits<double>::infinity();

        maxError = std::max(maxError, error);
        maxAbsError = std::max(maxAbsError, std::abs(error));
        if (error > 0) {
            sumLogError += logError;
            errorCount++;
        }
    }

    double avgLogError = errorCount > 0 ? sumLogError / errorCount : 0.0;

    std::cout << "\nRank Error Analysis:" << std::endl;
    std::cout << std::left << std::setw(30) << "Maximum Error:" << maxError
              << std::endl;
    std::cout << std::left << std::setw(30)
              << "Maximum Absolute Error:" << maxAbsError << std::endl;
    std::cout << std::left << std::setw(30)
              << "Average Log2 Error:" << avgLogError << std::endl;

    for (size_t i = 0; i < N; ++i) {
        ASSERT_NEAR(decryptedRanks[i], expectedRanks[i], 0.0001)
            << "Mismatch at index " << i << ": expected " << expectedRanks[i]
            << ", got " << decryptedRanks[i];
    }
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
    auto ctxtResult = directSort->rotationIndexCheck(ctxRank, ctxtInput);

    // Decrypt the result
    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxtResult, &result);
    std::vector<double> outputArray = result->GetRealPackedValue();

    // Expected sorted array
    std::vector<double> expectedArray = inputArray;
    std::sort(expectedArray.begin(), expectedArray.end());

    // Calculate and print error metrics
    double maxError = 0.0;
    double sumLogError = 0.0;
    int errorCount = 0;

    for (size_t i = 0; i < N; ++i) {
        double error = std::abs(outputArray[i] - expectedArray[i]);
        double logError = error > 0 ? std::log2(error)
                                    : -std::numeric_limits<double>::infinity();

        maxError = std::max(maxError, error);
        if (error > 0) {
            sumLogError += logError;
            errorCount++;
        }
    }

    double avgLogError = errorCount > 0 ? sumLogError / errorCount : 0.0;

    std::cout << "\nError Analysis:" << std::endl;
    std::cout << std::left << std::setw(30) << "Maximum Error:" << maxError
              << " (log2: " << std::log2(maxError) << ")" << std::endl;
    std::cout << std::left << std::setw(30)
              << "Average Log2 Error:" << avgLogError << std::endl;
    std::cout << std::left << std::setw(30)
              << "Result Level:" << ctxtResult->GetLevel() << std::endl;

    // Print arrays for visualization
    std::cout << "Output array: " << outputArray << std::endl;
    std::cout << "Expected array: " << expectedArray << std::endl;

    // Compare results
    for (size_t i = 0; i < N; ++i) {
        ASSERT_NEAR(outputArray[i], expectedArray[i], 0.01)
            << "Mismatch at index " << i << ": expected " << expectedArray[i]
            << ", got " << outputArray[i];
    }
}


TYPED_TEST_P(DirectSortTestFixture, RotationIndexCheckWithNoise) {
    constexpr size_t N = TypeParam::value;
    constexpr double NOISE_TOLERANCE = 0.001;

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

    // Add noise to ranks
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(-NOISE_TOLERANCE, NOISE_TOLERANCE);

    std::vector<double> noisyRanks = rankArray;
    for (size_t i = 0; i < N; ++i) {
        noisyRanks[i] += dis(gen);
    }

    std::cout << "Original Rank Array: " << rankArray << std::endl;
    std::cout << "Noisy Rank Array: " << noisyRanks << std::endl;

    // Encrypt input arrays
    auto ctxtInput = this->m_enc->encryptInput(inputArray);
    auto ctxRank = this->m_enc->encryptInput(noisyRanks);

    // Create DirectSort object
    auto directSort = std::make_unique<DirectSort<N>>(
        this->m_cc, this->m_publicKey, this->rotations, this->m_enc);

    auto ctxtResult = directSort->rotationIndexCheck(ctxRank, ctxtInput);

    // Decrypt the result
    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxtResult, &result);
    std::vector<double> outputArray = result->GetRealPackedValue();

    // Expected sorted array
    std::vector<double> expectedArray = inputArray;
    std::sort(expectedArray.begin(), expectedArray.end());

    // Calculate and print error metrics
    double maxError = 0.0;
    double sumLogError = 0.0;
    int errorCount = 0;

    for (size_t i = 0; i < N; ++i) {
        double error = std::abs(outputArray[i] - expectedArray[i]);
        double logError = error > 0 ? std::log2(error)
                                    : -std::numeric_limits<double>::infinity();

        maxError = std::max(maxError, error);
        if (error > 0) {
            sumLogError += logError;
            errorCount++;
        }
    }

    double avgLogError = errorCount > 0 ? sumLogError / errorCount : 0.0;

    std::cout << "\nError Analysis with Noisy Ranks:" << std::endl;
    std::cout << std::left << std::setw(30) << "Maximum Error:" << maxError
              << std::endl;
    std::cout << std::left << std::setw(30)
              << "Average Log2 Error:" << avgLogError << std::endl;
    std::cout << std::left << std::setw(30)
              << "Result Level:" << ctxtResult->GetLevel() << std::endl;

    for (size_t i = 0; i < N; ++i) {
        ASSERT_NEAR(outputArray[i], expectedArray[i], 0.01)
            << "Mismatch at index " << i << ": expected " << expectedArray[i]
            << ", got " << outputArray[i];
    }
}

TYPED_TEST_P(DirectSortTestFixture, SortTest) {
    constexpr size_t N = TypeParam::value;
    std::vector<double> inputArray = getVectorWithMinDiff(N, 0, 1, 1 / (double)N);

    std::cout << "Input array size: " << N << std::endl;
    std::cout << "Multiplicative depth: " << this->m_multDepth << std::endl;
    std::cout << "Input array: " << inputArray << std::endl;

    auto ctxt = this->m_enc->encryptInput(inputArray);

    auto directSort = std::make_unique<DirectSort<N>>(
        this->m_cc, this->m_publicKey, this->rotations, this->m_enc);

    SignConfig Cfg = SignConfig(CompositeSignConfig(3, 6, 3));

    // Get intermediate rank result
    auto ctxt_rank = directSort->constructRank(ctxt, SignFunc::CompositeSign, Cfg);
    
    // Decrypt and analyze rank precision
    Plaintext rank_result;
    this->m_cc->Decrypt(this->m_privateKey, ctxt_rank, &rank_result);
    std::vector<double> rank_array = rank_result->GetRealPackedValue();
    
    // Calculate expected ranks for comparison
    std::vector<double> expected_ranks(N);
    for (size_t i = 0; i < N; ++i) {
        expected_ranks[i] = std::count_if(inputArray.begin(), inputArray.end(),
                                        [&](double val) { return val < inputArray[i]; });
    }
    
    // Calculate rank precision
    double max_rank_error = 0.0;
    double sum_log_rank_error = 0.0;
    int rank_error_count = 0;
    
    for (size_t i = 0; i < N; ++i) {
        double error = std::abs(rank_array[i] - expected_ranks[i]);
        if (error > 0) {
            max_rank_error = std::max(max_rank_error, error);
            sum_log_rank_error += std::log2(error);
            rank_error_count++;
        }
    }
    
    std::cout << "\nRank Calculation Analysis:" << std::endl;
    std::cout << "Maximum rank error: " << max_rank_error
              << " (log2: " << std::log2(max_rank_error) << ")" << std::endl;
    if (rank_error_count > 0) {
        std::cout << "Average log2 rank error: " 
                  << sum_log_rank_error / rank_error_count << std::endl;
    }

    // Perform the final sort
    Ciphertext<DCRTPoly> ctxt_out =
        directSort->sort(ctxt, SignFunc::CompositeSign, Cfg);

    EXPECT_EQ(ctxt_out->GetLevel(), this->m_multDepth)
        << "Use the level returned by the result for best performance";

    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxt_out, &result);
    std::vector<double> output_array = result->GetRealPackedValue();

    auto expected = inputArray;
    std::sort(expected.begin(), expected.end());

    std::cout << "\nFinal Sort Results:" << std::endl;
    std::cout << "Output array: " << output_array << std::endl;
    std::cout << "Expected array: " << expected << std::endl;

    double maxError = 0.0;
    int largeErrorCount = 0;
    for (size_t i = 0; i < output_array.size(); ++i) {
        double error = std::abs(output_array[i] - expected[i]);
        maxError = std::max(maxError, error);
        if (error >= 0.01) {
            largeErrorCount++;
        }
    }

    std::cout << "\nSort Error Analysis:" << std::endl;
    std::cout << "Maximum error: " << maxError
              << ", log2: " << std::log2(maxError) << "\n";
    std::cout << "Number of errors larger than 0.01: " << largeErrorCount
              << "\n";

    ASSERT_LT(maxError, 0.01);
}

REGISTER_TYPED_TEST_SUITE_P(DirectSortTestFixture, SortTest, ConstructRank,
                            RotationIndexCheck, RotationIndexCheckWithNoise);


using TestSizes = ::testing::Types<
    std::integral_constant<size_t, 4>, std::integral_constant<size_t, 8>,
    std::integral_constant<size_t, 16>, std::integral_constant<size_t, 32>,
    std::integral_constant<size_t, 64>, 
    std::integral_constant<size_t, 128>,
    std::integral_constant<size_t, 256>, 
    std::integral_constant<size_t, 512>,
    std::integral_constant<size_t, 1024>,
    std::integral_constant<size_t, 2048>
>;

INSTANTIATE_TYPED_TEST_SUITE_P(DirectSort, DirectSortTestFixture, TestSizes);
