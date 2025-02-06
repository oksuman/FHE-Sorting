#include <algorithm>   
#include <cmath>
#include <gtest/gtest.h>
#include <iomanip>
#include <random>
#include <vector>
#include <chrono>
#include <filesystem>
#include <fstream>

#include "openfhe.h"

#include "comparison.h"
#include "encryption.h"
#include "sign.h"
#include "sort_algo.h"
#include "utils.h"

using namespace lbcrypto;
namespace fs = std::filesystem;

template <size_t N> class DirectSortTest : public ::testing::Test {
protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        DirectSort<N>::getSizeParameters(parameters, rotations);

        parameters.SetSecurityLevel(HEStd_NotSet);
        auto logRingDim = 17;
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

    void SaveResults(const std::string& filename, 
                    size_t arraySize,
                    int logRingDim,
                    int multDepth,
                    int scalingModSize,
                    const SignConfig& cfg,
                    double maxError,
                    double avgError,
                    double executionTimeMs) {
        // Create directory if it doesn't exist
        fs::create_directories("ours_results");
        
        std::ofstream outFile("ours_results/" + filename, std::ios::app);
        outFile << std::fixed << std::setprecision(6);
        outFile << "Array Size (N): " << arraySize << "\n";
        outFile << "Ring Dimension: 2^" << logRingDim << "\n";
        outFile << "Multiplicative Depth: " << multDepth << "\n";
        outFile << "Scaling Mod Size: " << scalingModSize << "\n";
        outFile << "Sign Configuration (degree, dg, df): (" 
               << cfg.degree << ", " << cfg.dg << ", " << cfg.df << ")\n";
        outFile << "Max Error: " << maxError << " (log2: " << std::log2(maxError) << ")\n";
        outFile << "Average Error: " << avgError << " (log2: " << std::log2(avgError) << ")\n";
        outFile << "Execution Time: " << executionTimeMs << " ms\n";
        outFile << "----------------------------------------\n";
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
    std::vector<double> inputArray = getVectorWithMinDiff(N, 0, 1, 1 / (double)N);

    std::cout << "Input array size: " << N << std::endl;
    std::cout << "Multiplicative depth: " << this->m_multDepth << std::endl;

    auto ctxt = this->m_enc->encryptInput(inputArray);

    auto directSort = std::make_unique<DirectSort<N>>(
        this->m_cc, this->m_publicKey, this->rotations, this->m_enc);

    SignConfig Cfg;
    if (N <= 16)
        Cfg = SignConfig(CompositeSignConfig(3, 2, 2));
    else if(N <= 128)
        Cfg = SignConfig(CompositeSignConfig(3, 3, 2));
    else
        Cfg = SignConfig(CompositeSignConfig(3, 4, 2));

    // Start timing
    auto start = std::chrono::high_resolution_clock::now();

    // Perform the sort
    Ciphertext<DCRTPoly> ctxt_out =
        directSort->sort(ctxt, SignFunc::CompositeSign, Cfg);

    // End timing
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    EXPECT_EQ(ctxt_out->GetLevel(), this->m_multDepth)
        << "Use the level returned by the result for best performance";

    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxt_out, &result);
    std::vector<double> output_array = result->GetRealPackedValue();

    auto expected = inputArray;
    std::sort(expected.begin(), expected.end());

    // Calculate errors
    double maxError = 0.0;
    double totalError = 0.0;
    int largeErrorCount = 0;

    for (size_t i = 0; i < output_array.size(); ++i) {
        double error = std::abs(output_array[i] - expected[i]);
        maxError = std::max(maxError, error);
        totalError += error;
        if (error >= 0.01) {
            largeErrorCount++;
        }
    }

    double avgError = totalError / output_array.size();

    // Print results to console
    std::cout << "\nPerformance Analysis:" << std::endl;
    std::cout << "Execution time: " << duration.count() << " ms" << std::endl;
    std::cout << "\nError Analysis:" << std::endl;
    std::cout << "Maximum error: " << maxError 
              << " (log2: " << std::log2(maxError) << ")" << std::endl;
    std::cout << "Average error: " << avgError 
              << " (log2: " << std::log2(avgError) << ")" << std::endl;
    std::cout << "Number of errors larger than 0.01: " << largeErrorCount << std::endl;

    // Save results to file
    std::string filename = "sort_results_N" + std::to_string(N) + ".txt";
    this->SaveResults(filename, 
                     N,
                     17, // logRingDim
                     this->m_multDepth,
                     this->m_cc->GetEncodingParams()->GetScalingModSize(),
                     Cfg,
                     maxError,
                     avgError,
                     duration.count());

    ASSERT_LT(maxError, 0.01);
}


REGISTER_TYPED_TEST_SUITE_P(DirectSortTestFixture, SortTest);

using TestSizes = ::testing::Types<
    // std::integral_constant<size_t, 4>, 
    // std::integral_constant<size_t, 8>,
    // std::integral_constant<size_t, 16>, 
    // std::integral_constant<size_t, 32>,
    // std::integral_constant<size_t, 64>, 
    // std::integral_constant<size_t, 128>,
    // std::integral_constant<size_t, 256>, 
    std::integral_constant<size_t, 512>,
    std::integral_constant<size_t, 1024>,
    std::integral_constant<size_t, 2048>
>;

INSTANTIATE_TYPED_TEST_SUITE_P(DirectSort, DirectSortTestFixture, TestSizes);