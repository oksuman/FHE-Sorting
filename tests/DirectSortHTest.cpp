#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
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
namespace fs = std::filesystem;

template <size_t N>
class HybridSortTest : public ::testing::Test {
protected:
    void SetupParameters() {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetBatchSize(N);
        
        // Set up rotation keys based on array size
        switch (N) {
        case 4:
            m_multDepth = 45;
            m_scaleMod = 48;
            // rotations = {0, 1, 2, 4, 8, 16};
            rotations = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            break;
        case 8:
            m_multDepth = 45;
            m_scaleMod = 48;
            rotations = {1, 2, 3, 4, 8, 12, 16, 32, 64, 128, 256};
            break;
        case 16:
            m_multDepth = 45;
            m_scaleMod = 48;
            rotations = {1, 2, 3, 4, 8, 12, 16, 32, 64, 128, 256};
            break;
        case 32:
            m_multDepth = 45;
            m_scaleMod = 48;
            rotations = {1, 2, 3, 4, 8, 12, 16, 20, 24, 28, 32, 64, 128, 256, 512, 1024};
            break;
        case 64:
            m_multDepth = 29;
            m_scaleMod = 48;
            rotations = {1, 2, 3, 4, 5, 6, 7, 8, 16, 24, 32, 40, 48, 56, 64, 128, 256, 512, 1024, 2048, 4096};
            break;
        case 128:
            m_multDepth = 30;
            m_scaleMod = 48;
            rotations = {1, 2, 3, 4, 5, 6, 7, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 
                        256, 512, 1024, 2048, 4096, 8192, 16384};
            break;
        case 256:
            m_multDepth = 34;
            m_scaleMod = 48;
            // Add other rotation indices for N=256
            rotations = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 32, 40, 48, 56, 64, 72, 80, 
                        88, 96, 104, 112, 120, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768};
            break;
        default:
            throw std::runtime_error("Unsupported array size");
        }

        parameters.SetSecurityLevel(HEStd_128_classic);
        parameters.SetRingDim(1 << 17);  // 2^17
        parameters.SetScalingModSize(m_scaleMod);
        parameters.SetMultiplicativeDepth(m_multDepth);
        
        m_cc = GenCryptoContext(parameters);
        
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);
    }

    void SetUp() override {
        SetupParameters();

        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);
        
        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
    }

    void SaveResults(const std::string &filename, size_t arraySize,
                    int logRingDim, const SignConfig &cfg, double maxError, 
                    double avgError, double executionTimeMs) {
        fs::create_directories("hybrid_results");

        std::ofstream outFile("hybrid_results/" + filename, std::ios::app);
        outFile << std::fixed << std::setprecision(6);
        outFile << "Array Size (N): " << arraySize << "\n";
        outFile << "Ring Dimension: 2^" << logRingDim << "\n";
        outFile << "Multiplicative Depth: " << m_multDepth << "\n";
        outFile << "Scaling Mod Size: " << m_scaleMod << "\n";
        outFile << "Sign Configuration (degree, dg, df): (" << cfg.compos.n
                << ", " << cfg.compos.dg << ", " << cfg.compos.df << ")\n";
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
    int m_scaleMod;
};

template <typename T>
class HybridSortTestFixture : public HybridSortTest<T::value> {};

TYPED_TEST_SUITE_P(HybridSortTestFixture);

TYPED_TEST_P(HybridSortTestFixture, SortHybridTest) {
    constexpr size_t N = TypeParam::value;
    std::vector<double> inputArray = getVectorWithMinDiff(N, 0, 1, 1 / (double)N);

    std::cout << "Input array size: " << N << std::endl;
    std::cout << "Multiplicative depth: " << this->m_multDepth << std::endl;
    std::cout << "Scaling Mod: " << this->m_scaleMod << std::endl;

    auto ctxt = this->m_enc->encryptInput(inputArray);

    auto directSort = std::make_unique<DirectSort<N>>(
        this->m_cc, this->m_publicKey, this->rotations, this->m_enc);

    SignConfig Cfg;
    if (N <= 16)
        Cfg = SignConfig(CompositeSignConfig(3, 2, 2));
    else if (N <= 128)
        Cfg = SignConfig(CompositeSignConfig(3, 3, 2));
    else if (N <= 512)
        Cfg = SignConfig(CompositeSignConfig(3, 4, 2));
    else
        Cfg = SignConfig(CompositeSignConfig(3, 5, 2));

    // Start timing
    auto start = std::chrono::high_resolution_clock::now();

    // Perform the hybrid sort
    Ciphertext<DCRTPoly> ctxt_out = directSort->sort_hybrid(ctxt, SignFunc::CompositeSign, Cfg);

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
    std::cout << "Maximum error: " << maxError << " (log2: " << std::log2(maxError) << ")" << std::endl;
    std::cout << "Average error: " << avgError << " (log2: " << std::log2(avgError) << ")" << std::endl;
    std::cout << "Number of errors larger than 0.01: " << largeErrorCount << std::endl;

    // Save results to file
    std::string filename = "hybrid_sort_results_N" + std::to_string(N) + ".txt";
    this->SaveResults(filename, N, 17, Cfg, maxError, avgError, duration.count());

    ASSERT_LT(maxError, 0.01);
}

REGISTER_TYPED_TEST_SUITE_P(HybridSortTestFixture, SortHybridTest);

using TestSizes = ::testing::Types<
    std::integral_constant<size_t, 4>,
    std::integral_constant<size_t, 8>,
    std::integral_constant<size_t, 16>,
    std::integral_constant<size_t, 32>,
    std::integral_constant<size_t, 64>,
    std::integral_constant<size_t, 128>,
    std::integral_constant<size_t, 256>>;

INSTANTIATE_TYPED_TEST_SUITE_P(HybridSort, HybridSortTestFixture, TestSizes);