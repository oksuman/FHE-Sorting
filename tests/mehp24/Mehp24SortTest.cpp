#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iomanip>
#include <random>
#include <vector>

#include "../utils.h"
#include "comparison.h"
#include "encryption.h"
#include "mehp24_sort.h"
#include "mehp24_utils.h"
#include "openfhe.h"

using namespace lbcrypto;
using namespace std::chrono;
namespace fs = std::filesystem;

template <int N> class MEHPSortTest : public ::testing::Test {
  protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;

        // parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetSecurityLevel(HEStd_128_classic);
        auto logRingDim = 17;
        // parameters.SetRingDim(1 << logRingDim);
        auto batchSize = std::min(N * N, (1 << logRingDim) / 2);
        std::cout << "batch size: " << batchSize << std::endl;
        parameters.SetBatchSize(batchSize);

        switch (N) {
        case 4:
            m_multDepth = 31;
            break;
        case 8:
            m_multDepth = 35;
            break;
        case 16:
            m_multDepth = 35;
            break;
        case 32:
            m_multDepth = 42;
            break;
        case 64:
            m_multDepth = 42;
            break;
        case 128:
            m_multDepth = 46;
            break;
        case 256:
            m_multDepth = 49;
            break;
        case 512:
            m_multDepth = 57;
            break;
        case 1024:
            m_multDepth = 60;
            break;
        case 2048:
            m_multDepth = 64;
            break;
        default:
            break;
        }
        m_scaleMod = 40;
        parameters.SetMultiplicativeDepth(m_multDepth);
        parameters.SetScalingModSize(m_scaleMod);

        m_cc = GenCryptoContext(parameters);
        std::cout << "Using Ring Dimension: " << m_cc->GetRingDimension()
                  << std::endl;
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        m_cc->EvalMultKeyGen(m_privateKey);
        rotations = mehp24::utils::getRotationIndices(N);
        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);
        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
        comp = std::make_unique<Comparison>(m_enc);
    }

    void SaveResults(const std::string &filename, size_t arraySize,
                     int logRingDim, int multDepth, int scalingModSize,
                     uint32_t dg_i, uint32_t df_i, // indicator configuration
                     double maxError, double avgError, double executionTimeMs,
                     int resultLevel) {
        // Create directory if it doesn't exist
        fs::create_directories("ours_results");

        std::ofstream outFile("ours_results/" + filename, std::ios::app);
        outFile << std::fixed << std::setprecision(6);
        outFile << "Array Size (N): " << arraySize << "\n";
        outFile << "Ring Dimension: 2^" << logRingDim << "\n";
        outFile << "Multiplicative Depth: " << multDepth << "\n";
        outFile << "Scaling Mod Size: " << scalingModSize << "\n";
        // outFile << "Comparison Configuration (degree, dg, df): (3, " << dg_c
        // << ", " << df_c << ")\n";
        outFile << "Indicator Configuration (dg_i, df_i): (" << dg_i << ", "
                << df_i << ")\n";
        outFile << "Max Error: " << maxError
                << " (log2: " << std::log2(maxError) << ")\n";
        outFile << "Average Error: " << avgError
                << " (log2: " << std::log2(avgError) << ")\n";
        outFile << "Execution Time: " << executionTimeMs << " ms\n";
        outFile << "Result Level: " << resultLevel << "\n";
        outFile << "----------------------------------------\n";
    }

    std::vector<int> rotations;
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
    std::unique_ptr<Comparison> comp;
    int m_multDepth;
    int m_scaleMod;
};

template <typename T>
class MEHPSortTestFixture : public MEHPSortTest<T::value> {};

TYPED_TEST_SUITE_P(MEHPSortTestFixture);

TYPED_TEST_P(MEHPSortTestFixture, SortFGTest) {
    constexpr size_t N = TypeParam::value;

    std::vector<double> inputArray =
        getVectorWithMinDiff(N, 0, 1, 1 / (double)N);
    std::cout << "Input array size: " << N << std::endl;
    std::cout << "Ring Dimension: " << this->m_cc->GetRingDimension()
              << std::endl;
    std::cout << "Multiplicative depth: " << this->m_multDepth << std::endl;
    std::cout << "Scaling size: " << this->m_scaleMod << std::endl;
    // std::cout << "Input array: " << inputArray << std::endl;

    auto ctxt = this->m_enc->encryptInput(inputArray);

    SignConfig Cfg;
    if (N <= 16)
        Cfg = SignConfig(CompositeSignConfig(3, 2, 2));
    else if (N <= 128)
        Cfg = SignConfig(CompositeSignConfig(3, 3, 2));
    else if (N <= 512)
        Cfg = SignConfig(CompositeSignConfig(3, 4, 2));
    else
        Cfg = SignConfig(CompositeSignConfig(3, 5, 2));

    uint32_t dg_i = (log2(N) + 1) / 2; // N = vectorLength
    uint32_t df_i = 2;

    Ciphertext<DCRTPoly> ctxt_out;
    auto start = high_resolution_clock::now();
    if (N <= 256)
        ctxt_out =
            mehp24::sortFG(ctxt, N, SignFunc::CompositeSign, Cfg, this->comp,
                           dg_i, df_i, this->m_privateKey, this->m_cc);
    else {
        const size_t subLength = 256;
        ctxt_out = mehp24::sortLargeArrayFG(ctxt, N, subLength,
                                            SignFunc::CompositeSign, Cfg,
                                            this->comp, dg_i, df_i, this->m_cc);
    }

    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start).count();

    Plaintext result;
    this->m_cc->Decrypt(this->m_privateKey, ctxt_out, &result);
    std::vector<double> outputArray = result->GetRealPackedValue();

    std::vector<double> expectedArray = inputArray;
    std::sort(expectedArray.begin(), expectedArray.end());

    // Calculate errors
    double maxError = 0.0;
    double totalError = 0.0;
    int largeErrorCount = 0;

    for (size_t i = 0; i < N; ++i) {
        double error = std::abs(outputArray[i] - expectedArray[i]);
        maxError = std::max(maxError, error);
        totalError += error;
        if (error >= 0.01) {
            largeErrorCount++;
        }
    }

    double avgError = totalError / N;

    std::cout << "\nSort Error Analysis:" << std::endl;
    std::cout << "Maximum error: " << maxError
              << " (log2: " << std::log2(maxError) << ")" << std::endl;
    std::cout << "Average error: " << avgError
              << " (log2: " << std::log2(avgError) << ")" << std::endl;
    std::cout << "Number of errors >= 0.01: " << largeErrorCount << std::endl;
    std::cout << "Sorting time: " << duration << " ms" << std::endl;
    std::cout << "Result Level: " << ctxt_out->GetLevel() << std::endl;

    // Save results to file
    std::string filename = "mehp_sort_results_N" + std::to_string(N) + ".txt";
    this->SaveResults(filename, N,
                      17, // logRingDim
                      this->m_multDepth, this->m_scaleMod, dg_i, df_i, maxError,
                      avgError, duration, ctxt_out->GetLevel());

    ASSERT_LT(maxError, 0.01);
}

REGISTER_TYPED_TEST_SUITE_P(MEHPSortTestFixture, SortFGTest);

using TestSizes = ::testing::Types<
    std::integral_constant<size_t, 4>, std::integral_constant<size_t, 8>,
    std::integral_constant<size_t, 16>, std::integral_constant<size_t, 32>,
    std::integral_constant<size_t, 64>, std::integral_constant<size_t, 128>,
    std::integral_constant<size_t, 256>, std::integral_constant<size_t, 512>,
    std::integral_constant<size_t, 1024>, std::integral_constant<size_t, 2048>>;

INSTANTIATE_TYPED_TEST_SUITE_P(MEHPSort, MEHPSortTestFixture, TestSizes);