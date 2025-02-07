/*
 * This code implements algorithms from:
 * "Efficient Ranking, Order Statistics, and Sorting under CKKS"
 * by Federico Mazzone, Maarten H. Everts, Florian Hahn, and Andreas Peter
 * (https://doi.org/10.48550/arXiv.2412.15126)
 *
 * Parts of this implementation are based on:
 * https://github.com/FedericoMazzone/openfhe-statistics
 * Copyright (c) 2024 Federico Mazzone
 * Licensed under BSD 2-Clause License
 *
 * Modified and adapted by oksuman 
 */
#include <algorithm>   
#include <cmath>
#include <gtest/gtest.h>
#include <iomanip>
#include <random>
#include <vector>
#include <chrono>
#include <memory>
#include <omp.h>

// OpenFHE includes
#include "openfhe.h"
#include "ciphertext-fwd.h"
#include "lattice/hal/lat-backend.h"

// Project specific includes
#include "comparison.h"
#include "encryption.h"
#include "sign.h"
#include "utils.h"
#include "generated_coeffs.h"

using namespace lbcrypto;

template <size_t N> class SincComparisonTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_multDepth = 30;
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 17);  
        parameters.SetMultiplicativeDepth(m_multDepth);  

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        m_cc->EvalMultKeyGen(m_privateKey);
        m_enc = std::make_shared<DebugEncryption>(m_cc, keyPair);
        comp = std::make_unique<Comparison>(m_enc);

    }

    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::shared_ptr<DebugEncryption> m_enc;
    std::unique_ptr<Comparison> comp;
    int m_multDepth;
};

template <typename T>
class SincComparisonTestFixture : public SincComparisonTest<T::value> {};

TYPED_TEST_SUITE_P(SincComparisonTestFixture);

TYPED_TEST_P(SincComparisonTestFixture, CompareApproximations) {
    constexpr size_t N = TypeParam::value;
    const size_t ringDim = this->m_cc->GetRingDimension();
    const size_t vectorLength = std::min(2*N*N, ringDim / 2);
    
    std::vector<double> inputArray(vectorLength);
    std::vector<double> expectedOutput(vectorLength, 0.0);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<long long> dis(-2LL * N, 2LL * N);

    int zeroCount = 0;

    for (size_t i = 0; i < vectorLength; i++) {
        long long randomVal = dis(gen);
        inputArray[i] = randomVal / (2.0 * N);
        if (std::abs(inputArray[i]) < 1e-10) {
            expectedOutput[i] = 1.0;
            zeroCount++;
        }
    }

    if (zeroCount == 0) {
        size_t zeroPos = gen() % vectorLength;
        inputArray[zeroPos] = 0.0;
        expectedOutput[zeroPos] = 1.0;
        zeroCount = 1;
    }

    std::cout << "\n=== Test Configuration ===" << std::endl;
    std::cout << "Ring dimension: " << ringDim << std::endl;
    std::cout << "Vector Length: " << vectorLength << std::endl;
    std::cout << "N value: " << N << std::endl;
    
    auto ctxt = this->m_enc->encryptInput(inputArray);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    static const auto &sincCoefficients = selectCoefficients<N>();
    auto chebResult = this->m_cc->EvalChebyshevSeriesPS(ctxt, sincCoefficients, -1, 1);
    auto end_time = std::chrono::high_resolution_clock::now();
    auto cheb_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    Plaintext chebPlaintext;
    this->m_cc->Decrypt(this->m_privateKey, chebResult, &chebPlaintext);
    std::vector<double> chebOutput = chebPlaintext->GetRealPackedValue();
    
    start_time = std::chrono::high_resolution_clock::now();
    SignConfig signConfig;
    
    if(N <= 128)
        signConfig = SignConfig(CompositeSignConfig(3, 4, 2));
    else if(N <= 512)
        signConfig = SignConfig(CompositeSignConfig(3, 5, 2));
    else
        signConfig = SignConfig(CompositeSignConfig(3, 6, 2));

    // auto c1 = this->m_cc->EvalAdd(ctxt, 0.5 / (2*N));
    // auto c2 = this->m_cc->EvalSub(ctxt, 0.5 / (2*N));
    // auto s1 = sign(c1, this->m_cc, SignFunc::CompositeSign, signConfig);
    // auto s2 = sign(c2, this->m_cc, SignFunc::CompositeSign, signConfig);

    // s1 = this->m_cc->EvalAdd(s1, 1.0);
    // this->m_cc->EvalMultInPlace(s1, 0.5);
    // s2 = this->m_cc->EvalAdd(s2, 1.0);
    // this->m_cc->EvalMultInPlace(s2, 0.5);

    // auto signResult = this->m_cc->EvalMultAndRelinearize(s1, this->m_cc->EvalSub(1.0, s2));
    const double c = 0.5 / (2*N);
    auto signResult = this->comp->indicator(this->m_cc, ctxt, c, SignFunc::CompositeSign, signConfig);
    end_time = std::chrono::high_resolution_clock::now();
    auto sign_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    Plaintext signPlaintext;
    this->m_cc->Decrypt(this->m_privateKey, signResult, &signPlaintext);
    std::vector<double> signOutput = signPlaintext->GetRealPackedValue();
    
    double maxChebError = 0.0;
    double maxSignError = 0.0;
    double avgChebError = 0.0;
    double avgSignError = 0.0;
    double avgChebAccuracy = 0.0;
    double avgSignAccuracy = 0.0;
    size_t maxChebErrorIdx = 0;
    size_t maxSignErrorIdx = 0;
    
    for (size_t i = 0; i < vectorLength; i++) {
        double chebErr = std::abs(chebOutput[i] - expectedOutput[i]);
        double signErr = std::abs(signOutput[i] - expectedOutput[i]);
        
        if (chebErr > maxChebError) {
            maxChebError = chebErr;
            maxChebErrorIdx = i;
        }
        if (signErr > maxSignError) {
            maxSignError = signErr;
            maxSignErrorIdx = i;
        }
        
        avgChebAccuracy += 1.0 - chebErr;
        avgSignAccuracy += 1.0 - signErr;
        
        avgChebError += chebErr;
        avgSignError += signErr;
    }
    
    avgChebError /= vectorLength;
    avgSignError /= vectorLength;
    avgChebAccuracy /= vectorLength;
    avgSignAccuracy /= vectorLength;
    
    double chebLogPrecision = std::log2(avgChebError);
    double signLogPrecision = std::log2(avgSignError);
    
    std::cout << std::fixed << std::setprecision(6);
    std::cout << "\n=== Performance Analysis ===" << std::endl;
    std::cout << "\nChebyshev Approximation:" << std::endl;
    std::cout << "  Time: " << cheb_duration.count() << "ms" << std::endl;
    std::cout << "  Average Error: " << avgChebError << std::endl;
    std::cout << "  Average Accuracy: " << avgChebAccuracy * 100 << "%" << std::endl;
    std::cout << "  Log Precision: " << chebLogPrecision << std::endl;
    std::cout << "  Final Level: " << chebResult->GetLevel() << std::endl;
    std::cout << "\n  Max Error Point (index " << maxChebErrorIdx << "):" << std::endl;
    std::cout << "    Input value: " << inputArray[maxChebErrorIdx] << std::endl;
    std::cout << "    Expected: " << expectedOutput[maxChebErrorIdx] << std::endl;
    std::cout << "    Actual: " << chebOutput[maxChebErrorIdx] << std::endl;
    std::cout << "    Error: " << maxChebError << std::endl;
    
    std::cout << "\nSign-based Approximation:" << std::endl;
    std::cout << "  Time: " << sign_duration.count() << "ms" << std::endl;
    std::cout << "  Average Error: " << avgSignError << std::endl;
    std::cout << "  Average Accuracy: " << avgSignAccuracy * 100 << "%" << std::endl;
    std::cout << "  Log Precision: " << signLogPrecision << std::endl;
    std::cout << "  Final Level: " << signResult->GetLevel() << std::endl;
    std::cout << "\n  Max Error Point (index " << maxSignErrorIdx << "):" << std::endl;
    std::cout << "    Input value: " << inputArray[maxSignErrorIdx] << std::endl;
    std::cout << "    Expected: " << expectedOutput[maxSignErrorIdx] << std::endl;
    std::cout << "    Actual: " << signOutput[maxSignErrorIdx] << std::endl;
    std::cout << "    Error: " << maxSignError << std::endl;

    
    ASSERT_LT(maxChebError, 0.1) << "Chebyshev approximation error too large";
    ASSERT_LT(maxSignError, 0.1) << "Sign-based approximation error too large";
}

// Register only the sinc comparison test
REGISTER_TYPED_TEST_SUITE_P(SincComparisonTestFixture, CompareApproximations);

// Define the test sizes
using TestSizes = ::testing::Types<
    std::integral_constant<size_t, 4>,
    std::integral_constant<size_t, 8>,
    std::integral_constant<size_t, 16>,
    std::integral_constant<size_t, 32>,
    std::integral_constant<size_t, 64>,
    std::integral_constant<size_t, 128>,
    std::integral_constant<size_t, 256>,
    std::integral_constant<size_t, 512>,
    std::integral_constant<size_t, 1024>,
    std::integral_constant<size_t, 2048>
>;

// Instantiate the test suite
INSTANTIATE_TYPED_TEST_SUITE_P(SincComparison, SincComparisonTestFixture, TestSizes);