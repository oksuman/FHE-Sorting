// DirectSort.cpp

#include "sort_algo.h"
#include "comparison.h"
#include <cassert>
#include <omp.h>

DirectSort::DirectSort(CryptoContext<DCRTPoly> cc,
                       PublicKey<DCRTPoly> publicKey)
    : m_cc(cc), m_PublicKey(publicKey) {}

Ciphertext<DCRTPoly>
DirectSort::constructRank(const Ciphertext<DCRTPoly> &input_array) {

    // omp_set_num_threads(1);
    int N = input_array->GetSlots();
    std::vector<double> Zero(N, 0.0);
    Plaintext ptxZero = m_cc->MakeCKKSPackedPlaintext(Zero);
    auto ctxRank = m_cc->Encrypt(m_PublicKey, ptxZero);
    const auto inputOver255 = m_cc->EvalMult(input_array, (double)1.0 / 255);

    // #pragma omp parallel for
    for (int i = 0; i < 32; i++) {
        std::cout << "comp i: " << i << std::endl;
        if (i == 0) {
            auto tmp1 = m_cc->Encrypt(m_PublicKey, ptxZero);
            auto tmp2 = m_cc->Encrypt(m_PublicKey, ptxZero);
            for (int j = 1; j < 32; j++) {
                std::cout << "Rotating by " << -j << std::endl;
                auto b = m_cc->EvalRotate(inputOver255, -j);
                // auto comp1 = compare(m_cc, inputOver255, b);
                auto diff = m_cc->EvalSub(inputOver255, b);
                auto comp1 = m_cc->EvalMult(
                    m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1), 0.5);
                m_cc->EvalAddInPlace(tmp1, comp1);
                auto comp2 = m_cc->EvalRotate(comp1, -32 + j);
                m_cc->EvalSubInPlace(1, comp2);
                m_cc->EvalAddInPlace(tmp2, comp2);
            }
            m_cc->EvalAddInPlace(tmp1, m_cc->EvalRotate(tmp2, -2016));
#pragma omp critical
            { m_cc->EvalAddInPlace(ctxRank, tmp1); }
        } else {
            auto b = m_cc->EvalRotate(inputOver255, -32 * i);
            auto diff = m_cc->EvalSub(inputOver255, b);
            auto tmp1 = m_cc->EvalMult(
                m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1), 0.5);
            auto tmp2 = m_cc->EvalRotate(tmp1, -32);
            m_cc->EvalSubInPlace(1, tmp2);
            for (int j = 1; j < 32; j++) {
                auto b2 = m_cc->EvalRotate(b, -j);
                auto diff = m_cc->EvalSub(inputOver255, b2);
                auto comp1 = m_cc->EvalMult(
                    m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1), 0.5);
                m_cc->EvalAddInPlace(tmp1, comp1);
                auto comp2 = m_cc->EvalRotate(comp1, -32 + j);
                m_cc->EvalSubInPlace(1, comp2);
                m_cc->EvalAddInPlace(tmp2, comp2);
            }
            m_cc->EvalAddInPlace(tmp1, m_cc->EvalRotate(tmp2, -2016 + 32 * i));
#pragma omp critical
            { m_cc->EvalAddInPlace(ctxRank, tmp1); }
        }
    }

    return ctxRank;
}

Ciphertext<DCRTPoly>
DirectSort::constructRankv2(const Ciphertext<DCRTPoly> &input_array) {
    int N = input_array->GetSlots();
    std::cout << "N size is " << N << "\n";
    // Pre-compute constants
    constexpr double kInvScale = 1.0 / 255.0;
    constexpr int kRotations = 8;
    constexpr int kLargeRotation = kRotations * (kRotations - 1);
    assert(N % kRotations == 0 && "Array size must be divisible by kRotations");
    std::cout << "Loop size: " << N / kRotations << "\n";
    // Initialize rank ciphertext
    auto ctxRank = m_cc->Encrypt(m_PublicKey, m_cc->MakeCKKSPackedPlaintext(
                                                  std::vector<double>(N, 0.0)));
    auto ctxInputScaled = m_cc->EvalMult(input_array, kInvScale);
    // Pre-compute rotations of input
    std::vector<Ciphertext<DCRTPoly>> rotatedInputs(kRotations);
#pragma omp parallel for
    for (int j = 1; j < kRotations; ++j) {
        rotatedInputs[j] = m_cc->EvalRotate(ctxInputScaled, -j);
    }
// Main computation loop
#pragma omp parallel
    {
        auto localRank = m_cc->Encrypt(
            m_PublicKey,
            m_cc->MakeCKKSPackedPlaintext(std::vector<double>(N, 0.0)));
#pragma omp for nowait
        for (int i = 0; i < N / kRotations; ++i) {
            std::cout << "Loop index: " << i << "\n";
            auto ctxTmp1 = m_cc->Encrypt(
                m_PublicKey,
                m_cc->MakeCKKSPackedPlaintext(std::vector<double>(N, 0.0)));
            auto ctxTmp2 = m_cc->Encrypt(
                m_PublicKey,
                m_cc->MakeCKKSPackedPlaintext(std::vector<double>(N, 0.0)));

            auto ctxRotatedInput =
                (i == 0) ? ctxInputScaled
                         : m_cc->EvalRotate(ctxInputScaled, -kRotations * i);
            for (int j = 1; j < kRotations; ++j) {
                auto rotInput = (i == 0)
                                    ? rotatedInputs[j]
                                    : m_cc->EvalRotate(ctxRotatedInput, -j);
                auto ctxComp = compare(m_cc, ctxInputScaled, rotInput);
                m_cc->EvalAddInPlace(ctxTmp1, ctxComp);
                auto ctxRotatedComp =
                    m_cc->EvalRotate(ctxComp, -kRotations + j);
                m_cc->EvalSubInPlace(ctxRotatedComp, 1);
                m_cc->EvalAddInPlace(ctxTmp2, ctxRotatedComp);
            }
            m_cc->EvalAddInPlace(
                ctxTmp1,
                m_cc->EvalRotate(ctxTmp2, -kLargeRotation + kRotations * i));
            m_cc->EvalAddInPlace(localRank, ctxTmp1);
        }
#pragma omp critical
        { m_cc->EvalAddInPlace(ctxRank, localRank); }
    }
    std::cout << "Finished computation" << std::endl;
    return ctxRank; // Add this line to return the result
}


Ciphertext<DCRTPoly>
DirectSort::constructRankv3(const Ciphertext<DCRTPoly> &input_array) {
    int N = input_array->GetSlots();
    std::cout << "N size is " << N << "\n";

    constexpr double kInvScale = 1.0 / 255.0;
    // Remove scaling for now
    auto ctxInputScaled = m_cc->EvalMult(input_array, kInvScale);

    auto ctxRank = m_cc->Encrypt(m_PublicKey, m_cc->MakeCKKSPackedPlaintext(
                                                  std::vector<double>(N, 0.0)));

    for (int i = 0; i < N; ++i) {
        auto ctxTmp = m_cc->Encrypt(
            m_PublicKey,
            m_cc->MakeCKKSPackedPlaintext(std::vector<double>(N, 0.0)));

        for (int j = 0; j < N; ++j) {
            if (i != j) {
                std::cout << "Rotate index j  " << j << "\n";
                auto rotInput = m_cc->EvalRotate(ctxInputScaled, -j);
                auto ctxComp = compare(m_cc, ctxInputScaled, rotInput);
                m_cc->EvalAddInPlace(ctxTmp, ctxComp);
            }
        }
        std::cout << "Rotate index i " << i << "\n";

        m_cc->EvalAddInPlace(ctxRank, m_cc->EvalRotate(ctxTmp, -i));
    }

    std::cout << "Finished computation" << std::endl;
    return ctxRank;
}
