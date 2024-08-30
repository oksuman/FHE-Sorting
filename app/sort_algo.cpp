// DirectSort.cpp

#include "sort_algo.h"
#include "comparison.h"
#include "encryption.h"
#include <cassert>
#include <memory>
#include <omp.h>

Ciphertext<DCRTPoly>
DirectSort::constructRankv3(const Ciphertext<DCRTPoly> &input_array) {

    Comparison comp(m_enc);
    int N = input_array->GetSlots();
    std::vector<double> Zero(N, 0.0);
    Plaintext ptxZero = m_cc->MakeCKKSPackedPlaintext(Zero);
    auto ctxRank = m_cc->Encrypt(m_PublicKey, ptxZero);
    const auto inputOver255 = m_cc->EvalMult(input_array, (double)1.0 / 255);

#pragma omp parallel for
    for (int i = 1; i < N; i++) {
        auto rotated = m_cc->EvalRotate(inputOver255, -i);
        auto compResult = comp.compare(m_cc, inputOver255, rotated);
        m_cc->EvalAddInPlace(ctxRank, compResult);
    }

    return ctxRank;
}
