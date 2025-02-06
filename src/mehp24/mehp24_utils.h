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
#pragma once

#include "openfhe.h"
#include <iomanip>
#include <iostream>
#include <vector>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN_VEC(V) *std::min_element(V.begin(), V.end())
#define MAX_VEC(V) *std::max_element(V.begin(), V.end())
#define LOG2(X) (size_t) std::ceil(std::log2((X)))

using namespace lbcrypto;

namespace mehp24 {
namespace utils {

template <typename Element>
Ciphertext<Element> operator<<(const Ciphertext<Element> &a, int32_t index) {
    return a->GetCryptoContext()->EvalRotate(a, index);
}

template <typename Element>
Ciphertext<Element> operator>>(const Ciphertext<Element> &a, int32_t index) {
    return a->GetCryptoContext()->EvalRotate(a, -index);
}

template <typename Element>
Ciphertext<Element> operator+(const Ciphertext<Element> &a, const double &b) {
    return a->GetCryptoContext()->EvalAdd(a, b);
}

template <typename Element>
Ciphertext<Element> operator+(const Ciphertext<Element> &a, const std::vector<double> &b) {
    CryptoContext<Element> cc = a->GetCryptoContext();
    auto plaintext = cc->MakeCKKSPackedPlaintext(b);
    return cc->EvalAdd(a, plaintext);
}

template <typename Element>
Ciphertext<Element> operator-(const double &a, const Ciphertext<Element> &b) {
    return b->GetCryptoContext()->EvalSub(a, b);
}

template <typename Element>
Ciphertext<Element> operator-(const Ciphertext<Element> &a, const double &b) {
    return a->GetCryptoContext()->EvalSub(a, b);
}

template <typename Element>
Ciphertext<Element> operator*(const Ciphertext<Element> &a, const std::vector<double> &b) {
    CryptoContext<Element> cc = a->GetCryptoContext();
    auto plaintext = cc->MakeCKKSPackedPlaintext(b);
    return cc->EvalMult(a, plaintext);
}

template <typename Element>
Ciphertext<Element> operator*(const std::vector<double> &a, const Ciphertext<Element> &b) {
    return b * a;
}

template <typename Element>
Ciphertext<Element> operator*(const Ciphertext<Element> &a, const double b) {
    CryptoContext<Element> cc = a->GetCryptoContext();
    return cc->EvalMult(a, b);
}

template <typename Element>
Ciphertext<Element> operator*(const double a, const Ciphertext<Element> &b) {
    return b * a;
}

// Matrix operations for sorting
Ciphertext<DCRTPoly> maskRow(
    Ciphertext<DCRTPoly> c,
    const size_t matrixSize,
    const size_t rowIndex
);

Ciphertext<DCRTPoly> maskColumn(
    Ciphertext<DCRTPoly> c,
    const size_t matrixSize,
    const size_t columnIndex
);

Ciphertext<DCRTPoly> replicateRow(
    Ciphertext<DCRTPoly> c,
    const size_t matrixSize
);

Ciphertext<DCRTPoly> replicateColumn(
    Ciphertext<DCRTPoly> c,
    const size_t matrixSize
);

Ciphertext<DCRTPoly> sumRows(
    Ciphertext<DCRTPoly> c,
    const size_t matrixSize,
    bool maskOutput=false,
    const size_t outputRow=0
);

Ciphertext<DCRTPoly> sumColumns(
    Ciphertext<DCRTPoly> c,
    const size_t matrixSize,
    bool maskOutput=false
);

Ciphertext<DCRTPoly> transposeRow(
    Ciphertext<DCRTPoly> c,
    const size_t matrixSize,
    bool maskOutput=false
);

Ciphertext<DCRTPoly> transposeColumn(
    Ciphertext<DCRTPoly> c,
    const size_t matrixSize,
    bool maskOutput=false
);

// Comparison operations
Ciphertext<DCRTPoly> equal(
    const Ciphertext<DCRTPoly> &c1,
    const Ciphertext<DCRTPoly> &c2,
    const double a,
    const double b,
    const uint32_t degree,
    const double error = 0.00001
);

Ciphertext<DCRTPoly> compare(
    const Ciphertext<DCRTPoly> &c1,
    const Ciphertext<DCRTPoly> &c2,
    const double a,
    const double b,
    const uint32_t degree,
    const double error = 0.00001
);

Ciphertext<DCRTPoly> compareAdv(
    const Ciphertext<DCRTPoly> &c1,
    const Ciphertext<DCRTPoly> &c2,
    const size_t dg,
    const size_t df
);

Ciphertext<DCRTPoly> compareGt(
    const Ciphertext<DCRTPoly> &c1,
    const Ciphertext<DCRTPoly> &c2,
    const double a,
    const double b,
    const uint32_t degree,
    const double error = 0.00001
);

// Indicator functions
Ciphertext<DCRTPoly> indicator(
    const Ciphertext<DCRTPoly> &c,
    const double a1,
    const double b1,
    const double a,
    const double b,
    const uint32_t degree
);

Ciphertext<DCRTPoly> indicatorAdv(
    const Ciphertext<DCRTPoly> &c,
    const double b,
    const size_t dg,
    const size_t df
);

Ciphertext<DCRTPoly> indicatorAdvShifted(
    const Ciphertext<DCRTPoly> &c,
    const double b,
    const size_t dg,
    const size_t df
);

// Helper functions
std::vector<int32_t> getRotationIndices(
    const size_t matrixSize
);

usint depth2degree(
    const usint depth
);

Ciphertext<DCRTPoly> signAdv(
    Ciphertext<DCRTPoly> &c,
    const size_t dg,
    const size_t df
);

} // namespace utils
} // namespace mehp24