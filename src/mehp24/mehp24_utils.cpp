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
#include "mehp24_utils.h"
#include <cassert>
#include <cmath>

namespace mehp24 {
namespace utils {

Ciphertext<DCRTPoly> maskRow(Ciphertext<DCRTPoly> c, const size_t matrixSize,
                             const size_t rowIndex) {
    assert(rowIndex >= 0 && rowIndex < matrixSize && "Invalid row index");

    std::vector<double> mask(matrixSize * matrixSize, 0.0);
    for (size_t i = 0; i < matrixSize; i++)
        mask[matrixSize * rowIndex + i] = 1.0;

    return c * mask;
}

Ciphertext<DCRTPoly> maskColumn(Ciphertext<DCRTPoly> c, const size_t matrixSize,
                                const size_t columnIndex) {
    assert(columnIndex >= 0 && columnIndex < matrixSize &&
           "Invalid column index");

    std::vector<double> mask(matrixSize * matrixSize, 0.0);
    for (size_t i = 0; i < matrixSize; i++)
        mask[matrixSize * i + columnIndex] = 1.0;

    return c * mask;
}

Ciphertext<DCRTPoly> replicateRow(Ciphertext<DCRTPoly> c,
                                  const size_t matrixSize) {
    for (size_t i = 0; i < LOG2(matrixSize); i++)
        c += c >> (1 << (LOG2(matrixSize) + i));

    return c;
}

Ciphertext<DCRTPoly> replicateColumn(Ciphertext<DCRTPoly> c,
                                     const size_t matrixSize) {
    for (size_t i = 0; i < LOG2(matrixSize); i++)
        c += c >> (1 << i);

    return c;
}

Ciphertext<DCRTPoly> sumRows(Ciphertext<DCRTPoly> c, const size_t matrixSize,
                             bool maskOutput, const size_t outputRow) {
    for (size_t i = 0; i < LOG2(matrixSize); i++)
        c += c >> (1 << (LOG2(matrixSize) + i));

    if (maskOutput)
        c = maskRow(c, matrixSize, outputRow);

    return c;
}

Ciphertext<DCRTPoly> sumColumns(Ciphertext<DCRTPoly> c, const size_t matrixSize,
                                bool maskOutput) {
    for (size_t i = 0; i < LOG2(matrixSize); i++)
        c += c << (1 << i);

    if (maskOutput)
        c = maskColumn(c, matrixSize, 0);

    return c;
}

Ciphertext<DCRTPoly> transposeRow(Ciphertext<DCRTPoly> c,
                                  const size_t matrixSize, bool maskOutput) {
    for (size_t i = 1; i <= LOG2(matrixSize); i++)
        c += c >> (matrixSize * (matrixSize - 1) / (1 << i));

    if (maskOutput)
        c = maskColumn(c, matrixSize, 0);

    return c;
}

Ciphertext<DCRTPoly> transposeColumn(Ciphertext<DCRTPoly> c,
                                     const size_t matrixSize, bool maskOutput) {
    for (size_t i = 1; i <= LOG2(matrixSize); i++)
        c += c << (matrixSize * (matrixSize - 1) / (1 << i));

    if (maskOutput)
        c = maskRow(c, matrixSize, 0);

    return c;
}

Ciphertext<DCRTPoly> equal(const Ciphertext<DCRTPoly> &c1,
                           const Ciphertext<DCRTPoly> &c2, const double a,
                           const double b, const uint32_t degree,
                           const double error) {
    return c1->GetCryptoContext()->EvalChebyshevFunction(
        [error](double x) -> double {
            if (x > error)
                return 0;
            else if (x >= -error)
                return 1.0;
            else
                return 0;
        },
        c1 - c2, a, b, degree);
}

Ciphertext<DCRTPoly> compare(const Ciphertext<DCRTPoly> &c1,
                             const Ciphertext<DCRTPoly> &c2, const double a,
                             const double b, const uint32_t degree,
                             const double error) {
    return c1->GetCryptoContext()->EvalChebyshevFunction(
        [error](double x) -> double {
            if (x > error)
                return 1;
            else if (x >= -error)
                return 0.5;
            else
                return 0;
        },
        c1 - c2, a, b, degree);
}

Ciphertext<DCRTPoly> compareAdv(const Ciphertext<DCRTPoly> &c1,
                                const Ciphertext<DCRTPoly> &c2, const size_t dg,
                                const size_t df) {
    auto c = c1 - c2;
    return signAdv(c, dg, df);
}

Ciphertext<DCRTPoly> compareGt(const Ciphertext<DCRTPoly> &c1,
                               const Ciphertext<DCRTPoly> &c2, const double a,
                               const double b, const uint32_t degree,
                               const double error) {
    return c1->GetCryptoContext()->EvalChebyshevFunction(
        [error](double x) -> double {
            if (x > error)
                return 1;
            else
                return 0;
        },
        c1 - c2, a, b, degree);
}

Ciphertext<DCRTPoly> indicator(const Ciphertext<DCRTPoly> &c, const double a1,
                               const double b1, const double a, const double b,
                               const uint32_t degree) {
    return c->GetCryptoContext()->EvalChebyshevFunction(
        [a1, b1](double x) -> double { return (x < a1 || x > b1) ? 0 : 1; }, c,
        a, b, degree);
}

Ciphertext<DCRTPoly> indicatorAdv(const Ciphertext<DCRTPoly> &c, const double b,
                                  const size_t dg, const size_t df) {
    auto tmp = (1.0 / b) * c;
    auto c1 = tmp + 0.5 / b;
    auto c2 = tmp - 0.5 / b;
    c1 = signAdv(c1, dg, df);
    c2 = signAdv(c2, dg, df);
    return c1 * (1 - c2);
}

Ciphertext<DCRTPoly> indicatorAdvShifted(const Ciphertext<DCRTPoly> &c,
                                         const double b, const size_t dg,
                                         const size_t df) {
    auto c1 = (2.0 / (b + 1)) * c + 2.0 / (b + 1) - 1.0;
    auto c2 = (-2.0 / (b + 1)) * c + 2.0 / (b + 1) + 1.0;
    c1 = signAdv(c1, dg, df);
    c2 = signAdv(c2, dg, df);
    return c1 * c2;
}

std::vector<int32_t> getRotationIndices(const size_t matrixSize) {
    int sz = matrixSize;

    std::vector<int32_t> indices;
    if (matrixSize > 256) {
        for (size_t i = 0; i < matrixSize / 256; i++) {
            indices.push_back(i * 256);
            indices.push_back(-i * 256);
        }
        sz = 256;
    }

    int32_t index;
    for (size_t i = 0; i < LOG2(sz); i++) {
        index = 1 << i;
        indices.push_back(index);
        indices.push_back(-index);

        index = 1 << (LOG2(sz) + i);
        indices.push_back(-index);

        index = (sz * (sz - 1) / (1 << (i + 1)));
        indices.push_back(index);
        indices.push_back(-index);
    }

    return indices;
}

usint depth2degree(const usint depth) {
    switch (depth) {
    case 3:
        return 2;
    case 4:
        return 5;
    case 5:
        return 13;
    case 6:
        return 27;
    case 7:
        return 59;
    case 8:
        return 119;
    case 9:
        return 247;
    case 10:
        return 495;
    case 11:
        return 1007;
    case 12:
        return 2031;
    case 13:
        return 4031;
    case 14:
        return 8127;
    default:
        return -1;
    }
}

Ciphertext<DCRTPoly> signAdv(Ciphertext<DCRTPoly> &c, const size_t dg,
                             const size_t df) {
    std::vector<double> coeffF3 = {0, 35.0 / 16.0, 0, -35.0 / 16.0,
                                   0, 21.0 / 16.0, 0, -5.0 / 16.0};
    std::vector<double> coeffF3_final = {0.5, 35.0 / 32.0, 0, -35.0 / 32.0,
                                         0,   21.0 / 32.0, 0, -5.0 / 32.0};
    std::vector<double> coeffG3 = {0, 4589.0 / 1024.0,  0, -16577.0 / 1024.0,
                                   0, 25614.0 / 1024.0, 0, -12860.0 / 1024.0};

    for (size_t d = 0; d < dg; d++)
        c = c->GetCryptoContext()->EvalPolyLinear(c, coeffG3);
    for (size_t d = 0; d < df - 1; d++)
        c = c->GetCryptoContext()->EvalPolyLinear(c, coeffF3);
    c = c->GetCryptoContext()->EvalPolyLinear(c, coeffF3_final);
    return c;
}

// added
// Split a ciphertext into multiple ciphertexts, each containing subLength
// elements
std::vector<Ciphertext<DCRTPoly>> splitCiphertext(const Ciphertext<DCRTPoly> &c,
                                                  const size_t totalLength,
                                                  const size_t subLength,
                                                  CryptoContext<DCRTPoly> &cc) {
    size_t numParts = totalLength / subLength; // e.g., 512/256 = 2 parts
    std::vector<Ciphertext<DCRTPoly>> result(numParts);

    for (size_t i = 0; i < numParts; i++) {
        // Create mask: 1's for the current part, 0's elsewhere
        std::vector<double> mask(totalLength, 0.0);
        for (size_t j = 0; j < subLength; j++) {
            mask[i * subLength + j] = 1.0;
        }

        // Apply mask and rotate
        Plaintext maskPlain = cc->MakeCKKSPackedPlaintext(mask);
        auto part = cc->EvalMult(c, maskPlain);
        if (i > 0)
            part = cc->EvalRotate(part, i * subLength);
        result[i] = part;
    }
    return result;
}

// Combine multiple ciphertexts back into a single ciphertext
Ciphertext<DCRTPoly>
combineCiphertext(const std::vector<Ciphertext<DCRTPoly>> &parts,
                  const size_t subLength, CryptoContext<DCRTPoly> &cc) {
    auto result = parts[0];

    for (size_t i = 1; i < parts.size(); i++) {
        // Rotate each part back to its original position and add
        auto rotated = cc->EvalRotate(parts[i], -i * subLength);
        result = cc->EvalAdd(result, rotated);
    }
    return result;
}


//added by oksuman
// Helper function to get binary path for target column
std::vector<bool> getBinaryPath(size_t columnIndex, size_t matrixSize) {
    std::vector<bool> path(LOG2(matrixSize));
    for(int i = LOG2(matrixSize)-1; i >= 0; i--) {
        path[LOG2(matrixSize)-1-i] = (columnIndex >> i) & 1;
    }
    return path;
}

// Extended version of sumColumns that allows specifying target column
Ciphertext<DCRTPoly> sumColumnsToTarget(Ciphertext<DCRTPoly> c, 
                                       const size_t matrixSize,
                                       const size_t columnIndex,
                                       bool maskOutput = false) {
    assert(columnIndex < matrixSize && "Invalid column index");
    
    // Get binary path to target column
    auto path = getBinaryPath(columnIndex, matrixSize);
    
    // Start with matrixSize/2 and divide by 2 in each step
    size_t step = matrixSize >> 1;
    
    for (size_t i = 0; i < LOG2(matrixSize); i++) {
        // path[i] == 1 means we want right child in binary tree
        // path[i] == 0 means we want left child in binary tree
        if(path[i]) {
            c += c << step;  // left rotation
        } else {
            c += c >> step;  // right rotation
        }
        step >>= 1;  // divide step by 2
    }

    if (maskOutput) {
        c = maskColumn(c, matrixSize, columnIndex);
    }

    return c;
}

Ciphertext<DCRTPoly> transposeColumnTarget(Ciphertext<DCRTPoly> c,
                                     const size_t matrixSize, const size_t rowIndex, bool maskOutput) {
    for (size_t i = 1; i <= LOG2(matrixSize); i++)
        c += c << (matrixSize * (matrixSize - 1) / (1 << i));

    if (maskOutput)
        c = maskRow(c, matrixSize, rowIndex);

    return c;
}



} // namespace utils
} // namespace mehp24



