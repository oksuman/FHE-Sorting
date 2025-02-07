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
#include "mehp24_utils.h"
#include "sign.h"
#include "comparison.h"

using namespace lbcrypto;

namespace mehp24 {

// Sort a ciphertext vector
Ciphertext<DCRTPoly> sort(
    Ciphertext<DCRTPoly> c,
    const size_t vectorLength,
    double leftBoundC,
    double rightBoundC,
    uint32_t degreeC,
    uint32_t degreeI
);

// Sort a vector stored in multiple ciphertexts
std::vector<Ciphertext<DCRTPoly>> sort(
    const std::vector<Ciphertext<DCRTPoly>> &c,
    const size_t subVectorLength,
    double leftBoundC,
    double rightBoundC,
    uint32_t degreeC,
    uint32_t degreeI
);

// Sort using FG approximation
Ciphertext<DCRTPoly> sortFG(
    Ciphertext<DCRTPoly> c,
    const size_t vectorLength,
    uint32_t dg_c,
    uint32_t df_c,
    uint32_t dg_i,
    uint32_t df_i,
    PrivateKey<DCRTPoly> sk,
    CryptoContext<DCRTPoly> m_cc
);

Ciphertext<DCRTPoly> sortFG(
    Ciphertext<DCRTPoly> c,
    const size_t vectorLength,
    SignFunc SignFunc, 
    SignConfig &Cfg,
    std::unique_ptr<Comparison> &comp,
    uint32_t dg_i,
    uint32_t df_i,
    PrivateKey<DCRTPoly> sk,
    CryptoContext<DCRTPoly> m_cc
);

// Sort using FG approximation for multiple ciphertexts
std::vector<Ciphertext<DCRTPoly>> sortFG(
    const std::vector<Ciphertext<DCRTPoly>> &c,
    const size_t subVectorLength,
    uint32_t dg_c,
    uint32_t df_c,
    uint32_t dg_i,
    uint32_t df_i
);

std::vector<Ciphertext<DCRTPoly>> sortFG(
    const std::vector<Ciphertext<DCRTPoly>> &c,
    const size_t subVectorLength,
    SignFunc SignFunc, 
    SignConfig &Cfg,
    std::unique_ptr<Comparison> &comp,
    uint32_t dg_i,
    uint32_t df_i
);

Ciphertext<DCRTPoly> sortLargeArrayFG(
    Ciphertext<DCRTPoly> c,
    const size_t totalLength,    
    const size_t subLength,      
    uint32_t dg_c,
    uint32_t df_c,
    uint32_t dg_i,
    uint32_t df_i,
    CryptoContext<DCRTPoly> cc
);

Ciphertext<DCRTPoly> sortLargeArrayFG(
    Ciphertext<DCRTPoly> c,
    const size_t totalLength,    
    const size_t subLength,      
    SignFunc SignFunc, 
    SignConfig &Cfg,
    std::unique_ptr<Comparison> &comp,
    uint32_t dg_i,
    uint32_t df_i,
    CryptoContext<DCRTPoly> cc
);

} // namespace mehp24