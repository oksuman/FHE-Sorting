// DirectSort.h

#pragma once

#include "encryption.h"
#include "openfhe.h"
#include <iostream>
#include <vector>

using namespace lbcrypto;

class DirectSort {
  private:
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;

  public:
    std::shared_ptr<Encryption> m_enc;
    // Constructor
    DirectSort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey,
               std::shared_ptr<Encryption> enc)
        : m_cc(cc), m_PublicKey(publicKey), m_enc(enc) {}

    // Main ranking function
    Ciphertext<DCRTPoly> constructRank(const Ciphertext<DCRTPoly> &input_array);
    Ciphertext<DCRTPoly>
    constructRankv2(const Ciphertext<DCRTPoly> &input_array);
    Ciphertext<DCRTPoly>
    constructRankv3(const Ciphertext<DCRTPoly> &input_array);
};
