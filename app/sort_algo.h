// DirectSort.h

#pragma once

#include "openfhe.h"
#include <iostream>
#include <vector>

using namespace lbcrypto;

class DirectSort {
  private:
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;

  public:
    // Constructor
    DirectSort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey);

    // Main ranking function
    Ciphertext<DCRTPoly> constructRank(const Ciphertext<DCRTPoly> &input_array);
    Ciphertext<DCRTPoly>
    constructRankv2(const Ciphertext<DCRTPoly> &input_array);
    Ciphertext<DCRTPoly>
    constructRankv3(const Ciphertext<DCRTPoly> &input_array);
};
