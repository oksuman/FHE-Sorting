#ifndef COMPARISON_H
#define COMPARISON_H

#include "openfhe.h"
#include <cmath>

double scaled_sinc(double x);
double scaled_sinc_j(double x, int j);

using namespace lbcrypto;

Ciphertext<lbcrypto::DCRTPoly> compositeSign(Ciphertext<lbcrypto::DCRTPoly> x,
                                             CryptoContext<DCRTPoly> cc, int dg,
                                             int df);

Ciphertext<DCRTPoly> compare(const CryptoContext<DCRTPoly> &cc,
                             const Ciphertext<DCRTPoly> &a,
                             const Ciphertext<DCRTPoly> &b);
#endif // COMPARISON_H
