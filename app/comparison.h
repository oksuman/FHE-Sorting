#ifndef COMPARISON_H
#define COMPARISON_H

#include "encryption.h"
#include "openfhe.h"
#include <cmath>
#include <memory>

double scaled_sinc(double x);
double scaled_sinc_j(double x, int j);

using namespace lbcrypto;

class Comparison {
  private:
    std::shared_ptr<Encryption> m_enc;
    Ciphertext<lbcrypto::DCRTPoly> f_n(Ciphertext<lbcrypto::DCRTPoly> x,
                                       CryptoContext<DCRTPoly> cc);

  public:
    Comparison(std::shared_ptr<Encryption> enc) : m_enc(enc) {}
    Comparison() : m_enc(nullptr) {}

    Ciphertext<lbcrypto::DCRTPoly>
    compositeSign(Ciphertext<lbcrypto::DCRTPoly> x, CryptoContext<DCRTPoly> cc,
                  int dg, int df);

    Ciphertext<DCRTPoly> compare(const CryptoContext<DCRTPoly> &cc,
                                 const Ciphertext<DCRTPoly> &a,
                                 const Ciphertext<DCRTPoly> &b);
};
#endif // COMPARISON_H
