#pragma once

#include "encryption.h"
#include "openfhe.h"
#include <cmath>
#include <memory>

using namespace lbcrypto;

template <int N> struct Sinc {

    static double scaled_sinc(double x) {
        if (std::abs(x) < 1e-10) {
            return 1.0;
        } else {
            // Periodic by the size of the array
            return std::sin(M_PI * N * x) / (M_PI * N * x);
        }
    }
    static double scaled_sinc_j(double x, int j) {
        constexpr double epsilon = 1e-10;
        constexpr double factor = N * M_PI;

        double denominator1 = factor * x - j * M_PI;
        double denominator2 = denominator1 + factor;

        double term1 = (std::abs(denominator1) < epsilon)
                           ? 1.0
                           : std::sin(denominator1) / denominator1;
        double term2 = (std::abs(denominator2) < epsilon)
                           ? 1.0
                           : std::sin(denominator2) / denominator2;

        double result = term1 + term2;

        return result;
    }
};

class Comparison {
  private:
    std::shared_ptr<Encryption> m_enc;

  public:
    Comparison(std::shared_ptr<Encryption> enc) : m_enc(enc) {}
    Comparison() : m_enc(nullptr) {}

    Ciphertext<DCRTPoly> compare(const CryptoContext<DCRTPoly> &cc,
                                 const Ciphertext<DCRTPoly> &a,
                                 const Ciphertext<DCRTPoly> &b);

    Ciphertext<DCRTPoly> compareLogistic(const CryptoContext<DCRTPoly> &cc,
                                         const Ciphertext<DCRTPoly> &a,
                                         const Ciphertext<DCRTPoly> &b);

    Ciphertext<DCRTPoly> max(const CryptoContext<DCRTPoly> &cc,
                             const Ciphertext<DCRTPoly> &a,
                             const Ciphertext<DCRTPoly> &b);
};
