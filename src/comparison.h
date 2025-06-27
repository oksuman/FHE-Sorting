#pragma once

#include "encryption.h"
#include "openfhe.h"
#include "sign.h"
#include <cmath>
#include <memory>

using namespace lbcrypto;

template <int N> struct Sinc {

    static double simple_sinc(double x) {
        if (std::abs(x) < 0.5) {
            return 1.0;
        } else {
            return 0.0;
        }
    }

    static double sinc(double x) {
        if (std::abs(x) < 1e-10) {
            return 1.0;
        } else {
            return std::sin(M_PI * x) / M_PI * x;
        }
    }

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

    static double doubled_sinc(double x) {
        constexpr double epsilon = 1e-10;

        // First term: Sinc(x)
        double term1;
        if (std::abs(x) < epsilon) {
            term1 = 1.0;
        } else {
            term1 = std::sin(M_PI * N * x) / (M_PI * N * x);
        }

        // Second term: Sinc(x + n)
        double x2 = x + 0.5;
        double term2;
        if (std::abs(x2) < epsilon) {
            term2 = 1.0;
        } else {
            term2 = std::sin(M_PI * N * x2) / (M_PI * N * x2);
        }

        return term1 + term2;
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
                                 const Ciphertext<DCRTPoly> &b,
                                 SignFunc SignFunc, SignConfig &Cfg);

    // implementation from MEHP24
    // outputs 1 if x == 0
    // outputs 0 otherwise
    Ciphertext<DCRTPoly> indicator(const CryptoContext<DCRTPoly> &cc,
                                   const Ciphertext<DCRTPoly> &x,
                                   const double c, SignFunc SignFunc,
                                   SignConfig &Cfg);
};
