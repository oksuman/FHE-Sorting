#pragma once

#include "encryption.h"
#include "openfhe.h"

enum class SignFunc {
    CompositeSign,
    MinimaxSign,
    SignumPolycircuit,
    Tanh,
    NaiveDiscrete,
};

struct CompositeSignConfig {
    int dg;
    int df;
    CompositeSignConfig(int dg, int df) : dg(dg), df(df) {}
    CompositeSignConfig() : dg(0), df(0) {}
};

struct MinimaxSignConfig {
    std::vector<int> degrees;
    std::vector<std::vector<double>> coeffs;
    MinimaxSignConfig(std::vector<int> deg,
                      std::vector<std::vector<double>> coeffs)
        : degrees(deg), coeffs(coeffs) {}
    MinimaxSignConfig() : degrees({0}), coeffs({{0.0}}) {}
};

struct SignConfig {
    CompositeSignConfig compos;
    MinimaxSignConfig minimax;

    SignConfig() : compos(0, 0) {}
    SignConfig(CompositeSignConfig compos) : compos(compos.dg, compos.df) {}
    SignConfig(MinimaxSignConfig minimax)
        : minimax(minimax.degrees, minimax.coeffs) {}
};

struct SignFunctionConfig {
    SignFunc func;
    SignConfig config;
};

// Only the composite sign function is made available
Ciphertext<lbcrypto::DCRTPoly> compositeSign(Ciphertext<lbcrypto::DCRTPoly> x,
                                             CryptoContext<DCRTPoly> cc, int dg,
                                             int df);

Ciphertext<lbcrypto::DCRTPoly> minimaxSign(Ciphertext<lbcrypto::DCRTPoly> x,
                                           CryptoContext<DCRTPoly> cc,
                                           const MinimaxSignConfig &config);

Ciphertext<lbcrypto::DCRTPoly> sign(Ciphertext<lbcrypto::DCRTPoly> x,
                                    CryptoContext<DCRTPoly> cc, SignFunc func,
                                    const SignConfig &Cfg);

Ciphertext<lbcrypto::DCRTPoly>
hybrid_sign(Ciphertext<lbcrypto::DCRTPoly> x, CryptoContext<DCRTPoly> cc,
            const std::vector<SignFunctionConfig> &chain_config);
