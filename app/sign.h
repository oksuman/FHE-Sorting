#pragma once

#include "encryption.h"
#include "openfhe.h"

enum class SignFunc {
    CompositeSign,
    SignumPolycircuit,
    Tanh,
    NaiveDiscrete,
};

struct CompositeSignConfig {
    int dg;
    int df;
    CompositeSignConfig(int dg, int df) : dg(dg), df(df) {}
};

struct SignConfig {
    CompositeSignConfig compos;

    SignConfig() : compos(0, 0) {}
    SignConfig(CompositeSignConfig compos) : compos(compos.dg, compos.df) {}
};

// Only the composite sign function is made available
Ciphertext<lbcrypto::DCRTPoly> compositeSign(Ciphertext<lbcrypto::DCRTPoly> x,
                                             CryptoContext<DCRTPoly> cc, int dg,
                                             int df);

Ciphertext<lbcrypto::DCRTPoly> sign(Ciphertext<lbcrypto::DCRTPoly> x,
                                    CryptoContext<DCRTPoly> cc, SignFunc func,
                                    const SignConfig &Cfg);
