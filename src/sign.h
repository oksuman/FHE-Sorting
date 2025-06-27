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
    int n;
    int dg;
    int df;
    CompositeSignConfig(int n, int dg, int df) : n(n), dg(dg), df(df) {}
};

struct SignConfig {
    CompositeSignConfig compos;

    int multDepth;

    SignConfig() : compos(0, 0, 0) {}
    // No bootstrap
    SignConfig(CompositeSignConfig compos)
        : compos(compos.n, compos.dg, compos.df), multDepth(100) {}
    // Bootstrap enabled
    SignConfig(CompositeSignConfig compos, int depth)
        : compos(compos.n, compos.dg, compos.df), multDepth(depth) {}
};

// Only the composite sign function is made available
template <int n>
Ciphertext<DCRTPoly> compositeSign(Ciphertext<DCRTPoly> x,
                                   CryptoContext<DCRTPoly> cc,
                                   const SignConfig &Cfg);

Ciphertext<DCRTPoly> sign(Ciphertext<DCRTPoly> x, CryptoContext<DCRTPoly> cc,
                          SignFunc func, const SignConfig &Cfg);
