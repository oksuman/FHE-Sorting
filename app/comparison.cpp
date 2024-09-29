#include "comparison.h"
#include "sign.h"

Ciphertext<DCRTPoly> Comparison::compare(const CryptoContext<DCRTPoly> &cc,
                                         const Ciphertext<DCRTPoly> &a,
                                         const Ciphertext<DCRTPoly> &b) {
    std::vector<int> degrees = {7, 7, 7, 13, 13, 27};
    std::vector<std::vector<double>> coeffs = {
        {
            0,
            0.639085028771546,
            0,
            -0.219824302408022,
            0,
            0.141450315105013,
            0,
            -0.560620554854071,
        },
        {
            0,
            0.639360910483311,
            0,
            -0.219913850303762,
            0,
            0.141501004286425,
            0,
            -0.560422828775413,
        },
        {
            0,
            0.640995555494780,
            0,
            -0.220444289629960,
            0,
            0.141801067852694,
            0,
            -0.559251053205863,
        },
        {
            0,
            0.658768822547799,
            0,
            -0.221429454178234,
            0,
            0.135166228077564,
            0,
            -0.099217351391485,
            0,
            0.080265448859416,
            0,
            -0.069360047195550,
            0,
            0.515804381583946,
        },
        {
            0,
            0.847610272136297,
            0,
            -0.283170189616444,
            0,
            0.170743232087551,
            0,
            -0.123020194788625,
            0,
            0.097051963801292,
            0,
            -0.081244654023919,
            0,
            0.372027031594664,
        },
        {
            0, 1.266277633441173,  0, -0.403933219726391, 0, 0.221820308131117,
            0, -0.138518127967010, 0, 0.089788045037979,  0, -0.058194457592534,
            0, 0.036925010039798,  0, -0.022586558503619, 0, 0.013132034793017,
            0, -0.007142927159322, 0, 0.003559003972027,  0, -0.001572153465569,
            0, 0.000579443579588,  0, -0.000156339337296,
        },
    };
    MinimaxSignConfig config(degrees, coeffs);

    // (sgn(a-b) + 1)/2
    // Returns 1 if a > b
    //         0 if a < b
    // Step 1: Subtraction
    auto diff = cc->EvalSub(a, b);

    // Step 2: Sign function
    auto sign = minimaxSign(diff, cc, config);

    // Step 3: Compute comparison result
    auto comp = cc->EvalMult(cc->EvalAdd(sign, 1), 0.5);

    return comp;
}

// TODO add unittest if used
Ciphertext<DCRTPoly> Comparison::max(const CryptoContext<DCRTPoly> &cc,
                                     const Ciphertext<DCRTPoly> &a,
                                     const Ciphertext<DCRTPoly> &b) {
    // max(a,b) = (a+b)/2 + (a-b)/2 * sign(a-b)
    auto diff = cc->EvalSub(a, b);
    auto sum = cc->EvalAdd(a, b);
    auto sign = compositeSign(diff, cc, 3, 3);

    auto halfDiff = cc->EvalMult(diff, 0.5);
    auto halfSum = cc->EvalMult(sum, 0.5);

    auto scale = cc->EvalMult(halfDiff, sign);

    return cc->EvalAdd(halfSum, scale);
}
