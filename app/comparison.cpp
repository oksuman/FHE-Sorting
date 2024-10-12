#include "comparison.h"
#include "sign.h"

Ciphertext<DCRTPoly> Comparison::compare(const CryptoContext<DCRTPoly> &cc,
                                         const Ciphertext<DCRTPoly> &a,
                                         const Ciphertext<DCRTPoly> &b,
                                         SignFunc SignFunc, SignConfig &Cfg) {

    // (sgn(a-b) + 1)/2
    // Returns 1 if a > b
    //         0 if a < b
    // Step 1: Subtraction
    auto diff = cc->EvalSub(a, b);

    // Step 2: Sign function
    auto signValue = sign(diff, cc, SignFunc, Cfg);

    // Step 3: Compute comparison result
    auto comp = cc->EvalMult(cc->EvalAdd(signValue, 1), 0.5);

    return comp;
}

// TODO add unittest if used
Ciphertext<DCRTPoly> Comparison::max(const CryptoContext<DCRTPoly> &cc,
                                     const Ciphertext<DCRTPoly> &a,
                                     const Ciphertext<DCRTPoly> &b) {
    // max(a,b) = (a+b)/2 + (a-b)/2 * sign(a-b)
    auto diff = cc->EvalSub(a, b);
    auto sum = cc->EvalAdd(a, b);
    auto sign = compositeSign<4>(diff, cc, 3, 3);

    auto halfDiff = cc->EvalMult(diff, 0.5);
    auto halfSum = cc->EvalMult(sum, 0.5);

    auto scale = cc->EvalMult(halfDiff, sign);

    return cc->EvalAdd(halfSum, scale);
}
