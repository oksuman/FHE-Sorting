#include "comparison.h"
#include "sign.h"

Ciphertext<DCRTPoly> Comparison::compare(const CryptoContext<DCRTPoly> &cc,
                                         const Ciphertext<DCRTPoly> &a,
                                         const Ciphertext<DCRTPoly> &b) {
    std::vector<int> degrees = {13, 13, 13, 13, 27};
    std::vector<std::vector<double>> coeffs = {
        {0, 0.637521624232179, 0, -0.214410085609765, 0, 0.131025092314809, 0, -0.096334661466356, 0, 0.078106902680506, 0, -0.067687481130277, 0, 0.531756561506267},
        {0, 0.639589760068116, 0, -0.215094255700719, 0, 0.131429310051565, 0, -0.096616513955493, 0, 0.078318761329921, 0, -0.067853009038948, 0, 0.530203990608004},
        {0, 0.662043033261071, 0, -0.222514602957091, 0, 0.135804057342459, 0, -0.099656460988517, 0, 0.080592085370209, 0, -0.069615920073568, 0, 0.513326796143351},
        {0, 1.046504392380398, 0, -0.348118160418968, 0, 0.208015553193116, 0, -0.147673474293600, 0, 0.113925320686963, 0, -0.092273857896572, 0, 0.077145433705809},
        {0, 1.258972382040490, 0, -0.383395863493761, 0, 0.191771130371970, 0, -0.103942850907721, 0, 0.055620046045078, 0, -0.028224005949209, 0, 0.013245914915556, 0, -0.005631044864086, 0, 0.002121918531639, 0, -0.000690115007953, 0, 0.000186624983631, 0, -0.000039558557172, 0, 0.000005888811044, 0, -0.000000467069802}
    };
    std::vector<double> interval_bound = {
        1.00,  
        1.9994, 
        1.9929,  
        1.9252, 
        1.2164  
    };
    MinimaxSignConfig config(degrees, coeffs, interval_bound);

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
