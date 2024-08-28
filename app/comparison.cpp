#include "comparison.h"

double scaled_sinc(double x) {
    if (std::abs(x) < 1e-10) {
        return 1.0;
    } else {
        return std::sin(M_PI * 2048 * x) / (M_PI * 2048 * x);
    }
}

double scaled_sinc_j(double x, int j) {
    const double epsilon = 1e-10;
    const double factor = 2048 * M_PI;

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

Ciphertext<lbcrypto::DCRTPoly> g_n(Ciphertext<lbcrypto::DCRTPoly> x,
                                   CryptoContext<DCRTPoly> cc) {
    std::vector<double> coeffs = {0.0, 1.112086941473206858077560355014,
                                  0.0, -3.734028305547490433902169115754e-01,
                                  0.0, 2.206814218885782830081865313332e-01,
                                  0.0, -1.614281734745303398259608229637e-01,
                                  0.0, 1.213110949202888116937870677248e-01,
                                  0.0, -1.040122217184874797712978988784e-01,
                                  0.0, 8.261882702673599421228090022851e-02,
                                  0.0, -7.778143277137586353298104313581e-02,
                                  0.0, 6.144666896827026547622807584048e-02,
                                  0.0, -6.346221296887255558516471865005e-02,
                                  0.0, 4.718457305271417379088916277396e-02,
                                  0.0, -5.579119677451320480354723940764e-02,
                                  0.0, 3.473519015361416217846368681421e-02,
                                  0.0, -5.622757517465633292363946793557e-02};
    return cc->EvalChebyshevSeriesPS(x, coeffs, -1, 1);
}

Ciphertext<lbcrypto::DCRTPoly> f_n(Ciphertext<lbcrypto::DCRTPoly> x,
                                   CryptoContext<DCRTPoly> cc) {
    const double c1 = 3.14208984375;
    const double c3 = -7.33154296875;
    const double c5 = 13.19677734375;
    const double c7 = -15.71044921875;
    const double c9 = 12.21923828125;
    const double c11 = -5.99853515625;
    const double c13 = 1.69189453125;
    const double c15 = -0.20947265625;

    auto x2 = cc->EvalSquare(x);
    auto x4 = cc->EvalSquare(x2);
    auto x8 = cc->EvalSquare(x4);

    auto y = cc->EvalMult(x, c1);
    cc->EvalAddInPlace(y, cc->EvalMultAndRelinearize(cc->EvalMult(x, c3), x2));

    auto c5x = cc->EvalMult(x, c5);
    auto c7x = cc->EvalMult(x, c7);
    auto c7x3 = cc->EvalMultAndRelinearize(c7x, x2);
    cc->EvalAddInPlace(y,
                       cc->EvalMultAndRelinearize(cc->EvalAdd(c5x, c7x3), x4));

    auto c9x = cc->EvalMult(x, c9);
    auto c11x = cc->EvalMult(x, c11);
    auto tmp1 = cc->EvalAdd(c9x, cc->EvalMultAndRelinearize(c11x, x2));

    auto c13x = cc->EvalMult(x, c13);
    auto c15x = cc->EvalMult(x, c15);
    auto tmp2 = cc->EvalAdd(c13x, cc->EvalMultAndRelinearize(c15x, x2));

    cc->EvalAddInPlace(tmp1, cc->EvalMultAndRelinearize(tmp2, x4));
    cc->EvalAddInPlace(y, cc->EvalMultAndRelinearize(tmp1, x8));

    return y;
}

Ciphertext<lbcrypto::DCRTPoly> compositeSign(Ciphertext<lbcrypto::DCRTPoly> x,
                                             CryptoContext<DCRTPoly> cc, int dg,
                                             int df) {

    auto y = g_n(x, cc);
    cc->EvalMultInPlace(y, 1.0 / 1.032466);
    for (int i = 1; i < dg; i++) {
        y = g_n(y, cc);
        cc->EvalMultInPlace(y, 1.0 / 1.032466);
    }
    for (int i = 0; i < df; i++) {
        y = f_n(y, cc);
    }
    return y;
}

Ciphertext<DCRTPoly> compare(const CryptoContext<DCRTPoly> &cc,
                             const Ciphertext<DCRTPoly> &a,
                             const Ciphertext<DCRTPoly> &b) {

    // (sgn(a-b) + 1)/2
    // Returns 1 if a > b
    //         0 if a < b
    // Step 1: Subtraction
    auto diff = cc->EvalSub(a, b);

    // Step 2: Sign function
    auto sign = compositeSign(diff, cc, 3, 3);

    // Step 3: Compute comparison result
    auto comp = cc->EvalMult(cc->EvalAdd(sign, 1), 0.5);

    return comp;
}
