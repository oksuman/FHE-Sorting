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
