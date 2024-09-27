#include "comparison.h"
#include "math/chebyshev.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include <array>
#include <cmath>
#include <fstream>
#include <iostream>
#include <vector>

constexpr double COEFFICIENT_THRESHOLD = 1e-10;
constexpr int sincPolyDegree = 611;

template <int N> std::vector<double> generateTruncatedCoefficients(int i) {
    auto coeffs = lbcrypto::EvalChebyshevCoefficients(
        [i](double x) { return Sinc<N>::scaled_sinc_j(x, i); }, -1.0, 1.0,
        sincPolyDegree);

    // Find the last significant coefficient
    int lastSignificantIndex = coeffs.size() - 1;
    while (lastSignificantIndex >= 0 &&
           std::abs(coeffs[lastSignificantIndex]) < COEFFICIENT_THRESHOLD) {
        lastSignificantIndex--;
    }

    // Create a new vector with only significant coefficients
    return std::vector<double>(coeffs.begin(),
                               coeffs.begin() + lastSignificantIndex + 1);
}

template <int N> void generateCoefficients(std::ofstream &outFile) {
    outFile << "const std::array<std::vector<double>, " << N
            << "> generatedCoefficients_" << N << " = {{\n";
    for (int i = 0; i < N; ++i) {
        auto coeffs = generateTruncatedCoefficients<N>(i);
        outFile << "    {";
        for (size_t j = 0; j < coeffs.size(); ++j) {
            outFile << coeffs[j];
            if (j < coeffs.size() - 1)
                outFile << ", ";
        }
        outFile << "}";
        if (i < N - 1)
            outFile << ",";
        outFile << "\n";
    }
    outFile << "}};\n\n";
}

void generateSelectorFunction(std::ofstream &outFile) {
    outFile << "template<std::size_t N>\n";
    outFile << "constexpr auto selectCoefficients() {\n";
    outFile << "    if constexpr (N == 4) {\n";
    outFile << "        return generatedCoefficients_4;\n";
    outFile << "    } else if constexpr (N == 32) {\n";
    outFile << "        return generatedCoefficients_32;\n";
    outFile << "    } else if constexpr (N == 128) {\n";
    outFile << "        return generatedCoefficients_128;\n";
    outFile << "    } else {\n";
    outFile << "        static_assert(N <= 128, \"Unsupported size for "
               "coefficients\");\n";
    outFile << "    }\n";
    outFile << "}\n";
}

int main() {
    std::ofstream outFile("generated_coeffs.h");
    outFile << "// This file is generated automatically by evaluating "
               "coefficients of \n";
    outFile << "// Chebyshev approximation for the given function. \n";
    outFile << "#include <array>\n";
    outFile << "#include <vector>\n\n";

    generateCoefficients<4>(outFile);
    generateCoefficients<32>(outFile);
    generateCoefficients<128>(outFile);
    generateSelectorFunction(outFile);

    outFile.close();
    return 0;
}
