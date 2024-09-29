#include "comparison.h"
#include "math/chebyshev.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include <array>
#include <cmath>
#include <fstream>
#include <iostream>
#include <vector>

constexpr double COEFFICIENT_THRESHOLD = 1e-15;
constexpr double EVEN_COEFFICIENT_THRESHOLD =
    1e-6; // New threshold for even coefficients
constexpr int sincPolyDegree = 1011;

template <int N> std::vector<double> generateTruncatedCoefficients() {
    auto coeffs = lbcrypto::EvalChebyshevCoefficients(
        [](double x) { return Sinc<2 * N>::scaled_sinc(x); }, -1.0, 1.0,
        sincPolyDegree);

    std::vector<double> filteredCoeffs;
    filteredCoeffs.reserve(coeffs.size());

    for (size_t i = 0; i < coeffs.size(); ++i) {
        if (i % 2 == 0) { // Even index
            if (std::abs(coeffs[i]) >= EVEN_COEFFICIENT_THRESHOLD) {
                filteredCoeffs.push_back(coeffs[i]);
            } else {
                filteredCoeffs.push_back(0.0); // Zero out if below threshold
            }
        } else {                           // Odd index
            filteredCoeffs.push_back(0.0); // Always zero out odd coefficients
        }
    }

    // Trim trailing zeros
    while (!filteredCoeffs.empty() &&
           std::abs(filteredCoeffs.back()) < COEFFICIENT_THRESHOLD) {
        filteredCoeffs.pop_back();
    }

    return filteredCoeffs;
}

template <int N> void generateCoefficients(std::ofstream &outFile) {
    outFile << "const std::vector<double> generatedCoefficients_" << N
            << " = {\n";
    auto coeffs = generateTruncatedCoefficients<N>();
    for (size_t j = 0; j < coeffs.size(); ++j) {
        outFile << "    " << coeffs[j];
        if (j < coeffs.size() - 1)
            outFile << ",";
        outFile << "\n";
    }
    outFile << "};\n\n";
}

void generateSelectorFunction(std::ofstream &outFile) {
    outFile << "template<std::size_t N>\n";
    outFile << "const std::vector<double>& selectCoefficients() {\n";
    outFile << "    if constexpr (N == 4) {\n";
    outFile << "        return generatedCoefficients_4;\n";
    outFile << "    } else if constexpr (N == 32) {\n";
    outFile << "        return generatedCoefficients_32;\n";
    outFile << "    } else if constexpr (N == 128) {\n";
    outFile << "        return generatedCoefficients_128;\n";
    outFile << "    } else {\n";
    outFile << "        static_assert(N == 4 || N == 32 || N == 128, "
               "\"Unsupported size for coefficients\");\n";
    outFile << "        return generatedCoefficients_4; // Default case to "
               "satisfy compiler\n";
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
