#include <array>
#include <cmath>
#include <fstream>
#include <iostream>
#include <vector>

#include "comparison.h" // Include your Sinc struct here
#include "math/chebyshev.h"
#include "openfhe.h"
constexpr int sincPolyDegree = 611;

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

template <int N> void generateCoefficients(std::ofstream &outFile) {
    outFile << "constexpr std::array<std::array<double, " << sincPolyDegree + 1
            << ">, " << N << "> generatedCoefficients_" << N << " = {{\n";
    for (int i = 0; i < N; ++i) {
        auto coeffs = lbcrypto::EvalChebyshevCoefficients(
            [i](double x) { return Sinc<N>::scaled_sinc_j(x, i); }, -1.0, 1.0,
            sincPolyDegree);
        outFile << "    {";
        for (size_t j = 0; j < sincPolyDegree + 1; ++j) {
            outFile << coeffs[j];
            if (j < sincPolyDegree)
                outFile << ", ";
        }
        outFile << "}";
        if (i < N - 1)
            outFile << ",";
        outFile << "\n";
    }
    outFile << "}};\n\n";
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
