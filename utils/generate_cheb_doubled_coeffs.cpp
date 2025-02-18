#include "comparison.h"
#include "math/chebyshev.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-utils.h"
#include <array>
#include <cmath>
#include <fstream>
#include <iostream>
#include <vector>

constexpr double COEFFICIENT_THRESHOLD = 1e-8;
constexpr int sincPolyDegree = 13011;

template <int N> std::vector<double> generateTruncatedCoefficients() {
    auto coeffs = lbcrypto::EvalChebyshevCoefficients(
        [](double x) { return Sinc<2 * N>::doubled_sinc(x); }, -1.0, 1.0,
        sincPolyDegree);

    std::vector<double> filteredCoeffs;
    filteredCoeffs.reserve(coeffs.size());

    for (size_t i = 0; i < coeffs.size(); ++i) {
        if (std::abs(coeffs[i]) >= COEFFICIENT_THRESHOLD) {
            filteredCoeffs.push_back(coeffs[i]);
        } else {
            filteredCoeffs.push_back(0.0);
        }
    }

    while (!filteredCoeffs.empty() &&
           std::abs(filteredCoeffs.back()) < COEFFICIENT_THRESHOLD) {
        filteredCoeffs.pop_back();
    }

    return filteredCoeffs;
}

template <int N> void generateCoefficients(std::ofstream &outFile) {
    outFile << "const std::vector<double> generatedDoubledSincCoefficients_"
            << N << " = {\n";
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
    outFile << "const std::vector<double>& selectDoubledSincCoefficients() {\n";
    outFile << "    if constexpr (N == 4) {\n";
    outFile << "        return generatedDoubledSincCoefficients_4;\n";

    auto print_size = [&outFile](int size) {
        outFile << " } else if constexpr (N == " << size << ") {\n";
        outFile << "     return generatedDoubledSincCoefficients_" << size
                << ";\n";
    };

    print_size(8);
    print_size(16);
    print_size(32);
    print_size(64);
    print_size(128);
    print_size(256);
    print_size(512);
    print_size(1024);
    print_size(2048);
    print_size(4096);
    print_size(8192);
    print_size(16384);

    outFile << "    } else {\n";
    outFile << "        return generatedDoubledSincCoefficients_4;\n";
    outFile << "    }\n";
    outFile << "}\n";
}

int main() {
    std::ofstream outFile("generated_doubled_sinc_coeffs.h");
    outFile << "#include <array>\n";
    outFile << "#include <vector>\n\n";

    generateCoefficients<4>(outFile);
    generateCoefficients<8>(outFile);
    generateCoefficients<16>(outFile);
    generateCoefficients<32>(outFile);
    generateCoefficients<64>(outFile);
    generateCoefficients<128>(outFile);
    generateCoefficients<256>(outFile);
    generateCoefficients<512>(outFile);
    generateCoefficients<1024>(outFile);
    generateCoefficients<2048>(outFile);
    generateCoefficients<4096>(outFile);
    generateCoefficients<8192>(outFile);
    generateCoefficients<16384>(outFile);
    generateSelectorFunction(outFile);

    outFile.close();
    return 0;
}