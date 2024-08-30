#pragma once

#include "ciphertext-fwd.h"
#include "key/keypair.h"
#include "lattice/hal/lat-backend.h"
#include "openfhe.h"
#include <cassert>
#include <vector>

using namespace lbcrypto;

inline std::string getContextLines(const char *filename, int lineNum,
                                   int contextLines) {
    std::ifstream file(filename);
    std::vector<std::string> lines;
    std::string line;
    int currentLine = 0;

    while (std::getline(file, line) && currentLine < lineNum) {
        if (lines.size() == static_cast<size_t>(contextLines)) {
            lines.erase(lines.begin());
        }
        lines.push_back(line);
        currentLine++;
    }

    std::ostringstream oss;
    for (const auto &l : lines) {
        oss << l << '\n';
    }
    return oss.str();
}

#define PRINT_PT(enc, ct)                                                      \
    do {                                                                       \
        std::cout << (enc)->getPlaintext((ct)) << ": " << #ct << "\n";         \
    } while (0)

#define PRINT_PT_CONTEXT(enc, ct)                                              \
    do {                                                                       \
        std::cout << "\n" << __FILE__ << ":" << __LINE__ << " - Context:\n";   \
        std::cout << getContextLines(__FILE__, __LINE__, 5);                   \
        std::cout << "Decrypted values:\n";                                    \
        PRINT_PT(enc, ct);                                                     \
    } while (0)

class Encryption {
  public:
    Ciphertext<DCRTPoly> encryptInput(std::vector<double> input);
    // std::vector<double> getPlaintext(Ciphertext<DCRTPoly> ct);
    [[nodiscard]] std::vector<double>
    getPlaintext(const Ciphertext<DCRTPoly> &ct,
                 double threshold = 1e-10) const;
    // std::vector<double> getPlaintextOutput(PrivateKey<DCRTPoly> sk);
    Encryption(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> kp)
        : m_cc(cc), m_KeyPair(kp) {}

  private:
    CryptoContext<DCRTPoly> m_cc;
    KeyPair<DCRTPoly> m_KeyPair;
};
