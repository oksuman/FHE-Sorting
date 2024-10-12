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

#ifdef ENABLE_PRINT_PT
#define PRINT_PT(enc, ct)                                                      \
    do {                                                                       \
        if (dynamic_cast<const DebugEncryption *>((enc).get()) != nullptr) {   \
            auto pt = (enc) -> getPlaintext((ct));                             \
            std::cout << pt << ": " << #ct << " Level: " << (ct)->GetLevel()   \
                      << ", LogPrecision: "                                    \
                      << (enc)->getDecrypt((ct))->GetLogPrecision() << "\n";   \
        }                                                                      \
    } while (0)
#else
#define PRINT_PT(enc, ct)
#endif

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
    Encryption(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk)
        : m_cc(cc), m_PublicKey(pk) {}

    virtual std::vector<double> getPlaintext(const Ciphertext<DCRTPoly> &ct,
                                             double threshold = 1e-10) const {
        // Default implementation throws an exception
        throw std::runtime_error(
            "Decryption not available in base Encryption class");
    }
    virtual Plaintext getDecrypt(const Ciphertext<DCRTPoly> &ct) const {
        // Default implementation throws an exception
        throw std::runtime_error(
            "Decryption not available in base Encryption class");
    }
    virtual ~Encryption() = default;

    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
};

class DebugEncryption : public Encryption {
  public:
    [[nodiscard]] std::vector<double>
    getPlaintext(const Ciphertext<DCRTPoly> &ct,
                 double threshold = 1e-10) const override;

    Plaintext getDecrypt(const Ciphertext<DCRTPoly> &ct) const override;

    DebugEncryption(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keyPair)
        : Encryption(cc, keyPair.publicKey), m_PrivateKey(keyPair.secretKey) {}

    ~DebugEncryption() override = default;

  private:
    PrivateKey<DCRTPoly> m_PrivateKey;
};
