#include "encryption.h"
#include "ciphertext-fwd.h"
#include "lattice/hal/lat-backend.h"

Ciphertext<DCRTPoly> Encryption::encryptInput(std::vector<double> input) {
    // std::cout << "max batch: " <<  m_cc->GetRingDimension() / 2 << std::endl;
    // std::cout << "input size: " << input.size() << std::endl;

    assert(input.size() <= m_cc->GetRingDimension() / 2 &&
           "Input size is larger than the maximum available batch size");

    Plaintext plaintext = m_cc->MakeCKKSPackedPlaintext(input);
    auto ciphertext = m_cc->Encrypt(m_PublicKey, plaintext);
    return ciphertext;
}

[[nodiscard]] std::vector<double>
DebugEncryption::getPlaintext(const Ciphertext<DCRTPoly> &ct,
                              double threshold) const {
    Plaintext decryptedResult;
    m_cc->Decrypt(m_PrivateKey, ct, &decryptedResult);
    std::vector<double> result = decryptedResult->GetRealPackedValue();

    for (auto &value : result) {
        if (std::abs(value) < threshold) {
            value = 0.0;
        }
    }
    return result;
}

Plaintext DebugEncryption::getDecrypt(const Ciphertext<DCRTPoly> &ct) const {
    Plaintext decryptedResult;
    m_cc->Decrypt(m_PrivateKey, ct, &decryptedResult);
    return decryptedResult;
}
