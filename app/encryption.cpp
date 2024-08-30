#include "encryption.h"
#include "ciphertext-fwd.h"
#include "lattice/hal/lat-backend.h"

Ciphertext<DCRTPoly> Encryption::encryptInput(std::vector<double> input) {
    assert(input.size() == m_cc->GetEncodingParams()->GetBatchSize() &&
           "Batch Size is not equal to input size");
    Plaintext plaintext = m_cc->MakeCKKSPackedPlaintext(input);
    auto ciphertext = m_cc->Encrypt(m_KeyPair.publicKey, plaintext);
    return ciphertext;
}

[[nodiscard]] std::vector<double>
Encryption::getPlaintext(const Ciphertext<DCRTPoly> &ct,
                         double threshold) const {
    Plaintext decryptedResult;
    m_cc->Decrypt(m_KeyPair.secretKey, ct, &decryptedResult);
    std::vector<double> result = decryptedResult->GetRealPackedValue();

    for (auto &value : result) {
        if (std::abs(value) < threshold) {
            value = 0.0;
        }
    }
    return result;
}
