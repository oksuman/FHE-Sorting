#include <algorithm>
#include <gtest/gtest.h>
#include <random>
#include <vector>

#include "comparison.h"
#include "constants.h"
#include "encryption.h"
#include "key/privatekey-fwd.h"
#include "lattice/hal/lat-backend.h"
#include "sort_algo.h"

using namespace lbcrypto;

class DirectSortTest : public ::testing::Test {
  protected:
    void SetUp() override {
        array_length = 32;
        // Set up the CryptoContext
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(40);
        parameters.SetScalingModSize(50);
        parameters.SetBatchSize(array_length);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 12);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);

        // Generate keys
        auto keyPair = m_cc->KeyGen();
        m_publicKey = keyPair.publicKey;
        m_privateKey = keyPair.secretKey;

        std::vector<int> rotations;

        for (int i = 1; i <= 32; i++) {
            rotations.push_back(i);
            rotations.push_back(-i);
        }
        for (int i = 1; i <= 32; i++) {
            rotations.push_back(-i * 64);
        }

        // Generate the rotation keys
        m_cc->EvalRotateKeyGen(m_privateKey, rotations);
        m_cc->EvalMultKeyGen(m_privateKey);

        // Create DirectSort object

        m_enc = std::make_shared<Encryption>(m_cc, keyPair);

        m_directSort = std::make_unique<DirectSort>(m_cc, m_publicKey, m_enc);
    }

    int array_length;
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::unique_ptr<DirectSort> m_directSort;
    std::shared_ptr<Encryption> m_enc;
};
TEST_F(DirectSortTest, ConstructRank) {
    // Create a random array of 32 elements
    std::vector<double> inputArray(array_length);
    std::iota(inputArray.begin(), inputArray.end(), 0.0);
    std::shuffle(inputArray.begin(), inputArray.end(),
                 std::mt19937{std::random_device{}()});
    std::cout << inputArray << "\n";

    // Encrypt the input array
    auto ctxt = m_enc->encryptInput(inputArray);

    // Construct rank using DirectSort
    auto ctxtRank = m_directSort->constructRankv3(ctxt);

    // Decrypt the result
    Plaintext result;
    m_cc->Decrypt(m_privateKey, ctxtRank, &result);
    std::vector<double> decryptedRanks = result->GetRealPackedValue();

    // Calculate the expected ranks
    std::vector<double> expectedRanks(array_length);
    for (int i = 0; i < 32; ++i) {
        expectedRanks[i] =
            std::count_if(inputArray.begin(), inputArray.end(),
                          [&](double val) { return val < inputArray[i]; });
    }

    // Compare the results
    for (int i = 0; i < array_length; ++i) {
        EXPECT_NEAR(decryptedRanks[i], expectedRanks[i], 0.1)
            << "Mismatch at index " << i << ": expected " << expectedRanks[i]
            << ", got " << decryptedRanks[i];
    }

    // Print the input array and the calculated ranks
    std::cout << "Input array: ";
    for (const auto &val : inputArray) {
        std::cout << val << " ";
    }
    std::cout << std::endl;

    std::cout << "Calculated ranks: ";
    for (const auto &rank : decryptedRanks) {
        std::cout << rank << " ";
    }
    std::cout << std::endl;
}
