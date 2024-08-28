#include <algorithm>
#include <gtest/gtest.h>
#include <random>
#include <vector>

#include "constants.h"
#include "key/privatekey-fwd.h"
#include "lattice/hal/lat-backend.h"
#include "sort_algo.h"

using namespace lbcrypto;

PrivateKey<DCRTPoly> sk;

class DirectSortTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Set up the CryptoContext
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(29);
        parameters.SetScalingModSize(50);
        parameters.SetBatchSize(32);
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
        sk = m_privateKey;

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
        m_directSort = std::make_unique<DirectSort>(m_cc, m_publicKey);
    }

    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_publicKey;
    PrivateKey<DCRTPoly> m_privateKey;
    std::unique_ptr<DirectSort> m_directSort;
};

TEST_F(DirectSortTest, ConstructRankForSize32Array) {
    // Create a random array of 32 elements
    std::vector<double> inputArray(32);
    std::iota(inputArray.begin(), inputArray.end(), 0);
    std::shuffle(inputArray.begin(), inputArray.end(),
                 std::mt19937{std::random_device{}()});

    // Encrypt the input array
    Plaintext ptxt = m_cc->MakeCKKSPackedPlaintext(inputArray);
    auto ctxt = m_cc->Encrypt(m_publicKey, ptxt);

    // Construct rank using DirectSort
    auto ctxtRank = m_directSort->constructRank(ctxt);

    // Decrypt the result
    Plaintext result;
    m_cc->Decrypt(m_privateKey, ctxtRank, &result);
    std::vector<double> decryptedRanks = result->GetRealPackedValue();

    // Calculate the expected ranks
    std::vector<double> expectedRanks(32);
    for (int i = 0; i < 32; ++i) {
        expectedRanks[i] =
            std::count_if(inputArray.begin(), inputArray.end(),
                          [&](double val) { return val < inputArray[i]; });
    }

    // Compare the results
    for (int i = 0; i < 32; ++i) {
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
