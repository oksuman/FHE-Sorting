#include "comparison.h"
#include "sort.h"
#include <gtest/gtest.h>
#include <random>

class arraySortTest : public ::testing::Test {
  protected:
    CryptoContext<DCRTPoly> cc;
    KeyPair<DCRTPoly> keyPair;
    arraySort *sorter;

    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(50);
        parameters.SetScalingModSize(59);
        parameters.SetBatchSize(8);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 14);
        parameters.SetFirstModSize(60);

        cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(FHE);

        keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        cc->EvalRotateKeyGen(keyPair.secretKey, {1});

        sorter = new arraySort(cc, keyPair.publicKey);
    }

    void TearDown() override { delete sorter; }

    Ciphertext<DCRTPoly> encryptValue(double value) {
        std::vector<double> vec = {value};
        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(vec);
        return cc->Encrypt(keyPair.publicKey, ptxt);
    }

    double decryptValue(const Ciphertext<DCRTPoly> &ciphertext) {
        Plaintext result;
        cc->Decrypt(keyPair.secretKey, ciphertext, &result);
        return result->GetRealPackedValue()[0];
    }

    void printPrecisionInfo(const Ciphertext<DCRTPoly> &ciphertext,
                            const std::string &label) {
        Plaintext ptxt;
        cc->Decrypt(keyPair.secretKey, ciphertext, &ptxt);
        std::cout << label << " Log Error: " << ptxt->GetLogError()
                  << ", Log Precision: " << ptxt->GetLogPrecision()
                  << std::endl;
    }
};

TEST_F(arraySortTest, EncryptionDecryptionTest) {
    double originalValue = 5.0;
    auto encrypted = encryptValue(originalValue);
    double decrypted = decryptValue(encrypted);
    EXPECT_NEAR(decrypted, originalValue, 0.01);
    printPrecisionInfo(encrypted, "After Encryption");
}

TEST_F(arraySortTest, CompareFunctionStepByStep) {
    auto a = encryptValue(5.0);
    auto b = encryptValue(3.0);

    // Step 1: Subtraction
    auto diff = cc->EvalSub(a, b);
    printPrecisionInfo(diff, "After Subtraction");
    double decryptedDiff = decryptValue(diff);
    EXPECT_NEAR(decryptedDiff, 2.0, 0.01);

    // Step 2: Sign function (simplified for testing)
    auto sign = compositeSign(diff, cc, 3, 3);
    printPrecisionInfo(sign, "After Sign");
    double decryptedSign = decryptValue(sign);
    EXPECT_NEAR(decryptedSign, 1.0, 0.01);

    // Step 3: Compute comparison result
    auto comp = cc->EvalMult(cc->EvalAdd(sign, 1.0), 0.5);
    printPrecisionInfo(comp, "After Comparison");
    double decryptedComp = decryptValue(comp);
    EXPECT_NEAR(decryptedComp, 1.0, 0.01);
}

TEST_F(arraySortTest, BitonicCompareFunction) {
    auto a = encryptValue(5.0);
    auto b = encryptValue(3.0);

    // Test ascending order
    auto result = sorter->bitonicCompare(a, b, true);
    printPrecisionInfo(result, "After Bitonic Compare (Ascending)");
    double decrypted_a = decryptValue(result);
    EXPECT_NEAR(decrypted_a, 3.0, 0.01);

    // Test descending order
    result = sorter->bitonicCompare(a, b, false);
    printPrecisionInfo(result, "After Bitonic Compare (Descending)");
    decrypted_a = decryptValue(result);
    EXPECT_NEAR(decrypted_a, 5.0, 0.01);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
