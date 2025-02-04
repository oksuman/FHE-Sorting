#include "SortUtils.h"
#include "openfhe.h"
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace lbcrypto;
using namespace kwaySort;

class SortUtilsTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Set up the crypto context
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(50);
        parameters.SetScalingModSize(59);
        parameters.SetBatchSize(16);
        parameters.SetRingDim(1 << 12);
        parameters.SetSecurityLevel(HEStd_NotSet);

        m_cc = GenCryptoContext(parameters);
        m_cc->Enable(PKE);
        m_cc->Enable(KEYSWITCH);
        m_cc->Enable(LEVELEDSHE);
        m_cc->Enable(ADVANCEDSHE);
        m_cc->Enable(FHE);

        m_keys = m_cc->KeyGen();
        m_cc->EvalMultKeyGen(m_keys.secretKey);

        std::vector<int> rotations;
        for (int i = 1; i < 16; i++) {
            rotations.push_back(i);
            rotations.push_back(-i);
        }

        m_cc->EvalRotateKeyGen(m_keys.secretKey, rotations);

        // Setup bootstrapping
        auto slots = m_cc->GetEncodingParams()->GetBatchSize();
        m_cc->EvalBootstrapSetup({3, 3}, {0, 0}, slots);
        m_cc->EvalBootstrapKeyGen(m_keys.secretKey, slots);

        auto enc = std::make_shared<DebugEncryption>(m_cc, m_keys);
        m_sortUtils =
            std::make_unique<SortUtils>(m_cc, enc, slots, 5 /*k*/, 2 /*M*/,
                                        m_keys.secretKey, m_keys.publicKey);
    }

    void VerifyResults(const Ciphertext<DCRTPoly> &result,
                       const std::vector<double> &expected,
                       double tolerance = 0.1) {
        Plaintext ptResult;
        m_cc->Decrypt(m_keys.secretKey, result, &ptResult);
        auto resultValues = ptResult->GetRealPackedValue();

        for (size_t i = 0; i < expected.size(); i++) {
            EXPECT_NEAR(resultValues[i], expected[i], tolerance)
                << "Mismatch at index " << i;
        }
    }

    CryptoContext<DCRTPoly> m_cc;
    KeyPair<DCRTPoly> m_keys;
    std::unique_ptr<SortUtils> m_sortUtils;
};

TEST_F(SortUtilsTest, FcnL) {
    // Test vectors
    std::vector<double> input1 = {2.0, 4.0, 6.0, 8.0};
    std::vector<double> input2 = {1.0, 5.0, 3.0, 7.0};
    std::vector<double> compValues = {1.0, 0.0, 1.0,
                                      1.0}; // a > b comparison results

    auto pt1 = m_cc->MakeCKKSPackedPlaintext(input1);
    auto pt2 = m_cc->MakeCKKSPackedPlaintext(input2);
    auto ptComp = m_cc->MakeCKKSPackedPlaintext(compValues);

    auto ct1 = m_cc->Encrypt(m_keys.publicKey, pt1);
    auto ct2 = m_cc->Encrypt(m_keys.publicKey, pt2);
    auto ctComp = m_cc->Encrypt(m_keys.publicKey, ptComp);

    Ciphertext<DCRTPoly> result;
    m_sortUtils->fcnL(ct1, ct2, ctComp, result);

    // Expected: (a > b) * a + (a < b) * b
    std::vector<double> expected = {2.0, 5.0, 6.0, 8.0};
    VerifyResults(result, expected);
}

TEST_F(SortUtilsTest, TwoSorter) {
    std::vector<double> input1 = {5.0, 2.0, 8.0, 1.0};
    std::vector<double> input2 = {3.0, 6.0, 4.0, 7.0};
    std::vector<double> compValues = {1.0, 0.0, 1.0, 0.0}; // comparison results

    auto pt1 = m_cc->MakeCKKSPackedPlaintext(input1);
    auto pt2 = m_cc->MakeCKKSPackedPlaintext(input2);
    auto ptComp = m_cc->MakeCKKSPackedPlaintext(compValues);

    Ciphertext<DCRTPoly> ctxt[2];
    ctxt[0] = m_cc->Encrypt(m_keys.publicKey, pt1);
    ctxt[1] = m_cc->Encrypt(m_keys.publicKey, pt2);
    auto ctComp = m_cc->Encrypt(m_keys.publicKey, ptComp);

    Ciphertext<DCRTPoly> result[2];
    m_sortUtils->twoSorter(ctxt, ctComp, result);

    std::vector<double> expectedMin = {3.0, 2.0, 4.0, 1.0};
    std::vector<double> expectedMax = {5.0, 6.0, 8.0, 7.0};

    VerifyResults(result[0], expectedMin);
    VerifyResults(result[1], expectedMax);
}

TEST_F(SortUtilsTest, ThreeSorter) {
    // Test vectors for 3-way sort
    std::vector<double> input1 = {5.0, 9.0, 3.0, 7.0};
    std::vector<double> input2 = {2.0, 4.0, 8.0, 1.0};
    std::vector<double> input3 = {6.0, 1.0, 4.0, 5.0};

    // Comparison vectors (a>b, a>c, b>c)
    std::vector<double> comp1 = {1.0, 1.0, 0.0, 1.0}; // a>b
    std::vector<double> comp2 = {0.0, 1.0, 0.0, 1.0}; // a>c
    std::vector<double> comp3 = {0.0, 1.0, 1.0, 0.0}; // b>c

    Ciphertext<DCRTPoly> ctxt[3];
    Ciphertext<DCRTPoly> ctxtComp[3];

    auto pt1 = m_cc->MakeCKKSPackedPlaintext(input1);
    auto pt2 = m_cc->MakeCKKSPackedPlaintext(input2);
    auto pt3 = m_cc->MakeCKKSPackedPlaintext(input3);

    ctxt[0] = m_cc->Encrypt(m_keys.publicKey, pt1);
    ctxt[1] = m_cc->Encrypt(m_keys.publicKey, pt2);
    ctxt[2] = m_cc->Encrypt(m_keys.publicKey, pt3);

    auto ptComp1 = m_cc->MakeCKKSPackedPlaintext(comp1);
    auto ptComp2 = m_cc->MakeCKKSPackedPlaintext(comp2);
    auto ptComp3 = m_cc->MakeCKKSPackedPlaintext(comp3);

    ctxtComp[0] = m_cc->Encrypt(m_keys.publicKey, ptComp1);
    ctxtComp[1] = m_cc->Encrypt(m_keys.publicKey, ptComp2);
    ctxtComp[2] = m_cc->Encrypt(m_keys.publicKey, ptComp3);

    Ciphertext<DCRTPoly> result[3];
    m_sortUtils->threeSorter(ctxt, ctxtComp, result);

    std::vector<double> expectedMin = {2.0, 1.0, 3.0, 1.0};
    std::vector<double> expectedMid = {5.0, 4.0, 4.0, 5.0};
    std::vector<double> expectedMax = {6.0, 9.0, 8.0, 7.0};

    VerifyResults(result[0], expectedMin);
    VerifyResults(result[1], expectedMid);
    VerifyResults(result[2], expectedMax);
}

TEST_F(SortUtilsTest, FourSorter) {
    // Test vectors for 4-way sort
    std::vector<double> input1 = {9.0, 7.0, 5.0};
    std::vector<double> input2 = {6.0, 4.0, 8.0};
    std::vector<double> input3 = {3.0, 8.0, 2.0};
    std::vector<double> input4 = {7.0, 2.0, 6.0};

    // Comparison vectors
    std::vector<double> comp1 = {1.0, 1.0, 0.0}; // a>b
    std::vector<double> comp2 = {1.0, 0.0, 1.0}; // a>c
    std::vector<double> comp3 = {1.0, 1.0, 0.0}; // a>d
    std::vector<double> comp4 = {1.0, 0.0, 1.0}; // b>c
    std::vector<double> comp5 = {0.0, 1.0, 1.0}; // b>d
    std::vector<double> comp6 = {0.0, 1.0, 0.0}; // c>d

    Ciphertext<DCRTPoly> ctxt[4];
    Ciphertext<DCRTPoly> ctxtComp[6];

    std::vector<std::vector<double>> inputs = {input1, input2, input3, input4};
    std::vector<std::vector<double>> comps = {comp1, comp2, comp3,
                                              comp4, comp5, comp6};

    for (int i = 0; i < 4; i++) {
        auto pt = m_cc->MakeCKKSPackedPlaintext(inputs[i]);
        ctxt[i] = m_cc->Encrypt(m_keys.publicKey, pt);
    }

    for (int i = 0; i < 6; i++) {
        auto pt = m_cc->MakeCKKSPackedPlaintext(comps[i]);
        ctxtComp[i] = m_cc->Encrypt(m_keys.publicKey, pt);
    }

    Ciphertext<DCRTPoly> result[4];
    m_sortUtils->fourSorter(ctxt, ctxtComp, result);

    std::vector<std::vector<double>> expected = {
        {3.0, 2.0, 2.0}, // min
        {6.0, 4.0, 5.0}, // second min
        {7.0, 7.0, 6.0}, // second max
        {9.0, 8.0, 8.0}  // max
    };

    for (int i = 0; i < 4; i++) {
        VerifyResults(result[i], expected[i]);
    }
}

TEST_F(SortUtilsTest, FiveSorter) {
    // Test vectors for 5-way sort
    std::vector<std::vector<double>> inputs = {
        {9.0, 7.0, 5.0}, // a
        {6.0, 4.0, 8.0}, // b
        {3.0, 8.0, 2.0}, // c
        {7.0, 2.0, 6.0}, // d
        {5.0, 6.0, 4.0}  // e
    };

    std::vector<std::vector<double>> comps = {
        {1.0, 1.0, 0.0}, // a>b
        {1.0, 0.0, 1.0}, // a>c
        {1.0, 1.0, 0.0}, // a>d
        {1.0, 1.0, 1.0}, // a>e
        {1.0, 0.0, 1.0}, // b>c
        {0.0, 1.0, 1.0}, // b>d
        {1.0, 0.0, 1.0}, // b>e
        {0.0, 1.0, 0.0}, // c>d
        {0.0, 1.0, 0.0}, // c>e
        {1.0, 0.0, 1.0}  // d>e
    };

    Ciphertext<DCRTPoly> ctxt[5];
    Ciphertext<DCRTPoly> ctxtComp[10];

    for (int i = 0; i < 5; i++) {
        auto pt = m_cc->MakeCKKSPackedPlaintext(inputs[i]);
        ctxt[i] = m_cc->Encrypt(m_keys.publicKey, pt);
    }

    for (int i = 0; i < 10; i++) {
        auto pt = m_cc->MakeCKKSPackedPlaintext(comps[i]);
        ctxtComp[i] = m_cc->Encrypt(m_keys.publicKey, pt);
    }

    Ciphertext<DCRTPoly> result[5];
    m_sortUtils->fiveSorter(ctxt, ctxtComp, result);

    // Expected sorted results
    std::vector<std::vector<double>> expected = {
        {3.0, 2.0, 2.0}, // min
        {5.0, 4.0, 4.0}, // second min
        {6.0, 6.0, 5.0}, // middle
        {7.0, 7.0, 6.0}, // second max
        {9.0, 8.0, 8.0}  // max
    };

    for (int i = 0; i < 5; i++) {
        VerifyResults(result[i], expected[i]);
    }
}

TEST_F(SortUtilsTest, SlotMatching2) {
    std::vector<double> input(16, 0.0);
    for (int i = 0; i < 16; i++) {
        input[i] = i + 1;
    }

    std::vector<double> compValues(16, 0.5);
    std::vector<std::vector<int>> indices(2, std::vector<int>(16, 0));

    auto pt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ptComp = m_cc->MakeCKKSPackedPlaintext(compValues);

    auto ct = m_cc->Encrypt(m_keys.publicKey, pt);
    auto ctComp = m_cc->Encrypt(m_keys.publicKey, ptComp);

    Ciphertext<DCRTPoly> ctxtOut[2];
    Ciphertext<DCRTPoly> ctxtCompOut;

    long shift = 1;
    m_sortUtils->slotMatching2(ct, ctComp, indices, shift, ctxtOut,
                               ctxtCompOut);

    std::vector<double> expected1 = input;
    std::vector<double> expected2(16);
    for (int i = 0; i < 15; i++) {
        expected2[i] = input[i + 1];
    }
    expected2[15] = input[0];

    VerifyResults(ctxtOut[0], expected1);
    VerifyResults(ctxtOut[1], expected2);
    VerifyResults(ctxtCompOut, compValues);
}

TEST_F(SortUtilsTest, SlotMatching3) {
    // Create and initialize input array with exact HEAAN reference values
    std::vector<double> input(16, 0.0);
    input[0] = 0.840188;
    input[1] = 0.394383;
    input[2] = 0.783099;
    input[3] = 0.79844;
    input[4] = 0.911647;
    input[5] = 0.197551; 
    input[6] = 0.335223;
    input[7] = 0.76823;
    input[8] = 0.277775;
    // Rest are 0

    // Comparison values matching HEAAN reference
    std::vector<double> compValues(16, 0.5);
    compValues[0] = 1.0;
    compValues[1] = 0.0;
    compValues[2] = 1.0;
    compValues[3] = 1.0;
    compValues[4] = 1.0;
    compValues[5] = 0.0;
    compValues[6] = 1.0;
    compValues[7] = 1.0;
    compValues[8] = 0.0;
    compValues[9] = 0.500616;

    // Create indices marking every third position
    std::vector<std::vector<int>> indices(2, std::vector<int>(16, 0));
    for (int i = 0; i < 9; i += 1) {
        indices[0][i] = 3;
        indices[1][i] = i % 3 + 1;
    }

    // Encrypt input and comparison values
    auto pt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ptComp = m_cc->MakeCKKSPackedPlaintext(compValues);
    auto ct = m_cc->Encrypt(m_keys.publicKey, pt);
    auto ctComp = m_cc->Encrypt(m_keys.publicKey, ptComp);

    // Process through slotMatching3
    Ciphertext<DCRTPoly> ctxtOut[3];
    Ciphertext<DCRTPoly> ctxtCompOut[3];
    long shift = 1;
    m_sortUtils->slotMatching3(ct, ctComp, indices, shift, ctxtOut, ctxtCompOut);

    // Expected rotated outputs - first 10 slots for each array
    std::vector<std::vector<double>> expectedOut = {
        // Original values (rotation 0)
        {0.840188, 0.394383, 0.783099, 0.79844, 0.911647, 0.197551, 0.335223, 0.76823, 0.277775, 0},
        // Rotated by 1
        {0.394397, 0.783099, 0.79844, 0.911647, 0.197551, 0.335223, 0.76823, 0.277775, 0.0, 0.0},
        // Rotated by 2
        {0.783097, 0.79844, 0.911647, 0.197551, 0.335223, 0.76823, 0.277775, 0.0, 0.0, 0.0}
    };

    // Expected comparison outputs - first 10 slots for each array
    std::vector<std::vector<double>> expectedComp = {
        // First comparison output after flipping
        {1.0, -1, -1, 0.0, 0.0, -1, 0.0, 0.0, -0.500616, -0.5008},
        // Second comparison output (unchanged)
        {1, 0.0, 1, 1, 1, 0.0, 1, 1, 0.0, 0.500616},
        // Third comparison output after flipping
        {0.0, -1, -1, 1, -1, -1, 1, -0.500616, -0.5008, -0.498664}
    };

    // Verify outputs with appropriate tolerance
    for (int i = 0; i < 3; i++) {
        Plaintext ptResult;
        m_cc->Decrypt(m_keys.secretKey, ctxtOut[i], &ptResult);
        auto result = ptResult->GetRealPackedValue();
        
        for (size_t j = 0; j < 10; j++) {  // Check first 10 slots
            // Higher tolerance for very small values
            double tolerance = (std::abs(expectedOut[i][j]) < 1e-6) ? 1e-6 : 1e-3;
            EXPECT_NEAR(result[j], expectedOut[i][j], tolerance)
                << "Value mismatch at rotation " << i << ", slot " << j;
        }
    }

    // Verify comparison outputs
    for (int i = 0; i < 3; i++) {
        Plaintext ptCompResult;
        m_cc->Decrypt(m_keys.secretKey, ctxtCompOut[i], &ptCompResult);
        auto compResult = ptCompResult->GetRealPackedValue();
        
        for (size_t j = 0; j < 10; j++) {
            // Use appropriate tolerance based on value magnitude
            double tolerance = 1e-2;
            EXPECT_NEAR(compResult[j], expectedComp[i][j], tolerance)
                << "Comparison mismatch at output " << i << ", slot " << j;
        }
    }
}

TEST_F(SortUtilsTest, SlotMatching4) {
    // Create test input with sequence
    std::vector<double> input(16, 0.0);
    for (int i = 0; i < 4; i++) {
        input[i] = i + 1; // [1,2,3,4,0,0,...]
    }

    std::vector<double> comp1(16, 0.5);
    std::vector<double> comp2(16, 0.5);

    // Create indices for 4-way matching - properly mark groups of 4
    std::vector<std::vector<int>> indices(2, std::vector<int>(16, 0));
    for (int i = 0; i < 16; i++) {
        indices[0][i] = 4; // All positions are part of 4-way groups
        indices[1][i] =
            ((i / 4) * 4 + (i % 4)) % 4 + 1; // 1,2,3,4 in each group
    }

    auto pt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ptComp1 = m_cc->MakeCKKSPackedPlaintext(comp1);
    auto ptComp2 = m_cc->MakeCKKSPackedPlaintext(comp2);

    auto ct = m_cc->Encrypt(m_keys.publicKey, pt);
    auto ctComp1 = m_cc->Encrypt(m_keys.publicKey, ptComp1);
    auto ctComp2 = m_cc->Encrypt(m_keys.publicKey, ptComp2);

    Ciphertext<DCRTPoly> ctxtArr[4];
    Ciphertext<DCRTPoly> ctxtCompArr[6];

    long shift = 1;
    m_sortUtils->slotMatching4(ct, ctComp1, ctComp2, indices, shift, ctxtArr,
                               ctxtCompArr);

    std::vector<std::vector<double>> expectedArr(4,
                                                 std::vector<double>(16, 0.0));
    for (int i = 0; i < 4; i++) {
        expectedArr[i][0] = i + 1; // Each array keeps i+1 in first position
    }

    for (int i = 0; i < 4; i++) {
        VerifyResults(ctxtArr[i], expectedArr[i]);
    }
}

TEST_F(SortUtilsTest, SlotAssemble) {
    std::vector<std::vector<double>> inputs = {
        {1.0, 0.0, 0.0, 0.0}, // First number in position 0
        {2.0, 0.0, 0.0, 0.0}, // Second number in position 0
        {3.0, 0.0, 0.0, 0.0}  // Third number in position 0
    };

    std::vector<Ciphertext<DCRTPoly>> ctxtSort(3);
    for (size_t i = 0; i < inputs.size(); i++) {
        auto pt = m_cc->MakeCKKSPackedPlaintext(inputs[i]);
        ctxtSort[i] = m_cc->Encrypt(m_keys.publicKey, pt);
    }

    // Test slot assembly with shift = 1
    // This should place 1.0 at pos 0, 2.0 at pos 1, 3.0 at pos 2
    Ciphertext<DCRTPoly> result;
    long shift = 1;
    m_sortUtils->slotAssemble(ctxtSort.data(), 3, shift, result);

    // Expected: After assembly, values should be in consecutive positions
    std::vector<double> expected(16, 0.0); // Initialize all to zero
    expected[0] = 1.0;                     // First number
    expected[1] = 2.0;                     // Second number shifted right by 1
    expected[2] = 3.0;                     // Third number shifted right by 2

    Plaintext ptResult;
    m_cc->Decrypt(m_keys.secretKey, result, &ptResult);
    auto resultValues = ptResult->GetRealPackedValue();

    for (size_t i = 0; i < 4; i++) {
        EXPECT_NEAR(resultValues[i], expected[i], 0.5)
            << "Mismatch at index " << i;
    }
}

TEST_F(SortUtilsTest, SlotMatching5) {
    std::vector<double> input(16, 0.0);
    for (int i = 0; i < 5; i++) {
        input[i] = i + 1.0; // [1,2,3,4,5,0,...,0]
    }

    std::vector<double> comp1(16, 0.5);
    std::vector<double> comp2(16, 0.5);

    std::vector<std::vector<int>> indices(2, std::vector<int>(16, 0));
    for (int i = 0; i < 16; i += 5) { // Mark every 5th position
        indices[0][i] = 5;
        indices[1][i] = 1;
    }

    auto pt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ptComp1 = m_cc->MakeCKKSPackedPlaintext(comp1);
    auto ptComp2 = m_cc->MakeCKKSPackedPlaintext(comp2);

    auto ct = m_cc->Encrypt(m_keys.publicKey, pt);
    auto ctComp1 = m_cc->Encrypt(m_keys.publicKey, ptComp1);
    auto ctComp2 = m_cc->Encrypt(m_keys.publicKey, ptComp2);

    Ciphertext<DCRTPoly> ctxtArr[5];
    Ciphertext<DCRTPoly> ctxtCompArr[10];

    long shift = 1;
    m_sortUtils->slotMatching5(ct, ctComp1, ctComp2, indices, shift, ctxtArr,
                               ctxtCompArr);

    std::vector<std::vector<double>> expectedArr = {
        {1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // No rotation
        {2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // Rotate 1
        {3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2}, // Rotate 2
        {4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3}, // Rotate 3
        {5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}  // Rotate 4
    };

    for (int i = 0; i < 5; i++) {
        VerifyResults(ctxtArr[i], expectedArr[i]);
    }

    for (int i = 0; i < 10; i++) {
        Plaintext ptResult;
        m_cc->Decrypt(m_keys.secretKey, ctxtCompArr[i], &ptResult);
        auto result = ptResult->GetRealPackedValue();

        // Check structure is maintained (non-zero values in expected positions)
        bool hasNonZero = false;
        for (size_t j = 0; j < 5; j++) {
            if (std::abs(result[j]) > 0.1) {
                hasNonZero = true;
                break;
            }
        }
        EXPECT_TRUE(hasNonZero)
            << "No significant values found in comparison result " << i;
    }
}

TEST_F(SortUtilsTest, SlotMatching2345) {
    std::vector<double> input(16, 0.0);
    for (int i = 0; i < 5; i++) {
        input[i] = i + 1.0; // [1,2,3,4,5,0,...,0]
    }

    std::vector<double> comp1(16, 0.5);
    std::vector<double> comp2(16, 0.5);

    // Create indices for different sized groups (2,3,4,5-way)
    std::vector<std::vector<int>> indices(2, std::vector<int>(16, 0));
    // Mark positions for each group size
    for (int i = 0; i < 16; i += 4) {
        if (i < 4) {
            indices[0][i] = 2;
            indices[1][i] = 1;
        }
        if (i < 8) {
            indices[0][i + 1] = 3;
            indices[1][i + 1] = 1;
        }
        if (i < 12) {
            indices[0][i + 2] = 4;
            indices[1][i + 2] = 1;
        }
        indices[0][i + 3] = 5;
        indices[1][i + 3] = 1;
    }

    auto pt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ptComp1 = m_cc->MakeCKKSPackedPlaintext(comp1);
    auto ptComp2 = m_cc->MakeCKKSPackedPlaintext(comp2);

    auto ct = m_cc->Encrypt(m_keys.publicKey, pt);
    auto ctComp1 = m_cc->Encrypt(m_keys.publicKey, ptComp1);
    auto ctComp2 = m_cc->Encrypt(m_keys.publicKey, ptComp2);

    Ciphertext<DCRTPoly> ctxtArr[5];
    Ciphertext<DCRTPoly> ctxtCompArr[10];

    long shift = 1;
    m_sortUtils->slotMatching2345(ct, ctComp1, ctComp2, indices, shift, ctxtArr,
                                  ctxtCompArr);

    std::vector<std::vector<double>> expectedArr = {
        {1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // No rotation
        {2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, // Rotate 1
        {3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2}, // Rotate 2
        {4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3}, // Rotate 3
        {5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4}  // Rotate 4
    };

    std::vector<std::vector<double>> expectedComp = {
        {0.5, 0.5, 0.5, 0.5, -0.5, 0.5, 0.5, 0.5, -0.5, -0.5, 0.5, 0.5, -0.5,
         -0.5, -0.5, 0.5}, // a>b
        {0.0, 0.5, 0.5, 0.5, 0.0, 0.5, 0.5, 0.5, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0,
         0.0, 0.5}, // a>c
        {0.0, 0.0, 0.5, 0.5, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0,
         0.0, 0.5}, // a>d
        {0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0,
         0.0, 0.5}, // a>e
        {0.0, 0.5, 0.5, 0.5, 0.0, 0.5, 0.5, 0.5, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0,
         0.0, 0.5}, // b>c
        {0.0, 0.0, 0.5, 0.5, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0,
         0.0, 0.5}, // b>d
        {0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0,
         0.0, 0.5}, // b>e
        {0.0, 0.0, 0.5, 0.5, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0, 0.5, 0.5, 0.0, 0.0,
         0.0, 0.5}, // c>d
        {0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0,
         0.0, 0.5}, // c>e
        {0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0, 0.0, 0.5, 0.0, 0.0,
         0.0, 0.5} // d>e
    };

    for (int i = 0; i < 5; i++) {
        VerifyResults(ctxtArr[i], expectedArr[i]);
    }

    for (int i = 0; i < 10; i++) {
        Plaintext ptResult;
        m_cc->Decrypt(m_keys.secretKey, ctxtCompArr[i], &ptResult);
        auto result = ptResult->GetRealPackedValue();

        for (size_t j = 0; j < 16; j++) {
            EXPECT_NEAR(result[j], expectedComp[i][j], 0.1)
                << "Comparison mismatch at array " << i << ", position " << j;
        }
    }
}
int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
