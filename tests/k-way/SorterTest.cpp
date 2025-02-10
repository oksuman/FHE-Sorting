#include "Sorter.h"
#include "openfhe.h"
#include <gtest/gtest.h>
#include <memory>

using namespace lbcrypto;
using namespace kwaySort;

class SorterTest : public ::testing::Test {
  protected:
    void SetUp() override {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(59);
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

        // Generate rotation keys
        std::vector<int> rotations;
        for (int i = 1; i < 16; i++) {
            rotations.push_back(i);
            rotations.push_back(-i);
        }
        m_cc->EvalRotateKeyGen(m_keys.secretKey, rotations);

        // Setup bootstrapping
        auto slots = m_cc->GetEncodingParams()->GetBatchSize();
        m_cc->EvalBootstrapSetup({4, 4}, {0, 0}, slots);
        m_cc->EvalBootstrapKeyGen(m_keys.secretKey, slots);

        // Create encryption helper
        m_enc = std::make_shared<DebugEncryption>(m_cc, m_keys);
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
    std::shared_ptr<DebugEncryption> m_enc;
};

TEST_F(SorterTest, RunTwoSorter) {
    long k = 2;
    long M = 2;
    long d_f = 2;
    long d_g = 5;
    auto slots = m_cc->GetEncodingParams()->GetBatchSize();

    std::unique_ptr<Sorter> sorter =
        std::make_unique<Sorter>(m_cc, m_enc, slots, k, M, d_f, d_g);

    // Create test data [5,2, 8,1, 3,6, 4,7] - Four pairs to be sorted
    std::vector<double> input = {5.0, 2.0, 8.0, 1.0, 3.0, 6.0, 4.0, 7.0};
    auto ptxt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = m_cc->Encrypt(m_keys.publicKey, ptxt);

    // Create comparison data (1 if first > second, 0 otherwise)
    std::vector<double> compData = {1.0, 0.0, 1.0, 0.0, 0.0, 1.0, 0.0, 1.0};
    auto ptxtComp = m_cc->MakeCKKSPackedPlaintext(compData);
    auto ctxtComp = m_cc->Encrypt(m_keys.publicKey, ptxtComp);

    // Create indices for two-way sorting
    std::vector<std::vector<int>> indices(2, std::vector<int>(slots, 0));
    for (int i = 0; i < 8; i += 2) {
        indices[0][i] = 2;
        indices[1][i] = 1;
    }

    Ciphertext<DCRTPoly> result;
    sorter->runTwoSorter(ctxt, indices, 1, ctxtComp, result);

    // Expected: pairs should be sorted
    std::vector<double> expected = {2.0, 5.0, 1.0, 8.0, 3.0, 6.0, 4.0, 7.0};
    VerifyResults(result, expected);
}

TEST_F(SorterTest, RunThreeSorter) {
    long k = 3;
    long M = 2;
    long d_f = 2;
    long d_g = 5;
    auto slots = m_cc->GetEncodingParams()->GetBatchSize();

    std::unique_ptr<Sorter> sorter =
        std::make_unique<Sorter>(m_cc, m_enc, slots, k, M, d_f, d_g);

    // Test data matching HEAAN example
    std::vector<double> input(slots, 0.0);
    input[0] = 0.840188;
    input[1] = 0.394383;
    input[2] = 0.783099;
    input[3] = 0.79844;
    input[4] = 0.911647;
    input[5] = 0.197551;
    input[6] = 0.335223;
    input[7] = 0.76823;
    input[8] = 0.277775;

    auto ptxt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = m_cc->Encrypt(m_keys.publicKey, ptxt);

    std::vector<double> compData(slots, 0.5);
    compData[0] = 1.0;
    compData[1] = 0.0; // -4.54951e-06 in HEAAN
    compData[2] = 1.0;
    compData[3] = 1.0;
    compData[4] = 1.0;
    compData[5] = 0.0; // 1.86265e-09 in HEAAN
    compData[6] = 1.0;
    compData[7] = 1.0;
    compData[8] = 0.0; // 1.30385e-08 in HEAAN

    auto ptxtComp = m_cc->MakeCKKSPackedPlaintext(compData);
    auto ctxtComp = m_cc->Encrypt(m_keys.publicKey, ptxtComp);

    std::vector<std::vector<int>> indices(2, std::vector<int>(slots, 0));
    // Matching HEAAN indices pattern
    for (int i = 0; i < 9; i++) {
        indices[0][i] = 3;
        indices[1][i] = (i % 3) + 1;
    }

    Ciphertext<DCRTPoly> result;
    sorter->runThreeSorter(ctxt, indices, 1, ctxtComp, result);

    // Expected results matching HEAAN example's output pattern
    std::vector<double> expected(slots, 0.0);
    expected[0] = 0.394404;
    expected[1] = 0.783115;
    expected[2] = 0.840147;
    expected[3] = 0.197544;
    expected[4] = 0.79844;
    expected[5] = 0.911647;
    expected[6] = 0.277775;
    expected[7] = 0.335223;
    expected[8] = 0.76823;

    VerifyResults(result, expected);
}

TEST_F(SorterTest, RunFourSorter) {
    long k = 4;
    long M = 2;
    long d_f = 2;
    long d_g = 5;
    auto slots = m_cc->GetEncodingParams()->GetBatchSize();

    std::unique_ptr<Sorter> sorter =
        std::make_unique<Sorter>(m_cc, m_enc, slots, k, M, d_f, d_g);

    // Test data: group of four numbers
    std::vector<double> input = {5.0, 2.0, 8.0, 1.0};
    auto ptxt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = m_cc->Encrypt(m_keys.publicKey, ptxt);

    std::vector<double> compData1(slots, 0.5);
    std::vector<double> compData2(slots, 0.5);
    // Two sets of comparison data needed for four-way sorting
    //{1.0, 0.0, 1.0, 0.0}
    compData1[0] = 1.0; // First set of comparisons a>b
    compData1[1] = 0.0;
    compData1[2] = 1.0;
    compData1[3] = 0.0;
    // {0.0, 1.0, 1.0, 0.0}
    compData2[0] = 0.0;
    compData2[1] = 1.0;
    compData2[2] = 1.0;
    compData2[3] = 0.0;

    auto ptxtComp1 = m_cc->MakeCKKSPackedPlaintext(compData1);
    auto ptxtComp2 = m_cc->MakeCKKSPackedPlaintext(compData2);
    auto ctxtComp1 = m_cc->Encrypt(m_keys.publicKey, ptxtComp1);
    auto ctxtComp2 = m_cc->Encrypt(m_keys.publicKey, ptxtComp2);

    std::vector<std::vector<int>> indices(2, std::vector<int>(slots, 0));
    indices[0][0] = 4;
    indices[0][1] = 4;
    indices[0][2] = 4;
    indices[0][3] = 4;
    indices[1][0] = 1;
    indices[1][1] = 2;
    indices[1][2] = 3;
    indices[1][3] = 4;

    Ciphertext<DCRTPoly> result;
    sorter->runFourSorter(ctxt, indices, 1, ctxtComp1, ctxtComp2, result);

    std::vector<double> expected = {1.0, 2.0, 5.0, 8.0};
    VerifyResults(result, expected);
}

TEST_F(SorterTest, RunFiveSorter) {
    long k = 5;
    long M = 2;
    long d_f = 2;
    long d_g = 5;
    auto slots = m_cc->GetEncodingParams()->GetBatchSize();

    std::unique_ptr<Sorter> sorter =
        std::make_unique<Sorter>(m_cc, m_enc, slots, k, M, d_f, d_g);

    std::vector<double> input = {5.0, 2.0, 8.0, 1.0, 3.0};
    auto ptxt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = m_cc->Encrypt(m_keys.publicKey, ptxt);

    std::vector<double> compData1(slots, 0.5);
    std::vector<double> compData2(slots, 0.5);

    // ctxt_comp1 = (a > e, b > a, c > b, d > c, e > d)
    compData1[0] = 1.0; // 5>3
    compData1[1] = 0.0; // 2<5
    compData1[2] = 1.0; // 8>2
    compData1[3] = 0.0; // 1<8
    compData1[4] = 1.0; // 3>1

    // ctxt_comp2 = (a > d, b > e, c > a, d > b, e > c)
    compData2[0] = 1.0; // 5>1
    compData2[1] = 0.0; // 2<3
    compData2[2] = 1.0; // 8>5
    compData2[3] = 0.0; // 1<2
    compData2[4] = 0.0; // 3<8

    auto ptxtComp1 = m_cc->MakeCKKSPackedPlaintext(compData1);
    auto ptxtComp2 = m_cc->MakeCKKSPackedPlaintext(compData2);
    auto ctxtComp1 = m_cc->Encrypt(m_keys.publicKey, ptxtComp1);
    auto ctxtComp2 = m_cc->Encrypt(m_keys.publicKey, ptxtComp2);

    std::vector<std::vector<int>> indices(2, std::vector<int>(slots, 0));
    for (int i = 0; i < 5; i++) {
        indices[0][i] = 5;
        indices[1][i] = i + 1;
    }

    Ciphertext<DCRTPoly> result;
    sorter->runFiveSorter(ctxt, indices, 1, ctxtComp1, ctxtComp2, result);

    std::vector<double> expected = {1.0, 2.0, 3.0, 5.0, 8.0};
    VerifyResults(result, expected);
}

// TODO inputs/outputs need to be considered
TEST_F(SorterTest, DISABLED_Run2345Sorter) {
    long k = 5;
    long M = 1;
    long d_f = 2;
    long d_g = 5;
    auto slots = m_cc->GetEncodingParams()->GetBatchSize();

    std::unique_ptr<Sorter> sorter =
        std::make_unique<Sorter>(m_cc, m_enc, slots, k, M, d_f, d_g);

    std::vector<double> input = {0.5, 0.2, 0.8, 0.1, 0.3};
    auto ptxt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = m_cc->Encrypt(m_keys.publicKey, ptxt);

    std::vector<double> compData1(slots, 0.5);
    std::vector<double> compData2(slots, 0.5);

    // ctxt_comp1 = (a > e, b > a, c > b, d > c, e > d)
    compData1[0] = 1.0; // 5>3
    compData1[1] = 0.0; // 2<5
    compData1[2] = 1.0; // 8>2
    compData1[3] = 0.0; // 1<8
    compData1[4] = 1.0; // 3>1

    // ctxt_comp2 = (a > d, b > e, c > a, d > b, e > c)
    compData2[0] = 1.0; // 5>1
    compData2[1] = 0.0; // 2<3
    compData2[2] = 1.0; // 8>5
    compData2[3] = 0.0; // 1<2
    compData2[4] = 0.0; // 3<8

    auto ptxtComp1 = m_cc->MakeCKKSPackedPlaintext(compData1);
    auto ptxtComp2 = m_cc->MakeCKKSPackedPlaintext(compData2);
    auto ctxtComp1 = m_cc->Encrypt(m_keys.publicKey, ptxtComp1);
    auto ctxtComp2 = m_cc->Encrypt(m_keys.publicKey, ptxtComp2);

    std::vector<std::vector<int>> indices(2, std::vector<int>(slots, 0));
    // Set indices for all possible sorter sizes (2,3,4,5)
    for (int i = 0; i < 5; i++) {
        indices[0][i] = i + 2; // Size of each group
        indices[1][i] = 1;     // First position
    }

    PRINT_PT(m_enc, ctxt);
    Ciphertext<DCRTPoly> result;
    sorter->run2345Sorter(ctxt, indices, 1, ctxtComp1, ctxtComp2, result);
    PRINT_PT(m_enc, result);

    // Verify first elements are properly sorted
    std::vector<double> expected = {0.1, 0.2, 0.3, 0.5, 0.8};
    VerifyResults(result, expected);
}

TEST_F(SorterTest, TwoWaySorting) {
    long k = 2;
    long M = 3;
    long d_f = 2;
    long d_g = 5;
    auto slots = m_cc->GetEncodingParams()->GetBatchSize();

    std::unique_ptr<Sorter> sorter = std::make_unique<Sorter>(
        m_cc, m_enc, slots, k, M, d_f, d_g, m_keys.secretKey, m_keys.publicKey);

    std::vector<double> input = {0.5, 0.2, 0.8, 0.1, 0.3, 0.6, 0.4, 0.7};
    std::vector<double> expected = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};

    auto ptxt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = m_cc->Encrypt(m_keys.publicKey, ptxt);

    Ciphertext<DCRTPoly> result;
    sorter->sorter(ctxt, result);

    VerifyResults(result, expected);
}

TEST_F(SorterTest, ThreeWaySorting) {
    long k = 3;
    long M = 1;
    long d_f = 2;
    long d_g = 5;
    auto slots = m_cc->GetEncodingParams()->GetBatchSize();

    std::unique_ptr<Sorter> sorter = std::make_unique<Sorter>(
        m_cc, m_enc, slots, k, M, d_f, d_g, m_keys.secretKey, m_keys.publicKey);

    std::vector<double> input = {0.5, 0.2, 0.8};
    std::vector<double> expected = {0.2, 0.5, 0.8};

    auto ptxt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = m_cc->Encrypt(m_keys.publicKey, ptxt);

    Ciphertext<DCRTPoly> result;
    sorter->sorter(ctxt, result);

    VerifyResults(result, expected);
}

TEST_F(SorterTest, FiveWaySorting) {
    long k = 5;
    long M = 1;
    long d_f = 2;
    long d_g = 5;
    auto slots = m_cc->GetEncodingParams()->GetBatchSize();

    std::unique_ptr<Sorter> sorter = std::make_unique<Sorter>(
        m_cc, m_enc, slots, k, M, d_f, d_g, m_keys.secretKey, m_keys.publicKey);

    // Test data: 5 numbers in ascending order
    std::vector<double> input = {0.5, 0.3, 0.4, 0.1, 0.2};
    std::vector<double> expected = {0.1, 0.2, 0.3, 0.4, 0.5};

    auto ptxt = m_cc->MakeCKKSPackedPlaintext(input);
    auto ctxt = m_cc->Encrypt(m_keys.publicKey, ptxt);

    Ciphertext<DCRTPoly> result;
    PRINT_PT(m_enc, ctxt);
    sorter->sorter(ctxt, result);

    VerifyResults(result, expected);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
