#include "sort.h"
#include "comparison.h"

arraySort::arraySort(std::string ccLocation, std::string pubKeyLocation,
                     std::string multKeyLocation, std::string rotKeyLocation,
                     std::string arrayLocation, std::string outputLocation)
    : m_PubKeyLocation(pubKeyLocation), m_MultKeyLocation(multKeyLocation),
      m_RotKeyLocation(rotKeyLocation), m_CCLocation(ccLocation),
      m_arrayLocation(arrayLocation), m_OutputLocation(outputLocation) {

    initCC();
};

arraySort::arraySort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pk)
    : m_cc(cc), m_PublicKey(pk){};

void arraySort::initCC() {
    if (!Serial::DeserializeFromFile(m_CCLocation, m_cc, SerType::BINARY)) {
        std::cerr << "Could not deserialize cryptocontext file" << std::endl;
        std::exit(1);
    }

    if (!Serial::DeserializeFromFile(m_PubKeyLocation, m_PublicKey,
                                     SerType::BINARY)) {
        std::cerr << "Could not deserialize public key file" << std::endl;
        std::exit(1);
    }

    std::ifstream multKeyIStream(m_MultKeyLocation,
                                 std::ios::in | std::ios::binary);
    if (!multKeyIStream.is_open()) {
        std::exit(1);
    }
    if (!m_cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
        std::cerr << "Could not deserialize mult key file" << std::endl;
        std::exit(1);
    }

    std::ifstream rotKeyIStream(m_RotKeyLocation,
                                std::ios::in | std::ios::binary);
    if (!rotKeyIStream.is_open()) {
        std::exit(1);
    }
    if (!m_cc->DeserializeEvalAutomorphismKey(rotKeyIStream, SerType::BINARY)) {
        std::cerr << "Could not deserialize eval rot key file" << std::endl;
        std::exit(1);
    }

    if (!Serial::DeserializeFromFile(m_arrayLocation, input_array,
                                     SerType::BINARY)) {
        std::cerr << "Could not deserialize array cipher" << std::endl;
        std::exit(1);
    }
}

void arraySort::eval() {
    omp_set_num_threads(16);
    int N = 2048;
    uint32_t sincPolyDegree = 7721;

    std::vector<double> Zero(N, 0.0);
    Plaintext ptx_Zero = m_cc->MakeCKKSPackedPlaintext(Zero);
    auto ctx_Rank = m_cc->Encrypt(m_PublicKey, ptx_Zero);

    auto input_over_255 = m_cc->EvalMult(input_array, (double)1.0 / 255);

#pragma omp parallel for
    for (int i = 0; i < 32; i++) {
        std::cout << "comp i: " << i << std::endl;
        if (i == 0) {
            auto tmp1 = m_cc->Encrypt(m_PublicKey, ptx_Zero);
            auto tmp2 = m_cc->Encrypt(m_PublicKey, ptx_Zero);

            for (int j = 1; j < 32; j++) {
                auto b = m_cc->EvalRotate(input_over_255, -j);
                auto diff = m_cc->EvalSub(input_over_255, b);

                auto comp1 = m_cc->EvalMult(
                    m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1), 0.5);
                m_cc->EvalAddInPlace(tmp1, comp1);

                auto comp2 = m_cc->EvalRotate(comp1, -32 + j);
                m_cc->EvalSubInPlace(1, comp2);
                m_cc->EvalAddInPlace(tmp2, comp2);
            }

            m_cc->EvalAddInPlace(tmp1, m_cc->EvalRotate(tmp2, -2016));
#pragma omp critical
            { m_cc->EvalAddInPlace(ctx_Rank, tmp1); }
        } else {
            auto b = m_cc->EvalRotate(input_over_255, -32 * i);
            auto diff = m_cc->EvalSub(input_over_255, b);

            auto tmp1 = m_cc->EvalMult(
                m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1), 0.5);
            auto tmp2 = m_cc->EvalRotate(tmp1, -32);
            m_cc->EvalSubInPlace(1, tmp2);

            for (int j = 1; j < 32; j++) {
                auto b2 = m_cc->EvalRotate(b, -j);
                auto diff = m_cc->EvalSub(input_over_255, b2);

                auto comp1 = m_cc->EvalMult(
                    m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1), 0.5);
                m_cc->EvalAddInPlace(tmp1, comp1);

                auto comp2 = m_cc->EvalRotate(comp1, -32 + j);
                m_cc->EvalSubInPlace(1, comp2);
                m_cc->EvalAddInPlace(tmp2, comp2);
            }
            m_cc->EvalAddInPlace(tmp1, m_cc->EvalRotate(tmp2, -2016 + 32 * i));
#pragma omp critical
            { m_cc->EvalAddInPlace(ctx_Rank, tmp1); }
        }
    }
    std::cout << "finish comp" << std::endl;

    auto b = m_cc->EvalRotate(input_over_255, -1024);
    auto diff = m_cc->EvalSub(input_over_255, b);
    auto comp =
        m_cc->EvalMult(m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1), 0.5);
    m_cc->EvalAddInPlace(ctx_Rank, comp);

    std::vector<double> Index(N);
    std::iota(Index.begin(), Index.end(), 0);
    Plaintext ptx_Index = m_cc->MakeCKKSPackedPlaintext(Index);

    auto Index_minus_Rank = m_cc->EvalSub(ptx_Index, ctx_Rank);
    m_cc->EvalMultInPlace(Index_minus_Rank, 1.0 / N);

    auto rotIndex = m_cc->EvalChebyshevFunction(scaled_sinc, Index_minus_Rank,
                                                -1, 1, sincPolyDegree);
    output_array = m_cc->EvalMultAndRelinearize(rotIndex, input_array);

#pragma omp parallel for
    for (int i = 0; i < 64; i++) {
        std::cout << "rank i: " << i << std::endl;
        if (i == 0) {
            auto intermediate = m_cc->Encrypt(m_PublicKey, ptx_Zero);
            for (int j = 1; j < 32; j++) {

                auto rotIndex = m_cc->EvalChebyshevFunction(
                    [j](double x) { return scaled_sinc_j(x, j); },
                    Index_minus_Rank, -1, 1, 7701);
                auto tmp = m_cc->EvalMultAndRelinearize(rotIndex, input_array);

                m_cc->EvalAddInPlace(intermediate,
                                     m_cc->EvalRotate(tmp, j - 32));
            }
            intermediate = m_cc->EvalRotate(intermediate, -63 * 32);

#pragma omp critical
            { m_cc->EvalAddInPlace(output_array, intermediate); }
        } else if (i == 63) {
            for (int j = 0; j < 32; j++) {

                auto rotIndex = m_cc->EvalChebyshevFunction(
                    [i, j](double x) { return scaled_sinc_j(x, i * 32 + j); },
                    Index_minus_Rank, -1, 1, 7701);
                auto tmp = m_cc->EvalMultAndRelinearize(rotIndex, input_array);

                auto tmp2 = m_cc->EvalRotate(tmp, i * 32 + j - N);
#pragma omp critical
                { m_cc->EvalAddInPlace(output_array, tmp2); }
            }
        } else {
            auto intermediate = m_cc->Encrypt(m_PublicKey, ptx_Zero);
            for (int j = 0; j < 32; j++) {

                auto rotIndex = m_cc->EvalChebyshevFunction(
                    [i, j](double x) { return scaled_sinc_j(x, i * 32 + j); },
                    Index_minus_Rank, -1, 1, 7701);
                auto tmp = m_cc->EvalMultAndRelinearize(rotIndex, input_array);

                m_cc->EvalAddInPlace(intermediate,
                                     m_cc->EvalRotate(tmp, j - 32));
            }
            intermediate = m_cc->EvalRotate(intermediate, (i - 63) * 32);

#pragma omp critical
            { m_cc->EvalAddInPlace(output_array, intermediate); }
        }
    }
}

void arraySort::encryptInput(std::vector<double> input) {
    Plaintext plaintext = m_cc->MakeCKKSPackedPlaintext(input);
    input_array = m_cc->Encrypt(m_PublicKey, plaintext);
}

std::vector<double> arraySort::getPlaintextOutput(PrivateKey<DCRTPoly> sk) {
    Plaintext decryptedResult;
    m_cc->Decrypt(sk, output_array, &decryptedResult);
    return decryptedResult->GetRealPackedValue();
}

void arraySort::deserializeOutput() {
    if (!Serial::SerializeToFile(m_OutputLocation, output_array,
                                 SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 1" << std::endl;
    }
}

Ciphertext<lbcrypto::DCRTPoly> arraySort::g_n(Ciphertext<lbcrypto::DCRTPoly> x,
                                              CryptoContext<DCRTPoly> cc) {
    std::vector<double> coeffs = {0.0, 1.112086941473206858077560355014,
                                  0.0, -3.734028305547490433902169115754e-01,
                                  0.0, 2.206814218885782830081865313332e-01,
                                  0.0, -1.614281734745303398259608229637e-01,
                                  0.0, 1.213110949202888116937870677248e-01,
                                  0.0, -1.040122217184874797712978988784e-01,
                                  0.0, 8.261882702673599421228090022851e-02,
                                  0.0, -7.778143277137586353298104313581e-02,
                                  0.0, 6.144666896827026547622807584048e-02,
                                  0.0, -6.346221296887255558516471865005e-02,
                                  0.0, 4.718457305271417379088916277396e-02,
                                  0.0, -5.579119677451320480354723940764e-02,
                                  0.0, 3.473519015361416217846368681421e-02,
                                  0.0, -5.622757517465633292363946793557e-02};
    return cc->EvalChebyshevSeriesPS(x, coeffs, -1, 1);
}

Ciphertext<lbcrypto::DCRTPoly> arraySort::f_n(Ciphertext<lbcrypto::DCRTPoly> x,
                                              CryptoContext<DCRTPoly> cc) {
    const double c1 = 3.14208984375;
    const double c3 = -7.33154296875;
    const double c5 = 13.19677734375;
    const double c7 = -15.71044921875;
    const double c9 = 12.21923828125;
    const double c11 = -5.99853515625;
    const double c13 = 1.69189453125;
    const double c15 = -0.20947265625;

    auto x2 = cc->EvalSquare(x);
    auto x4 = cc->EvalSquare(x2);
    auto x8 = cc->EvalSquare(x4);

    auto y = cc->EvalMult(x, c1);
    cc->EvalAddInPlace(y, cc->EvalMultAndRelinearize(cc->EvalMult(x, c3), x2));

    auto c5x = cc->EvalMult(x, c5);
    auto c7x = cc->EvalMult(x, c7);
    auto c7x3 = cc->EvalMultAndRelinearize(c7x, x2);
    cc->EvalAddInPlace(y,
                       cc->EvalMultAndRelinearize(cc->EvalAdd(c5x, c7x3), x4));

    auto c9x = cc->EvalMult(x, c9);
    auto c11x = cc->EvalMult(x, c11);
    auto tmp1 = cc->EvalAdd(c9x, cc->EvalMultAndRelinearize(c11x, x2));

    auto c13x = cc->EvalMult(x, c13);
    auto c15x = cc->EvalMult(x, c15);
    auto tmp2 = cc->EvalAdd(c13x, cc->EvalMultAndRelinearize(c15x, x2));

    cc->EvalAddInPlace(tmp1, cc->EvalMultAndRelinearize(tmp2, x4));
    cc->EvalAddInPlace(y, cc->EvalMultAndRelinearize(tmp1, x8));

    return y;
}

Ciphertext<lbcrypto::DCRTPoly>
arraySort::compositeSign(Ciphertext<lbcrypto::DCRTPoly> x,
                         CryptoContext<DCRTPoly> cc, int dg, int df) {

    auto y = g_n(x, cc);
    cc->EvalMultInPlace(y, 1.0 / 1.032466);
    for (int i = 1; i < dg; i++) {
        y = g_n(y, cc);
        cc->EvalMultInPlace(y, 1.0 / 1.032466);
    }
    for (int i = 0; i < df; i++) {
        y = f_n(y, cc);
    }
    return y;
}
