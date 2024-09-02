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
    omp_set_num_threads(24);
    Comparison comp;
    // Every slot should contain one element, same as batch_size
    int N = input_array->GetSlots();
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
                    m_cc->EvalAdd(comp.compositeSign(diff, m_cc, 3, 3), 1), 0.5);
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
                m_cc->EvalAdd(comp.compositeSign(diff, m_cc, 3, 3), 1), 0.5);
            auto tmp2 = m_cc->EvalRotate(tmp1, -32);
            m_cc->EvalSubInPlace(1, tmp2);

            for (int j = 1; j < 32; j++) {
                auto b2 = m_cc->EvalRotate(b, -j);
                auto diff = m_cc->EvalSub(input_over_255, b2);

                auto comp1 = m_cc->EvalMult(
                    m_cc->EvalAdd(comp.compositeSign(diff, m_cc, 3, 3), 1), 0.5);
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
    auto comp1 =
        m_cc->EvalMult(m_cc->EvalAdd(comp.compositeSign(diff, m_cc, 3, 3), 1), 0.5);
    m_cc->EvalAddInPlace(ctx_Rank, comp1);

    std::vector<double> Index(N);
    std::iota(Index.begin(), Index.end(), 0);
    Plaintext ptx_Index = m_cc->MakeCKKSPackedPlaintext(Index);

    auto Index_minus_Rank = m_cc->EvalSub(ptx_Index, ctx_Rank);
    m_cc->EvalMultInPlace(Index_minus_Rank, 1.0 / N);

    auto rotIndex = m_cc->EvalChebyshevFunction(
        Sinc<2048>::scaled_sinc, Index_minus_Rank, -1, 1, sincPolyDegree);
    output_array = m_cc->EvalMultAndRelinearize(rotIndex, input_array);

#pragma omp parallel for
    for (int i = 0; i < 64; i++) {
        std::cout << "rank i: " << i << std::endl;
        if (i == 0) {
            auto intermediate = m_cc->Encrypt(m_PublicKey, ptx_Zero);
            for (int j = 1; j < 32; j++) {

                auto rotIndex = m_cc->EvalChebyshevFunction(
                    [j](double x) { return Sinc<2048>::scaled_sinc_j(x, j); },
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
                    [i, j](double x) {
                        return Sinc<2048>::scaled_sinc_j(x, i * 32 + j);
                    },
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
                    [i, j](double x) {
                        return Sinc<2048>::scaled_sinc_j(x, i * 32 + j);
                    },
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

void arraySort::deserializeOutput() {
    if (!Serial::SerializeToFile(m_OutputLocation, output_array,
                                 SerType::BINARY)) {
        std::cerr << " Error writing ciphertext 1" << std::endl;
    }
}
