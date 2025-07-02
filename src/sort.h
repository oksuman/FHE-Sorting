#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include <functional>
#include <omp.h>

#include "comparison.h"
#include "sign.h"
#include "sort_algo.h"

using namespace lbcrypto;

template <int N> struct SortContext {
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    Ciphertext<DCRTPoly> input_array;
    Ciphertext<DCRTPoly> output_array;
    std::string m_outputLocation;

    SortContext(std::string ccLocation, std::string pubKeyLocation,
                std::string multKeyLocation, std::string rotKeyLocation,
                std::string arrayLocation, std::string outputLocation)
        : m_outputLocation(outputLocation) {

        initCC(ccLocation, pubKeyLocation, multKeyLocation, rotKeyLocation,
               arrayLocation, outputLocation);
    };

    void initCC(std::string ccLocation, std::string pubKeyLocation,
                std::string multKeyLocation, std::string rotKeyLocation,
                std::string arrayLocation, std::string outputLocation) {
        if (!Serial::DeserializeFromFile(ccLocation, m_cc, SerType::BINARY)) {
            std::cerr << "Could not deserialize cryptocontext file"
                      << std::endl;
            std::exit(1);
        }

        if (!Serial::DeserializeFromFile(pubKeyLocation, m_PublicKey,
                                         SerType::BINARY)) {
            std::cerr << "Could not deserialize public key file" << std::endl;
            std::exit(1);
        }

        std::ifstream multKeyIStream(multKeyLocation,
                                     std::ios::in | std::ios::binary);
        if (!multKeyIStream.is_open()) {
            std::cerr << "Mult key stream not open" << std::endl;
            std::exit(1);
        }
        if (!m_cc->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY)) {
            std::cerr << "Could not deserialize mult key file" << std::endl;
            std::exit(1);
        }

        std::ifstream rotKeyIStream(rotKeyLocation,
                                    std::ios::in | std::ios::binary);
        if (!rotKeyIStream.is_open()) {
            std::cerr << "Rot key stream not open" << std::endl;
            std::exit(1);
        }
        if (!m_cc->DeserializeEvalAutomorphismKey(rotKeyIStream,
                                                  SerType::BINARY)) {
            std::cerr << "Could not deserialize eval rot key file" << std::endl;
            std::exit(1);
        }

        if (!Serial::DeserializeFromFile(arrayLocation, input_array,
                                         SerType::BINARY)) {
            std::cerr << "Could not deserialize array cipher" << std::endl;
            std::exit(1);
        }
    }

    void eval(SortAlgo algo, std::vector<int> rotIndices) {
        auto enc = std::make_shared<Encryption>(m_cc, m_PublicKey);

        std::unique_ptr<SortBase<N>> sorter;

        switch (algo) {
        case SortAlgo::DirectSort:
        default:
            sorter = std::make_unique<DirectSort<N>>(m_cc, m_PublicKey,
                                                     rotIndices, enc);
            break;
        case SortAlgo::BitonicSort:
            sorter = std::make_unique<BitonicSort<N>>(m_cc, m_PublicKey,
                                                      rotIndices, enc);
            break;
        }

        auto Cfg = SignConfig(CompositeSignConfig(4, 3, 3));
        output_array = sorter->sort(input_array, SignFunc::CompositeSign, Cfg);
    }

    void deserializeOutput() {
        if (!Serial::SerializeToFile(m_outputLocation, output_array,
                                     SerType::BINARY)) {
            std::cerr << " Error writing ciphertext 1" << std::endl;
        }
    }
};
