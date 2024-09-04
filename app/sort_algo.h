// DirectSort.h

#pragma once

#include "comparison.h"
#include "encryption.h"
#include "openfhe.h"
#include <iostream>
#include <vector>

using namespace lbcrypto;

#include "generated_coeffs.h"

// Base class for sorting algorithms
template <int N> // Array size
class SortBase {
  protected:
    std::shared_ptr<Encryption> m_enc;
    const Ciphertext<DCRTPoly> m_zeroCache;

    virtual Ciphertext<DCRTPoly> createZeroCache() {
        std::vector<double> zeroVec(N, 0.0);
        return m_enc->encryptInput(zeroVec);
    }

  public:
    SortBase(std::shared_ptr<Encryption> enc)
        : m_enc(enc), m_zeroCache(createZeroCache()) {}

    virtual ~SortBase() = default;

    virtual Ciphertext<DCRTPoly>
    sort(const Ciphertext<DCRTPoly> &input_array) = 0;

    virtual const Ciphertext<DCRTPoly> &getZero() const { return m_zeroCache; }
    // Common methods that can be used by all sorting algorithms
    constexpr size_t getArraySize() const { return N; }
};

template <int N> class DirectSort : public SortBase<N> {
  private:
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    Comparison comp;

    static constexpr int sincPolyDegree = 611;

  public:
    std::shared_ptr<Encryption> m_enc;

    DirectSort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey,
               std::shared_ptr<Encryption> enc)
        : SortBase<N>(enc), m_cc(cc), m_PublicKey(publicKey), comp(enc),
          m_enc(enc) {}

    Ciphertext<DCRTPoly>
    constructRank(const Ciphertext<DCRTPoly> &input_array) {

        auto ctxRank = this->getZero()->Clone();
        const auto inputOver255 =
            m_cc->EvalMult(input_array, (double)1.0 / 255);

#pragma omp parallel for
        for (int i = 1; i < N; i++) {
            auto rotated = m_cc->EvalRotate(inputOver255, -i);
            auto compResult = comp.compare(m_cc, inputOver255, rotated);
// TODO remove critical section for performance and instead add results later
#pragma omp critical
            { m_cc->EvalAddInPlace(ctxRank, compResult); }
        }

        return ctxRank;
    }

    Ciphertext<DCRTPoly>
    rotationIndexCheck(const Ciphertext<DCRTPoly> &Index_minus_Rank,
                       const Ciphertext<DCRTPoly> &input_array) {
        // int N = input_array->GetSlots();

        auto output_array = this->getZero()->Clone();
        static constexpr auto allCoefficients = selectCoefficients<N>();
        assert(allCoefficients.size() == N &&
               "The size of precomputed coefficient matrix is different than "
               "the array size.");
        assert(allCoefficients[0].size() == sincPolyDegree + 1 &&
               "The degree of sinc is different than coefficient vector size.");

#pragma omp parallel for
        for (int i = 0; i < N; i++) {
            // Compute the sinc interpolation for this rotation
            const auto &coefficients = allCoefficients[i];
            std::vector<double> coeffVector(coefficients.begin(),
                                            coefficients.end());
            auto rotIndex = m_cc->EvalChebyshevSeriesPS(Index_minus_Rank,
                                                        coeffVector, -1, 1);

            // Apply the rotation mask to the input array
            auto masked_input =
                m_cc->EvalMultAndRelinearize(rotIndex, input_array);

            // Rotate the masked input
            auto rotated = m_cc->EvalRotate(masked_input, i);

#pragma omp critical
            // Add to the output array
            { m_cc->EvalAddInPlace(output_array, rotated); }
        }

        return output_array;
    }

    Ciphertext<DCRTPoly>
    sort(const Ciphertext<DCRTPoly> &input_array) override {

        std::cout << "\n===== Direct Sort Input Array: \n";
        PRINT_PT(m_enc, input_array);
        auto ctx_Rank = constructRank(input_array);
        std::cout << "\n===== Constructed Rank: \n";
        PRINT_PT(m_enc, ctx_Rank);

        // Make a plaintext index array [1, 2, 3, ...]
        std::vector<double> Index(N);
        std::iota(Index.begin(), Index.end(), 0);
        Plaintext ptx_Index = m_cc->MakeCKKSPackedPlaintext(Index);

        // Evaluate index - rank, which denotes the rotation index to be sorted
        auto Index_minus_Rank = m_cc->EvalSub(ptx_Index, ctx_Rank);
        std::cout << "\n===== Index - Rank: \n";
        PRINT_PT(m_enc, Index_minus_Rank);

        m_cc->EvalMultInPlace(Index_minus_Rank, 1.0 / N);

        auto output_array = rotationIndexCheck(Index_minus_Rank, input_array);
        std::cout << "\n===== Final Output: \n";
        PRINT_PT(m_enc, output_array);
        return output_array;
    }
};
