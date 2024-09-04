// DirectSort.h

#pragma once

#include "comparison.h"
#include "encryption.h"
#include "openfhe.h"
#include <iostream>
#include <vector>

using namespace lbcrypto;

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

        for (int i = 1; i < N / 2; i++) {
            auto rotated = m_cc->EvalRotate(inputOver255, i);
            auto compResult1 = comp.compare(m_cc, inputOver255, rotated);
            auto compResult2 = m_cc->EvalRotate(compResult1, -i);
            m_cc->EvalSubInPlace(compResult1, compResult2);

// TODO remove critical section for performance and instead add results later
#pragma omp critical
            { m_cc->EvalAddInPlace(ctxRank, compResult1); }
        }
        m_cc->EvalAddInPlace(ctxRank, N / 2 - 1);

        /*
            We need comparison of (inputOver255, Rot(inputOver255, N/2)
        */
        auto rotated = m_cc->EvalRotate(inputOver255, N / 2);
        auto compResult = comp.compare(m_cc, inputOver255, rotated);
        m_cc->EvalAddInPlace(ctxRank, compResult);

        return ctxRank;
    }

    Ciphertext<DCRTPoly>
    rotationIndexCheck(const Ciphertext<DCRTPoly> &Index_minus_Rank,
                       const Ciphertext<DCRTPoly> &input_array) {
        // int N = input_array->GetSlots();
        constexpr int sincPolyDegree = 611; // for array size of 128

        auto output_array = this->getZero()->Clone();

#pragma omp parallel for
        for (int i = 0; i < N; i++) {
            // Compute the sinc interpolation for this rotation
            auto rotIndex = m_cc->EvalChebyshevFunction(
                [i](double x) { return Sinc<N>::scaled_sinc_j(x, i); },
                Index_minus_Rank, -1, 1, sincPolyDegree);

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
