// DirectSort.h

#pragma once

#include "comparison.h"
#include "encryption.h"
#include "openfhe.h"
#include <iostream>
#include <vector>

using namespace lbcrypto;

// Abstract base class for sorting algorithms
template <int N> // Array size
class SortBase {

  public:
    SortBase() {}

    virtual ~SortBase() = default;

    virtual Ciphertext<DCRTPoly>
    sort(const Ciphertext<DCRTPoly> &input_array) = 0;

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
    // Constructor
    DirectSort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey,
               std::shared_ptr<Encryption> enc)
        : m_cc(cc), m_PublicKey(publicKey), comp(enc), m_enc(enc) {}

    Ciphertext<DCRTPoly>
    constructRank(const Ciphertext<DCRTPoly> &input_array) {

        std::vector<double> Zero(N, 0.0);
        Plaintext ptxZero = m_cc->MakeCKKSPackedPlaintext(Zero);
        auto ctxRank = m_cc->Encrypt(m_PublicKey, ptxZero);
        const auto inputOver255 =
            m_cc->EvalMult(input_array, (double)1.0 / 255);
        PRINT_PT(m_enc, inputOver255);

#pragma omp parallel for
        for (int i = 1; i < N; i++) {
            std::cout << "Rotation index " << -i << "\n";
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
        constexpr int sincPolyDegree = 7701;

        // TODO This is done to prevent rotation in the loop. However this means
        // more sequential execution.
        //  OpenFHE EvalRotate -> EvalAtIndex actually checks for 0 rotation and
        //  clones the ct back. Check if it is better to keep it in the loop for
        //  parallelisation.
        auto rotIndex = m_cc->EvalChebyshevFunction(
            Sinc<N>::scaled_sinc, Index_minus_Rank, -1, 1, sincPolyDegree);
        PRINT_PT(m_enc, rotIndex);
        auto output_array = m_cc->EvalMultAndRelinearize(rotIndex, input_array);
        PRINT_PT(m_enc, output_array);

        // TODO share precompute values with rank construction.
        //  Create a zero plaintext
        std::vector<double> Zero(N, 0.0);
        Plaintext ptx_Zero = m_cc->MakeCKKSPackedPlaintext(Zero);

        for (int i = 1; i < N; i++) {
            // Compute the sinc interpolation for this rotation
            auto rotIndex = m_cc->EvalChebyshevFunction(
                [i](double x) { return Sinc<N>::scaled_sinc_j(x, i); },
                Index_minus_Rank, -1, 1, 7701);
            PRINT_PT(m_enc, rotIndex);

            // Apply the rotation mask to the input array
            auto masked_input =
                m_cc->EvalMultAndRelinearize(rotIndex, input_array);

            // Rotate the masked input
            auto rotated = m_cc->EvalRotate(masked_input, i);

            // Add to the output array
            m_cc->EvalAddInPlace(output_array, rotated);

            // Debug: print intermediate results
            std::cout << "Rotation " << i << ": \n";
            PRINT_PT(m_enc, rotated);
        }

        return output_array;
    }

    Ciphertext<DCRTPoly>
    sort(const Ciphertext<DCRTPoly> &input_array) override {

        auto ctx_Rank = constructRank(input_array);
        PRINT_PT(m_enc, ctx_Rank);

        // auto input_over_255 = m_cc->EvalMult(input_array, (double)1.0 / 255);
        // auto b = m_cc->EvalRotate(input_over_255, -N/2);
        // auto comp1 = comp.compare(m_cc, input_over_255, b);
        // m_cc->EvalAddInPlace(ctx_Rank, comp1);
        // PRINT_PT(m_enc, ctx_Rank);

        // Make a plaintext index array [1, 2, 3, ...]
        std::vector<double> Index(N);
        std::iota(Index.begin(), Index.end(), 0);
        Plaintext ptx_Index = m_cc->MakeCKKSPackedPlaintext(Index);
        std::cout << ptx_Index << "\n";

        // Evaluate index - rank, which denotes the rotation index to be sorted
        auto Index_minus_Rank = m_cc->EvalSub(ptx_Index, ctx_Rank);
        PRINT_PT(m_enc, Index_minus_Rank);

        m_cc->EvalMultInPlace(Index_minus_Rank, 1.0 / N);
        PRINT_PT(m_enc, Index_minus_Rank);

        auto output_array = rotationIndexCheck(Index_minus_Rank, input_array);
        return output_array;
    }
};
