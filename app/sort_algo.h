#pragma once

#include "comparison.h"
#include "encryption.h"
#include "openfhe.h"
#include "rotation.h"
#include <iostream>
#include <vector>

using namespace lbcrypto;

#include "generated_coeffs.h"

enum class SortAlgo { DirectSort, BitonicSort };

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
    RotationComposer<N> rot;

  public:
    std::shared_ptr<Encryption> m_enc;

    DirectSort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey,
               std::vector<int> rotIndices, std::shared_ptr<Encryption> enc)
        : SortBase<N>(enc), m_cc(cc), m_PublicKey(publicKey), comp(enc),
          rot(m_cc, enc, rotIndices), m_enc(enc) {}

    /*
        masking vector generation for SIMD optimization
    */
    std::vector<double> generateMaskVector1(int array_size, int k) {
        std::vector<double> result(array_size * array_size, 0.0);

        for (int i = k * array_size; i < (k + 1) * array_size; ++i) {
            result[i] = 1.0;
        }

        return result;
    }

    std::vector<double> generateMaskVector2(int array_size, int k) {
        std::vector<double> result(array_size * array_size, 1.0);

        for (int i = k * array_size; i < (k + 1) * array_size; ++i) {
            result[i] = 0.0;
        }

        return result;
    }

    std::vector<double> generateMaskVector3(int array_size, int k) {
        std::vector<double> result(2 * array_size * array_size, 0.0);

        for (int i = k * array_size; i < (k + 1) * array_size; ++i) {
            result[i] = 1.0;
        }

        return result;
    }

    std::vector<double> generateMaskVector4(int array_size, int k) {
        std::vector<double> result(2 * array_size * array_size, 0.0);

        for (int i = k * array_size; i < (k + 1) * array_size; ++i) {
            result[i] = 1.0;
        }
        for (int i = array_size * (2 * array_size - k);
             i < array_size * (2 * array_size - k + 1); ++i) {
            result[i] = 1.0;
        }

        return result;
    }

    std::vector<double> generateCheckingVector(int array_size) {
        const int total_size = 2 * array_size * array_size;
        std::vector<double> stretched_index(total_size);

#pragma omp parallel
        {
#pragma omp for nowait
            for (int i = 0; i < array_size * array_size; ++i) {
                stretched_index[i] = i / array_size;
            }

#pragma omp for nowait
            for (int i = array_size * array_size;
                 i < array_size * array_size + array_size; ++i) {
                stretched_index[i] = array_size;
            }

#pragma omp for
            for (int i = array_size * array_size + array_size; i < total_size;
                 ++i) {
                stretched_index[i] =
                    -((i - array_size * array_size - array_size) / array_size +
                      1);
            }
        }

        return stretched_index;
    }

    std::vector<double> generateRepeatedIndex(int array_size) {
        std::vector<double> result;
        result.reserve(2 * array_size * array_size);

        for (int i = 0; i < 2 * array_size; ++i) {
            for (int j = 0; j < array_size; ++j) {
                result.push_back(static_cast<double>(j));
            }
        }

        return result;
    }

    Ciphertext<DCRTPoly>
    constructRank(const Ciphertext<DCRTPoly> &input_array) {

        auto shifted_input_array = this->getZero()->Clone();
        const auto inputOver255 =
            m_cc->EvalMult(input_array, (double)1.0 / 255);

        // The repeated rotation is optimized with treeRotate structure by
        // reusing intermediate rotations
        rot.buildRotationTree(1, N);
        std::vector<Ciphertext<DCRTPoly>> rotated_results(N);
        for (int i = 1; i < N; i++) {
            rotated_results[i] = rot.treeRotate(inputOver255, i);
            rotated_results[i]->SetSlots(N * N);
        }
#pragma omp parallel for
        for (int i = 1; i < N; i++) {
            auto rotated = rotated_results[i];
            rotated->SetSlots(N * N);
            rotated = m_cc->EvalMult(rotated, m_cc->MakeCKKSPackedPlaintext(
                                                  generateMaskVector1(N, i - 1),
                                                  1, 0, nullptr, N * N));

#pragma omp critical
            { m_cc->EvalAddInPlace(shifted_input_array, rotated); }
        }

        auto duplicated_input_array = inputOver255->Clone();
        duplicated_input_array->SetSlots(N * N);
        auto ctxRank =
            comp.compare(m_cc, duplicated_input_array, shifted_input_array);

        ctxRank = m_cc->EvalMult(
            ctxRank, m_cc->MakeCKKSPackedPlaintext(
                         generateMaskVector2(N, N - 1), 1, 0, nullptr, N * N));

        // This cannot be parallelized
        for (int i = 1; i < log2(N) + 1; i++) {
            m_cc->EvalAddInPlace(ctxRank,
                                 rot.rotate(ctxRank, (N * N) / (1 << i)));
        }
        ctxRank->SetSlots(N);
        // rot.getStats().print();

        return ctxRank;
    }

    Ciphertext<DCRTPoly>
    rotationIndexCheck(const Ciphertext<DCRTPoly> &ctx_Rank,
                       const Ciphertext<DCRTPoly> &input_array) {
        static const auto &sincCoefficients = selectCoefficients<N>();
        auto output_array = this->getZero()->Clone();
        output_array->SetSlots(2 * N * N);
        ctx_Rank->SetSlots(2 * N * N);
        input_array->SetSlots(2 * N * N);

        Plaintext duplicated_index = m_cc->MakeCKKSPackedPlaintext(
            generateRepeatedIndex(N), 1, ctx_Rank->GetLevel(), nullptr,
            2 * N * N);

        auto index_minus_rank = m_cc->EvalSub(duplicated_index, ctx_Rank);

        Plaintext rot_checking_vector = m_cc->MakeCKKSPackedPlaintext(
            generateCheckingVector(N), 1, ctx_Rank->GetLevel(), nullptr,
            2 * N * N);

        auto rotIndex = m_cc->EvalSub(index_minus_rank, rot_checking_vector);

        m_cc->EvalMultInPlace(rotIndex, 1.0 / N / 2);

        rotIndex =
            m_cc->EvalChebyshevSeriesPS(rotIndex, sincCoefficients, -1, 1);

        auto masked_input = m_cc->EvalMultAndRelinearize(rotIndex, input_array);

#pragma omp parallel for
        for (int i = 0; i < N; i++) {
            if (i == 0) {
                Plaintext msk = m_cc->MakeCKKSPackedPlaintext(
                    generateMaskVector3(N, i), 1, masked_input->GetLevel(),
                    nullptr, 2 * N * N);
                auto rotated = m_cc->EvalMult(masked_input, msk);
#pragma omp critical
                // Add to the output array
                { m_cc->EvalAddInPlace(output_array, rotated); }
            } else {
                Plaintext msk = m_cc->MakeCKKSPackedPlaintext(
                    generateMaskVector4(N, i), 1, masked_input->GetLevel(),
                    nullptr, 2 * N * N);
                auto rotated = m_cc->EvalMult(masked_input, msk);
                rotated->SetSlots(N);
                rotated = rot.rotate(rotated, i);
#pragma omp critical
                // Add to the output array
                { m_cc->EvalAddInPlace(output_array, rotated); }
            }
        }

        for (int i = 1; i < log2(2 * N) + 1; i++) {
            m_cc->EvalAddInPlace(
                output_array, rot.rotate(output_array, (2 * N * N) / (1 << i)));
        }
        output_array->SetSlots(N);
        return output_array;
    }

    Ciphertext<DCRTPoly>
    sort(const Ciphertext<DCRTPoly> &input_array) override {

        std::cout << "\n===== Direct Sort Input Array: \n";
        PRINT_PT(m_enc, input_array);
        auto ctx_Rank = constructRank(input_array);
        std::cout << "\n===== Constructed Rank: \n";
        PRINT_PT(m_enc, ctx_Rank);

        auto output_array = rotationIndexCheck(ctx_Rank, input_array);
        std::cout << "\n===== Final Output: \n";
        PRINT_PT(m_enc, output_array);
        return output_array;
    }
};

template <int N> class BitonicSort : public SortBase<N> {
  private:
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    Comparison comp;
    RotationComposer<N> rot;

    Ciphertext<DCRTPoly> compare_and_swap(const Ciphertext<DCRTPoly> &a1,
                                          const Ciphertext<DCRTPoly> &a2,
                                          const Ciphertext<DCRTPoly> &a3,
                                          const Ciphertext<DCRTPoly> &a4) {
        auto comparison_result = comp.compare(m_cc, a1, a2);
        auto temp1 = m_cc->EvalMult(comparison_result, a3);
        auto one = m_cc->EvalSub(1, comparison_result);
        auto temp2 = m_cc->EvalMult(one, a4);
        return m_cc->EvalAdd(temp1, temp2);
    }

  public:
    std::shared_ptr<Encryption> m_enc;

    BitonicSort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey,
                std::vector<int> rotIndices, std::shared_ptr<Encryption> enc)
        : SortBase<N>(enc), m_cc(cc), m_PublicKey(publicKey), comp(enc),
          rot(cc, enc, rotIndices), m_enc(enc) {}

    Ciphertext<DCRTPoly>
    sort(const Ciphertext<DCRTPoly> &input_array) override {

        // Normalize the input
        auto inputOver255 = m_cc->EvalMult(input_array, (double)1.0 / 255);

        auto result = inputOver255;

        // k being the size of the bitonic sequences
        for (size_t k = 2; k <= N; k *= 2) {
            // j being the distance of the elements to compare
            for (size_t j = k / 2; j > 0; j /= 2) {
                std::cout << "Loop k: " << k << " j: " << j << "\n";
                std::vector<double> mask1(N, 0), mask2(N, 0), mask3(N, 0),
                    mask4(N, 0);

                // TODO add a class constructor parameter for bootstrap
                // threshold
                if (result->GetLevel() > 32) {
                    // We use double iteration bootstrapping for better
                    // precision
                    result = m_cc->EvalBootstrap(result, 2, 20);
                }

                for (size_t i = 0; i < N; i++) {
                    size_t l = i ^ j;
                    if (i < l) {
                        if ((i & k) == 0) {
                            mask1[i] = 1;
                            mask2[l] = 1;
                        } else {
                            mask3[i] = 1;
                            mask4[l] = 1;
                        }
                    }
                }

                auto arr1 = m_cc->EvalMult(
                    result, m_cc->MakeCKKSPackedPlaintext(mask1));
                auto arr2 = m_cc->EvalMult(
                    result, m_cc->MakeCKKSPackedPlaintext(mask2));
                auto arr3 = m_cc->EvalMult(
                    result, m_cc->MakeCKKSPackedPlaintext(mask3));
                auto arr4 = m_cc->EvalMult(
                    result, m_cc->MakeCKKSPackedPlaintext(mask4));

                auto arr5_1 = rot.rotate(arr1, -j);
                auto arr5_2 = rot.rotate(arr3, -j);
                auto arr6_1 = rot.rotate(arr2, j);
                auto arr6_2 = rot.rotate(arr4, j);

                auto arr7 = m_cc->EvalAdd(m_cc->EvalAdd(arr5_1, arr5_2),
                                          m_cc->EvalAdd(arr6_1, arr6_2));
                auto arr8 = result;
                auto arr9 = m_cc->EvalAdd(m_cc->EvalAdd(arr5_1, arr1),
                                          m_cc->EvalAdd(arr6_2, arr4));
                auto arr10 = m_cc->EvalAdd(m_cc->EvalAdd(arr5_2, arr3),
                                           m_cc->EvalAdd(arr6_1, arr2));

                result = compare_and_swap(arr7, arr8, arr9, arr10);
            }
        }

        // Denormalize to recover the data
        result = m_cc->EvalMult(result, (double)255);
        return result;
    }
};
