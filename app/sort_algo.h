#pragma once

#include "ciphertext-fwd.h"
#include "comparison.h"
#include "encryption.h"
#include "lattice/hal/lat-backend.h"
#include "openfhe.h"
#include "rotation.h"
#include <iostream>
#include <vector>

using namespace lbcrypto;

#include "generated_coeffs.h"

enum class SortAlgo { DirectSort, BitonicSort };

inline void
printElapsedTime(const std::string &description,
                 const std::chrono::high_resolution_clock::time_point &start) {
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << description << ": "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                       start)
                     .count()
              << " ms" << std::endl;
}

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

    virtual Ciphertext<DCRTPoly> sort(const Ciphertext<DCRTPoly> &input_array,
                                      SignFunc SignFunc, SignConfig &Cfg) = 0;

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

    static void getSizeParameters(CCParams<CryptoContextCKKSRNS> &parameters,
                                  std::vector<int> &rotations) {
        parameters.SetBatchSize(N);
        parameters.SetScalingModSize(40);

        for (int i = 1; i < N / 2; i *= 2) {
            rotations.push_back(-i);
            rotations.push_back(i);
        }
        rotations.push_back(N / 2);

        // Pattern for output_array rotations
        for (int i = 1; i < log2(2 * N) + 1; i++) {
            rotations.push_back((2 * N * N) / (1 << i));
        }

        std::cout << "Rotation indices: "
                  << "\n";
        std::cout << rotations << "\n";
        int multDepth;
        switch (N) {
        case 4:
            multDepth = 40;
            break;
        case 8:
            multDepth = 41;
            break;
        case 16:
            multDepth = 41;
            break;
        case 32:
            multDepth = 42;
            break;
        case 64:
            multDepth = 43;
            break;
        case 128:
            multDepth = 44;
            break;
            // TODO correct depths for large sizes
        case 256:
            multDepth = 44;
            break;
        case 512:
            multDepth = 44;
            break;
        case 1024:
            multDepth = 44;
            break;
        }
        // Disabled normalization at constructRank
        multDepth--;
        parameters.SetMultiplicativeDepth(multDepth);
    }

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

    std::vector<double> generateMaskVector1_flexible(int array_size,
                                                     int max_batch, int k) {
        std::vector<double> result(max_batch, 0.0);

        for (int i = k * array_size; i < (k + 1) * array_size; ++i) {
            result[i] = 1.0;
        }

        return result;
    }

    std::vector<double> generateMaskVector1_2n(int array_size, int k) {
        std::vector<double> result(array_size * array_size, 0.0);

        for (int i = k * array_size * 2; i < (k + 1) * array_size * 2; ++i) {
            result[i] = 1.0;
        }

        return result;
    }

    std::vector<double> generateMaskVector1_2n_flexible(int array_size,
                                                        int max_batch, int k) {
        std::vector<double> result(max_batch, 0.0);

        for (int i = k * array_size * 2; i < (k + 1) * array_size * 2; ++i) {
            result[i] = 1.0;
        }

        return result;
    }

    std::vector<double> generateMaskVectorSetUnset(int array_size) {
        std::vector<double> result;

        for (int i = 0; i < array_size / 2; ++i) {
            result.insert(result.end(), array_size, 1.0);
            result.insert(result.end(), array_size, 0.0);
        }

        return result;
    }

    std::vector<double> generateMaskVectorSetUnset2(int array_size) {
        std::vector<double> result;

        for (int i = 0; i < array_size / 2; ++i) {
            result.insert(result.end(), array_size, 1.0);
            result.insert(result.end(), array_size, 0.0);
        }

        result.erase(result.end() - array_size, result.end());
        result.insert(result.end(), array_size, 1.0);

        return result;
    }

    std::vector<double>
    generateMaskVectorSetUnset2_generalized1(int array_size, int max_batch) {
        std::vector<double> result;

        for (int i = 0; i < max_batch / array_size / 2; ++i) {
            result.insert(result.end(), array_size, 1.0);
            result.insert(result.end(), array_size, 0.0);
        }

        return result;
    }

    std::vector<double>
    generateMaskVectorSetUnset2_generalized2(int array_size, int max_batch) {
        std::vector<double> result;

        for (int i = 0; i < max_batch / array_size / 2; ++i) {
            result.insert(result.end(), array_size, 1.0);
            result.insert(result.end(), array_size, 0.0);
        }

        result.erase(result.end() - array_size, result.end());
        result.insert(result.end(), array_size, 1.0);

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

    Ciphertext<DCRTPoly> constructRank(const Ciphertext<DCRTPoly> &input_array,
                                       SignFunc SignFunc, SignConfig &Cfg) {

        auto shifted_input_array = this->getZero()->Clone();
        // If the input is already normalized, else we should normalize by
        // max-min
        const auto inputOver255 = input_array;
        // m_cc->EvalMult(input_array, (double)1.0 / 255);

        // The repeated rotation is optimized with treeRotate structure by
        // reusing intermediate rotations
        std::vector<Ciphertext<DCRTPoly>> rotated_results(N);
        RotationTree<N> rotTree(m_cc, rot.getRotIndices());
        rotTree.buildTree(1, N / 2 + 1);
        for (int i = 4; i <= N / 2; i += 4) {
            rotated_results[i] = rotTree.treeRotate(inputOver255, i);
        }
#pragma omp parallel for
        for (int i = 1; i <= N / 2; i++) {
            auto rotated = i % 4 == 0 ? rotated_results[i]
                                      : rotTree.treeRotate(inputOver255, i);
            rotated->SetSlots(N * N);
            rotated = m_cc->EvalMult(
                rotated,
                m_cc->MakeCKKSPackedPlaintext(generateMaskVector1_2n(N, i - 1),
                                              1, 0, nullptr, N * N));

#pragma omp critical
            { m_cc->EvalAddInPlace(shifted_input_array, rotated); }
        }
        shifted_input_array->SetSlots(N * N);

        auto duplicated_input_array = inputOver255->Clone();
        duplicated_input_array->SetSlots(N * N);

        auto ctxRank = comp.compare(m_cc, duplicated_input_array,
                                    shifted_input_array, SignFunc, Cfg);

        // ctxRank->SetSlots(N * N);

        auto half_comparisons = m_cc->EvalMult(
            ctxRank, m_cc->MakeCKKSPackedPlaintext(
                         generateMaskVectorSetUnset(N), 1, 0, nullptr, N * N));

        auto inverted_comparisons = this->getZero()->Clone();
        Ciphertext<DCRTPoly> rotated = ctxRank->Clone();
        for (int i = 2; i <= N - 2; i += 2) {
            // auto rotated = rotated_results[i];
            rotated = m_cc->EvalRotate(rotated, -1);

            // rotated->SetSlots(N * N);
            auto masked = m_cc->EvalMult(
                rotated,
                m_cc->MakeCKKSPackedPlaintext(generateMaskVector1(N, i - 1), 1,
                                              0, nullptr, N * N));

            // #pragma omp critical
            { m_cc->EvalAddInPlace(inverted_comparisons, masked); }
        }
        inverted_comparisons->SetSlots(N * N);
        inverted_comparisons = m_cc->EvalAdd(
            inverted_comparisons,
            m_cc->MakeCKKSPackedPlaintext(generateMaskVectorSetUnset2(N), 1, 0,
                                          nullptr, N * N));
        inverted_comparisons = m_cc->EvalSub(1, inverted_comparisons);

        ctxRank = m_cc->EvalAdd(half_comparisons, inverted_comparisons);

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
    constructRankGeneral(const Ciphertext<DCRTPoly> &input_array,
                         SignFunc SignFunc, SignConfig &Cfg) {

        auto shifted_input_array = this->getZero()->Clone();
        // If the input is already normalized, else we should normalize by
        // max-min
        const auto inputOver255 = input_array;
        // m_cc->EvalMult(input_array, (double)1.0 / 255);

        // The repeated rotation is optimized with treeRotate structure by
        // reusing intermediate rotations
        std::vector<Ciphertext<DCRTPoly>> rotated_results(N);
        RotationTree<N> rotTree(m_cc, rot.getRotIndices());
        rotTree.buildTree(1, N / 2 + 1);
        for (int i = 4; i <= N / 2; i += 4) {
            rotated_results[i] = rotTree.treeRotate(inputOver255, i);
        }

        auto max_batch = m_cc->GetRingDimension() / 2;
        auto num_chunk = (N * N) / max_batch; // the number of vectorizations

        auto rank_result = this->getZero()->Clone();

        for (int c = 0; c < num_chunk; c++) {
            int start = 1 + (N / 2 / num_chunk) *
                                c; //  (N / 2 / num_chunk) : the number of
                                   //  covered indices in each chunk
            int end = (N / 2 / num_chunk) * (c + 1);

#pragma omp parallel for
            for (int i = start; i <= end; i++) {
                auto rotated = i % 4 == 0 ? rotated_results[i]
                                          : rotTree.treeRotate(inputOver255, i);
                rotated->SetSlots(max_batch);

                rotated = m_cc->EvalMult(
                    rotated,
                    m_cc->MakeCKKSPackedPlaintext(
                        generateMaskVector1_2n_flexible(
                            N, max_batch, (i - 1) % (N / 2 / num_chunk)),
                        1, 0, nullptr, max_batch));

#pragma omp critical
                { m_cc->EvalAddInPlace(shifted_input_array, rotated); }
            }

            auto duplicated_input_array = inputOver255->Clone();
            duplicated_input_array->SetSlots(max_batch);

            auto comp_result = comp.compare(m_cc, duplicated_input_array,
                                            shifted_input_array, SignFunc, Cfg);

            auto half_comparisons = m_cc->EvalMult(
                comp_result, 0.5); // Identical to masking the half portion,
                                   // since they are added up later.

            auto inverted_comparisons = this->getZero()->Clone();
            Ciphertext<DCRTPoly> rotated = comp_result->Clone();

            if (c != 0)
                rotated = rot.rotate(rotated, -(N / 2 / num_chunk) * c);

            for (int i = 2; i <= (c == num_chunk - 1) ? (N / num_chunk) - 2
                                                      : (N / num_chunk);
                 i += 2) {
                // auto rotated = rotated_results[i];
                rotated = m_cc->EvalRotate(rotated, -1);

                auto masked = m_cc->EvalMult(
                    rotated,
                    m_cc->MakeCKKSPackedPlaintext(
                        generateMaskVector1_flexible(N, max_batch, i - 1), 1, 0,
                        nullptr, max_batch));

                // #pragma omp critical
                { m_cc->EvalAddInPlace(inverted_comparisons, masked); }
            }

            if (c != num_chunk - 1) {
                inverted_comparisons = m_cc->EvalAdd(
                    inverted_comparisons,
                    m_cc->MakeCKKSPackedPlaintext(
                        generateMaskVectorSetUnset2_generalized1(N), 1, 0,
                        nullptr, max_batch));
            } else {
                inverted_comparisons = m_cc->EvalAdd(
                    inverted_comparisons,
                    m_cc->MakeCKKSPackedPlaintext(
                        generateMaskVectorSetUnset2_generalized1(N), 1, 0,
                        nullptr, max_batch));
            }

            inverted_comparisons = m_cc->EvalSub(1, inverted_comparisons);

#pragma omp critical
            {
                m_cc->EvalAddInPlace(
                    rank_result,
                    m_cc->EvalAdd(half_comparisons, inverted_comparisons));
            }
        }

        // This cannot be parallelized
        for (int i = 1; i < log2(N / num_chunk) + 1; i++) {
            m_cc->EvalAddInPlace(rank_result,
                                 rot.rotate(rank_result, max_batch / (1 << i)));
        }
        rank_result->SetSlots(N);

        return rank_result;
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

        auto masked_input = m_cc->EvalMult(rotIndex, input_array);

        std::vector<Ciphertext<DCRTPoly>> rotated_results(N);
        RotationTree<N> rotTree(m_cc, rot.getRotIndices());
        rotTree.buildTree(1, N + 1);
        for (int i = 4; i < N; i += 4) {
            rotated_results[i] = rotTree.treeRotate(masked_input, i);
        }
#pragma omp parallel for
        for (int i = 0; i < N; i++) {
            if (i == 0) {
                Plaintext msk = m_cc->MakeCKKSPackedPlaintext(
                    generateMaskVector3(N, i), 1, masked_input->GetLevel(),
                    nullptr, 2 * N * N);
                auto rotated = m_cc->EvalMult(masked_input, msk);
#pragma omp critical
                { m_cc->EvalAddInPlace(output_array, rotated); }
            } else {
                auto rotated = i % 4 == 0 ? rotated_results[i]
                                          : rotTree.treeRotate(masked_input, i);
                auto vec = generateMaskVector4(N, i);
                std::rotate(vec.begin(), vec.begin() + i, vec.end());
                Plaintext msk = m_cc->MakeCKKSPackedPlaintext(
                    vec, 1, masked_input->GetLevel(), nullptr, 2 * N * N);
                rotated = m_cc->EvalMult(rotated, msk);
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

    Ciphertext<DCRTPoly> sort(const Ciphertext<DCRTPoly> &input_array,
                              SignFunc SignFunc, SignConfig &Cfg) override {

        auto max_batch = m_cc->GetRingDimension() / 2;
        std::cout << "\n===== Direct Sort Input Array: \n";
        PRINT_PT(m_enc, input_array);

        Ciphertext<DCRTPoly> ctx_Rank;
        if (max_batch > N * N) // vectorization unavailable
            ctx_Rank = constructRank(input_array, SignFunc, Cfg);
        else
            ctx_Rank = constructRank(input_array, SignFunc, Cfg);

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
                                          const Ciphertext<DCRTPoly> &a4,
                                          SignFunc SignFunc, SignConfig &Cfg) {
        auto comparison_result = comp.compare(m_cc, a1, a2, SignFunc, Cfg);
        auto temp1 = m_cc->EvalMult(comparison_result, a3);
        auto one = m_cc->EvalSub(1, comparison_result);
        auto temp2 = m_cc->EvalMult(one, a4);
        auto result = m_cc->EvalAdd(temp1, temp2);
        return result;
    }

  public:
    std::shared_ptr<Encryption> m_enc;

    BitonicSort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey,
                std::vector<int> rotIndices, std::shared_ptr<Encryption> enc)
        : SortBase<N>(enc), m_cc(cc), m_PublicKey(publicKey), comp(enc),
          rot(cc, enc, rotIndices), m_enc(enc) {}

    Ciphertext<DCRTPoly> sort(const Ciphertext<DCRTPoly> &input_array,
                              SignFunc SignFunc, SignConfig &Cfg) override {
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

                if (result->GetLevel() > 29) {
                    result = m_cc->EvalBootstrap(result, 2, 20);
                }

                // Masking operations
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

                // Rotation operations
                auto arr5_1 = rot.rotate(arr1, -j);
                auto arr5_2 = rot.rotate(arr3, -j);
                auto arr6_1 = rot.rotate(arr2, j);
                auto arr6_2 = rot.rotate(arr4, j);

                // Addition operations
                auto arr7 = m_cc->EvalAdd(m_cc->EvalAdd(arr5_1, arr5_2),
                                          m_cc->EvalAdd(arr6_1, arr6_2));
                auto arr8 = result;
                auto arr9 = m_cc->EvalAdd(m_cc->EvalAdd(arr5_1, arr1),
                                          m_cc->EvalAdd(arr6_2, arr4));
                auto arr10 = m_cc->EvalAdd(m_cc->EvalAdd(arr5_2, arr3),
                                           m_cc->EvalAdd(arr6_1, arr2));

                result =
                    compare_and_swap(arr7, arr8, arr9, arr10, SignFunc, Cfg);
            }
        }

        // Denormalize to recover the data
        result = m_cc->EvalMult(result, (double)255);

        return result;
    }
};
