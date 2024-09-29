#pragma once

#include "comparison.h"
#include "encryption.h"
#include "openfhe.h"
#include "rotation.h"
#include <array>
#include <cmath>
#include <iostream>
#include <vector>

using namespace lbcrypto;

template <int N> class Masking {
  private:
    // Functor for generating mask vectors
    template <int Size> struct MaskVectorGenerator {
        template <int K>
        static constexpr std::array<double, Size * Size> generateMaskVector1() {
            std::array<double, Size * Size> result{};
            for (int i = K * Size; i < (K + 1) * Size && i < Size * Size; ++i) {
                result[i] = 1.0;
            }
            return result;
        }

        template <int K>
        static constexpr std::array<double, 2 * Size * Size>
        generateMaskVector4() {
            std::array<double, 2 * Size * Size> result{};
            for (int i = K * Size; i < (K + 1) * Size && i < 2 * Size * Size;
                 ++i) {
                result[i] = 1.0;
            }
            for (int i = Size * (2 * Size - K);
                 i < Size * (2 * Size - K + 1) && i < 2 * Size * Size; ++i) {
                result[i] = 1.0;
            }
            return result;
        }
    };

    static constexpr std::array<double, N * N> generateMaskVector2() {
        std::array<double, N * N> result{};
        for (int i = 0; i < N * (N - 1); ++i) {
            result[i] = 1.0;
        }
        return result;
    }

    static constexpr std::array<double, 2 * N * N> generateMaskVector3() {
        std::array<double, 2 * N * N> result{};
        for (int i = 0; i < N && i < 2 * N * N; ++i) {
            result[i] = 1.0;
        }
        return result;
    }

    // Compile-time generation of checking vector and repeated index
    static constexpr auto generateCheckingVectorImpl() {
        std::array<double, 2 * N * N> result{};
        for (int i = 0; i < 2 * N * N; ++i) {
            if (i < N * N) {
                result[i] = static_cast<double>(i / N);
            } else if (i < N * N + N) {
                result[i] = static_cast<double>(N);
            } else {
                result[i] = -static_cast<double>((i - N * N - N) / N + 1);
            }
        }
        return result;
    }

    static constexpr auto generateRepeatedIndexImpl() {
        std::array<double, 2 * N * N> result{};
        for (int i = 0; i < 2 * N * N; ++i) {
            result[i] = static_cast<double>(i % N);
        }
        return result;
    }

    // Helper function to generate all mask vectors
    template <typename F, size_t... I>
    static constexpr auto generateAllMaskVectors(std::index_sequence<I...>) {
        return std::array{F::template generateMaskVector1<I>()...};
    }

    template <typename F, size_t... I>
    static constexpr auto generateAllMaskVectors4(std::index_sequence<I...>) {
        return std::array{F::template generateMaskVector4<I>()...};
    }

    // Compile-time constants
    static constexpr auto maskVectors1 =
        generateAllMaskVectors<MaskVectorGenerator<N>>(
            std::make_index_sequence<N>{});
    static constexpr auto maskVector2 = generateMaskVector2();
    static constexpr auto maskVector3 = generateMaskVector3();
    static constexpr auto maskVectors4 =
        generateAllMaskVectors4<MaskVectorGenerator<N>>(
            std::make_index_sequence<N>{});
    static constexpr auto checkingVectorArray = generateCheckingVectorImpl();
    static constexpr auto repeatedIndexArray = generateRepeatedIndexImpl();

    // Cached vectors
    std::vector<std::vector<double>> cachedMaskVectors1;
    std::vector<double> cachedMaskVector2;
    std::vector<double> cachedMaskVector3;
    std::vector<std::vector<double>> cachedMaskVectors4;
    std::vector<double> cachedCheckingVector;
    std::vector<double> cachedRepeatedIndex;

    // Helper function to convert std::array to std::vector
    template <typename T, size_t S>
    static std::vector<T> to_vector(const std::array<T, S> &arr) {
        return std::vector<T>(arr.begin(), arr.end());
    }

  public:
    Masking() { initializeCachedVectors(); }

    void initializeCachedVectors() {
        cachedMaskVectors1.reserve(N);
        cachedMaskVectors4.reserve(N);

        for (const auto &arr : maskVectors1) {
            cachedMaskVectors1.push_back(to_vector(arr));
        }
        for (const auto &arr : maskVectors4) {
            cachedMaskVectors4.push_back(to_vector(arr));
        }

        cachedMaskVector2 = to_vector(maskVector2);
        cachedMaskVector3 = to_vector(maskVector3);
        cachedCheckingVector = to_vector(checkingVectorArray);
        cachedRepeatedIndex = to_vector(repeatedIndexArray);
    }

    const std::vector<double> &getMaskVector1(int index) const {
        return cachedMaskVectors1[index];
    }
    const std::vector<double> &getMaskVector2() const {
        return cachedMaskVector2;
    }
    const std::vector<double> &getMaskVector3() const {
        return cachedMaskVector3;
    }
    const std::vector<double> &getMaskVector4(int index) const {
        return cachedMaskVectors4[index];
    }
    const std::vector<double> &getCheckingVector() const {
        return cachedCheckingVector;
    }
    const std::vector<double> &getRepeatedIndex() const {
        return cachedRepeatedIndex;
    }
};

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
};

template <int N> class DirectSort : public SortBase<N> {
  private:
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    Comparison comp;
    RotationComposer<N> rot;
    Masking<N> masking;

  public:
    std::shared_ptr<Encryption> m_enc;

    DirectSort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey,
               std::vector<int> rotIndices, std::shared_ptr<Encryption> enc)
        : SortBase<N>(enc), m_cc(cc), m_PublicKey(publicKey), comp(enc),
          rot(m_cc, enc, rotIndices), m_enc(enc) {}

    Ciphertext<DCRTPoly>
    constructRank(const Ciphertext<DCRTPoly> &input_array) {

        auto shifted_input_array = this->getZero()->Clone();
        const auto inputOver255 =
            m_cc->EvalMult(input_array, (double)1.0 / 255);

#pragma omp parallel for
        for (int i = 1; i < N; i++) {
            auto rotated = rot.rotate(inputOver255, i);
            rotated->SetSlots(N * N);
            rotated = m_cc->EvalMult(rotated, m_cc->MakeCKKSPackedPlaintext(
                                                  masking.getMaskVector1(i - 1),
                                                  1, 0, nullptr, N * N));

            // TODO remove critical section for performance and instead add
            // results later
#pragma omp critical
            { m_cc->EvalAddInPlace(shifted_input_array, rotated); }
        }

        auto duplicated_input_array = inputOver255->Clone();
        duplicated_input_array->SetSlots(N * N);
        auto ctxRank =
            comp.compare(m_cc, duplicated_input_array, shifted_input_array);

        ctxRank = m_cc->EvalMult(
            ctxRank, m_cc->MakeCKKSPackedPlaintext(masking.getMaskVector2(), 1,
                                                   0, nullptr, N * N));

        // This cannot be parallelized
        for (int i = 1; i < log2(N) + 1; i++) {
            m_cc->EvalAddInPlace(ctxRank,
                                 rot.rotate(ctxRank, (N * N) / (1 << i)));
        }
        ctxRank->SetSlots(N);

        return ctxRank;
    }

    Ciphertext<DCRTPoly>
    rotationIndexCheck(const Ciphertext<DCRTPoly> &ctx_Rank,
                       const Ciphertext<DCRTPoly> &input_array) {

        auto output_array = this->getZero()->Clone();
        output_array->SetSlots(2 * N * N);
        ctx_Rank->SetSlots(2 * N * N);
        input_array->SetSlots(2 * N * N);

        Plaintext duplicated_index = m_cc->MakeCKKSPackedPlaintext(
            masking.getRepeatedIndex(), 1, ctx_Rank->GetLevel(), nullptr,
            2 * N * N);

        auto index_minus_rank = m_cc->EvalSub(duplicated_index, ctx_Rank);

        Plaintext rot_checking_vector = m_cc->MakeCKKSPackedPlaintext(
            masking.getCheckingVector(), 1, ctx_Rank->GetLevel(), nullptr,
            2 * N * N);

        auto rotIndex = m_cc->EvalSub(index_minus_rank, rot_checking_vector);

        m_cc->EvalMultInPlace(rotIndex, 1.0 / N / 2);

        rotIndex = m_cc->EvalChebyshevFunction(
            [](double x) {
                if (std::abs(x) < 1e-10) {
                    return 1.0;
                } else {
                    return std::sin(M_PI * 256 * x) / (M_PI * 256 * x);
                }
            },
            rotIndex, -1, 1, 1011);
        auto masked_input = m_cc->EvalMultAndRelinearize(rotIndex, input_array);

#pragma omp parallel for
        for (int i = 0; i < N; i++) {
            if (i == 0) {
                Plaintext msk = m_cc->MakeCKKSPackedPlaintext(
                    masking.getMaskVector3(), 1, masked_input->GetLevel(),
                    nullptr, 2 * N * N);
                auto rotated = m_cc->EvalMult(masked_input, msk);
#pragma omp critical
                // Add to the output array
                { m_cc->EvalAddInPlace(output_array, rotated); }
            } else {
                Plaintext msk = m_cc->MakeCKKSPackedPlaintext(
                    masking.getMaskVector4(i), 1, masked_input->GetLevel(),
                    nullptr, 2 * N * N);
                auto rotated = m_cc->EvalMult(masked_input, msk);
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
