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

    int max_batch; // Maximum number of slots which can be utilized  (=
                   // ringDim/2)

  public:
    std::shared_ptr<Encryption> m_enc;

    DirectSort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey,
               std::vector<int> rotIndices, std::shared_ptr<Encryption> enc)
        : SortBase<N>(enc), m_cc(cc), m_PublicKey(publicKey), comp(enc),
          rot(m_cc, enc, rotIndices), m_enc(enc) {

        // Initializations are currently hard coded
        this->max_batch = m_cc->GetRingDimension() / 2;
    }

    static void getSizeParameters(CCParams<CryptoContextCKKSRNS> &parameters,
                                  std::vector<int> &rotations) {
        parameters.SetBatchSize(N);

        for (int i = 1; i < N / 2; i *= 2) {
            rotations.push_back(-i);
            rotations.push_back(i);
        }
        rotations.push_back(N / 2);

        // Pattern for output_array rotations
        if (2 * N * N > 1 << 16) {
            for (int i = 1; i < log2((1 << 16) / N) + 1; i++) {
                rotations.push_back((1 << 16) / (1 << i));
            }
        } else {
            for (int i = 1; i < log2(2 * N) + 1; i++) {
                rotations.push_back((2 * N * N) / (1 << i));
            }
        }

        std::cout << "Rotation indices: "
                  << "\n";
        std::cout << rotations << "\n";
        int multDepth;
        int modSize = 50;

        switch (N) {
        case 4:
            multDepth = 38;
            break;
        case 8:
            multDepth = 39;
            break;
        case 16:
            multDepth = 39;
            break;
        case 32:
            multDepth = 40;
            break;
        case 64:
            multDepth = 41;
            break;
        case 128: // require stronger precision in comparison
            multDepth = 48;
            break;
        case 256:
            multDepth = 49;
            break;
        case 512:
            multDepth = 49;
            break;
        case 1024:
            multDepth = 50;
            break;
        }
        parameters.SetScalingModSize(modSize);
        parameters.SetMultiplicativeDepth(multDepth);
    }

    /*
        masking vector generation for SIMD optimization
    */
    std::vector<double> generateMaskVector(int num_slots, int k) {
        std::vector<double> result(num_slots, 0.0);

        for (int i = k * N; i < (k + 1) * N; ++i) {
            result[i] = 1.0;
        }

        return result;
    }

    std::vector<double> generateMaskVector2N(int num_slots, int k) {
        std::vector<double> result(num_slots, 0.0);

        for (int i = k * N * 2; i < (k + 1) * N * 2; ++i) {
            result[i] = 1.0;
        }

        return result;
    }

    // generate index vector, e.g. n=4 [0,1,2,3]
    std::vector<double> generateIndexVector() {
        std::vector<double> result;
        result.reserve(N);

        for (int i = 0; i < N; ++i) {
            result.push_back(static_cast<double>(i));
        }

        return result;
    }

    /*
        This function creates a vector of size max_batch, filled with a
       repeating pattern of [k, k, ..., k, -N+k, -N+k, ..., -N+k] where each
       value is repeated N times.
    */
    std::vector<double> generateCheckingVector(int num_slots, int k) {
        std::vector<double> result(num_slots);
        int index = 0;
        int current_k = k;

        while (index < num_slots) {
            // Fill with [k | -N+k] pattern
            for (int i = 0; i < N && index < num_slots; ++i) {
                result[index++] = current_k;
            }
            for (int i = 0; i < N && index < num_slots; ++i) {
                result[index++] = -N + current_k;
            }

            // Move to next k
            current_k = (current_k + 1) % N;
        }

        return result;
    }

    // Rotate the plaintext vector (vec) by rotationIndex
    std::vector<double> vectorRotate(const std::vector<double> &vec,
                                     int rotateIndex) {
        if (vec.empty())
            return std::vector<double>();

        std::vector<double> result = vec;
        int n = result.size();

        if (rotateIndex > 0) // left rotation
            std::rotate(result.begin(), result.begin() + rotateIndex,
                        result.end());
        else if (rotateIndex < 0) { // right rotation
            rotateIndex += n;
            std::rotate(result.begin(), result.begin() + rotateIndex,
                        result.end());
        }
        return result;
    }

    Ciphertext<DCRTPoly> vecRots(const Ciphertext<DCRTPoly> &input_array,
                                 int num_partition, int num_slots, int is) {
        auto rots = this->getZero()->Clone();

#pragma omp parallel for
        for (int j = 0; j < num_partition; j++) {
            auto rotated = rot.rotate(input_array, is * num_partition + j);
            rotated->SetSlots(num_slots);

            auto pmsk = m_cc->MakeCKKSPackedPlaintext(
                generateMaskVector(num_slots, j), 1, 0, nullptr, num_slots);
            auto masked = m_cc->EvalMult(rotated, pmsk);
#pragma omp critical
            {
                m_cc->EvalAddInPlace(rots, masked);
            }
        }
        return rots;
    }

    Ciphertext<DCRTPoly>
    vecRotsOpt(const std::vector<Ciphertext<DCRTPoly>> &preRotatedArrays,
               int num_partition, int num_slots, int np, int is) {
        auto result = this->getZero()->Clone();
        Plaintext ptx;
        // Observation: Inner loop parallelization performs better
        for (int j = 0; j < num_partition / np; j++) {

            auto T = this->getZero()->Clone();
            T->SetSlots(num_slots);

#pragma omp parallel for
            for (int i = 0; i < np; i++) {

                auto msk = generateMaskVector(num_slots, np * j + i);
                msk = vectorRotate(msk, -is * num_partition - j * np);
                auto pmsk = m_cc->MakeCKKSPackedPlaintext(msk, 1, 0, nullptr,
                                                          num_slots);
                auto masked = m_cc->EvalMult(preRotatedArrays[i], pmsk);
#pragma omp critical
                {
                    m_cc->EvalAddInPlace(T, masked);
                }
            }
            auto TT = rot.rotate(T, is * num_partition + j * np);
            m_cc->EvalAddInPlace(result, TT);
        }

        return result;
    }

    Ciphertext<DCRTPoly> constructRank(const Ciphertext<DCRTPoly> &input_array,
                                       SignFunc SignFunc, SignConfig &Cfg) {

        ///////////////// Meta Data for Rank Construction /////////////////
        int num_partition; // The number of arrays to be packed into a single
                           // ciphertext (=min(N, max_batch / N))
        int num_batch; // The number of required batches (= N / num_partition)
        int num_slots; // The number of slots to be utilized (= N *
                       // num_partition)

        num_partition = std::min(N, max_batch / N);
        num_batch = N / num_partition;
        num_slots = N * num_partition;

        int np; // The number of precomputed rotations for VecRotsOpt
        switch (N) {
        case 4:
            np = std::min(2, num_partition);
            break;
        case 8:
            np = std::min(2, num_partition);
            break;
        case 16:
            np = std::min(4, num_partition);
            break;
        case 32:
            np = std::min(4, num_partition);
            break;
        case 64:
            np = std::min(8, num_partition);
            break;
        case 128:
            np = std::min(8, num_partition);
            break;
        case 256:
            np = std::min(16, num_partition);
            break;
        case 512:
            np = std::min(16, num_partition);
            break;
        case 1024:
            np = std::min(32, num_partition);
            break;
        case 2048:
            np = std::min(32, num_partition);
            break;
        default:
            break;
        }
        ///////////////////////////////////////////////////////////////////

        // If the input is already normalized, else we should normalize by
        // max-min
        const auto inputOver255 = input_array;

        // precomputation for VecRotsOpt
        std::vector<Ciphertext<DCRTPoly>> babyStpesofB(np);
#pragma omp for
        for (int i = 0; i < np; i++) {
            Ciphertext<DCRTPoly> t;
            t = rot.rotate(input_array, i);
            t->SetSlots(num_slots);
            babyStpesofB[i] = t;
        }

        auto rank_result = this->getZero()->Clone();
        rank_result->SetSlots(num_slots);

        // Note : B is the number of vectorizations
        for (int i = 0; i < num_batch; i++) {
            // Generate shifted input array
            // auto shifted_input_array = vecRots(input_array, i);
            auto shifted_input_array =
                vecRotsOpt(babyStpesofB, num_partition, num_slots, np, i);

            // Generate duplicated input array
            auto duplicated_input_array = inputOver255->Clone();
            duplicated_input_array->SetSlots(num_slots);

            // comp(duplicated, shifted)
            auto comp_result = comp.compare(m_cc, duplicated_input_array,
                                            shifted_input_array, SignFunc, Cfg);

            m_cc->EvalAddInPlace(rank_result, comp_result);
        }

        // This cannot be parallelized
        for (int i = 1; i < log2(num_partition) + 1; i++) {
            m_cc->EvalAddInPlace(rank_result,
                                 rot.rotate(rank_result, num_slots / (1 << i)));
        }
        rank_result->SetSlots(N);

        // Compensate for the self comprison (input_array - Rot(input_array, 0))
        rank_result = m_cc->EvalSub(rank_result, 0.5);
        return rank_result;
    }

    /*
        Rotate the input array using a masked input array.
        Each chunk of the masked input is rotated by a predefined index, which
       we use to perform the rotation.

        ib : Index of current batch

    */
    Ciphertext<DCRTPoly> blindRotation(const Ciphertext<DCRTPoly> &masked_input,
                                       int num_slots, int ib) {
        auto result = this->getZero()->Clone();

#pragma omp parallel for
        for (int i = ib * (num_slots / N / 2);
             i < (ib + 1) * (num_slots / N / 2); i++) {
            auto rotated = rot.rotate(masked_input, i);

            auto vec = generateMaskVector2N(num_slots, i % (num_slots / N / 2));
            std::rotate(vec.begin(), vec.begin() + i, vec.end());
            Plaintext msk = m_cc->MakeCKKSPackedPlaintext(
                vec, 1, masked_input->GetLevel(), nullptr, num_slots);
            rotated = m_cc->EvalMult(rotated, msk);
#pragma omp critical
            {
                m_cc->EvalAddInPlace(result, rotated);
            }
        }
        return result;
    }

    Ciphertext<DCRTPoly>
    blindRotationOpt(const std::vector<Ciphertext<DCRTPoly>> &masked_inputs,
                     int num_slots, int np, int ib) {
        auto result = this->getZero()->Clone();

        for (int i = 0; i < (num_slots / N / 2) / np; i++) {
            auto tmp = this->getZero()->Clone();

#pragma omp parallel for
            for (int j = 0; j < np; j++) {
                auto msk = generateMaskVector2N(num_slots, (np * i + j));
                msk = vectorRotate(msk, j);
                Plaintext pmsk = m_cc->MakeCKKSPackedPlaintext(
                    msk, 1, masked_inputs[j]->GetLevel(), nullptr, num_slots);

                auto rotated = m_cc->EvalMult(masked_inputs[j], pmsk);
#pragma omp critical
                {
                    m_cc->EvalAddInPlace(tmp, rotated);
                }
            }
            tmp = rot.rotate(tmp, i * np);
            m_cc->EvalAddInPlace(result, tmp);
        }
        return result;
    }

    Ciphertext<DCRTPoly>
    rotationIndexCheck(const Ciphertext<DCRTPoly> &ctx_Rank,
                       const Ciphertext<DCRTPoly> &input_array) {

        static const auto &sincCoefficients = selectCoefficients<N>();
        auto output_array = this->getZero()->Clone();

        /////////////// Meta Data for Rotation Index Checking ///////////////
        int num_partition =
            std::min(2 * N, max_batch / N); // slot usage = num_partition * N
        int num_batch = 2 * N / num_partition;
        int num_slots = num_partition * N;

        int np = 1 << ((31 - __builtin_clz(num_partition / 2)) >> 1);
        if ((np * np) > (num_partition / 2)) {
            np >>= 1;
        }
        /////////////////////////////////////////////////////////////////////

        Plaintext index_vector = m_cc->MakeCKKSPackedPlaintext(
            generateIndexVector(), 1, ctx_Rank->GetLevel(), nullptr, N);
        auto index_minus_rank = m_cc->EvalSub(index_vector, ctx_Rank);

        index_minus_rank->SetSlots(num_slots);
        input_array->SetSlots(num_slots);

        for (int b = 0; b < num_batch; b++) {
            Plaintext rot_checking_vector = m_cc->MakeCKKSPackedPlaintext(
                generateCheckingVector(num_slots, b * (num_slots / N / 2)), 1,
                index_minus_rank->GetLevel(), nullptr, num_slots);

            auto rotIndex =
                m_cc->EvalSub(index_minus_rank, rot_checking_vector);

            // approximate just sinc(x) in range (-2N, 2N)
            m_cc->EvalMultInPlace(rotIndex, 1.0 / N / 2);
            rotIndex =
                m_cc->EvalChebyshevSeriesPS(rotIndex, sincCoefficients, -1, 1);

            auto masked_input = m_cc->EvalMult(rotIndex, input_array);
            std::vector<Ciphertext<DCRTPoly>> masked_inputs(np);
#pragma omp for
            for (int i = 0; i < np; i++) {
                masked_inputs[i] =
                    rot.rotate(masked_input, b * (num_slots / N / 2) + i);
            }
            auto rotated_input =
                blindRotationOpt(masked_inputs, num_slots, np, b);
            // auto rotated_input = blindRotation(masked_input, num_slots, b);
            m_cc->EvalAddInPlace(output_array, rotated_input);
        }

        for (int i = 1; i < log2(num_partition) + 1; i++) {
            m_cc->EvalAddInPlace(
                output_array, rot.rotate(output_array, num_slots / (1 << i)));
        }
        output_array->SetSlots(N);
        return output_array;
    }

    Ciphertext<DCRTPoly> sort(const Ciphertext<DCRTPoly> &input_array,
                              SignFunc SignFunc, SignConfig &Cfg) override {
        std::cout << "\n===== Direct Sort Input Array: \n";
        PRINT_PT(m_enc, input_array);

        Ciphertext<DCRTPoly> ctx_Rank;
        ctx_Rank = constructRank(input_array, SignFunc, Cfg);

        std::cout << "\n===== Constructed Rank: \n";
        PRINT_PT(m_enc, ctx_Rank);

        Ciphertext<DCRTPoly> output_array;
        std::cout << "general rotation index checking" << std::endl;
        output_array = rotationIndexCheck(ctx_Rank, input_array);

        std::cout << "\n===== Final Output: \n";
        PRINT_PT(m_enc, output_array);

        std::cout << "Final Level: " << output_array->GetLevel() << std::endl;
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
