#include "encryption.h"
#include "openfhe.h"
#include <array>
#include <cstdint>
#include <vector>

using namespace lbcrypto;

template <int N> class NAFComputer {
  public:
    static constexpr int MAX_NAF_SIZE =
        32; // log2(128) + 1, adjust if N changes

    static constexpr std::array<int8_t, MAX_NAF_SIZE> computeNAF(int rotation) {
        std::array<int8_t, MAX_NAF_SIZE> naf = {};
        for (int i = 0; i < MAX_NAF_SIZE && rotation != 0; ++i) {
            if (rotation & 1) {
                int8_t z = (rotation & 2) ? -1 : 1;
                naf[i] = z;
                rotation -= z;
            }
            rotation /= 2;
        }
        return naf;
    }
};

template <int N> class OptimizedRotator {
  private:
    CryptoContext<DCRTPoly> m_cc;
    std::shared_ptr<Encryption> m_enc;

    // Compile-time computation of all NAFs
    static constexpr auto computeAllNAFs() {
        std::array<std::array<int8_t, 32>, N> nafs = {};
        for (int i = 0; i < N; ++i) {
            nafs[i] = NAFComputer<N>::computeNAF(i);
        }
        return nafs;
    }

    static constexpr auto rotationNAFs = computeAllNAFs();

  public:
    OptimizedRotator(CryptoContext<DCRTPoly> cc,
                     std::shared_ptr<Encryption> enc)
        : m_cc(cc), m_enc(enc) {}

    Ciphertext<DCRTPoly> rotate(const Ciphertext<DCRTPoly> &input,
                                int rotation) {
        rotation = ((rotation % N) + N) % N;
        auto result = input->Clone();
        const auto &naf = rotationNAFs[rotation % N];

        for (int i = 31; i >= 0; --i) {
            if (naf[i] != 0) {
                int step = (1 << i) * naf[i];
                if (step != N)
                    result = m_cc->EvalRotate(result, step);
            }
        }

        return result;
    }
};
