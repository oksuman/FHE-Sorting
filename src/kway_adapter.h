#ifndef KWAY_ADAPTER_H
#define KWAY_ADAPTER_H

#include "k-way/Sorter.h"
#include "key/privatekey-fwd.h"
#include "sort_algo.h"
#include <memory>

constexpr int next_power_of_two(int n) {
    if (n <= 0)
        return 1;

    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;

    return n + 1;
}

template <int N> class KWayAdapter : public SortBase<N> {
  private:
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    std::shared_ptr<Encryption> m_enc;
    std::unique_ptr<kwaySort::Sorter> m_sorter;
    int m_multDepth;

  public:
    KWayAdapter(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey,
                PrivateKey<DCRTPoly> privateKey,
                std::shared_ptr<Encryption> enc, int k, int M)
        : SortBase<N>(enc), m_cc(cc), m_PublicKey(publicKey), m_enc(enc) {
        assert(std::pow(k, M) == N && "k^M should be equal to input length N");
        m_sorter = std::make_unique<kwaySort::Sorter>(cc, enc, N, k, M,
                                                      privateKey, publicKey);
    }

    static void getSizeParameters(CCParams<CryptoContextCKKSRNS> &parameters,
                                  std::vector<int> &rotations,
                                  std::vector<uint32_t> &levelBudget) {
        parameters.SetBatchSize(next_power_of_two(N));
        parameters.SetFirstModSize(60);
        parameters.SetScalingModSize(59);

        // Generate rotation indices needed for K-way sorting
        for (int i = 1; i < N; i *= 2) {
            rotations.push_back(i);
            rotations.push_back(-i);
        }

        // Set multiplicative depth based on array size
        int multDepth = 40;
        if (N <= 128) {
            levelBudget = {4, 4};
            // multDepth = 44;
        } else {
            levelBudget = {5, 5};
            // multDepth = 44;
        }
        parameters.SetMultiplicativeDepth(multDepth);
    }

    Ciphertext<DCRTPoly> sort(const Ciphertext<DCRTPoly> &input_array,
                              SignFunc signFunc, SignConfig &Cfg) override {
        Ciphertext<DCRTPoly> result;
        Ciphertext<DCRTPoly> input_copy = input_array->Clone();
        m_sorter->sorter(input_copy, result, Cfg);
        return result;
    }
};

#endif // KWAY_ADAPTER_H
