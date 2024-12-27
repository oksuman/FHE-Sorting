#ifndef SORTER_H_
#define SORTER_H_

#include "SortUtils.h"
#include "openfhe.h"
#include <memory>
#include <string>
#include <vector>

namespace kwaySort {

class Sorter : public SortUtils {
  public:
    Sorter() = default;

    Sorter(CryptoContext<DCRTPoly> cc, std::shared_ptr<Encryption> enc,
           long numSlots, long k, long M, long d_f, long d_g)
        : SortUtils(cc, enc, numSlots, k, M), m_d_f(d_f), m_d_g(d_g) {
        initLevels();
    }

    Sorter(CryptoContext<DCRTPoly> cc, std::shared_ptr<Encryption> enc,
           long numSlots, long k, long M, long d_f, long d_g,
           const PrivateKey<DCRTPoly> &privateKey,
           const PublicKey<DCRTPoly> &publicKey)
        : SortUtils(cc, enc, numSlots, k, M, privateKey, publicKey), m_d_f(d_f),
          m_d_g(d_g) {
        initLevels();
    }

    // Core sorting functions
    void runTwoSorter(Ciphertext<DCRTPoly> &ctxt,
                      std::vector<std::vector<int>> &indices, long shift,
                      Ciphertext<DCRTPoly> &ctxt_comp,
                      Ciphertext<DCRTPoly> &ctxt_out);

    void runThreeSorter(Ciphertext<DCRTPoly> &ctxt,
                        std::vector<std::vector<int>> &indices, long shift,
                        Ciphertext<DCRTPoly> &ctxt_comp,
                        Ciphertext<DCRTPoly> &ctxt_out);

    void runFourSorter(Ciphertext<DCRTPoly> &ctxt,
                       std::vector<std::vector<int>> &indices, long shift,
                       Ciphertext<DCRTPoly> &ctxt_comp1,
                       Ciphertext<DCRTPoly> &ctxt_comp2,
                       Ciphertext<DCRTPoly> &ctxt_out);

    void runFiveSorter(Ciphertext<DCRTPoly> &ctxt,
                       std::vector<std::vector<int>> &indices, long shift,
                       Ciphertext<DCRTPoly> &ctxt_comp1,
                       Ciphertext<DCRTPoly> &ctxt_comp2,
                       Ciphertext<DCRTPoly> &ctxt_out);

    void run2345Sorter(Ciphertext<DCRTPoly> &ctxt,
                       std::vector<std::vector<int>> &indices, long shift,
                       Ciphertext<DCRTPoly> &ctxt_comp1,
                       Ciphertext<DCRTPoly> &ctxt_comp2,
                       Ciphertext<DCRTPoly> &ctxt_out);

    // Rotation and comparison functions
    void rightRotateForSort(Ciphertext<DCRTPoly> &ctxt,
                            std::vector<std::vector<int>> &indices,
                            long logDist, long slope,
                            Ciphertext<DCRTPoly> &ctxt_rot,
                            Ciphertext<DCRTPoly> &ctxt_fix);

    void comparisonForSort(Ciphertext<DCRTPoly> &ctxt,
                           std::vector<std::vector<int>> &indices, long logDist,
                           long slope, Ciphertext<DCRTPoly> &ctxt_comp,
                           Ciphertext<DCRTPoly> &ctxt_fix);

    void comparisonForSort2(Ciphertext<DCRTPoly> &ctxt,
                            std::vector<std::vector<int>> &indices,
                            long logDist, long slope,
                            Ciphertext<DCRTPoly> &ctxt_comp1,
                            Ciphertext<DCRTPoly> &ctxt_comp2,
                            Ciphertext<DCRTPoly> &ctxt_fix);

    // Main sorting function
    void sorter(Ciphertext<DCRTPoly> &ctxt, Ciphertext<DCRTPoly> &ctxt_out);

  protected:
    void initLevels() {
        m_level.resize(6);
        m_level[0] = 0;
        m_level[1] = 1;
        m_level[2] = 3;
        m_level[3] = 5;
        m_level[4] = 6;
        m_level[5] = 7;
    }

    long m_d_f; // Depth parameter for F function
    long m_d_g; // Depth parameter for G function
};

} // namespace kwaySort

#endif
