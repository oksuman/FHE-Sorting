#ifndef SORTER_H_
#define SORTER_H_

#include "SortUtils.h"
#include "openfhe.h"
#include "sign.h"
#include "comparison.h"
#include <memory>
#include <string>
#include <vector>

namespace kwaySort {

class Sorter : public SortUtils {
  public:
    Sorter() = default;

    Sorter(CryptoContext<DCRTPoly> cc, std::shared_ptr<Encryption> enc,
           long numSlots, long k, long M)
        : SortUtils(cc, enc, numSlots, k, M) {
        initLevels();
    }

    Sorter(CryptoContext<DCRTPoly> cc, std::shared_ptr<Encryption> enc,
           long numSlots, long k, long M,
           const PrivateKey<DCRTPoly> &privateKey,
           const PublicKey<DCRTPoly> &publicKey)
        : SortUtils(cc, enc, numSlots, k, M, privateKey, publicKey) {
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
                           Ciphertext<DCRTPoly> &ctxt_fix, SignConfig &Cfg);

    void comparisonForSort2(Ciphertext<DCRTPoly> &ctxt,
                            std::vector<std::vector<int>> &indices,
                            long logDist, long slope,
                            Ciphertext<DCRTPoly> &ctxt_comp1,
                            Ciphertext<DCRTPoly> &ctxt_comp2,
                            Ciphertext<DCRTPoly> &ctxt_fix, SignConfig &Cfg);

    // Main sorting function
    void sorter(Ciphertext<DCRTPoly> &ctxt, Ciphertext<DCRTPoly> &ctxt_out,
                SignConfig &Cfg);

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

    Comparison comp;
};

} // namespace kwaySort

#endif
