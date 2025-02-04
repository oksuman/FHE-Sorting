#ifndef SORTUTILS_H_
#define SORTUTILS_H_

#include "EvalUtils.h"
#include "Masking.h"
#include "encryption.h"
#include "openfhe.h"
#include <memory>
#include <string>
#include <vector>

using namespace lbcrypto;

namespace kwaySort {

class SortUtils : public EvalUtils {
  public:
    SortUtils() = default;

    SortUtils(CryptoContext<DCRTPoly> cc, std::shared_ptr<Encryption> enc,
              long numSlots, long k, long M)
        : EvalUtils(cc), m_numSlots(numSlots), m_k(k), m_M(M), m_enc(enc) {
        initializeLevels();
    }

    SortUtils(CryptoContext<DCRTPoly> cc, std::shared_ptr<Encryption> enc,
              long numSlots, long k, long M,
              const PrivateKey<DCRTPoly> &privateKey,
              const PublicKey<DCRTPoly> &publicKey)
        : EvalUtils(cc, enc, publicKey, privateKey), m_numSlots(numSlots),
          m_k(k), m_M(M), m_enc(enc) {
        initializeLevels();
    }

    // Core sorting functions
    void fcnL(Ciphertext<DCRTPoly> &ctxt1, Ciphertext<DCRTPoly> &ctxt2,
              Ciphertext<DCRTPoly> &comp, Ciphertext<DCRTPoly> &ctxt_out);

    void compareMax(Ciphertext<DCRTPoly> &ctxt1, Ciphertext<DCRTPoly> &ctxt2,
                    Ciphertext<DCRTPoly> &comp, Ciphertext<DCRTPoly> &ctxt_out);

    void compareMin(Ciphertext<DCRTPoly> &ctxt1, Ciphertext<DCRTPoly> &ctxt2,
                    Ciphertext<DCRTPoly> &comp, Ciphertext<DCRTPoly> &ctxt_out);

    // Multi-element sorters
    void twoSorter(Ciphertext<DCRTPoly> *ctxt, Ciphertext<DCRTPoly> &comp,
                   Ciphertext<DCRTPoly> *ctxt_out);

    void twoSorter(Ciphertext<DCRTPoly> &ctxt1, Ciphertext<DCRTPoly> &ctxt2,
                   Ciphertext<DCRTPoly> &comp, Ciphertext<DCRTPoly> *ctxt_out);

    void threeSorter(Ciphertext<DCRTPoly> *ctxt, Ciphertext<DCRTPoly> *comp,
                     Ciphertext<DCRTPoly> *ctxt_out);

    void fourSorter(Ciphertext<DCRTPoly> *ctxt, Ciphertext<DCRTPoly> *comp,
                    Ciphertext<DCRTPoly> *ctxt_out);

    void fiveSorter(Ciphertext<DCRTPoly> *ctxt, Ciphertext<DCRTPoly> *comp,
                    Ciphertext<DCRTPoly> *ctxt_out);

    // Slot management functions
    void slotMatching2(Ciphertext<DCRTPoly> &ctxt,
                       Ciphertext<DCRTPoly> &ctxt_comp,
                       std::vector<std::vector<int>> &indices, long shift,
                       Ciphertext<DCRTPoly> *ctxt_out,
                       Ciphertext<DCRTPoly> &ctxt_comp_out);

    void slotMatching3(Ciphertext<DCRTPoly> &ctxt,
                       Ciphertext<DCRTPoly> &ctxt_comp,
                       std::vector<std::vector<int>> &indices, long shift,
                       Ciphertext<DCRTPoly> *ctxt_out,
                       Ciphertext<DCRTPoly> *ctxt_comp_out);

    void slotMatching4(Ciphertext<DCRTPoly> &ctxt,
                       Ciphertext<DCRTPoly> &ctxt_comp1,
                       Ciphertext<DCRTPoly> &ctxt_comp2,
                       std::vector<std::vector<int>> &indices, long shift,
                       Ciphertext<DCRTPoly> *ctxt_out,
                       Ciphertext<DCRTPoly> *ctxt_comp_out);

    void slotMatching5(Ciphertext<DCRTPoly> &ctxt,
                       Ciphertext<DCRTPoly> &ctxt_comp1,
                       Ciphertext<DCRTPoly> &ctxt_comp2,
                       std::vector<std::vector<int>> &indices, long shift,
                       Ciphertext<DCRTPoly> *ctxt_out,
                       Ciphertext<DCRTPoly> *ctxt_comp_out);

    void slotMatching2345(Ciphertext<DCRTPoly> &ctxt,
                          Ciphertext<DCRTPoly> &ctxt_comp1,
                          Ciphertext<DCRTPoly> &ctxt_comp2,
                          std::vector<std::vector<int>> &indices, long shift,
                          Ciphertext<DCRTPoly> *ctxt_out,
                          Ciphertext<DCRTPoly> *ctxt_comp_out);

    void slotMatching23(Ciphertext<DCRTPoly> &ctxt,
                        Ciphertext<DCRTPoly> &ctxt_comp,
                        std::vector<std::vector<int>> &indices, long shift,
                        Ciphertext<DCRTPoly> *ctxt_out,
                        Ciphertext<DCRTPoly> *ctxt_comp_out);

    void slotAssemble(Ciphertext<DCRTPoly> *ctxt_sort, long num, long shift,
                      Ciphertext<DCRTPoly> &ctxt_out);

  protected:
    void initializeLevels() {
        m_level.resize(6);
        m_level[2] = 2;
        m_level[3] = 3;
        m_level[4] = 4;
        m_level[5] = 6;
    }

    long m_numSlots;
    long m_k;
    long m_M;
    std::vector<int> m_level;
    std::shared_ptr<Encryption> m_enc;
};

} // namespace kwaySort

#endif
