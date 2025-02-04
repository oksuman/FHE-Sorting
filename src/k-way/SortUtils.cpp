#include "SortUtils.h"

namespace kwaySort {

void SortUtils::fcnL(Ciphertext<DCRTPoly> &ctxt1, Ciphertext<DCRTPoly> &ctxt2,
                     Ciphertext<DCRTPoly> &comp,
                     Ciphertext<DCRTPoly> &ctxt_out) {
    /*
        input : a, b, comp = (a > b)
        output : (a > b) * a + (a < b) * b
                = (a > b) * (a - b) + b
    */
    auto diff = m_cc->EvalSub(ctxt1, ctxt2);
    auto weighted = m_cc->EvalMult(diff, comp);
    ctxt_out = m_cc->EvalAdd(weighted, ctxt2);
}

void SortUtils::compareMax(Ciphertext<DCRTPoly> &ctxt1,
                           Ciphertext<DCRTPoly> &ctxt2,
                           Ciphertext<DCRTPoly> &comp,
                           Ciphertext<DCRTPoly> &ctxt_out) {
    fcnL(ctxt1, ctxt2, comp, ctxt_out);
}

void SortUtils::compareMin(Ciphertext<DCRTPoly> &ctxt1,
                           Ciphertext<DCRTPoly> &ctxt2,
                           Ciphertext<DCRTPoly> &comp,
                           Ciphertext<DCRTPoly> &ctxt_out) {
    fcnL(ctxt2, ctxt1, comp, ctxt_out);
}

void SortUtils::twoSorter(Ciphertext<DCRTPoly> *ctxt,
                          Ciphertext<DCRTPoly> &comp,
                          Ciphertext<DCRTPoly> *ctxt_out) {
    /*
        input:
            ctxt = [a, b]
            ctxt_comp = [(a > b)]
        output:
            [min(a,b), max(a,b)]
    */
    fcnL(ctxt[0], ctxt[1], comp, ctxt_out[1]);
    auto sum = m_cc->EvalAdd(ctxt[0], ctxt[1]);
    ctxt_out[0] = m_cc->EvalSub(sum, ctxt_out[1]);
}

void SortUtils::twoSorter(Ciphertext<DCRTPoly> &ctxt0,
                          Ciphertext<DCRTPoly> &ctxt1,
                          Ciphertext<DCRTPoly> &comp,
                          Ciphertext<DCRTPoly> *ctxt_out) {
    fcnL(ctxt0, ctxt1, comp, ctxt_out[1]);
    auto sum = m_cc->EvalAdd(ctxt0, ctxt1);
    ctxt_out[0] = m_cc->EvalSub(sum, ctxt_out[1]);
}

void SortUtils::threeSorter(Ciphertext<DCRTPoly> *ctxt,
                            Ciphertext<DCRTPoly> *ctxt_comp,
                            Ciphertext<DCRTPoly> *ctxt_sort) {
    /*
        input:
            ctxt = [a, b, c]
            ctxt_comp = [(a > b), (a > c), (b > c)]
        output:
            [min, middle, max]
    */
    Ciphertext<DCRTPoly> ctxt_Mm1[2], ctxt_Mm1vsC[2];

    twoSorter(ctxt[0], ctxt[1], ctxt_comp[0], ctxt_Mm1);
    twoSorter(ctxt_comp[1], ctxt_comp[2], ctxt_comp[0], ctxt_Mm1vsC);

    compareMax(ctxt_Mm1[1], ctxt[2], ctxt_Mm1vsC[1], ctxt_sort[2]);
    compareMin(ctxt_Mm1[0], ctxt[2], ctxt_Mm1vsC[0], ctxt_sort[0]);

    auto sum = m_cc->EvalAdd(ctxt[0], ctxt[1]);
    sum = m_cc->EvalAdd(sum, ctxt[2]);
    ctxt_sort[1] = m_cc->EvalSub(sum, ctxt_sort[0]);
    ctxt_sort[1] = m_cc->EvalSub(ctxt_sort[1], ctxt_sort[2]);
}

void SortUtils::fourSorter(Ciphertext<DCRTPoly> *ctxt,
                           Ciphertext<DCRTPoly> *ctxt_comp,
                           Ciphertext<DCRTPoly> *ctxt_sort) {
    /*
        input:
            ctxt = [a, b, c, d]
            ctxt_comp = [(a > b), (a > c), (a > d), (b > c), (b > d), (c > d)]
    */
    Ciphertext<DCRTPoly> ctxtMm1[2];
    Ciphertext<DCRTPoly> ctxtMm2[2];
    Ciphertext<DCRTPoly> ctxt_ab[2] = {ctxt[0], ctxt[1]};
    Ciphertext<DCRTPoly> ctxt_cd[2] = {ctxt[2], ctxt[3]};

    // First level sorting
    twoSorter(ctxt_ab, ctxt_comp[0], ctxtMm1);
    twoSorter(ctxt_cd, ctxt_comp[5], ctxtMm2);

    // Compare results
    Ciphertext<DCRTPoly> Mm1vsC[2];
    Ciphertext<DCRTPoly> Mm1vsD[2];
    twoSorter(ctxt_comp[1], ctxt_comp[3], ctxt_comp[0], Mm1vsC);
    twoSorter(ctxt_comp[2], ctxt_comp[4], ctxt_comp[0], Mm1vsD);

    Ciphertext<DCRTPoly> M1vsMm2[2], m1vsMm2[2];
    twoSorter(Mm1vsC[1], Mm1vsD[1], ctxt_comp[5], M1vsMm2);
    twoSorter(Mm1vsC[0], Mm1vsD[0], ctxt_comp[5], m1vsMm2);

    // Find max
    compareMax(ctxtMm1[1], ctxtMm2[1], M1vsMm2[1], ctxt_sort[3]);

    // Find second max
    Ciphertext<DCRTPoly> left, right;
    compareMax(ctxtMm1[0], ctxtMm2[1], m1vsMm2[1], left);
    compareMax(ctxtMm1[1], ctxtMm2[0], M1vsMm2[0], right);
    compareMax(left, right, M1vsMm2[1], ctxt_sort[2]);

    // Find min
    compareMin(ctxtMm1[0], ctxtMm2[0], m1vsMm2[0], ctxt_sort[0]);

    // Find second min by subtraction
    ctxt_sort[1] = ctxt[0];
    for (int i = 1; i < 4; i++) {
        ctxt_sort[1] = m_cc->EvalAdd(ctxt_sort[1], ctxt[i]);
    }
    for (int i = 0; i < 4; i++) {
        if (i != 1) {
            ctxt_sort[1] = m_cc->EvalSub(ctxt_sort[1], ctxt_sort[i]);
        }
    }
}

void SortUtils::fiveSorter(Ciphertext<DCRTPoly> *ctxt,
                           Ciphertext<DCRTPoly> *ctxt_comp,
                           Ciphertext<DCRTPoly> *ctxt_sort) {
    /*
        input:
            ctxt = [a b c d e]
            ctxt_comp = [a>b a>c a>d a>e b>c b>d b>e c>d c>e d>e]
    */
    Ciphertext<DCRTPoly> ctxtABC[3] = {ctxt[0], ctxt[1], ctxt[2]};
    Ciphertext<DCRTPoly> ctxtABC_comp[3] = {ctxt_comp[0], ctxt_comp[1],
                                            ctxt_comp[4]};
    Ciphertext<DCRTPoly> ctxtABC_sort[3];

    threeSorter(ctxtABC, ctxtABC_comp, ctxtABC_sort);

    Ciphertext<DCRTPoly> ctxtDE_sort[2];
    twoSorter(ctxt[3], ctxt[4], ctxt_comp[9], ctxtDE_sort);

    // Prepare comparisons
    Ciphertext<DCRTPoly> ctxtABCvsD[3] = {ctxt_comp[2], ctxt_comp[5],
                                          ctxt_comp[7]};
    Ciphertext<DCRTPoly> ctxtABCvsD_sort[3];
    threeSorter(ctxtABCvsD, ctxtABC_comp, ctxtABCvsD_sort);

    Ciphertext<DCRTPoly> ctxtABCvsE[3] = {ctxt_comp[3], ctxt_comp[6],
                                          ctxt_comp[8]};
    Ciphertext<DCRTPoly> ctxtABCvsE_sort[3];
    threeSorter(ctxtABCvsE, ctxtABC_comp, ctxtABCvsE_sort);

    // Comparison results
    Ciphertext<DCRTPoly> ctxtM1vsMm2[2];
    twoSorter(ctxtABCvsD_sort[2], ctxtABCvsE_sort[2], ctxt_comp[9],
              ctxtM1vsMm2);

    Ciphertext<DCRTPoly> ctxtD1vsMm2[2];
    twoSorter(ctxtABCvsD_sort[1], ctxtABCvsE_sort[1], ctxt_comp[9],
              ctxtD1vsMm2);

    Ciphertext<DCRTPoly> ctxtm1vsMm2[2];
    twoSorter(ctxtABCvsD_sort[0], ctxtABCvsE_sort[0], ctxt_comp[9],
              ctxtm1vsMm2);

    // Find max (5th element)
    compareMax(ctxtABC_sort[2], ctxtDE_sort[1], ctxtM1vsMm2[1], ctxt_sort[4]);

    // Find min (1st element)
    compareMin(ctxtABC_sort[0], ctxtDE_sort[0], ctxtm1vsMm2[0], ctxt_sort[0]);

    // Find second max (4th element)
    Ciphertext<DCRTPoly> left, right;
    compareMax(ctxtABC_sort[1], ctxtDE_sort[1], ctxtD1vsMm2[1], left);
    compareMax(ctxtABC_sort[2], ctxtDE_sort[0], ctxtM1vsMm2[0], right);
    compareMax(left, right, ctxtM1vsMm2[1], ctxt_sort[3]);

    // Find second min (2nd element)
    compareMin(ctxtABC_sort[1], ctxtDE_sort[0], ctxtD1vsMm2[0], left);
    compareMin(ctxtABC_sort[0], ctxtDE_sort[1], ctxtm1vsMm2[1], right);
    compareMin(left, right, ctxtm1vsMm2[0], ctxt_sort[1]);

    // Find middle element (3rd element) by subtraction
    ctxt_sort[2] = ctxt[0];
    for (int i = 1; i < 5; i++) {
        ctxt_sort[2] = m_cc->EvalAdd(ctxt_sort[2], ctxt[i]);
    }
    for (int i = 0; i < 5; i++) {
        if (i != 2) {
            ctxt_sort[2] = m_cc->EvalSub(ctxt_sort[2], ctxt_sort[i]);
        }
    }
}

void SortUtils::slotMatching2(Ciphertext<DCRTPoly> &ctxt,
                              Ciphertext<DCRTPoly> &ctxt_comp,
                              std::vector<std::vector<int>> &indices,
                              long shift, Ciphertext<DCRTPoly> *ctxt_out,
                              Ciphertext<DCRTPoly> &ctxt_comp_out) {
    ctxt_out[0] = ctxt;
    leftRotate(ctxt, shift, ctxt_out[1]);
    ctxt_comp_out = ctxt_comp;
}

void SortUtils::slotMatching3(Ciphertext<DCRTPoly> &ctxt,
                              Ciphertext<DCRTPoly> &ctxt_comp,
                              std::vector<std::vector<int>> &indices,
                              long shift, Ciphertext<DCRTPoly> *ctxt_out,
                              Ciphertext<DCRTPoly> *ctxt_comp_out) {
    std::vector<double> mask3(m_numSlots, 0.0);
    for (int i = 0; i < m_numSlots; i++) {
        if (indices[0][i] == 3 && indices[1][i] == 1)
            mask3[i] = 1.0;
    }
    auto mask3Plain = m_cc->MakeCKKSPackedPlaintext(mask3);

    // Rotate for each position
    for (int i = 0; i < 3; i++) {
        leftRotate(ctxt, i * shift, ctxt_out[i]);
    }

    // Handle comparisons
    ctxt_comp_out[1] = ctxt_comp;
    leftRotate(ctxt_comp, shift, ctxt_comp_out[0]);
    leftRotate(ctxt_comp, 2 * shift, ctxt_comp_out[2]);

    // Flip necessary comparisons
    flipCtxt(ctxt_comp_out[0], mask3Plain);
    flipCtxt(ctxt_comp_out[2], mask3Plain);
}

void SortUtils::slotMatching4(Ciphertext<DCRTPoly> &ctxt,
                              Ciphertext<DCRTPoly> &ctxt_comp1,
                              Ciphertext<DCRTPoly> &ctxt_comp2,
                              std::vector<std::vector<int>> &indices,
                              long shift, Ciphertext<DCRTPoly> *ctxt_arr,
                              Ciphertext<DCRTPoly> *ctxt_comp_arr) {
    // Generate masks for each position
    std::vector<std::vector<double>> mask4(
        4, std::vector<double>(m_numSlots, 0.0));
    for (int k = 0; k < 4; k++) {
        genMask(indices, 4, k + 1, mask4[k]);
    }
    auto mask4Plains = std::vector<Plaintext>(4);
    for (int k = 0; k < 4; k++) {
        mask4Plains[k] = m_cc->MakeCKKSPackedPlaintext(mask4[k]);
    }

    // Make ctxt_comp_arr = { (a > b), (a > c), (a > d), (b > c), (b > d), (c >
    // d) }
    ctxt_comp_arr[2] = m_cc->EvalMult(ctxt_comp1, mask4Plains[0]); // a > b
    ctxt_comp_arr[0] = m_cc->EvalMult(ctxt_comp1, mask4Plains[1]); // a > c
    ctxt_comp_arr[3] = m_cc->EvalMult(ctxt_comp1, mask4Plains[2]); // a > d
    ctxt_comp_arr[5] = m_cc->EvalMult(ctxt_comp1, mask4Plains[3]); // b > c
    ctxt_comp_arr[1] = m_cc->EvalMult(ctxt_comp2, mask4Plains[0]); // b > d
    ctxt_comp_arr[4] = m_cc->EvalMult(ctxt_comp2, mask4Plains[1]); // c > d

    // Copy and rotate comparisons
    ctxt_comp_arr[2] = ctxt_comp1;                       // original a > b
    leftRotate(ctxt_comp1, 1 * shift, ctxt_comp_arr[0]); // rotate for a > c
    leftRotate(ctxt_comp1, 2 * shift, ctxt_comp_arr[3]); // rotate for a > d
    leftRotate(ctxt_comp1, 3 * shift, ctxt_comp_arr[5]); // rotate for b > c

    ctxt_comp_arr[1] = ctxt_comp2;                       // original b > d
    leftRotate(ctxt_comp2, 1 * shift, ctxt_comp_arr[4]); // rotate for c > d

    // Flip necessary comparisons
    flipCtxt(ctxt_comp_arr[0], mask4Plains[0]);
    flipCtxt(ctxt_comp_arr[3], mask4Plains[0]);
    flipCtxt(ctxt_comp_arr[5], mask4Plains[0]);

    // Handle input array rotations
    for (int i = 0; i < 4; i++) {
        leftRotate(ctxt, i * shift, ctxt_arr[i]);
        ctxt_arr[i] = m_cc->EvalMult(ctxt_arr[i], mask4Plains[0]);
    }
}

void SortUtils::slotMatching5(Ciphertext<DCRTPoly> &ctxt,
                              Ciphertext<DCRTPoly> &ctxt_comp1,
                              Ciphertext<DCRTPoly> &ctxt_comp2,
                              std::vector<std::vector<int>> &indices,
                              long shift, Ciphertext<DCRTPoly> *ctxt_arr,
                              Ciphertext<DCRTPoly> *ctxt_comp_arr) {
    // Create mask for 5-position elements
    std::vector<double> mask5(m_numSlots, 0.0);
    for (int i = 0; i < m_numSlots; i++) {
        if (indices[0][i] == 5 && indices[1][i] == 1)
            mask5[i] = 1.0;
    }
    auto mask5Plain = m_cc->MakeCKKSPackedPlaintext(mask5);

    // Rotate input array for each position
    for (int i = 0; i < 5; i++) {
        leftRotate(ctxt, i * shift, ctxt_arr[i]);
    }

    // Handle first set of comparisons from ctxt_comp1
    ctxt_comp_arr[3] = ctxt_comp1;                       // a>e
    leftRotate(ctxt_comp1, shift, ctxt_comp_arr[0]);     // a>b
    leftRotate(ctxt_comp1, 2 * shift, ctxt_comp_arr[4]); // b>c
    leftRotate(ctxt_comp1, 3 * shift, ctxt_comp_arr[7]); // c>d
    leftRotate(ctxt_comp1, 4 * shift, ctxt_comp_arr[9]); // d>e

    // Handle second set of comparisons from ctxt_comp2
    ctxt_comp_arr[2] = ctxt_comp2;                       // a>d
    leftRotate(ctxt_comp2, shift, ctxt_comp_arr[6]);     // b>e
    leftRotate(ctxt_comp2, 2 * shift, ctxt_comp_arr[1]); // a>c
    leftRotate(ctxt_comp2, 3 * shift, ctxt_comp_arr[5]); // b>d
    leftRotate(ctxt_comp2, 4 * shift, ctxt_comp_arr[8]); // c>e

    // Flip necessary comparison results
    for (int i : {0, 1, 4, 5, 7, 8, 9}) {
        flipCtxt(ctxt_comp_arr[i], mask5Plain);
    }
}

void SortUtils::slotMatching2345(Ciphertext<DCRTPoly> &ctxt,
                                 Ciphertext<DCRTPoly> &ctxt_comp1,
                                 Ciphertext<DCRTPoly> &ctxt_comp2,
                                 std::vector<std::vector<int>> &indices,
                                 long shift, Ciphertext<DCRTPoly> *ctxt_arr,
                                 Ciphertext<DCRTPoly> *ctxt_comp_arr) {
    // Rotate input array for each position
    for (int i = 0; i < 5; i++) {
        leftRotate(ctxt, i * shift, ctxt_arr[i]);
    }

    // Create required masks
    std::vector<double> mask2345(m_numSlots, 0.0);
    std::vector<double> mask45(m_numSlots, 0.0);
    std::vector<double> mask345(m_numSlots, 0.0);
    std::vector<double> mask3(m_numSlots, 0.0);
    std::vector<double> mask4(m_numSlots, 0.0);
    std::vector<double> mask5(m_numSlots, 0.0);

    for (int i = 0; i < m_numSlots; i++) {
        if (indices[0][i] == 2 && indices[1][i] == 1) {
            mask2345[i] = 1.0;
        }
        if (indices[0][i] == 3 && indices[1][i] == 1) {
            mask2345[i] = 1.0;
            mask345[i] = 1.0;
            mask3[i] = 1.0;
        }
        if (indices[0][i] == 4 && indices[1][i] == 1) {
            mask2345[i] = 1.0;
            mask345[i] = 1.0;
            mask45[i] = 1.0;
            mask4[i] = 1.0;
        }
        if (indices[0][i] == 5 && indices[1][i] == 1) {
            mask2345[i] = 1.0;
            mask345[i] = 1.0;
            mask45[i] = 1.0;
            mask5[i] = 1.0;
        }
    }

    // Convert masks to plaintexts
    auto mask2345Plain = m_cc->MakeCKKSPackedPlaintext(mask2345);
    auto mask45Plain = m_cc->MakeCKKSPackedPlaintext(mask45);
    auto mask345Plain = m_cc->MakeCKKSPackedPlaintext(mask345);
    auto mask3Plain = m_cc->MakeCKKSPackedPlaintext(mask3);
    auto mask4Plain = m_cc->MakeCKKSPackedPlaintext(mask4);
    auto mask5Plain = m_cc->MakeCKKSPackedPlaintext(mask5);

    // a > b
    leftRotate(ctxt_comp1, shift, ctxt_comp_arr[0]);
    flipCtxt(ctxt_comp_arr[0], mask2345Plain);

    // a > c
    auto tmp = m_cc->EvalMult(ctxt_comp1, mask3Plain);
    auto tmp2 = ctxt_comp2->Clone();
    leftRotate(tmp2, 2 * shift, tmp2);
    tmp2 = m_cc->EvalMult(tmp2, mask45Plain);
    flipCtxt(tmp2, mask45Plain);
    ctxt_comp_arr[1] = m_cc->EvalAdd(tmp, tmp2);

    // a > d
    ctxt_comp_arr[2] = m_cc->EvalMult(ctxt_comp1, mask4Plain);
    tmp = m_cc->EvalMult(ctxt_comp2, mask5Plain);
    ctxt_comp_arr[2] = m_cc->EvalAdd(ctxt_comp_arr[2], tmp);

    // a > e
    ctxt_comp_arr[3] = m_cc->EvalMult(ctxt_comp1, mask5Plain);

    // b > c
    leftRotate(ctxt_comp1, 2 * shift, ctxt_comp_arr[4]);
    ctxt_comp_arr[4] = m_cc->EvalMult(ctxt_comp_arr[4], mask345Plain);
    flipCtxt(ctxt_comp_arr[4], mask345Plain);

    // b > d
    leftRotate(ctxt_comp2, 3 * shift, ctxt_comp_arr[5]);
    ctxt_comp_arr[5] = m_cc->EvalMult(ctxt_comp_arr[5], mask45Plain);
    flipCtxt(ctxt_comp_arr[5], mask45Plain);

    // b > e
    leftRotate(ctxt_comp2, shift, ctxt_comp_arr[6]);
    ctxt_comp_arr[6] = m_cc->EvalMult(ctxt_comp_arr[6], mask5Plain);

    // c > d
    leftRotate(ctxt_comp1, 3 * shift, ctxt_comp_arr[7]);
    ctxt_comp_arr[7] = m_cc->EvalMult(ctxt_comp_arr[7], mask45Plain);
    flipCtxt(ctxt_comp_arr[7], mask45Plain);

    // c > e
    leftRotate(ctxt_comp2, 4 * shift, ctxt_comp_arr[8]);
    ctxt_comp_arr[8] = m_cc->EvalMult(ctxt_comp_arr[8], mask5Plain);
    flipCtxt(ctxt_comp_arr[8], mask5Plain);

    // d > e
    leftRotate(ctxt_comp1, 4 * shift, ctxt_comp_arr[9]);
    ctxt_comp_arr[9] = m_cc->EvalMult(ctxt_comp_arr[9], mask5Plain);
    flipCtxt(ctxt_comp_arr[9], mask5Plain);
}

void SortUtils::slotAssemble(Ciphertext<DCRTPoly> *ctxt_sort, long num,
                             long shift, Ciphertext<DCRTPoly> &ctxt_out) {
    ctxt_out = ctxt_sort[0];
    for (int i = 1; i < num; i++) {
        Ciphertext<DCRTPoly> rotated;
        rightRotate(ctxt_sort[i], i * shift, rotated);
        ctxt_out = m_cc->EvalAdd(ctxt_out, rotated);
    }
}

} // namespace kwaySort
