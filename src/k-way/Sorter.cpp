#include "Sorter.h"
#include "sign.h"
#include <vector>

namespace kwaySort {

void Sorter::runTwoSorter(Ciphertext<DCRTPoly> &ctxt,
                          std::vector<std::vector<int>> &indices, long shift,
                          Ciphertext<DCRTPoly> &ctxt_comp,
                          Ciphertext<DCRTPoly> &ctxt_out) {
    // Generate mask for 2-way sort
    std::vector<double> mask2(m_numSlots, 0.0);
    for (size_t i = 0; i < indices[0].size(); i++) {
        if (indices[0][i] == 2 && indices[1][i] == 1) {
            mask2[i] = 1.0;
        }
    }
    auto mask2Plain = m_cc->MakeCKKSPackedPlaintext(mask2);

    // Get slots for sorting
    Ciphertext<DCRTPoly> ctxt_slots[2], ctxt_comp_slots;
    slotMatching2(ctxt, ctxt_comp, indices, shift, ctxt_slots, ctxt_comp_slots);

    // Sort the slots
    Ciphertext<DCRTPoly> ctxt_sort[2];
    twoSorter(ctxt_slots, ctxt_comp, ctxt_sort);

    // Apply mask
    for (int i = 0; i < 2; i++) {
        ctxt_sort[i] = m_cc->EvalMult(ctxt_sort[i], mask2Plain);
    }

    // Rotate and combine results
    Ciphertext<DCRTPoly> rotated;
    rightRotate(ctxt_sort[1], shift, rotated);
    ctxt_out = m_cc->EvalAdd(ctxt_sort[0], rotated);
}

void Sorter::runThreeSorter(Ciphertext<DCRTPoly> &ctxt,
                            std::vector<std::vector<int>> &indices, long shift,
                            Ciphertext<DCRTPoly> &ctxt_comp,
                            Ciphertext<DCRTPoly> &ctxt_out) {
    // Generate mask for 3-way sort
    std::vector<double> mask3(m_numSlots, 0.0);
    genMask(indices, 3, 1, mask3);
    auto mask3Plain = m_cc->MakeCKKSPackedPlaintext(mask3);

    // Get slots and comparisons
    Ciphertext<DCRTPoly> ctxt_arr[3], ctxt_comp_arr[3];
    slotMatching3(ctxt, ctxt_comp, indices, shift, ctxt_arr, ctxt_comp_arr);

    // Sort the slots
    Ciphertext<DCRTPoly> ctxt_sort[3];
    threeSorter(ctxt_arr, ctxt_comp_arr, ctxt_sort);

    // Apply mask to results
    for (int i = 0; i < 3; i++) {
        ctxt_sort[i] = m_cc->EvalMult(ctxt_sort[i], mask3Plain);
    }

    // Rotate and combine results
    Ciphertext<DCRTPoly> rotated1, rotated2;
    rightRotate(ctxt_sort[1], shift, rotated1);
    rightRotate(ctxt_sort[2], 2 * shift, rotated2);

    ctxt_out = m_cc->EvalAdd(ctxt_sort[0], rotated1);
    ctxt_out = m_cc->EvalAdd(ctxt_out, rotated2);
}

void Sorter::runFourSorter(Ciphertext<DCRTPoly> &ctxt,
                           std::vector<std::vector<int>> &indices, long shift,
                           Ciphertext<DCRTPoly> &ctxt_comp1,
                           Ciphertext<DCRTPoly> &ctxt_comp2,
                           Ciphertext<DCRTPoly> &ctxt_out) {
    // Get slots and comparison results
    Ciphertext<DCRTPoly> ctxt_arr[4], ctxt_comp_arr[6];
    slotMatching4(ctxt, ctxt_comp1, ctxt_comp2, indices, shift, ctxt_arr,
                  ctxt_comp_arr);

    // Sort the slots
    Ciphertext<DCRTPoly> ctxt_sort[4];
    fourSorter(ctxt_arr, ctxt_comp_arr, ctxt_sort);

    // Combine results
    slotAssemble(ctxt_sort, 4, shift, ctxt_out);
}

void Sorter::runFiveSorter(Ciphertext<DCRTPoly> &ctxt,
                           std::vector<std::vector<int>> &indices, long shift,
                           Ciphertext<DCRTPoly> &ctxt_comp1,
                           Ciphertext<DCRTPoly> &ctxt_comp2,
                           Ciphertext<DCRTPoly> &ctxt_out) {
    // Generate mask for 5-way sort
    std::vector<double> mask5(m_numSlots, 0.0);
    for (size_t i = 0; i < indices[0].size(); i++) {
        if (indices[0][i] == 5 && indices[1][i] == 1) {
            mask5[i] = 1.0;
        }
    }
    auto mask5Plain = m_cc->MakeCKKSPackedPlaintext(mask5);

    // Get slots and comparison results
    Ciphertext<DCRTPoly> ctxt_arr[5], ctxt_comp_arr[10];
    slotMatching5(ctxt, ctxt_comp1, ctxt_comp2, indices, shift, ctxt_arr,
                  ctxt_comp_arr);

    // Sort the slots
    Ciphertext<DCRTPoly> ctxt_sort[5];
    fiveSorter(ctxt_arr, ctxt_comp_arr, ctxt_sort);

    // Apply mask to results
    for (int i = 0; i < 5; i++) {
        ctxt_sort[i] = m_cc->EvalMult(ctxt_sort[i], mask5Plain);
    }

    // Combine results
    slotAssemble(ctxt_sort, 5, shift, ctxt_out);
}

void Sorter::run2345Sorter(Ciphertext<DCRTPoly> &ctxt,
                           std::vector<std::vector<int>> &indices, long shift,
                           Ciphertext<DCRTPoly> &ctxt_comp1,
                           Ciphertext<DCRTPoly> &ctxt_comp2,
                           Ciphertext<DCRTPoly> &ctxt_out) {
    // Create masks for each size
    std::vector<double> mask2345(m_numSlots, 0.0), mask45(m_numSlots, 0.0),
        mask345(m_numSlots, 0.0), mask3(m_numSlots, 0.0),
        mask4(m_numSlots, 0.0), mask5(m_numSlots, 0.0);

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

    auto mask2345Plain = m_cc->MakeCKKSPackedPlaintext(mask2345);
    auto mask45Plain = m_cc->MakeCKKSPackedPlaintext(mask45);
    auto mask345Plain = m_cc->MakeCKKSPackedPlaintext(mask345);
    auto mask3Plain = m_cc->MakeCKKSPackedPlaintext(mask3);
    auto mask5Plain = m_cc->MakeCKKSPackedPlaintext(mask5);

    // Get slots and comparison results
    Ciphertext<DCRTPoly> ctxt_arr[5], ctxt_comp_arr[10];
    slotMatching2345(ctxt, ctxt_comp1, ctxt_comp2, indices, shift, ctxt_arr,
                     ctxt_comp_arr);

    // Sort the slots
    Ciphertext<DCRTPoly> ctxt_sort[5];
    fiveSorter(ctxt_arr, ctxt_comp_arr, ctxt_sort);

    // Apply appropriate masks
    ctxt_sort[0] = m_cc->EvalMult(ctxt_sort[0], mask2345Plain);
    ctxt_sort[1] = m_cc->EvalMult(ctxt_sort[1], mask2345Plain);
    ctxt_sort[2] = m_cc->EvalMult(ctxt_sort[2], mask345Plain);
    ctxt_sort[3] = m_cc->EvalMult(ctxt_sort[3], mask45Plain);
    ctxt_sort[4] = m_cc->EvalMult(ctxt_sort[4], mask5Plain);

    // Combine results
    slotAssemble(ctxt_sort, 5, shift, ctxt_out);
}

void Sorter::rightRotateForSort(Ciphertext<DCRTPoly> &ctxt,
                                std::vector<std::vector<int>> &indices,
                                long logDist, long slope,
                                Ciphertext<DCRTPoly> &ctxt_rot,
                                Ciphertext<DCRTPoly> &ctxt_fix) {
    // Create mask vectors
    std::vector<double> maskLeft(m_numSlots, 0.0);
    std::vector<std::vector<double>> maskRight(
        m_k, std::vector<double>(m_numSlots, 0.0));

    for (int i = 0; i < m_numSlots; i++) {
        if (indices[1][i] < indices[0][i]) {
            maskLeft[i] = 1.0;
        }
        if (indices[0][i] > 0 && indices[0][i] == indices[1][i]) {
            maskRight[indices[0][i] - 1][i] = 1.0;
        }
    }

    // long dist = pow(m_k, logDist);
    auto maskLeftPlain = m_cc->MakeCKKSPackedPlaintext(maskLeft);

    // Left part
    Ciphertext<DCRTPoly> ctxt_left = m_cc->EvalMult(ctxt, maskLeftPlain);
    long rot = getRotateDistance(m_k, logDist, slope);

    if (slope == 0) {
        // Handle slope 0 case
        auto maskRightPlain = m_cc->MakeCKKSPackedPlaintext(maskRight[m_k - 1]);
        auto ctxt_right = m_cc->EvalMult(ctxt, maskRightPlain);

        Ciphertext<DCRTPoly> rotRight;
        leftRotate(ctxt_right, (m_k - 1) * rot, rotRight);
        rightRotate(ctxt_left, rot, ctxt_rot);
        ctxt_rot = m_cc->EvalAdd(ctxt_rot, rotRight);
    } else if (slope == m_k / 2 + 1) {
        // Handle middle slope case
        auto maskRightPlain = m_cc->MakeCKKSPackedPlaintext(maskRight[m_k - 2]);
        auto ctxt_right = m_cc->EvalMult(ctxt, maskRightPlain);

        ctxt_fix = m_cc->EvalSub(ctxt, ctxt_left);
        ctxt_fix = m_cc->EvalSub(ctxt_fix, ctxt_right);

        Ciphertext<DCRTPoly> rotRight;
        leftRotate(ctxt_right, (m_k - 2) * rot, rotRight);
        rightRotate(ctxt_left, rot, ctxt_rot);
        ctxt_rot = m_cc->EvalAdd(ctxt_rot, rotRight);
    } else {
        // Handle other slopes
        std::vector<Ciphertext<DCRTPoly>> ctxt_right(m_k);
        for (int i = 0; i < m_k; i++) {
            auto maskRightPlain = m_cc->MakeCKKSPackedPlaintext(maskRight[i]);
            ctxt_right[i] = m_cc->EvalMult(ctxt, maskRightPlain);
        }

        // Calculate fix part
        ctxt_fix = m_cc->EvalSub(ctxt, ctxt_left);
        for (int i = 0; i < m_k; i++) {
            ctxt_fix = m_cc->EvalSub(ctxt_fix, ctxt_right[i]);
        }

        // Rotate and combine
        rightRotate(ctxt_left, rot, ctxt_rot);
        for (int i = 1; i < m_k; i++) {
            Ciphertext<DCRTPoly> rotated;
            leftRotate(ctxt_right[i], i * rot, rotated);
            ctxt_rot = m_cc->EvalAdd(ctxt_rot, rotated);
        }
    }
}

void Sorter::comparisonForSort(Ciphertext<DCRTPoly> &ctxt,
                               std::vector<std::vector<int>> &indices,
                               long logDist, long slope,
                               Ciphertext<DCRTPoly> &ctxt_comp,
                               Ciphertext<DCRTPoly> &ctxt_fix,
                               SignConfig &Cfg) {
    Ciphertext<DCRTPoly> ctxt_rot;
    rightRotateForSort(ctxt, indices, logDist, slope, ctxt_rot, ctxt_fix);
    ctxt_comp = ctxt->Clone();
    ctxt_comp =
        comp.compare(m_cc, ctxt_comp, ctxt_rot, SignFunc::CompositeSign, Cfg);
}

void Sorter::comparisonForSort2(Ciphertext<DCRTPoly> &ctxt,
                                std::vector<std::vector<int>> &indices,
                                long logDist, long slope,
                                Ciphertext<DCRTPoly> &ctxt_comp1,
                                Ciphertext<DCRTPoly> &ctxt_comp2,
                                Ciphertext<DCRTPoly> &ctxt_fix,
                                SignConfig &Cfg) {
    Ciphertext<DCRTPoly> ctxt_rot1, ctxt_rot2, ctxt_dummy;
    rightRotateForSort(ctxt, indices, logDist, slope, ctxt_rot1, ctxt_fix);
    rightRotateForSort(ctxt_rot1, indices, logDist, slope, ctxt_rot2,
                       ctxt_dummy);

    ctxt_comp1 = ctxt->Clone();
    ctxt_comp2 = ctxt_comp1->Clone();
    ctxt_comp1 =
        comp.compare(m_cc, ctxt_comp1, ctxt_rot1, SignFunc::CompositeSign, Cfg);
    ctxt_comp2 =
        comp.compare(m_cc, ctxt_comp2, ctxt_rot2, SignFunc::CompositeSign, Cfg);
}

void Sorter::sorter(Ciphertext<DCRTPoly> &ctxt, Ciphertext<DCRTPoly> &ctxt_out,
                    SignConfig &Cfg) {
    Ciphertext<DCRTPoly> ctxt_fix, ctxt_comp1, ctxt_comp2;
    Ciphertext<DCRTPoly> ctxt_out2, ctxt_out3, ctxt_out4, ctxt_out5;
    assert(m_k == 2 || m_k == 3 || m_k == 5 && "Only k=2,3,5 is supported");
    std::vector<std::vector<int>> indices;
    std::tuple<int, int, int> type;
    long m, logDist, slope, shift;
    // debugWithSk(ctxt, 5, "start sorter");

    int stage_num = m_M + m_M * (m_M - 1) / 2 * ((m_k + 1) / 2);

    for (int stage = 0; stage < stage_num; stage++) {
        std::cout << " == stage " << stage << " == " << std::endl;
        type = sortType(m_k, m_M, stage);
        m = std::get<0>(type);
        logDist = std::get<1>(type);
        slope = std::get<2>(type);
        shift = getRotateDistance(m_k, logDist, slope);
        std::cout << m_k << " " << m_M << " " << m << " " << logDist << " "
                  << slope << std::endl;
        std::cout << "Level " << m_level[m_k] << "\n";
        PRINT_PT(m_enc, ctxt);
        indices = genIndices(m_numSlots, m_k, m_M, m, logDist, slope);

        if (slope == 0) {
            if (m_k == 2) {
                // checkLevelAndBoot(ctxt, m_level[m_k], 1);
                comparisonForSort(ctxt, indices, logDist, slope, ctxt_comp1,
                                  ctxt_fix, Cfg);
                checkLevelAndBoot(ctxt_comp1, m_level[m_k], 0);
                runTwoSorter(ctxt, indices, shift, ctxt_comp1, ctxt);
            } else if (m_k == 3) {
                // checkLevelAndBoot(ctxt, m_level[m_k], 0);
                comparisonForSort(ctxt, indices, logDist, slope, ctxt_comp1,
                                  ctxt_fix, Cfg);
                checkLevelAndBoot(ctxt_comp1, m_level[m_k], 0);
                runThreeSorter(ctxt, indices, shift, ctxt_comp1, ctxt);
            } else if (m_k == 5) {
                // checkLevelAndBoot(ctxt, m_level[m_k], 1);
                comparisonForSort2(ctxt, indices, logDist, slope, ctxt_comp1,
                                   ctxt_comp2, ctxt_fix, Cfg);
                checkLevelAndBoot2(ctxt_comp1, ctxt_comp2, m_level[m_k], 1);
                runFiveSorter(ctxt, indices, shift, ctxt_comp1, ctxt_comp2,
                              ctxt);
            }
        } else if (slope == m_k / 2 + 1) {
            if (m_k == 3) {
                // checkLevelAndBoot(ctxt, m_level[m_k - 1], 0);
                comparisonForSort(ctxt, indices, logDist, slope, ctxt_comp1,
                                  ctxt_fix, Cfg);
                checkLevelAndBoot(ctxt_comp1, m_level[m_k - 1], 0);
                runTwoSorter(ctxt, indices, shift, ctxt_comp1, ctxt);
                ctxt = m_cc->EvalAdd(ctxt, ctxt_fix);
            } else if (m_k == 5) {
                // checkLevelAndBoot(ctxt, m_level[m_k - 1], 0);
                comparisonForSort2(ctxt, indices, logDist, slope, ctxt_comp1,
                                   ctxt_comp2, ctxt_fix, Cfg);
                checkLevelAndBoot2(ctxt_comp1, ctxt_comp2, m_level[m_k - 1], 0);
                runFourSorter(ctxt, indices, shift, ctxt_comp1, ctxt_comp2,
                              ctxt);
                ctxt = m_cc->EvalAdd(ctxt, ctxt_fix);
            }
        } else {
            if (m_k == 5 && slope == 1) {
                // checkLevelAndBoot(ctxt, m_level[5], 0);
                comparisonForSort2(ctxt, indices, logDist, slope, ctxt_comp1,
                                   ctxt_comp2, ctxt_fix, Cfg);
                checkLevelAndBoot2(ctxt_comp1, ctxt_comp2, m_level[5], 0);
                run2345Sorter(ctxt, indices, shift, ctxt_comp1, ctxt_comp2,
                              ctxt);
                ctxt = m_cc->EvalAdd(ctxt, ctxt_fix);
            } else if ((m_k == 5 && slope == 2) || (m_k == 3 && slope == 1)) {
                Ciphertext<DCRTPoly> ctxt2, ctxt3;
                // checkLevelAndBoot(ctxt, m_level[3], 0);
                comparisonForSort(ctxt, indices, logDist, slope, ctxt_comp1,
                                  ctxt_fix, Cfg);
                checkLevelAndBoot(ctxt_comp1, m_level[3], 0);
                runTwoSorter(ctxt, indices, shift, ctxt_comp1, ctxt2);
                runThreeSorter(ctxt, indices, shift, ctxt_comp1, ctxt3);
                ctxt2 = m_cc->EvalAdd(ctxt2, ctxt_fix);
                ctxt = m_cc->EvalAdd(ctxt2, ctxt3);
            } else if (m_k == 2 && slope == 1) {
                Ciphertext<DCRTPoly> ctxt2;
                // checkLevelAndBoot(ctxt, m_level[2], 0);
                comparisonForSort(ctxt, indices, logDist, slope, ctxt_comp1,
                                  ctxt_fix, Cfg);
                checkLevelAndBoot(ctxt_comp1, m_level[2], 0);
                runTwoSorter(ctxt, indices, shift, ctxt_comp1, ctxt2);
                ctxt = m_cc->EvalAdd(ctxt2, ctxt_fix);
            } else {
                std::cout << "[Sorter::Sorter] ERROR : no matching k & slope"
                          << std::endl;
                return;
            }
        }
        std::cout << " == End stage " << stage << " == " << std::endl;

        // long checklen = 2;
        // if (m_M < 2) {
        //     checklen = checklen;
        // }
        // decryptAndPrint(ctxt, pow(m_k, checklen), "check");
    }
    ctxt_out = ctxt;
    std::cout << "Level of output: " << ctxt->GetLevel() << std::endl;
    PRINT_PT(m_enc, ctxt_out);
}

} // namespace kwaySort
