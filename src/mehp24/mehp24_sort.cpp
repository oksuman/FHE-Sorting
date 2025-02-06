/*
 * This code implements algorithms from:
 * "Efficient Ranking, Order Statistics, and Sorting under CKKS"
 * by Federico Mazzone, Maarten H. Everts, Florian Hahn, and Andreas Peter
 * (https://doi.org/10.48550/arXiv.2412.15126)
 *
 * Parts of this implementation are based on:
 * https://github.com/FedericoMazzone/openfhe-statistics
 * Copyright (c) 2024 Federico Mazzone
 * Licensed under BSD 2-Clause License
 *
 * Modified and adapted by oksuman 
 */
#include "mehp24_sort.h"
#include "mehp24_utils.h"
#include <cassert>
#include <omp.h>

namespace mehp24 {

using namespace utils;

Ciphertext<DCRTPoly> sort(
    Ciphertext<DCRTPoly> c,
    const size_t vectorLength,
    double leftBoundC,
    double rightBoundC,
    uint32_t degreeC,
    uint32_t degreeI
)
{
    Ciphertext<DCRTPoly> VR = replicateRow(c, vectorLength);
    Ciphertext<DCRTPoly> VC = replicateColumn(transposeRow(c, vectorLength, true), vectorLength);
    

    Ciphertext<DCRTPoly> C = compare(
        VR, VC,
        leftBoundC, rightBoundC,
        degreeC
    );

    Ciphertext<DCRTPoly> R = sumRows(C, vectorLength);

    std::vector<double> subMask(vectorLength * vectorLength);
    for (size_t i = 0; i < vectorLength; i++)
        for (size_t j = 0; j < vectorLength; j++)
            subMask[i * vectorLength + j] = -1.0 * i - 0.5;
    
    Ciphertext<DCRTPoly> M = indicator(
        R + subMask,
        -0.5, 0.5,
        -1.0 * vectorLength, 1.0 * vectorLength,
        degreeI
    );

    Ciphertext<DCRTPoly> S = sumColumns(M * VR, vectorLength);

    return S;
}

std::vector<Ciphertext<DCRTPoly>> sort(
    const std::vector<Ciphertext<DCRTPoly>> &c,
    const size_t subVectorLength,
    double leftBoundC,
    double rightBoundC,
    uint32_t degreeC,
    uint32_t degreeI
)
{

    const size_t numCiphertext = c.size();
    const size_t vectorLength = subVectorLength * numCiphertext;

    static std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double> elapsed_seconds;

    start = std::chrono::high_resolution_clock::now();
    std::vector<Ciphertext<DCRTPoly>> replR(numCiphertext);
    std::vector<Ciphertext<DCRTPoly>> replC(numCiphertext);

    #pragma omp parallel for collapse(2)
    for (size_t loopID = 0; loopID < 2; loopID++) {
        for (size_t j = 0; j < numCiphertext; j++) {
            if (loopID == 0) {
                replR[j] = replicateRow(c[j], subVectorLength);
            } else {
                replC[j] = replicateColumn(transposeRow(c[j], subVectorLength, true), subVectorLength);
            }
        }
    }
    end = std::chrono::high_resolution_clock::now();
    elapsed_seconds = end - start;

    start = std::chrono::high_resolution_clock::now();
    std::vector<Ciphertext<DCRTPoly>> Cv(numCiphertext);
    std::vector<Ciphertext<DCRTPoly>> Ch(numCiphertext);
    std::vector<bool> Cvinitialized(numCiphertext, false);
    std::vector<bool> Chinitialized(numCiphertext, false);

    const size_t numReqThreads = numCiphertext * (numCiphertext + 1) / 2;

    #pragma omp parallel for
    for (size_t i = 0; i < numReqThreads; i++) {
        size_t j = 0, k = 0, counter = 0;
        bool loopCond = true;
        for (j = 0; j < numCiphertext && loopCond; j++)
            for (k = j; k < numCiphertext && loopCond; k++)
                if (counter++ == i) loopCond = false;
        j--; k--;

        Ciphertext<DCRTPoly> Cjk = compare(
            replR[j],
            replC[k],
            leftBoundC, rightBoundC, degreeC
        );

        #pragma omp critical
        {
        if (!Cvinitialized[j]) { Cv[j] = Cjk; Cvinitialized[j] = true; }
        else                   { Cv[j] = Cv[j] + Cjk;                  }
        }

        if (j != k) {
            Ciphertext<DCRTPoly> Ckj = 1.0 - Cjk;

            #pragma omp critical
            {
            if (!Chinitialized[k]) { Ch[k] = Ckj; Chinitialized[k] = true; }
            else                   { Ch[k] = Ch[k] + Ckj;                  }
            }
        }
    }
    end = std::chrono::high_resolution_clock::now();
    elapsed_seconds = end - start;

    start = std::chrono::high_resolution_clock::now();
    std::vector<Ciphertext<DCRTPoly>> sv(numCiphertext);
    std::vector<Ciphertext<DCRTPoly>> sh(numCiphertext);
    std::vector<Ciphertext<DCRTPoly>> s(numCiphertext);
    std::vector<bool> sinitialized(numCiphertext, false);

    #pragma omp parallel for collapse(2)
    for (size_t loopID = 0; loopID < 2; loopID++) {
        for (size_t j = 0; j < numCiphertext; j++) {
            if (loopID == 0) {
                sv[j] = sumRows(Cv[j], subVectorLength);
                
                #pragma omp critical
                {
                if (!sinitialized[j]) { s[j] = sv[j]; sinitialized[j] = true; }
                else                  { s[j] = s[j] + sv[j];                  }
                }
            } else {
                if (j > 0) {
                    sh[j] = sumColumns(Ch[j], subVectorLength, true);
                    sh[j] = transposeColumn(sh[j], subVectorLength, true);
                    sh[j] = replicateRow(sh[j], subVectorLength);

                    #pragma omp critical
                    {
                    if (!sinitialized[j]) { s[j] = sh[j]; sinitialized[j] = true; }
                    else                  { s[j] = s[j] + sh[j];                  }
                    }
                }
            }
        }
    }
    end = std::chrono::high_resolution_clock::now();
    elapsed_seconds = end - start;

    start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<double>> subMasks(numCiphertext);
    for (size_t i = 0; i < numCiphertext; i++) {
        std::vector<double> subMask(subVectorLength * subVectorLength);
        for (size_t j = 0; j < subVectorLength; j++)
            for (size_t k = 0; k < subVectorLength; k++)
                subMask[j * subVectorLength + k] = -1.0 * (i * subVectorLength + j) - 0.5;
        subMasks[i] = subMask;
    }

    std::vector<Ciphertext<DCRTPoly>> subSorted(numCiphertext);
    std::vector<bool> subSortedInitialized(numCiphertext, false);

    #pragma omp parallel for collapse(2)
    for (size_t j = 0; j < numCiphertext; j++) {
        for (size_t k = 0; k < numCiphertext; k++) {
            Ciphertext<DCRTPoly> ind = indicator(
                s[k] + subMasks[j],
                -0.5, 0.5,
                -1.01 * vectorLength, 1.01 * vectorLength,
                degreeI
            ) * replR[k];

            #pragma omp critical
            {
            if (!subSortedInitialized[j]) { subSorted[j] = ind; subSortedInitialized[j] = true; }
            else                          { subSorted[j] = subSorted[j] + ind;                  }
            }
        }
    }
    end = std::chrono::high_resolution_clock::now();
    elapsed_seconds = end - start;

    start = std::chrono::high_resolution_clock::now();
    std::vector<Ciphertext<DCRTPoly>> result(numCiphertext);

    #pragma omp parallel for
    for (size_t j = 0; j < numCiphertext; j++) {
        result[j] = sumColumns(subSorted[j], subVectorLength);
    }
    end = std::chrono::high_resolution_clock::now();
    elapsed_seconds = end - start;

    return result;
}


Ciphertext<DCRTPoly> sortFG(
    Ciphertext<DCRTPoly> c,
    const size_t vectorLength,
    uint32_t dg_c,
    uint32_t df_c,
    uint32_t dg_i,
    uint32_t df_i,
    PrivateKey<DCRTPoly> sk,
    CryptoContext<DCRTPoly> m_cc
)
{
    Plaintext ptx;

    Ciphertext<DCRTPoly> VR = replicateRow(c, vectorLength);
    // m_cc->Decrypt(VR, sk, &ptx);
    // std::cout << "VR: " << std::endl;
    // std::cout << ptx << std::endl;

    Ciphertext<DCRTPoly> VC = replicateColumn(transposeRow(c, vectorLength, true), vectorLength);
    // m_cc->Decrypt(VC, sk, &ptx);
    // std::cout << "VC: " << std::endl;
    // std::cout << ptx << std::endl;
    
    Ciphertext<DCRTPoly> C = compareAdv(
        VR, VC,
        dg_c, df_c
    );
    std::cout << "C levels: " << C->GetLevel() << std::endl;
    // m_cc->Decrypt(C, sk, &ptx);
    // std::cout << "C: " << std::endl;
    // std::cout << ptx << std::endl;
    
    Ciphertext<DCRTPoly> R = sumRows(C, vectorLength);
    // m_cc->Decrypt(R, sk, &ptx);
    // std::cout << "R: " << std::endl;
    // std::cout << ptx << std::endl;

    std::vector<double> subMask(vectorLength * vectorLength);
    for (size_t i = 0; i < vectorLength; i++)
        for (size_t j = 0; j < vectorLength; j++)
            subMask[i * vectorLength + j] = -1.0 * i - 0.5;
    Ciphertext<DCRTPoly> M = indicatorAdv(
        R + subMask,
        vectorLength,
        dg_i, df_i
    );
    std::cout << "M levels: " << M->GetLevel() << std::endl;
    // m_cc->Decrypt(M, sk, &ptx);
    // std::cout << "M: " << std::endl;
    // std::cout << ptx << std::endl;

    auto tmp = M * VR;
    // m_cc->Decrypt(tmp, sk, &ptx);
    // std::cout << "M*VR: " << std::endl;
    // std::cout << ptx << std::endl;


    Ciphertext<DCRTPoly> S = sumColumns(M * VR, vectorLength, true);
    std::cout << "S levels: " << S->GetLevel() << std::endl;
    // m_cc->Decrypt(S, sk, &ptx);
    // std::cout << "S: " << std::endl;
    // std::cout << ptx << std::endl;

    auto result = transposeColumn(S, vectorLength, true);
    // m_cc->Decrypt(result, sk, &ptx);
    // std::cout << "result: " << std::endl;
    // std::cout << ptx << std::endl;

    return result;
}

std::vector<Ciphertext<DCRTPoly>> sortFG(
    const std::vector<Ciphertext<DCRTPoly>> &c,
    const size_t subVectorLength,
    uint32_t dg_c,
    uint32_t df_c,
    uint32_t dg_i,
    uint32_t df_i
)
{
    const size_t numCiphertext = c.size();
    const size_t vectorLength = subVectorLength * numCiphertext;

    static std::chrono::time_point<std::chrono::high_resolution_clock> start, end;
    std::chrono::duration<double> elapsed_seconds;

    start = std::chrono::high_resolution_clock::now();
    std::vector<Ciphertext<DCRTPoly>> replR(numCiphertext);
    std::vector<Ciphertext<DCRTPoly>> replC(numCiphertext);

    #pragma omp parallel for collapse(2)
    for (size_t loopID = 0; loopID < 2; loopID++) {
        for (size_t j = 0; j < numCiphertext; j++) {
            if (loopID == 0) {
                replR[j] = replicateRow(c[j], subVectorLength);
            } else {
                replC[j] = replicateColumn(transposeRow(c[j], subVectorLength, true), subVectorLength);
            }
        }
    }
    std::cout << "replR levels: " << replR[0]->GetLevel() << std::endl;
    std::cout << "replC levels: " << replC[0]->GetLevel() << std::endl;
    end = std::chrono::high_resolution_clock::now();
    elapsed_seconds = end - start;
    std::cout << "Replication completed in " << elapsed_seconds.count() << "s" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    std::vector<Ciphertext<DCRTPoly>> Cv(numCiphertext);
    std::vector<Ciphertext<DCRTPoly>> Ch(numCiphertext);
    std::vector<bool> Cvinitialized(numCiphertext, false);
    std::vector<bool> Chinitialized(numCiphertext, false);

    const size_t numReqThreads = numCiphertext * (numCiphertext + 1) / 2;

    #pragma omp parallel for
    for (size_t i = 0; i < numReqThreads; i++) {
        size_t j = 0, k = 0, counter = 0;
        bool loopCond = true;
        for (j = 0; j < numCiphertext && loopCond; j++)
            for (k = j; k < numCiphertext && loopCond; k++)
                if (counter++ == i) loopCond = false;
        j--; k--;

        Ciphertext<DCRTPoly> Cjk = compareAdv(
            replR[j],
            replC[k],
            dg_c, df_c
        );

        #pragma omp critical
        {
        if (!Cvinitialized[j]) { Cv[j] = Cjk; Cvinitialized[j] = true; }
        else                   { Cv[j] = Cv[j] + Cjk;                  }
        }

        if (j != k) {
            Ciphertext<DCRTPoly> Ckj = 1.0 - Cjk;

            #pragma omp critical
            {
            if (!Chinitialized[k]) { Ch[k] = Ckj; Chinitialized[k] = true; }
            else                   { Ch[k] = Ch[k] + Ckj;                  }
            }
        }
    }
    std::cout << "Cv levels: " << Cv[0]->GetLevel() << std::endl;
    if (numCiphertext > 1) {
        std::cout << "Ch levels: " << Ch[1]->GetLevel() << std::endl;
    }
    end = std::chrono::high_resolution_clock::now();
    elapsed_seconds = end - start;
    std::cout << "Compare completed in " << elapsed_seconds.count() << "s" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    std::vector<Ciphertext<DCRTPoly>> s(numCiphertext);
    std::vector<bool> sinitialized(numCiphertext, false);

    #pragma omp parallel for collapse(2)
    for (size_t loopID = 0; loopID < 2; loopID++) {
        for (size_t j = 0; j < numCiphertext; j++) {
            if (loopID == 0) {
                Ciphertext<DCRTPoly> svj = sumRows(Cv[j], subVectorLength);
                
                #pragma omp critical
                {
                if (!sinitialized[j]) { s[j] = svj; sinitialized[j] = true; }
                else                  { s[j] = s[j] + svj;                  }
                }
            } else {
                if (j > 0) {
                    Ciphertext<DCRTPoly> shj = sumColumns(Ch[j], subVectorLength, true);
                    shj = transposeColumn(shj, subVectorLength, true);
                    shj = replicateRow(shj, subVectorLength);

                    #pragma omp critical
                    {
                    if (!sinitialized[j]) { s[j] = shj; sinitialized[j] = true; }
                    else                  { s[j] = s[j] + shj;                  }
                    }
                }
            }
        }
    }
    std::cout << "s levels: " << s[0]->GetLevel() << std::endl;
    end = std::chrono::high_resolution_clock::now();
    elapsed_seconds = end - start;
    std::cout << "Sum rows/columns completed in " << elapsed_seconds.count() << "s" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    std::vector<std::vector<double>> subMasks(numCiphertext);
    for (size_t i = 0; i < numCiphertext; i++) {
        std::vector<double> subMask(subVectorLength * subVectorLength);
        for (size_t j = 0; j < subVectorLength; j++)
            for (size_t k = 0; k < subVectorLength; k++)
                subMask[j * subVectorLength + k] = -1.0 * (i * subVectorLength + j) - 0.5;
        subMasks[i] = subMask;
    }

    std::vector<Ciphertext<DCRTPoly>> subSorted(numCiphertext);
    std::vector<bool> subSortedInitialized(numCiphertext, false);

    #pragma omp parallel for collapse(2)
    for (size_t j = 0; j < numCiphertext; j++) {
        for (size_t k = 0; k < numCiphertext; k++) {
            Ciphertext<DCRTPoly> ind = indicatorAdv(
                s[k] + subMasks[j],
                vectorLength,
                dg_i, df_i
            ) * replR[k];

            #pragma omp critical
            {
            if (!subSortedInitialized[j]) { subSorted[j] = ind; subSortedInitialized[j] = true; }
            else                          { subSorted[j] = subSorted[j] + ind;                  }
            }
        }
    }
    std::cout << "subSorted levels: " << subSorted[0]->GetLevel() << std::endl;
    end = std::chrono::high_resolution_clock::now();
    elapsed_seconds = end - start;
    std::cout << "Indicator completed in " << elapsed_seconds.count() << "s" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    std::vector<Ciphertext<DCRTPoly>> result(numCiphertext);

    #pragma omp parallel for
    for (size_t j = 0; j < numCiphertext; j++) {
        result[j] = sumColumns(subSorted[j], subVectorLength);
    }
    std::cout << "result levels: " << result[0]->GetLevel() << std::endl;
    end = std::chrono::high_resolution_clock::now();
    elapsed_seconds = end - start;
    std::cout << "Final sum completed in " << elapsed_seconds.count() << "s" << std::endl;

    return result;
}

} // namespace mehp24