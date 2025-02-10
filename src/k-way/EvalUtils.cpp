#include "EvalUtils.h"
#include "lattice/hal/lat-backend.h"
#include "scheme/ckksrns/ckksrns-fhe.h"

namespace kwaySort {

// Used for binary decomposition in rotation composition
std::vector<int> binary(int n) {
    std::vector<int> bin_vec;
    while (n > 0) {
        bin_vec.push_back(n % 2);
        n /= 2;
    }
    return bin_vec;
}

void EvalUtils::multByInt(Ciphertext<DCRTPoly> &ctxt, long coeff,
                          Ciphertext<DCRTPoly> &ctxt_out) {
    Ciphertext<DCRTPoly> ctxt_origin;
    if (coeff < 0) {
        coeff *= -1;
        ctxt_out = m_cc->EvalNegate(ctxt);
        ctxt_origin = ctxt_out;
    } else {
        ctxt_out = ctxt;
        ctxt_origin = ctxt;
    }

    std::vector<bool> bin;
    while (coeff > 0) {
        bin.push_back(coeff % 2);
        coeff /= 2;
    }

    // Binary multiplication implementation
    for (int i = bin.size() - 1; i > 0; i--) {
        ctxt_out = m_cc->EvalAdd(ctxt_out, ctxt_out);
        if (bin[i - 1]) {
            ctxt_out = m_cc->EvalAdd(ctxt_out, ctxt_origin);
        }
    }
}

void EvalUtils::multAndKillImage(Ciphertext<DCRTPoly> &ctxt1,
                                 Ciphertext<DCRTPoly> &ctxt2,
                                 Ciphertext<DCRTPoly> &ctxt_out) {
    // Imaginary part is not used in OpenFHE
    ctxt_out = m_cc->EvalMult(ctxt1, ctxt2);
}

void EvalUtils::squareAndKillImage(Ciphertext<DCRTPoly> &ctxt1,
                                   Ciphertext<DCRTPoly> &ctxt_out) {
    ctxt_out = m_cc->EvalSquare(ctxt1);
}

void EvalUtils::checkLevelAndBoot(Ciphertext<DCRTPoly> &ctxt, long level,
                                  long po2bit, bool verbose) {
    auto currentLevel = ctxt->GetLevel();

    // Bootstrap if level is too high
    if (static_cast<long>(currentLevel) > level) {
        if (verbose) {
            std::cout << "Starting bootstrap at level " << currentLevel
                      << std::endl;
            debugWithSk(ctxt, 5, "before boot");
        }

        // Perform bootstrapping
        ctxt = m_cc->EvalBootstrap(ctxt);

        if (verbose) {
            std::cout << "Finished bootstrapping at level " << ctxt->GetLevel()
                      << std::endl;
            debugWithSk(ctxt, 5, "after boot");
        }
    }
}

void EvalUtils::checkLevelAndBoot2(Ciphertext<DCRTPoly> &ctxt,
                                   Ciphertext<DCRTPoly> &ctxt2, long level,
                                   long po2bit, bool verbose) {
    // Check the levels and bootstrap if needed
    checkLevelAndBoot(ctxt, level, po2bit, verbose);
    checkLevelAndBoot(ctxt2, level, po2bit, verbose);

    // Optional: Ensure both ciphertexts are at the same level
    auto ctxtLevel = ctxt->GetLevel();
    auto ctxt2Level = ctxt2->GetLevel();

    if (ctxtLevel != ctxt2Level) {
        if (verbose) {
            std::cout << "Adjusting levels to match..." << std::endl;
        }

        // Bring both ciphertexts to the same level (the lower of the two)
        int targetLevel = std::min(ctxtLevel, ctxt2Level);
        if (static_cast<long>(ctxtLevel) > targetLevel) {
            m_cc->LevelReduceInPlace(ctxt, nullptr, ctxtLevel - targetLevel);
        }
        if (static_cast<long>(ctxt2Level) > targetLevel) {
            m_cc->LevelReduceInPlace(ctxt2, nullptr, ctxt2Level - targetLevel);
        }
    }
}

void EvalUtils::flipCtxt(Ciphertext<DCRTPoly> &ctxt) {
    m_cc->EvalNegateInPlace(ctxt);
    m_cc->EvalAddInPlace(ctxt, 1.0);
}

void EvalUtils::flipCtxt(Ciphertext<DCRTPoly> &ctxt, const Plaintext &mask) {
    m_cc->EvalNegateInPlace(ctxt);
    m_cc->EvalAddInPlace(ctxt, mask);
}

void EvalUtils::evalPoly(Ciphertext<DCRTPoly> &ctxt,
                         const std::vector<long> &coeff, long logDivByPo2,
                         Ciphertext<DCRTPoly> &ctxt_out) {
    long degree = 7;
    if (degree == 9) {
        debugWithSk(ctxt, 5, "evalPoly_start");
        // Goal: f(x) = c1*x + c3*x^3 + c5*x^5 + c7*x^7 + c9*x^9
        //            = (c1*x + c3*x^3) + c5 * x^3 * x^2 + x^6 * (c7*x + c9*x^3)

        // Compute powers
        Ciphertext<DCRTPoly> ctxt2, ctxt3, ctxt6;
        ctxt2 = m_cc->EvalSquare(ctxt);
        ctxt3 = m_cc->EvalMult(ctxt, ctxt2);
        ctxt6 = m_cc->EvalSquare(ctxt3);

        debugWithSk(ctxt2, 5, "evalPoly_ctxt2");
        debugWithSk(ctxt3, 5, "evalPoly_ctxt3");
        debugWithSk(ctxt6, 5, "evalPoly_ctxt6");

        // A = c1*x + c3*x^3
        Ciphertext<DCRTPoly> A, B, C, tmp;
        multByInt(ctxt, coeff[1], A);
        multByInt(ctxt3, coeff[3], tmp);
        A = m_cc->EvalAdd(A, tmp);
        debugWithSk(A, 5, "A");

        // B = c5*x^3*x^2
        B = m_cc->EvalMult(ctxt2, ctxt3);
        multByInt(B, coeff[5], B);
        debugWithSk(B, 5, "B");

        // C = x^6 * (c7*x + c9*x^3)
        multByInt(ctxt, coeff[7], C);
        multByInt(ctxt3, coeff[9], tmp);
        C = m_cc->EvalAdd(C, tmp);
        C = m_cc->EvalMult(C, ctxt6);
        debugWithSk(C, 5, "C");

        // ans = A + B + C
        ctxt_out = m_cc->EvalAdd(m_cc->EvalAdd(A, B), C);

        // Scale down result
        std::vector<double> scaleFactors(
            m_cc->GetEncodingParams()->GetBatchSize(),
            std::pow(2.0, -logDivByPo2));
        auto scalePlain = m_cc->MakeCKKSPackedPlaintext(scaleFactors);
        ctxt_out = m_cc->EvalMult(ctxt_out, scalePlain);

        debugWithSk(ctxt_out, 5, "evalPoly_end");
    } else {
        // debugWithSk(ctxt, 5, "evalPoly_start");
        // Goal: f(x) = c1*x + c3*x^3 + c5*x^5 + c7*x^7
        //            = (c1*x + c3*x^3) + x^4 * (c5*x + c7*x^3)

        Ciphertext<DCRTPoly> ctxt2, ctxt3, ctxt4;
        ctxt2 = m_cc->EvalSquare(ctxt);
        ctxt3 = m_cc->EvalMultAndRelinearize(ctxt, ctxt2);
        ctxt4 = m_cc->EvalSquare(ctxt2);

        // A = c1*x + c3*x^3
        Ciphertext<DCRTPoly> A, B, tmp;
        multByInt(ctxt3, coeff[3], tmp);
        multByInt(ctxt, coeff[1], A);
        A = m_cc->EvalAdd(A, tmp);

        // B = x^4 * (c5*x + c7*x^3)
        multByInt(ctxt3, coeff[7], tmp);
        multByInt(ctxt, coeff[5], B);
        B = m_cc->EvalAdd(B, tmp);
        B = m_cc->EvalMultAndRelinearize(B, ctxt4);

        // ans = A + B
        ctxt_out = m_cc->EvalAdd(A, B);

        // HEAAN has an API for divideByPowofTwo but there is no equivalent in
        // OpenFHE
        std::vector<double> scaleFactors(
            m_cc->GetEncodingParams()->GetBatchSize(),
            std::pow(2.0, -logDivByPo2));
        auto scalePlain = m_cc->MakeCKKSPackedPlaintext(scaleFactors);
        ctxt_out = m_cc->EvalMult(ctxt_out, scalePlain);

        // debugWithSk(ctxt_out, 5, "evalPoly_end");
    }
}

void EvalUtils::evalF(Ciphertext<DCRTPoly> &ctxt,
                      Ciphertext<DCRTPoly> &ctxt_out) {
    std::vector<long> coeff = {0, 35, 0, -35, 0, 21, 0, -5, 0, 0};
    long logDivByPo2 = 4;
    evalPoly(ctxt, coeff, logDivByPo2, ctxt_out);
}

void EvalUtils::evalG(Ciphertext<DCRTPoly> &ctxt,
                      Ciphertext<DCRTPoly> &ctxt_out) {
    std::vector<long> coeff = {0, 4589, 0, -16577, 0, 25614, 0, -12860, 0, 0};
    long logDivByPo2 = 10;
    evalPoly(ctxt, coeff, logDivByPo2, ctxt_out);
}

void EvalUtils::approxComp(Ciphertext<DCRTPoly> &a, Ciphertext<DCRTPoly> &b,
                           long d_f, long d_g) {
    // a = a - b
    a = m_cc->EvalSub(a, b);

    // Apply G polynomial d_g times
    for (int i = 0; i < d_g; i++) {
        checkLevelAndBoot(a, 4, 10);
        evalG(a, a);
        // debugWithSk(a, 5, "a");
    }

    // Apply F polynomial d_f times
    for (int i = 0; i < d_f; i++) {
        checkLevelAndBoot(a, 4, 7);
        evalF(a, a);
        // debugWithSk(a, 5, "a");
    }

    int numSlots = m_cc->GetEncodingParams()->GetBatchSize();
    // Add 1 and divide by 2
    std::vector<double> ones(numSlots, 1.0);
    auto plainOne = m_cc->MakeCKKSPackedPlaintext(ones);
    a = m_cc->EvalAdd(a, plainOne);

    std::vector<double> half(numSlots, 0.5);
    auto plainHalf = m_cc->MakeCKKSPackedPlaintext(half);
    a = m_cc->EvalMult(a, plainHalf);
}

void EvalUtils::approxComp2(Ciphertext<DCRTPoly> &a, Ciphertext<DCRTPoly> &b,
                            Ciphertext<DCRTPoly> &c, Ciphertext<DCRTPoly> &d,
                            long d_f, long d_g) {
    // Initial subtractions
    a = m_cc->EvalSub(a, b);
    c = m_cc->EvalSub(c, d);

    // Apply G polynomial d_g times
    for (int i = 0; i < d_g; i++) {
        checkLevelAndBoot2(a, c, 4, 10, true);
        std::cout << "\nStarting G aa\n";
        evalG(a, a);
        evalG(c, c);
        debugWithSk(a, 5, "a_g_" + std::to_string(i));
        debugWithSk(c, 5, "c_g_" + std::to_string(i));
    }

    // Apply F polynomial d_f times
    for (int i = 0; i < d_f; i++) {
        checkLevelAndBoot2(a, c, 4, 4);
        evalF(a, a);
        evalF(c, c);
        debugWithSk(a, 5, "a_f_" + std::to_string(i));
        debugWithSk(c, 5, "c_f_" + std::to_string(i));
    }

    int numSlots = m_cc->GetEncodingParams()->GetBatchSize();
    // Add 1 and divide by 2 for both a and c
    std::vector<double> ones(numSlots, 1.0);
    auto plainOne = m_cc->MakeCKKSPackedPlaintext(ones);
    std::vector<double> half(numSlots, 0.5);
    auto plainHalf = m_cc->MakeCKKSPackedPlaintext(half);

    a = m_cc->EvalAdd(a, plainOne);
    a = m_cc->EvalMult(a, plainHalf);
    c = m_cc->EvalAdd(c, plainOne);
    c = m_cc->EvalMult(c, plainHalf);
}
void EvalUtils::leftRotate(Ciphertext<DCRTPoly> &ctxt, long r,
                           Ciphertext<DCRTPoly> &ctxt_out) {
    if (r == 0) {
        ctxt_out = ctxt;
        return;
    }

    std::vector<int> r_bin = binary(r);
    long power_of_two = 1;

    ctxt_out = ctxt;
    for (size_t i = 0; i < r_bin.size(); i++) {
        long rot = r_bin[i] * power_of_two;
        if (rot > 0) {
            // std::cout << "Left Rotate: \n";
            // std::cout << rot << "\n";
            ctxt_out = m_cc->EvalRotate(ctxt_out, rot);
        }
        power_of_two *= 2;
    }
}

void EvalUtils::rightRotate(Ciphertext<DCRTPoly> &ctxt, long r,
                            Ciphertext<DCRTPoly> &ctxt_out) {
    if (r == 0) {
        ctxt_out = ctxt;
        return;
    }

    std::vector<int> r_bin = binary(r);
    long power_of_two = 1;

    ctxt_out = ctxt;
    for (size_t i = 0; i < r_bin.size(); i++) {
        long rot = r_bin[i] * power_of_two;
        if (rot > 0) {
            ctxt_out =
                m_cc->EvalRotate(ctxt_out, -rot); // Negative for right rotation
        }
        power_of_two *= 2;
    }
}

void EvalUtils::debugWithSk(Ciphertext<DCRTPoly> &ctxt, long length,
                            const std::string &str) {
    if (!str.empty()) {
        std::cout << "check " + str << std::endl;
    }

    Plaintext decrypted;
    m_cc->Decrypt(m_privateKey, ctxt, &decrypted);
    std::vector<double> result = decrypted->GetRealPackedValue();

    // Print first 20 values
    for (int i = 0; i < std::min(20L, length); i++) {
        std::cout << "(" << i << ", " << result[i] << "), ";
    }

    // Print last 20 values
    for (size_t i = std::max(static_cast<size_t>(0), result.size() - 20);
         i < result.size(); i++) {
        std::cout << "(" << i << ", " << result[i] << "), ";
    }

    // Find max value
    double max_val = 0;
    size_t index = 0;
    for (size_t i = 0; i < result.size(); i++) {
        if (std::abs(result[i]) > max_val) {
            max_val = std::abs(result[i]);
            index = i;
        }
    }
    std::cout << str << " max val = " << index << ", " << max_val << std::endl;
}

} // namespace kwaySort
