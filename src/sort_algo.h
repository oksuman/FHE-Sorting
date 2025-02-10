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
#include "mehp24/mehp24_utils.h"


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

        // for (int i = 1; i < N / 2; i *= 2) {
        //     rotations.push_back(-i);
        //     rotations.push_back(i);
        // }
        // rotations.push_back(N / 2);

        // // Pattern for output_array rotations
        // if (2 * N * N > 1 << 16) {
        //     for (int i = 1; i < log2((1 << 16) / N) + 1; i++) {
        //         rotations.push_back((1 << 16) / (1 << i));
        //     }
        // } else {
        //     for (int i = 1; i < log2(2 * N) + 1; i++) {
        //         rotations.push_back((2 * N * N) / (1 << i));
        //     }
        // }

        int multDepth;
        int modSize = 48;

        switch (N) {
        case 4:
            multDepth = 23;
            rotations = {1, 2, 4, 8, 16};
            break;
        case 8:
            multDepth = 24;
            rotations = {1, 2, 4, 6, 8, 16, 32, 64};
            break;
        case 16:
            rotations = {1, 2, 3, 4, 8, 12, 16, 32, 64, 128, 256};
            multDepth = 24;
            break;
        case 32:
            rotations = {1,  2,  3,  4,  8,   12,  16,  20,
                         24, 28, 32, 64, 128, 256, 512, 1024};
            multDepth = 28;
            break;
        case 64:
            rotations = {1,  2,  3,  4,  5,   6,   7,   8,    16,   24,  32,
                         40, 48, 56, 64, 128, 256, 512, 1024, 2048, 4096};
            multDepth = 29;
            break;
        case 128:
            rotations = {1,   2,    3,    4,    5,    6,    7,   8,
                         16,  24,   32,   40,   48,   56,   64,  72,
                         80,  88,   96,   104,  112,  120,  128, 256,
                         512, 1024, 2048, 4096, 8192, 16384};
            multDepth = 30;
            break;
        case 256:
            rotations = {1,   2,    3,    4,    5,    6,     7,    8,   9,
                         10,  11,   12,   13,   14,   15,    16,   24,  32,
                         40,  48,   56,   64,   72,   80,    88,   96,  104,
                         112, 120,  128,  129,  130,  131,   132,  133, 134,
                         135, 144,  160,  176,  192,  208,   224,  240, 256,
                         512, 1024, 2048, 4096, 8192, 16384, 32768};
            multDepth = 34;
            // multDepth = 46;
            break;
        case 512:
            multDepth = 46;
            rotations = {
                1,    2,    3,    4,    5,     6,    7,   8,   9,   10,  11,
                12,   13,   14,   15,   16,    24,   32,  40,  48,  56,  64,
                65,   66,   67,   68,   69,    70,   71,  80,  96,  112, 128,
                129,  130,  131,  132,  133,   134,  135, 144, 160, 176, 192,
                193,  194,  195,  196,  197,   198,  199, 208, 224, 240, 256,
                257,  258,  259,  260,  261,   262,  263, 272, 288, 304, 320,
                321,  322,  323,  324,  325,   326,  327, 336, 352, 368, 384,
                385,  386,  387,  388,  389,   390,  391, 400, 416, 432, 448,
                449,  450,  451,  452,  453,   454,  455, 464, 480, 496, 512,
                1024, 2048, 4096, 8192, 16384, 32768};
            break;
        case 1024:
            multDepth = 52;
            rotations = {
                1,   2,    3,    4,    5,    6,     7,    8,   9,   10,  11,
                12,  13,   14,   15,   16,   17,    18,   19,  20,  21,  22,
                23,  24,   25,   26,   27,   28,    29,   30,  31,  32,  33,
                34,  35,   64,   65,   66,   67,    96,   97,  98,  99,  128,
                129, 130,  131,  160,  161,  162,   163,  192, 193, 194, 195,
                224, 225,  226,  227,  256,  257,   258,  259, 288, 289, 290,
                291, 320,  321,  322,  323,  352,   353,  354, 355, 384, 385,
                386, 387,  416,  417,  418,  419,   448,  449, 450, 451, 480,
                481, 482,  483,  512,  513,  514,   515,  544, 545, 546, 547,
                576, 577,  578,  579,  608,  609,   610,  611, 640, 641, 642,
                643, 672,  673,  674,  675,  704,   705,  706, 707, 736, 737,
                738, 739,  768,  769,  770,  771,   800,  801, 802, 803, 832,
                833, 834,  835,  864,  865,  866,   867,  896, 897, 898, 899,
                928, 929,  930,  931,  960,  961,   962,  963, 992, 993, 994,
                995, 1024, 2048, 4096, 8192, 16384, 32768};
            break;
        case 2048:
            multDepth = 52;
            rotations = {
                1,    2,    4,    8,    16,   31,   32,   64,   115,   128,
                179,  211,  227,  241,  242,  243,  256,  307,  339,   355,
                369,  370,  371,  403,  419,  433,  434,  435,  451,   465,
                466,  467,  481,  482,  483,  496,  497,  498,  499,   512,
                563,  595,  611,  625,  626,  627,  659,  675,  689,   690,
                691,  707,  721,  722,  723,  737,  738,  739,  752,   753,
                754,  755,  787,  803,  817,  818,  819,  835,  849,   850,
                851,  865,  866,  867,  880,  881,  882,  883,  899,   913,
                914,  915,  929,  930,  931,  944,  945,  946,  947,   961,
                962,  963,  976,  977,  978,  979,  992,  993,  994,   995,
                1008, 1009, 1010, 1011, 1024, 1075, 1107, 1123, 1137,  1138,
                1139, 1171, 1187, 1201, 1202, 1203, 1219, 1233, 1234,  1235,
                1249, 1250, 1251, 1264, 1265, 1266, 1267, 1299, 1315,  1329,
                1330, 1331, 1347, 1361, 1362, 1363, 1377, 1378, 1379,  1392,
                1393, 1394, 1395, 1411, 1425, 1426, 1427, 1441, 1442,  1443,
                1456, 1457, 1458, 1459, 1473, 1474, 1475, 1488, 1489,  1490,
                1491, 1504, 1505, 1506, 1507, 1520, 1521, 1522, 1523,  1555,
                1571, 1585, 1586, 1587, 1603, 1617, 1618, 1619, 1633,  1634,
                1635, 1648, 1649, 1650, 1651, 1667, 1681, 1682, 1683,  1697,
                1698, 1699, 1712, 1713, 1714, 1715, 1729, 1730, 1731,  1744,
                1745, 1746, 1747, 1760, 1761, 1762, 1763, 1776, 1777,  1778,
                1779, 1795, 1809, 1810, 1811, 1825, 1826, 1827, 1840,  1841,
                1842, 1843, 1857, 1858, 1859, 1872, 1873, 1874, 1875,  1888,
                1889, 1890, 1891, 1904, 1905, 1906, 1907, 1921, 1922,  1923,
                1937, 1938, 1939, 1953, 1954, 1955, 1968, 1969, 1970,  1971,
                1985, 1986, 1987, 2000, 2001, 2002, 2003, 2016, 2017,  2018,
                2019, 2032, 2033, 2034, 2035, 2048, 4096, 8192, 16384, 32768};
            // rotations = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            // 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            // 32, 33, 34, 35, 48, 49, 50, 51, 64, 65, 66, 67, 80, 81, 82, 83,
            // 96, 97, 98, 99, 112, 113, 114, 115, 128, 129, 130, 131, 144, 145,
            // 146, 147, 160, 161, 162, 163, 176, 177, 178, 179, 192, 193, 194,
            // 195, 208, 209, 210, 211, 224, 225, 226, 227, 240, 241, 242, 243,
            // 256, 257, 258, 259, 272, 273, 274, 275, 288, 289, 290, 291, 304,
            // 305, 306, 307, 320, 321, 322, 323, 336, 337, 338, 339, 352, 353,
            // 354, 355, 368, 369, 370, 371, 384, 385, 386, 387, 400, 401, 402,
            // 403, 416, 417, 418, 419, 432, 433, 434, 435, 448, 449, 450, 451,
            // 464, 465, 466, 467, 480, 481, 482, 483, 496, 497, 498, 499, 512,
            // 513, 514, 515, 528, 529, 530, 531, 544, 545, 546, 547, 560, 561,
            // 562, 563, 576, 577, 578, 579, 592, 593, 594, 595, 608, 609, 610,
            // 611, 624, 625, 626, 627, 640, 641, 642, 643, 656, 657, 658, 659,
            // 672, 673, 674, 675, 688, 689, 690, 691, 704, 705, 706, 707, 720,
            // 721, 722, 723, 736, 737, 738, 739, 752, 753, 754, 755, 768, 769,
            // 770, 771, 784, 785, 786, 787, 800, 801, 802, 803, 816, 817, 818,
            // 819, 832, 833, 834, 835, 848, 849, 850, 851, 864, 865, 866, 867,
            // 880, 881, 882, 883, 896, 897, 898, 899, 912, 913, 914, 915, 928,
            // 929, 930, 931, 944, 945, 946, 947, 960, 961, 962, 963, 976, 977,
            // 978, 979, 992, 993, 994, 995, 1008, 1009, 1010, 1011, 1024, 1025,
            // 1026, 1027, 1040, 1041, 1042, 1043, 1056, 1057, 1058, 1059, 1072,
            // 1073, 1074, 1075, 1088, 1089, 1090, 1091, 1104, 1105, 1106, 1107,
            // 1120, 1121, 1122, 1123, 1136, 1137, 1138, 1139, 1152, 1153, 1154,
            // 1155, 1168, 1169, 1170, 1171, 1184, 1185, 1186, 1187, 1200, 1201,
            // 1202, 1203, 1216, 1217, 1218, 1219, 1232, 1233, 1234, 1235, 1248,
            // 1249, 1250, 1251, 1264, 1265, 1266, 1267, 1280, 1281, 1282, 1283,
            // 1296, 1297, 1298, 1299, 1312, 1313, 1314, 1315, 1328, 1329, 1330,
            // 1331, 1344, 1345, 1346, 1347, 1360, 1361, 1362, 1363, 1376, 1377,
            // 1378, 1379, 1392, 1393, 1394, 1395, 1408, 1409, 1410, 1411, 1424,
            // 1425, 1426, 1427, 1440, 1441, 1442, 1443, 1456, 1457, 1458, 1459,
            // 1472, 1473, 1474, 1475, 1488, 1489, 1490, 1491, 1504, 1505, 1506,
            // 1507, 1520, 1521, 1522, 1523, 1536, 1537, 1538, 1539, 1552, 1553,
            // 1554, 1555, 1568, 1569, 1570, 1571, 1584, 1585, 1586, 1587, 1600,
            // 1601, 1602, 1603, 1616, 1617, 1618, 1619, 1632, 1633, 1634, 1635,
            // 1648, 1649, 1650, 1651, 1664, 1665, 1666, 1667, 1680, 1681, 1682,
            // 1683, 1696, 1697, 1698, 1699, 1712, 1713, 1714, 1715, 1728, 1729,
            // 1730, 1731, 1744, 1745, 1746, 1747, 1760, 1761, 1762, 1763, 1776,
            // 1777, 1778, 1779, 1792, 1793, 1794, 1795, 1808, 1809, 1810, 1811,
            // 1824, 1825, 1826, 1827, 1840, 1841, 1842, 1843, 1856, 1857, 1858,
            // 1859, 1872, 1873, 1874, 1875, 1888, 1889, 1890, 1891, 1904, 1905,
            // 1906, 1907, 1920, 1921, 1922, 1923, 1936, 1937, 1938, 1939, 1952,
            // 1953, 1954, 1955, 1968, 1969, 1970, 1971, 1984, 1985, 1986, 1987,
            // 2000, 2001, 2002, 2003, 2016, 2017, 2018, 2019, 2032, 2033, 2034,
            // 2035, 2048, 4096, 8192, 16384, 32768};
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
            // auto rotated = m_cc->EvalRotate(input_array, is * num_partition +
            // j);
            rotated->SetSlots(num_slots);

            auto pmsk = m_cc->MakeCKKSPackedPlaintext(
                generateMaskVector(num_slots, j), 1, 0, nullptr, num_slots);
            auto masked = m_cc->EvalMult(rotated, pmsk);
#pragma omp critical
            { m_cc->EvalAddInPlace(rots, masked); }
        }
        return rots;
    }

    Ciphertext<DCRTPoly>
    vecRotsOpt(const std::vector<Ciphertext<DCRTPoly>> &preRotatedArrays,
               int num_partition, int num_slots, int np, int is) {
        auto result = this->getZero()->Clone();

        std::vector<Ciphertext<DCRTPoly>> outer_results(num_partition / np);

#pragma omp parallel for num_threads(32) schedule(dynamic)
        for (int j = 0; j < num_partition / np; j++) {
            std::vector<Ciphertext<DCRTPoly>> inner_results(np);

#pragma omp parallel for if (N >= 64) num_threads(2)
            for (int i = 0; i < np; i++) {
                auto msk = generateMaskVector(num_slots, np * j + i);
                msk = vectorRotate(msk, -is * num_partition - j * np);
                auto pmsk = m_cc->MakeCKKSPackedPlaintext(msk, 1, 0, nullptr,
                                                          num_slots);
                inner_results[i] = m_cc->EvalMult(preRotatedArrays[i], pmsk);
            }
            
            auto T = m_cc->EvalAddMany(inner_results);
            T->SetSlots(num_slots);
            outer_results[j] = rot.rotate(T, is * num_partition + j * np);
        }

        for (const auto &partial : outer_results) {
            m_cc->EvalAddInPlace(result, partial);
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
#pragma omp parallel for
        for (int i = 0; i < np; i++) {
            Ciphertext<DCRTPoly> t;
            t = rot.rotate(input_array, i);
            // t = m_cc->EvalRotate(input_array, i);
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
            // m_cc->EvalAddInPlace(rank_result,
            //                      m_cc->EvalRotate(rank_result, num_slots / (1
            //                      << i)));
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
            // auto rotated = m_cc->EvalRotate(masked_input, i);

            auto vec = generateMaskVector2N(num_slots, i % (num_slots / N / 2));
            std::rotate(vec.begin(), vec.begin() + i, vec.end());
            Plaintext msk = m_cc->MakeCKKSPackedPlaintext(
                vec, 1, masked_input->GetLevel(), nullptr, num_slots);
            rotated = m_cc->EvalMult(rotated, msk);
#pragma omp critical
            { m_cc->EvalAddInPlace(result, rotated); }
        }
        return result;
    }

    Ciphertext<DCRTPoly>
    blindRotationOpt(const std::vector<Ciphertext<DCRTPoly>> &masked_inputs,
                     int num_slots, int np, int ib) {
        auto result = this->getZero()->Clone();

        for (int i = 0; i < (num_slots / N / 2) / np; i++) {
            auto tmp = this->getZero()->Clone();

#pragma omp parallel for num_threads(32)
            for (int j = 0; j < np; j++) {
                auto msk = generateMaskVector2N(num_slots, (np * i + j));
                msk = vectorRotate(msk, j);
                Plaintext pmsk = m_cc->MakeCKKSPackedPlaintext(
                    msk, 1, masked_inputs[j]->GetLevel(), nullptr, num_slots);

                auto rotated = m_cc->EvalMult(masked_inputs[j], pmsk);
#pragma omp critical
                { m_cc->EvalAddInPlace(tmp, rotated); }
            }
            tmp = rot.rotate(tmp, i * np);
            // tmp = m_cc->EvalRotate(tmp, i * np);
            m_cc->EvalAddInPlace(result, tmp);
        }
        return result;
    }

    Ciphertext<DCRTPoly>
    rotationIndexCheck(const Ciphertext<DCRTPoly> &ctx_Rank,
                       const Ciphertext<DCRTPoly> &input_array) {

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
        // np values for different N (when max_batch = 65536 = 2^16)
        // N=[8]      -> np=2  (num_partition=16)
        // N=[16,32]  -> np=4  (num_partition=32,64)
        // N=[64-512] -> np=8  (num_partition=128,256,256,128)
        // N=[1024,2048] -> np=4  (num_partition=64,32)
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

            static const auto &sincCoefficients = selectCoefficients<N>();
            rotIndex = m_cc->EvalChebyshevSeriesPS(rotIndex,
                                                    sincCoefficients, -1, 1);



            auto masked_input = m_cc->EvalMult(rotIndex, input_array);
            std::vector<Ciphertext<DCRTPoly>> masked_inputs(np);
#pragma omp parallel for
            for (int i = 0; i < np; i++) {
                masked_inputs[i] =
                    rot.rotate(masked_input, b * (num_slots / N / 2) + i);
                // masked_inputs[i] =
                //     m_cc->EvalRotate(masked_input, b * (num_slots / N / 2) +
                //     i);
            }
            auto rotated_input =
                blindRotationOpt(masked_inputs, num_slots, np, b);
            // auto rotated_input = blindRotation(masked_input, num_slots, b);
            m_cc->EvalAddInPlace(output_array, rotated_input);
        }

        for (int i = 1; i < log2(num_partition) + 1; i++) {
            m_cc->EvalAddInPlace(
                output_array, rot.rotate(output_array, num_slots / (1 << i)));
            // m_cc->EvalAddInPlace(
            //     output_array, m_cc->EvalRotate(output_array, num_slots / (1
            //     << i)));
        }
        output_array->SetSlots(N);
        return output_array;
    }

    Ciphertext<DCRTPoly> sort(const Ciphertext<DCRTPoly> &input_array,
                              SignFunc SignFunc, SignConfig &Cfg) override {
        // std::cout << "\n===== Direct Sort Input Array: \n";
        // PRINT_PT(m_enc, input_array);

        Ciphertext<DCRTPoly> ctx_Rank;
        ctx_Rank = constructRank(input_array, SignFunc, Cfg);

        // std::cout << "\n===== Constructed Rank: \n";
        // PRINT_PT(m_enc, ctx_Rank);

        Ciphertext<DCRTPoly> output_array;
        output_array = rotationIndexCheck(ctx_Rank, input_array);

        // std::cout << "\n===== Final Output: \n";
        // PRINT_PT(m_enc, output_array);

        std::cout << "Final Level: " << output_array->GetLevel() << std::endl;
        return output_array;
    }

    Ciphertext<DCRTPoly>
    rotationIndexCheckH(const Ciphertext<DCRTPoly> &ctx_Rank,
                       const Ciphertext<DCRTPoly> &input_array) {
    

        Ciphertext<DCRTPoly> result;
        if(N <= 256){
            std::vector<double> subMask(N * N);
#pragma omp parallel for collapse(2) 
            for (size_t i = 0; i < N; i++)
                    for (size_t j = 0; j < N; j++)
                        subMask[i * N + j] = i;

            Plaintext subMaskPtx = m_cc->MakeCKKSPackedPlaintext(subMask, 1, ctx_Rank->GetLevel(), nullptr, N*N);
            auto rotationMask = m_cc->EvalSub(subMaskPtx, ctx_Rank);

            SignConfig Cfg = SignConfig(CompositeSignConfig(3, 4, 2));
            rotationMask = comp.indicator(m_cc, rotationMask, 0.5 / N, SignFunc::CompositeSign, Cfg);
            auto masked_input = m_cc->EvalMult(rotationMask, input_array);

            result = mehp24::utils::sumColumnsH(masked_input, N, true);
            result = mehp24::utils::transposeColumnH(result, N, true);
        }else{

        }

        // if (N < 512) {
        //     static const auto &sincCoefficients = selectCoefficients<N>();
        //     rotIndex = m_cc->EvalChebyshevSeriesPS(rotIndex,
        //                                             sincCoefficients, -1, 1);
        // } else if (N == 512) {
        //     SignConfig Cfg = SignConfig(CompositeSignConfig(3, 5, 2));
        //     rotIndex = comp.indicator(m_cc, rotIndex, 0.5 / (2 * N),
        //                                 SignFunc::CompositeSign, Cfg);
        // } else {
        //     SignConfig Cfg = SignConfig(CompositeSignConfig(3, 6, 2));
        //     rotIndex = comp.indicator(m_cc, rotIndex, 0.5 / (2 * N),
        //                                 SignFunc::CompositeSign, Cfg);
        // }


        return result;
    }

    
    // Employing rotation index checking method from MEHP24
    Ciphertext<DCRTPoly> sort_hybrid(const Ciphertext<DCRTPoly> &input_array,
                              SignFunc SignFunc, SignConfig &Cfg) {
        Ciphertext<DCRTPoly> ctx_Rank;
        ctx_Rank = constructRank(input_array, SignFunc, Cfg);

        Ciphertext<DCRTPoly> output_array = rotationIndexCheckH(ctx_Rank, input_array);

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
