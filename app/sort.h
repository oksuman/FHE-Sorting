#include "openfhe.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

// #include <iostream>
// #include <vector>
// #include <cmath>
// #include <algorithm>
// #include <numeric>
// #include <cstdlib>
#include <functional>
#include <omp.h>

using namespace lbcrypto;

enum class SortingAlgo { DIRECT, BITONIC };

struct arraySort {
    CryptoContext<DCRTPoly> m_cc;
    PublicKey<DCRTPoly> m_PublicKey;
    Ciphertext<DCRTPoly> input_array;
    Ciphertext<DCRTPoly> output_array;
    std::string m_PubKeyLocation;
    std::string m_MultKeyLocation;
    std::string m_RotKeyLocation;
    std::string m_CCLocation;
    std::string m_arrayLocation;
    std::string m_OutputLocation;

    arraySort(std::string ccLocation, std::string pubKeyLocation,
              std::string multKeyLocation, std::string rotKeyLocation,
              std::string arraytLocation, std::string outputLocation);

    arraySort(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> publicKey);

    void initCC();

    void eval(SortingAlgo algo);
    void directSort();
    void bitonicSort();
    Ciphertext<DCRTPoly> bitonicCompare(const Ciphertext<DCRTPoly> &x,
                                        const Ciphertext<DCRTPoly> &y,
                                        bool ascending);
    void bitonicMerge(std::vector<Ciphertext<DCRTPoly>> &arr, int low,
                      int count, bool ascending);
    void bitonicSortRecursive(std::vector<Ciphertext<DCRTPoly>> &arr, int low,
                              int count, bool ascending);

    void encryptInput(std::vector<double>);

    std::vector<double> getPlaintextOutput(PrivateKey<DCRTPoly> sk);
    void deserializeOutput();
};
