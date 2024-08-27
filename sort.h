#include "openfhe.h"

// #include <iostream>
// #include <vector>
// #include <cmath>
// #include <algorithm>
// #include <numeric>
// #include <cstdlib>
#include <omp.h>
#include <functional>

using namespace lbcrypto;

class arraySort {

    private:
        CryptoContext<DCRTPoly> m_cc; 
        PublicKey<DCRTPoly> m_PublicKey;
        PrivateKey<DCRTPoly> m_PrivateKey;

        std::vector<double> ptx_array; // input plaintext array 
        Ciphertext<DCRTPoly> input_array; // input ciphertext array
        Ciphertext<DCRTPoly> output_array; // output ciphertext array

        Ciphertext<DCRTPoly> Index_minus_Rank; 

    public:
        arraySort();

        void initCC();
        void eval();
    

        Ciphertext<lbcrypto::DCRTPoly> g_n(Ciphertext<lbcrypto::DCRTPoly> x, CryptoContext<DCRTPoly> cc);
        Ciphertext<lbcrypto::DCRTPoly> f_n(Ciphertext<lbcrypto::DCRTPoly> x, CryptoContext<DCRTPoly> cc);
        Ciphertext<lbcrypto::DCRTPoly> compositeSign(Ciphertext<lbcrypto::DCRTPoly> x, CryptoContext<DCRTPoly> cc, int dg, int df);

        Ciphertext<DCRTPoly> treeComputeOfLagrange(int start, int end, const std::vector<double>& all_xi); 

        Ciphertext<DCRTPoly> computeProductExceptJ(int j, const std::vector<Ciphertext<DCRTPoly>>& precomputed, const std::vector<double>& all_xi);
        Ciphertext<DCRTPoly> computePartialProductExceptJ(int start, int end, int j, const std::vector<double>& all_xi);

        std::vector<double> generateVectorWithMinDifference(int N);



};