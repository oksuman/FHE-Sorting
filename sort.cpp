#include "sort.h"

arraySort::arraySort()
{
    initCC();
};

void arraySort::initCC()
{
    usint scalingModSize = 59;
    uint32_t multDepth = 47;

    int N = 2048;
    uint32_t batchSize = N;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);
    parameters.SetScalingModSize(scalingModSize);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetBatchSize(batchSize);

    m_cc = GenCryptoContext(parameters);
    m_cc->Enable(PKE);
    m_cc->Enable(KEYSWITCH);
    m_cc->Enable(LEVELEDSHE);
    m_cc->Enable(ADVANCEDSHE);

    std::vector<int> key_indices = {1,-1,-2,-3,-4,-5,-6,-7,-8,-9,-10,-11,-12,-13,-14,-15,-16,-17,-18,-19,-20,-21,-22,-23,-24,-25,-26,-27,-28,-29,-30,-31,-32, -64, -96, -128, -160, -192, -224, -256, -288, -320, -352, -384, -416, -448, -480, -512, -544, -576, -608, -640, -672, -704, -736, -768, -800, -832, -864, -896, -928, -960, -992, -1024, -1056, -1088, -1120, -1152, -1184, -1216, -1248, -1280, -1312, -1344, -1376, -1408, -1440, -1472, -1504, -1536, -1568, -1600, -1632, -1664, -1696, -1728, -1760, -1792, -1824, -1856, -1888, -1920, -1952, -1984, -2016};


    auto keyPair = m_cc->KeyGen();
    m_PublicKey - keyPair.publicKey;
    m_PrivateKey - keyPair.secretKey;
    m_cc->EvalMultKeyGen(m_PrivateKey);
    m_cc->EvalRotateKeyGen(keyPair.secretKey, key_indices);

    ptx_array = generateVectorWithMinDifference(N);
    input_array = m_cc->Encrypt(m_publicKey, m_cc->MakeCKKSPackedPlaintext(ptx_array));
}

void arraySort::eval()
{
    int num_threads = 16;
    omp_set_num_threads(num_threads);
    int N = 2048;

    /*
        Construct Rank

        ctx_Rank is a ciphertext that contains the rank for each entry in the input_array.
        For example, if input_array[i] is the largest number, ctx_Rank[i] would be 2047.
        In other words, the smallest entry in input_array will have a corresponding ctx_Rank value of 0.
    */
    std::vector<double> Zero(N, 0.0);
    Plaintext ptx_Zero = m_cc->MakeCKKSPackedPlaintext(Zero);
    auto ctx_Rank = m_cc->Encrypt(m_PublicKey, ptx_Zero); // initalize ctx_Rank as encryption of 0

    // scale input array for evaluation of sign function. 
    auto input_over_255 = m_cc->EvalMult(input_array, (double)1.0/255);


    /*
        compositeSign outputs 1 if diff > 0, and 0 if diff < 0. (The case where diff == 0 is neglected.)
        (diff denotes the difference between two entries in the input array)

        The comparison is conducted as (compositeSign(diff) + 1) / 2.
        By summing up the comparison results for all pairs of entries in the input array, we can obtain ctx_Rank.
    */
    #pragma omp parallel for
    for(int i=0; i< 32; i++){
        std::cout << "comp i: " << i << std::endl;
        if(i==0){   
            auto tmp1 = m_cc->Encrypt(m_PublicKey, ptx_Zero);
            auto tmp2 = m_cc->Encrypt(m_PublicKey, ptx_Zero);

            for(int j=1; j<32; j++){
                auto b = m_cc->EvalRotate(input_over_255, -j);
                auto diff = m_cc->EvalSub(input_over_255, b);

                auto comp1 = m_cc->EvalMult(m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1), 0.5);
                m_cc->EvalAddInPlace(tmp1, comp1);
                
                auto comp2 = m_cc->EvalRotate(comp1, -32+j);
                m_cc->EvalSubInPlace(1, comp2); 
                m_cc->EvalAddInPlace(tmp2, comp2);
            }

            m_cc->EvalAddInPlace(tmp1, m_cc->EvalRotate(tmp2, -2016));
            #pragma omp critical
            {
                m_cc->EvalAddInPlace(ctx_Rank, tmp1);
            }
        }
        else{
            auto b = m_cc->EvalRotate(input_over_255, -32*i);
            auto diff = m_cc->EvalSub(input_over_255, b);

            auto tmp1 = m_cc->EvalMult(m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1) , 0.5);
            auto tmp2 = m_cc->EvalRotate(tmp1, -32);
            m_cc->EvalSubInPlace(1, tmp2);

            for(int j=1; j<32; j++){
                auto b2 = m_cc->EvalRotate(b, -j);
                auto diff = m_cc->EvalSub(input_over_255, b2);

                auto comp1 = m_cc->EvalMult(m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1) , 0.5);
                m_cc->EvalAddInPlace(tmp1, comp1);

                auto comp2 = m_cc->EvalRotate(comp1, -32+j);
                m_cc->EvalSubInPlace(1, comp2); 
                m_cc->EvalAddInPlace(tmp2, comp2);
            }
            m_cc->EvalAddInPlace(tmp1, m_cc->EvalRotate(tmp2, -2016+32*i));
            #pragma omp critical
            {
                m_cc->EvalAddInPlace(ctx_Rank, tmp1);
            }
        }
    }
    std::cout << "finish comp" << std::endl;
    
    auto b = m_cc->EvalRotate(input_over_255, -1024);
    auto diff = m_cc->EvalSub(input_over_255, b);
    auto comp = m_cc->EvalMult(m_cc->EvalAdd(compositeSign(diff, m_cc, 3, 3), 1) , 0.5);
    m_cc->EvalAddInPlace(ctx_Rank, comp);

    // End of Rank Construction // 
    /*
        There exist two ways i think.. 
        
        1) using chebyshev approximation of sinc function
        2) using lagrange interpolation of sinc function

        in this code, i'm working on the second method. 
    */

    /*
        Sort using ctx_Rank

        Index_minus_Rank represents the number of rotations needed for sorting.

    */

    std::vector<double> Index(N);
    std::iota(Index.begin(), Index.end(), 0);
    Plaintext ptx_Index = m_cc->MakeCKKSPackedPlaintext(Index);

    auto Index_minus_Rank = m_cc->EvalSub(ptx_Index, ctx_Rank); // ptx_index - ctx_Rank
    m_cc->EvalMultInPlace(Index_minus_Rank, 1.0 / N); // scaling for numerical stability 

    /*
        Exhaustively check if the loop index equals Index_minus_Rank.
        If loop index == Index_minus_Rank[i], then rotIndex[i] is set to 1.
        Otherwise, if loop index != Index_minus_Rank[i], then rotIndex[i] is set to 0.

        Therefore, rotIndex acts as a masking vector, retaining only the entries that need to be rotated by the loop index.
    
        Checking if index equals Index_minus_Rank is based on the Sinc function.
    */

    int chunk_size = 256;
    std::vector<double> all_xi(4095);
    for (int i = 0; i < 4095; ++i) {
        all_xi[i] = -2047.0 / 2048.0 + static_cast<double>(i) / 2048.0;
    }
    Ciphertext<DCRTPoly>* precomputed = (Ciphertext<DCRTPoly>*)malloc(num_threads * sizeof(Ciphertext<DCRTPoly>));

    #pragma omp parallel num_threads(num_threads)
    {
        int thread_num = omp_get_thread_num();
        int start_index = thread_num * chunk_size; 
        int end_index = (thread_num == num_threads - 1) ? 4095 : (thread_num + 1) * chunk_size;

        precomputed[thread_num] = treeComputeOfLagrange(start_index, end_index, all_xi);
    }

    // first start with rotation index == 0. 

    // TODO ... 


}


Ciphertext<lbcrypto::DCRTPoly> arraySort::g_n(Ciphertext<lbcrypto::DCRTPoly> x, CryptoContext<DCRTPoly> cc){
    std::vector<double> coeffs = {0.0, 1.112086941473206858077560355014, 0.0, -3.734028305547490433902169115754e-01, 0.0, 2.206814218885782830081865313332e-01, 0.0, -1.614281734745303398259608229637e-01, 0.0, 1.213110949202888116937870677248e-01, 0.0, -1.040122217184874797712978988784e-01, 0.0, 8.261882702673599421228090022851e-02, 0.0, -7.778143277137586353298104313581e-02, 0.0, 6.144666896827026547622807584048e-02, 0.0, -6.346221296887255558516471865005e-02, 0.0, 4.718457305271417379088916277396e-02, 0.0, -5.579119677451320480354723940764e-02, 0.0, 3.473519015361416217846368681421e-02, 0.0, -5.622757517465633292363946793557e-02};
    return cc->EvalChebyshevSeriesPS(x, coeffs, -1, 1);
}

Ciphertext<lbcrypto::DCRTPoly> arraySort::f_n(Ciphertext<lbcrypto::DCRTPoly> x, CryptoContext<DCRTPoly> cc){
    const double c1 = 3.14208984375;
    const double c3 = -7.33154296875;
    const double c5 = 13.19677734375;
    const double c7 = -15.71044921875;
    const double c9 = 12.21923828125;
    const double c11 = -5.99853515625;
    const double c13 = 1.69189453125;
    const double c15 = -0.20947265625;

    auto x2 = cc->EvalSquare(x);
    auto x4 = cc->EvalSquare(x2);
    auto x8 = cc->EvalSquare(x4);

    auto y = cc->EvalMult(x, c1);
    cc->EvalAddInPlace(y, cc->EvalMultAndRelinearize(cc->EvalMult(x, c3), x2));

    auto c5x = cc->EvalMult(x, c5);
    auto c7x = cc->EvalMult(x, c7);
    auto c7x3 = cc->EvalMultAndRelinearize(c7x, x2);
    cc->EvalAddInPlace(y, cc->EvalMultAndRelinearize(cc->EvalAdd(c5x, c7x3), x4));

    auto c9x = cc->EvalMult(x, c9);
    auto c11x = cc->EvalMult(x, c11);
    auto tmp1 = cc->EvalAdd(c9x, cc->EvalMultAndRelinearize(c11x, x2));

    auto c13x = cc->EvalMult(x, c13);
    auto c15x = cc->EvalMult(x, c15);
    auto tmp2 = cc->EvalAdd(c13x, cc->EvalMultAndRelinearize(c15x, x2));

    cc->EvalAddInPlace(tmp1, cc->EvalMultAndRelinearize(tmp2 ,x4));
    cc->EvalAddInPlace(y, cc->EvalMultAndRelinearize(tmp1, x8));

    return y; 
}


Ciphertext<lbcrypto::DCRTPoly> arraySort::compositeSign(Ciphertext<lbcrypto::DCRTPoly> x, CryptoContext<DCRTPoly> cc, int dg, int df){

    auto y = g_n(x, cc);
    cc->EvalMultInPlace(y, 1.0/1.032466);
    for(int i=1; i<dg; i++){
        y = g_n(y, cc);
        cc->EvalMultInPlace(y, 1.0/1.032466);
    }
    for(int i=0; i<df; i++){
        y = f_n(y, cc);
    } 
    return y; 
}

Ciphertext<DCRTPoly> arraySort::treeComputeOfLagrange(int start, int end, const std::vector<double>& all_xi) {
    int length = end - start;
    int levels = static_cast<int>(std::ceil(std::log2(length)));

    std::vector<Ciphertext<DCRTPoly>> nodes;
    nodes.reserve((length + 1) / 2); 

    for (int i = start; i < end - 1; i += 2) {
        auto left = m_cc->EvalSub(Index_minus_Rank, all_xi[i]);
        auto right = m_cc->EvalSub(Index_minus_Rank, all_xi[i + 1]);
        nodes.push_back(m_cc->EvalMultAndRelinearlize(left, right));
    }

    if (length % 2 != 0) {
        auto last = m_cc->EvalSub(Index_minus_Rank, all_xi[end - 1]);
        nodes.push_back(std::move(last));
    }

    for (int level = 1; level < levels; level++) {
        int size = nodes.size() / 2;
        for (int i = 0; i < size; i++) {
            nodes[i] = m_cc->EvalMultAndRelinearlize(nodes[2*i], nodes[2*i + 1]);
        }
        nodes.resize(size);
    }

    return std::move(nodes[0]);
}

Ciphertext<DCRTPoly> arraySort::computeProductExceptJ(int j, const std::vector<Ciphertext<DCRTPoly>>& precomputed, const std::vector<double>& all_xi) {
    const int chunk_size = 256;
    const int num_chunks = 16; 
    const int j_chunk = j / chunk_size;

    int start = j_chunk * chunk_size;
    int end = (j_chunk == num_chunks - 1) ? 4095 : (j_chunk + 1) * chunk_size;
    Ciphertext<DCRTPoly> partial_product = computePartialProductExceptJ(start, end, j, all_xi);

    std::vector<Ciphertext<DCRTPoly>> tree;
    tree.reserve(num_chunks);
    for (int i = 0; i < num_chunks; ++i) {
        if (i == j_chunk) {
            tree.push_back(partial_product);
        } else {
            tree.push_back(precomputed[i]);
        }
    }

    for (int level = 0; level < 4; ++level) {
        int step = 1 << level;
        for (int i = 0; i < num_chunks; i += (step * 2)) {
            tree[i] = m_cc->EvalMultAndRelinearlize(tree[i], tree[i + step]);
        }
    }

    return tree[0];
}

Ciphertext<DCRTPoly> arraySort::computePartialProductExceptJ(int start, int end, int j, const std::vector<double>& all_xi) {
    std::vector<Ciphertext<DCRTPoly>> nodes;
    nodes.reserve((end - start + 1) / 2);

    for (int i = start; i < end; i += 2) {
        if (i == j) {
            if (i + 1 < end) {
                nodes.push_back(m_cc->EvalSub(Index_minus_Rank, all_xi[i + 1]));
            }
        } else if (i + 1 == j) {
            nodes.push_back(m_cc->EvalSub(Index_minus_Rank, all_xi[i]));
        } else if (i + 1 < end) {
            auto left = m_cc->EvalSub(Index_minus_Rank, all_xi[i]);
            auto right = m_cc->EvalSub(Index_minus_Rank, all_xi[i + 1]);
            nodes.push_back(m_cc->EvalMultAndRelinearlize(left, right));
        } else {
            nodes.push_back(m_cc->EvalSub(Index_minus_Rank, all_xi[i]));
        }
    }

    while (nodes.size() > 1) {
        int size = nodes.size();
        int new_size = (size + 1) / 2;
        for (int i = 0; i < new_size; ++i) {
            if (2*i + 1 < size) {
                nodes[i] = m_cc->EvalMultAndRelinearlize(nodes[2*i], nodes[2*i + 1]);
            } else {
                nodes[i] = std::move(nodes[2*i]);
            }
        }
        nodes.resize(new_size);
    }

    return nodes[0];
}

/*
    Generate input array instance for local test
*/
std::vector<double> arraySort::generateVectorWithMinDifference(int N) {
    if (N > 255 * 100) {
        throw std::invalid_argument("N should be less than or equal to 25500 to ensure all values are unique and have a minimum difference of 0.01.");
    }

    std::vector<double> result(N);
    std::vector<int> integers(25500); // 25500 = 255 * 100
    std::iota(integers.begin(), integers.end(), 0); // Fill with values from 0 to 25499
    std::shuffle(integers.begin(), integers.end(), std::mt19937{std::random_device{}()}); // Shuffle the integers

    for (int i = 0; i < N; ++i) {
        result[i] = integers[i] * 0.01; // Scale to have minimum difference of 0.01
    }

    return result;
}